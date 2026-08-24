//! CUDA vanity search pipeline.
//!
//! Launches the SAME kernel sources as the OpenCL path, compiled to PTX at
//! build time by `build.rs` and JIT-loaded through the driver API. Mirrors the
//! loop-based (`vanity_seed` + `vanity_search`) production path; CPU hit
//! verification is shared with `pipeline.rs`.

use super::check;
use super::ffi::{CuDevicePtr, CuEvent, CuFunction, CuStream};
use super::{launch, launch_on, CudaBuffer, CudaDevice, CudaModule};
use crate::buffers::{pack_patterns, GpuHit, MAX_HITS, MAX_PATTERNS, MAX_PATTERN_DATA};
use crate::comb::load_comb_table;
use crate::context::GpuError;
use crate::pipeline::{
    prepare_patterns_for_gpu, sort_patterns_longest_first, verify_hits_shared, VanityConfig,
    VanityResult,
};
use crate::wordlist::{generate_word_lens, generate_words_data};
use erg_vanity_cpu::MatchType;
use std::ffi::c_void;

fn search_disabled() -> bool {
    std::env::var("ERG_NO_SEARCH").is_ok_and(|v| v == "1")
}

/// PTX produced by build.rs when nvcc was available at compile time.
#[cfg(not(no_cuda_backend))]
static VANITY_PTX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vanity_cuda.ptx"));
#[cfg(not(no_cuda_backend))]
pub const CUDA_BUILT: bool = true;

/// The embedded PTX image (empty when the backend was not built).
#[cfg(not(no_cuda_backend))]
pub(crate) fn vanity_ptx() -> &'static [u8] {
    VANITY_PTX
}
#[cfg(no_cuda_backend)]
pub(crate) fn vanity_ptx() -> &'static [u8] {
    &[]
}

#[cfg(no_cuda_backend)]
pub const CUDA_BUILT: bool = false;

pub struct CudaVanityPipeline {
    device: CudaDevice,
    #[allow(dead_code)]
    module: CudaModule,
    seed_fn: CuFunction,
    search_fn: CuFunction,

    salt: CudaBuffer,
    words8: CudaBuffer,
    lens: CudaBuffer,
    seeds: CudaBuffer,
    patterns: CudaBuffer,
    pattern_offsets: CudaBuffer,
    pattern_lens: CudaBuffer,
    pattern_lower: CudaBuffer,
    pattern_upper: CudaBuffer,
    hits: CudaBuffer,
    hit_count: CudaBuffer,
    comb: CudaBuffer,

    batch_size: usize,
    num_indices: u32,
    ignore_case: bool,
    patterns_cpu: Vec<String>,
    pattern_index_map: Vec<u32>,
    match_type: MatchType,
    seed_local: usize,
    search_local: usize,
    hits_dropped_total: u64,
    num_patterns: u32,

    // ---- optional ping-pong overlap (ERG_CUDA_OVERLAP=1) ----
    overlap: bool,
    streams: [CuStream; 2],
    ev_seed_done: [CuEvent; 2],
    ev_search_done: [CuEvent; 2],
    seeds_pp: [CuDevicePtr; 2],
    hits_pp: [CuDevicePtr; 2],
    hit_count_pp: [CuDevicePtr; 2],
    batch_index: u64,
    pending: Option<PendingBatch>,
    // Pinned host staging for async hit readback (overlap mode only).
    pin_count: [*mut c_void; 2],
    pin_hits: [*mut c_void; 2],
}

struct PendingBatch {
    slot: usize,
}

impl CudaVanityPipeline {
    /// Build a pipeline on CUDA device `device_index`.
    pub fn new(
        patterns: &[String],
        cfg: VanityConfig,
        device_index: usize,
        salt: [u8; 32],
    ) -> Result<Self, GpuError> {
        if !CUDA_BUILT {
            return Err(GpuError::Other(
                "CUDA backend not built into this binary (nvcc missing at build time); \
                 rebuild with nvcc installed or use the OpenCL backend"
                    .to_string(),
            ));
        }
        if patterns.is_empty() {
            return Err(GpuError::Other("at least one pattern required".to_string()));
        }

        let device = CudaDevice::open(device_index)?;
        eprintln!("Compiling CUDA module from embedded PTX (first run JITs; cached afterwards)...");
        let module = CudaModule::load_ptx(&device, vanity_ptx())?;
        let seed_fn = module.function(&device, "vanity_seed")?;
        let search_fn = module.function(&device, "vanity_search")?;

        // Buffer sizing mirrors buffers.rs exactly (kernels are identical).
        let batch = cfg.batch_size;
        let words8_data = generate_words_data();
        let lens_data = generate_word_lens();
        let comb_bytes: Vec<u8> = load_comb_table()
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();

        // Patterns: same sorting + packing as the OpenCL path so hit
        // `pattern_index` values mean the same thing on both backends.
        let (sorted, pattern_index_map) = sort_patterns_longest_first(patterns);
        let prepared = prepare_patterns_for_gpu(&sorted, cfg.ignore_case);
        let gpu_patterns: &[String] = prepared.as_deref().unwrap_or(&sorted);
        let pack = pack_patterns(gpu_patterns, cfg.ignore_case)?;

        let salt_buf = CudaBuffer::new(&device, 32)?;
        salt_buf.upload(&device, &salt)?;
        let words8_buf = CudaBuffer::new(&device, words8_data.len())?;
        words8_buf.upload(&device, &words8_data)?;
        let lens_buf = CudaBuffer::new(&device, lens_data.len())?;
        lens_buf.upload(&device, &lens_data)?;
        let seeds_buf = CudaBuffer::new(&device, batch * 64)?;
        let patterns_buf = CudaBuffer::new(&device, MAX_PATTERN_DATA)?;
        patterns_buf.upload(&device, &pack.data)?;
        let offsets_buf = CudaBuffer::new(&device, MAX_PATTERNS * 4)?;
        offsets_buf.upload(&device, &bytemuck_u32(&pack.offsets))?;
        let lens_pat_buf = CudaBuffer::new(&device, MAX_PATTERNS * 4)?;
        lens_pat_buf.upload(&device, &bytemuck_u32(&pack.lens))?;
        let lower_buf = CudaBuffer::new(&device, MAX_PATTERNS * 38)?;
        lower_buf.upload(&device, &pack.lowers)?;
        let upper_buf = CudaBuffer::new(&device, MAX_PATTERNS * 38)?;
        upper_buf.upload(&device, &pack.uppers)?;
        let hits_buf = CudaBuffer::new(&device, MAX_HITS * 64)?;
        let hit_count_buf = CudaBuffer::new(&device, 16)?;
        hit_count_buf.upload(&device, &[0u8; 16])?;
        let comb_buf = CudaBuffer::new(&device, comb_bytes.len())?;
        comb_buf.upload(&device, &comb_bytes)?;

        let seeds_ptr0 = seeds_buf.ptr;
        let hits_ptr0 = hits_buf.ptr;
        let hit_count_ptr0 = hit_count_buf.ptr;

        // Ping-pong streaming is a clear win at production batch sizes; opt out
        // with ERG_CUDA_OVERLAP=0.
        let overlap = std::env::var("ERG_CUDA_OVERLAP").as_deref() != Ok("0");
        let mut streams = [std::ptr::null_mut(); 2];
        let mut ev_seed_done = [std::ptr::null_mut(); 2];
        let mut ev_search_done = [std::ptr::null_mut(); 2];
        let mut pin_count = [std::ptr::null_mut(); 2];
        let mut pin_hits = [std::ptr::null_mut(); 2];
        if overlap {
            for s in streams.iter_mut() {
                check!(device.lib, cuStreamCreate, s, 0u32);
            }
            for e in ev_seed_done.iter_mut().chain(ev_search_done.iter_mut()) {
                check!(device.lib, cuEventCreate, e, 0u32);
            }
            for slot in 0..2 {
                check!(device.lib, cuMemAllocHost, &mut pin_count[slot], 16);
                check!(
                    device.lib,
                    cuMemAllocHost,
                    &mut pin_hits[slot],
                    MAX_HITS * 64
                );
                unsafe {
                    std::ptr::write_bytes(pin_count[slot] as *mut u8, 0, 16);
                }
            }
        }

        // Per-kernel block sizes: 128 measured fastest for the PBKDF2-
        // dominated seed kernel on sm_86; the search kernel matches the
        // OpenCL path's large work groups.
        // Defaults measured fastest on sm_86; overridable for other chips.
        let seed_local: usize = std::env::var("ERG_CUDA_SEED_LOCAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128);
        let search_local: usize = std::env::var("ERG_CUDA_SEARCH_LOCAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128);

        Ok(CudaVanityPipeline {
            seed_fn,
            search_fn,
            module,
            device,
            salt: salt_buf,
            words8: words8_buf,
            lens: lens_buf,
            seeds: seeds_buf,
            patterns: patterns_buf,
            pattern_offsets: offsets_buf,
            pattern_lens: lens_pat_buf,
            pattern_lower: lower_buf,
            pattern_upper: upper_buf,
            hits: hits_buf,
            hit_count: hit_count_buf,
            comb: comb_buf,
            batch_size: batch,
            num_indices: cfg.num_indices,
            ignore_case: cfg.ignore_case,
            patterns_cpu: patterns.to_vec(),
            pattern_index_map,
            match_type: cfg.match_type,
            seed_local,
            search_local,
            hits_dropped_total: 0,
            num_patterns: gpu_patterns.len() as u32,
            overlap,
            streams,
            ev_seed_done,
            ev_search_done,
            seeds_pp: [seeds_ptr0; 2],
            hits_pp: [hits_ptr0; 2],
            hit_count_pp: [hit_count_ptr0; 2],
            batch_index: 0,
            pending: None,
            pin_count,
            pin_hits,
        })
    }

    fn reset_hits(&self) -> Result<(), GpuError> {
        self.hit_count.upload(&self.device, &[0u8; 16])
    }

    pub fn run_batch_with_counter(
        &mut self,
        counter_start: u64,
    ) -> Result<Vec<VanityResult>, GpuError> {
        if self.overlap {
            // SAFETY: all raw launches use validated handles and matched args.
            return unsafe { self.run_batch_overlapped(counter_start) };
        }
        self.reset_hits()?;
        let skip_search = search_disabled();

        let mut salt_ptr = self.salt.ptr;
        let mut counter = counter_start;
        let mut words_ptr = self.words8.ptr;
        let mut lens_ptr = self.lens.ptr;
        let mut seeds_ptr = self.seeds.ptr;

        {
            let mut params: [*mut c_void; 5] = [
                &mut salt_ptr as *mut _ as *mut c_void,
                &mut counter as *mut _ as *mut c_void,
                &mut words_ptr as *mut _ as *mut c_void,
                &mut lens_ptr as *mut _ as *mut c_void,
                &mut seeds_ptr as *mut _ as *mut c_void,
            ];
            unsafe {
                launch(
                    &self.device,
                    self.seed_fn,
                    self.batch_size,
                    self.seed_local,
                    &mut params,
                )?;
            }
        }

        if skip_search {
            // Seed-only diagnostic mode: no search, no readback, no event.
            let out = Vec::new();
            self.batch_index += 1;
            return Ok(out);
        }
        let mut patterns_ptr = self.patterns.ptr;
        let mut offsets_ptr = self.pattern_offsets.ptr;
        let mut plens_ptr = self.pattern_lens.ptr;
        let mut lower_ptr = self.pattern_lower.ptr;
        let mut upper_ptr = self.pattern_upper.ptr;
        let mut num_patterns = self.num_patterns;
        let mut icase = if self.ignore_case { 1u32 } else { 0u32 };
        let mut nidx = self.num_indices;
        let mut hits_ptr = self.hits.ptr;
        let mut hc_ptr = self.hit_count.ptr;
        let mut max_hits = MAX_HITS as u32;
        let mut comb_ptr = self.comb.ptr;

        {
            let mut params: [*mut c_void; 15] = [
                &mut salt_ptr as *mut _ as *mut c_void,
                &mut counter as *mut _ as *mut c_void,
                &mut seeds_ptr as *mut _ as *mut c_void,
                &mut patterns_ptr as *mut _ as *mut c_void,
                &mut offsets_ptr as *mut _ as *mut c_void,
                &mut plens_ptr as *mut _ as *mut c_void,
                &mut lower_ptr as *mut _ as *mut c_void,
                &mut upper_ptr as *mut _ as *mut c_void,
                &mut num_patterns as *mut _ as *mut c_void,
                &mut icase as *mut _ as *mut c_void,
                &mut nidx as *mut _ as *mut c_void,
                &mut hits_ptr as *mut _ as *mut c_void,
                &mut hc_ptr as *mut _ as *mut c_void,
                &mut max_hits as *mut _ as *mut c_void,
                &mut comb_ptr as *mut _ as *mut c_void,
            ];
            unsafe {
                launch(
                    &self.device,
                    self.search_fn,
                    self.batch_size,
                    self.search_local,
                    &mut params,
                )?;
            }
        }

        // Read back hits
        let mut count_bytes = [0u8; 16];
        self.hit_count.download(&self.device, &mut count_bytes)?;
        let hit_count = i32::from_le_bytes(count_bytes[0..4].try_into().unwrap());
        if hit_count <= 0 {
            return Ok(Vec::new());
        }
        let dropped = (hit_count as usize).saturating_sub(MAX_HITS);
        if dropped > 0 {
            self.hits_dropped_total += dropped as u64;
        }
        let take = (hit_count as usize).min(MAX_HITS);
        let mut raw = vec![0u8; take * 64];
        self.hits.download(&self.device, &mut raw)?;

        let hits: Vec<GpuHit> = raw
            .as_chunks::<64>()
            .0
            .iter()
            .map(|c| unsafe { std::ptr::read(c.as_ptr() as *const GpuHit) })
            .collect();

        verify_hits_shared(
            &hits,
            &self.patterns_cpu,
            &self.pattern_index_map,
            self.match_type,
            self.ignore_case,
        )
    }

    pub fn hits_dropped_total(&self) -> u64 {
        self.hits_dropped_total
    }

    /// Ping-pong overlap: enqueue seed(n) on stream A and search(n) on stream
    /// B while batch n-1's results are verified on the host. seeds/hits/
    /// hit_count are double-buffered; results are returned one batch late.
    ///
    /// # Safety
    /// Raw pointer juggling mirrors the single-stream path; all launches go
    /// through `launch_on` with validated handles.
    unsafe fn run_batch_overlapped(
        &mut self,
        counter_start: u64,
    ) -> Result<Vec<VanityResult>, GpuError> {
        let slot = (self.batch_index % 2) as usize;
        let s_seed = self.streams[0];
        let s_search = self.streams[1];

        // Enqueue FIRST, harvest LAST: seed(n+1) overlaps search(n) on the
        // other stream - the whole point of the ping-pong.

        // 2) Free the slot: wait until search(n-2) finished reading it.
        if self.batch_index >= 2 {
            check!(
                self.device.lib,
                cuStreamWaitEvent,
                s_seed,
                self.ev_search_done[slot],
                0u32
            );
        }
        // Zero this slot's device-side hit counter on stream A; ordered
        // before seed(n), and search(n) is gated behind seed(n).
        let zeros = [0u8; 16];
        check!(
            self.device.lib,
            cuMemcpyHtoDAsync_v2,
            self.hit_count_pp[slot],
            zeros.as_ptr() as *const c_void,
            16usize,
            s_seed
        );

        // 3) Seed kernel on stream A.
        let mut salt_ptr = self.salt.ptr;
        let mut counter = counter_start;
        let mut words_ptr = self.words8.ptr;
        let mut lens_ptr = self.lens.ptr;
        let mut seeds_ptr = self.seeds_pp[slot];
        let mut params_a: [*mut c_void; 5] = [
            &mut salt_ptr as *mut _ as *mut c_void,
            &mut counter as *mut _ as *mut c_void,
            &mut words_ptr as *mut _ as *mut c_void,
            &mut lens_ptr as *mut _ as *mut c_void,
            &mut seeds_ptr as *mut _ as *mut c_void,
        ];
        launch_on(
            &self.device,
            self.seed_fn,
            self.batch_size,
            self.seed_local,
            s_seed,
            &mut params_a,
        )?;
        check!(
            self.device.lib,
            cuEventRecord,
            self.ev_seed_done[slot],
            s_seed
        );

        // 4) Search kernel on stream B, gated on the seed of THIS batch.
        let skip_search = search_disabled();
        check!(
            self.device.lib,
            cuStreamWaitEvent,
            s_search,
            self.ev_seed_done[slot],
            0u32
        );
        if skip_search {
            // Seed-only diagnostic mode: no search, no readback, no event.
            let out = Vec::new();
            self.batch_index += 1;
            return Ok(out);
        }
        let mut patterns_ptr = self.patterns.ptr;
        let mut offsets_ptr = self.pattern_offsets.ptr;
        let mut plens_ptr = self.pattern_lens.ptr;
        let mut lower_ptr = self.pattern_lower.ptr;
        let mut upper_ptr = self.pattern_upper.ptr;
        let mut num_patterns = self.num_patterns;
        let mut icase = if self.ignore_case { 1u32 } else { 0u32 };
        let mut nidx = self.num_indices;
        let mut hits_ptr = self.hits_pp[slot];
        let mut hc_ptr = self.hit_count_pp[slot];
        let mut max_hits = MAX_HITS as u32;
        let mut comb_ptr = self.comb.ptr;
        let mut params_b: [*mut c_void; 15] = [
            &mut salt_ptr as *mut _ as *mut c_void,
            &mut counter as *mut _ as *mut c_void,
            &mut seeds_ptr as *mut _ as *mut c_void,
            &mut patterns_ptr as *mut _ as *mut c_void,
            &mut offsets_ptr as *mut _ as *mut c_void,
            &mut plens_ptr as *mut _ as *mut c_void,
            &mut lower_ptr as *mut _ as *mut c_void,
            &mut upper_ptr as *mut _ as *mut c_void,
            &mut num_patterns as *mut _ as *mut c_void,
            &mut icase as *mut _ as *mut c_void,
            &mut nidx as *mut _ as *mut c_void,
            &mut hits_ptr as *mut _ as *mut c_void,
            &mut hc_ptr as *mut _ as *mut c_void,
            &mut max_hits as *mut _ as *mut c_void,
            &mut comb_ptr as *mut _ as *mut c_void,
        ];
        launch_on(
            &self.device,
            self.search_fn,
            self.batch_size,
            self.search_local,
            s_search,
            &mut params_b,
        )?;
        // Async readback of this slot's results on the same stream: by the
        // time ev_search_done fires, host staging is already filled.
        check!(
            self.device.lib,
            cuMemcpyDtoHAsync_v2,
            self.pin_count[slot],
            self.hit_count_pp[slot],
            16usize,
            s_search
        );
        check!(
            self.device.lib,
            cuMemcpyDtoHAsync_v2,
            self.pin_hits[slot],
            self.hits_pp[slot],
            MAX_HITS * 64usize,
            s_search
        );
        check!(
            self.device.lib,
            cuEventRecord,
            self.ev_search_done[slot],
            s_search
        );

        // Harvest batch n-1 WHILE the GPU chews on batch n.
        let mut out = Vec::new();
        if let Some(pending) = self.pending.take() {
            check!(
                self.device.lib,
                cuEventSynchronize,
                self.ev_search_done[pending.slot]
            );
            out = self.read_and_verify_pinned(pending.slot)?;
        }

        self.pending = Some(PendingBatch { slot });
        self.batch_index += 1;

        Ok(out)
    }

    /// Read results from PINNED host staging (filled by async copies that
    /// completed before ev_search_done fired).
    ///
    /// # Safety
    /// `pin_count`/`pin_hits` must have been filled by the matching async
    /// copies for `slot`, synchronized by the caller.
    unsafe fn read_and_verify_pinned(
        &mut self,
        slot: usize,
    ) -> Result<Vec<VanityResult>, GpuError> {
        let count_bytes = std::slice::from_raw_parts(self.pin_count[slot] as *const u8, 16);
        let hit_count = i32::from_le_bytes(count_bytes[0..4].try_into().unwrap());
        if hit_count <= 0 {
            // Clear the counter for the next use of this slot.
            std::ptr::write_bytes(self.pin_count[slot] as *mut u8, 0, 16);
            return Ok(Vec::new());
        }
        let dropped = (hit_count as usize).saturating_sub(MAX_HITS);
        if dropped > 0 {
            self.hits_dropped_total += dropped as u64;
        }
        // Reset counter staging for the next use of this slot.
        std::ptr::write_bytes(self.pin_count[slot] as *mut u8, 0, 16);
        let take = (hit_count as usize).min(MAX_HITS);
        let raw = std::slice::from_raw_parts(self.pin_hits[slot] as *const u8, take * 64);
        let mut hits = Vec::with_capacity(take);
        for c in raw.as_chunks::<64>().0 {
            let mut hit = GpuHit::default();
            let bytes: &[u8; 64] = c;
            // SAFETY: GpuHit is repr(C, align(16)), 64 bytes, plain data.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    &mut hit as *mut GpuHit as *mut u8,
                    64,
                )
            };
            hits.push(hit);
        }
        verify_hits_shared(
            &hits,
            &self.patterns_cpu,
            &self.pattern_index_map,
            self.match_type,
            self.ignore_case,
        )
    }
}

fn bytemuck_u32(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
