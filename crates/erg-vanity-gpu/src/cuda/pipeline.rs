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
}

struct PendingBatch {
    slot: usize,
    #[allow(dead_code)]
    counter_start: u64,
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
        let module = CudaModule::load_ptx(&device, VANITY_PTX)?;
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

        let overlap = std::env::var("ERG_CUDA_OVERLAP").as_deref() == Ok("1");
        let mut streams = [std::ptr::null_mut(); 2];
        let mut ev_seed_done = [std::ptr::null_mut(); 2];
        let mut ev_search_done = [std::ptr::null_mut(); 2];
        if overlap {
            for s in streams.iter_mut() {
                check!(device.lib, cuStreamCreate, s, 0u32);
            }
            for e in ev_seed_done.iter_mut().chain(ev_search_done.iter_mut()) {
                check!(device.lib, cuEventCreate, e, 0u32);
            }
        }

        // Per-kernel block sizes: 128 measured fastest for the PBKDF2-
        // dominated seed kernel on sm_86; the search kernel matches the
        // OpenCL path's large work groups.
        let seed_local = 128usize;
        let search_local = 256usize;

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
            .chunks_exact(64)
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

        // 1) Harvest the previous batch (same slot was already synchronized).
        let mut out = Vec::new();
        if let Some(pending) = self.pending.take() {
            check!(
                self.device.lib,
                cuEventSynchronize,
                self.ev_search_done[pending.slot]
            );
            out = self.read_and_verify(pending.slot)?;
        }

        // 2) Free the slot: wait until search(n-2) finished reading it.
        if self.batch_index >= 2 {
            check!(
                self.device.lib,
                cuStreamWaitEvent,
                s_seed,
                self.ev_search_done[slot],
                0u32
            );
        } else {
            // First use of this slot: clear its hit counter on the host side.
            let zeros = [0u8; 16];
            self.upload_raw(self.hit_count_pp[slot], &zeros)?;
        }

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
        check!(
            self.device.lib,
            cuStreamWaitEvent,
            s_search,
            self.ev_seed_done[slot],
            0u32
        );
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
        check!(
            self.device.lib,
            cuEventRecord,
            self.ev_search_done[slot],
            s_search
        );

        self.pending = Some(PendingBatch {
            slot,
            counter_start,
        });
        self.batch_index += 1;

        Ok(out)
    }

    fn read_and_verify(&mut self, slot: usize) -> Result<Vec<VanityResult>, GpuError> {
        let mut count_bytes = [0u8; 16];
        self.download_raw(self.hit_count_pp[slot], &mut count_bytes)?;
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
        self.download_raw(self.hits_pp[slot], &mut raw)?;
        let mut hits = Vec::with_capacity(take);
        for c in raw.chunks_exact(64) {
            let mut hit = GpuHit::default();
            let bytes: &[u8; 64] = c.try_into().unwrap();
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

    fn upload_raw(&self, dst: CuDevicePtr, data: &[u8]) -> Result<(), GpuError> {
        check!(
            self.device.lib,
            cuMemcpyHtoD_v2,
            dst,
            data.as_ptr() as *const c_void,
            data.len()
        );
        Ok(())
    }

    fn download_raw(&self, src: CuDevicePtr, out: &mut [u8]) -> Result<(), GpuError> {
        check!(
            self.device.lib,
            cuMemcpyDtoH_v2,
            out.as_mut_ptr() as *mut c_void,
            src,
            out.len()
        );
        Ok(())
    }
}

fn bytemuck_u32(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
