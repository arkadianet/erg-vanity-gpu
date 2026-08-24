//! CUDA implementation of `--bench`, mirroring `bench.rs` semantics:
//! per-component event timing over the same bench kernels with the same
//! uniform signature.

use super::check;
use super::{launch, CudaBuffer, CudaDevice, CudaModule};
use crate::bench::{BenchConfig, DeviceBenchStats};
use crate::comb::load_comb_table;
use crate::context::GpuError;
use crate::cuda::ffi::{CuEvent, CuFunction, CuStream};
use crate::wordlist::{generate_word_lens, generate_words_data};
use std::ffi::c_uint;
use std::ffi::c_void;

struct EventPair {
    beg: CuEvent,
    end: CuEvent,
}

impl EventPair {
    fn new(dev: &CudaDevice) -> Result<Self, GpuError> {
        let mut beg = std::ptr::null_mut();
        let mut end = std::ptr::null_mut();
        // CU_EVENT_DEFAULT == 0
        check!(dev.lib, cuEventCreate, &mut beg, 0u32);
        check!(dev.lib, cuEventCreate, &mut end, 0u32);
        Ok(EventPair { beg, end })
    }

    fn elapsed_ms(&self, dev: &CudaDevice) -> Result<f32, GpuError> {
        let mut ms = 0f32;
        check!(dev.lib, cuEventElapsedTime, &mut ms, self.beg, self.end);
        Ok(ms)
    }
}

#[allow(clippy::too_many_arguments)]
fn launch6(
    dev: &CudaDevice,
    f: CuFunction,
    global: usize,
    local: usize,
    salt: &mut u64,
    counter: &mut u64,
    words: &mut u64,
    lens: &mut u64,
    nidx: &mut u32,
    sums: &mut u64,
) -> Result<(), GpuError> {
    if std::env::var("ERG_CUDA_DEBUG").is_ok() {
        eprintln!(
            "pbkdf2 args: salt={:#x} counter={} words={:#x} lens={:#x} nidx={} sums={:#x} grid={}",
            salt,
            counter,
            words,
            lens,
            nidx,
            sums,
            (global as c_uint).div_ceil((local as c_uint).max(1))
        );
    }
    let mut params: [*mut c_void; 6] = [
        salt as *mut u64 as *mut c_void,
        counter as *mut u64 as *mut c_void,
        words as *mut u64 as *mut c_void,
        lens as *mut u64 as *mut c_void,
        nidx as *mut u32 as *mut c_void,
        sums as *mut u64 as *mut c_void,
    ];
    unsafe { launch(dev, f, global, local, &mut params) }
}

#[allow(clippy::too_many_arguments)]
fn launch7(
    dev: &CudaDevice,
    f: CuFunction,
    global: usize,
    local: usize,
    stream: CuStream,
    salt: &mut u64,
    counter: &mut u64,
    words: &mut u64,
    lens: &mut u64,
    nidx: &mut u32,
    sums: &mut u64,
    comb: &mut u64,
) -> Result<(), GpuError> {
    if std::env::var("ERG_CUDA_DEBUG").is_ok() {
        eprintln!("bip32-class args: salt={:#x} words={:#x} lens={:#x} sums={:#x} comb={:#x} nidx={} grid={}", salt, words, lens, sums, comb, nidx, (global as c_uint).div_ceil((local as c_uint).max(1)));
    }
    let mut params: [*mut c_void; 7] = [
        salt as *mut u64 as *mut c_void,
        counter as *mut u64 as *mut c_void,
        words as *mut u64 as *mut c_void,
        lens as *mut u64 as *mut c_void,
        nidx as *mut u32 as *mut c_void,
        sums as *mut u64 as *mut c_void,
        comb as *mut u64 as *mut c_void,
    ];
    // Launch on an explicit stream via the raw entry point.
    let lx: c_uint = local as c_uint;
    let gx: c_uint = (global as c_uint).div_ceil(lx.max(1));
    check!(
        dev.lib,
        cuLaunchKernel,
        f,
        gx,
        1u32,
        1u32,
        lx,
        1u32,
        1u32,
        0usize,
        stream,
        params.as_mut_ptr(),
        std::ptr::null_mut()
    );
    Ok(())
}

/// Run the component benchmark on CUDA device `device_index`.
pub fn run_bench_cuda(
    device_index: usize,
    cfg: &BenchConfig,
) -> Result<DeviceBenchStats, GpuError> {
    if !super::pipeline::CUDA_BUILT {
        return Err(GpuError::Other(
            "CUDA backend not built into this binary".to_string(),
        ));
    }
    let device = CudaDevice::open(device_index)?;
    eprintln!("Compiling CUDA module from embedded PTX...");
    let module = CudaModule::load_ptx(&device, super::pipeline::vanity_ptx())?;
    let f_pbkdf2 = module.function(&device, "bench_pbkdf2")?;
    let f_bip32 = module.function(&device, "bench_bip32")?;
    let f_secp = module.function(&device, "bench_secp256k1")?;
    let f_base58 = module.function(&device, "bench_base58")?;

    let batch = cfg.batch_size;
    let words8 = generate_words_data();
    let lens = generate_word_lens();
    let comb_bytes: Vec<u8> = load_comb_table()
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();

    let salt_buf = CudaBuffer::new(&device, 32)?;
    salt_buf.upload(&device, &[0x42u8; 32])?;
    let checksums = CudaBuffer::new(&device, batch * 4)?;
    let words8_buf = CudaBuffer::new(&device, words8.len())?;
    words8_buf.upload(&device, &words8)?;
    let lens_buf = CudaBuffer::new(&device, lens.len())?;
    lens_buf.upload(&device, &lens)?;
    let comb_buf = CudaBuffer::new(&device, comb_bytes.len())?;
    comb_buf.upload(&device, &comb_bytes)?;

    // Pointer staging (values set fresh before each launch).
    let mut salt_ptr = salt_buf.ptr;
    let mut words_ptr = words8_buf.ptr;
    let mut lens_ptr = lens_buf.ptr;
    let mut sums_ptr = checksums.ptr;
    let mut comb_ptr = comb_buf.ptr;

    // `needs_comb` selects the 7-arg kernels (bip32/secp/base58); pbkdf2 has 6.
    let mut time_kernel = |f: CuFunction,
                           dev: &CudaDevice,
                           ev: &EventPair,
                           needs_comb: bool,
                           counter_start: u64|
     -> Result<u64, GpuError> {
        let mut counter = counter_start;
        let mut nidx = cfg.num_indices;
        {
            check!(dev.lib, cuEventRecord, ev.beg, std::ptr::null_mut());
            if needs_comb {
                launch7(
                    dev,
                    f,
                    batch,
                    128,
                    std::ptr::null_mut(),
                    &mut salt_ptr,
                    &mut counter,
                    &mut words_ptr,
                    &mut lens_ptr,
                    &mut nidx,
                    &mut sums_ptr,
                    &mut comb_ptr,
                )?;
            } else {
                launch6(
                    dev,
                    f,
                    batch,
                    128,
                    &mut salt_ptr,
                    &mut counter,
                    &mut words_ptr,
                    &mut lens_ptr,
                    &mut nidx,
                    &mut sums_ptr,
                )?;
            }
            check!(dev.lib, cuEventRecord, ev.end, std::ptr::null_mut());
        }
        check!(dev.lib, cuEventSynchronize, ev.end);
        let ms = ev.elapsed_ms(dev)?;
        Ok((ms * 1e6) as u64)
    };

    let ev_pbkdf2 = EventPair::new(&device)?;
    let ev_bip32 = EventPair::new(&device)?;
    let ev_secp = EventPair::new(&device)?;
    let ev_b58 = EventPair::new(&device)?;

    // Warmup
    for i in 0..cfg.warmup {
        let c = i as u64 * batch as u64;
        time_kernel(f_pbkdf2, &device, &ev_pbkdf2, false, c)?;
        time_kernel(f_bip32, &device, &ev_bip32, true, c)?;
        time_kernel(f_secp, &device, &ev_secp, true, c)?;
        time_kernel(f_base58, &device, &ev_b58, true, c)?;
    }

    let mut pbkdf2_ns = 0u64;
    let mut bip32_ns = 0u64;
    let mut secp_ns = 0u64;
    let mut b58_ns = 0u64;
    for i in cfg.warmup..cfg.warmup + cfg.iters {
        let c = i as u64 * batch as u64;
        pbkdf2_ns += time_kernel(f_pbkdf2, &device, &ev_pbkdf2, false, c)?;
        bip32_ns += time_kernel(f_bip32, &device, &ev_bip32, true, c)?;
        secp_ns += time_kernel(f_secp, &device, &ev_secp, true, c)?;
        b58_ns += time_kernel(f_base58, &device, &ev_b58, true, c)?;
    }

    if cfg.validate {
        let mut out = vec![0u8; 16];
        checksums.download(&device, &mut out)?;
        let any = out.iter().any(|&b| b != 0);
        if !any {
            return Err(GpuError::Other(
                "CUDA bench validation failed (zero checksums)".into(),
            ));
        }
    }

    Ok(DeviceBenchStats {
        device_info: device.info.clone(),
        pbkdf2: crate::bench::ComponentStats {
            total_ns: pbkdf2_ns,
            count: cfg.iters,
        },
        bip32: crate::bench::ComponentStats {
            total_ns: bip32_ns,
            count: cfg.iters,
        },
        secp256k1: crate::bench::ComponentStats {
            total_ns: secp_ns,
            count: cfg.iters,
        },
        base58: crate::bench::ComponentStats {
            total_ns: b58_ns,
            count: cfg.iters,
        },
    })
}
