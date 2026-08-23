//! Backend dispatch: OpenCL (original) or CUDA (driver API + JIT'd PTX).
//!
//! Selection via `ERG_BACKEND`:
//!   - `opencl` (default): the original path, unchanged.
//!   - `cuda`: require the CUDA backend; error if unavailable.
//!   - `auto`: CUDA when built-in and a driver is present, else OpenCL.

use crate::context::{DeviceInfo, GpuError};
use crate::cuda::CudaVanityPipeline;
use crate::pipeline::{VanityConfig, VanityPipeline, VanityResult};

#[allow(clippy::large_enum_variant)]
pub enum AnyPipeline {
    Ocl(VanityPipeline),
    Cuda(CudaVanityPipeline),
}

/// Enumerate devices of the active backend, respecting `ERG_BACKEND`.
pub fn enumerate_devices() -> Result<Vec<DeviceInfo>, GpuError> {
    match backend_pref() {
        "cuda" => crate::cuda::CudaDevice::enumerate(),
        _ => {
            if crate::cuda::pipeline::CUDA_BUILT {
                // auto: report OpenCL devices (the default path) but note
                // CUDA availability separately in --list-devices.
            }
            crate::context::GpuContext::enumerate_devices()
        }
    }
}

/// Device-recommended batch size for the active backend.
///
/// Measured optimum differs: OpenCL likes 1M work items, CUDA peaks at
/// 512k with stream overlap enabled.
pub fn recommended_batch_size(device_index: usize) -> Result<usize, GpuError> {
    if backend_pref() == "cuda" {
        return Ok(1 << 19); // 524,288
    }
    Ok(crate::context::GpuContext::with_device(device_index)?.recommended_batch_size())
}

fn backend_pref() -> &'static str {
    static ONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| std::env::var("ERG_BACKEND").unwrap_or_else(|_| "auto".to_string()))
}

impl AnyPipeline {
    pub fn new_with_device_and_salt(
        patterns: &[String],
        cfg: VanityConfig,
        device_index: usize,
        salt: [u8; 32],
    ) -> Result<Self, GpuError> {
        let pref = backend_pref();
        // `auto` stays on the battle-tested OpenCL path; CUDA is opt-in
        // while it soaks (live parity today, kernel-level wins pending).
        let want_cuda = pref == "cuda";
        if want_cuda {
            match CudaVanityPipeline::new(patterns, cfg.clone(), device_index, salt) {
                Ok(p) => return Ok(AnyPipeline::Cuda(p)),
                Err(e) => {
                    if pref == "cuda" {
                        return Err(e);
                    }
                    eprintln!("CUDA backend unavailable ({e}); falling back to OpenCL");
                }
            }
        }
        Ok(AnyPipeline::Ocl(VanityPipeline::new_with_device_and_salt(
            patterns,
            cfg,
            device_index,
            salt,
        )?))
    }

    pub fn run_batch_with_counter(
        &mut self,
        counter_start: u64,
    ) -> Result<Vec<VanityResult>, GpuError> {
        match self {
            AnyPipeline::Ocl(p) => p.run_batch_with_counter(counter_start),
            AnyPipeline::Cuda(p) => p.run_batch_with_counter(counter_start),
        }
    }

    pub fn hits_dropped_total(&self) -> u64 {
        match self {
            AnyPipeline::Ocl(p) => p.hits_dropped_total(),
            AnyPipeline::Cuda(p) => p.hits_dropped_total(),
        }
    }

    /// Human-readable backend label for progress output.
    pub fn backend_name(&self) -> &'static str {
        match self {
            AnyPipeline::Ocl(_) => "gpu:opencl",
            AnyPipeline::Cuda(_) => "gpu:cuda",
        }
    }
}
