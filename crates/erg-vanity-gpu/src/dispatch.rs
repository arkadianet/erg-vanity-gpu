//! Backend dispatch: OpenCL (original) or CUDA (driver API + JIT'd PTX).
//!
//! Selection via `ERG_BACKEND`:
//!   - `opencl` (default for `auto`, and explicit): the original path.
//!   - `cuda`: require the CUDA backend; error if unavailable.

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
        // `auto` runs OpenCL; CUDA devices are listed separately by
        // --list-devices when ERG_CUDA_* users ask for them.
        _ => crate::context::GpuContext::enumerate_devices(),
    }
}

/// Device-recommended batch size for the active backend.
///
/// Measured optimum differs: OpenCL likes 1M work items, CUDA peaks at
/// 512k with stream overlap enabled.
pub fn recommended_batch_size(device_index: usize) -> Result<usize, GpuError> {
    if backend_pref() == "cuda" {
        return Ok(1 << 20); // 1,048,576 - pairs best with stream overlap
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
            // Explicit cuda selection: errors propagate, no silent fallback.
            return CudaVanityPipeline::new(patterns, cfg.clone(), device_index, salt)
                .map(AnyPipeline::Cuda);
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

    /// Return the final in-flight batch (CUDA ping-pong keeps one pending;
    /// OpenCL batches are returned immediately, so this is a no-op there).
    pub fn drain(&mut self) -> Result<Vec<VanityResult>, GpuError> {
        match self {
            AnyPipeline::Ocl(p) => p.drain(),
            AnyPipeline::Cuda(p) => p.drain(),
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
