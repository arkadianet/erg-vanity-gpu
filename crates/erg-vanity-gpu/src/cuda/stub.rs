//! Compile-time placeholder for the CUDA backend on non-Linux targets.
//!
//! The real backend dlopens `libcuda.so.1` and relies on POSIX `ulong`,
//! so its FFI only links on Linux. Everywhere else these same-shaped
//! stubs keep the public API compiling and report unavailability at
//! run time instead.

use crate::context::{DeviceInfo, GpuError};
use crate::pipeline::{VanityConfig, VanityResult};

fn unavailable() -> GpuError {
    GpuError::Other(
        "CUDA backend requires Linux (dlopen of libcuda.so.1); this binary is OpenCL-only"
            .to_string(),
    )
}

pub struct CudaDevice;

impl CudaDevice {
    pub fn enumerate() -> Result<Vec<DeviceInfo>, GpuError> {
        Err(unavailable())
    }
}

pub struct CudaVanityPipeline;

impl CudaVanityPipeline {
    pub fn new(
        _patterns: &[String],
        _cfg: VanityConfig,
        _device_index: usize,
        _salt: [u8; 32],
    ) -> Result<Self, GpuError> {
        Err(unavailable())
    }

    pub fn run_batch_with_counter(
        &mut self,
        _counter_start: u64,
    ) -> Result<Vec<VanityResult>, GpuError> {
        Err(unavailable())
    }

    pub fn drain(&mut self) -> Result<Vec<VanityResult>, GpuError> {
        Ok(Vec::new())
    }

    pub fn hits_dropped_total(&self) -> u64 {
        0
    }
}

pub mod pipeline {
    /// The stub never embeds PTX.
    pub const CUDA_BUILT: bool = false;
}

pub mod bench {
    use super::unavailable;
    use crate::bench::{BenchConfig, DeviceBenchStats};
    use crate::context::GpuError;

    pub fn run_bench_cuda(
        _device_index: usize,
        _cfg: &BenchConfig,
    ) -> Result<DeviceBenchStats, GpuError> {
        Err(unavailable())
    }
}
