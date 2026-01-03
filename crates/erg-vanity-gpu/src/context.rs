//! OpenCL context setup.
//!
//! Handles platform/device discovery, context creation, and command queue setup.

use ocl::{Context, Device, DeviceType, Platform, Queue};
use thiserror::Error;

/// GPU context errors.
#[derive(Debug, Error)]
pub enum GpuError {
    #[error("No OpenCL platforms found")]
    NoPlatforms,
    #[error("No GPU devices found")]
    NoDevices,
    #[error("Device index {0} out of range (found {1} devices)")]
    DeviceIndexOutOfRange(usize, usize),
    #[error("OpenCL error: {0}")]
    Ocl(#[from] ocl::Error),
    #[error("{0}")]
    Other(String),
}

/// Information about an available GPU device.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    /// Global index across all platforms (for CLI selection)
    pub global_idx: usize,
    /// Platform index
    pub platform_idx: usize,
    /// Device index within GPU list for that platform
    pub device_idx: usize,
    /// Platform name
    pub platform_name: String,
    /// Device name
    pub device_name: String,
    /// Device vendor
    pub vendor: String,
    /// Max compute units
    pub compute_units: u32,
    /// Max work group size
    pub max_work_group_size: usize,
    /// Global memory size in bytes
    pub global_mem_size: u64,
    /// Local memory size in bytes
    pub local_mem_size: u64,
}

/// OpenCL GPU context.
pub struct GpuContext {
    /// The OpenCL context
    context: Context,
    /// The selected device
    device: Device,
    /// Command queue for the device
    queue: Queue,
    /// Device information
    info: DeviceInfo,
}

impl GpuContext {
    /// Create a new GPU context with the first available GPU.
    pub fn new() -> Result<Self, GpuError> {
        let devices = Self::enumerate_devices()?;
        if devices.is_empty() {
            return Err(GpuError::NoDevices);
        }
        Self::with_device(0)
    }

    /// Create a GPU context with a specific device index (global index).
    pub fn with_device(global_selection: usize) -> Result<Self, GpuError> {
        Self::with_device_impl(global_selection, false)
    }

    /// Create a GPU context with profiling enabled (for benchmark mode).
    pub fn with_device_profiling(global_selection: usize) -> Result<Self, GpuError> {
        Self::with_device_impl(global_selection, true)
    }

    /// Internal implementation for creating GPU context with optional profiling.
    fn with_device_impl(global_selection: usize, enable_profiling: bool) -> Result<Self, GpuError> {
        let devices = Self::enumerate_devices()?;
        let info = devices
            .get(global_selection)
            .ok_or(GpuError::DeviceIndexOutOfRange(
                global_selection,
                devices.len(),
            ))?
            .clone();

        let platforms = Platform::list();
        let platform = *platforms
            .get(info.platform_idx)
            .ok_or(GpuError::NoPlatforms)?;

        let gpus = Device::list(platform, Some(DeviceType::GPU))?;
        let device = gpus
            .get(info.device_idx)
            .cloned()
            .ok_or(GpuError::NoDevices)?;

        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;

        let queue_props = if enable_profiling {
            Some(ocl::flags::CommandQueueProperties::PROFILING_ENABLE)
        } else {
            None
        };
        let queue = Queue::new(&context, device, queue_props)?;

        Ok(Self {
            context,
            device,
            queue,
            info,
        })
    }

    /// Enumerate all available GPU devices.
    pub fn enumerate_devices() -> Result<Vec<DeviceInfo>, GpuError> {
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err(GpuError::NoPlatforms);
        }

        let mut out = Vec::new();
        let mut global_idx = 0usize;

        for (platform_idx, platform) in platforms.iter().enumerate() {
            let platform_name = platform
                .info(ocl::enums::PlatformInfo::Name)
                .map(|i| i.to_string())
                .unwrap_or_else(|_| "Unknown".into());

            let gpus = Device::list(*platform, Some(DeviceType::GPU)).unwrap_or_default();

            for (device_idx, device) in gpus.iter().enumerate() {
                let device_name = device
                    .info(ocl::enums::DeviceInfo::Name)
                    .map(|i| i.to_string())
                    .unwrap_or_else(|_| "Unknown".into());

                let vendor = device
                    .info(ocl::enums::DeviceInfo::Vendor)
                    .map(|i| i.to_string())
                    .unwrap_or_else(|_| "Unknown".into());

                let compute_units = device
                    .info(ocl::enums::DeviceInfo::MaxComputeUnits)
                    .map(|i| match i {
                        ocl::enums::DeviceInfoResult::MaxComputeUnits(n) => n,
                        _ => 0,
                    })
                    .unwrap_or(0);

                let max_work_group_size = device
                    .info(ocl::enums::DeviceInfo::MaxWorkGroupSize)
                    .map(|i| match i {
                        ocl::enums::DeviceInfoResult::MaxWorkGroupSize(n) => n,
                        _ => 256,
                    })
                    .unwrap_or(256);

                let global_mem_size = device
                    .info(ocl::enums::DeviceInfo::GlobalMemSize)
                    .map(|i| match i {
                        ocl::enums::DeviceInfoResult::GlobalMemSize(n) => n,
                        _ => 0,
                    })
                    .unwrap_or(0);

                let local_mem_size = device
                    .info(ocl::enums::DeviceInfo::LocalMemSize)
                    .map(|i| match i {
                        ocl::enums::DeviceInfoResult::LocalMemSize(n) => n,
                        _ => 0,
                    })
                    .unwrap_or(0);

                out.push(DeviceInfo {
                    global_idx,
                    platform_idx,
                    device_idx,
                    platform_name: platform_name.clone(),
                    device_name,
                    vendor,
                    compute_units,
                    max_work_group_size,
                    global_mem_size,
                    local_mem_size,
                });

                global_idx += 1;
            }
        }

        Ok(out)
    }

    /// Get the OpenCL context.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Get the selected device.
    pub fn device(&self) -> Device {
        self.device
    }

    /// Get the command queue.
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Get device information.
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    /// Get recommended work group size for this device.
    pub fn recommended_work_group_size(&self) -> usize {
        let max = self.info.max_work_group_size.max(1);
        std::cmp::min(256, max)
    }

    /// Get recommended global work size (batch size).
    ///
    /// Based on compute units and a multiplier for good occupancy.
    pub fn recommended_batch_size(&self) -> usize {
        // Aim for good occupancy: compute_units * waves_per_cu * work_group_size
        let work_group_size = self.recommended_work_group_size();
        let waves_per_cu = 4; // Target 4 wavefronts per CU
        let batch = (self.info.compute_units as usize).max(1) * waves_per_cu * work_group_size;

        // Round up to nice power of 2, cap at 1M
        let batch = batch.next_power_of_two();
        std::cmp::min(batch, 1 << 20) // 1M max
    }
}

impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} - {} ({} CUs, {} MB global, {} KB local)",
            self.global_idx,
            self.vendor.trim(),
            self.device_name.trim(),
            self.compute_units,
            self.global_mem_size / (1024 * 1024),
            self.local_mem_size / 1024
        )
    }
}

/// Try to create a GPU context, returning None if no device available.
/// Use this in tests to gracefully skip when no GPU is present.
/// Also catches panics from the OpenCL library (e.g., no ICD installed).
#[cfg(test)]
pub(crate) fn try_ctx() -> Option<GpuContext> {
    match std::panic::catch_unwind(GpuContext::new) {
        Ok(Ok(ctx)) => Some(ctx),
        Ok(Err(e)) => {
            eprintln!("Skipping GPU test (no OpenCL device available): {e}");
            None
        }
        Err(_) => {
            eprintln!("Skipping GPU test (OpenCL runtime panicked - likely no ICD installed)");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_devices() {
        // Test that enumeration doesn't crash, regardless of device count
        // Catch panics from OpenCL library (e.g., no ICD installed)
        match std::panic::catch_unwind(GpuContext::enumerate_devices) {
            Ok(Ok(devices)) => {
                println!("OpenCL devices found: {}", devices.len());
                for dev in &devices {
                    println!("  {}", dev);
                }
            }
            Ok(Err(e)) => {
                eprintln!("Skipping enumerate_devices test: {e}");
            }
            Err(_) => {
                eprintln!("Skipping enumerate_devices test (OpenCL runtime panicked)");
            }
        }
    }

    #[test]
    fn test_create_context() {
        let Some(ctx) = try_ctx() else { return };
        println!("Created context for: {}", ctx.info());
        println!(
            "Recommended work group size: {}",
            ctx.recommended_work_group_size()
        );
        println!("Recommended batch size: {}", ctx.recommended_batch_size());
    }
}
