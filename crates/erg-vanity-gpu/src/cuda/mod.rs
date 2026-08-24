//! CUDA backend: device/context/module/buffer wrappers over the driver API.
//!
//! Mirrors just enough of the ocl surface for `CudaVanityPipeline`. All
//! launches go to the default (NULL) stream, matching the in-order OpenCL
//! queue semantics the rest of the code assumes.

use self::ffi::{CuDevice, CuDevicePtr, CuFunction, CuModule, CuStream};
use crate::context::{DeviceInfo, GpuError};
use std::ffi::{c_char, c_int, c_uint, c_void};

pub mod bench;
pub mod ffi;
pub mod pipeline;

pub use pipeline::CudaVanityPipeline;

pub(crate) const CUDA_SUCCESS: i32 = 0;

pub(crate) fn err(op: &str, code: i32) -> GpuError {
    GpuError::Other(format!("CUDA {op} failed with error {code}"))
}

macro_rules! check {
    ($lib:expr, $op:ident, $($args:expr),* $(,)?) => {{
        // SAFETY: symbols resolved from a live libcuda handle at init.
        let rc = unsafe { ($lib.$op)($($args),*) };
        if rc != $crate::cuda::CUDA_SUCCESS {
            return Err($crate::cuda::err(stringify!($op), rc));
        }
    }};
}
pub(crate) use check;

pub struct CudaDevice {
    pub lib: ffi::LibCuda,
    pub ctx: ffi::CuContext,
    pub info: DeviceInfo,
}

impl CudaDevice {
    /// Enumerate CUDA devices without creating contexts.
    pub fn enumerate() -> Result<Vec<DeviceInfo>, GpuError> {
        let lib = unsafe { ffi::load_libcuda() }.map_err(GpuError::Other)?;
        check!(lib, cuInit, 0u32);
        let mut count: c_int = 0;
        check!(lib, cuDeviceGetCount, &mut count);
        let mut out = Vec::new();
        for idx in 0..count {
            let mut dev: CuDevice = 0;
            if unsafe { (lib.cuDeviceGet)(&mut dev, idx) } != CUDA_SUCCESS {
                continue;
            }
            out.push(Self::describe(&lib, dev, idx as usize));
        }
        Ok(out)
    }

    fn attr(lib: &ffi::LibCuda, dev: CuDevice, which: c_uint) -> i32 {
        let mut v: c_int = 0;
        // SAFETY: valid device handle from cuDeviceGet.
        let _ = unsafe { (lib.cuDeviceGetAttribute)(&mut v, which, dev) };
        v
    }

    fn describe(lib: &ffi::LibCuda, dev: CuDevice, ordinal: usize) -> DeviceInfo {
        let mut name = [0 as c_char; 128];
        // SAFETY: valid device and buffer.
        unsafe { (lib.cuDeviceGetName)(name.as_mut_ptr(), 128, dev) };
        let device_name: String = unsafe {
            std::ffi::CStr::from_ptr(name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let sm_count = Self::attr(lib, dev, ffi::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT);
        let _major = Self::attr(lib, dev, ffi::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR);
        let _minor = Self::attr(lib, dev, ffi::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR);
        DeviceInfo {
            global_idx: ordinal,
            platform_idx: 0,
            device_idx: ordinal,
            platform_name: "NVIDIA CUDA".to_string(),
            device_name,
            vendor: "NVIDIA".to_string(),
            compute_units: u32::try_from(sm_count).unwrap_or(1),
            max_clock_mhz: None,
            max_work_group_size: 1024,
            global_mem_size: 0,
            local_mem_size: 48 << 10,
        }
    }

    /// Open device `ordinal` and create a context (SPIN sched: lowest sync latency).
    pub fn open(ordinal: usize) -> Result<Self, GpuError> {
        let lib = unsafe { ffi::load_libcuda() }.map_err(GpuError::Other)?;
        check!(lib, cuInit, 0u32);
        let mut dev: CuDevice = 0;
        check!(lib, cuDeviceGet, &mut dev, ordinal as c_int);
        let info = Self::describe(&lib, dev, ordinal);
        const CU_CTX_SCHED_SPIN: c_uint = 0x01;
        let mut ctx: ffi::CuContext = std::ptr::null_mut();
        check!(lib, cuCtxCreate_v2, &mut ctx, CU_CTX_SCHED_SPIN, dev);
        Ok(CudaDevice { lib, ctx, info })
    }
}

impl Drop for CudaDevice {
    fn drop(&mut self) {
        // Declared-last field of the owning structs, so buffers/streams/
        // events have already released everything tied to this context.
        // SAFETY: ctx came from cuCtxCreate_v2 and is destroyed once.
        unsafe { (self.lib.cuCtxDestroy_v2)(self.ctx) };
    }
}

pub struct CudaBuffer {
    pub ptr: CuDevicePtr,
    pub size: usize,
    /// Kept so `Drop` can free even if the device struct moved on.
    lib: ffi::LibCuda,
}

impl CudaBuffer {
    pub fn new(dev: &CudaDevice, size: usize) -> Result<Self, GpuError> {
        let mut ptr: CuDevicePtr = 0;
        check!(dev.lib, cuMemAlloc_v2, &mut ptr, size);
        Ok(CudaBuffer {
            ptr,
            size,
            lib: dev.lib,
        })
    }

    pub fn upload(&self, dev: &CudaDevice, data: &[u8]) -> Result<(), GpuError> {
        assert!(data.len() <= self.size);
        check!(
            dev.lib,
            cuMemcpyHtoD_v2,
            self.ptr,
            data.as_ptr() as *const c_void,
            data.len()
        );
        Ok(())
    }

    pub fn download(&self, dev: &CudaDevice, out: &mut [u8]) -> Result<(), GpuError> {
        assert!(out.len() <= self.size);
        check!(
            dev.lib,
            cuMemcpyDtoH_v2,
            out.as_mut_ptr() as *mut c_void,
            self.ptr,
            out.len()
        );
        Ok(())
    }
}

impl Drop for CudaBuffer {
    fn drop(&mut self) {
        if self.ptr != 0 {
            // SAFETY: ptr came from cuMemAlloc_v2 and is freed exactly once.
            unsafe { (self.lib.cuMemFree_v2)(self.ptr) };
        }
    }
}

pub struct CudaModule {
    module: CuModule,
}

impl CudaModule {
    /// Load PTX (driver expects a NUL-terminated image).
    pub fn load_ptx(dev: &CudaDevice, ptx: &[u8]) -> Result<Self, GpuError> {
        let mut img = ptx.to_vec();
        img.push(0);
        let mut module: CuModule = std::ptr::null_mut();
        check!(
            dev.lib,
            cuModuleLoadData,
            &mut module,
            img.as_ptr() as *const c_void
        );
        Ok(CudaModule { module })
    }

    pub fn function(&self, dev: &CudaDevice, name: &str) -> Result<CuFunction, GpuError> {
        let cname =
            std::ffi::CString::new(name).map_err(|_| GpuError::Other("bad kernel name".into()))?;
        let mut f: CuFunction = std::ptr::null_mut();
        check!(
            dev.lib,
            cuModuleGetFunction,
            &mut f,
            self.module,
            cname.as_ptr()
        );
        Ok(f)
    }
}

/// Launch on an explicit stream. See `launch` for semantics.
///
/// # Safety
/// Same requirements as `launch`.
pub unsafe fn launch_on(
    dev: &CudaDevice,
    func: CuFunction,
    global: usize,
    local: usize,
    stream: CuStream,
    params: &mut [*mut c_void],
) -> Result<(), GpuError> {
    if local == 0 {
        return Err(GpuError::Other(
            "launch local size must be >= 1 (cuLaunchKernel has no automatic block size)".into(),
        ));
    }

    let lx = c_uint::try_from(local).map_err(|_| GpuError::Other("block too large".into()))?;
    let blocks = global.div_ceil(local);
    let gx = c_uint::try_from(blocks).map_err(|_| GpuError::Other("grid too large".into()))?;
    check!(
        dev.lib,
        cuLaunchKernel,
        func,
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

/// Launch on the default stream with OpenCL semantics: `global` is the TOTAL
/// thread count and `local` the block size (`0` lets the driver choose).
///
/// # Safety
/// `func` must come from `CudaModule::function` of a loaded module and params
/// must match the kernel signature.
pub unsafe fn launch(
    dev: &CudaDevice,
    func: CuFunction,
    global: usize,
    local: usize,
    params: &mut [*mut c_void],
) -> Result<(), GpuError> {
    if local == 0 {
        return Err(GpuError::Other(
            "launch local size must be >= 1 (cuLaunchKernel has no automatic block size)".into(),
        ));
    }

    let lx = c_uint::try_from(local).map_err(|_| GpuError::Other("block too large".into()))?;
    let blocks = global.div_ceil(local);
    let gx = c_uint::try_from(blocks).map_err(|_| GpuError::Other("grid too large".into()))?;
    check!(
        dev.lib,
        cuLaunchKernel,
        func,
        gx,
        1u32,
        1u32,
        lx,
        1u32,
        1u32,
        0usize,
        std::ptr::null_mut::<c_void>(),
        params.as_mut_ptr(),
        std::ptr::null_mut()
    );
    Ok(())
}
