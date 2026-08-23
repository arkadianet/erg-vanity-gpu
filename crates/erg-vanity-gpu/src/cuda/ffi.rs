//! Minimal CUDA Driver API bindings loaded via dlopen.
//!
//! Deliberately no `-lcuda`: the backend activates only when a driver is
//! present at runtime, so OpenCL-only builds and machines stay unaffected.

use std::ffi::{c_char, c_int, c_uint, c_void};

pub type CuResult = c_int; // CUDA_SUCCESS == 0
pub type CuDevice = c_int;
pub type CuContext = *mut c_void;
pub type CuModule = *mut c_void;
pub type CuFunction = *mut c_void;
pub type CuStream = *mut c_void;
pub type CuDevicePtr = u64;
pub type CuEvent = *mut c_void;

// cuDeviceGetAttribute selectors
pub const CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT: c_uint = 16;
pub const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: c_uint = 75;
pub const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: c_uint = 76;

#[allow(non_snake_case)]
#[derive(Clone, Copy)]
pub struct LibCuda {
    pub cuInit: unsafe extern "C" fn(c_uint) -> CuResult,
    pub cuDeviceGetCount: unsafe extern "C" fn(*mut c_int) -> CuResult,
    pub cuDeviceGet: unsafe extern "C" fn(*mut CuDevice, c_int) -> CuResult,
    pub cuDeviceGetName: unsafe extern "C" fn(*mut c_char, c_int, CuDevice) -> CuResult,
    pub cuDeviceGetAttribute: unsafe extern "C" fn(*mut c_int, c_uint, CuDevice) -> CuResult,
    pub cuCtxCreate_v2: unsafe extern "C" fn(*mut CuContext, c_uint, CuDevice) -> CuResult,
    pub cuCtxSetCurrent: unsafe extern "C" fn(CuContext) -> CuResult,
    pub cuModuleLoadData: unsafe extern "C" fn(*mut CuModule, *const c_void) -> CuResult,
    pub cuModuleGetFunction:
        unsafe extern "C" fn(*mut CuFunction, CuModule, *const c_char) -> CuResult,
    pub cuMemAlloc_v2: unsafe extern "C" fn(*mut CuDevicePtr, usize) -> CuResult,
    pub cuMemFree_v2: unsafe extern "C" fn(CuDevicePtr) -> CuResult,
    pub cuMemAllocHost: unsafe extern "C" fn(*mut *mut c_void, usize) -> CuResult,
    pub cuMemFreeHost: unsafe extern "C" fn(*mut c_void) -> CuResult,
    pub cuMemcpyHtoDAsync_v2:
        unsafe extern "C" fn(CuDevicePtr, *const c_void, usize, CuStream) -> CuResult,
    pub cuMemcpyDtoHAsync_v2:
        unsafe extern "C" fn(*mut c_void, CuDevicePtr, usize, CuStream) -> CuResult,
    pub cuMemcpyHtoD_v2: unsafe extern "C" fn(CuDevicePtr, *const c_void, usize) -> CuResult,
    pub cuMemcpyDtoH_v2: unsafe extern "C" fn(*mut c_void, CuDevicePtr, usize) -> CuResult,
    pub cuStreamCreate: unsafe extern "C" fn(*mut CuStream, c_uint) -> CuResult,
    pub cuStreamSynchronize: unsafe extern "C" fn(CuStream) -> CuResult,
    pub cuStreamWaitEvent: unsafe extern "C" fn(CuStream, CuEvent, c_uint) -> CuResult,
    pub cuEventCreate: unsafe extern "C" fn(*mut CuEvent, c_uint) -> CuResult,
    pub cuEventRecord: unsafe extern "C" fn(CuEvent, CuStream) -> CuResult,
    pub cuEventSynchronize: unsafe extern "C" fn(CuEvent) -> CuResult,
    pub cuEventElapsedTime: unsafe extern "C" fn(*mut f32, CuEvent, CuEvent) -> CuResult,
    pub cuLaunchKernel: unsafe extern "C" fn(
        CuFunction,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        usize, // sharedMemBytes is size_t
        CuStream,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> CuResult,
}

unsafe extern "C" {
    #[link_name = "\u{1}dlopen"]
    fn sys_dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    #[link_name = "\u{1}dlsym"]
    fn sys_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Load libcuda and resolve every symbol we need. Err on any gap.
///
/// # Safety
/// dlopen/dlsym are inherently unsafe interfaces; we only read symbols whose
/// signatures match the documented CUDA Driver API.
pub unsafe fn load_libcuda() -> Result<LibCuda, String> {
    let mut handle = sys_dlopen(c"libcuda.so.1".as_ptr(), 2);
    if handle.is_null() {
        handle = sys_dlopen(c"libcuda.so".as_ptr(), 2);
    }
    if handle.is_null() {
        return Err("libcuda.so.1 not found (no NVIDIA driver?)".to_string());
    }
    macro_rules! sym {
        ($name:literal) => {{
            let p = sys_dlsym(handle, concat!($name, "\0").as_ptr() as *const c_char);
            if p.is_null() {
                return Err(concat!("libcuda missing symbol ", $name).to_string());
            }
            // Signature is enforced by the struct field this feeds.
            let p: *mut c_void = p;
            ::std::mem::transmute_copy::<*mut c_void, _>(&p)
        }};
    }
    Ok(LibCuda {
        cuInit: sym!("cuInit"),
        cuDeviceGetCount: sym!("cuDeviceGetCount"),
        cuDeviceGet: sym!("cuDeviceGet"),
        cuDeviceGetName: sym!("cuDeviceGetName"),
        cuDeviceGetAttribute: sym!("cuDeviceGetAttribute"),
        cuCtxCreate_v2: sym!("cuCtxCreate_v2"),
        cuCtxSetCurrent: sym!("cuCtxSetCurrent"),
        cuModuleLoadData: sym!("cuModuleLoadData"),
        cuModuleGetFunction: sym!("cuModuleGetFunction"),
        cuMemAllocHost: sym!("cuMemAllocHost_v2"),
        cuMemFreeHost: sym!("cuMemFreeHost"),
        cuMemcpyHtoDAsync_v2: sym!("cuMemcpyHtoDAsync_v2"),
        cuMemcpyDtoHAsync_v2: sym!("cuMemcpyDtoHAsync_v2"),
        cuMemAlloc_v2: sym!("cuMemAlloc_v2"),
        cuMemFree_v2: sym!("cuMemFree_v2"),
        cuMemcpyHtoD_v2: sym!("cuMemcpyHtoD_v2"),
        cuMemcpyDtoH_v2: sym!("cuMemcpyDtoH_v2"),
        cuStreamCreate: sym!("cuStreamCreate"),
        cuStreamSynchronize: sym!("cuStreamSynchronize"),
        cuStreamWaitEvent: sym!("cuStreamWaitEvent"),
        cuEventCreate: sym!("cuEventCreate"),
        cuEventRecord: sym!("cuEventRecord"),
        cuEventSynchronize: sym!("cuEventSynchronize"),
        cuEventElapsedTime: sym!("cuEventElapsedTime"),
        cuLaunchKernel: sym!("cuLaunchKernel"),
    })
}
