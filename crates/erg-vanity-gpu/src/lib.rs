//! GPU-accelerated vanity address generation via OpenCL.

pub mod bench;
pub mod buffers;
pub mod comb;
pub mod context;
/// CUDA backend: Linux-only (driver API loaded via dlopen of
/// libcuda.so.1, POSIX ulong). Other targets get `stub.rs`, which keeps
/// the API surface compiling and reports unavailability at run time.
#[cfg(target_os = "linux")]
#[path = "cuda/mod.rs"]
pub mod cuda;
#[cfg(not(target_os = "linux"))]
#[path = "cuda/stub.rs"]
pub mod cuda;
pub mod dispatch;
pub mod kernel;
pub mod pipeline;
pub mod wordlist;
