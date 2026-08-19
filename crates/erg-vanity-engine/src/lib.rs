//! Shared vanity search engine used by the CLI and GUI.

#![forbid(unsafe_code)]

pub mod estimate;
pub mod search;
pub mod verify;

pub use estimate::{
    estimate_pattern, format_time, PatternEstimate, CPU_ASSUMED_RATE, GPU_ASSUMED_RATE,
};
pub use search::{
    list_gpu_devices, run_search, validate_pattern, Backend, Hit, SearchEvent, SearchRequest,
    MAX_PATTERNS, MAX_PATTERN_DATA, MAX_PATTERN_LEN,
};
pub use verify::verify_hit_ergo_lib;
