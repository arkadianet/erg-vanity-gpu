//! CPU reference implementation for vanity address generation.

#![forbid(unsafe_code)]

pub mod generator;
pub mod matcher;
pub mod parallel;

pub use generator::{
    generate_address, generate_address_from_entropy, generate_address_from_entropy_at,
    GeneratedAddress,
};
pub use matcher::{first_match, MatchType, Pattern};
pub use parallel::{search, search_counter_range, search_many, CpuHit, SearchResult};
