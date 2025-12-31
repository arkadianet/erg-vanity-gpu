//! CPU reference implementation for vanity address generation.

#![forbid(unsafe_code)]

pub mod generator;
pub mod matcher;
pub mod parallel;

pub use generator::{generate_address, generate_address_from_entropy, GeneratedAddress};
pub use matcher::{MatchType, Pattern};
pub use parallel::{search, SearchResult};
