//! Core types, traits, and BIP39 wordlist for erg-vanity.

#![forbid(unsafe_code)]

mod error;
mod wordlist;

pub use error::Error;
pub use wordlist::WORDLIST;

pub type Result<T> = std::result::Result<T, Error>;
