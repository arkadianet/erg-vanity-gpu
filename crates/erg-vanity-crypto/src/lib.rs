//! Cryptographic primitives for erg-vanity.
//!
//! All implementations are from scratch for GPU portability.
//! Reference crates (sha2, hmac, etc.) are dev-dependencies only.

#![forbid(unsafe_code)]

pub mod sha256;
pub mod sha512;
pub mod hmac;
pub mod pbkdf2;
pub mod secp256k1;
pub mod blake2b;
pub mod base58;
