//! Ergo address encoding.

#![forbid(unsafe_code)]

pub mod network;
pub mod p2pk;

pub use network::{prefix_byte, AddressType, Network};
pub use p2pk::{encode_p2pk, encode_p2pk_mainnet, encode_p2pk_testnet, CHECKSUM_LEN, P2PK_ADDRESS_BYTES};
