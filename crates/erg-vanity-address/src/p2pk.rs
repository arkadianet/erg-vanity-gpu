//! P2PK address encoding.
//!
//! Address format:
//! - Prefix byte: network | address_type (1 byte)
//! - Content: compressed public key (33 bytes)
//! - Checksum: blake2b256(prefix || content)[0:4] (4 bytes)
//! - Encoded: Base58(prefix || content || checksum)

#![forbid(unsafe_code)]

use crate::network::{prefix_byte, AddressType, Network};
use erg_vanity_crypto::{base58, blake2b};

/// P2PK address length in bytes before Base58 encoding.
/// 1 (prefix) + 33 (pubkey) + 4 (checksum) = 38 bytes
pub const P2PK_ADDRESS_BYTES: usize = 38;

/// Checksum length in bytes.
pub const CHECKSUM_LEN: usize = 4;

/// Encode a compressed public key as an Ergo P2PK address.
///
/// The public key must be 33 bytes (compressed SEC1 format).
pub fn encode_p2pk(pubkey: &[u8; 33], network: Network) -> String {
    let prefix = prefix_byte(network, AddressType::P2PK);

    // Build prefix || content for checksum
    let mut content = [0u8; 34]; // 1 + 33
    content[0] = prefix;
    content[1..34].copy_from_slice(pubkey);

    // Checksum = blake2b256(prefix || pubkey)[0:4]
    let hash = blake2b::digest(&content);
    let checksum = &hash[..CHECKSUM_LEN];

    // Full address bytes: prefix || pubkey || checksum
    let mut address_bytes = [0u8; P2PK_ADDRESS_BYTES];
    address_bytes[0] = prefix;
    address_bytes[1..34].copy_from_slice(pubkey);
    address_bytes[34..38].copy_from_slice(checksum);

    base58::encode(&address_bytes)
}

/// Encode a compressed public key as a mainnet P2PK address.
pub fn encode_p2pk_mainnet(pubkey: &[u8; 33]) -> String {
    encode_p2pk(pubkey, Network::Mainnet)
}

/// Encode a compressed public key as a testnet P2PK address.
pub fn encode_p2pk_testnet(pubkey: &[u8; 33]) -> String {
    encode_p2pk(pubkey, Network::Testnet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{prefix_byte, AddressType, Network};

    fn decode(addr: &str) -> Vec<u8> {
        bs58::decode(addr).into_vec().unwrap()
    }

    fn assert_valid_p2pk(addr: &str, pubkey: &[u8; 33], network: Network) {
        let raw = decode(addr);
        assert_eq!(raw.len(), P2PK_ADDRESS_BYTES);

        let expected_prefix = prefix_byte(network, AddressType::P2PK);
        assert_eq!(raw[0], expected_prefix);
        assert_eq!(&raw[1..34], pubkey);

        let hash = blake2b::digest(&raw[0..34]);
        assert_eq!(&raw[34..38], &hash[..CHECKSUM_LEN]);
    }

    #[test]
    fn test_mainnet_roundtrip_structure() {
        let pubkey = [0x02u8; 33];
        let addr = encode_p2pk_mainnet(&pubkey);
        assert_valid_p2pk(&addr, &pubkey, Network::Mainnet);
    }

    #[test]
    fn test_testnet_roundtrip_structure() {
        let pubkey = [0x02u8; 33];
        let addr = encode_p2pk_testnet(&pubkey);
        assert_valid_p2pk(&addr, &pubkey, Network::Testnet);
    }

    #[test]
    fn test_deterministic() {
        let pubkey = [0x03u8; 33];
        let addr1 = encode_p2pk_mainnet(&pubkey);
        let addr2 = encode_p2pk_mainnet(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_pubkeys_different_addresses() {
        let pubkey1 = [0x02u8; 33];
        let pubkey2 = [0x03u8; 33];
        let addr1 = encode_p2pk_mainnet(&pubkey1);
        let addr2 = encode_p2pk_mainnet(&pubkey2);
        assert_ne!(addr1, addr2);
    }
}
