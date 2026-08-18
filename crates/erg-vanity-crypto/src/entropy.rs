//! Deterministic entropy from a per-search salt and a unique counter.

use crate::blake2b;

/// Mix salt and a little-endian counter into 32 bytes of entropy.
///
/// `entropy = Blake2b-256(salt || counter_le)`
///
/// GPU and CPU searchers must use this same construction so a (salt, counter)
/// pair produces the same mnemonic on either backend.
pub fn from_salt_counter(salt: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(salt);
    buf[32..].copy_from_slice(&counter.to_le_bytes());
    blake2b::digest(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_entropy() {
        let salt = [7u8; 32];
        assert_eq!(from_salt_counter(&salt, 123), from_salt_counter(&salt, 123));
    }

    #[test]
    fn different_counter_different_entropy() {
        let salt = [7u8; 32];
        assert_ne!(from_salt_counter(&salt, 1), from_salt_counter(&salt, 2));
    }
}
