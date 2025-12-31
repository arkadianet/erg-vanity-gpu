//! BIP32 hierarchical deterministic key derivation.
//!
//! Implements master key derivation and child derivation (hardened + normal).
//! Handles edge cases per BIP32 spec (IL >= n, key == 0).

#![forbid(unsafe_code)]

use erg_vanity_crypto::hmac::hmac_sha512;
use erg_vanity_crypto::secp256k1::pubkey::PublicKey;
use erg_vanity_crypto::secp256k1::scalar::Scalar;

/// Hardened derivation flag.
pub const HARDENED: u32 = 0x80000000;

/// BIP32 derivation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip32Error {
    /// IL >= curve order n (extremely rare, ~1 in 2^127)
    InvalidChildKey,
    /// Resulting key is zero (extremely rare)
    ZeroKey,
    /// Invalid seed length
    InvalidSeedLength,
}

/// Extended private key (private key + chain code).
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    /// 32-byte private key
    key: [u8; 32],
    /// 32-byte chain code
    chain_code: [u8; 32],
}

impl ExtendedPrivateKey {
    /// Derive master key from BIP39 seed.
    ///
    /// Uses HMAC-SHA512("Bitcoin seed", seed) per BIP32 spec.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Bip32Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Bip32Error::InvalidSeedLength);
        }

        let hmac = hmac_sha512(b"Bitcoin seed", seed);
        let (il, ir) = hmac.split_at(32);

        // Check IL is valid (< n and != 0)
        let key: [u8; 32] = il.try_into().unwrap();
        if Scalar::from_bytes(&key).is_none() {
            return Err(Bip32Error::InvalidChildKey);
        }
        if key == [0u8; 32] {
            return Err(Bip32Error::ZeroKey);
        }

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(Self { key, chain_code })
    }

    /// Derive hardened child key at given index.
    ///
    /// Convenience wrapper that adds HARDENED flag.
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Bip32Error> {
        self.derive_child(index | HARDENED)
    }

    /// Derive child key at given index.
    ///
    /// For hardened (index >= 0x80000000): Data = 0x00 || key || index
    /// For normal (index < 0x80000000): Data = compressed_pubkey || index
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let parent_scalar = Scalar::from_bytes(&self.key).ok_or(Bip32Error::InvalidChildKey)?;

        let data: [u8; 37] = if index >= HARDENED {
            // Hardened derivation: 0x00 || key || index
            let mut d = [0u8; 37];
            d[0] = 0x00;
            d[1..33].copy_from_slice(&self.key);
            d[33..37].copy_from_slice(&index.to_be_bytes());
            d
        } else {
            // Normal derivation: compressed_pubkey || index
            let pubkey = PublicKey::from_private_key(&parent_scalar).ok_or(Bip32Error::ZeroKey)?;
            let mut d = [0u8; 37];
            d[0..33].copy_from_slice(pubkey.as_bytes());
            d[33..37].copy_from_slice(&index.to_be_bytes());
            d
        };

        let hmac = hmac_sha512(&self.chain_code, &data);
        let (il, ir) = hmac.split_at(32);

        // Parse IL as scalar
        let il_bytes: [u8; 32] = il.try_into().unwrap();
        let il_scalar = Scalar::from_bytes(&il_bytes).ok_or(Bip32Error::InvalidChildKey)?;

        if il_scalar.is_zero() {
            return Err(Bip32Error::InvalidChildKey);
        }

        // Child key = IL + parent_key (mod n)
        let child_scalar = il_scalar.add(&parent_scalar);

        if child_scalar.is_zero() {
            return Err(Bip32Error::ZeroKey);
        }

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(Self {
            key: child_scalar.to_bytes(),
            chain_code,
        })
    }

    /// Derive key at BIP32 path.
    ///
    /// Path format: [index0, index1, ...] where each index is used as-is.
    /// Use HARDENED | i for hardened indices.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Bip32Error> {
        let mut current = self.clone();
        for &index in path {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }

    /// Get the raw 32-byte private key.
    pub fn private_key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the 32-byte chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the private key as a Scalar.
    pub fn private_key_scalar(&self) -> Option<Scalar> {
        Scalar::from_bytes(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_master_key_derivation() {
        // BIP32 test vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // Expected master key from BIP32 spec
        assert_eq!(
            to_hex(master.private_key()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            to_hex(master.chain_code()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn test_hardened_child_derivation() {
        // BIP32 test vector 1, path m/0'
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = master.derive_hardened(0).unwrap();

        assert_eq!(
            to_hex(child.private_key()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            to_hex(child.chain_code()),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
    }

    #[test]
    fn test_normal_child_derivation() {
        // BIP32 test vector 1, path m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = master.derive_path(&[HARDENED, 1]).unwrap();

        assert_eq!(
            to_hex(child.private_key()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            to_hex(child.chain_code()),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
    }

    #[test]
    fn test_path_derivation() {
        // BIP32 test vector 1, path m/0'/1/2'
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let derived = master.derive_path(&[HARDENED, 1, HARDENED | 2]).unwrap();

        assert_eq!(
            to_hex(derived.private_key()),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        );
    }

    #[test]
    fn test_bip39_to_bip32() {
        // Standard test: BIP39 seed → BIP32 master
        // Using "abandon" x 11 + "about" mnemonic seed
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // Verify we get a valid key
        assert!(master.private_key_scalar().is_some());
        assert!(!master.private_key_scalar().unwrap().is_zero());
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [0u8; 8];
        assert!(matches!(
            ExtendedPrivateKey::from_seed(&short_seed),
            Err(Bip32Error::InvalidSeedLength)
        ));
    }
}
