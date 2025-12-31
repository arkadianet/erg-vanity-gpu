//! BIP44 derivation paths.
//!
//! Path structure: m / purpose' / coin_type' / account' / change / address_index
//! For Ergo: m/44'/429'/0'/0/0

#![forbid(unsafe_code)]

use crate::bip32::{Bip32Error, ExtendedPrivateKey, HARDENED};

/// BIP44 purpose constant.
pub const PURPOSE: u32 = 44;

/// Ergo coin type (SLIP-0044).
pub const ERGO_COIN_TYPE: u32 = 429;

/// Derive Ergo key at standard path m/44'/429'/account'/change/address_index.
pub fn derive_ergo_key(
    master: &ExtendedPrivateKey,
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<ExtendedPrivateKey, Bip32Error> {
    // m/44'/429'/account'/change/address_index
    let path = [
        HARDENED | PURPOSE,       // 44'
        HARDENED | ERGO_COIN_TYPE, // 429'
        HARDENED | account,        // account'
        change,                    // change (not hardened)
        address_index,             // address_index (not hardened)
    ];
    master.derive_path(&path)
}

/// Derive first Ergo key at m/44'/429'/0'/0/0.
pub fn derive_ergo_first_key(master: &ExtendedPrivateKey) -> Result<ExtendedPrivateKey, Bip32Error> {
    derive_ergo_key(master, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::mnemonic_to_seed;

    #[test]
    fn test_ergo_derivation_path() {
        // Standard test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // Derive m/44'/429'/0'/0/0
        let ergo_key = derive_ergo_first_key(&master).unwrap();

        // Verify we get a valid key
        assert!(ergo_key.private_key_scalar().is_some());
        assert!(!ergo_key.private_key_scalar().unwrap().is_zero());

        // The key should be deterministic
        let ergo_key2 = derive_ergo_first_key(&master).unwrap();
        assert_eq!(ergo_key.private_key(), ergo_key2.private_key());
    }

    #[test]
    fn test_different_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        let key0 = derive_ergo_key(&master, 0, 0, 0).unwrap();
        let key1 = derive_ergo_key(&master, 1, 0, 0).unwrap();

        // Different accounts should produce different keys
        assert_ne!(key0.private_key(), key1.private_key());
    }

    #[test]
    fn test_different_addresses() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        let key0 = derive_ergo_key(&master, 0, 0, 0).unwrap();
        let key1 = derive_ergo_key(&master, 0, 0, 1).unwrap();

        // Different address indices should produce different keys
        assert_ne!(key0.private_key(), key1.private_key());
    }

    #[test]
    fn test_full_pipeline() {
        // Test the full pipeline: mnemonic → seed → master → ergo key
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";

        // 1. Mnemonic to seed
        let seed = mnemonic_to_seed(mnemonic, "");

        // 2. Seed to master key
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // 3. Master to Ergo key at m/44'/429'/0'/0/0
        let ergo_key = derive_ergo_first_key(&master).unwrap();

        // Verify the private key is valid and can be used
        let scalar = ergo_key.private_key_scalar().unwrap();
        assert!(!scalar.is_zero());
    }
}
