//! Single-threaded vanity address generator.
//!
//! Full pipeline: entropy → mnemonic → seed → master key → derived key → pubkey → address

#![forbid(unsafe_code)]

use erg_vanity_address::{encode_p2pk, Network};
use erg_vanity_bip::bip32::ExtendedPrivateKey;
use erg_vanity_bip::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
use erg_vanity_bip::bip44::derive_ergo_first_key;
use erg_vanity_crypto::secp256k1::pubkey::PublicKey;
use rand::{CryptoRng, RngCore};
use std::fmt;

/// Result of successful address generation.
#[derive(Clone)]
pub struct GeneratedAddress {
    /// The generated Ergo address
    pub address: String,
    /// The BIP39 mnemonic (24 words for 256-bit entropy)
    pub mnemonic: String,
    /// The raw 32-byte private key at m/44'/429'/0'/0/0
    pub private_key: [u8; 32],
}

impl fmt::Debug for GeneratedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedAddress")
            .field("address", &self.address)
            .field("mnemonic", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Generate a random Ergo address from 256-bit entropy.
///
/// Returns the address, mnemonic, and derived private key.
pub fn generate_address<R: RngCore + CryptoRng>(
    rng: &mut R,
    network: Network,
) -> Result<GeneratedAddress, &'static str> {
    // 1. Generate 256 bits of entropy (for 24-word mnemonic)
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);

    generate_address_from_entropy(&entropy, network)
}

/// Generate an Ergo address from specific entropy bytes.
///
/// Entropy must be 16, 20, 24, 28, or 32 bytes.
pub fn generate_address_from_entropy(
    entropy: &[u8],
    network: Network,
) -> Result<GeneratedAddress, &'static str> {
    // 1. Entropy → Mnemonic
    let mnemonic = entropy_to_mnemonic(entropy)?;

    // 2. Mnemonic → Seed (no passphrase)
    let seed = mnemonic_to_seed(&mnemonic, "");

    // 3. Seed → Master key
    let master = ExtendedPrivateKey::from_seed(&seed).map_err(|_| "invalid master key")?;

    // 4. Master → Ergo key at m/44'/429'/0'/0/0
    let ergo_key = derive_ergo_first_key(&master).map_err(|_| "derivation failed")?;

    // 5. Private key → Public key
    let scalar = ergo_key
        .private_key_scalar()
        .ok_or("invalid private key scalar")?;
    let pubkey = PublicKey::from_private_key(&scalar).ok_or("invalid public key")?;

    // 6. Public key → Address
    let address = encode_p2pk(pubkey.as_bytes(), network);

    Ok(GeneratedAddress {
        address,
        mnemonic,
        private_key: *ergo_key.private_key(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_generate_address_deterministic() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let result1 = generate_address(&mut rng, Network::Mainnet).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let result2 = generate_address(&mut rng, Network::Mainnet).unwrap();

        assert_eq!(result1.address, result2.address);
        assert_eq!(result1.mnemonic, result2.mnemonic);
        assert_eq!(result1.private_key, result2.private_key);
    }

    #[test]
    fn test_generate_address_from_known_entropy() {
        // All zeros → "abandon" mnemonic
        let entropy = [0u8; 32];
        let result = generate_address_from_entropy(&entropy, Network::Mainnet).unwrap();

        // Should start with "abandon abandon..."
        assert!(result.mnemonic.starts_with("abandon abandon"));

        // Should have 24 words
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_different_entropy_different_address() {
        let entropy1 = [0u8; 32];
        let entropy2 = [1u8; 32];

        let result1 = generate_address_from_entropy(&entropy1, Network::Mainnet).unwrap();
        let result2 = generate_address_from_entropy(&entropy2, Network::Mainnet).unwrap();

        assert_ne!(result1.address, result2.address);
    }

    #[test]
    fn test_mainnet_vs_testnet() {
        let entropy = [0u8; 32];
        let mainnet = generate_address_from_entropy(&entropy, Network::Mainnet).unwrap();
        let testnet = generate_address_from_entropy(&entropy, Network::Testnet).unwrap();

        // Same mnemonic and private key
        assert_eq!(mainnet.mnemonic, testnet.mnemonic);
        assert_eq!(mainnet.private_key, testnet.private_key);

        // Different addresses
        assert_ne!(mainnet.address, testnet.address);
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let entropy = [0u8; 32];
        let result = generate_address_from_entropy(&entropy, Network::Mainnet).unwrap();
        let debug_str = format!("{:?}", result);

        // Should contain address but not the actual mnemonic or key bytes
        assert!(debug_str.contains(&result.address));
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("abandon"));
    }
}
