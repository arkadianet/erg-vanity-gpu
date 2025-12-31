//! BIP39 mnemonic implementation.
//!
//! Entropy → Mnemonic (with SHA-256 checksum)
//! Mnemonic → Seed (PBKDF2 with NFKD normalization)

#![forbid(unsafe_code)]

use erg_vanity_core::WORDLIST;
use erg_vanity_crypto::{pbkdf2, sha256};
use unicode_normalization::UnicodeNormalization;

/// Mnemonic word count options and their entropy sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnemonicType {
    /// 12 words, 128-bit entropy, 4-bit checksum
    Words12,
    /// 15 words, 160-bit entropy, 5-bit checksum
    Words15,
    /// 18 words, 192-bit entropy, 6-bit checksum
    Words18,
    /// 21 words, 224-bit entropy, 7-bit checksum
    Words21,
    /// 24 words, 256-bit entropy, 8-bit checksum
    Words24,
}

impl MnemonicType {
    /// Get entropy size in bytes.
    pub const fn entropy_bytes(&self) -> usize {
        match self {
            Self::Words12 => 16,
            Self::Words15 => 20,
            Self::Words18 => 24,
            Self::Words21 => 28,
            Self::Words24 => 32,
        }
    }

    /// Get entropy size in bits.
    pub const fn entropy_bits(&self) -> usize {
        self.entropy_bytes() * 8
    }

    /// Get checksum size in bits (ENT / 32).
    pub const fn checksum_bits(&self) -> usize {
        self.entropy_bits() / 32
    }

    /// Get word count.
    pub const fn word_count(&self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }
}

/// Generate mnemonic from entropy bytes.
///
/// The entropy length determines the mnemonic type:
/// - 16 bytes → 12 words
/// - 20 bytes → 15 words
/// - 24 bytes → 18 words
/// - 28 bytes → 21 words
/// - 32 bytes → 24 words
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, &'static str> {
    let mtype = match entropy.len() {
        16 => MnemonicType::Words12,
        20 => MnemonicType::Words15,
        24 => MnemonicType::Words18,
        28 => MnemonicType::Words21,
        32 => MnemonicType::Words24,
        _ => return Err("invalid entropy length"),
    };

    // Compute SHA-256 checksum
    let hash = sha256::digest(entropy);
    let checksum_bits = mtype.checksum_bits();

    // Build bit stream: entropy || checksum
    // Total bits = ENT + ENT/32 = (ENT + ENT/32) / 11 * 11 = word_count * 11
    let total_bits = mtype.entropy_bits() + checksum_bits;
    let mut bits = Vec::with_capacity(total_bits);

    // Add entropy bits
    for &byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }

    // Add checksum bits (first checksum_bits bits of hash)
    for i in 0..checksum_bits {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        bits.push((hash[byte_idx] >> bit_idx) & 1);
    }

    // Convert to words (11 bits per word)
    let mut words = Vec::with_capacity(mtype.word_count());
    for chunk in bits.chunks_exact(11) {
        let mut index = 0u16;
        for &bit in chunk {
            index = (index << 1) | (bit as u16);
        }
        words.push(WORDLIST[index as usize]);
    }

    Ok(words.join(" "))
}

/// Convert mnemonic to seed using PBKDF2-HMAC-SHA512.
///
/// Both mnemonic and passphrase are NFKD normalized per BIP39 spec.
/// Salt = "mnemonic" + passphrase
/// Iterations = 2048
/// Output = 64 bytes
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    // NFKD normalize mnemonic and passphrase
    let mnemonic_normalized: String = mnemonic.nfkd().collect();
    let passphrase_normalized: String = passphrase.nfkd().collect();

    // Salt = "mnemonic" + passphrase
    let salt = format!("mnemonic{}", passphrase_normalized);

    // PBKDF2-HMAC-SHA512 with 2048 iterations
    let mut seed = [0u8; 64];
    pbkdf2::derive(
        mnemonic_normalized.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    );

    seed
}

/// Validate mnemonic checksum.
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    let mtype = match words.len() {
        12 => MnemonicType::Words12,
        15 => MnemonicType::Words15,
        18 => MnemonicType::Words18,
        21 => MnemonicType::Words21,
        24 => MnemonicType::Words24,
        _ => return false,
    };

    // Convert words to indices
    let mut indices = Vec::with_capacity(words.len());
    for word in &words {
        match WORDLIST.iter().position(|&w| w == *word) {
            Some(idx) => indices.push(idx as u16),
            None => return false,
        }
    }

    // Convert indices to bits
    let mut bits = Vec::with_capacity(words.len() * 11);
    for index in indices {
        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }

    // Split into entropy and checksum
    let entropy_bits = mtype.entropy_bits();
    let checksum_bits = mtype.checksum_bits();

    // Extract entropy bytes
    let mut entropy = vec![0u8; mtype.entropy_bytes()];
    for (i, byte) in entropy.iter_mut().enumerate() {
        for j in 0..8 {
            *byte = (*byte << 1) | bits[i * 8 + j];
        }
    }

    // Compute expected checksum
    let hash = sha256::digest(&entropy);
    let mut expected_checksum = Vec::with_capacity(checksum_bits);
    for i in 0..checksum_bits {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        expected_checksum.push((hash[byte_idx] >> bit_idx) & 1);
    }

    // Compare with actual checksum
    let actual_checksum = &bits[entropy_bits..];
    expected_checksum == actual_checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_entropy_to_mnemonic_12_words() {
        // Test vector from BIP39
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_entropy_to_mnemonic_24_words() {
        // All zeros → 24 words
        let entropy =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        // First 23 words should be "abandon", last word includes checksum
        for word in &words[..23] {
            assert_eq!(*word, "abandon");
        }
    }

    #[test]
    fn test_mnemonic_to_seed_no_passphrase() {
        // BIP39 test vector
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        assert_eq!(
            to_hex(&seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        // BIP39 test vector with "TREZOR" passphrase
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "TREZOR");
        assert_eq!(
            to_hex(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_validate_mnemonic_valid() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic(mnemonic));
    }

    #[test]
    fn test_validate_mnemonic_invalid_checksum() {
        // Changed last word from "about" to "abandon"
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon";
        assert!(!validate_mnemonic(mnemonic));
    }

    #[test]
    fn test_validate_mnemonic_invalid_word() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon notaword";
        assert!(!validate_mnemonic(mnemonic));
    }

    #[test]
    fn test_validate_mnemonic_wrong_count() {
        let mnemonic = "abandon abandon abandon";
        assert!(!validate_mnemonic(mnemonic));
    }

    #[test]
    fn test_roundtrip() {
        let entropy = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert!(validate_mnemonic(&mnemonic));
    }
}
