//! PBKDF2-HMAC-SHA512 implementation (RFC 8018).
//! This is the dominant cost in BIP39 seed derivation (2048 iterations).

#![forbid(unsafe_code)]

use crate::hmac::hmac_sha512;

/// HMAC-SHA512 output length.
const HLEN: usize = 64;

/// Derive key using PBKDF2-HMAC-SHA512.
///
/// DK = T1 || T2 || ... || Tn where Ti = F(Password, Salt, c, i)
/// F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
/// U1 = HMAC(P, S || INT_32_BE(i)), Uj = HMAC(P, Uj-1)
pub fn derive(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    assert!(iterations >= 1, "PBKDF2 iterations must be >= 1");

    let num_blocks = (output.len() + HLEN - 1) / HLEN;

    for block_idx in 0..num_blocks {
        let block_num = (block_idx + 1) as u32; // 1-indexed
        let block_start = block_idx * HLEN;
        let block_end = (block_start + HLEN).min(output.len());

        // U1 = HMAC(password, salt || block_num)
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        let mut u = hmac_sha512(password, &salt_block);
        let mut result = u;

        // U2 ... Uc, XORing into result
        for _ in 1..iterations {
            u = hmac_sha512(password, &u);
            for (r, ui) in result.iter_mut().zip(u.iter()) {
                *r ^= *ui;
            }
        }

        // Copy to output (may be partial for last block)
        output[block_start..block_end].copy_from_slice(&result[..block_end - block_start]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_bip39_no_passphrase() {
        // BIP39 test vector: mnemonic "abandon" x 11 + "about", no passphrase
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let salt = "mnemonic"; // BIP39 uses "mnemonic" + passphrase as salt

        let mut seed = [0u8; 64];
        derive(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        assert_eq!(
            to_hex(&seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn test_bip39_with_passphrase() {
        // BIP39 test vector: same mnemonic, passphrase "TREZOR"
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let salt = "mnemonicTREZOR"; // "mnemonic" + passphrase

        let mut seed = [0u8; 64];
        derive(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        assert_eq!(
            to_hex(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_short_output() {
        // Test with output shorter than one HMAC block
        let mut output = [0u8; 32];
        derive(b"password", b"salt", 1, &mut output);

        // Verify against reference
        let mut full = [0u8; 64];
        derive(b"password", b"salt", 1, &mut full);
        assert_eq!(&output[..], &full[..32]);
    }

    #[test]
    fn test_multi_block() {
        // Test output requiring multiple blocks (> 64 bytes)
        let mut output = [0u8; 100];
        derive(b"password", b"salt", 1, &mut output);

        // First 64 bytes should match single-block derivation
        let mut block1 = [0u8; 64];
        derive(b"password", b"salt", 1, &mut block1);
        assert_eq!(&output[..64], &block1[..]);
    }

    #[test]
    fn test_against_pbkdf2_crate() {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let test_cases = [
            (b"password".as_slice(), b"salt".as_slice(), 1u32),
            (b"password", b"salt", 2),
            (b"password", b"salt", 4096),
            (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096),
            (b"", b"salt", 1),
            (b"password", b"", 1),
        ];

        for (password, salt, iterations) in test_cases {
            let mut our_result = [0u8; 64];
            derive(password, salt, iterations, &mut our_result);

            let mut ref_result = [0u8; 64];
            pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut ref_result);

            assert_eq!(
                our_result, ref_result,
                "mismatch for password={:?}, salt={:?}, iterations={}",
                String::from_utf8_lossy(password),
                String::from_utf8_lossy(salt),
                iterations
            );
        }
    }
}
