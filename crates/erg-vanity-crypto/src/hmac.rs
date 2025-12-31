//! HMAC-SHA512 implementation (RFC 2104).

#![forbid(unsafe_code)]

use crate::sha512;

/// SHA-512 block size in bytes.
const BLOCK_SIZE: usize = 128;

/// Compute HMAC-SHA512.
///
/// HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
/// where K' is the key padded/hashed to block size.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // If key is longer than block size, hash it first
    let key_block: [u8; BLOCK_SIZE] = if key.len() > BLOCK_SIZE {
        let mut block = [0u8; BLOCK_SIZE];
        block[..64].copy_from_slice(&sha512::digest(key));
        block
    } else {
        let mut block = [0u8; BLOCK_SIZE];
        block[..key.len()].copy_from_slice(key);
        block
    };

    // Compute inner and outer padded keys
    let mut i_key_pad = [0x36u8; BLOCK_SIZE];
    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        i_key_pad[i] ^= key_block[i];
        o_key_pad[i] ^= key_block[i];
    }

    // Inner hash: H(i_key_pad || data)
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_input.extend_from_slice(&i_key_pad);
    inner_input.extend_from_slice(data);
    let inner_hash = sha512::digest(&inner_input);

    // Outer hash: H(o_key_pad || inner_hash)
    let mut outer_input = [0u8; BLOCK_SIZE + 64];
    outer_input[..BLOCK_SIZE].copy_from_slice(&o_key_pad);
    outer_input[BLOCK_SIZE..].copy_from_slice(&inner_hash);
    sha512::digest(&outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_rfc4231_case1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha512(&key, data);
        assert_eq!(
            to_hex(&result),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn test_rfc4231_case2() {
        // RFC 4231 Test Case 2 ("Jefe" / "what do ya want for nothing?")
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha512(key, data);
        assert_eq!(
            to_hex(&result),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    #[test]
    fn test_rfc4231_case3() {
        // RFC 4231 Test Case 3 (key = 0xaa repeated 20 times, data = 0xdd repeated 50 times)
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let result = hmac_sha512(&key, &data);
        assert_eq!(
            to_hex(&result),
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        );
    }

    #[test]
    fn test_rfc4231_case6() {
        // RFC 4231 Test Case 6 (key larger than block size: 131 bytes of 0xaa)
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let result = hmac_sha512(&key, data);
        assert_eq!(
            to_hex(&result),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    #[test]
    fn test_against_hmac_crate() {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let test_cases: &[(&[u8], &[u8])] = &[
            (b"key", b"message"),
            (b"", b""),
            (&[0u8; 64], b"block-size key"),
            (&[0u8; 128], b"exactly block-size key"),
            (&[0u8; 200], b"larger than block-size key"),
        ];

        for (key, data) in test_cases {
            let our_result = hmac_sha512(key, data);
            let mut mac = HmacSha512::new_from_slice(key).unwrap();
            mac.update(data);
            let ref_result: [u8; 64] = mac.finalize().into_bytes().into();
            assert_eq!(
                our_result,
                ref_result,
                "mismatch for key len {}, data len {}",
                key.len(),
                data.len()
            );
        }
    }
}
