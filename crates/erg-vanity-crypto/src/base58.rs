//! Base58 encoding for Ergo addresses.
//!
//! Uses Bitcoin alphabet (excludes 0, O, I, l to avoid confusion).

#![forbid(unsafe_code)]

/// Base58 alphabet (Bitcoin/Ergo style).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to Base58 string.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Allocate enough space for result (log(256)/log(58) ≈ 1.37)
    let size = (data.len() * 138 / 100) + 1;
    let mut buf = vec![0u8; size];

    // Convert to base58
    for &byte in data {
        let mut carry = byte as u32;
        for digit in buf.iter_mut().rev() {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
    }

    // Skip leading zeros in result buffer
    let first_non_zero = buf.iter().position(|&b| b != 0).unwrap_or(buf.len());

    // Build result string
    let mut result = String::with_capacity(leading_zeros + buf.len() - first_non_zero);

    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        result.push('1');
    }

    // Add encoded characters
    for &digit in &buf[first_non_zero..] {
        result.push(ALPHABET[digit as usize] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn test_single_zero() {
        assert_eq!(encode(&[0]), "1");
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(encode(&[0, 0, 0, 1]), "1112");
    }

    #[test]
    fn test_hello_world() {
        // "Hello World!" in Base58
        let result = encode(b"Hello World!");
        assert_eq!(result, "2NEpo7TZRRrLZSi2U");
    }

    #[test]
    fn test_against_bs58_crate() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"Hello World!",
            &[0],
            &[0, 0, 0],
            &[0, 0, 0, 1, 2, 3],
            &[0xff; 32],
            &[0x00, 0xff, 0x00, 0xff],
        ];

        for data in test_cases {
            let our_result = encode(data);
            let ref_result = bs58::encode(data).into_string();
            assert_eq!(
                our_result, ref_result,
                "mismatch for data {:?}",
                data
            );
        }
    }

    #[test]
    fn test_ergo_address_like() {
        // Test with 38-byte data (typical Ergo address before encoding)
        // prefix (1) + pubkey (33) + checksum (4) = 38 bytes
        let data = [0x01u8; 38];
        let result = encode(&data);
        assert!(!result.is_empty());

        // Verify against bs58
        let ref_result = bs58::encode(&data).into_string();
        assert_eq!(result, ref_result);
    }
}
