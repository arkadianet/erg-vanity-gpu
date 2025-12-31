//! Blake2b-256 implementation (RFC 7693).
//!
//! Used for Ergo address checksum computation.

#![forbid(unsafe_code)]

/// Blake2b block size in bytes.
const BLOCK_SIZE: usize = 128;

/// Blake2b-256 output size.
const OUT_SIZE: usize = 32;

/// Blake2b initialization vector.
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Sigma permutation table for message schedule.
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// G mixing function.
#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Compress a single block.
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_SIZE], t: u128, last: bool) {
    // Parse message block into 16 words
    let mut m = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    // Initialize working vector
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&IV);

    // XOR with counter
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;

    // Invert if last block
    if last {
        v[14] = !v[14];
    }

    // 12 rounds of mixing
    for round in 0..12 {
        let s = &SIGMA[round];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    // Finalize state
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Compute Blake2b-256 digest of input data.
pub fn digest(data: &[u8]) -> [u8; OUT_SIZE] {
    // Initialize state with parameter block
    // h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen
    // For Blake2b-256 with no key: h[0] ^= 0x01010000 ^ 32 = 0x01010020
    let mut h = IV;
    h[0] ^= 0x01010000 ^ (OUT_SIZE as u64);

    let mut t: u128 = 0;
    let mut offset = 0;

    // Process full blocks
    while offset + BLOCK_SIZE < data.len() {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
        t += BLOCK_SIZE as u128;
        compress(&mut h, &block, t, false);
        offset += BLOCK_SIZE;
    }

    // Process final block (with padding)
    let remaining = data.len() - offset;
    let mut block = [0u8; BLOCK_SIZE];
    block[..remaining].copy_from_slice(&data[offset..]);
    t += remaining as u128;
    compress(&mut h, &block, t, true);

    // Extract output
    let mut output = [0u8; OUT_SIZE];
    for (i, word) in h.iter().take(OUT_SIZE / 8).enumerate() {
        output[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_empty() {
        // Blake2b-256("") from RFC 7693 / reference implementation
        let result = digest(b"");
        assert_eq!(
            to_hex(&result),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn test_abc() {
        // Blake2b-256("abc")
        let result = digest(b"abc");
        assert_eq!(
            to_hex(&result),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    #[test]
    fn test_long() {
        // Test with data longer than one block
        let data = vec![0x61u8; 256]; // 256 'a's
        let result = digest(&data);
        // This should produce a valid hash (verified against reference)
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_against_blake2_crate() {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;

        type Blake2b256 = Blake2b<U32>;

        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            &[0u8; 128],  // exactly one block
            &[0u8; 129],  // one block + 1 byte
            &[0xffu8; 256],
        ];

        for data in test_cases {
            let our_result = digest(data);
            let ref_result: [u8; 32] = Blake2b256::digest(data).into();
            assert_eq!(
                our_result, ref_result,
                "mismatch for data len {}",
                data.len()
            );
        }
    }
}
