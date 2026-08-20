//! Research-only HMAC-64 compressors and Ampere ISA accounting.
//!
//! Does not change the production SHA-512. Used to prove bit-exact candidates
//! and to count modeled RTX integer ops. Author: arkadianet

#![allow(clippy::too_many_arguments)]

use crate::sha512_circuit::{hmac64_expand16, IsaCost};

const H_INIT: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub const PAD: u64 = 0x8000_0000_0000_0000;
pub const BIT_LEN: u64 = 1536;

/// Ampere SHF-native 64-bit rotate (two 32-bit funnel shifts).
pub fn ror64_shf(x: u64, n: u32) -> u64 {
    let lo = x as u32;
    let hi = (x >> 32) as u32;
    let shf = |a: u32, b: u32, k: u32| {
        if k == 0 {
            a
        } else {
            (a >> k) | (b << (32 - k))
        }
    };
    let (rlo, rhi) = if n < 32 {
        (shf(lo, hi, n), shf(hi, lo, n))
    } else {
        let k = n - 32;
        (shf(hi, lo, k), shf(lo, hi, k))
    };
    ((rhi as u64) << 32) | rlo as u64
}

#[inline]
fn ror(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    z ^ (x & (y ^ z))
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & (y ^ z)) ^ (y & z)
}

#[inline]
fn ep0(x: u64) -> u64 {
    ror(x, 28) ^ ror(x, 34) ^ ror(x, 39)
}

#[inline]
fn ep1(x: u64) -> u64 {
    ror(x, 14) ^ ror(x, 18) ^ ror(x, 41)
}

#[inline]
fn ep0_shf(x: u64) -> u64 {
    ror64_shf(x, 28) ^ ror64_shf(x, 34) ^ ror64_shf(x, 39)
}

#[inline]
fn ep1_shf(x: u64) -> u64 {
    ror64_shf(x, 14) ^ ror64_shf(x, 18) ^ ror64_shf(x, 41)
}

fn rnd(
    a: u64,
    b: u64,
    c: u64,
    d: &mut u64,
    e: u64,
    f: u64,
    g: u64,
    h: &mut u64,
    k: u64,
    w: u64,
    shf: bool,
) {
    let s1 = if shf { ep1_shf(e) } else { ep1(e) };
    let s0 = if shf { ep0_shf(a) } else { ep0(a) };
    *h = h
        .wrapping_add(s1)
        .wrapping_add(ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    *d = d.wrapping_add(*h);
    *h = h.wrapping_add(s0).wrapping_add(maj(a, b, c));
}

fn add8(mid: [u64; 8], a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> [u64; 8] {
    [
        mid[0].wrapping_add(a),
        mid[1].wrapping_add(b),
        mid[2].wrapping_add(c),
        mid[3].wrapping_add(d),
        mid[4].wrapping_add(e),
        mid[5].wrapping_add(f),
        mid[6].wrapping_add(g),
        mid[7].wrapping_add(h),
    ]
}

/// One SHA-512 compress of a 16-word block (ipad/opad).
pub fn compress16(mid: [u64; 8], mut w: [u64; 16]) -> [u64; 8] {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = mid;
    for base in [0usize, 16, 32, 48] {
        rounds16(
            base, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, false,
        );
        expand16_generic(&mut w);
    }
    rounds16(
        64, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, false,
    );
    add8(mid, a, b, c, d, e, f, g, h)
}

fn rounds16(
    base: usize,
    a: &mut u64,
    b: &mut u64,
    c: &mut u64,
    d: &mut u64,
    e: &mut u64,
    f: &mut u64,
    g: &mut u64,
    h: &mut u64,
    w: &[u64; 16],
    shf: bool,
) {
    let ww = *w;
    rnd(*a, *b, *c, d, *e, *f, *g, h, K[base], ww[0], shf);
    rnd(*h, *a, *b, c, *d, *e, *f, g, K[base + 1], ww[1], shf);
    rnd(*g, *h, *a, b, *c, *d, *e, f, K[base + 2], ww[2], shf);
    rnd(*f, *g, *h, a, *b, *c, *d, e, K[base + 3], ww[3], shf);
    rnd(*e, *f, *g, h, *a, *b, *c, d, K[base + 4], ww[4], shf);
    rnd(*d, *e, *f, g, *h, *a, *b, c, K[base + 5], ww[5], shf);
    rnd(*c, *d, *e, f, *g, *h, *a, b, K[base + 6], ww[6], shf);
    rnd(*b, *c, *d, e, *f, *g, *h, a, K[base + 7], ww[7], shf);
    rnd(*a, *b, *c, d, *e, *f, *g, h, K[base + 8], ww[8], shf);
    rnd(*h, *a, *b, c, *d, *e, *f, g, K[base + 9], ww[9], shf);
    rnd(*g, *h, *a, b, *c, *d, *e, f, K[base + 10], ww[10], shf);
    rnd(*f, *g, *h, a, *b, *c, *d, e, K[base + 11], ww[11], shf);
    rnd(*e, *f, *g, h, *a, *b, *c, d, K[base + 12], ww[12], shf);
    rnd(*d, *e, *f, g, *h, *a, *b, c, K[base + 13], ww[13], shf);
    rnd(*c, *d, *e, f, *g, *h, *a, b, K[base + 14], ww[14], shf);
    rnd(*b, *c, *d, e, *f, *g, *h, a, K[base + 15], ww[15], shf);
}

fn expand16_generic(w: &mut [u64; 16]) {
    let sig0 = |x: u64| ror(x, 1) ^ ror(x, 8) ^ (x >> 7);
    let sig1 = |x: u64| ror(x, 19) ^ ror(x, 61) ^ (x >> 6);
    w[0] = w[0]
        .wrapping_add(sig1(w[14]))
        .wrapping_add(w[9])
        .wrapping_add(sig0(w[1]));
    w[1] = w[1]
        .wrapping_add(sig1(w[15]))
        .wrapping_add(w[10])
        .wrapping_add(sig0(w[2]));
    w[2] = w[2]
        .wrapping_add(sig1(w[0]))
        .wrapping_add(w[11])
        .wrapping_add(sig0(w[3]));
    w[3] = w[3]
        .wrapping_add(sig1(w[1]))
        .wrapping_add(w[12])
        .wrapping_add(sig0(w[4]));
    w[4] = w[4]
        .wrapping_add(sig1(w[2]))
        .wrapping_add(w[13])
        .wrapping_add(sig0(w[5]));
    w[5] = w[5]
        .wrapping_add(sig1(w[3]))
        .wrapping_add(w[14])
        .wrapping_add(sig0(w[6]));
    w[6] = w[6]
        .wrapping_add(sig1(w[4]))
        .wrapping_add(w[15])
        .wrapping_add(sig0(w[7]));
    w[7] = w[7]
        .wrapping_add(sig1(w[5]))
        .wrapping_add(w[0])
        .wrapping_add(sig0(w[8]));
    w[8] = w[8]
        .wrapping_add(sig1(w[6]))
        .wrapping_add(w[1])
        .wrapping_add(sig0(w[9]));
    w[9] = w[9]
        .wrapping_add(sig1(w[7]))
        .wrapping_add(w[2])
        .wrapping_add(sig0(w[10]));
    w[10] = w[10]
        .wrapping_add(sig1(w[8]))
        .wrapping_add(w[3])
        .wrapping_add(sig0(w[11]));
    w[11] = w[11]
        .wrapping_add(sig1(w[9]))
        .wrapping_add(w[4])
        .wrapping_add(sig0(w[12]));
    w[12] = w[12]
        .wrapping_add(sig1(w[10]))
        .wrapping_add(w[5])
        .wrapping_add(sig0(w[13]));
    w[13] = w[13]
        .wrapping_add(sig1(w[11]))
        .wrapping_add(w[6])
        .wrapping_add(sig0(w[14]));
    w[14] = w[14]
        .wrapping_add(sig1(w[12]))
        .wrapping_add(w[7])
        .wrapping_add(sig0(w[15]));
    w[15] = w[15]
        .wrapping_add(sig1(w[13]))
        .wrapping_add(w[8])
        .wrapping_add(sig0(w[0]));
}

fn pad64_words(msg: [u64; 8]) -> [u64; 16] {
    let mut w = [0u64; 16];
    w[..8].copy_from_slice(&msg);
    w[8] = PAD;
    w[15] = BIT_LEN;
    w
}

/// Production-shaped pad64 compress (`rotate` + generic expand).
pub fn compress_pad64_prod(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    compress16(mid, pad64_words(msg))
}

/// Same compress with SHF-pair rotates. Bit-identical if SHF == ROTR.
pub fn compress_pad64_shf(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let mut w = pad64_words(msg);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = mid;
    for base in [0usize, 16, 32, 48] {
        rounds16(
            base, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, true,
        );
        expand16_generic(&mut w);
    }
    rounds16(
        64, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, true,
    );
    add8(mid, a, b, c, d, e, f, g, h)
}

/// HMAC-64 specialized first expand. Same 80 rounds as production pad64.
pub fn compress_pad64_hmac64(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let head = pad64_words(msg);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = mid;
    rounds16(
        0, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &head, false,
    );
    let mut w = hmac64_expand16(msg);
    for base in [16usize, 32, 48] {
        rounds16(
            base, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, false,
        );
        expand16_generic(&mut w);
    }
    rounds16(
        64, &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, false,
    );
    add8(mid, a, b, c, d, e, f, g, h)
}

pub fn pack_be8(bytes: &[u8; 64]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for i in 0..8 {
        w[i] = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

pub fn unpack_be8(words: [u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&words[i].to_be_bytes());
    }
    out
}

fn load_be_block(block: &[u8; 128]) -> [u64; 16] {
    let mut w = [0u64; 16];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

/// Cached I/O midstates for a HMAC key (same as the GPU init).
pub fn hmac_mids(key: &[u8]) -> ([u64; 8], [u64; 8]) {
    let mut kb = [0u8; 128];
    if key.len() > 128 {
        kb[..64].copy_from_slice(&crate::sha512::digest(key));
    } else {
        kb[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 128];
    let mut opad = [0u8; 128];
    for i in 0..128 {
        ipad[i] = kb[i] ^ 0x36;
        opad[i] = kb[i] ^ 0x5c;
    }
    (
        compress16(H_INIT, load_be_block(&ipad)),
        compress16(H_INIT, load_be_block(&opad)),
    )
}

pub fn hmac64(inner: [u64; 8], outer: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    compress_pad64_prod(outer, compress_pad64_prod(inner, msg))
}

pub fn hmac64_specialized(inner: [u64; 8], outer: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    compress_pad64_hmac64(outer, compress_pad64_hmac64(inner, msg))
}

/// Modeled RTX integer cost of one pad64 compression.
pub fn pad64_isa_cost(specialized_expand: bool) -> IsaCost {
    let first = if specialized_expand { 22 } else { 32 };
    let sig = first + 48; // three dense expands are always 48 σ
    let rounds = crate::sha512_circuit::round_cost_floor();
    IsaCost {
        shf: rounds.shf * 80 + sig * 5,
        iadd: rounds.iadd * 80 + sig * 2 + 16,
        lop3: rounds.lop3 * 80 + sig * 2,
    }
}

/// Predicted compression-only saving of the known first-expand cut.
pub fn predicted_expand_speedup() -> f64 {
    let a = pad64_isa_cost(false).total() as f64;
    let b = pad64_isa_cost(true).total() as f64;
    (a - b) / a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac::hmac_sha512;
    use crate::pbkdf2;

    const K8_PAD: u64 = 0x5807_aa98_a303_0242;
    const K15_LEN: u64 = 0xc19b_f174_cf69_2c94;

    #[test]
    fn hmac64_k_fold_constants() {
        assert_eq!(K[8].wrapping_add(PAD), K8_PAD);
        assert_eq!(K[15].wrapping_add(BIT_LEN), K15_LEN);
    }

    #[test]
    fn shf_rotate_matches_rotate_right() {
        for n in 1..64u32 {
            for i in 0..40u64 {
                let x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(n);
                assert_eq!(ror64_shf(x, n), x.rotate_right(n), "n={n}");
            }
        }
    }

    #[test]
    fn pad64_candidates_match_production_hmac() {
        let keys: [&[u8]; 3] = [b"Jefe", &[0x0bu8; 20], b"password"];
        let msgs: [[u8; 64]; 3] = [
            [0x11; 64],
            {
                let mut m = [0u8; 64];
                let s = b"what do ya want for nothing?";
                m[..s.len()].copy_from_slice(s);
                m
            },
            [0xfe; 64],
        ];
        for key in keys {
            let (i, o) = hmac_mids(key);
            for msg in msgs {
                let expect = hmac_sha512(key, &msg);
                let words = pack_be8(&msg);
                let prod = unpack_be8(hmac64(i, o, words));
                let shf = unpack_be8(compress_pad64_shf(o, compress_pad64_shf(i, words)));
                let spec = unpack_be8(hmac64_specialized(i, o, words));
                assert_eq!(prod, expect, "prod hmac mismatch");
                assert_eq!(shf, expect, "shf hmac mismatch");
                assert_eq!(spec, expect, "hmac64-expand mismatch");
            }
        }
    }

    #[test]
    fn specialized_pbkdf2_matches_production() {
        let password = b"password";
        let salt = b"mnemonic";
        let (inner, outer) = hmac_mids(password);
        for iters in [1u32, 2, 8, 64] {
            let mut expect = [0u8; 64];
            pbkdf2::derive(password, salt, iters, &mut expect);
            let mut salt_block = Vec::from(&salt[..]);
            salt_block.extend_from_slice(&1u32.to_be_bytes());
            let u1 = hmac_sha512(password, &salt_block);
            let mut u = pack_be8(&u1);
            let mut acc = u;
            for _ in 1..iters {
                u = hmac64_specialized(inner, outer, u);
                for k in 0..8 {
                    acc[k] ^= u[k];
                }
            }
            assert_eq!(unpack_be8(acc), expect, "iters={iters}");
        }
    }

    #[test]
    fn known_expand_cut_is_below_ten_percent() {
        let s = predicted_expand_speedup();
        assert!(s > 0.02 && s < 0.05, "predicted {s}");
    }
}
