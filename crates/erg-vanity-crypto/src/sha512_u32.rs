//! SHA-512 on 32-bit halves: the RTX SHF-native execution of the same rounds.
//!
//! Ampere/Turing expose 32-bit funnel shift (`SHF`), not 64-bit rotate.
//! A 64-bit `ROTR(n)` is exactly two `SHF`s. This module is that mapping:
//! every rotate/shift is written as half-word funnel ops so the count is
//! explicit and the OpenCL kernel can match it.
//!
//! This is not a different hash. It is a different *machine* for the same
//! 80-round ARX. Bit-major evaluation (ripple *or* Kogge–Stone) is the
//! `arx_basis` module: it changes the representation, then loses on a SIMT
//! ALU whose add already *is* that prefix network.

#![allow(clippy::too_many_arguments)]

use crate::sha512_hmac64::{BIT_LEN, PAD};

const SIG0_PAD: u64 = 0x4180_0000_0000_0000;
const SIG1_LEN: u64 = 0x00c0_0000_0000_3018;
const SIG0_LEN: u64 = 0x030a;
const K8_PAD: u64 = 0x5807_aa98_a303_0242;
const K15_LEN: u64 = 0xc19b_f174_cf69_2c94;

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

/// 64-bit word as (lo, hi) — same layout as OpenCL `as_uint2(ulong)` on LE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64x2 {
    pub lo: u32,
    pub hi: u32,
}

impl U64x2 {
    pub const fn from_u64(x: u64) -> Self {
        Self {
            lo: x as u32,
            hi: (x >> 32) as u32,
        }
    }

    pub const fn to_u64(self) -> u64 {
        (self.lo as u64) | ((self.hi as u64) << 32)
    }
}

/// 32-bit funnel shift: low 32 bits of `(hi:lo) >> n` for `n` in 1..31.
#[inline(always)]
pub const fn shf_r(lo: u32, hi: u32, n: u32) -> u32 {
    (lo >> n) | (hi << (32 - n))
}

/// 64-bit ROTR as two SHF. `n` in 1..63.
#[inline(always)]
pub const fn ror64(x: U64x2, n: u32) -> U64x2 {
    if n < 32 {
        U64x2 {
            lo: shf_r(x.lo, x.hi, n),
            hi: shf_r(x.hi, x.lo, n),
        }
    } else {
        let k = n - 32;
        U64x2 {
            lo: shf_r(x.hi, x.lo, k),
            hi: shf_r(x.lo, x.hi, k),
        }
    }
}

/// 64-bit SHR as one SHF + one 32-bit SHR. `n` in 1..31.
#[inline(always)]
pub const fn shr64(x: U64x2, n: u32) -> U64x2 {
    U64x2 {
        lo: shf_r(x.lo, x.hi, n),
        hi: x.hi >> n,
    }
}

#[inline(always)]
fn add64(a: U64x2, b: U64x2) -> U64x2 {
    let (lo, c) = a.lo.overflowing_add(b.lo);
    U64x2 {
        lo,
        hi: a.hi.wrapping_add(b.hi).wrapping_add(u32::from(c)),
    }
}

#[inline(always)]
fn xor3(a: U64x2, b: U64x2, c: U64x2) -> U64x2 {
    U64x2 {
        lo: a.lo ^ b.lo ^ c.lo,
        hi: a.hi ^ b.hi ^ c.hi,
    }
}

/// Σ0: ROTR 28, 34, 39 → 6 SHF
#[inline(always)]
fn ep0(x: U64x2) -> U64x2 {
    xor3(ror64(x, 28), ror64(x, 34), ror64(x, 39))
}

/// Σ1: ROTR 14, 18, 41 → 6 SHF
#[inline(always)]
fn ep1(x: U64x2) -> U64x2 {
    xor3(ror64(x, 14), ror64(x, 18), ror64(x, 41))
}

/// σ0: ROTR 1, 8, SHR 7 → 5 SHF + 1 SHR
#[inline(always)]
fn sig0(x: U64x2) -> U64x2 {
    xor3(ror64(x, 1), ror64(x, 8), shr64(x, 7))
}

/// σ1: ROTR 19, 61, SHR 6 → 5 SHF + 1 SHR
#[inline(always)]
fn sig1(x: U64x2) -> U64x2 {
    xor3(ror64(x, 19), ror64(x, 61), shr64(x, 6))
}

#[inline(always)]
fn ch(x: U64x2, y: U64x2, z: U64x2) -> U64x2 {
    // bitselect(z, y, x) = z ^ (x & (y ^ z))
    U64x2 {
        lo: z.lo ^ (x.lo & (y.lo ^ z.lo)),
        hi: z.hi ^ (x.hi & (y.hi ^ z.hi)),
    }
}

#[inline(always)]
fn maj(x: U64x2, y: U64x2, z: U64x2) -> U64x2 {
    U64x2 {
        lo: (x.lo & (y.lo ^ z.lo)) ^ (y.lo & z.lo),
        hi: (x.hi & (y.hi ^ z.hi)) ^ (y.hi & z.hi),
    }
}

/// SHF-equivalent count for one HMAC-64 compression (specialized pad64).
///
/// Rounds: 80 × (EP0 + EP1) = 80 × 12 = 960 SHF.
/// Schedule: first expand specialized (110 SHF) + 3 dense expands (3 × 16 × 10
/// = 480) = 590 SHF.
/// Floor on RTX: 1550 SHF/compression. Cannot go below 2 SHF per 64-bit ROTR
/// without changing the value of Σ/σ (no 32-bit SHF can rotate 64 bits).
pub const HMAC64_SHF_FLOOR: u32 = 960 + 110 + 480;

/// Bitsliced 64-bit add: ripple-carry steps (one per bit). The reason
/// bitslicing does not beat SHF on SHA-512: each round has ~7 adds.
pub const BITSLICE_ADD_RIPPLE_STEPS: u32 = 64;

#[inline(always)]
fn rnd(
    a: U64x2,
    b: U64x2,
    c: U64x2,
    d: &mut U64x2,
    e: U64x2,
    f: U64x2,
    g: U64x2,
    h: &mut U64x2,
    k: U64x2,
    w: U64x2,
) {
    *h = add64(add64(add64(add64(*h, ep1(e)), ch(e, f, g)), k), w);
    *d = add64(*d, *h);
    *h = add64(add64(*h, ep0(a)), maj(a, b, c));
}

/// HMAC-64 compress using only 32-bit SHF/add. Bit-identical to `compress_hmac64`.
pub fn compress_hmac64_u32(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let mut w = [
        U64x2::from_u64(msg[0]),
        U64x2::from_u64(msg[1]),
        U64x2::from_u64(msg[2]),
        U64x2::from_u64(msg[3]),
        U64x2::from_u64(msg[4]),
        U64x2::from_u64(msg[5]),
        U64x2::from_u64(msg[6]),
        U64x2::from_u64(msg[7]),
        U64x2::from_u64(PAD),
        U64x2::from_u64(0),
        U64x2::from_u64(0),
        U64x2::from_u64(0),
        U64x2::from_u64(0),
        U64x2::from_u64(0),
        U64x2::from_u64(0),
        U64x2::from_u64(BIT_LEN),
    ];

    let midw = [
        U64x2::from_u64(mid[0]),
        U64x2::from_u64(mid[1]),
        U64x2::from_u64(mid[2]),
        U64x2::from_u64(mid[3]),
        U64x2::from_u64(mid[4]),
        U64x2::from_u64(mid[5]),
        U64x2::from_u64(mid[6]),
        U64x2::from_u64(mid[7]),
    ];
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = midw;

    rnd(
        a,
        b,
        c,
        &mut d,
        e,
        f,
        g,
        &mut h,
        U64x2::from_u64(K[0]),
        w[0],
    );
    rnd(
        h,
        a,
        b,
        &mut c,
        d,
        e,
        f,
        &mut g,
        U64x2::from_u64(K[1]),
        w[1],
    );
    rnd(
        g,
        h,
        a,
        &mut b,
        c,
        d,
        e,
        &mut f,
        U64x2::from_u64(K[2]),
        w[2],
    );
    rnd(
        f,
        g,
        h,
        &mut a,
        b,
        c,
        d,
        &mut e,
        U64x2::from_u64(K[3]),
        w[3],
    );
    rnd(
        e,
        f,
        g,
        &mut h,
        a,
        b,
        c,
        &mut d,
        U64x2::from_u64(K[4]),
        w[4],
    );
    rnd(
        d,
        e,
        f,
        &mut g,
        h,
        a,
        b,
        &mut c,
        U64x2::from_u64(K[5]),
        w[5],
    );
    rnd(
        c,
        d,
        e,
        &mut f,
        g,
        h,
        a,
        &mut b,
        U64x2::from_u64(K[6]),
        w[6],
    );
    rnd(
        b,
        c,
        d,
        &mut e,
        f,
        g,
        h,
        &mut a,
        U64x2::from_u64(K[7]),
        w[7],
    );
    rnd(
        a,
        b,
        c,
        &mut d,
        e,
        f,
        g,
        &mut h,
        U64x2::from_u64(K8_PAD),
        U64x2::from_u64(0),
    );
    rnd(
        h,
        a,
        b,
        &mut c,
        d,
        e,
        f,
        &mut g,
        U64x2::from_u64(K[9]),
        U64x2::from_u64(0),
    );
    rnd(
        g,
        h,
        a,
        &mut b,
        c,
        d,
        e,
        &mut f,
        U64x2::from_u64(K[10]),
        U64x2::from_u64(0),
    );
    rnd(
        f,
        g,
        h,
        &mut a,
        b,
        c,
        d,
        &mut e,
        U64x2::from_u64(K[11]),
        U64x2::from_u64(0),
    );
    rnd(
        e,
        f,
        g,
        &mut h,
        a,
        b,
        c,
        &mut d,
        U64x2::from_u64(K[12]),
        U64x2::from_u64(0),
    );
    rnd(
        d,
        e,
        f,
        &mut g,
        h,
        a,
        b,
        &mut c,
        U64x2::from_u64(K[13]),
        U64x2::from_u64(0),
    );
    rnd(
        c,
        d,
        e,
        &mut f,
        g,
        h,
        a,
        &mut b,
        U64x2::from_u64(K[14]),
        U64x2::from_u64(0),
    );
    rnd(
        b,
        c,
        d,
        &mut e,
        f,
        g,
        h,
        &mut a,
        U64x2::from_u64(K15_LEN),
        U64x2::from_u64(0),
    );

    expand16_hmac64(&mut w);
    rounds16(
        &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, 16,
    );
    expand16(&mut w);
    rounds16(
        &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, 32,
    );
    expand16(&mut w);
    rounds16(
        &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, 48,
    );
    expand16(&mut w);
    rounds16(
        &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h, &w, 64,
    );

    [
        add64(midw[0], a).to_u64(),
        add64(midw[1], b).to_u64(),
        add64(midw[2], c).to_u64(),
        add64(midw[3], d).to_u64(),
        add64(midw[4], e).to_u64(),
        add64(midw[5], f).to_u64(),
        add64(midw[6], g).to_u64(),
        add64(midw[7], h).to_u64(),
    ]
}

fn rounds16(
    a: &mut U64x2,
    b: &mut U64x2,
    c: &mut U64x2,
    d: &mut U64x2,
    e: &mut U64x2,
    f: &mut U64x2,
    g: &mut U64x2,
    h: &mut U64x2,
    w: &[U64x2; 16],
    base: usize,
) {
    rnd(*a, *b, *c, d, *e, *f, *g, h, U64x2::from_u64(K[base]), w[0]);
    rnd(
        *h,
        *a,
        *b,
        c,
        *d,
        *e,
        *f,
        g,
        U64x2::from_u64(K[base + 1]),
        w[1],
    );
    rnd(
        *g,
        *h,
        *a,
        b,
        *c,
        *d,
        *e,
        f,
        U64x2::from_u64(K[base + 2]),
        w[2],
    );
    rnd(
        *f,
        *g,
        *h,
        a,
        *b,
        *c,
        *d,
        e,
        U64x2::from_u64(K[base + 3]),
        w[3],
    );
    rnd(
        *e,
        *f,
        *g,
        h,
        *a,
        *b,
        *c,
        d,
        U64x2::from_u64(K[base + 4]),
        w[4],
    );
    rnd(
        *d,
        *e,
        *f,
        g,
        *h,
        *a,
        *b,
        c,
        U64x2::from_u64(K[base + 5]),
        w[5],
    );
    rnd(
        *c,
        *d,
        *e,
        f,
        *g,
        *h,
        *a,
        b,
        U64x2::from_u64(K[base + 6]),
        w[6],
    );
    rnd(
        *b,
        *c,
        *d,
        e,
        *f,
        *g,
        *h,
        a,
        U64x2::from_u64(K[base + 7]),
        w[7],
    );
    rnd(
        *a,
        *b,
        *c,
        d,
        *e,
        *f,
        *g,
        h,
        U64x2::from_u64(K[base + 8]),
        w[8],
    );
    rnd(
        *h,
        *a,
        *b,
        c,
        *d,
        *e,
        *f,
        g,
        U64x2::from_u64(K[base + 9]),
        w[9],
    );
    rnd(
        *g,
        *h,
        *a,
        b,
        *c,
        *d,
        *e,
        f,
        U64x2::from_u64(K[base + 10]),
        w[10],
    );
    rnd(
        *f,
        *g,
        *h,
        a,
        *b,
        *c,
        *d,
        e,
        U64x2::from_u64(K[base + 11]),
        w[11],
    );
    rnd(
        *e,
        *f,
        *g,
        h,
        *a,
        *b,
        *c,
        d,
        U64x2::from_u64(K[base + 12]),
        w[12],
    );
    rnd(
        *d,
        *e,
        *f,
        g,
        *h,
        *a,
        *b,
        c,
        U64x2::from_u64(K[base + 13]),
        w[13],
    );
    rnd(
        *c,
        *d,
        *e,
        f,
        *g,
        *h,
        *a,
        b,
        U64x2::from_u64(K[base + 14]),
        w[14],
    );
    rnd(
        *b,
        *c,
        *d,
        e,
        *f,
        *g,
        *h,
        a,
        U64x2::from_u64(K[base + 15]),
        w[15],
    );
}

fn expand16(w: &mut [U64x2; 16]) {
    w[0] = add64(add64(add64(w[0], sig1(w[14])), w[9]), sig0(w[1]));
    w[1] = add64(add64(add64(w[1], sig1(w[15])), w[10]), sig0(w[2]));
    w[2] = add64(add64(add64(w[2], sig1(w[0])), w[11]), sig0(w[3]));
    w[3] = add64(add64(add64(w[3], sig1(w[1])), w[12]), sig0(w[4]));
    w[4] = add64(add64(add64(w[4], sig1(w[2])), w[13]), sig0(w[5]));
    w[5] = add64(add64(add64(w[5], sig1(w[3])), w[14]), sig0(w[6]));
    w[6] = add64(add64(add64(w[6], sig1(w[4])), w[15]), sig0(w[7]));
    w[7] = add64(add64(add64(w[7], sig1(w[5])), w[0]), sig0(w[8]));
    w[8] = add64(add64(add64(w[8], sig1(w[6])), w[1]), sig0(w[9]));
    w[9] = add64(add64(add64(w[9], sig1(w[7])), w[2]), sig0(w[10]));
    w[10] = add64(add64(add64(w[10], sig1(w[8])), w[3]), sig0(w[11]));
    w[11] = add64(add64(add64(w[11], sig1(w[9])), w[4]), sig0(w[12]));
    w[12] = add64(add64(add64(w[12], sig1(w[10])), w[5]), sig0(w[13]));
    w[13] = add64(add64(add64(w[13], sig1(w[11])), w[6]), sig0(w[14]));
    w[14] = add64(add64(add64(w[14], sig1(w[12])), w[7]), sig0(w[15]));
    w[15] = add64(add64(add64(w[15], sig1(w[13])), w[8]), sig0(w[0]));
}

fn expand16_hmac64(w: &mut [U64x2; 16]) {
    w[0] = add64(w[0], sig0(w[1]));
    w[1] = add64(add64(w[1], U64x2::from_u64(SIG1_LEN)), sig0(w[2]));
    w[2] = add64(add64(w[2], sig1(w[0])), sig0(w[3]));
    w[3] = add64(add64(w[3], sig1(w[1])), sig0(w[4]));
    w[4] = add64(add64(w[4], sig1(w[2])), sig0(w[5]));
    w[5] = add64(add64(w[5], sig1(w[3])), sig0(w[6]));
    w[6] = add64(
        add64(add64(w[6], sig1(w[4])), U64x2::from_u64(BIT_LEN)),
        sig0(w[7]),
    );
    w[7] = add64(
        add64(add64(w[7], sig1(w[5])), w[0]),
        U64x2::from_u64(SIG0_PAD),
    );
    w[8] = add64(add64(w[8], sig1(w[6])), w[1]);
    w[9] = add64(add64(w[9], sig1(w[7])), w[2]);
    w[10] = add64(add64(w[10], sig1(w[8])), w[3]);
    w[11] = add64(add64(w[11], sig1(w[9])), w[4]);
    w[12] = add64(add64(w[12], sig1(w[10])), w[5]);
    w[13] = add64(add64(w[13], sig1(w[11])), w[6]);
    w[14] = add64(
        add64(add64(w[14], sig1(w[12])), w[7]),
        U64x2::from_u64(SIG0_LEN),
    );
    w[15] = add64(add64(add64(w[15], sig1(w[13])), w[8]), sig0(w[0]));
}

/// Ripple-carry bitsliced add: `steps` sequential majority/carry updates.
/// Used to make the bitslice-vs-SHF argument executable, not as a compressor.
pub fn bitslice_add_ripple(a: u64, b: u64) -> (u64, u32) {
    let mut sum = 0u64;
    let mut carry = 0u64;
    let mut steps = 0u32;
    for i in 0..64 {
        let ai = (a >> i) & 1;
        let bi = (b >> i) & 1;
        let s = ai ^ bi ^ carry;
        carry = (ai & bi) | (ai & carry) | (bi & carry);
        sum |= s << i;
        steps += 1;
    }
    (sum, steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512_hmac64;

    #[test]
    fn ror_shr_match_u64() {
        let amounts = [1u32, 6, 7, 8, 14, 18, 19, 28, 34, 39, 41, 61];
        let mut rng = 0x1111_2222_3333_4444u64;
        for _ in 0..200 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = U64x2::from_u64(rng);
            for &n in &amounts {
                assert_eq!(ror64(x, n).to_u64(), rng.rotate_right(n), "ror {n}");
            }
            assert_eq!(shr64(x, 6).to_u64(), rng >> 6);
            assert_eq!(shr64(x, 7).to_u64(), rng >> 7);
        }
    }

    #[test]
    fn sigma_match_u64() {
        let mut rng = 0xABCDu64;
        for _ in 0..80 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = U64x2::from_u64(rng);
            let s0 = rng.rotate_right(1) ^ rng.rotate_right(8) ^ (rng >> 7);
            let s1 = rng.rotate_right(19) ^ rng.rotate_right(61) ^ (rng >> 6);
            let e0 = rng.rotate_right(28) ^ rng.rotate_right(34) ^ rng.rotate_right(39);
            let e1 = rng.rotate_right(14) ^ rng.rotate_right(18) ^ rng.rotate_right(41);
            assert_eq!(sig0(x).to_u64(), s0);
            assert_eq!(sig1(x).to_u64(), s1);
            assert_eq!(ep0(x).to_u64(), e0);
            assert_eq!(ep1(x).to_u64(), e1);
        }
    }

    #[test]
    fn hmac64_u32_matches_u64() {
        let mut rng = 0x5a5a_5a5a_5a5a_5a5au64;
        for _ in 0..200 {
            let mut mid = [0u64; 8];
            let mut msg = [0u64; 8];
            for word in mid.iter_mut().chain(msg.iter_mut()) {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                *word = rng;
            }
            assert_eq!(
                compress_hmac64_u32(mid, msg),
                sha512_hmac64::compress_hmac64(mid, msg)
            );
        }
    }

    #[test]
    fn bitslice_add_needs_64_ripple_steps() {
        let (sum, steps) = bitslice_add_ripple(0xffff_ffff_ffff_ffff, 1);
        assert_eq!(sum, 0);
        assert_eq!(steps, BITSLICE_ADD_RIPPLE_STEPS);
        assert_eq!(HMAC64_SHF_FLOOR, 1550);
        const {
            assert!(80 * 7 * BITSLICE_ADD_RIPPLE_STEPS > HMAC64_SHF_FLOOR * 10);
        }
    }
}
