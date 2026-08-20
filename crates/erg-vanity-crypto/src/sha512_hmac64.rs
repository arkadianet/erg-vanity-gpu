//! Specialized SHA-512 compression for HMAC of a 64-byte message.
//!
//! After the ipad/opad block, HMAC-SHA512 of a 64-byte `U` always compresses:
//!   W[0..7]  = message
//!   W[8]     = 0x8000..00
//!   W[9..14] = 0
//!   W[15]    = 1536   (bit length of 128-byte ipad/opad + 64-byte U)
//!
//! This is not a generic SHA-512. It is the exact PBKDF2 inner-loop block.

/// HMAC padding bit as a SHA-512 word.
pub const PAD: u64 = 0x8000_0000_0000_0000;
/// Bit length of (128-byte key pad || 64-byte message).
pub const BIT_LEN: u64 = 1536;

// σ0(PAD), σ1(BIT_LEN), σ0(BIT_LEN) — compile-time schedule constants.
const SIG0_PAD: u64 = 0x4180_0000_0000_0000;
const SIG1_LEN: u64 = 0x00c0_0000_0000_3018;
const SIG0_LEN: u64 = 0x030a;

// K[8]+PAD and K[15]+BIT_LEN (wrapping).
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

#[inline(always)]
fn sig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline(always)]
fn sig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

#[inline(always)]
fn ep0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline(always)]
fn ep1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// CH as bitselect(z, y, x): z ^ (x & (y ^ z))
#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    z ^ (x & (y ^ z))
}

/// MAJ: (x&y) ^ (x&z) ^ (y&z) == (x & (y^z)) ^ (y & z)
#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & (y ^ z)) ^ (y & z)
}

/// In-place SHA-512 round. `h` becomes new `a`; `d` becomes new `e`.
#[inline(always)]
fn rnd(a: u64, b: u64, c: u64, d: &mut u64, e: u64, f: u64, g: u64, h: &mut u64, k: u64, w: u64) {
    *h = h
        .wrapping_add(ep1(e))
        .wrapping_add(ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    *d = d.wrapping_add(*h);
    *h = h.wrapping_add(ep0(a)).wrapping_add(maj(a, b, c));
}

#[inline(always)]
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

/// Generic 16-word SHA-512 compress (ipad/opad and U1 inner).
pub fn compress16(mid: [u64; 8], w_in: [u64; 16]) -> [u64; 8] {
    let mut w = [0u64; 80];
    w[..16].copy_from_slice(&w_in);
    for i in 16..80 {
        w[i] = w[i - 16]
            .wrapping_add(sig0(w[i - 15]))
            .wrapping_add(w[i - 7])
            .wrapping_add(sig1(w[i - 2]));
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = mid;
    for i in 0..80 {
        let t1 = h
            .wrapping_add(ep1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = ep0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    add8(mid, a, b, c, d, e, f, g, h)
}

/// Generic HMAC-64 block: same math as [`compress_hmac64`], no schedule folding.
/// Fair baseline for measuring specialization (matches the previous GPU hot path).
pub fn compress_hmac64_generic(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let mut w = [0u64; 16];
    w[..8].copy_from_slice(&msg);
    w[8] = PAD;
    w[15] = BIT_LEN;
    compress16(mid, w)
}

macro_rules! rounds16_from {
    ($base:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident,
     $w0:ident, $w1:ident, $w2:ident, $w3:ident, $w4:ident, $w5:ident, $w6:ident, $w7:ident,
     $w8:ident, $w9:ident, $w10:ident, $w11:ident, $w12:ident, $w13:ident, $w14:ident, $w15:ident) => {{
        rnd($a, $b, $c, &mut $d, $e, $f, $g, &mut $h, K[$base], $w0);
        rnd($h, $a, $b, &mut $c, $d, $e, $f, &mut $g, K[$base + 1], $w1);
        rnd($g, $h, $a, &mut $b, $c, $d, $e, &mut $f, K[$base + 2], $w2);
        rnd($f, $g, $h, &mut $a, $b, $c, $d, &mut $e, K[$base + 3], $w3);
        rnd($e, $f, $g, &mut $h, $a, $b, $c, &mut $d, K[$base + 4], $w4);
        rnd($d, $e, $f, &mut $g, $h, $a, $b, &mut $c, K[$base + 5], $w5);
        rnd($c, $d, $e, &mut $f, $g, $h, $a, &mut $b, K[$base + 6], $w6);
        rnd($b, $c, $d, &mut $e, $f, $g, $h, &mut $a, K[$base + 7], $w7);
        rnd($a, $b, $c, &mut $d, $e, $f, $g, &mut $h, K[$base + 8], $w8);
        rnd($h, $a, $b, &mut $c, $d, $e, $f, &mut $g, K[$base + 9], $w9);
        rnd(
            $g,
            $h,
            $a,
            &mut $b,
            $c,
            $d,
            $e,
            &mut $f,
            K[$base + 10],
            $w10,
        );
        rnd(
            $f,
            $g,
            $h,
            &mut $a,
            $b,
            $c,
            $d,
            &mut $e,
            K[$base + 11],
            $w11,
        );
        rnd(
            $e,
            $f,
            $g,
            &mut $h,
            $a,
            $b,
            $c,
            &mut $d,
            K[$base + 12],
            $w12,
        );
        rnd(
            $d,
            $e,
            $f,
            &mut $g,
            $h,
            $a,
            $b,
            &mut $c,
            K[$base + 13],
            $w13,
        );
        rnd(
            $c,
            $d,
            $e,
            &mut $f,
            $g,
            $h,
            $a,
            &mut $b,
            K[$base + 14],
            $w14,
        );
        rnd(
            $b,
            $c,
            $d,
            &mut $e,
            $f,
            $g,
            $h,
            &mut $a,
            K[$base + 15],
            $w15,
        );
    }};
}

#[inline(always)]
fn expand16(
    w0: &mut u64,
    w1: &mut u64,
    w2: &mut u64,
    w3: &mut u64,
    w4: &mut u64,
    w5: &mut u64,
    w6: &mut u64,
    w7: &mut u64,
    w8: &mut u64,
    w9: &mut u64,
    w10: &mut u64,
    w11: &mut u64,
    w12: &mut u64,
    w13: &mut u64,
    w14: &mut u64,
    w15: &mut u64,
) {
    *w0 = w0
        .wrapping_add(sig1(*w14))
        .wrapping_add(*w9)
        .wrapping_add(sig0(*w1));
    *w1 = w1
        .wrapping_add(sig1(*w15))
        .wrapping_add(*w10)
        .wrapping_add(sig0(*w2));
    *w2 = w2
        .wrapping_add(sig1(*w0))
        .wrapping_add(*w11)
        .wrapping_add(sig0(*w3));
    *w3 = w3
        .wrapping_add(sig1(*w1))
        .wrapping_add(*w12)
        .wrapping_add(sig0(*w4));
    *w4 = w4
        .wrapping_add(sig1(*w2))
        .wrapping_add(*w13)
        .wrapping_add(sig0(*w5));
    *w5 = w5
        .wrapping_add(sig1(*w3))
        .wrapping_add(*w14)
        .wrapping_add(sig0(*w6));
    *w6 = w6
        .wrapping_add(sig1(*w4))
        .wrapping_add(*w15)
        .wrapping_add(sig0(*w7));
    *w7 = w7
        .wrapping_add(sig1(*w5))
        .wrapping_add(*w0)
        .wrapping_add(sig0(*w8));
    *w8 = w8
        .wrapping_add(sig1(*w6))
        .wrapping_add(*w1)
        .wrapping_add(sig0(*w9));
    *w9 = w9
        .wrapping_add(sig1(*w7))
        .wrapping_add(*w2)
        .wrapping_add(sig0(*w10));
    *w10 = w10
        .wrapping_add(sig1(*w8))
        .wrapping_add(*w3)
        .wrapping_add(sig0(*w11));
    *w11 = w11
        .wrapping_add(sig1(*w9))
        .wrapping_add(*w4)
        .wrapping_add(sig0(*w12));
    *w12 = w12
        .wrapping_add(sig1(*w10))
        .wrapping_add(*w5)
        .wrapping_add(sig0(*w13));
    *w13 = w13
        .wrapping_add(sig1(*w11))
        .wrapping_add(*w6)
        .wrapping_add(sig0(*w14));
    *w14 = w14
        .wrapping_add(sig1(*w12))
        .wrapping_add(*w7)
        .wrapping_add(sig0(*w15));
    *w15 = w15
        .wrapping_add(sig1(*w13))
        .wrapping_add(*w8)
        .wrapping_add(sig0(*w0));
}

/// First expand: W[8..15] are HMAC-64 padding constants.
#[inline(always)]
fn expand16_hmac64(
    w0: &mut u64,
    w1: &mut u64,
    w2: &mut u64,
    w3: &mut u64,
    w4: &mut u64,
    w5: &mut u64,
    w6: &mut u64,
    w7: &mut u64,
    w8: &mut u64,
    w9: &mut u64,
    w10: &mut u64,
    w11: &mut u64,
    w12: &mut u64,
    w13: &mut u64,
    w14: &mut u64,
    w15: &mut u64,
) {
    *w0 = w0.wrapping_add(sig0(*w1));
    *w1 = w1.wrapping_add(SIG1_LEN).wrapping_add(sig0(*w2));
    *w2 = w2.wrapping_add(sig1(*w0)).wrapping_add(sig0(*w3));
    *w3 = w3.wrapping_add(sig1(*w1)).wrapping_add(sig0(*w4));
    *w4 = w4.wrapping_add(sig1(*w2)).wrapping_add(sig0(*w5));
    *w5 = w5.wrapping_add(sig1(*w3)).wrapping_add(sig0(*w6));
    *w6 = w6
        .wrapping_add(sig1(*w4))
        .wrapping_add(BIT_LEN)
        .wrapping_add(sig0(*w7));
    *w7 = w7
        .wrapping_add(sig1(*w5))
        .wrapping_add(*w0)
        .wrapping_add(SIG0_PAD);
    *w8 = w8.wrapping_add(sig1(*w6)).wrapping_add(*w1);
    *w9 = w9.wrapping_add(sig1(*w7)).wrapping_add(*w2);
    *w10 = w10.wrapping_add(sig1(*w8)).wrapping_add(*w3);
    *w11 = w11.wrapping_add(sig1(*w9)).wrapping_add(*w4);
    *w12 = w12.wrapping_add(sig1(*w10)).wrapping_add(*w5);
    *w13 = w13.wrapping_add(sig1(*w11)).wrapping_add(*w6);
    *w14 = w14
        .wrapping_add(sig1(*w12))
        .wrapping_add(*w7)
        .wrapping_add(SIG0_LEN);
    *w15 = w15
        .wrapping_add(sig1(*w13))
        .wrapping_add(*w8)
        .wrapping_add(sig0(*w0));
}

/// SHA-512 compress of the HMAC-64 padded block, schedule-specialized.
#[inline(always)]
pub fn compress_hmac64(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let mut w0 = msg[0];
    let mut w1 = msg[1];
    let mut w2 = msg[2];
    let mut w3 = msg[3];
    let mut w4 = msg[4];
    let mut w5 = msg[5];
    let mut w6 = msg[6];
    let mut w7 = msg[7];
    let mut w8 = PAD;
    let mut w9 = 0u64;
    let mut w10 = 0u64;
    let mut w11 = 0u64;
    let mut w12 = 0u64;
    let mut w13 = 0u64;
    let mut w14 = 0u64;
    let mut w15 = BIT_LEN;

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = mid;

    // Rounds 0-7: variable message words.
    rnd(a, b, c, &mut d, e, f, g, &mut h, K[0], w0);
    rnd(h, a, b, &mut c, d, e, f, &mut g, K[1], w1);
    rnd(g, h, a, &mut b, c, d, e, &mut f, K[2], w2);
    rnd(f, g, h, &mut a, b, c, d, &mut e, K[3], w3);
    rnd(e, f, g, &mut h, a, b, c, &mut d, K[4], w4);
    rnd(d, e, f, &mut g, h, a, b, &mut c, K[5], w5);
    rnd(c, d, e, &mut f, g, h, a, &mut b, K[6], w6);
    rnd(b, c, d, &mut e, f, g, h, &mut a, K[7], w7);
    // Rounds 8-15: W is padding; K+W folded for 8 and 15, W=0 for 9-14.
    rnd(a, b, c, &mut d, e, f, g, &mut h, K8_PAD, 0);
    rnd(h, a, b, &mut c, d, e, f, &mut g, K[9], 0);
    rnd(g, h, a, &mut b, c, d, e, &mut f, K[10], 0);
    rnd(f, g, h, &mut a, b, c, d, &mut e, K[11], 0);
    rnd(e, f, g, &mut h, a, b, c, &mut d, K[12], 0);
    rnd(d, e, f, &mut g, h, a, b, &mut c, K[13], 0);
    rnd(c, d, e, &mut f, g, h, a, &mut b, K[14], 0);
    rnd(b, c, d, &mut e, f, g, h, &mut a, K15_LEN, 0);

    expand16_hmac64(
        &mut w0, &mut w1, &mut w2, &mut w3, &mut w4, &mut w5, &mut w6, &mut w7, &mut w8, &mut w9,
        &mut w10, &mut w11, &mut w12, &mut w13, &mut w14, &mut w15,
    );
    rounds16_from!(
        16, a, b, c, d, e, f, g, h, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13,
        w14, w15
    );
    expand16(
        &mut w0, &mut w1, &mut w2, &mut w3, &mut w4, &mut w5, &mut w6, &mut w7, &mut w8, &mut w9,
        &mut w10, &mut w11, &mut w12, &mut w13, &mut w14, &mut w15,
    );
    rounds16_from!(
        32, a, b, c, d, e, f, g, h, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13,
        w14, w15
    );
    expand16(
        &mut w0, &mut w1, &mut w2, &mut w3, &mut w4, &mut w5, &mut w6, &mut w7, &mut w8, &mut w9,
        &mut w10, &mut w11, &mut w12, &mut w13, &mut w14, &mut w15,
    );
    rounds16_from!(
        48, a, b, c, d, e, f, g, h, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13,
        w14, w15
    );
    expand16(
        &mut w0, &mut w1, &mut w2, &mut w3, &mut w4, &mut w5, &mut w6, &mut w7, &mut w8, &mut w9,
        &mut w10, &mut w11, &mut w12, &mut w13, &mut w14, &mut w15,
    );
    rounds16_from!(
        64, a, b, c, d, e, f, g, h, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13,
        w14, w15
    );

    add8(mid, a, b, c, d, e, f, g, h)
}

/// HMAC-SHA512 of a 64-byte message given cached ipad/opad midstates.
#[inline(always)]
pub fn hmac64(inner: [u64; 8], outer: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    compress_hmac64(outer, compress_hmac64(inner, msg))
}

/// Two independent HMAC-64 evaluations, compressions interleaved for ILP.
pub fn hmac64_x2(inner: [[u64; 8]; 2], outer: [[u64; 8]; 2], msg: [[u64; 8]; 2]) -> [[u64; 8]; 2] {
    let i0 = compress_hmac64_x2(inner[0], msg[0], inner[1], msg[1]);
    compress_hmac64_x2(outer[0], i0[0], outer[1], i0[1])
}

#[inline(always)]
fn rnd2(
    a: [u64; 2],
    b: [u64; 2],
    c: [u64; 2],
    d: &mut [u64; 2],
    e: [u64; 2],
    f: [u64; 2],
    g: [u64; 2],
    h: &mut [u64; 2],
    k: u64,
    w: [u64; 2],
) {
    rnd(
        a[0], b[0], c[0], &mut d[0], e[0], f[0], g[0], &mut h[0], k, w[0],
    );
    rnd(
        a[1], b[1], c[1], &mut d[1], e[1], f[1], g[1], &mut h[1], k, w[1],
    );
}

/// Two HMAC-64 compressions in lockstep (independent midstates and messages).
fn compress_hmac64_x2(
    mid_a: [u64; 8],
    msg_a: [u64; 8],
    mid_b: [u64; 8],
    msg_b: [u64; 8],
) -> [[u64; 8]; 2] {
    let mut w0 = [msg_a[0], msg_b[0]];
    let mut w1 = [msg_a[1], msg_b[1]];
    let mut w2 = [msg_a[2], msg_b[2]];
    let mut w3 = [msg_a[3], msg_b[3]];
    let mut w4 = [msg_a[4], msg_b[4]];
    let mut w5 = [msg_a[5], msg_b[5]];
    let mut w6 = [msg_a[6], msg_b[6]];
    let mut w7 = [msg_a[7], msg_b[7]];
    let mut w8 = [PAD, PAD];
    let mut w9 = [0u64, 0];
    let mut w10 = [0u64, 0];
    let mut w11 = [0u64, 0];
    let mut w12 = [0u64, 0];
    let mut w13 = [0u64, 0];
    let mut w14 = [0u64, 0];
    let mut w15 = [BIT_LEN, BIT_LEN];

    let mut a = [mid_a[0], mid_b[0]];
    let mut b = [mid_a[1], mid_b[1]];
    let mut c = [mid_a[2], mid_b[2]];
    let mut d = [mid_a[3], mid_b[3]];
    let mut e = [mid_a[4], mid_b[4]];
    let mut f = [mid_a[5], mid_b[5]];
    let mut g = [mid_a[6], mid_b[6]];
    let mut h = [mid_a[7], mid_b[7]];

    rnd2(a, b, c, &mut d, e, f, g, &mut h, K[0], w0);
    rnd2(h, a, b, &mut c, d, e, f, &mut g, K[1], w1);
    rnd2(g, h, a, &mut b, c, d, e, &mut f, K[2], w2);
    rnd2(f, g, h, &mut a, b, c, d, &mut e, K[3], w3);
    rnd2(e, f, g, &mut h, a, b, c, &mut d, K[4], w4);
    rnd2(d, e, f, &mut g, h, a, b, &mut c, K[5], w5);
    rnd2(c, d, e, &mut f, g, h, a, &mut b, K[6], w6);
    rnd2(b, c, d, &mut e, f, g, h, &mut a, K[7], w7);
    rnd2(a, b, c, &mut d, e, f, g, &mut h, K8_PAD, [0, 0]);
    rnd2(h, a, b, &mut c, d, e, f, &mut g, K[9], [0, 0]);
    rnd2(g, h, a, &mut b, c, d, e, &mut f, K[10], [0, 0]);
    rnd2(f, g, h, &mut a, b, c, d, &mut e, K[11], [0, 0]);
    rnd2(e, f, g, &mut h, a, b, c, &mut d, K[12], [0, 0]);
    rnd2(d, e, f, &mut g, h, a, b, &mut c, K[13], [0, 0]);
    rnd2(c, d, e, &mut f, g, h, a, &mut b, K[14], [0, 0]);
    rnd2(b, c, d, &mut e, f, g, h, &mut a, K15_LEN, [0, 0]);

    expand16_hmac64(
        &mut w0[0],
        &mut w1[0],
        &mut w2[0],
        &mut w3[0],
        &mut w4[0],
        &mut w5[0],
        &mut w6[0],
        &mut w7[0],
        &mut w8[0],
        &mut w9[0],
        &mut w10[0],
        &mut w11[0],
        &mut w12[0],
        &mut w13[0],
        &mut w14[0],
        &mut w15[0],
    );
    expand16_hmac64(
        &mut w0[1],
        &mut w1[1],
        &mut w2[1],
        &mut w3[1],
        &mut w4[1],
        &mut w5[1],
        &mut w6[1],
        &mut w7[1],
        &mut w8[1],
        &mut w9[1],
        &mut w10[1],
        &mut w11[1],
        &mut w12[1],
        &mut w13[1],
        &mut w14[1],
        &mut w15[1],
    );

    macro_rules! r16x2 {
        ($base:expr) => {{
            rnd2(a, b, c, &mut d, e, f, g, &mut h, K[$base], w0);
            rnd2(h, a, b, &mut c, d, e, f, &mut g, K[$base + 1], w1);
            rnd2(g, h, a, &mut b, c, d, e, &mut f, K[$base + 2], w2);
            rnd2(f, g, h, &mut a, b, c, d, &mut e, K[$base + 3], w3);
            rnd2(e, f, g, &mut h, a, b, c, &mut d, K[$base + 4], w4);
            rnd2(d, e, f, &mut g, h, a, b, &mut c, K[$base + 5], w5);
            rnd2(c, d, e, &mut f, g, h, a, &mut b, K[$base + 6], w6);
            rnd2(b, c, d, &mut e, f, g, h, &mut a, K[$base + 7], w7);
            rnd2(a, b, c, &mut d, e, f, g, &mut h, K[$base + 8], w8);
            rnd2(h, a, b, &mut c, d, e, f, &mut g, K[$base + 9], w9);
            rnd2(g, h, a, &mut b, c, d, e, &mut f, K[$base + 10], w10);
            rnd2(f, g, h, &mut a, b, c, d, &mut e, K[$base + 11], w11);
            rnd2(e, f, g, &mut h, a, b, c, &mut d, K[$base + 12], w12);
            rnd2(d, e, f, &mut g, h, a, b, &mut c, K[$base + 13], w13);
            rnd2(c, d, e, &mut f, g, h, a, &mut b, K[$base + 14], w14);
            rnd2(b, c, d, &mut e, f, g, h, &mut a, K[$base + 15], w15);
        }};
    }

    r16x2!(16);
    expand16(
        &mut w0[0],
        &mut w1[0],
        &mut w2[0],
        &mut w3[0],
        &mut w4[0],
        &mut w5[0],
        &mut w6[0],
        &mut w7[0],
        &mut w8[0],
        &mut w9[0],
        &mut w10[0],
        &mut w11[0],
        &mut w12[0],
        &mut w13[0],
        &mut w14[0],
        &mut w15[0],
    );
    expand16(
        &mut w0[1],
        &mut w1[1],
        &mut w2[1],
        &mut w3[1],
        &mut w4[1],
        &mut w5[1],
        &mut w6[1],
        &mut w7[1],
        &mut w8[1],
        &mut w9[1],
        &mut w10[1],
        &mut w11[1],
        &mut w12[1],
        &mut w13[1],
        &mut w14[1],
        &mut w15[1],
    );
    r16x2!(32);
    expand16(
        &mut w0[0],
        &mut w1[0],
        &mut w2[0],
        &mut w3[0],
        &mut w4[0],
        &mut w5[0],
        &mut w6[0],
        &mut w7[0],
        &mut w8[0],
        &mut w9[0],
        &mut w10[0],
        &mut w11[0],
        &mut w12[0],
        &mut w13[0],
        &mut w14[0],
        &mut w15[0],
    );
    expand16(
        &mut w0[1],
        &mut w1[1],
        &mut w2[1],
        &mut w3[1],
        &mut w4[1],
        &mut w5[1],
        &mut w6[1],
        &mut w7[1],
        &mut w8[1],
        &mut w9[1],
        &mut w10[1],
        &mut w11[1],
        &mut w12[1],
        &mut w13[1],
        &mut w14[1],
        &mut w15[1],
    );
    r16x2!(48);
    expand16(
        &mut w0[0],
        &mut w1[0],
        &mut w2[0],
        &mut w3[0],
        &mut w4[0],
        &mut w5[0],
        &mut w6[0],
        &mut w7[0],
        &mut w8[0],
        &mut w9[0],
        &mut w10[0],
        &mut w11[0],
        &mut w12[0],
        &mut w13[0],
        &mut w14[0],
        &mut w15[0],
    );
    expand16(
        &mut w0[1],
        &mut w1[1],
        &mut w2[1],
        &mut w3[1],
        &mut w4[1],
        &mut w5[1],
        &mut w6[1],
        &mut w7[1],
        &mut w8[1],
        &mut w9[1],
        &mut w10[1],
        &mut w11[1],
        &mut w12[1],
        &mut w13[1],
        &mut w14[1],
        &mut w15[1],
    );
    r16x2!(64);

    [
        add8(mid_a, a[0], b[0], c[0], d[0], e[0], f[0], g[0], h[0]),
        add8(mid_b, a[1], b[1], c[1], d[1], e[1], f[1], g[1], h[1]),
    ]
}

/// Pack 64 bytes as eight big-endian words.
pub fn pack_be8(bytes: &[u8; 64]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (i, word) in w.iter_mut().enumerate() {
        let o = i * 8;
        *word = u64::from_be_bytes([
            bytes[o],
            bytes[o + 1],
            bytes[o + 2],
            bytes[o + 3],
            bytes[o + 4],
            bytes[o + 5],
            bytes[o + 6],
            bytes[o + 7],
        ]);
    }
    w
}

/// Unpack eight big-endian words to 64 bytes.
pub fn unpack_be8(words: [u64; 8]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

/// Sixteen big-endian words from a 128-byte block.
pub fn pack_be16(block: &[u8]) -> [u64; 16] {
    debug_assert!(block.len() >= 128);
    let mut w = [0u64; 16];
    for (i, word) in w.iter_mut().enumerate() {
        let o = i * 8;
        *word = u64::from_be_bytes([
            block[o],
            block[o + 1],
            block[o + 2],
            block[o + 3],
            block[o + 4],
            block[o + 5],
            block[o + 6],
            block[o + 7],
        ]);
    }
    w
}

/// SHA-512 finalize from a midstate (bytes already consumed = `prior_len`).
pub fn finalize_from_mid(mid: [u64; 8], prior_len: u64, data: &[u8]) -> [u64; 8] {
    let mut state = mid;
    let mut pos = 0usize;
    while pos + 128 <= data.len() {
        state = compress16(state, pack_be16(&data[pos..]));
        pos += 128;
    }

    let rem = &data[pos..];
    let bit_len = (prior_len + data.len() as u64).wrapping_mul(8);
    let mut block = [0u8; 128];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    if rem.len() >= 112 {
        state = compress16(state, pack_be16(&block));
        block = [0u8; 128];
    }
    block[120..128].copy_from_slice(&bit_len.to_be_bytes());
    compress16(state, pack_be16(&block))
}

/// HMAC-SHA512 of arbitrary data from cached midstates.
pub fn hmac_from_mid(inner: [u64; 8], outer: [u64; 8], data: &[u8]) -> [u64; 8] {
    if data.len() == 64 {
        return hmac64(inner, outer, pack_be8(data.try_into().unwrap()));
    }
    let inner_hash = finalize_from_mid(inner, 128, data);
    compress_hmac64(outer, inner_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512;

    fn maj_bitselect(x: u64, y: u64, z: u64) -> u64 {
        // bitselect(x, y, x^z) = ((x^z) & y) | (~(x^z) & x)
        let c = x ^ z;
        (c & y) | (!c & x)
    }

    #[test]
    fn constants_match_definition() {
        assert_eq!(SIG0_PAD, sig0(PAD));
        assert_eq!(SIG1_LEN, sig1(BIT_LEN));
        assert_eq!(SIG0_LEN, sig0(BIT_LEN));
        assert_eq!(K8_PAD, K[8].wrapping_add(PAD));
        assert_eq!(K15_LEN, K[15].wrapping_add(BIT_LEN));
    }

    #[test]
    fn maj_matches_spec_and_bitselect() {
        let spec = |x, y, z| (x & y) ^ (x & z) ^ (y & z);
        for x in [0u64, 1, 0xaaaa, u64::MAX, 0x0123_4567_89ab_cdef] {
            for y in [0u64, 1, 0x5555, u64::MAX, 0xfedc_ba98_7654_3210] {
                for z in [0u64, 3, 0xffff, u64::MAX, 0x1111_2222_3333_4444] {
                    assert_eq!(maj(x, y, z), spec(x, y, z));
                    assert_eq!(maj(x, y, z), maj_bitselect(x, y, z));
                }
            }
        }
    }

    #[test]
    fn hmac64_matches_generic_and_block_compress() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for _ in 0..400 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut mid = [0u64; 8];
            let mut msg = [0u64; 8];
            for word in mid.iter_mut().chain(msg.iter_mut()) {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                *word = rng;
            }

            let specialized = compress_hmac64(mid, msg);
            let generic = compress_hmac64_generic(mid, msg);
            assert_eq!(specialized, generic);

            let mut block = [0u8; 128];
            for (i, word) in msg.iter().enumerate() {
                block[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
            }
            block[64] = 0x80;
            block[120..128].copy_from_slice(&BIT_LEN.to_be_bytes());
            let mut state = mid;
            sha512::compress_block(&mut state, &block);
            assert_eq!(specialized, state);
        }
    }

    #[test]
    fn hmac64_x2_matches_singles() {
        let a = hmac64([1; 8], [2; 8], [3; 8]);
        let b = hmac64([4; 8], [5; 8], [6; 8]);
        let pair = hmac64_x2([[1; 8], [4; 8]], [[2; 8], [5; 8]], [[3; 8], [6; 8]]);
        assert_eq!(pair[0], a);
        assert_eq!(pair[1], b);
    }
}
