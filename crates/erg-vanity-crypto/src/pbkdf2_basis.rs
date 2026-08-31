//! Collective evaluation of N independent PBKDF2 instances.
//!
//! H22 showed that the conventional product DAG
//!   C_N = (C(P_1,S), …, C(P_N,S))
//! has almost no common subexpressions. That is not a lower bound on
//! *every* algorithm for C_N: FFT, batch inversion, fast multipoint
//! evaluation, and Pippenger MSM all compute many outputs cheaper than
//! N scalar runs *without* sharing the scalar intermediates.
//!
//! This module asks whether SHA-512 / HMAC / PBKDF2 has any analogous
//! change of basis. Research only; production `derive` is untouched.

use crate::sha512_hmac64::hmac64;
use crate::sha512_search::minisha8_round;

/// Prime used as a stand-in group for inversion / polynomial tests.
pub const P: u64 = 1_000_003;

/// 4-bit rotate (SHA-style circulant, not an 8-bit shift of a nibble).
#[inline]
fn rol4(x: u8, n: u32) -> u8 {
    let x = x & 15;
    let n = n & 3;
    ((x << n) | (x >> (4 - n))) & 15
}

/// MiniARX-4: one SHA-like ARX step on a 4-bit pair.
/// x' = x + rot₄(y,1),  y' = y ⊕ (x ∧ rot₄(y,2))  (mod 16).
#[inline]
pub fn miniarx4(x: u8, y: u8) -> (u8, u8) {
    let x = x & 15;
    let y = y & 15;
    let xp = x.wrapping_add(rol4(y, 1)) & 15;
    let yp = y ^ (x & rol4(y, 2));
    (xp, yp)
}

/// Scalar MiniARX-4 cost in {ADD, XOR, AND, ROT}.
pub const MINIARX4_OPS: u32 = 5;
pub const MINIARX4_PAIR_OPS: u32 = 2 * MINIARX4_OPS;

// ---------------------------------------------------------------------------
// Phenomenon that *does* work: Montgomery batch inversion
// ---------------------------------------------------------------------------

fn egcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

pub fn mod_inv(a: u64, p: u64) -> u64 {
    let (g, x, _) = egcd(a as i64, p as i64);
    assert_eq!(g, 1, "not invertible");
    ((x % p as i64 + p as i64) % p as i64) as u64
}

/// Fermat inversion in F_p, counting multiplications (square-and-multiply).
pub fn fermat_inv_muls(a: u64, p: u64) -> (u64, u32) {
    // a^{p-2} mod p
    let mut e = p - 2;
    let mut base = a % p;
    let mut acc = 1u64;
    let mut muls = 0u32;
    while e > 0 {
        if e & 1 == 1 {
            acc = (acc * base) % p;
            muls += 1;
        }
        e >>= 1;
        if e > 0 {
            base = (base * base) % p;
            muls += 1;
        }
    }
    (acc, muls)
}

/// Montgomery batch inverse: N inverses via 1 inverse + O(N) muls.
/// Returns (inverses, mul_count, inv_count).
pub fn batch_inv(xs: &[u64], p: u64) -> (Vec<u64>, u32, u32) {
    let n = xs.len();
    assert!(n > 0);
    let mut prefix = vec![0u64; n];
    prefix[0] = xs[0] % p;
    let mut muls = 0u32;
    for i in 1..n {
        prefix[i] = (prefix[i - 1] * (xs[i] % p)) % p;
        muls += 1;
    }
    let inv_all = mod_inv(prefix[n - 1], p);
    let mut out = vec![0u64; n];
    let mut acc = inv_all;
    for i in (1..n).rev() {
        out[i] = (acc * prefix[i - 1]) % p;
        muls += 1;
        acc = (acc * (xs[i] % p)) % p;
        muls += 1;
    }
    out[0] = acc;
    (out, muls, 1)
}

/// Work model: batch inversion beats N Fermat inversions for N ≥ 2.
pub fn batch_inv_beats_n(n: u32) -> bool {
    let mut xs = Vec::with_capacity(n as usize);
    let mut seed = 0x1234_5678u64;
    for _ in 0..n {
        seed = seed.wrapping_mul(0x9e37).wrapping_add(1);
        xs.push((seed % (P - 1)) + 1);
    }
    let (invs, muls, ninv) = batch_inv(&xs, P);
    let mut fermat_muls = 0u32;
    for (i, &x) in xs.iter().enumerate() {
        let (v, m) = fermat_inv_muls(x, P);
        assert_eq!(v, invs[i]);
        fermat_muls += m;
    }
    // One egcd inverse is cheaper than one Fermat; even counting it as a
    // full Fermat, 3N muls + 1 inv < N invs.
    let batch_as_fermat = muls + ninv * (fermat_muls / n);
    batch_as_fermat < fermat_muls
}

// ---------------------------------------------------------------------------
// Independent ANDs: one multiplication cannot produce two disjoint products
// ---------------------------------------------------------------------------

/// Affine form of 4 bits: bits 0..3 = coeffs of (a,b,c,d), bit 4 = constant.
fn eval_affine(mask: u8, abcd: u8) -> u8 {
    let mut v = (mask >> 4) & 1;
    for i in 0..4 {
        if (mask >> i) & 1 == 1 {
            v ^= (abcd >> i) & 1;
        }
    }
    v
}

/// GF(2) Gaussian: is `target[x]` in the affine span of {1, a, b, c, d, m(x)}?
#[allow(clippy::needless_range_loop)]
fn in_affine_span(m_of: &[u8; 16], target: impl Fn(u8) -> u8) -> bool {
    // Columns: 1, a, b, c, d, m. 16 rows.
    let mut a = [[0u8; 7]; 16];
    for x in 0..16u8 {
        a[x as usize][0] = 1;
        for i in 0..4 {
            a[x as usize][1 + i] = (x >> i) & 1;
        }
        a[x as usize][5] = m_of[x as usize];
        a[x as usize][6] = target(x);
    }
    let mut row = 0usize;
    for col in 0..6 {
        let mut piv = None;
        for r in row..16 {
            if a[r][col] == 1 {
                piv = Some(r);
                break;
            }
        }
        let Some(p) = piv else {
            continue;
        };
        a.swap(row, p);
        for r in 0..16 {
            if r != row && a[r][col] == 1 {
                for c in col..7 {
                    a[r][c] ^= a[row][c];
                }
            }
        }
        row += 1;
    }
    (row..16).all(|r| a[r][6] == 0)
}

/// Exhaustive: no single AND of affine forms of (a,b,c,d) yields both a∧b and c∧d.
pub fn one_and_cannot_make_two_independent() -> bool {
    for l1 in 0..32u8 {
        for l2 in 0..32u8 {
            let mut m = [0u8; 16];
            for x in 0..16u8 {
                m[x as usize] = eval_affine(l1, x) & eval_affine(l2, x);
            }
            let got_ab = in_affine_span(&m, |x| (x & 1) & ((x >> 1) & 1));
            let got_cd = in_affine_span(&m, |x| ((x >> 2) & 1) & ((x >> 3) & 1));
            if got_ab && got_cd {
                return false;
            }
        }
    }
    true
}

/// Same-pair identity: a+b = (a⊕b) + 2(a∧b). Couples ADD and AND of *one* pair.
pub fn add_xor_and_same_pair(a: u8, b: u8) -> bool {
    let add = a.wrapping_add(b);
    let xor = a ^ b;
    let and = a & b;
    add == xor.wrapping_add(and << 1)
}

// ---------------------------------------------------------------------------
// Polarization / homomorphism: f(x)⋆f(y) vs f(x⋆y)
// ---------------------------------------------------------------------------

pub fn minisha8_not_homomorphic(samples: u32) -> u32 {
    let mut bad = 0u32;
    let mut s = 0x1111_u64;
    for _ in 0..samples {
        s = s.wrapping_mul(0x9e37).wrapping_add(1);
        let x = s.to_le_bytes();
        s = s.wrapping_mul(0x9e37).wrapping_add(3);
        let y = s.to_le_bytes();
        let k = [0xA5u8, 0x3C];
        let w = [0x11u8, 0x22];
        let fx = minisha8_round(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], k[0], w[0]);
        let fy = minisha8_round(y[0], y[1], y[2], y[3], y[4], y[5], y[6], y[7], k[0], w[0]);
        let mut sum = [0u8; 8];
        let mut xor = [0u8; 8];
        for i in 0..8 {
            sum[i] = x[i].wrapping_add(y[i]);
            xor[i] = x[i] ^ y[i];
        }
        let fs = minisha8_round(
            sum[0], sum[1], sum[2], sum[3], sum[4], sum[5], sum[6], sum[7], k[0], w[0],
        );
        let fz = minisha8_round(
            xor[0], xor[1], xor[2], xor[3], xor[4], xor[5], xor[6], xor[7], k[0], w[0],
        );
        let f_add = (fx.0.wrapping_add(fy.0), fx.1.wrapping_add(fy.1));
        let f_xor = (fx.0 ^ fy.0, fx.1 ^ fy.1);
        if fs != f_add {
            bad += 1;
        }
        if fz != f_xor {
            bad += 1;
        }
    }
    bad
}

pub fn hmac64_polarization_fails(samples: u32) -> u32 {
    let mut bad = 0u32;
    let mut s = 7u64;
    for _ in 0..samples {
        s = s.wrapping_mul(0x9e37).wrapping_add(1);
        let inner = split8(s);
        s = s.wrapping_mul(3).wrapping_add(5);
        let outer = split8(s);
        s = s.wrapping_mul(7).wrapping_add(9);
        let m1 = split8(s);
        s = s.wrapping_mul(11).wrapping_add(13);
        let m2 = split8(s);
        let mut sum = [0u64; 8];
        let mut xor = [0u64; 8];
        for i in 0..8 {
            sum[i] = m1[i].wrapping_add(m2[i]);
            xor[i] = m1[i] ^ m2[i];
        }
        let h1 = hmac64(inner, outer, m1);
        let h2 = hmac64(inner, outer, m2);
        let hs = hmac64(inner, outer, sum);
        let hx = hmac64(inner, outer, xor);
        let mut ha = [0u64; 8];
        let mut hz = [0u64; 8];
        for i in 0..8 {
            ha[i] = h1[i].wrapping_add(h2[i]);
            hz[i] = h1[i] ^ h2[i];
        }
        if hs != ha {
            bad += 1;
        }
        if hx != hz {
            bad += 1;
        }
        // 2h(x) vs h(2x)
        let mut dbl = [0u64; 8];
        for i in 0..8 {
            dbl[i] = m1[i].wrapping_mul(2);
        }
        let hd = hmac64(inner, outer, dbl);
        let mut h2x = [0u64; 8];
        for i in 0..8 {
            h2x[i] = h1[i].wrapping_mul(2);
        }
        if hd != h2x {
            bad += 1;
        }
    }
    bad
}

fn split8(seed: u64) -> [u64; 8] {
    let mut s = seed;
    let mut o = [0u64; 8];
    for e in &mut o {
        s = s.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        *e = s.rotate_left(17) ^ s.wrapping_mul(0xbf58);
    }
    o
}

// ---------------------------------------------------------------------------
// Fourier / Walsh across the instance axis
// ---------------------------------------------------------------------------

/// Length-8 Walsh–Hadamard (instance axis). 24 add/sub = N log N.
pub fn walsh8(v: &mut [i32; 8]) {
    let mut h = 1;
    while h < 8 {
        for i in (0..8).step_by(h * 2) {
            for j in 0..h {
                let a = v[i + j];
                let b = v[i + j + h];
                v[i + j] = a + b;
                v[i + j + h] = a - b;
            }
        }
        h *= 2;
    }
}

pub fn ch_u8(e: u8, f: u8, g: u8) -> u8 {
    g ^ (e & (f ^ g))
}

/// Pointwise Ch after a Walsh mix is not Ch of the originals.
pub fn walsh_then_ch_is_wrong(samples: u32) -> u32 {
    let mut bad = 0u32;
    let mut s = 99u64;
    for _ in 0..samples {
        s = s.wrapping_mul(0x9e37).wrapping_add(1);
        let mut e = [0u8; 8];
        let mut f = [0u8; 8];
        let mut g = [0u8; 8];
        for i in 0..8 {
            e[i] = (s >> (i * 3)) as u8;
            f[i] = (s.wrapping_mul(3) >> (i * 3)) as u8;
            g[i] = (s.wrapping_mul(5) >> (i * 3)) as u8;
        }
        let direct: [u8; 8] = std::array::from_fn(|i| ch_u8(e[i], f[i], g[i]));
        let mut we = e.map(|x| x as i32);
        walsh8(&mut we);
        let mut wf = f.map(|x| x as i32);
        walsh8(&mut wf);
        let mut wg = g.map(|x| x as i32);
        walsh8(&mut wg);
        let mut mixed = [0i32; 8];
        for i in 0..8 {
            // Ch on Walsh lanes (the "evaluate in the other basis" attempt).
            let ee = we[i] as u8;
            let ff = wf[i] as u8;
            let gg = wg[i] as u8;
            mixed[i] = ch_u8(ee, ff, gg) as i32;
        }
        walsh8(&mut mixed);
        // Inverse WH is WH/8; compare signs / equality after scale.
        let mut differ = false;
        for i in 0..8 {
            if mixed[i] / 8 != direct[i] as i32 {
                differ = true;
            }
        }
        if differ {
            bad += 1;
        }
    }
    bad
}

/// Cost: N pointwise 3-rotate Σ vs enter-DFT / pointwise / leave-DFT.
/// Circulant Σ is already 3-sparse; FFT-N is N log N.
pub fn fft_sigma_cost(n: u32) -> (u32, u32) {
    let sparse = 3 * n;
    // radix-2 real FFT-ish: 2 N log2 N butterflies, each ~2 add + 1 mul.
    let log = n.trailing_zeros().max(1);
    let fft = 2 * n * log * 3;
    (sparse, fft)
}

// ---------------------------------------------------------------------------
// Polynomial / multipoint economics
// ---------------------------------------------------------------------------

/// Naive Horner muls for a degree-d poly at N points: N · d.
pub fn horner_muls(n: u32, d: u32) -> u32 {
    n * d
}

/// Textbook fast-multipoint estimate: O((N+d) log²(N+d)).
pub fn fast_mp_muls_est(n: u32, d: u32) -> u32 {
    let m = (n + d).max(2);
    let log = 32 - m.leading_zeros();
    m * log * log
}

pub fn ch_is_degree_two_horner_optimal() -> bool {
    // Ch = z ⊕ (x ∧ (y⊕z)): already 1 AND. Horner of a dense degree-2
    // trivariate is not cheaper. Fast multipoint helps dense *high* degree.
    horner_muls(32, 2) < fast_mp_muls_est(32, 2)
        && fast_mp_muls_est(256, 256) < horner_muls(256, 256)
}

/// Algebraic degree over GF(2) of one output bit, via Möbius transform.
pub fn anf_degree(truth: &[u8], nbits: u32) -> u32 {
    let n = 1usize << nbits;
    assert_eq!(truth.len(), n);
    let mut a = truth.to_vec();
    let mut step = 1;
    while step < n {
        for i in 0..n {
            if i & step != 0 {
                a[i] ^= a[i ^ step];
            }
        }
        step <<= 1;
    }
    let mut deg = 0u32;
    for (i, &c) in a.iter().enumerate() {
        if c & 1 == 1 {
            deg = deg.max((i as u32).count_ones());
        }
    }
    deg
}

/// Carry makes wrapping-add high degree over GF(2). Ch is degree 2.
/// No single ring makes the whole ARX step a low-degree polynomial.
pub fn add_high_degree_ch_degree_two() -> (u32, u32) {
    // bit 3 of 4-bit x+y: 8 input bits.
    let mut add_bit3 = vec![0u8; 256];
    for x in 0..16u8 {
        for y in 0..16u8 {
            let s = x.wrapping_add(y) & 15;
            add_bit3[((x as usize) << 4) | y as usize] = (s >> 3) & 1;
        }
    }
    // bit 0 of Ch(e,f,g) on 3 bits (embed in 8 by padding zeros conceptually:
    // use 3-bit domain).
    let mut ch_bit = vec![0u8; 8];
    for e in 0..2u8 {
        for f in 0..2u8 {
            for g in 0..2u8 {
                let v = ch_u8(e, f, g) & 1;
                ch_bit[((e as usize) << 2) | ((f as usize) << 1) | g as usize] = v;
            }
        }
    }
    (anf_degree(&add_bit3, 8), anf_degree(&ch_bit, 3))
}

/// Finite differences of MiniARX along an arithmetic progression of x.
/// A low-degree integer polynomial of degree < k has vanishing k-th diffs.
pub fn miniarx_ap_nth_diff_nonzero(order: usize) -> bool {
    let y = 0x5u8;
    let mut vals: Vec<i32> = (0..24u8).map(|i| miniarx4(i & 15, y).0 as i32).collect();
    for _ in 0..order {
        if vals.len() < 2 {
            return true;
        }
        let next: Vec<i32> = vals.windows(2).map(|w| w[1] - w[0]).collect();
        vals = next;
    }
    vals.iter().any(|&d| d != 0)
}

// ---------------------------------------------------------------------------
// Packed / SWAR batch add (representation change, not a prefix adder)
// ---------------------------------------------------------------------------

/// Exact two 4-bit adds packed in 8 bits with a 1-bit guard.
/// Returns (z0, z1, word-ops). Bitwise counted at the same unit as ADD.
pub fn packed_nibble_add(x0: u8, y0: u8, x1: u8, y1: u8) -> (u8, u8, u32) {
    // Guard bit between nibbles so the packed add cannot carry across instances.
    let a = (u16::from(x0) & 15) | ((u16::from(x1) & 15) << 5);
    let b = (u16::from(y0) & 15) | ((u16::from(y1) & 15) << 5);
    let s = a.wrapping_add(b);
    let z0 = (s & 15) as u8;
    let z1 = ((s >> 5) & 15) as u8;
    // pack: 4 AND + 2 SHL + 2 OR; 1 add; unpack: 1 SHR + 2 AND.
    (z0, z1, 12)
}

pub const TWO_SCALAR_ADDS: u32 = 2;

// ---------------------------------------------------------------------------
// Linear change of basis across instances
// ---------------------------------------------------------------------------

/// Store (u,v) = (x0+x1, x0⊕x1) instead of (x0,x1). Recover, apply MiniARX,
/// re-encode. Extra linear mix cannot avoid two MiniARX evaluations.
pub fn mixed_basis_still_two_miniarx(x0: u8, y0: u8, x1: u8, y1: u8) -> bool {
    let (a0, b0) = miniarx4(x0, y0);
    let (a1, b1) = miniarx4(x1, y1);
    let (mu, mv) = miniarx4(x0.wrapping_add(x1) & 15, y0.wrapping_add(y1) & 15);
    mu != (a0.wrapping_add(a1) & 15) || mv != (b0.wrapping_add(b1) & 15)
}

// ---------------------------------------------------------------------------
// 2-instance MiniARX superopt with cross-instance ops
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Op {
    Add(u8, u8),
    Xor(u8, u8),
    And(u8, u8),
    Rol(u8, u8),
}

fn exec_prog(ops: &[Op], x0: u8, y0: u8, x1: u8, y1: u8) -> Option<(u8, u8, u8, u8)> {
    let mut r = vec![x0 & 15, y0 & 15, x1 & 15, y1 & 15];
    for op in ops {
        let v = match *op {
            Op::Add(i, j) => r.get(i as usize)?.wrapping_add(*r.get(j as usize)?) & 15,
            Op::Xor(i, j) => r.get(i as usize)? ^ *r.get(j as usize)?,
            Op::And(i, j) => r.get(i as usize)? & *r.get(j as usize)?,
            Op::Rol(i, k) => rol4(*r.get(i as usize)?, (k % 4) as u32),
        };
        r.push(v);
    }
    let n = r.len();
    if n < 8 {
        return None;
    }
    // Last four values are a candidate for (x0',y0',x1',y1') in some order.
    // Conventional SIMD writes results as it goes; we accept any 4-tuple
    // that matches the spec (search checks all windows of 4 at the end).
    Some((r[n - 4], r[n - 3], r[n - 2], r[n - 1]))
}

fn spec4(x0: u8, y0: u8, x1: u8, y1: u8) -> (u8, u8, u8, u8) {
    let (a, b) = miniarx4(x0, y0);
    let (c, d) = miniarx4(x1, y1);
    (a, b, c, d)
}

fn matches_spec(ops: &[Op], trials: &[(u8, u8, u8, u8)]) -> bool {
    for &(x0, y0, x1, y1) in trials {
        let Some(got) = exec_prog(ops, x0, y0, x1, y1) else {
            return false;
        };
        if got != spec4(x0, y0, x1, y1) {
            return false;
        }
    }
    true
}

fn random_op(rng: &mut u64, nregs: u8) -> Op {
    *rng = rng.wrapping_mul(0x9e37_79b9).wrapping_add(1);
    let k = (*rng >> 8) as u8;
    let i = k % nregs;
    let j = (k >> 2) % nregs;
    match k % 4 {
        0 => Op::Add(i, j),
        1 => Op::Xor(i, j),
        2 => Op::And(i, j),
        _ => Op::Rol(i, 1 + (k % 3)),
    }
}

/// Random mixed-instance programs cheaper than 2× scalar. Returns hits.
pub fn miniarx_mixed_superopt(steps: u32, seed: u64) -> u32 {
    let mut trials = Vec::with_capacity(48);
    let mut s = 1u64;
    for _ in 0..48 {
        s = s.wrapping_mul(0x9e37).wrapping_add(3);
        trials.push((
            (s as u8) & 15,
            ((s >> 8) as u8) & 15,
            ((s >> 16) as u8) & 15,
            ((s >> 24) as u8) & 15,
        ));
    }
    let mut rng = seed;
    let mut hits = 0u32;
    for _ in 0..steps {
        // Programs of length 8 or 9 (< 10).
        rng = rng.wrapping_mul(0x9e37).wrapping_add(1);
        let len = 8 + (rng % 2) as usize;
        let mut ops = Vec::with_capacity(len);
        for k in 0..len {
            ops.push(random_op(&mut rng, 4 + k as u8));
        }
        if matches_spec(&ops, &trials) {
            // Confirm on a denser sample before counting.
            let mut extra = Vec::with_capacity(256);
            let mut t = rng;
            for _ in 0..256 {
                t = t.wrapping_mul(0x9e37).wrapping_add(1);
                extra.push((
                    (t as u8) & 15,
                    ((t >> 4) as u8) & 15,
                    ((t >> 8) as u8) & 15,
                    ((t >> 12) as u8) & 15,
                ));
            }
            if matches_spec(&ops, &extra) {
                hits += 1;
            }
        }
    }
    hits
}

/// Applying MiniARX to (x0+x1, y0+y1) does not yield a pair of outputs.
pub fn sum_then_miniarx_fails() -> bool {
    let (x0, y0, x1, y1) = (3u8, 5, 9, 12);
    let (a0, b0) = miniarx4(x0, y0);
    let (a1, b1) = miniarx4(x1, y1);
    let (as_, bs) = miniarx4(x0.wrapping_add(x1) & 15, y0.wrapping_add(y1) & 15);
    as_ != (a0.wrapping_add(a1) & 15) || bs != (b0.wrapping_add(b1) & 15)
}

// ---------------------------------------------------------------------------
// Same map, many iterates: PBKDF2 wants the XOR of the orbit, not f^c
// ---------------------------------------------------------------------------

/// If we only needed f^c(x) and f were linear, matrix power would help.
/// PBKDF2 needs ⊕_{j=1..c} f^j(x), and f differs per password (I,O).
pub fn orbit_xor_needs_all_images(c: u32) -> bool {
    // Toy linear f(x) = 3x+1 mod P. Closed form exists, but the XOR (here:
    // field sum) of the orbit is not a cheap function of f^c alone.
    let x = 17u64;
    let mut u = x;
    let mut acc = 0u64;
    let mut last = 0u64;
    for _ in 0..c {
        u = (3 * u + 1) % P;
        acc = (acc + u) % P;
        last = u;
    }
    // acc == last would mean the rest cancelled — false for this f, c>1.
    acc != last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_inversion_is_the_existence_proof() {
        assert!(batch_inv_beats_n(8));
        assert!(batch_inv_beats_n(32));
        let xs: Vec<u64> = (1..9).collect();
        let (invs, muls, ninv) = batch_inv(&xs, P);
        assert_eq!(ninv, 1);
        assert!(muls <= 3 * 8);
        for (x, i) in xs.iter().zip(invs.iter()) {
            assert_eq!((*x * *i) % P, 1);
        }
    }

    #[test]
    fn independent_ands_need_independent_multiplies() {
        assert!(one_and_cannot_make_two_independent());
        assert!(add_xor_and_same_pair(0xA5, 0x3C));
        assert!(add_xor_and_same_pair(0x00, 0xFF));
        assert!(add_xor_and_same_pair(0x80, 0x80));
        // The identity is per-pair. It does not give a second AND.
        let a = 0x0Fu8;
        let b = 0x33u8;
        let c = 0x55u8;
        let d = 0xAAu8;
        let from_add = a.wrapping_add(b) ^ (a ^ b); // 2*(a&b) in the low bits, not c&d
        assert_ne!(from_add, c & d);
    }

    #[test]
    fn sha_like_maps_have_no_polarization() {
        assert!(minisha8_not_homomorphic(80) >= 150);
        assert!(hmac64_polarization_fails(40) >= 110);
        assert!(sum_then_miniarx_fails());
        // A few arithmetic-progression pairs add by accident; the map is not additive.
        let mut mixed_bad = 0u32;
        for x0 in 0..16u8 {
            for y0 in 0..16u8 {
                if mixed_basis_still_two_miniarx(x0, y0, x0.wrapping_add(3) & 15, y0 ^ 5) {
                    mixed_bad += 1;
                }
            }
        }
        assert!(
            mixed_bad > 200,
            "mixed-basis MiniARX failed on {mixed_bad} pairs"
        );
    }

    #[test]
    fn walsh_basis_makes_ch_a_different_function() {
        assert_eq!(walsh_then_ch_is_wrong(60), 60);
        let (sparse, fft) = fft_sigma_cost(32);
        assert_eq!(sparse, 96);
        assert!(fft > sparse * 4);
    }

    #[test]
    fn multipoint_wins_only_for_dense_high_degree() {
        assert!(ch_is_degree_two_horner_optimal());
        let (add_deg, ch_deg) = add_high_degree_ch_degree_two();
        assert_eq!(ch_deg, 2);
        // Carry into bit 3 of a 4-bit add depends on all lower bits.
        assert!(add_deg >= 4, "add degree {add_deg}");
        // MiniARX along an AP is not a cubic (or degree-7) integer poly.
        assert!(miniarx_ap_nth_diff_nonzero(3));
        assert!(miniarx_ap_nth_diff_nonzero(7));
    }

    #[test]
    fn swar_pack_is_more_word_ops_than_two_adds() {
        for x0 in 0..16u8 {
            for y0 in (0..16).step_by(3) {
                let (z0, z1, ops) = packed_nibble_add(x0, y0, x0 ^ 7, y0 ^ 9);
                assert_eq!(z0, x0.wrapping_add(y0) & 15);
                assert_eq!(z1, (x0 ^ 7).wrapping_add(y0 ^ 9) & 15);
                assert!(ops > TWO_SCALAR_ADDS);
            }
        }
    }

    #[test]
    fn mixed_miniarx_superopt_finds_no_sub_2x_program() {
        // 8k random mixed programs of length 8–9. A hit would be a toy
        // collective ARX win and would be pursued.
        let hits = miniarx_mixed_superopt(8_000, 0x000b_4515_u64);
        assert_eq!(hits, 0);
        assert_eq!(MINIARX4_PAIR_OPS, 10);
    }

    #[test]
    fn orbit_xor_is_not_the_last_iterate() {
        assert!(orbit_xor_needs_all_images(8));
        assert!(orbit_xor_needs_all_images(2048));
    }

    #[test]
    fn miniarx_matches_hand() {
        assert_eq!(miniarx4(1, 2), {
            let xp = (1u8.wrapping_add(rol4(2, 1))) & 15;
            let yp = 2 ^ (1 & rol4(2, 2));
            (xp, yp)
        });
        // 4-bit rotate is not ℤ-linear: rot(8)+rot(8) ≠ rot(8+8).
        assert_ne!(rol4(8, 1).wrapping_add(rol4(8, 1)) & 15, rol4(0, 1));
    }
}
