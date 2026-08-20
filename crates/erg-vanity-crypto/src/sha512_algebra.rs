//! Exact-evaluation experiments on SHA-512 / HMAC-64 / PBKDF2.
//!
//! Not a production path. Each prototype is either bit-identical to the
//! conventional compressor or a deliberate counter-example.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::assertions_on_constants)]

use std::collections::HashMap;

#[cfg(test)]
use crate::sha512_hmac64::compress_hmac64;
use crate::sha512_hmac64::{BIT_LEN, K, PAD};

const K0: u64 = K[0];
const K1: u64 = K[1];

#[inline]
fn ror(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline]
fn sig0(x: u64) -> u64 {
    ror(x, 1) ^ ror(x, 8) ^ (x >> 7)
}

#[inline]
fn sig1(x: u64) -> u64 {
    ror(x, 19) ^ ror(x, 61) ^ (x >> 6)
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
fn ch(x: u64, y: u64, z: u64) -> u64 {
    z ^ (x & (y ^ z))
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & (y ^ z)) ^ (y & z)
}

/// Ch(x, c, d) when c, d are independent of x: one AND and one XOR with constants.
#[inline]
pub fn ch_fixed_yz(x: u64, c: u64, d: u64) -> u64 {
    (x & (c ^ d)) ^ d
}

/// Maj(x, c, d) when c, d are independent of x.
#[inline]
pub fn maj_fixed_yz(x: u64, c: u64, d: u64) -> u64 {
    (x & (c ^ d)) ^ (c & d)
}

/// Carry-save 3:2. (s, c) satisfies s.wrapping_add(c) == x+y+z (mod 2^64).
#[inline]
pub fn csa32(x: u64, y: u64, z: u64) -> (u64, u64) {
    let s = x ^ y ^ z;
    let c = ((x & y) | (x & z) | (y & z)).wrapping_shl(1);
    (s, c)
}

/// T1 via 5-to-2 CSA + one CPA. Bit-identical to four sequential adds.
pub fn t1_csa(h: u64, s1: u64, chv: u64, k: u64, w: u64) -> u64 {
    let (s, c) = csa32(h, s1, chv);
    let (s, c) = csa32(s, c, k);
    let (s, c) = csa32(s, c, w);
    s.wrapping_add(c)
}

/// One conventional SHA-512 step. Returns (a', e') and the shifted state.
#[inline]
fn step(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    k: u64,
    w: u64,
) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let t1 = h
        .wrapping_add(ep1(e))
        .wrapping_add(ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = ep0(a).wrapping_add(maj(a, b, c));
    (t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g)
}

/// Two rounds written as one formula. Same ops as two `step`s; no cancellation.
pub fn fused_two_rounds(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    k0: u64,
    w0: u64,
    k1: u64,
    w1: u64,
) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let t1_0 = h
        .wrapping_add(ep1(e))
        .wrapping_add(ch(e, f, g))
        .wrapping_add(k0)
        .wrapping_add(w0);
    let t2_0 = ep0(a).wrapping_add(maj(a, b, c));
    let a1 = t1_0.wrapping_add(t2_0);
    let e1 = d.wrapping_add(t1_0);
    let t1_1 = g
        .wrapping_add(ep1(e1))
        .wrapping_add(ch(e1, e, f))
        .wrapping_add(k1)
        .wrapping_add(w1);
    let t2_1 = ep0(a1).wrapping_add(maj(a1, a, b));
    (
        t1_1.wrapping_add(t2_1),
        a1,
        a,
        b,
        c.wrapping_add(t1_1),
        e1,
        e,
        f,
    )
}

/// Per-seed constants for round 0 of a fixed midstate (inner or outer).
#[derive(Clone, Copy)]
pub struct Round0Pe {
    a_base: u64,
    e_base: u64,
    a0: u64,
    b0: u64,
    c0: u64,
    e0: u64,
    f0: u64,
    g0: u64,
}

impl Round0Pe {
    pub fn from_mid(mid: [u64; 8]) -> Self {
        let [a0, b0, c0, d0, e0, f0, g0, h0] = mid;
        let t1_base = h0
            .wrapping_add(ep1(e0))
            .wrapping_add(ch(e0, f0, g0))
            .wrapping_add(K0);
        Self {
            a_base: t1_base.wrapping_add(ep0(a0)).wrapping_add(maj(a0, b0, c0)),
            e_base: d0.wrapping_add(t1_base),
            a0,
            b0,
            c0,
            e0,
            f0,
            g0,
        }
    }
}

/// HMAC-64 compress with round 0 compiled from `mid` and round-1 Ch/Maj specialized.
/// Bit-identical to [`compress_hmac64`]. Saves ~1/80 of the round function.
pub fn compress_hmac64_pe(mid: [u64; 8], msg: [u64; 8]) -> [u64; 8] {
    let pe = Round0Pe::from_mid(mid);
    let mut w = [0u64; 80];
    w[..8].copy_from_slice(&msg);
    w[8] = PAD;
    w[15] = BIT_LEN;
    for t in 16..80 {
        w[t] = w[t - 16]
            .wrapping_add(sig0(w[t - 15]))
            .wrapping_add(w[t - 7])
            .wrapping_add(sig1(w[t - 2]));
    }

    let a1 = pe.a_base.wrapping_add(w[0]);
    let e1 = pe.e_base.wrapping_add(w[0]);
    let t1 = pe
        .g0
        .wrapping_add(ep1(e1))
        .wrapping_add(ch_fixed_yz(e1, pe.e0, pe.f0))
        .wrapping_add(K1)
        .wrapping_add(w[1]);
    let t2 = ep0(a1).wrapping_add(maj_fixed_yz(a1, pe.a0, pe.b0));
    let mut a = t1.wrapping_add(t2);
    let mut b = a1;
    let mut c = pe.a0;
    let mut d = pe.b0;
    let mut e = pe.c0.wrapping_add(t1);
    let mut f = e1;
    let mut g = pe.e0;
    let mut h = pe.f0;

    for t in 2..80 {
        let nxt = step(a, b, c, d, e, f, g, h, K[t], w[t]);
        a = nxt.0;
        b = nxt.1;
        c = nxt.2;
        d = nxt.3;
        e = nxt.4;
        f = nxt.5;
        g = nxt.6;
        h = nxt.7;
    }
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

/// Word-level hash-cons DAG. Counts unique ARX nodes; used to hunt CSE.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Node {
    In(u8),
    Const(u64),
    Ror(u32, u8),
    Shr(u32, u8),
    Xor(u32, u32),
    And(u32, u32),
    Add(u32, u32),
}

#[derive(Default)]
struct Dag {
    nodes: Vec<Node>,
    intern: HashMap<Node, u32>,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct DagCounts {
    pub ror: u32,
    pub shr: u32,
    pub xor: u32,
    pub and: u32,
    pub add: u32,
}

impl Dag {
    fn id(&mut self, n: Node) -> u32 {
        if let Some(&i) = self.intern.get(&n) {
            return i;
        }
        let i = self.nodes.len() as u32;
        self.nodes.push(n);
        self.intern.insert(n, i);
        i
    }

    fn inp(&mut self, i: u8) -> u32 {
        self.id(Node::In(i))
    }
    fn cst(&mut self, c: u64) -> u32 {
        self.id(Node::Const(c))
    }
    fn as_const(&self, x: u32) -> Option<u64> {
        match self.nodes[x as usize] {
            Node::Const(c) => Some(c),
            _ => None,
        }
    }
    fn ror(&mut self, x: u32, n: u8) -> u32 {
        if let Some(c) = self.as_const(x) {
            return self.cst(c.rotate_right(n as u32));
        }
        self.id(Node::Ror(x, n))
    }
    fn shr(&mut self, x: u32, n: u8) -> u32 {
        if let Some(c) = self.as_const(x) {
            return self.cst(c >> n);
        }
        self.id(Node::Shr(x, n))
    }
    fn xor(&mut self, a: u32, b: u32) -> u32 {
        match (self.as_const(a), self.as_const(b)) {
            (Some(x), Some(y)) => return self.cst(x ^ y),
            (Some(0), _) => return b,
            (_, Some(0)) => return a,
            _ => {}
        }
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        self.id(Node::Xor(a, b))
    }
    fn and(&mut self, a: u32, b: u32) -> u32 {
        match (self.as_const(a), self.as_const(b)) {
            (Some(x), Some(y)) => return self.cst(x & y),
            (Some(0), _) | (_, Some(0)) => return self.cst(0),
            _ => {}
        }
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        self.id(Node::And(a, b))
    }
    fn add(&mut self, a: u32, b: u32) -> u32 {
        match (self.as_const(a), self.as_const(b)) {
            (Some(x), Some(y)) => return self.cst(x.wrapping_add(y)),
            (Some(0), _) => return b,
            (_, Some(0)) => return a,
            _ => {}
        }
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        self.id(Node::Add(a, b))
    }

    fn xor3(&mut self, a: u32, b: u32, c: u32) -> u32 {
        let t = self.xor(a, b);
        self.xor(t, c)
    }

    fn ep0(&mut self, x: u32) -> u32 {
        let r28 = self.ror(x, 28);
        let r34 = self.ror(x, 34);
        let r39 = self.ror(x, 39);
        self.xor3(r28, r34, r39)
    }
    fn ep1(&mut self, x: u32) -> u32 {
        let r14 = self.ror(x, 14);
        let r18 = self.ror(x, 18);
        let r41 = self.ror(x, 41);
        self.xor3(r14, r18, r41)
    }
    fn s0(&mut self, x: u32) -> u32 {
        let r1 = self.ror(x, 1);
        let r8 = self.ror(x, 8);
        let s7 = self.shr(x, 7);
        self.xor3(r1, r8, s7)
    }
    fn s1(&mut self, x: u32) -> u32 {
        let r19 = self.ror(x, 19);
        let r61 = self.ror(x, 61);
        let s6 = self.shr(x, 6);
        self.xor3(r19, r61, s6)
    }
    fn ch(&mut self, x: u32, y: u32, z: u32) -> u32 {
        let t = self.xor(y, z);
        let t = self.and(x, t);
        self.xor(z, t)
    }
    fn maj(&mut self, x: u32, y: u32, z: u32) -> u32 {
        let t = self.xor(y, z);
        let t = self.and(x, t);
        let u = self.and(y, z);
        self.xor(t, u)
    }

    fn counts(&self) -> DagCounts {
        let mut c = DagCounts::default();
        for n in &self.nodes {
            match n {
                Node::Ror(_, _) => c.ror += 1,
                Node::Shr(_, _) => c.shr += 1,
                Node::Xor(_, _) => c.xor += 1,
                Node::And(_, _) => c.and += 1,
                Node::Add(_, _) => c.add += 1,
                Node::In(_) | Node::Const(_) => {}
            }
        }
        c
    }
}

fn dag_rounds(n: usize, with_schedule: bool) -> DagCounts {
    let mut d = Dag::default();
    let mut a = d.inp(0);
    let mut b = d.inp(1);
    let mut c = d.inp(2);
    let mut d_s = d.inp(3);
    let mut e = d.inp(4);
    let mut f = d.inp(5);
    let mut g = d.inp(6);
    let mut h = d.inp(7);
    let mut w = [0u32; 16];
    if with_schedule {
        for i in 0..8 {
            w[i] = d.inp(8 + i as u8);
        }
        w[8] = d.cst(PAD);
        for i in 9..15 {
            w[i] = d.cst(0);
        }
        w[15] = d.cst(BIT_LEN);
    }
    for t in 0..n {
        let wt = if with_schedule {
            if t >= 16 {
                let i = t % 16;
                let s1 = d.s1(w[(i + 14) % 16]);
                let s0 = d.s0(w[(i + 1) % 16]);
                let t1 = d.add(w[i], s1);
                let t2 = d.add(t1, w[(i + 9) % 16]);
                w[i] = d.add(t2, s0);
            }
            w[t % 16]
        } else {
            d.inp(8 + t as u8)
        };
        let k = d.cst(K0.wrapping_add(t as u64));
        let s1 = d.ep1(e);
        let chv = d.ch(e, f, g);
        let t1 = d.add(h, s1);
        let t1 = d.add(t1, chv);
        let t1 = d.add(t1, k);
        let t1 = d.add(t1, wt);
        let s0 = d.ep0(a);
        let mj = d.maj(a, b, c);
        let t2 = d.add(s0, mj);
        let new_e = d.add(d_s, t1);
        let new_a = d.add(t1, t2);
        h = g;
        g = f;
        f = e;
        e = new_e;
        d_s = c;
        c = b;
        b = a;
        a = new_a;
    }
    let _ = (a, e);
    d.counts()
}

/// SHA-512 Σ/σ rotation distances. All twelve are distinct, so no two
/// of {Σ0,Σ1,σ0,σ1} share a rotate of the same word.
pub const SIGMA_DISTS: [u32; 12] = [28, 34, 39, 14, 18, 41, 1, 8, 7, 19, 61, 6];

/// Digit width vs how many of those 12 distances are wire permutes.
pub fn free_rotates_for_digit(digit_bits: u32) -> u32 {
    SIGMA_DISTS.iter().filter(|&&r| r % digit_bits == 0).count() as u32
}

/// Ripple digit-add steps for a 64-bit word.
pub fn digit_add_steps(digit_bits: u32) -> u32 {
    64 / digit_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512_hmac64::hmac64;

    fn splitmix(seed: u64) -> [u64; 8] {
        let mut x = seed;
        let mut o = [0u64; 8];
        for slot in &mut o {
            x = x.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            *slot = z ^ (z >> 31);
        }
        o
    }

    #[test]
    fn algebras_do_not_coincide() {
        let mut add_not_f2 = 0u32;
        let mut rot_not_z = 0u32;
        let mut csa_rot_fails = 0u32;
        let mut dm_xor_fails = 0u32;
        for seed in 1..80u64 {
            let [x, y, z, o, e, e2, ..] = splitmix(seed);
            if x.wrapping_add(y) != x ^ y {
                add_not_f2 += 1;
            }
            if ror(x.wrapping_add(y), 14) != ror(x, 14).wrapping_add(ror(y, 14)) {
                rot_not_z += 1;
            }
            assert_eq!(ror(x ^ y, 14), ror(x, 14) ^ ror(y, 14));
            let (s, c) = csa32(x, y, z);
            assert_eq!(s.wrapping_add(c), x.wrapping_add(y).wrapping_add(z));
            if ror(s, 14).wrapping_add(ror(c, 14)) != ror(x.wrapping_add(y).wrapping_add(z), 14) {
                csa_rot_fails += 1;
            }
            if (e.wrapping_add(o)) ^ (e2.wrapping_add(o)) != e ^ e2 {
                dm_xor_fails += 1;
            }
        }
        // Identities fail on a majority of random words; they are not equivalences.
        assert!(add_not_f2 > 70);
        assert!(rot_not_z > 40);
        assert!(csa_rot_fails > 40);
        assert!(dm_xor_fails > 70);
    }

    #[test]
    fn ch_maj_one_var_identities() {
        for seed in 0..200u64 {
            let [x, c, d, ..] = splitmix(seed);
            assert_eq!(ch(x, c, d), ch_fixed_yz(x, c, d));
            assert_eq!(maj(x, c, d), maj_fixed_yz(x, c, d));
        }
    }

    #[test]
    fn t1_csa_matches_adds() {
        for seed in 0..400u64 {
            let [h, s1, chv, k, w, ..] = splitmix(seed);
            let naive = h
                .wrapping_add(s1)
                .wrapping_add(chv)
                .wrapping_add(k)
                .wrapping_add(w);
            assert_eq!(t1_csa(h, s1, chv, k, w), naive);
        }
        // 3 CSA each need a 64-bit <<1 (2 SHF) → +6 SHF per T1, +480 SHF / 80 rounds.
        // That is a cost move onto SHF, not a reduction.
        const CSA_SHL_SHF: u32 = 3 * 2 * 80;
        assert_eq!(CSA_SHL_SHF, 480);
        assert!(CSA_SHL_SHF > 0);
    }

    #[test]
    fn fused_two_rounds_eq_two_steps() {
        for seed in 0..200u64 {
            let s = splitmix(seed);
            let w = splitmix(seed ^ 0xdead_beef);
            let a = step(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], K0, w[0]);
            let b = step(a.0, a.1, a.2, a.3, a.4, a.5, a.6, a.7, K1, w[1]);
            let f = fused_two_rounds(
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], K0, w[0], K1, w[1],
            );
            assert_eq!(f, b);
        }
    }

    #[test]
    fn pe_round0_matches_production() {
        for seed in 0..200u64 {
            let mid = splitmix(seed);
            let msg = splitmix(seed.wrapping_mul(0x9e37));
            assert_eq!(compress_hmac64_pe(mid, msg), compress_hmac64(mid, msg));
        }
        // Round 0 compiled: 2 Σ + Ch + Maj leave the per-compression circuit.
        // 4 of 160 Σ/Ch/Maj-class ops ≈ 2.5% of that class, ≈ 1.2% of a compression
        // after the schedule is counted. Not a 10% path.
        const ROUND0_SIGMA: u32 = 2;
        const TOTAL_ROUND_SIGMA: u32 = 160;
        assert!(ROUND0_SIGMA * 100 / TOTAL_ROUND_SIGMA <= 2);
    }

    #[test]
    fn hmac64_not_a_homomorphism() {
        let inner = splitmix(1);
        let outer = splitmix(2);
        let m1 = splitmix(3);
        let m2 = splitmix(4);
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
        let mut h_add = [0u64; 8];
        let mut h_xor = [0u64; 8];
        for i in 0..8 {
            h_add[i] = h1[i].wrapping_add(h2[i]);
            h_xor[i] = h1[i] ^ h2[i];
        }
        assert_ne!(hs, h_add);
        assert_ne!(hx, h_xor);
        assert_ne!(hs, h_xor);
    }

    #[test]
    fn word_dag_has_no_cross_round_cse() {
        let r1 = dag_rounds(1, false);
        let r2 = dag_rounds(2, false);
        let r4 = dag_rounds(4, false);
        let r8 = dag_rounds(8, false);
        // Distinct W[t], K[t] → each round contributes a fresh Σ/Ch/Maj/add set.
        assert_eq!(r2.ror, r1.ror * 2);
        assert_eq!(r2.add, r1.add * 2);
        assert_eq!(r4.ror, r1.ror * 4);
        assert_eq!(r8.ror, r1.ror * 8);
        assert_eq!(r8.and, r1.and * 8);
        // Connecting the pad64 schedule does not share rotates with Σ (disjoint distances).
        let s2 = dag_rounds(2, true);
        assert!(s2.ror >= r2.ror);
    }

    #[test]
    fn sigma_distances_are_all_distinct() {
        let mut v = SIGMA_DISTS.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), 12);
        // Only bitslice (digit=1) makes every rotate a wire permute.
        assert_eq!(free_rotates_for_digit(1), 12);
        assert_eq!(free_rotates_for_digit(4), 2); // 8, 28
        assert_eq!(free_rotates_for_digit(8), 1); // 8
        assert_eq!(free_rotates_for_digit(64), 0);
        // Digit-slice add steps vs the 1550-SHF word-parallel floor.
        // radix 4: 8960 nibble-adds (~5.8×) and only 2/12 rotates are free.
        // radix 8: 4480 byte-adds (~2.9×) and only 1/12 rotates are free.
        // RTX has 32-bit IADD, so the native radix is already 32 — that is the
        // SHF machine, not a new middle ground.
        assert_eq!(80 * 7 * digit_add_steps(4), 8960);
        assert_eq!(80 * 7 * digit_add_steps(8), 4480);
        assert_eq!(digit_add_steps(32), 2);
        assert_eq!(free_rotates_for_digit(32), 0);
    }

    #[test]
    fn pad64_schedule_has_no_hidden_identities() {
        // After the first expand, no later W is a copy, a constant offset, or a
        // single σ of an earlier word — those would be extra specializations.
        for seed in 0..80u64 {
            let msg = splitmix(seed + 11);
            let mut w = [0u64; 80];
            w[..8].copy_from_slice(&msg);
            w[8] = PAD;
            w[15] = BIT_LEN;
            for t in 16..80 {
                w[t] = w[t - 16]
                    .wrapping_add(sig0(w[t - 15]))
                    .wrapping_add(w[t - 7])
                    .wrapping_add(sig1(w[t - 2]));
            }
            for t in 32..80 {
                for s in 0..t {
                    assert_ne!(w[t], w[s], "W[{t}]=W[{s}] seed={seed}");
                    assert_ne!(w[t], w[s].wrapping_add(1));
                    assert_ne!(w[t], w[s].wrapping_add(PAD));
                    assert_ne!(w[t], w[s].wrapping_add(BIT_LEN));
                    assert_ne!(w[t], sig0(w[s]));
                    assert_ne!(w[t], sig1(w[s]));
                }
            }
        }
    }

    #[test]
    fn schedule_dag_matches_specialized_first_expand() {
        let mut d = Dag::default();
        let mut w = [0u32; 16];
        for i in 0..8 {
            w[i] = d.inp(i as u8);
        }
        w[8] = d.cst(PAD);
        for i in 9..15 {
            w[i] = d.cst(0);
        }
        w[15] = d.cst(BIT_LEN);
        for t in 16..32 {
            let i = t % 16;
            let s1 = d.s1(w[(i + 14) % 16]);
            let s0 = d.s0(w[(i + 1) % 16]);
            let t1 = d.add(w[i], s1);
            let t2 = d.add(t1, w[(i + 9) % 16]);
            w[i] = d.add(t2, s0);
        }
        let first = d.counts();
        // Const-folded first expand: 22 remaining σ → 44 ror + 22 shr.
        assert_eq!(first.ror, 44);
        assert_eq!(first.shr, 22);
        for t in 32..80 {
            let i = t % 16;
            let s1 = d.s1(w[(i + 14) % 16]);
            let s0 = d.s0(w[(i + 1) % 16]);
            let t1 = d.add(w[i], s1);
            let t2 = d.add(t1, w[(i + 9) % 16]);
            w[i] = d.add(t2, s0);
        }
        let all = d.counts();
        // Three dense expands: 48 steps × (σ0+σ1) × (2 ror + 1 shr).
        // Hash-cons finds no extra sharing across those expands.
        assert_eq!(all.ror, first.ror + 192);
        assert_eq!(all.shr, first.shr + 96);
    }

    #[test]
    fn iterate_xor_needs_each_image() {
        // If f were F2-linear, ⊕_j f^j(x) would collapse. It is not.
        let inner = splitmix(9);
        let outer = splitmix(10);
        let x = splitmix(11);
        let f1 = hmac64(inner, outer, x);
        let f2 = hmac64(inner, outer, f1);
        let f3 = hmac64(inner, outer, f2);
        let mut acc = [0u64; 8];
        for i in 0..8 {
            acc[i] = f1[i] ^ f2[i] ^ f3[i];
        }
        // No cheap identities against the three images.
        assert_ne!(acc, f1);
        assert_ne!(acc, f3);
        let mut xored = x;
        for i in 0..8 {
            xored[i] ^= f1[i] ^ f2[i] ^ f3[i];
        }
        assert_ne!(xored, x);
    }
}
