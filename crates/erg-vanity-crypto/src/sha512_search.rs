//! Automated search for cheaper exact circuits (research only).
//!
//! Does not change the production compressor. Deterministic seeds.

use crate::sha512::{self, H_INIT};
use crate::sha512_hmac64::compress16;

const COST_ROR: u32 = 2;
const COST_OTH: u32 = 1;

#[inline]
fn ror8(x: u8, n: u32) -> u8 {
    x.rotate_right(n & 7)
}

#[inline]
fn ror64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline]
fn ch8(x: u8, y: u8, z: u8) -> u8 {
    z ^ (x & (y ^ z))
}

#[inline]
fn maj8(x: u8, y: u8, z: u8) -> u8 {
    (x & (y ^ z)) ^ (y & z)
}

/// MiniSHA-8 Σ1: same 3-xor-rotate shape, amounts 14,18,41 mod 8.
#[inline]
pub fn sig1_8(e: u8) -> u8 {
    ror8(e, 14) ^ ror8(e, 18) ^ ror8(e, 41)
}

#[inline]
pub fn sig0_8(a: u8) -> u8 {
    ror8(a, 28) ^ ror8(a, 34) ^ ror8(a, 39)
}

#[inline]
pub fn fused_spec_8(e: u8, f: u8, g: u8) -> u8 {
    sig1_8(e).wrapping_add(ch8(e, f, g))
}

#[inline]
pub fn fused_spec_64(e: u64, f: u64, g: u64) -> u64 {
    let s1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
    let ch = g ^ (e & (f ^ g));
    s1.wrapping_add(ch)
}

/// Integer-adding Ch cannot drop a rotate from Σ: add(Σ,Ch)=add(Σ',Ch) iff Σ=Σ'.
pub fn add_does_not_cancel_sigma() -> bool {
    let mut differ = 0u32;
    for e in 0u8..=255 {
        if sig1_8(e) != (ror8(e, 14) ^ ror8(e, 18)) {
            differ += 1;
        }
    }
    differ > 200
}

fn sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
fn sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// Exhaustive F₂ search: no 2-rotate (plus optional shift) equals SHA-512 Σ0/Σ1.
/// Linear maps are compared on all 64 basis vectors.
pub fn two_term_sigma_search() -> Option<(char, u32, u32, u32)> {
    for a in 0..64u32 {
        for b in a..64u32 {
            let mut eq0 = true;
            let mut eq1 = true;
            for i in 0..64u32 {
                let x = 1u64 << i;
                let two = x.rotate_right(a) ^ x.rotate_right(b);
                eq0 &= two == sigma0(x);
                eq1 &= two == sigma1(x);
            }
            if eq0 {
                return Some(('0', a, b, 64));
            }
            if eq1 {
                return Some(('1', a, b, 64));
            }
            for sh in 0..64u32 {
                let mut e0 = true;
                let mut e1 = true;
                for i in 0..64u32 {
                    let x = 1u64 << i;
                    let t = x.rotate_right(a) ^ x.rotate_right(b) ^ (x >> sh);
                    e0 &= t == sigma0(x);
                    e1 &= t == sigma1(x);
                }
                if e0 {
                    return Some(('0', a, b, sh));
                }
                if e1 {
                    return Some(('1', a, b, sh));
                }
            }
        }
    }
    None
}

/// Structured fusions of Σ1 and Ch. Screened on many 64-bit triples.
/// A hit would be a ≥10% SHF candidate (one rotate dropped per Σ per round).
pub fn structured_fusion_hits(samples: u32) -> u32 {
    let mut hits = 0u32;
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..samples {
        seed = seed.wrapping_mul(0x9e37).wrapping_add(1);
        let e = split(seed, 0);
        let f = split(seed, 1);
        let g = split(seed, 2);
        let spec = fused_spec_64(e, f, g);
        let ch = g ^ (e & (f ^ g));
        let s1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        let cands = [
            (ror64(e, 14) ^ ror64(e, 18)).wrapping_add(ch),
            (ror64(e, 14) ^ ror64(e, 41)).wrapping_add(ch),
            (ror64(e, 18) ^ ror64(e, 41)).wrapping_add(ch),
            ror64(e.wrapping_add(ch), 14) ^ ror64(e, 18) ^ ror64(e, 41),
            ror64(e, 14) ^ ror64(e.wrapping_add(ch), 18) ^ ror64(e, 41),
            ror64(e, 14) ^ ror64(e, 18) ^ ror64(e.wrapping_add(ch), 41),
            s1.wrapping_add(ch.rotate_right(14)),
            ror64(e, 14).wrapping_add(ror64(e, 18)).wrapping_add(ch) ^ ror64(e, 41),
            (s1 ^ ch).wrapping_add(ch), // 2 Ch
            ror64(e ^ ch, 14) ^ ror64(e, 18) ^ ror64(e, 41),
            ror64(e, 14) ^ ror64(e ^ ch, 18) ^ ror64(e, 41),
            ror64(e, 14) ^ ror64(e, 18) ^ ror64(e ^ ch, 41),
            ror64(ch, 14) ^ ror64(e, 18) ^ ror64(e, 41),
            s1.wrapping_add(f ^ g),
            (ror64(e, 14) ^ ror64(e, 18) ^ (e >> 41)).wrapping_add(ch),
        ];
        for c in cands {
            if c == spec {
                hits += 1;
            }
        }
    }
    hits
}

fn split(s: u64, i: u32) -> u64 {
    s.rotate_left(i.wrapping_mul(17))
        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

#[derive(Clone, Debug)]
pub struct CorrectionReport {
    pub eq_rate_num: u32,
    pub eq_rate_den: u32,
    pub min_influence: u32,
    pub max_influence: u32,
}

/// How cheap is the correction `ROTR(x+y) - (ROTR(x)+ROTR(y))` at 8-bit?
pub fn correction_w8(k: u32) -> CorrectionReport {
    let mut eq = 0u32;
    let mut infl = [0u32; 16];
    for x in 0u16..256 {
        for y in 0u16..256 {
            let x8 = x as u8;
            let y8 = y as u8;
            let spec = ror8(x8.wrapping_add(y8), k);
            let split = ror8(x8, k).wrapping_add(ror8(y8, k));
            if spec == split {
                eq += 1;
            }
            let corr = spec.wrapping_sub(split);
            for b in 0..8 {
                let x2 = x8 ^ (1 << b);
                let spec2 = ror8(x2.wrapping_add(y8), k);
                let split2 = ror8(x2, k).wrapping_add(ror8(y8, k));
                if spec2.wrapping_sub(split2) != corr {
                    infl[b] += 1;
                }
                let y2 = y8 ^ (1 << b);
                let spec3 = ror8(x8.wrapping_add(y2), k);
                let split3 = ror8(x8, k).wrapping_add(ror8(y2, k));
                if spec3.wrapping_sub(split3) != corr {
                    infl[8 + b] += 1;
                }
            }
        }
    }
    CorrectionReport {
        eq_rate_num: eq,
        eq_rate_den: 256 * 256,
        min_influence: *infl.iter().min().unwrap(),
        max_influence: *infl.iter().max().unwrap(),
    }
}

/// Mendel/Nikolić single-variable form: same F, same adds. Graph rewrite only.
pub fn mendel_a_next(
    a: u64,
    b: u64,
    c: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    k: u64,
    w: u64,
) -> u64 {
    let f_fn = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39))
        .wrapping_add((a & (b ^ c)) ^ (b & c))
        .wrapping_add(ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41))
        .wrapping_add(g ^ (e & (f ^ g)))
        .wrapping_add(k);
    f_fn.wrapping_add(h).wrapping_add(w)
}

pub fn standard_a_next(
    a: u64,
    b: u64,
    c: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    k: u64,
    w: u64,
) -> u64 {
    let t1 = h
        .wrapping_add(ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41))
        .wrapping_add(g ^ (e & (f ^ g)))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)).wrapping_add((a & (b ^ c)) ^ (b & c));
    t1.wrapping_add(t2)
}

#[derive(Clone, Copy)]
enum Inst {
    Ror(u8, u8),
    Xor(u8, u8),
    And(u8, u8),
    Add(u8, u8),
}

struct Prog {
    ops: Vec<Inst>,
}

impl Prog {
    fn conventional() -> Self {
        // slots: 0=e 1=f 2=g
        // 3 = ror e 14; 4 = ror e 18; 5 = ror e 41
        // 6 = 3^4; 7 = 6^5 = Σ1
        // 8 = f^g; 9 = e&8; 10 = g^9 = Ch
        // 11 = 7+10
        Self {
            ops: vec![
                Inst::Ror(0, 14),
                Inst::Ror(0, 18),
                Inst::Ror(0, 41),
                Inst::Xor(3, 4),
                Inst::Xor(6, 5),
                Inst::Xor(1, 2),
                Inst::And(0, 8),
                Inst::Xor(2, 9),
                Inst::Add(7, 10),
            ],
        }
    }

    fn cost(&self) -> u32 {
        self.ops
            .iter()
            .map(|op| match op {
                Inst::Ror(_, _) => COST_ROR,
                _ => COST_OTH,
            })
            .sum()
    }

    fn ror_count(&self) -> u32 {
        self.ops
            .iter()
            .filter(|op| matches!(op, Inst::Ror(_, _)))
            .count() as u32
    }

    fn eval8(&self, e: u8, f: u8, g: u8) -> u8 {
        let mut s = [0u8; 32];
        s[0] = e;
        s[1] = f;
        s[2] = g;
        for (i, op) in self.ops.iter().enumerate() {
            let dst = 3 + i;
            if dst >= s.len() {
                break;
            }
            s[dst] = match *op {
                Inst::Ror(a, n) => ror8(s[slot(a)], n as u32),
                Inst::Xor(a, b) => s[slot(a)] ^ s[slot(b)],
                Inst::And(a, b) => s[slot(a)] & s[slot(b)],
                Inst::Add(a, b) => s[slot(a)].wrapping_add(s[slot(b)]),
            };
        }
        s[2 + self.ops.len()]
    }

    fn matches_spec_sample(&self, n: u32, seed0: u64) -> bool {
        let mut seed = seed0;
        for _ in 0..n {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let e = (seed & 0xff) as u8;
            let f = ((seed >> 8) & 0xff) as u8;
            let g = ((seed >> 16) & 0xff) as u8;
            if self.eval8(e, f, g) != fused_spec_8(e, f, g) {
                return false;
            }
        }
        true
    }
}

fn slot(i: u8) -> usize {
    i as usize
}

fn mutate(p: &Prog, rng: &mut u64) -> Prog {
    let mut q = Prog { ops: p.ops.clone() };
    if q.ops.is_empty() {
        return q;
    }
    *rng = rng
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let i = (*rng as usize) % q.ops.len();
    let max_src = (3 + i) as u8;
    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
    match *rng % 4 {
        0 => {
            if let Inst::Ror(s, n) = q.ops[i] {
                q.ops[i] = Inst::Ror(s, ((n as u32 + 1) % 8) as u8);
            } else {
                let a = (*rng as u8) % max_src.max(1);
                let b = ((*rng >> 8) as u8) % max_src.max(1);
                q.ops[i] = Inst::Xor(a, b);
            }
        }
        1 => {
            let a = (*rng as u8) % max_src.max(1);
            let b = ((*rng >> 8) as u8) % max_src.max(1);
            q.ops[i] = match q.ops[i] {
                Inst::Ror(_, n) => Inst::Ror(a, n),
                Inst::Xor(_, _) => Inst::Xor(a, b),
                Inst::And(_, _) => Inst::And(a, b),
                Inst::Add(_, _) => Inst::Add(a, b),
            };
        }
        2 => {
            let a = (*rng as u8) % max_src.max(1);
            let b = ((*rng >> 8) as u8) % max_src.max(1);
            q.ops[i] = Inst::Add(a, b);
        }
        _ => {
            if q.ops.len() > 4 && i + 1 < q.ops.len() {
                q.ops.swap(i, i + 1);
            }
        }
    }
    q
}

/// STOKE-style walk. Returns cheapest equivalent program found (8-bit sample).
pub fn superopt_fused(steps: u32, seed: u64) -> (u32, u32) {
    let mut best = Prog::conventional();
    let mut rng = seed;
    let start_cost = best.cost();
    for _ in 0..steps {
        let cand = mutate(&best, &mut rng);
        if cand.cost() < best.cost() && cand.matches_spec_sample(64, rng) {
            if cand.matches_spec_sample(512, rng ^ 0xdead) {
                best = cand;
            }
        }
    }
    (start_cost, best.cost())
}

pub fn hamming8(a: [u64; 8], b: [u64; 8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// Midstates of passwords that share a long prefix: avalanche, not a shared loop.
pub fn related_password_mid_hamming() -> (u32, u32) {
    let p1 = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let p2 = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon legal";
    let mut b1 = [0u8; 128];
    let mut b2 = [0u8; 128];
    b1[..p1.len()].copy_from_slice(p1);
    b2[..p2.len()].copy_from_slice(p2);
    let xor_pad = |block: [u8; 128], pad: u8| {
        let mut w = [0u64; 16];
        for i in 0..16 {
            let mut v = 0u64;
            for k in 0..8 {
                v = (v << 8) | (block[i * 8 + k] ^ pad) as u64;
            }
            w[i] = v;
        }
        w
    };
    let i1 = compress16(H_INIT, xor_pad(b1, 0x36));
    let i2 = compress16(H_INIT, xor_pad(b2, 0x36));
    let o1 = compress16(H_INIT, xor_pad(b1, 0x5c));
    let o2 = compress16(H_INIT, xor_pad(b2, 0x5c));
    (hamming8(i1, i2), hamming8(o1, o2))
}

/// MiniSHA-8 one-round cost in the same model. Used as the reduced-width baseline.
pub fn minisha8_round(
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
    h: u8,
    k: u8,
    w: u8,
) -> (u8, u8) {
    let t1 = h
        .wrapping_add(sig1_8(e))
        .wrapping_add(ch8(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = sig0_8(a).wrapping_add(maj8(a, b, c));
    (t1.wrapping_add(t2), d.wrapping_add(t1))
}

/// Two MiniSHA-8 rounds as one map. Same ops as two rounds (graph is serial).
pub fn minisha8_two(
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
    h: u8,
    k0: u8,
    w0: u8,
    k1: u8,
    w1: u8,
) -> (u8, u8) {
    let (a1, e1) = minisha8_round(a, b, c, d, e, f, g, h, k0, w0);
    minisha8_round(a1, a, b, c, e1, e, f, g, k1, w1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_has_no_two_term_form() {
        assert!(add_does_not_cancel_sigma());
        assert_eq!(two_term_sigma_search(), None);
    }

    #[test]
    fn structured_fusions_never_match() {
        // 400 random 64-bit triples × 15 shapes. A single hit would be a 10% SHF lead.
        assert_eq!(structured_fusion_hits(400), 0);
    }

    #[test]
    fn add_ror_correction_is_dense() {
        for k in 1..8u32 {
            let r = correction_w8(k);
            // Identity holds only on a minority of pairs (carry-free cases).
            assert!(
                r.eq_rate_num * 2 < r.eq_rate_den,
                "k={k} eq={}",
                r.eq_rate_num
            );
            // Every operand bit influences the correction — not a sparse fixup.
            assert!(r.min_influence > 0, "k={k} min_infl={}", r.min_influence);
            assert!(r.max_influence > r.eq_rate_den / 4);
        }
    }

    #[test]
    fn mendel_form_is_the_same_circuit() {
        let mut seed = 1u64;
        for _ in 0..200 {
            seed = seed.wrapping_mul(0x9e37).wrapping_add(3);
            let v = [0, 1, 2, 3, 4, 5, 6, 7, 8].map(|i| split(seed, i));
            assert_eq!(
                mendel_a_next(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]),
                standard_a_next(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8])
            );
        }
    }

    #[test]
    fn superopt_does_not_drop_a_rotate() {
        let (start, found) = superopt_fused(12_000, 0xcafe_u64);
        assert_eq!(start, 3 * COST_ROR + 6 * COST_OTH);
        // Walk may shuffle equivalent programs; it must not drop a rotate and stay correct.
        assert!(found >= start);
        let conv = Prog::conventional();
        assert_eq!(conv.ror_count(), 3);
        assert!(conv.matches_spec_sample(200, 99));
    }

    #[test]
    fn related_mnemonics_avalanche_midstates() {
        let (hi, ho) = related_password_mid_hamming();
        // 512-bit values, ~50% bits differ. Shared prefix does not yield a close I/O.
        assert!(hi > 180 && hi < 340, "inner hamming {hi}");
        assert!(ho > 180 && ho < 340, "outer hamming {ho}");
    }

    #[test]
    fn minisha8_two_rounds_match_composed() {
        for seed in 0..400u64 {
            let x = seed.to_le_bytes();
            let y = seed.wrapping_mul(7).wrapping_add(3).to_le_bytes();
            let a = minisha8_two(
                x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], y[0], y[1], y[2], y[3],
            );
            let (a1, e1) =
                minisha8_round(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], y[0], y[1]);
            let b = minisha8_round(a1, x[0], x[1], x[2], e1, x[4], x[5], x[6], y[2], y[3]);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn digest_still_matches_crate_sanity() {
        // Search module must not drift the production hash.
        let d = sha512::digest(b"abc");
        assert_eq!(d[0], 0xdd);
    }
}
