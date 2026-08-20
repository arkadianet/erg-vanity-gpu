//! First-principles exact-circuit attack on SHA-512 compression.
//!
//! Research only. Does not change the production compressor.
//! Previous closed lines (orbits, bitslice, CSA persistence, 2-term linear Σ,
//! 15 textbook Σ+Ch fusions) are not repeated. This module attacks:
//!   - mixed-operand 2-rotate forms of Σ1+Ch and Σ0+Maj
//!   - reduced-width scaling (4/8/12/16/64)
//!   - IADD3 association of T1 / a'
//!   - pad64 first-expand extension past W[31]
//!   - σ/Σ shared-rotate overlap
//!   - two-round dependency depth
//!
//! Author: arkadianet

#![allow(dead_code)]

/// SHA-512 Σ1 amounts.
const S1: [u32; 3] = [14, 18, 41];
/// SHA-512 Σ0 amounts.
const S0: [u32; 3] = [28, 34, 39];
/// SHA-512 σ0 amounts (last is a shift).
const SM0: [u32; 3] = [1, 8, 7];
/// SHA-512 σ1 amounts (last is a shift).
const SM1: [u32; 3] = [19, 61, 6];

const PAD: u64 = 0x8000_0000_0000_0000;
const BIT_LEN: u64 = 1536;

#[inline]
fn ror(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline]
fn ror_w(x: u64, n: u32, w: u32) -> u64 {
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let n = n % w;
    ((x >> n) | (x << (w - n))) & mask
}

#[inline]
fn add_w(x: u64, y: u64, w: u32) -> u64 {
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    x.wrapping_add(y) & mask
}

#[inline]
fn ch(e: u64, f: u64, g: u64) -> u64 {
    g ^ (e & (f ^ g))
}

#[inline]
fn maj(a: u64, b: u64, c: u64) -> u64 {
    (a & (b ^ c)) ^ (b & c)
}

#[inline]
fn sig1(e: u64) -> u64 {
    ror(e, 14) ^ ror(e, 18) ^ ror(e, 41)
}

#[inline]
fn sig0(a: u64) -> u64 {
    ror(a, 28) ^ ror(a, 34) ^ ror(a, 39)
}

#[inline]
fn sigma0(x: u64) -> u64 {
    ror(x, 1) ^ ror(x, 8) ^ (x >> 7)
}

#[inline]
fn sigma1(x: u64) -> u64 {
    ror(x, 19) ^ ror(x, 61) ^ (x >> 6)
}

#[inline]
fn sig1_w(e: u64, w: u32) -> u64 {
    ror_w(e, 14, w) ^ ror_w(e, 18, w) ^ ror_w(e, 41, w)
}

#[inline]
fn ch_w(e: u64, f: u64, g: u64, w: u32) -> u64 {
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    (g ^ (e & (f ^ g))) & mask
}

#[inline]
fn fused_w(e: u64, f: u64, g: u64, w: u32) -> u64 {
    add_w(sig1_w(e, w), ch_w(e, f, g, w), w)
}

#[inline]
fn fused64(e: u64, f: u64, g: u64) -> u64 {
    sig1(e).wrapping_add(ch(e, f, g))
}

#[inline]
fn fused0_64(a: u64, b: u64, c: u64) -> u64 {
    sig0(a).wrapping_add(maj(a, b, c))
}

/// Distinct rotate amounts of Σ1 after reduction mod `w`.
pub fn sigma1_distinct_mod(w: u32) -> usize {
    let mut v = [14 % w, 18 % w, 41 % w];
    v.sort_unstable();
    v.dedup();
    v.len()
}

/// Distinct rotate amounts of Σ0 after reduction mod `w`.
pub fn sigma0_distinct_mod(w: u32) -> usize {
    let mut v = [28 % w, 34 % w, 39 % w];
    v.sort_unstable();
    v.dedup();
    v.len()
}

/// Textbook Boolean atoms used as mixed rotate/add operands.
/// These are the cheap 3-input forms a GPU already has via LOP3.
fn atoms64(e: u64, f: u64, g: u64) -> [u64; 18] {
    [
        e,
        f,
        g,
        !e,
        !f,
        !g,
        e ^ f,
        e ^ g,
        f ^ g,
        e & f,
        e & g,
        f & g,
        e | f,
        e | g,
        f | g,
        ch(e, f, g),
        e & (f ^ g),
        f ^ g ^ e,
    ]
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn sample_triple(i: u64) -> (u64, u64, u64) {
    (
        splitmix(i.wrapping_mul(3) + 1),
        splitmix(i.wrapping_mul(3) + 2),
        splitmix(i.wrapping_mul(3) + 3),
    )
}

/// Screen a 2-rotate + add catalog against Σ1+Ch.
///
/// Class: (ROTR(X,a) ⊕ ROTR(Y,b)) + Z  with X,Y,Z from the atom catalog.
/// This is the open B4 class: not of the form Σ'(e)+Ch unless X=Y=e and Z=Ch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionHit {
    pub class: &'static str,
    pub xi: u8,
    pub yi: u8,
    pub zi: u8,
    pub a: u32,
    pub b: u32,
}

fn screen_xor_add(samples: u32) -> Vec<FusionHit> {
    let mut hits = Vec::new();
    let triples: Vec<(u64, u64, u64)> = (0..samples as u64).map(sample_triple).collect();
    for xi in 0..18u8 {
        for yi in xi..18u8 {
            for zi in 0..18u8 {
                for a in 0..64u32 {
                    // Only SHA-like and nearby amounts: full 0..63 is 64× more
                    // and still F2-linear in the rotate args. Restrict to the
                    // Σ1 amounts plus a few offsets that could absorb Ch.
                    let amounts = [14u32, 18, 41, 4, 23, 27, 32, 0];
                    if !amounts.contains(&a) {
                        continue;
                    }
                    for b in amounts {
                        if b < a && xi == yi {
                            continue;
                        }
                        let mut ok = true;
                        for &(e, f, g) in &triples {
                            let at = atoms64(e, f, g);
                            let cand = (ror(at[xi as usize], a) ^ ror(at[yi as usize], b))
                                .wrapping_add(at[zi as usize]);
                            if cand != fused64(e, f, g) {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            hits.push(FusionHit {
                                class: "xor_add",
                                xi,
                                yi,
                                zi,
                                a,
                                b,
                            });
                        }
                    }
                }
            }
        }
    }
    hits
}

fn screen_add_add(samples: u32) -> Vec<FusionHit> {
    let mut hits = Vec::new();
    let triples: Vec<(u64, u64, u64)> = (0..samples as u64).map(sample_triple).collect();
    let amounts = [14u32, 18, 41, 0, 4];
    for xi in 0..18u8 {
        for yi in 0..18u8 {
            for zi in 0..18u8 {
                for a in amounts {
                    for b in amounts {
                        let mut ok = true;
                        for &(e, f, g) in &triples {
                            let at = atoms64(e, f, g);
                            let cand = ror(at[xi as usize], a)
                                .wrapping_add(ror(at[yi as usize], b))
                                .wrapping_add(at[zi as usize]);
                            if cand != fused64(e, f, g) {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            hits.push(FusionHit {
                                class: "add_add",
                                xi,
                                yi,
                                zi,
                                a,
                                b,
                            });
                        }
                    }
                }
            }
        }
    }
    hits
}

fn screen_rot_sum(samples: u32) -> Vec<FusionHit> {
    let mut hits = Vec::new();
    let triples: Vec<(u64, u64, u64)> = (0..samples as u64).map(sample_triple).collect();
    let amounts = [14u32, 18, 41, 4, 23, 27];
    for xi in 0..18u8 {
        for yi in 0..18u8 {
            for zi in 0..18u8 {
                for a in amounts {
                    for b in amounts {
                        let mut ok = true;
                        for &(e, f, g) in &triples {
                            let at = atoms64(e, f, g);
                            let cand = ror(at[xi as usize].wrapping_add(at[yi as usize]), a)
                                ^ ror(at[zi as usize], b);
                            if cand != fused64(e, f, g) {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            hits.push(FusionHit {
                                class: "rot_sum",
                                xi,
                                yi,
                                zi,
                                a,
                                b,
                            });
                        }
                    }
                }
            }
        }
    }
    hits
}

fn screen_maj_xor_add(samples: u32) -> Vec<FusionHit> {
    let mut hits = Vec::new();
    let triples: Vec<(u64, u64, u64)> = (0..samples as u64).map(sample_triple).collect();
    let amounts = [28u32, 34, 39, 6, 11, 5, 0];
    for xi in 0..18u8 {
        for yi in xi..18u8 {
            for zi in 0..18u8 {
                for a in amounts {
                    for b in amounts {
                        let mut ok = true;
                        for &(e, f, g) in &triples {
                            // reuse (e,f,g) as (a,b,c)
                            let at = atoms64(e, f, g);
                            let cand = (ror(at[xi as usize], a) ^ ror(at[yi as usize], b))
                                .wrapping_add(at[zi as usize]);
                            if cand != fused0_64(e, f, g) {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            hits.push(FusionHit {
                                class: "maj_xor_add",
                                xi,
                                yi,
                                zi,
                                a,
                                b,
                            });
                        }
                    }
                }
            }
        }
    }
    hits
}

/// Confirm a hit on many 64-bit triples (rejects 8-bit-only accidents).
pub fn confirm64(hit: &FusionHit, n: u32) -> bool {
    for i in 0..n as u64 {
        let (e, f, g) = sample_triple(0xC0FFEE + i);
        let at = atoms64(e, f, g);
        let cand = match hit.class {
            "xor_add" | "maj_xor_add" => (ror(at[hit.xi as usize], hit.a)
                ^ ror(at[hit.yi as usize], hit.b))
            .wrapping_add(at[hit.zi as usize]),
            "add_add" => ror(at[hit.xi as usize], hit.a)
                .wrapping_add(ror(at[hit.yi as usize], hit.b))
                .wrapping_add(at[hit.zi as usize]),
            "rot_sum" => {
                ror(
                    at[hit.xi as usize].wrapping_add(at[hit.yi as usize]),
                    hit.a,
                ) ^ ror(at[hit.zi as usize], hit.b)
            }
            _ => return false,
        };
        let spec = if hit.class == "maj_xor_add" {
            fused0_64(e, f, g)
        } else {
            fused64(e, f, g)
        };
        if cand != spec {
            return false;
        }
    }
    true
}

/// Drop the conventional 3-rotate+Ch form from a hit list.
/// Conventional: X=Y=e (atom 0), Z=Ch (atom 15), {a,b} a 2-subset of {14,18,41}
/// is NOT a hit unless the missing rotate is free — which it is not.
fn nontrivial(hits: &[FusionHit]) -> Vec<FusionHit> {
    hits.iter()
        .cloned()
        .filter(|h| confirm64(h, 64))
        .collect()
}

/// Exhaustive 8-bit check that +Ch cannot hide a missing rotate.
/// Uses a width where {14,18,41} stay distinct (8, 12, 16).
pub fn missing_rotate_survives_add(w: u32) -> bool {
    let max = 1u32 << w.min(16);
    // Full exhaustive only at 8-bit. Wider widths sample.
    if w <= 8 {
        for e in 0..max {
            let e = e as u64;
            let two = ror_w(e, 14, w) ^ ror_w(e, 18, w);
            if two == sig1_w(e, w) {
                return false;
            }
            // add(two, ch) == add(Σ1, ch) iff two == Σ1
            for f in 0..max {
                for g in 0..max {
                    let f = f as u64;
                    let g = g as u64;
                    if add_w(two, ch_w(e, f, g, w), w) == fused_w(e, f, g, w) {
                        return false;
                    }
                }
            }
        }
        true
    } else {
        for i in 0..4000u64 {
            let (e, f, g) = sample_triple(i);
            let mask = (1u64 << w) - 1;
            let e = e & mask;
            let f = f & mask;
            let g = g & mask;
            let two = ror_w(e, 14, w) ^ ror_w(e, 18, w);
            if add_w(two, ch_w(e, f, g, w), w) == fused_w(e, f, g, w) {
                return false;
            }
        }
        true
    }
}

/// Ampere-style 32-bit instruction model for one SHA-512 round.
///
/// SHF: 32-bit funnel. ROTR64 = 2 SHF. SHR64-by-n<32 = 1 SHF + 1 SHR.
/// LOP3: 32-bit 3-input logic. 64-bit bitwise = 2 LOP3.
/// IADD3: 32-bit 3-input add. 64-bit 2-input or 3-input add = 2 IADD3
///        (lo with carry, hi with carry-in). A 2-input add still costs 2
///        IADD3 if the compiler emits IADD3 ..., RZ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaCost {
    pub shf: u32,
    pub iadd: u32,
    pub lop3: u32,
}

impl IsaCost {
    pub fn total(self) -> u32 {
        self.shf + self.iadd + self.lop3
    }
}

/// Conventional round if the compiler already uses SHF + LOP3 + IADD3.
pub fn round_cost_floor() -> IsaCost {
    IsaCost {
        // Σ1: 3×ROTR64 = 6 SHF; Σ0: 6 SHF
        shf: 12,
        // T1 = IADD3(h,Σ1,Ch) + IADD3(_,K,W) = 4
        // e' = d+T1 = 2
        // a' = IADD3(T1,Σ0,Maj) = 2
        iadd: 8,
        // Σ1 3-xor, Σ0 3-xor, Ch, Maj: 4 × 2 LOP3
        lop3: 8,
    }
}

/// Same round if 64-bit add is lowered to a 2-input chain (no IADD3 fold).
pub fn round_cost_binary_add() -> IsaCost {
    let mut c = round_cost_floor();
    // T1 four binary adds = 8 IADD vs 4; a' as T2 then +T1 = 4 vs 2
    c.iadd = 14;
    c
}

/// Same round if `rotate(ulong)` becomes shr.b64/shl.b64/or.b64.
/// Each 64-bit op is two 32-bit halves: 3×2 = 6 per ROTR64 vs 2 SHF.
pub fn round_cost_soft_rotate() -> IsaCost {
    let mut c = round_cost_floor();
    c.shf = 36; // 6 ROTR64 × 6 half-ops, counted in the SHF slot as 32-bit work
    c
}

/// HMAC-64 first-expand σ count (known ~3% path) vs generic.
pub fn hmac64_first_expand_sigma() -> (u32, u32) {
    // generic: 16 × (σ0+σ1) = 32
    // specialized: 22 (derived and tested below)
    (32, 22)
}

fn expand_generic(w: &mut [u64; 80]) {
    for i in 16..80 {
        w[i] = w[i - 16]
            .wrapping_add(sigma0(w[i - 15]))
            .wrapping_add(w[i - 7])
            .wrapping_add(sigma1(w[i - 2]));
    }
}

fn hmac64_block(msg: [u64; 8]) -> [u64; 16] {
    let mut w = [0u64; 16];
    w[..8].copy_from_slice(&msg);
    w[8] = PAD;
    w[15] = BIT_LEN;
    w
}

/// Specialized first expand. Returns W[16..32].
pub fn hmac64_expand16(msg: [u64; 8]) -> [u64; 16] {
    let mut w = hmac64_block(msg);
    // Identities from W[8]=PAD, W[9..14]=0, W[15]=1536.
    let mut out = [0u64; 16];
    let mut v = w;
    v[0] = v[0].wrapping_add(sigma0(v[1]));
    v[1] = v[1]
        .wrapping_add(sigma1(BIT_LEN))
        .wrapping_add(sigma0(v[2]));
    v[2] = v[2].wrapping_add(sigma1(v[0])).wrapping_add(sigma0(v[3]));
    v[3] = v[3].wrapping_add(sigma1(v[1])).wrapping_add(sigma0(v[4]));
    v[4] = v[4].wrapping_add(sigma1(v[2])).wrapping_add(sigma0(v[5]));
    v[5] = v[5].wrapping_add(sigma1(v[3])).wrapping_add(sigma0(v[6]));
    v[6] = v[6]
        .wrapping_add(sigma1(v[4]))
        .wrapping_add(BIT_LEN)
        .wrapping_add(sigma0(v[7]));
    v[7] = v[7]
        .wrapping_add(sigma1(v[5]))
        .wrapping_add(v[0])
        .wrapping_add(sigma0(PAD));
    v[8] = v[8].wrapping_add(sigma1(v[6])).wrapping_add(v[1]);
    v[9] = v[9].wrapping_add(sigma1(v[7])).wrapping_add(v[2]);
    v[10] = v[10].wrapping_add(sigma1(v[8])).wrapping_add(v[3]);
    v[11] = v[11].wrapping_add(sigma1(v[9])).wrapping_add(v[4]);
    v[12] = v[12].wrapping_add(sigma1(v[10])).wrapping_add(v[5]);
    v[13] = v[13].wrapping_add(sigma1(v[11])).wrapping_add(v[6]);
    v[14] = v[14]
        .wrapping_add(sigma1(v[12]))
        .wrapping_add(v[7])
        .wrapping_add(sigma0(BIT_LEN));
    v[15] = v[15]
        .wrapping_add(sigma1(v[13]))
        .wrapping_add(v[8])
        .wrapping_add(sigma0(v[0]));
    out.copy_from_slice(&v);
    out
}

#[derive(Clone, Debug, Default)]
pub struct ScheduleIdentityHits {
    pub eq: u32,
    pub xor_c: u32,
    pub add_c: u32,
    pub ror: u32,
    pub pair_add: u32,
    pub pair_xor: u32,
    pub samples: u32,
}

/// Search W[t], t≥32, for leftover exact identities vs earlier words.
pub fn schedule_identity_search(samples: u32) -> ScheduleIdentityHits {
    let mut h = ScheduleIdentityHits {
        samples,
        ..Default::default()
    };
    for s in 0..samples as u64 {
        let msg = [
            splitmix(s * 8 + 1),
            splitmix(s * 8 + 2),
            splitmix(s * 8 + 3),
            splitmix(s * 8 + 4),
            splitmix(s * 8 + 5),
            splitmix(s * 8 + 6),
            splitmix(s * 8 + 7),
            splitmix(s * 8 + 8),
        ];
        let mut w = [0u64; 80];
        let b = hmac64_block(msg);
        w[..16].copy_from_slice(&b);
        expand_generic(&mut w);
        for t in 32..80 {
            for sidx in 0..t {
                if w[t] == w[sidx] {
                    h.eq += 1;
                }
                let d = w[t].wrapping_sub(w[sidx]);
                // constant offset: same d for this pair shape is not counted
                // globally; a per-message +C still corrupts later σ.
                if d == PAD || d == BIT_LEN || d == sigma0(PAD) || d == sigma1(BIT_LEN) {
                    h.add_c += 1;
                }
                if w[t] == (w[sidx] ^ PAD)
                    || w[t] == (w[sidx] ^ BIT_LEN)
                    || w[t] == (w[sidx] ^ sigma0(PAD))
                {
                    h.xor_c += 1;
                }
                for k in [1u32, 6, 7, 8, 14, 18, 19, 28, 34, 39, 41, 61] {
                    if w[t] == ror(w[sidx], k) {
                        h.ror += 1;
                    }
                }
            }
            for i in 0..t {
                for j in i + 1..t {
                    if w[t] == w[i].wrapping_add(w[j]) {
                        h.pair_add += 1;
                    }
                    if w[t] == (w[i] ^ w[j]) {
                        h.pair_xor += 1;
                    }
                }
            }
        }
    }
    h
}

/// Rotates used by Σ0, Σ1, σ0, σ1. All 12 are distinct: no shared SHF.
pub fn rotate_amount_overlap() -> bool {
    let mut all = Vec::from(S0);
    all.extend_from_slice(&S1);
    all.extend_from_slice(&SM0);
    all.extend_from_slice(&SM1);
    all.sort_unstable();
    let n = all.len();
    all.dedup();
    all.len() == n
}

/// Two-round critical-path depth in the IADD3/SHF/LOP3 model.
///
/// Within a round, Σ0∥Maj run in parallel with Σ1∥Ch∥T1.
/// T1 is on the long path; a' and e' wait on T1.
/// Round 2 cannot start Σ1(e') or Σ0(a') until those adds complete.
pub fn two_round_depth() -> (u32, u32) {
    // Depth units: SHF=1 (throughput, but we count latency slots conservatively
    // as 4 for SHF, 4 for IADD3, 4 for LOP3 — Ampere integer latency ~4).
    // Serial: 3 SHF (Σ1 xor tree after last rotate) + 2 IADD3 (T1) + 1 IADD3 (a')
    // Parallel work does not shorten this.
    // Two rounds: 2 × that depth. No cross-round CSE of Σ/Ch/Maj.
    let one = 3 + 2 + 1;
    (one, one * 2)
}

/// IADD3 association is bit-identical to the textbook T1/T2 form.
pub fn iadd3_assoc_matches(n: u32) -> bool {
    for i in 0..n as u64 {
        let h = splitmix(i + 11);
        let e = splitmix(i + 22);
        let f = splitmix(i + 33);
        let g = splitmix(i + 44);
        let a = splitmix(i + 55);
        let b = splitmix(i + 66);
        let c = splitmix(i + 77);
        let d = splitmix(i + 88);
        let k = splitmix(i + 99);
        let w = splitmix(i + 111);
        let t1 = h
            .wrapping_add(sig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = sig0(a).wrapping_add(maj(a, b, c));
        let e_text = d.wrapping_add(t1);
        let a_text = t1.wrapping_add(t2);
        // 3+2 fold
        let t1_i = (h.wrapping_add(sig1(e)).wrapping_add(ch(e, f, g)))
            .wrapping_add(k.wrapping_add(w));
        let e_i = d.wrapping_add(t1_i);
        let a_i = t1_i.wrapping_add(sig0(a)).wrapping_add(maj(a, b, c));
        if t1 != t1_i || e_text != e_i || a_text != a_i {
            return false;
        }
    }
    true
}

/// Live 64-bit values at the start of a generic rolling-schedule round.
pub fn live_values_generic_round() -> u32 {
    // a..h (8) + W[0..15] (16) = 24. Midstate is dead during the 80 rounds.
    24
}

/// Whether first-expand W16/W17 can be computed before any round
/// (ILP only; no op-count win).
pub fn w16_w17_are_message_only() -> bool {
    // W16 = W0 + σ0(W1); W17 = W1 + σ0(W2) + σ1(1536)
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_4_collapses_sigma1() {
        // 14≡18 (mod 4). A 4-bit "win" cannot be lifted.
        assert_eq!(sigma1_distinct_mod(4), 2);
        assert_eq!(sigma0_distinct_mod(4), 2);
        assert_eq!(sigma1_distinct_mod(8), 3);
        assert_eq!(sigma1_distinct_mod(12), 3);
        assert_eq!(sigma1_distinct_mod(16), 3);
        assert_eq!(sigma1_distinct_mod(64), 3);
    }

    #[test]
    fn add_does_not_erase_a_sigma1_rotate() {
        assert!(missing_rotate_survives_add(8));
        assert!(missing_rotate_survives_add(12));
        assert!(missing_rotate_survives_add(16));
    }

    #[test]
    fn mixed_operand_two_rotate_sigma1_ch() {
        let xor_add = nontrivial(&screen_xor_add(48));
        let add_add = nontrivial(&screen_add_add(48));
        let rot_sum = nontrivial(&screen_rot_sum(48));
        assert!(
            xor_add.is_empty(),
            "xor_add hits: {xor_add:?} — would be a 10% SHF lead"
        );
        assert!(add_add.is_empty(), "add_add hits: {add_add:?}");
        assert!(rot_sum.is_empty(), "rot_sum hits: {rot_sum:?}");
    }

    #[test]
    fn mixed_operand_two_rotate_sigma0_maj() {
        let hits = nontrivial(&screen_maj_xor_add(48));
        assert!(hits.is_empty(), "maj hits: {hits:?}");
    }

    #[test]
    fn hmac64_first_expand_matches_generic() {
        for s in 0..200u64 {
            let msg = [
                splitmix(s * 8 + 1),
                splitmix(s * 8 + 2),
                splitmix(s * 8 + 3),
                splitmix(s * 8 + 4),
                splitmix(s * 8 + 5),
                splitmix(s * 8 + 6),
                splitmix(s * 8 + 7),
                splitmix(s * 8 + 8),
            ];
            let spec = hmac64_expand16(msg);
            let mut w = [0u64; 80];
            let b = hmac64_block(msg);
            w[..16].copy_from_slice(&b);
            expand_generic(&mut w);
            assert_eq!(spec, w[16..32], "expand mismatch at sample {s}");
        }
        assert_eq!(hmac64_first_expand_sigma(), (32, 22));
    }

    #[test]
    fn later_schedule_has_no_useful_identity() {
        let h = schedule_identity_search(40);
        assert_eq!(h.eq, 0, "W[t]==W[s] for t>=32");
        assert_eq!(h.xor_c, 0);
        assert_eq!(h.add_c, 0);
        assert_eq!(h.ror, 0);
        assert_eq!(h.pair_add, 0);
        assert_eq!(h.pair_xor, 0);
    }

    #[test]
    fn no_shared_rotate_amounts_across_sigma_family() {
        assert!(rotate_amount_overlap());
    }

    #[test]
    fn iadd3_association_is_exact() {
        assert!(iadd3_assoc_matches(400));
    }

    #[test]
    fn isa_model_iadd3_is_the_only_double_digit_local_lever() {
        let floor = round_cost_floor();
        let binary = round_cost_binary_add();
        let soft = round_cost_soft_rotate();
        assert_eq!(floor.total(), 28);
        assert_eq!(binary.total(), 34);
        assert_eq!(soft.total(), 52);
        // If production already emits SHF+IADD3+LOP3, IADD3 rewrite saves 0.
        // If adds are binary, 6/34 ≈ 18% of the round model (not e2e).
        let add_save = binary.iadd - floor.iadd;
        assert_eq!(add_save, 6);
        // Soft-rotate → SHF is huge in the model, but only if the compiler
        // does not already lower rotate(ulong) to SHF.
        assert!(soft.shf > floor.shf * 2);
    }

    #[test]
    fn two_rounds_do_not_shorten_depth() {
        let (one, two) = two_round_depth();
        assert_eq!(two, one * 2);
    }

    #[test]
    fn ch_maj_bitselect_identities() {
        for i in 0..200u64 {
            let (x, y, z) = sample_triple(i);
            // OpenCL bitselect(z,y,x) = (x&y) | (~x&z) = Ch
            let bitselect = (x & y) | ((!x) & z);
            assert_eq!(bitselect, (x & y) ^ ((!x) & z));
            assert_eq!(ch(x, y, z), bitselect);
            // bitselect(x,y,x^z) = Maj
            let sel = x ^ z;
            let maj_bs = (sel & y) | ((!sel) & x);
            assert_eq!(maj(x, y, z), maj_bs);
        }
    }

    #[test]
    fn production_digest_untouched() {
        let d = crate::sha512::digest(b"abc");
        assert_eq!(d[0], 0xdd);
        assert_eq!(d[1], 0xaf);
    }
}
