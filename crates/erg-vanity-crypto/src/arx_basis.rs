//! Alternative computational bases for batched ARX, as a reduced-width model.
//!
//! MiniARX is not SHA-512. It has the same *kinds* of coupling: wrapping add,
//! multi-distance rotate, XOR, Ch, Maj, and a σ-style schedule. Width 8 is
//! small enough that a bitslice working set fits in a realistic SIMD register
//! file, so a theoretical bitslice win can appear. The cost model then scales
//! the same circuit to width 64, where that working set no longer fits.
//!
//! Counters are **SIMD/warp issues for one batch of HASHES**, not scalar ops
//! per hash. One word-parallel add is 1 issue. One Kogge–Stone stage is a
//! handful of issues for the whole batch.

const WIDTH: usize = 8;
const HASHES: usize = 8;
const ROUNDS: usize = 8;
const STATE: usize = 4;
const MSG: usize = 4;

const K: [u8; ROUNDS] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];

/// One warp/SIMD-issue bundle. `shfl` is a cross-lane prefix access.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Issues {
    pub add: u32,
    pub rot: u32,
    pub shr: u32,
    pub xor: u32,
    pub and: u32,
    pub or: u32,
    pub shfl: u32,
    pub xpose: u32,
}

impl Issues {
    pub fn total(self) -> u32 {
        self.add + self.rot + self.shr + self.xor + self.and + self.or + self.shfl + self.xpose
    }

    fn accum(&mut self, o: Self) {
        self.add += o.add;
        self.rot += o.rot;
        self.shr += o.shr;
        self.xor += o.xor;
        self.and += o.and;
        self.or += o.or;
        self.shfl += o.shfl;
        self.xpose += o.xpose;
    }
}

type Word = u8;
type State = [Word; STATE];
type Planes = [Word; WIDTH];

// --- word-parallel -----------------------------------------------------------

fn ror(x: Word, n: u32) -> Word {
    let n = n & 7;
    x.rotate_right(n)
}

fn shr(x: Word, n: u32) -> Word {
    x >> (n & 7)
}

fn ch(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (!x & z)
}

fn maj(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sig0(x: Word) -> Word {
    ror(x, 1) ^ ror(x, 2) ^ shr(x, 3)
}

fn sig1(x: Word) -> Word {
    ror(x, 2) ^ ror(x, 4) ^ shr(x, 1)
}

fn ep0(x: Word) -> Word {
    ror(x, 2) ^ ror(x, 3) ^ ror(x, 5)
}

fn ep1(x: Word) -> Word {
    ror(x, 1) ^ ror(x, 4) ^ ror(x, 6)
}

fn compress_word(h: State, m: [Word; MSG]) -> State {
    let mut w = [0u8; ROUNDS];
    w[..MSG].copy_from_slice(&m);
    for t in MSG..ROUNDS {
        w[t] = sig1(w[t - 2])
            .wrapping_add(w[t - 3])
            .wrapping_add(sig0(w[t - 4]));
    }
    let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
    for t in 0..ROUNDS {
        let t1 = d
            .wrapping_add(ep1(c))
            .wrapping_add(ch(c, a, b))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = ep0(a).wrapping_add(maj(a, b, c));
        d = c;
        c = b.wrapping_add(t1);
        b = a;
        a = t1.wrapping_add(t2);
    }
    [
        h[0].wrapping_add(a),
        h[1].wrapping_add(b),
        h[2].wrapping_add(c),
        h[3].wrapping_add(d),
    ]
}

/// Word-parallel batch: HASHES independent states, one issue per op.
pub fn batch_word(hs: [State; HASHES], ms: [[Word; MSG]; HASHES]) -> ([State; HASHES], Issues) {
    let mut out = [State::default(); HASHES];
    for i in 0..HASHES {
        out[i] = compress_word(hs[i], ms[i]);
    }
    (out, word_issues())
}

fn word_issues() -> Issues {
    // Schedule: 4 × (σ1 + add + add + σ0). Each σ is 2 rot + 1 shr + 2 xor.
    // Rounds: 8 × (ep1 + ch + 4 add + ep0 + maj + 2 add).
    // ep is 3 rot + 2 xor. ch is 1 not + 2 and + 1 xor. maj is 3 and + 2 xor.
    // Davies–Meyer: 4 add.
    let sched_sigma = 4 * 2; // σ0+σ1 per expand
    let sched_add = 4 * 2;
    let rnd_ep = ROUNDS * 2;
    let rnd_add = ROUNDS * 6;
    let dm_add = STATE as u32;
    Issues {
        add: sched_add + rnd_add as u32 + dm_add,
        rot: (sched_sigma * 2 + rnd_ep * 3) as u32,
        shr: sched_sigma as u32,
        xor: (sched_sigma * 2 + rnd_ep * 2 + ROUNDS * (1 + 2)) as u32,
        and: (ROUNDS * (2 + 3)) as u32,
        or: 0,
        shfl: 0,
        xpose: 0,
    }
}

// --- bitslice packing --------------------------------------------------------

fn pack_word(words: [Word; HASHES]) -> Planes {
    let mut p = [0u8; WIDTH];
    for (hash, &w) in words.iter().enumerate() {
        for (bit, plane) in p.iter_mut().enumerate() {
            *plane |= ((w >> bit) & 1) << hash;
        }
    }
    p
}

fn unpack_word(p: Planes) -> [Word; HASHES] {
    let mut words = [0u8; HASHES];
    for (bit, &plane) in p.iter().enumerate() {
        for (hash, word) in words.iter_mut().enumerate() {
            *word |= ((plane >> hash) & 1) << bit;
        }
    }
    words
}

fn pack_states(hs: [State; HASHES]) -> [Planes; STATE] {
    let mut out = [[0u8; WIDTH]; STATE];
    for s in 0..STATE {
        let mut lane = [0u8; HASHES];
        for i in 0..HASHES {
            lane[i] = hs[i][s];
        }
        out[s] = pack_word(lane);
    }
    out
}

fn unpack_states(p: [Planes; STATE]) -> [State; HASHES] {
    let mut hs = [State::default(); HASHES];
    for s in 0..STATE {
        let lane = unpack_word(p[s]);
        for i in 0..HASHES {
            hs[i][s] = lane[i];
        }
    }
    hs
}

fn bs_ror(p: Planes, n: u32) -> Planes {
    let n = (n as usize) & 7;
    let mut o = [0u8; WIDTH];
    for i in 0..WIDTH {
        o[i] = p[(i + n) & 7];
    }
    o
}

fn bs_shr(p: Planes, n: u32) -> Planes {
    let n = n as usize;
    let mut o = [0u8; WIDTH];
    if n < WIDTH {
        o[..WIDTH - n].copy_from_slice(&p[n..]);
    }
    o
}

fn bs_xor(a: Planes, b: Planes, ops: &mut Issues) -> Planes {
    ops.xor += 1;
    let mut o = [0u8; WIDTH];
    for i in 0..WIDTH {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn bs_and(a: Planes, b: Planes, ops: &mut Issues) -> Planes {
    ops.and += 1;
    let mut o = [0u8; WIDTH];
    for i in 0..WIDTH {
        o[i] = a[i] & b[i];
    }
    o
}

fn bs_not(a: Planes, ops: &mut Issues) -> Planes {
    ops.xor += 1;
    let mut o = [0u8; WIDTH];
    for i in 0..WIDTH {
        o[i] = !a[i];
    }
    o
}

fn bs_ch(x: Planes, y: Planes, z: Planes, ops: &mut Issues) -> Planes {
    let t = bs_and(x, y, ops);
    let nx = bs_not(x, ops);
    let u = bs_and(nx, z, ops);
    bs_xor(t, u, ops)
}

fn bs_maj(x: Planes, y: Planes, z: Planes, ops: &mut Issues) -> Planes {
    let xy = bs_and(x, y, ops);
    let xz = bs_and(x, z, ops);
    let yz = bs_and(y, z, ops);
    bs_xor(bs_xor(xy, xz, ops), yz, ops)
}

fn bs_sig0(x: Planes, ops: &mut Issues) -> Planes {
    ops.rot += 2;
    ops.shr += 1;
    bs_xor(bs_xor(bs_ror(x, 1), bs_ror(x, 2), ops), bs_shr(x, 3), ops)
}

fn bs_sig1(x: Planes, ops: &mut Issues) -> Planes {
    ops.rot += 2;
    ops.shr += 1;
    bs_xor(bs_xor(bs_ror(x, 2), bs_ror(x, 4), ops), bs_shr(x, 1), ops)
}

fn bs_ep0(x: Planes, ops: &mut Issues) -> Planes {
    ops.rot += 3;
    bs_xor(bs_xor(bs_ror(x, 2), bs_ror(x, 3), ops), bs_ror(x, 5), ops)
}

fn bs_ep1(x: Planes, ops: &mut Issues) -> Planes {
    ops.rot += 3;
    bs_xor(bs_xor(bs_ror(x, 1), bs_ror(x, 4), ops), bs_ror(x, 6), ops)
}

/// Ripple add on bit-planes. Carry walks WIDTH sequential steps.
fn bs_add_ripple(a: Planes, b: Planes, ops: &mut Issues) -> Planes {
    let mut carry = 0u8;
    let mut s = [0u8; WIDTH];
    for i in 0..WIDTH {
        let axb = a[i] ^ b[i];
        s[i] = axb ^ carry;
        carry = (a[i] & b[i]) | (axb & carry);
        ops.xor += 2;
        ops.and += 2;
        ops.or += 1;
        if i > 0 {
            ops.shfl += 1;
        }
    }
    s
}

/// Prefix add (Kogge–Stone) on bit-planes.
///
/// Stage `d` reads generate/propagate from bit-lane `i-d`. On a warp-split
/// machine that is a shuffle, not a register rename.
pub fn kogge_stone_issues(width: u32) -> Issues {
    let stages = width.next_power_of_two().trailing_zeros();
    Issues {
        xor: 2,
        and: 1 + stages * 2,
        or: stages,
        shfl: stages * 2 + 1,
        ..Issues::default()
    }
}

fn bs_add_ks(a: Planes, b: Planes, ops: &mut Issues) -> Planes {
    ops.accum(kogge_stone_issues(WIDTH as u32));
    let mut p = [0u8; WIDTH];
    let mut g = [0u8; WIDTH];
    for i in 0..WIDTH {
        p[i] = a[i] ^ b[i];
        g[i] = a[i] & b[i];
    }
    let p0 = p;
    let mut d = 1;
    while d < WIDTH {
        let mut np = p;
        let mut ng = g;
        for i in d..WIDTH {
            ng[i] = g[i] | (p[i] & g[i - d]);
            np[i] = p[i] & p[i - d];
        }
        p = np;
        g = ng;
        d <<= 1;
    }
    let mut s = [0u8; WIDTH];
    s[0] = p0[0];
    for i in 1..WIDTH {
        s[i] = p0[i] ^ g[i - 1];
    }
    s
}

fn bs_add3<F>(a: Planes, b: Planes, c: Planes, add: F, ops: &mut Issues) -> Planes
where
    F: Fn(Planes, Planes, &mut Issues) -> Planes,
{
    add(add(a, b, ops), c, ops)
}

fn compress_bitslice<F>(
    hs: [State; HASHES],
    ms: [[Word; MSG]; HASHES],
    add: F,
) -> ([State; HASHES], Issues)
where
    F: Fn(Planes, Planes, &mut Issues) -> Planes,
{
    let mut ops = Issues::default();
    let mut w = [[0u8; WIDTH]; ROUNDS];
    for t in 0..MSG {
        let mut lane = [0u8; HASHES];
        for i in 0..HASHES {
            lane[i] = ms[i][t];
        }
        w[t] = pack_word(lane);
    }
    for t in MSG..ROUNDS {
        let s1 = bs_sig1(w[t - 2], &mut ops);
        let s0 = bs_sig0(w[t - 4], &mut ops);
        w[t] = bs_add3(s1, w[t - 3], s0, &add, &mut ops);
    }

    let st = pack_states(hs);
    let (mut a, mut b, mut c, mut d) = (st[0], st[1], st[2], st[3]);
    for t in 0..ROUNDS {
        let t1 = add(d, bs_ep1(c, &mut ops), &mut ops);
        let t1 = add(t1, bs_ch(c, a, b, &mut ops), &mut ops);
        let t1 = add(t1, pack_word([K[t]; HASHES]), &mut ops);
        let t1 = add(t1, w[t], &mut ops);
        let t2 = add(bs_ep0(a, &mut ops), bs_maj(a, b, c, &mut ops), &mut ops);
        d = c;
        c = add(b, t1, &mut ops);
        b = a;
        a = add(t1, t2, &mut ops);
    }
    let out_p = [
        add(st[0], a, &mut ops),
        add(st[1], b, &mut ops),
        add(st[2], c, &mut ops),
        add(st[3], d, &mut ops),
    ];
    (unpack_states(out_p), ops)
}

pub fn batch_bitslice_ripple(
    hs: [State; HASHES],
    ms: [[Word; MSG]; HASHES],
) -> ([State; HASHES], Issues) {
    compress_bitslice(hs, ms, bs_add_ripple)
}

pub fn batch_bitslice_ks(
    hs: [State; HASHES],
    ms: [[Word; MSG]; HASHES],
) -> ([State; HASHES], Issues) {
    compress_bitslice(hs, ms, bs_add_ks)
}

/// Hybrid: Σ/σ in bit-major (rotate = plane reindex), add in word-major.
/// Each crossing pays an 8×8 transpose.
pub fn batch_hybrid(hs: [State; HASHES], ms: [[Word; MSG]; HASHES]) -> ([State; HASHES], Issues) {
    let (out, mut ops) = batch_word(hs, ms);
    // Reprice: leaving word-major for each Σ/σ means transpose, plane-rotate,
    // untranspose. Adds stay native. This is the cost, not a second hash.
    let linear = word_issues().rot + word_issues().shr;
    ops.rot = 0;
    ops.shr = 0;
    ops.xpose = linear * 2;
    (out, ops)
}

/// 3:2 carry-save of three words, then one CPA. Gate-level vs 2 sequential adds.
pub fn csa3_issues() -> Issues {
    Issues {
        xor: 2,
        and: 2,
        or: 1,
        rot: 1, // carry << 1
        add: 1, // final CPA
        ..Issues::default()
    }
}

pub fn add5_word_issues() -> Issues {
    Issues {
        add: 4,
        ..Issues::default()
    }
}

/// SHA-512 HMAC-64 mix used only to scale the MiniARX conclusion.
/// Adds: 80×7 round + specialized first expand (35) + 48×3 dense + 8 DM.
pub const SHA512_HMAC64_ADDS: u32 = 80 * 7 + 35 + 48 * 3 + 8;
/// ROTR: 80×6 (Σ) + first-expand 22σ×2 + 48×(σ0+σ1)×2.
pub const SHA512_HMAC64_ROTR: u32 = 80 * 6 + 22 * 2 + 48 * 4;

#[derive(Clone, Copy, Debug)]
pub struct MachineCost {
    pub word: f64,
    pub bitslice_ks: f64,
    pub bitslice_ripple: f64,
    pub hybrid_sigma: f64,
}

/// GPU SIMT: one warp evaluates `lanes` hashes. Native add is `add_per_word`
/// issues (2 on a 32-bit ALU for a 64-bit add). Rotate is `rot_per_word`
/// (2 SHF for 64-bit ROTR). A shuffle is charged `shfl_weight` add-equivalents.
pub fn gpu_hmac64_cost(shfl_weight: f64) -> MachineCost {
    let adds = f64::from(SHA512_HMAC64_ADDS);
    let rots = f64::from(SHA512_HMAC64_ROTR);
    let word = adds * 2.0 + rots * 2.0;
    let ks = kogge_stone_issues(64);
    let add_ks = f64::from(ks.shfl) * shfl_weight + f64::from(ks.xor + ks.and + ks.or);
    let bitslice_ks = adds * add_ks + rots * 2.0 * shfl_weight;
    let bitslice_ripple =
        adds * (64.0 * (2.0 + 2.0 + 1.0) + 63.0 * shfl_weight) + rots * 2.0 * shfl_weight;
    // Hybrid: stay word-major for add; each Σ/σ is transpose-rotate-untranspose.
    // 32×32 transpose ≈ 5 stages × 2 SHFL (two halves of a 64-bit word).
    let xpose = 10.0 * shfl_weight;
    let hybrid_sigma = adds * 2.0 + rots * (2.0 * xpose);
    MachineCost {
        word,
        bitslice_ks,
        bitslice_ripple,
        hybrid_sigma,
    }
}

/// Wide SIMD (AVX-512-shaped): `vec_bits` lanes, `n_vec_regs` architectural
/// registers. Word-parallel packs `vec_bits/word_bits` hashes per vector.
/// Bitslice packs `vec_bits` hashes, but needs `word_bits` planes per live word.
pub fn wide_simd_hmac64_cost(vec_bits: u32, n_vec_regs: u32, word_bits: u32) -> MachineCost {
    let adds = f64::from(SHA512_HMAC64_ADDS);
    let rots = f64::from(SHA512_HMAC64_ROTR);
    let hashes_word = f64::from(vec_bits / word_bits);
    let hashes_slice = f64::from(vec_bits);
    let word = (adds + rots) / hashes_word;

    let ks = kogge_stone_issues(word_bits);
    let planes_needed = word_bits * 8; // 8 live state words, W spilled
    let fits = planes_needed <= n_vec_regs;
    let add_ks = f64::from(ks.xor + ks.and + ks.or + ks.shfl);
    let bitslice_ks = if fits {
        adds * add_ks / hashes_slice
    } else {
        // Planes live in L1. Each KS stage touches every plane.
        let stages = f64::from(word_bits.next_power_of_two().trailing_zeros());
        let per_add = stages * f64::from(word_bits) * 6.0;
        (adds * per_add + rots * 3.0 * f64::from(word_bits)) / hashes_slice
    };
    let bitslice_ripple = (adds * f64::from(word_bits) * 5.0) / hashes_slice;
    let hybrid_sigma = (adds / hashes_word) + (rots * 2.0 * 10.0) / hashes_slice;
    MachineCost {
        word,
        bitslice_ks,
        bitslice_ripple,
        hybrid_sigma,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_batch(seed: u8) -> ([State; HASHES], [[Word; MSG]; HASHES]) {
        let mut hs = [State::default(); HASHES];
        let mut ms = [[0u8; MSG]; HASHES];
        for i in 0..HASHES {
            let s = seed.wrapping_add(i as u8).wrapping_mul(17);
            hs[i] = [s, s.wrapping_add(3), s.wrapping_add(11), s.wrapping_add(29)];
            ms[i] = [
                s.wrapping_mul(3),
                s.wrapping_mul(5).wrapping_add(1),
                s.wrapping_mul(7).wrapping_add(2),
                s.wrapping_mul(11).wrapping_add(3),
            ];
        }
        (hs, ms)
    }

    #[test]
    fn all_bases_match_word_parallel() {
        for seed in 0u8..40 {
            let (hs, ms) = det_batch(seed);
            let (word, _) = batch_word(hs, ms);
            let (ripple, _) = batch_bitslice_ripple(hs, ms);
            let (ks, _) = batch_bitslice_ks(hs, ms);
            let (hyb, _) = batch_hybrid(hs, ms);
            assert_eq!(ripple, word, "ripple seed={seed}");
            assert_eq!(ks, word, "ks seed={seed}");
            assert_eq!(hyb, word, "hybrid seed={seed}");
        }
    }

    #[test]
    fn kogge_stone_matches_ripple_on_corners() {
        let cases = [
            ([0xff; 8], [0x01; 8]),
            ([0x80; 8], [0x80; 8]),
            ([0x00; 8], [0x00; 8]),
            ([0xa5; 8], [0x5a; 8]),
        ];
        for (a_w, b_w) in cases {
            let a = pack_word(a_w);
            let b = pack_word(b_w);
            let mut o1 = Issues::default();
            let mut o2 = Issues::default();
            assert_eq!(bs_add_ks(a, b, &mut o1), bs_add_ripple(a, b, &mut o2));
        }
    }

    #[test]
    fn toy_gpu_ks_is_more_issues_than_word_add() {
        let (hs, ms) = det_batch(1);
        let (_, w) = batch_word(hs, ms);
        let (_, ks) = batch_bitslice_ks(hs, ms);
        let (_, rp) = batch_bitslice_ripple(hs, ms);
        let (_, hy) = batch_hybrid(hs, ms);
        // Prefix add cannot beat a native word adder: the ALU *is* that prefix
        // network, collapsed into one issue. KS re-expands it.
        assert!(
            ks.total() > w.total() * 3,
            "ks={} word={}",
            ks.total(),
            w.total()
        );
        assert!(rp.total() > ks.total());
        assert!(hy.total() > w.total());
    }

    #[test]
    fn csa_loses_when_add_equals_xor() {
        let csa = csa3_issues();
        let seq = Issues {
            add: 2,
            ..Issues::default()
        };
        // Three-operand sum: 2 IADD vs CSA+CPA. If IADD ≈ LOP, sequential wins.
        assert!(csa.total() > seq.total());
        assert!(csa3_issues().total() + 2 > add5_word_issues().total());
    }

    #[test]
    fn gpu_sha512_projection_ks_loses() {
        let eq = gpu_hmac64_cost(1.0);
        assert!(
            eq.bitslice_ks / eq.word > 4.0,
            "ks/word = {}",
            eq.bitslice_ks / eq.word
        );
        assert!(eq.bitslice_ripple / eq.word > eq.bitslice_ks / eq.word);
        assert!(eq.hybrid_sigma / eq.word > 3.0);
        // Even if SHFL were 4× cheaper than SHF, KS add still dominates.
        let cheap = gpu_hmac64_cost(0.25);
        assert!(cheap.bitslice_ks / cheap.word > 2.0);
    }

    #[test]
    fn avx512_win_is_register_file_fiction() {
        // Infinite registers: bitslice KS would beat 8-wide word-parallel.
        let infinite = wide_simd_hmac64_cost(512, u32::MAX, 64);
        assert!(
            infinite.bitslice_ks < infinite.word * 0.5,
            "infinite ks/word = {}",
            infinite.bitslice_ks / infinite.word
        );
        // 32 ZMM: 64 planes × 8 words do not fit. Spill reverses the win.
        let avx = wide_simd_hmac64_cost(512, 32, 64);
        assert!(
            avx.bitslice_ks > avx.word * 2.0,
            "avx ks/word = {}",
            avx.bitslice_ks / avx.word
        );
    }

    #[test]
    fn basis_cost_table() {
        let (hs, ms) = det_batch(7);
        let (_, w) = batch_word(hs, ms);
        let (_, ks) = batch_bitslice_ks(hs, ms);
        let (_, rp) = batch_bitslice_ripple(hs, ms);
        let (_, hy) = batch_hybrid(hs, ms);
        let gpu = gpu_hmac64_cost(1.0);
        let avx = wide_simd_hmac64_cost(512, 32, 64);
        let inf = wide_simd_hmac64_cost(512, u32::MAX, 64);
        eprintln!(
            "MiniARX warp issues  word={} ks={} ripple={} hybrid={}",
            w.total(),
            ks.total(),
            rp.total(),
            hy.total()
        );
        eprintln!(
            "SHA-512 HMAC-64 GPU (add-eq)  word={:.0} ks={:.0} ripple={:.0} hybrid={:.0}",
            gpu.word, gpu.bitslice_ks, gpu.bitslice_ripple, gpu.hybrid_sigma
        );
        eprintln!(
            "SHA-512 per-hash AVX-512  word={:.3} ks_spill={:.3} ks_infinite={:.3}",
            avx.word, avx.bitslice_ks, inf.bitslice_ks
        );
    }
}
