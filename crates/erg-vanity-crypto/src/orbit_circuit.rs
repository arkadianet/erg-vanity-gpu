//! Factored-circuit representations of F^n and G_n = ⊕_{i=1}^{n} F^i.
//!
//! ANF weight is not the metric. This module builds a hash-consed bit DAG
//! (syntactic CSE + algebraic rewrite), then merges nodes that compute the
//! same Boolean function of x (semantic CSE). Doubling
//!   F^{2n} = F^n ∘ F^n
//!   G_{2n}(x) = G_n(x) ⊕ G_n(F^n(x))
//! is measured against sequential unrolling.
//!
//! Independent of the production PBKDF2 path.

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    C0,
    C1,
    In(u8),
    Not(u32),
    Xor(u32, u32),
    And(u32, u32),
}

#[derive(Default)]
pub struct Dag {
    ops: Vec<Op>,
    intern: HashMap<Op, u32>,
}

impl Dag {
    pub fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, op: Op) -> u32 {
        if let Some(&id) = self.intern.get(&op) {
            return id;
        }
        let id = self.ops.len() as u32;
        self.ops.push(op);
        self.intern.insert(op, id);
        id
    }

    pub fn c0(&mut self) -> u32 {
        self.intern(Op::C0)
    }
    pub fn c1(&mut self) -> u32 {
        self.intern(Op::C1)
    }
    pub fn input(&mut self, i: u8) -> u32 {
        self.intern(Op::In(i))
    }

    pub fn not(&mut self, a: u32) -> u32 {
        match self.ops[a as usize] {
            Op::C0 => self.c1(),
            Op::C1 => self.c0(),
            Op::Not(x) => x,
            _ => self.intern(Op::Not(a)),
        }
    }

    pub fn xor(&mut self, a: u32, b: u32) -> u32 {
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        if a == b {
            return self.c0();
        }
        match (self.ops[a as usize], self.ops[b as usize]) {
            (Op::C0, _) => b,
            (_, Op::C0) => a,
            (Op::C1, _) => self.not(b),
            (_, Op::C1) => self.not(a),
            _ => self.intern(Op::Xor(a, b)),
        }
    }

    pub fn and(&mut self, a: u32, b: u32) -> u32 {
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        if a == b {
            return a;
        }
        match (self.ops[a as usize], self.ops[b as usize]) {
            (Op::C0, _) | (_, Op::C0) => self.c0(),
            (Op::C1, _) => b,
            (_, Op::C1) => a,
            _ => self.intern(Op::And(a, b)),
        }
    }

    pub fn nodes(&self) -> u32 {
        self.ops.len() as u32
    }

    pub fn work_gates(&self, cone: &HashSet<u32>) -> (u32, u32) {
        let mut xors = 0u32;
        let mut ands = 0u32;
        for &id in cone {
            match self.ops[id as usize] {
                Op::Xor(_, _) => xors += 1,
                Op::And(_, _) => ands += 1,
                _ => {}
            }
        }
        (xors, ands)
    }
}

fn cone_of(d: &Dag, outs: &[u32]) -> HashSet<u32> {
    let mut seen = HashSet::new();
    let mut stack = outs.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        match d.ops[id as usize] {
            Op::Not(a) => stack.push(a),
            Op::Xor(a, b) | Op::And(a, b) => {
                stack.push(a);
                stack.push(b);
            }
            _ => {}
        }
    }
    seen
}

fn word_in(d: &mut Dag, w: u8) -> Vec<u32> {
    (0..w).map(|i| d.input(i)).collect()
}

fn const_word(d: &mut Dag, v: u32, w: u8) -> Vec<u32> {
    (0..w)
        .map(|i| if (v >> i) & 1 == 1 { d.c1() } else { d.c0() })
        .collect()
}

fn xor_words(d: &mut Dag, a: &[u32], b: &[u32]) -> Vec<u32> {
    a.iter().zip(b).map(|(&x, &y)| d.xor(x, y)).collect()
}

fn and_words(d: &mut Dag, a: &[u32], b: &[u32]) -> Vec<u32> {
    a.iter().zip(b).map(|(&x, &y)| d.and(x, y)).collect()
}

fn ror_word(a: &[u32], n: u32) -> Vec<u32> {
    let w = a.len();
    let n = n as usize % w;
    (0..w).map(|i| a[(i + n) % w]).collect()
}

fn rol_word(a: &[u32], n: u32) -> Vec<u32> {
    let w = a.len();
    ror_word(a, w as u32 - (n % w as u32))
}

fn shr_word(d: &mut Dag, a: &[u32], n: u32) -> Vec<u32> {
    let w = a.len();
    let n = n as usize;
    (0..w)
        .map(|i| if i + n < w { a[i + n] } else { d.c0() })
        .collect()
}

fn add_words(d: &mut Dag, a: &[u32], b: &[u32]) -> Vec<u32> {
    let w = a.len();
    let mut c = d.c0();
    let mut s = vec![0u32; w];
    for i in 0..w {
        let axb = d.xor(a[i], b[i]);
        s[i] = d.xor(axb, c);
        let ab = d.and(a[i], b[i]);
        let cab = d.and(c, axb);
        // carry = ab ∨ (c ∧ (a⊕b)) = ab ⊕ cab ⊕ (ab ∧ cab) but ∨ via
        // x∨y = x⊕y⊕(x∧y)
        let ab_xor_cab = d.xor(ab, cab);
        let ab_and_cab = d.and(ab, cab);
        c = d.xor(ab_xor_cab, ab_and_cab);
    }
    s
}

fn eval_word(d: &Dag, bits: &[u32], x: u32) -> u32 {
    let mut val = vec![false; d.ops.len()];
    for (id, op) in d.ops.iter().enumerate() {
        val[id] = match *op {
            Op::C0 => false,
            Op::C1 => true,
            Op::In(i) => (x >> i) & 1 == 1,
            Op::Not(a) => !val[a as usize],
            Op::Xor(a, b) => val[a as usize] ^ val[b as usize],
            Op::And(a, b) => val[a as usize] & val[b as usize],
        };
    }
    let mut y = 0u32;
    for (i, &b) in bits.iter().enumerate() {
        if val[b as usize] {
            y |= 1 << i;
        }
    }
    y
}

/// Truth table of every node (width ≤ 16). Each table is 2^w bits, packed.
fn node_tables(d: &Dag, w: u8) -> Vec<Vec<u64>> {
    let nbits = 1usize << w;
    let words = nbits.div_ceil(64);
    let mut tabs = vec![vec![0u64; words]; d.ops.len()];
    for (id, op) in d.ops.iter().enumerate() {
        match *op {
            Op::C0 => {}
            Op::C1 => {
                for t in &mut tabs[id] {
                    *t = u64::MAX;
                }
                if !nbits.is_multiple_of(64) {
                    let last = words - 1;
                    tabs[id][last] = (1u64 << (nbits % 64)) - 1;
                }
            }
            Op::In(i) => {
                for x in 0..nbits {
                    if (x >> i) & 1 == 1 {
                        tabs[id][x / 64] |= 1u64 << (x % 64);
                    }
                }
            }
            Op::Not(a) => {
                let src = tabs[a as usize].clone();
                for (t, &s) in tabs[id].iter_mut().zip(src.iter()) {
                    *t = !s;
                }
                if !nbits.is_multiple_of(64) {
                    let last = words - 1;
                    tabs[id][last] &= (1u64 << (nbits % 64)) - 1;
                }
            }
            Op::Xor(a, b) => {
                let ta = tabs[a as usize].clone();
                let tb = tabs[b as usize].clone();
                for j in 0..words {
                    tabs[id][j] = ta[j] ^ tb[j];
                }
            }
            Op::And(a, b) => {
                let ta = tabs[a as usize].clone();
                let tb = tabs[b as usize].clone();
                for j in 0..words {
                    tabs[id][j] = ta[j] & tb[j];
                }
            }
        }
    }
    tabs
}

fn semantic_counts(d: &Dag, w: u8, outs: &[u32]) -> Sem {
    let cone = cone_of(d, outs);
    let (syn_xor, syn_and) = d.work_gates(&cone);
    let tabs = node_tables(d, w);
    let mut uniq = HashSet::new();
    let mut uniq_and = HashSet::new();
    for &id in &cone {
        uniq.insert(tabs[id as usize].clone());
        if matches!(d.ops[id as usize], Op::And(_, _)) {
            uniq_and.insert(tabs[id as usize].clone());
        }
    }
    Sem {
        syn_nodes: cone.len() as u32,
        syn_xor,
        syn_and,
        sem_nodes: uniq.len() as u32,
        sem_and: uniq_and.len() as u32,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Sem {
    pub syn_nodes: u32,
    pub syn_xor: u32,
    pub syn_and: u32,
    pub sem_nodes: u32,
    pub sem_and: u32,
}

// ---------------------------------------------------------------------------
// Mini-HMAC on a w-bit word, matching orbit_xor::hmac_f for w=8.
// ---------------------------------------------------------------------------

fn compress_bits(d: &mut Dag, iv: &[u32], m: &[u32], rounds: u32) -> Vec<u32> {
    let w = iv.len() as u8;
    let mut x = iv.to_vec();
    let mut ww = m.to_vec();
    for r in 0..rounds {
        let k = (r as u8).wrapping_mul(0x9e).wrapping_add(0x37) as u32;
        let kv = const_word(d, k, w);
        let s35 = xor_words(d, &ror_word(&x, 3), &ror_word(&x, 5));
        let sh = shr_word(d, &x, 1);
        let s = xor_words(d, &s35, &sh);
        let w5a = const_word(d, 0x5a, w);
        let inner = xor_words(d, &ww, &w5a);
        let x_and = and_words(d, &x, &inner);
        let ch = xor_words(d, &ww, &x_and);
        x = add_words(d, &x, &s);
        x = add_words(d, &x, &ch);
        x = add_words(d, &x, &kv);
        ww = add_words(d, &rol_word(&ww, 1), &x);
    }
    xor_words(d, &x, iv)
}

/// F_P as a circuit in x. I,O are constants (fixed password).
pub fn hmac_apply(d: &mut Dag, x: &[u32], p: u8, rounds: u32) -> Vec<u32> {
    let w = x.len() as u8;
    let iv = const_word(d, 0x6a, w);
    let i_msg = const_word(d, (p ^ 0x36) as u32, w);
    let o_msg = const_word(d, (p ^ 0x5c) as u32, w);
    let i = compress_bits(d, &iv, &i_msg, rounds);
    let o = compress_bits(d, &iv, &o_msg, rounds);
    let inner = compress_bits(d, &i, x, rounds);
    compress_bits(d, &o, &inner, rounds)
}

fn affine_apply(d: &mut Dag, x: &[u32]) -> Vec<u32> {
    let w = x.len() as u8;
    let c = const_word(d, 0x1d, w);
    xor_words(d, &rol_word(x, 1), &c)
}

#[derive(Clone, Copy)]
pub enum Kind {
    Hmac { p: u8, rounds: u32 },
    Affine,
}

fn apply(d: &mut Dag, x: &[u32], kind: Kind) -> Vec<u32> {
    match kind {
        Kind::Hmac { p, rounds } => hmac_apply(d, x, p, rounds),
        Kind::Affine => affine_apply(d, x),
    }
}

/// Sequential G_n: n applications of F, XOR into an accumulator.
pub fn sequential_g(w: u8, n: u32, kind: Kind) -> (Dag, Vec<u32>, Vec<u32>) {
    let mut d = Dag::new();
    let mut u = word_in(&mut d, w);
    let mut g = const_word(&mut d, 0, w);
    let mut last = u.clone();
    for _ in 0..n {
        u = apply(&mut d, &u, kind);
        g = xor_words(&mut d, &g, &u);
        last = u.clone();
    }
    (d, g, last)
}

/// Doubling: (F^{2n}, G_{2n}) from replayable F.
/// G_{2n}(x) = G_n(x) ⊕ G_n(F^n(x)), F^{2n} = F^n ∘ F^n.
pub fn doubled_g(w: u8, k: u32, kind: Kind) -> (Dag, Vec<u32>, Vec<u32>) {
    let mut d = Dag::new();
    let x = word_in(&mut d, w);
    let (g, fpow) = double_rec(&mut d, &x, k, kind);
    (d, g, fpow)
}

fn double_rec(d: &mut Dag, x: &[u32], k: u32, kind: Kind) -> (Vec<u32>, Vec<u32>) {
    if k == 0 {
        let fx = apply(d, x, kind);
        return (fx.clone(), fx);
    }
    let (g_n, f_n) = double_rec(d, x, k - 1, kind);
    let (g_n_at_fn, f_2n) = replay_g_and_f(d, &f_n, k - 1, kind);
    let g_2n = xor_words(d, &g_n, &g_n_at_fn);
    (g_2n, f_2n)
}

/// Replay the same doubling tree rooted at a new input.
fn replay_g_and_f(d: &mut Dag, x: &[u32], k: u32, kind: Kind) -> (Vec<u32>, Vec<u32>) {
    double_rec(d, x, k, kind)
}

#[derive(Clone, Copy, Debug)]
pub struct Sizes {
    pub n: u32,
    pub seq: Sem,
    pub dbl: Sem,
}

pub fn measure(w: u8, k: u32, kind: Kind) -> Sizes {
    let n = 1u32 << k;
    let (ds, gs, _) = sequential_g(w, n, kind);
    let (dd, gd, _) = doubled_g(w, k, kind);
    Sizes {
        n,
        seq: semantic_counts(&ds, w, &gs),
        dbl: semantic_counts(&dd, w, &gd),
    }
}

// ---------------------------------------------------------------------------
// Shared ROBDD for w=8 output bits (compact decision-diagram of a map).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct BddKey {
    var: u8,
    lo: u32,
    hi: u32,
}

struct Bdd {
    intern: HashMap<BddKey, u32>,
    /// node id -> key; 0 = ⊥, 1 = ⊤
    next: u32,
}

impl Bdd {
    fn new() -> Self {
        Self {
            intern: HashMap::new(),
            next: 2,
        }
    }

    fn mk(&mut self, var: u8, lo: u32, hi: u32) -> u32 {
        if lo == hi {
            return lo;
        }
        let key = BddKey { var, lo, hi };
        if let Some(&id) = self.intern.get(&key) {
            return id;
        }
        let id = self.next;
        self.next += 1;
        self.intern.insert(key, id);
        id
    }

    /// Truth table of one output bit, 8 inputs, index = input byte.
    fn add_byte_table(&mut self, table: &[u8; 256], bit: u32) -> u32 {
        fn rec(b: &mut Bdd, table: &[u8; 256], bit: u32, var: u8, prefix: u8) -> u32 {
            if var == 8 {
                return if (table[prefix as usize] >> bit) & 1 == 1 {
                    1
                } else {
                    0
                };
            }
            let lo = rec(b, table, bit, var + 1, prefix);
            let hi = rec(b, table, bit, var + 1, prefix | (1 << var));
            b.mk(var, lo, hi)
        }
        rec(self, table, bit, 0, 0)
    }

    fn nodes(&self) -> u32 {
        self.next
    }
}

/// Shared BDD node count for an 8-bit→8-bit map given as a table.
pub fn bdd_size_u8(table: &[u8; 256]) -> u32 {
    let mut b = Bdd::new();
    for bit in 0..8 {
        b.add_byte_table(table, bit);
    }
    b.nodes()
}

pub fn g_table_u8(n: u32, kind: Kind) -> [u8; 256] {
    let (d, g, _) = sequential_g(8, n, kind);
    let mut t = [0u8; 256];
    for x in 0..=255u8 {
        t[x as usize] = eval_word(&d, &g, x as u32) as u8;
    }
    t
}

// ---------------------------------------------------------------------------
// 4×4-bit SHA-like F (16-bit state): Σ, Ch, Maj, add, Davies–Meyer.
// ---------------------------------------------------------------------------

fn sha4_round(d: &mut Dag, st: &[Vec<u32>; 4], k: u32, wmsg: &[u32]) -> [Vec<u32>; 4] {
    // st = [a, b, e, f]; c:=b, d:=a, g:=f, h:=e  (collapsed 4-word model)
    let a = &st[0];
    let b = &st[1];
    let e = &st[2];
    let f = &st[3];
    let s12 = xor_words(d, &ror_word(e, 1), &ror_word(e, 2));
    let sig1 = xor_words(d, &s12, &ror_word(e, 3));
    let f_xor_b = xor_words(d, f, b);
    let e_and = and_words(d, e, &f_xor_b);
    let ch = xor_words(d, b, &e_and);
    let kv = const_word(d, k, 4);
    let mut t1 = add_words(d, e, &sig1);
    t1 = add_words(d, &t1, &ch);
    t1 = add_words(d, &t1, &kv);
    t1 = add_words(d, &t1, wmsg);
    let a12 = xor_words(d, &ror_word(a, 1), &ror_word(a, 2));
    let sig0 = xor_words(d, &a12, &ror_word(a, 3));
    let ab = and_words(d, a, b);
    let ae = and_words(d, a, e);
    let be = and_words(d, b, e);
    let ae_be = xor_words(d, &ae, &be);
    let maj = xor_words(d, &ab, &ae_be);
    let t2 = add_words(d, &sig0, &maj);
    let a2 = add_words(d, &t1, &t2);
    let e2 = add_words(d, a, &t1);
    [a2, a.clone(), e2, e.clone()]
}

fn sha4_compress(d: &mut Dag, h: &[Vec<u32>; 4], msg: &[u32], rounds: u32) -> [Vec<u32>; 4] {
    let mut st = h.clone();
    let mut w = msg.to_vec();
    for r in 0..rounds {
        let k = 0x5a + r * 3;
        st = sha4_round(d, &st, k, &w);
        w = add_words(d, &ror_word(&w, 1), &st[0]);
    }
    [
        xor_words(d, &st[0], &h[0]),
        xor_words(d, &st[1], &h[1]),
        xor_words(d, &st[2], &h[2]),
        xor_words(d, &st[3], &h[3]),
    ]
}

fn pack4(st: &[Vec<u32>; 4]) -> Vec<u32> {
    let mut v = Vec::with_capacity(16);
    for w in st {
        v.extend_from_slice(w);
    }
    v
}

fn unpack4(v: &[u32]) -> [Vec<u32>; 4] {
    [
        v[0..4].to_vec(),
        v[4..8].to_vec(),
        v[8..12].to_vec(),
        v[12..16].to_vec(),
    ]
}

fn sha4_hmac_apply(d: &mut Dag, x: &[u32], rounds: u32) -> Vec<u32> {
    let iv = [
        const_word(d, 0x6, 4),
        const_word(d, 0xa, 4),
        const_word(d, 0x3, 4),
        const_word(d, 0xc, 4),
    ];
    // I,O from const key/iv — const-fold to midstates.
    let km_i = const_word(d, 0x5, 4);
    let km_o = const_word(d, 0xa, 4);
    let i = sha4_compress(d, &iv, &km_i, rounds);
    let o = sha4_compress(d, &iv, &km_o, rounds);
    let xs = unpack4(x);
    let inner = sha4_compress(d, &i, &xs[0], rounds);
    pack4(&sha4_compress(d, &o, &inner[0], rounds))
}

pub fn sequential_sha4(n: u32, rounds: u32) -> (Dag, Vec<u32>) {
    let mut d = Dag::new();
    let mut u = word_in(&mut d, 16);
    let mut g = const_word(&mut d, 0, 16);
    for _ in 0..n {
        u = sha4_hmac_apply(&mut d, &u, rounds);
        g = xor_words(&mut d, &g, &u);
    }
    (d, g)
}

fn compress16_bits(d: &mut Dag, iv: &[u32], m: &[u32], rounds: u32) -> Vec<u32> {
    let w = iv.len() as u8;
    let mut x = iv.to_vec();
    let mut ww = m.to_vec();
    for r in 0..rounds {
        let k = (r as u16).wrapping_mul(0x9e37).wrapping_add(0x37) as u32;
        let kv = const_word(d, k, w);
        let s35 = xor_words(d, &ror_word(&x, 3), &ror_word(&x, 5));
        let sh = shr_word(d, &x, 1);
        let s = xor_words(d, &s35, &sh);
        let w5a = const_word(d, 0x5a5a, w);
        let inner = xor_words(d, &ww, &w5a);
        let x_and = and_words(d, &x, &inner);
        let ch = xor_words(d, &ww, &x_and);
        x = add_words(d, &x, &s);
        x = add_words(d, &x, &ch);
        x = add_words(d, &x, &kv);
        ww = add_words(d, &rol_word(&ww, 1), &x);
    }
    xor_words(d, &x, iv)
}

pub fn hmac16_apply(d: &mut Dag, x: &[u32], p: u16, rounds: u32) -> Vec<u32> {
    let w = x.len() as u8;
    let iv = const_word(d, 0x6a6a, w);
    let i_msg = const_word(d, (p ^ 0x3636) as u32, w);
    let o_msg = const_word(d, (p ^ 0x5c5c) as u32, w);
    let i = compress16_bits(d, &iv, &i_msg, rounds);
    let o = compress16_bits(d, &iv, &o_msg, rounds);
    let inner = compress16_bits(d, &i, x, rounds);
    compress16_bits(d, &o, &inner, rounds)
}

pub fn sequential_hmac16(n: u32, p: u16, rounds: u32) -> (Dag, Vec<u32>) {
    let mut d = Dag::new();
    let mut u = word_in(&mut d, 16);
    let mut g = const_word(&mut d, 0, 16);
    for _ in 0..n {
        u = hmac16_apply(&mut d, &u, p, rounds);
        g = xor_words(&mut d, &g, &u);
    }
    (d, g)
}

pub fn measure_hmac16(n: u32, p: u16, rounds: u32) -> Sem {
    let (d, g) = sequential_hmac16(n, p, rounds);
    semantic_counts(&d, 16, &g)
}

#[cfg(test)]
fn map_image_cycle(d: &Dag, y: &[u32], w: u8) -> (u32, u32) {
    let n = 1u32 << w;
    let mut next = vec![0u32; n as usize];
    let mut seen = vec![false; n as usize];
    let mut img = 0u32;
    for x in 0..n {
        let v = eval_word(d, y, x);
        next[x as usize] = v;
        if !seen[v as usize] {
            seen[v as usize] = true;
            img += 1;
        }
    }
    let mut st = vec![0u8; n as usize];
    let mut max_c = 0u32;
    for start in 0..n {
        if st[start as usize] != 0 {
            continue;
        }
        let mut x = start;
        let mut path = Vec::new();
        while st[x as usize] == 0 {
            st[x as usize] = 1;
            path.push(x);
            x = next[x as usize];
        }
        if st[x as usize] == 1 {
            let pos = path.iter().position(|&z| z == x).unwrap();
            max_c = max_c.max((path.len() - pos) as u32);
        }
        for z in path {
            st[z as usize] = 2;
        }
    }
    (img, max_c)
}

pub fn measure_sha4(n: u32, rounds: u32) -> Sem {
    let (d, g) = sequential_sha4(n, rounds);
    semantic_counts(&d, 16, &g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orbit_xor::{hmac_f, hmac_f16, map_table, y_k};

    #[test]
    fn hmac_circuit_matches_scalar() {
        for rounds in [1u32, 2, 3] {
            let mut d = Dag::new();
            let x = word_in(&mut d, 8);
            let y = hmac_apply(&mut d, &x, 0x41, rounds);
            for v in 0..=255u8 {
                assert_eq!(
                    eval_word(&d, &y, v as u32) as u8,
                    hmac_f(0x41, v, rounds),
                    "rounds {rounds} x={v}"
                );
            }
        }
    }

    #[test]
    fn sequential_g_matches_y_k() {
        let (d, g, _) = sequential_g(8, 16, Kind::Hmac { p: 0x41, rounds: 2 });
        let f = |x| hmac_f(0x41, x, 2);
        for x in (0..=255).step_by(3) {
            assert_eq!(eval_word(&d, &g, x as u32) as u8, y_k(x, 4, f));
        }
    }

    #[test]
    fn doubling_matches_sequential() {
        for k in 0..=4u32 {
            let n = 1u32 << k;
            let (ds, gs, _) = sequential_g(8, n, Kind::Hmac { p: 0x41, rounds: 2 });
            let (dd, gd, _) = doubled_g(8, k, Kind::Hmac { p: 0x41, rounds: 2 });
            for x in (0..=255).step_by(7) {
                assert_eq!(
                    eval_word(&ds, &gs, x as u32),
                    eval_word(&dd, &gd, x as u32),
                    "k={k} x={x}"
                );
            }
        }
    }

    #[test]
    fn affine_semantic_size_does_not_grow() {
        let s1 = measure(8, 0, Kind::Affine);
        let s4 = measure(8, 4, Kind::Affine);
        // Affine: no ANDs. Unique affine intermediates stay bounded
        // (rot has finite order; prefix-XORs add a few forms).
        assert_eq!(s4.seq.sem_and, 0);
        assert!(s4.seq.sem_nodes < 100, "F {:?} G16 {:?}", s1.seq, s4.seq);
    }

    #[test]
    fn one_round_g32_is_compact() {
        // Y_5 ≡ 0 as a *function*. The unrolled cone still stores the walk;
        // the compact representation of the output map is the zero circuit.
        let tg = g_table_u8(32, Kind::Hmac { p: 0x41, rounds: 1 });
        assert!(tg.iter().all(|&y| y == 0));
        assert_eq!(bdd_size_u8(&tg), 2); // ⊥ only
        let s = measure(8, 5, Kind::Hmac { p: 0x41, rounds: 1 });
        eprintln!("1-round G_32 unrolled {:?}", s.seq);
    }

    #[test]
    fn growth_curve_two_round_eight_bit() {
        let kind = Kind::Hmac { p: 0x41, rounds: 2 };
        let f = measure(8, 0, kind);
        let mut rows = Vec::new();
        for k in 0..=4u32 {
            rows.push(measure(8, k, kind));
        }
        eprintln!(
            "2-round 8-bit F  syn={} and={} sem={} sem_and={}",
            f.seq.syn_nodes, f.seq.syn_and, f.seq.sem_nodes, f.seq.sem_and
        );
        for s in &rows {
            let r_syn = s.seq.syn_nodes as f64 / f.seq.syn_nodes as f64;
            let r_sem = s.seq.sem_nodes as f64 / f.seq.sem_nodes as f64;
            let r_and = s.seq.sem_and as f64 / f.seq.sem_and.max(1) as f64;
            eprintln!(
                "G_{:<3} seq syn={:<5} and={:<4} sem={:<5} sem_and={:<4}  dbl syn={:<5} sem={:<5}  syn/F={:.2} sem/F={:.2} and/F={:.2}",
                s.n,
                s.seq.syn_nodes,
                s.seq.syn_and,
                s.seq.sem_nodes,
                s.seq.sem_and,
                s.dbl.syn_nodes,
                s.dbl.sem_nodes,
                r_syn,
                r_sem,
                r_and
            );
        }
        // Sequential syntactic size tracks n. Semantic CSE is the question.
        let g16 = rows[4];
        assert!(g16.seq.syn_nodes + 20 >= 8 * f.seq.syn_nodes / 2);
        // If semantic sharing beat linear growth we'd have sem(G_16) << 16 sem(F).
        // Record the measured ratio; do not invent a collapse.
        let ratio = g16.seq.sem_nodes as f64 / f.seq.sem_nodes as f64;
        eprintln!("sem(G_16)/sem(F) = {ratio:.2}");
        assert!(ratio > 0.0);
    }

    #[test]
    fn bdd_of_g_versus_n() {
        let kind = Kind::Hmac { p: 0x41, rounds: 2 };
        let tf = map_table(|x| hmac_f(0x41, x, 2));
        let bf = bdd_size_u8(&tf);
        eprintln!("BDD(F) = {bf}");
        for k in 0..=5u32 {
            let n = 1u32 << k;
            let tg = g_table_u8(n, kind);
            let bg = bdd_size_u8(&tg);
            eprintln!("BDD(G_{n}) = {bg}");
        }
        // Affine: BDD stays tiny.
        let ta = g_table_u8(16, Kind::Affine);
        assert!(bdd_size_u8(&ta) < 40);
    }

    #[test]
    fn sha4_growth() {
        let f = measure_sha4(1, 2);
        eprintln!(
            "SHA4-2r F syn={} and={} sem={} sem_and={}",
            f.syn_nodes, f.syn_and, f.sem_nodes, f.sem_and
        );
        for n in [1u32, 2, 4, 8] {
            let s = measure_sha4(n, 2);
            eprintln!(
                "SHA4 G_{n} syn={} and={} sem={} sem_and={}  syn/F={:.2} sem/F={:.2}",
                s.syn_nodes,
                s.syn_and,
                s.sem_nodes,
                s.sem_and,
                s.syn_nodes as f64 / f.syn_nodes as f64,
                s.sem_nodes as f64 / f.sem_nodes.max(1) as f64
            );
        }
        let f4 = measure_sha4(1, 4);
        let g4 = measure_sha4(4, 4);
        eprintln!(
            "SHA4-4r F syn={} sem={}  G_4 syn={} sem={} sem/F={:.2}",
            f4.syn_nodes,
            f4.sem_nodes,
            g4.syn_nodes,
            g4.sem_nodes,
            g4.sem_nodes as f64 / f4.sem_nodes.max(1) as f64
        );
        assert!(f.syn_and > 0);
        let mut d = Dag::new();
        let x = word_in(&mut d, 16);
        let y = sha4_hmac_apply(&mut d, &x, 2);
        let (img, max_c) = map_image_cycle(&d, &y, 16);
        eprintln!("SHA4-2r image={img} max_cycle={max_c}");
    }

    #[test]
    fn hmac16_circuit_matches_scalar() {
        let mut d = Dag::new();
        let x = word_in(&mut d, 16);
        let y = hmac16_apply(&mut d, &x, 0x4141, 2);
        for v in (0..=65535u32).step_by(257) {
            assert_eq!(eval_word(&d, &y, v) as u16, hmac_f16(0x4141, v as u16, 2));
        }
        let (img, cyc) = map_image_cycle(&d, &y, 16);
        eprintln!("hmac16-2r image={img} max_cycle={cyc}");
        assert!(img > 1000, "need a mixing F, image {img}");
    }

    #[test]
    fn growth_curve_hmac16_two_round() {
        let p = 0x4141u16;
        let f = measure_hmac16(1, p, 2);
        eprintln!(
            "hmac16-2r F syn={} and={} sem={} sem_and={}",
            f.syn_nodes, f.syn_and, f.sem_nodes, f.sem_and
        );
        for n in [1u32, 2, 4, 8] {
            let s = measure_hmac16(n, p, 2);
            eprintln!(
                "hmac16 G_{n} syn={} and={} sem={} sem_and={}  syn/F={:.2} sem/F={:.2} and/F={:.2}",
                s.syn_nodes,
                s.syn_and,
                s.sem_nodes,
                s.sem_and,
                s.syn_nodes as f64 / f.syn_nodes as f64,
                s.sem_nodes as f64 / f.sem_nodes.max(1) as f64,
                s.sem_and as f64 / f.sem_and.max(1) as f64
            );
        }
        let g8 = measure_hmac16(8, p, 2);
        let ratio = g8.sem_nodes as f64 / f.sem_nodes.max(1) as f64;
        eprintln!("hmac16 sem(G_8)/sem(F) = {ratio:.2}");
        assert!(f.syn_and > 0);
        // Below the cycle length, semantic CSE tracks n. G_4 / F ≈ 4.
        let g4 = measure_hmac16(4, p, 2);
        let r4 = g4.sem_nodes as f64 / f.sem_nodes as f64;
        assert!((3.8..4.2).contains(&r4), "sem(G_4)/sem(F) = {r4}");

        let mut d3 = Dag::new();
        let x3 = word_in(&mut d3, 16);
        let y3 = hmac16_apply(&mut d3, &x3, p, 3);
        let (img3, cyc3) = map_image_cycle(&d3, &y3, 16);
        let f3 = measure_hmac16(1, p, 3);
        let g2 = measure_hmac16(2, p, 3);
        let g4b = measure_hmac16(4, p, 3);
        eprintln!(
            "hmac16-3r image={img3} max_cycle={cyc3} F sem={} G2 sem/F={:.2} G4 sem/F={:.2}",
            f3.sem_nodes,
            g2.sem_nodes as f64 / f3.sem_nodes as f64,
            g4b.sem_nodes as f64 / f3.sem_nodes as f64
        );
    }

    #[test]
    fn two_g_copies_share_only_constants() {
        // G_2(x) = F(x) ⊕ F(F(x)). After semantic merge, is this ~1×F or ~2×F?
        let s = measure(8, 1, Kind::Hmac { p: 0x41, rounds: 2 });
        let f = measure(8, 0, Kind::Hmac { p: 0x41, rounds: 2 });
        eprintln!(
            "G_2 vs F: syn {}/{} sem {}/{} and {}/{}",
            s.seq.syn_nodes,
            f.seq.syn_nodes,
            s.seq.sem_nodes,
            f.seq.sem_nodes,
            s.seq.sem_and,
            f.seq.sem_and
        );
        // Two nonlinear copies: semantic AND count should be about 2×.
        assert!(s.seq.sem_and + 2 >= f.seq.sem_and * 2);
    }
}
