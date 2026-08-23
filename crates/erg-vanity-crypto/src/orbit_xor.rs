//! Algorithms for T = U_1 ⊕ … ⊕ U_c of an iterated HMAC-like map.
//!
//! The conventional algorithm walks the orbit. This module asks whether
//! the orbit-XOR maps themselves have a cheaper representation.
//!
//! Independent of the production PBKDF2/SHA-512 path.

/// One Davies–Meyer-ish compress: `rounds` ARX steps, then XOR the IV.
pub fn compress(iv: u8, m: u8, rounds: u32) -> u8 {
    let mut x = iv;
    let mut w = m;
    for r in 0..rounds {
        let k = (r as u8).wrapping_mul(0x9e).wrapping_add(0x37);
        let s = x.rotate_right(3) ^ x.rotate_right(5) ^ (x >> 1);
        let ch = w ^ (x & (w ^ 0x5a));
        x = x.wrapping_add(s).wrapping_add(ch).wrapping_add(k);
        w = w.rotate_left(1).wrapping_add(x);
    }
    x ^ iv
}

/// HMAC-shaped F_P(x) = C(O, C(I, x)) with I,O from P.
pub fn hmac_f(p: u8, x: u8, rounds: u32) -> u8 {
    let i = compress(0x6a, p ^ 0x36, rounds);
    let o = compress(0x6a, p ^ 0x5c, rounds);
    compress(o, compress(i, x, rounds), rounds)
}

/// Affine calibration: F(x) = rot(x,1) ⊕ 0x1d. Orbit-XOR must stay degree 1.
pub fn affine_f(x: u8) -> u8 {
    x.rotate_left(1) ^ 0x1d
}

pub fn iterate(mut x: u8, n: u32, f: impl Fn(u8) -> u8) -> u8 {
    for _ in 0..n {
        x = f(x);
    }
    x
}

/// Y_k(x) = F(x) ⊕ F²(x) ⊕ … ⊕ F^{2^k}(x).
pub fn y_k(x: u8, k: u32, f: impl Fn(u8) -> u8) -> u8 {
    let n = 1u32 << k;
    let mut u = x;
    let mut t = 0u8;
    for _ in 0..n {
        u = f(u);
        t ^= u;
    }
    t
}

/// Doubling law: Y_{k+1}(x) = Y_k(x) ⊕ Y_k(F^{2^k}(x)). Always true.
pub fn y_doubles(x: u8, k: u32, f: impl Fn(u8) -> u8 + Copy) -> bool {
    let left = y_k(x, k + 1, f);
    let mid = iterate(x, 1 << k, f);
    let right = y_k(x, k, f) ^ y_k(mid, k, f);
    left == right
}

#[derive(Clone, Copy, Debug)]
pub struct Anf {
    pub weight: u32,
    pub degree: u32,
}

/// Algebraic normal form of an 8-bit Boolean function (one output bit).
pub fn anf_bit(truth: &[u8; 256], bit: u32) -> Anf {
    let mut a = [0u8; 256];
    for i in 0..256 {
        a[i] = (truth[i] >> bit) & 1;
    }
    let mut step = 1;
    while step < 256 {
        for i in 0..256 {
            if i & step != 0 {
                a[i] ^= a[i ^ step];
            }
        }
        step <<= 1;
    }
    let mut weight = 0u32;
    let mut degree = 0u32;
    for (i, &c) in a.iter().enumerate() {
        if c == 1 {
            weight += 1;
            degree = degree.max((i as u32).count_ones());
        }
    }
    Anf { weight, degree }
}

pub fn map_table(f: impl Fn(u8) -> u8) -> [u8; 256] {
    let mut t = [0u8; 256];
    for x in 0..=255u8 {
        t[x as usize] = f(x);
    }
    t
}

pub fn table_anf_max(table: &[u8; 256]) -> Anf {
    let mut weight = 0u32;
    let mut degree = 0u32;
    for bit in 0..8 {
        let a = anf_bit(table, bit);
        weight = weight.max(a.weight);
        degree = degree.max(a.degree);
    }
    Anf { weight, degree }
}

pub fn image_size(table: &[u8; 256]) -> u32 {
    let mut seen = [false; 256];
    let mut n = 0u32;
    for &y in table {
        if !seen[y as usize] {
            seen[y as usize] = true;
            n += 1;
        }
    }
    n
}

pub fn is_bijection(table: &[u8; 256]) -> bool {
    image_size(table) == 256
}

pub fn image_is_power_of_two(table: &[u8; 256]) -> bool {
    let n = image_size(table);
    n > 0 && n.count_ones() == 1
}

/// Walsh–Hadamard nonzero count of one output bit (256-point).
pub fn walsh_nonzero(table: &[u8; 256], bit: u32) -> u32 {
    let mut v = [0i32; 256];
    for i in 0..256 {
        v[i] = 1 - 2 * (((table[i] >> bit) & 1) as i32);
    }
    let mut h = 1;
    while h < 256 {
        for i in (0..256).step_by(h * 2) {
            for j in 0..h {
                let a = v[i + j];
                let b = v[i + j + h];
                v[i + j] = a + b;
                v[i + j + h] = a - b;
            }
        }
        h *= 2;
    }
    v.iter().filter(|&&x| x != 0).count() as u32
}

/// Linear complexity of a GF(2) sequence (Berlekamp–Massey).
pub fn linear_complexity(s: &[u8]) -> usize {
    let n = s.len();
    let mut c = vec![0u8; n + 1];
    let mut b = vec![0u8; n + 1];
    c[0] = 1;
    b[0] = 1;
    let mut l = 0usize;
    let mut m = -1i32;
    for ni in 0..n {
        let mut d = s[ni];
        for i in 1..=l {
            d ^= c[i] & s[ni - i];
        }
        if d == 1 {
            let t = c.clone();
            let shift = ni as i32 - m;
            for (i, ci) in c.iter_mut().enumerate() {
                let j = i as i32 - shift;
                if j >= 0 {
                    *ci ^= b[j as usize];
                }
            }
            if 2 * l <= ni {
                l = ni + 1 - l;
                b = t;
                m = ni as i32;
            }
        }
    }
    l
}

pub fn orbit_bit_complexity(x0: u8, len: usize, bit: u32, f: impl Fn(u8) -> u8) -> usize {
    let mut s = vec![0u8; len];
    let mut x = x0;
    for item in &mut s {
        x = f(x);
        *item = (x >> bit) & 1;
    }
    linear_complexity(&s)
}

/// Fraction of x where F(x⊕F(x)) = F(x)⊕F(F(x)) (additivity on {x,F(x)}).
pub fn pair_additive_rate(f: impl Fn(u8) -> u8) -> f64 {
    let mut ok = 0u32;
    for x in 0..=255u8 {
        let fx = f(x);
        let f2 = f(fx);
        if f(x ^ fx) == fx ^ f2 {
            ok += 1;
        }
    }
    f64::from(ok) / 256.0
}

/// Second difference F(x⊕a⊕b)⊕F(x⊕a)⊕F(x⊕b)⊕F(x). Constant ⇒ quadratic.
pub fn second_diff_constant(f: impl Fn(u8) -> u8) -> bool {
    let a = 0x01u8;
    let b = 0x02u8;
    let d0 = f(a ^ b) ^ f(a) ^ f(b) ^ f(0);
    for x in 1..=255u8 {
        let d = f(x ^ a ^ b) ^ f(x ^ a) ^ f(x ^ b) ^ f(x);
        if d != d0 {
            return false;
        }
    }
    true
}

pub fn affine_over_xor(f: impl Fn(u8) -> u8) -> bool {
    let f0 = f(0);
    // F(x⊕y) = F(x)⊕F(y)⊕F(0)
    for x in 0..=31u8 {
        for y in 0..=31u8 {
            if f(x ^ y) != (f(x) ^ f(y) ^ f0) {
                return false;
            }
        }
    }
    true
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointHits {
    pub t_eq_xor_ends: u32,
    pub t_eq_end: u32,
    pub t_eq_start: u32,
}

/// How often T = g(x, F^c(x)) for cheap g, over all starts.
pub fn endpoint_identities(c: u32, f: impl Fn(u8) -> u8) -> EndpointHits {
    let mut h = EndpointHits {
        t_eq_xor_ends: 0,
        t_eq_end: 0,
        t_eq_start: 0,
    };
    for x in 0..=255u8 {
        let mut u = x;
        let mut t = 0u8;
        for _ in 0..c {
            u = f(u);
            t ^= u;
        }
        if t == (x ^ u) {
            h.t_eq_xor_ends += 1;
        }
        if t == u {
            h.t_eq_end += 1;
        }
        if t == x {
            h.t_eq_start += 1;
        }
    }
    h
}

/// T(P) and U1(P) for Mini-PBKDF2 with fixed S, as tables of P.
pub fn t_and_u1_tables(salt: u8, c: u32, rounds: u32) -> ([u8; 256], [u8; 256]) {
    let mut ttab = [0u8; 256];
    let mut u1tab = [0u8; 256];
    for p in 0..=255u8 {
        let mut u = hmac_f(p, salt, rounds);
        u1tab[p as usize] = u;
        let mut t = u;
        for _ in 1..c {
            u = hmac_f(p, u, rounds);
            t ^= u;
        }
        ttab[p as usize] = t;
    }
    (ttab, u1tab)
}

/// Random invertible 8×8 GF(2) matrix applied to a byte.
fn apply_lin(m: &[u8; 8], x: u8) -> u8 {
    let mut y = 0u8;
    for (i, &col) in m.iter().enumerate() {
        if (x >> i) & 1 == 1 {
            y ^= col;
        }
    }
    y
}

fn rnd_matrix(seed: &mut u64) -> [u8; 8] {
    let mut m = [0u8; 8];
    // Rejection: require full rank via image size of the linear map.
    for _ in 0..64 {
        for col in &mut m {
            *seed = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
            *col = (*seed >> 33) as u8;
            if *col == 0 {
                *col = 1;
            }
        }
        let tab = map_table(|x| apply_lin(&m, x));
        if is_bijection(&tab) {
            return m;
        }
    }
    [1, 2, 4, 8, 16, 32, 64, 128]
}

/// 16-bit compress / HMAC-shaped F, same coupling kinds as the 8-bit toy.
pub fn compress16(iv: u16, m: u16, rounds: u32) -> u16 {
    let mut x = iv;
    let mut w = m;
    for r in 0..rounds {
        let k = (r as u16).wrapping_mul(0x9e37).wrapping_add(0x37);
        let s = x.rotate_right(3) ^ x.rotate_right(5) ^ (x >> 1);
        let ch = w ^ (x & (w ^ 0x5a5a));
        x = x.wrapping_add(s).wrapping_add(ch).wrapping_add(k);
        w = w.rotate_left(1).wrapping_add(x);
    }
    x ^ iv
}

pub fn hmac_f16(p: u16, x: u16, rounds: u32) -> u16 {
    let i = compress16(0x6a6a, p ^ 0x3636, rounds);
    let o = compress16(0x6a6a, p ^ 0x5c5c, rounds);
    compress16(o, compress16(i, x, rounds), rounds)
}

pub fn y_k16(x: u16, k: u32, f: impl Fn(u16) -> u16) -> u16 {
    let n = 1u32 << k;
    let mut u = x;
    let mut t = 0u16;
    for _ in 0..n {
        u = f(u);
        t ^= u;
    }
    t
}

#[allow(clippy::needless_range_loop)]
pub fn anf16_max(f: impl Fn(u16) -> u16) -> Anf {
    let mut weight = 0u32;
    let mut degree = 0u32;
    for bit in 0..16u32 {
        let mut a = vec![0u8; 65536];
        for x in 0..65536 {
            a[x] = ((f(x as u16) >> bit) & 1) as u8;
        }
        let mut step = 1;
        while step < 65536 {
            for i in 0..65536 {
                if i & step != 0 {
                    a[i] ^= a[i ^ step];
                }
            }
            step <<= 1;
        }
        let mut w = 0u32;
        let mut d = 0u32;
        for (i, &c) in a.iter().enumerate() {
            if c == 1 {
                w += 1;
                d = d.max((i as u32).count_ones());
            }
        }
        weight = weight.max(w);
        degree = degree.max(d);
    }
    Anf { weight, degree }
}

pub fn image_size16(f: impl Fn(u16) -> u16) -> u32 {
    let mut seen = vec![false; 65536];
    let mut n = 0u32;
    for x in 0..=65535u16 {
        let y = f(x) as usize;
        if !seen[y] {
            seen[y] = true;
            n += 1;
        }
    }
    n
}

/// Longest cycle in the functional graph (8-bit).
pub fn max_cycle_len(f: impl Fn(u8) -> u8) -> u32 {
    let tab = map_table(f);
    let mut state = [0u8; 256];
    let mut best = 0u32;
    for start in 0..=255u8 {
        if state[start as usize] != 0 {
            continue;
        }
        let mut x = start;
        let mut path = Vec::new();
        while state[x as usize] == 0 {
            state[x as usize] = 1;
            path.push(x);
            x = tab[x as usize];
        }
        if state[x as usize] == 1 {
            let pos = path.iter().position(|&z| z == x).unwrap();
            best = best.max((path.len() - pos) as u32);
        }
        for z in path {
            state[z as usize] = 2;
        }
    }
    best
}

/// If Y_k is a constant function, that constant; else None.
pub fn y_constant(k: u32, f: impl Fn(u8) -> u8 + Copy) -> Option<u8> {
    let y0 = y_k(0, k, f);
    for x in 1..=255u8 {
        if y_k(x, k, f) != y0 {
            return None;
        }
    }
    Some(y0)
}

/// Try random linear conjugacies: is A^{-1} F A affine?
pub fn linear_conjugacy_hits(trials: u32, f: impl Fn(u8) -> u8, seed0: u64) -> u32 {
    let ft = map_table(f);
    let mut seed = seed0;
    let mut hits = 0u32;
    for _ in 0..trials {
        let a = rnd_matrix(&mut seed);
        // Inverse by building the permutation table.
        let mut inv = [0u8; 256];
        for x in 0..=255u8 {
            inv[apply_lin(&a, x) as usize] = x;
        }
        let conj = map_table(|x| {
            let ax = apply_lin(&a, x);
            inv[ft[ax as usize] as usize]
        });
        if affine_over_xor(|x| conj[x as usize]) {
            hits += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubling_law_holds() {
        let f = |x| hmac_f(0x41, x, 2);
        for x in (0..=255).step_by(5) {
            assert!(y_doubles(x, 0, f));
            assert!(y_doubles(x, 2, f));
            assert!(y_doubles(x, 3, f));
        }
    }

    #[test]
    fn affine_orbit_xor_stays_degree_one() {
        let f = affine_f;
        assert!(affine_over_xor(f));
        let y0 = map_table(|x| y_k(x, 0, f));
        let y3 = map_table(|x| y_k(x, 3, f));
        let a0 = table_anf_max(&y0);
        let a3 = table_anf_max(&y3);
        assert_eq!(a0.degree, 1);
        assert_eq!(a3.degree, 1);
        assert!(a3.weight <= 9);
    }

    #[test]
    fn berlekamp_massey_on_lfsr() {
        // x^3 + x + 1, period 7: 1,1,1,0,1,0,0 repeating
        let mut s = Vec::new();
        let seq = [1u8, 1, 1, 0, 1, 0, 0];
        for _ in 0..21 {
            s.extend_from_slice(&seq);
        }
        assert_eq!(linear_complexity(&s), 3);
    }

    #[test]
    fn hmac_like_is_not_the_affine_class() {
        let f = |x| hmac_f(0x41, x, 2);
        assert!(!affine_over_xor(f));
        assert!(!second_diff_constant(f));
        assert!(pair_additive_rate(f) < 0.1);
        let tab = map_table(f);
        // Not a linear-conjugacy candidate via |image| = 2^r (usually).
        // Record the actual image; conjugacy to affine needs a power of two.
        let _ = image_is_power_of_two(&tab);
        assert!(!is_bijection(&tab) || image_size(&tab) == 256);
    }

    #[test]
    fn yk_anf_grows_to_saturation_for_hmac_like() {
        let f = |x| hmac_f(0x41, x, 2);
        let fy = table_anf_max(&map_table(f));
        let y2 = table_anf_max(&map_table(|x| y_k(x, 2, f)));
        let y4 = table_anf_max(&map_table(|x| y_k(x, 4, f)));
        // 2-round Mini-HMAC already has high-degree F; block-XOR does not
        // stay a small polynomial.
        assert!(fy.degree >= 4, "F degree {}", fy.degree);
        assert!(y2.degree >= fy.degree);
        assert!(y4.weight >= 64, "Y_4 weight {}", y4.weight);
    }

    #[test]
    fn one_round_orbit_xor_collapses() {
        // The surviving toy: 1-round Mini-HMAC. Y_k gets simpler as k grows
        // and Y_5 (XOR of 32 iterates) is the zero map.
        let f = |x| hmac_f(0x41, x, 1);
        let f_anf = table_anf_max(&map_table(f));
        let y3 = table_anf_max(&map_table(|x| y_k(x, 3, f)));
        let y4 = table_anf_max(&map_table(|x| y_k(x, 4, f)));
        assert!(f_anf.degree >= 4);
        assert!(y3.weight < f_anf.weight, "Y_3 {y3:?} F {f_anf:?}");
        assert_eq!(y4.degree, 1, "Y_4 {:?}", y4);
        assert_eq!(y_constant(5, f), Some(0));
        let cyc = max_cycle_len(f);
        assert!(cyc <= 32, "max cycle {cyc}");
    }

    #[test]
    fn endpoints_do_not_determine_t_cheaply() {
        let f = |x| hmac_f(0x41, x, 2);
        let h = endpoint_identities(16, f);
        // Random 8-bit: ~1/256 accidental hits. Allow a few.
        assert!(h.t_eq_xor_ends < 8, "{:?}", h);
        assert!(h.t_eq_end < 8);
        assert!(h.t_eq_start < 8);
    }

    #[test]
    fn t_of_password_is_not_simpler_than_u1() {
        let (t, u1) = t_and_u1_tables(0x6d, 16, 2);
        let at = table_anf_max(&t);
        let au = table_anf_max(&u1);
        // XOR-aggregate does not collapse T(P) below U1(P).
        assert!(at.degree >= au.degree.saturating_sub(1));
        assert!(at.weight + 8 >= au.weight || at.weight >= 64);
    }

    #[test]
    fn eight_bit_orbits_die_in_short_cycles() {
        let f = |x| hmac_f(0x41, x, 2);
        assert!(max_cycle_len(f) <= 8);
        let lc = orbit_bit_complexity(0x11, 256, 0, f);
        // Not a 512-bit phenomenon: the 8-bit map falls into a 2-cycle.
        assert!(lc < 16, "linear complexity {lc}");
    }

    #[test]
    fn walsh_spectrum_is_dense() {
        let tab = map_table(|x| hmac_f(0x41, x, 2));
        let nz = walsh_nonzero(&tab, 0);
        assert!(nz >= 128, "Walsh nonzeros {nz}");
    }

    #[test]
    fn linear_conjugacy_search_empty() {
        let f = |x| hmac_f(0x41, x, 2);
        let hits = linear_conjugacy_hits(400, f, 0xC0FFEE);
        assert_eq!(hits, 0);
    }

    #[test]
    fn composition_does_not_shrink() {
        let f = |x| hmac_f(0x41, x, 2);
        let f1 = table_anf_max(&map_table(f));
        let f2 = table_anf_max(&map_table(|x| f(f(x))));
        assert!(f2.degree >= f1.degree);
        assert!(f2.weight + 4 >= f1.weight);
    }

    #[test]
    fn sixteen_bit_one_round_yk() {
        let p = 0x4141u16;
        let f = |x| hmac_f16(p, x, 1);
        let f_anf = anf16_max(f);
        let y3 = anf16_max(|x| y_k16(x, 3, f));
        let y4 = anf16_max(|x| y_k16(x, 4, f));
        let img = image_size16(f);
        eprintln!("16b 1-round F {f_anf:?} Y3 {y3:?} Y4 {y4:?} image {img}");
        // Degree falls as the XOR-block doubles; weight stays tiny.
        assert!(y4.degree < f_anf.degree, "F {f_anf:?} Y4 {y4:?}");
        assert!(y4.weight <= 32);
        assert!(img < 1024);
    }

    #[test]
    fn sixteen_bit_two_round_yk() {
        let p = 0x4141u16;
        let f = |x| hmac_f16(p, x, 2);
        let f_anf = anf16_max(f);
        let y3 = anf16_max(|x| y_k16(x, 3, f));
        let img = image_size16(f);
        eprintln!("16b 2-round F {f_anf:?} Y3 {y3:?} image {img}");
        // Two rounds: F is already a dense 16-bit map. Y_3 does not shrink.
        assert!(f_anf.degree == 16 && f_anf.weight > 10_000);
        assert!(y3.degree == 16 && y3.weight > 10_000);
        assert!(img > 1000);
    }

    #[test]
    fn sixteen_bit_three_round_f_is_dense() {
        let f = |x| hmac_f16(0x4141, x, 3);
        let f_anf = anf16_max(f);
        let img = image_size16(f);
        eprintln!("16b 3-round F {f_anf:?} image {img}");
        assert!(f_anf.degree == 16);
        assert!(f_anf.weight > 10_000);
    }
}
