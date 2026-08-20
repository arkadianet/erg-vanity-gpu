//! Batch complexity of many BIP39 PBKDF2-HMAC-SHA512 instances.
//!
//! Question: is Work(N) < N · Work(1) by a material amount?
//! Research only. Does not change the production derive path.

use crate::pbkdf2_fast::Hmac64Key;
use crate::sha512_hmac64::{compress16, hmac64, pack_be16};

/// HMAC-64 compressions in the BIP39 loop after U1 (2047 × 2).
pub const LOOP_COMPRESSIONS: u32 = 4094;
/// Setup + U1: ipad, opad, U1 inner, U1 outer.
pub const SETUP_COMPRESSIONS: u32 = 4;
pub const COMPRESSIONS_PER_SEED: u32 = SETUP_COMPRESSIONS + LOOP_COMPRESSIONS;

/// Word-parallel SHF / IADD model already established for one HMAC-64 compress.
pub const SHF_PER_COMPRESS: u32 = 1550;
pub const IADD_PER_COMPRESS: u32 = 80 * 7 * 2;

/// Bitslice ripple: 64 full-adders × 3 bitops, packed 32 instances per register.
pub const BITSLICE_ADD_BITOPS_32: u32 = 80 * 7 * 64 * 3;
/// Per-instance equivalent after packing 32 instance-bits per register.
pub const BITSLICE_ADD_BITOPS_PER_INST: u32 = BITSLICE_ADD_BITOPS_32 / 32;

/// Kogge-Stone work per 64-bit add (generate/propagate + 6 prefix levels).
pub const KOGGE_STONE_OPS_PER_ADD: u32 = 64 * 2 + 6 * 64 * 2;
pub const KOGGE_STONE_ADD_OPS_PER_COMPRESS: u32 = 80 * 7 * KOGGE_STONE_OPS_PER_ADD;

/// Warp SHFL to transpose 64×32 bits (6 log stages × 32-bit halves × 8 words).
pub const TRANSPOSE_SHFL_PER_STATE: u32 = 6 * 2 * 8;
/// Hybrid: transpose to bitslice for Σ, back for add, every round.
pub const HYBRID_TRANSPOSE_SHFL_PER_COMPRESS: u32 = 80 * 2 * TRANSPOSE_SHFL_PER_STATE;

#[derive(Clone, Copy, Debug)]
pub struct SharedWork {
    /// Shared compress-equivalents / (N × compressions per seed).
    pub ratio: f64,
    pub u1_inner_w_shared: bool,
    pub prefix_rounds: u32,
}

/// Shared work that does not grow with N, as a fraction of N seeds.
///
/// Only nodes that depend solely on (salt, K, IV, padding) can be computed
/// once. Everything that depends on password i is private.
pub fn shared_fraction_unrelated(n: u32) -> SharedWork {
    // U1 inner schedule + K[t]+W[t] for that one block ≈ 1/4 of a compression.
    let shared = 0.25;
    let total = f64::from(n) * f64::from(COMPRESSIONS_PER_SEED);
    SharedWork {
        ratio: shared / total,
        u1_inner_w_shared: true,
        prefix_rounds: 0,
    }
}

/// Last-word family: share the first `prefix_rounds` of ipad and of opad.
pub fn shared_fraction_last_word_family(n: u32, prefix_rounds: u32) -> SharedWork {
    let shared = 0.25 + 2.0 * f64::from(prefix_rounds) / 80.0;
    let total = f64::from(n) * f64::from(COMPRESSIONS_PER_SEED);
    SharedWork {
        ratio: shared / total,
        u1_inner_w_shared: true,
        prefix_rounds,
    }
}

fn key_block(password: &[u8]) -> [u8; 128] {
    let mut block = [0u8; 128];
    if password.len() > 128 {
        let d = crate::sha512::digest(password);
        block[..64].copy_from_slice(&d);
    } else {
        block[..password.len()].copy_from_slice(password);
    }
    block
}

/// First 128-byte key-block word (0..15) that differs, or 16 if identical.
pub fn first_diff_key_word(a: &[u8], b: &[u8]) -> u32 {
    let wa = pack_be16(&key_block(a));
    let wb = pack_be16(&key_block(b));
    for i in 0..16 {
        if wa[i] != wb[i] {
            return i as u32;
        }
    }
    16
}

/// ipad/opad rounds that share W (rounds 0..k-1).
pub fn shared_setup_rounds(a: &[u8], b: &[u8]) -> u32 {
    first_diff_key_word(a, b)
}

/// U1 inner padded block depends only on salt||counter, not the password.
pub fn u1_inner_block(salt: &[u8], block_num: u32) -> [u64; 16] {
    let mut raw = [0u8; 128];
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&block_num.to_be_bytes());
    let n = msg.len().min(111);
    raw[..n].copy_from_slice(&msg[..n]);
    raw[n] = 0x80;
    let bit_len = ((128 + msg.len()) as u128) * 8;
    raw[112..].copy_from_slice(&bit_len.to_be_bytes());
    pack_be16(&raw)
}

pub fn hamming8(a: [u64; 8], b: [u64; 8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// After `iters` HMAC-64 steps, how many state words collide (should be ~0).
pub fn loop_word_collisions(
    ka: &Hmac64Key,
    kb: &Hmac64Key,
    start_a: [u64; 8],
    start_b: [u64; 8],
    iters: u32,
) -> u32 {
    let mut a = start_a;
    let mut b = start_b;
    let mut hits = 0u32;
    for _ in 0..iters {
        a = hmac64(ka.inner, ka.outer, a);
        b = hmac64(kb.inner, kb.outer, b);
        for i in 0..8 {
            if a[i] == b[i] {
                hits += 1;
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512_hmac64::hmac_from_mid;

    const MN12_A: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MN12_B: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon legal";
    const SALT: &[u8] = b"mnemonic";

    #[test]
    fn work_models_bitslice_and_prefix_lose_to_iadd() {
        assert_eq!(BITSLICE_ADD_BITOPS_PER_INST, 3360);
        assert_eq!(IADD_PER_COMPRESS, 1120);
        assert!(BITSLICE_ADD_BITOPS_PER_INST > IADD_PER_COMPRESS * 2);
        assert!(KOGGE_STONE_ADD_OPS_PER_COMPRESS > BITSLICE_ADD_BITOPS_32);
        assert!(HYBRID_TRANSPOSE_SHFL_PER_COMPRESS > SHF_PER_COMPRESS * 5);
        // Hardware IADD is already a silicon prefix adder. Rebuilding it in
        // LOP3, even packed across a batch, is more work per instance.
    }

    #[test]
    fn unrelated_shared_fraction_vanishes() {
        let f1 = shared_fraction_unrelated(1);
        let f1k = shared_fraction_unrelated(1024);
        // One quarter-compress of U1-inner schedule vs 4098 compressions.
        assert!(f1.ratio < 0.001);
        assert!(f1k.ratio < 1e-6);
        assert!(f1.u1_inner_w_shared);
    }

    #[test]
    fn last_word_family_still_under_a_percent() {
        // Typical 12-word: last word starts in key word 8..10 → ~9 shared rounds.
        let prefix = shared_setup_rounds(MN12_A, MN12_B);
        assert!(prefix >= 8 && prefix <= 11, "prefix rounds {prefix}");
        // 128 valid checksum last-words for a 12-word prefix (4-bit checksum).
        let f = shared_fraction_last_word_family(128, prefix);
        // < 0.1% of the batch.
        assert!(f.ratio < 0.001);
    }

    #[test]
    fn u1_inner_w_depends_only_on_salt() {
        let w = u1_inner_block(SALT, 1);
        let ka = Hmac64Key::new(MN12_A);
        let kb = Hmac64Key::new(MN12_B);
        // Same salt block fed to different midstates.
        let ia = compress16(ka.inner, w);
        let ib = compress16(kb.inner, w);
        assert_ne!(ia, ib);
        assert!(hamming8(ia, ib) > 180);
        // Two different passphrases would change w; empty/"TREZOR" differ.
        let w2 = u1_inner_block(b"mnemonicTREZOR", 1);
        assert_ne!(w, w2);
        // Same salt, any password: identical U1 inner schedule.
        assert_eq!(u1_inner_block(SALT, 1), w);
    }

    #[test]
    fn u1_inner_matches_production_path() {
        let key = Hmac64Key::new(MN12_A);
        let via_block = {
            let inner = compress16(key.inner, u1_inner_block(SALT, 1));
            crate::sha512_hmac64::compress_hmac64(key.outer, inner)
        };
        let mut m = SALT.to_vec();
        m.extend_from_slice(&1u32.to_be_bytes());
        let via_prod = hmac_from_mid(key.inner, key.outer, &m);
        let u1 = crate::pbkdf2_fast::derive_block(&key, SALT, 1, 1);
        assert_eq!(via_prod, u1);
        assert_eq!(via_block, u1);
    }

    #[test]
    fn loop_intermediates_do_not_coincide() {
        let ka = Hmac64Key::new(MN12_A);
        let kb = Hmac64Key::new(MN12_B);
        let u1a = crate::pbkdf2_fast::derive_block(&ka, SALT, 1, 1);
        let u1b = crate::pbkdf2_fast::derive_block(&kb, SALT, 1, 1);
        // Related last word: I/O already avalanched.
        assert!(hamming8(ka.inner, kb.inner) > 180);
        assert!(hamming8(ka.outer, kb.outer) > 180);
        assert!(hamming8(u1a, u1b) > 180);
        let hits = loop_word_collisions(&ka, &kb, u1a, u1b, 8);
        assert_eq!(hits, 0);

        // Unrelated random-looking passwords.
        let kc = Hmac64Key::new(
            b"legal winner thank year wave sausage worth useful legal winner thank yellow",
        );
        let u1c = crate::pbkdf2_fast::derive_block(&kc, SALT, 1, 1);
        assert_eq!(loop_word_collisions(&ka, &kc, u1a, u1c, 8), 0);
    }

    #[test]
    fn twelve_word_fits_one_key_block_twenty_four_does_not() {
        assert!(MN12_A.len() <= 128);
        let w24 = [b"abandon ".as_slice(); 23].concat();
        let mut s24 = w24;
        s24.extend_from_slice(b"about");
        assert!(s24.len() > 128);
        // 24-word related keys share SHA-512(P) only in the first 128-byte
        // password block, then I/O diverge. Still setup-only.
        assert_eq!(first_diff_key_word(MN12_A, MN12_A), 16);
    }

    #[test]
    fn salt_partial_eval_is_setup_only() {
        // Fixed "mnemonic"||passphrase ⇒ one U1-inner W for the whole batch.
        // That is already in shared_fraction_unrelated. The 4094-loop messages
        // are HMAC outputs, not the salt.
        let f = shared_fraction_unrelated(10_000);
        assert!(f.u1_inner_w_shared);
        assert!(f.ratio < 1e-7);
    }

    #[test]
    fn disjoint_inputs_mean_disjoint_data_nodes() {
        // Circuit size lower bound: N copies of the private DAG plus O(1) shared
        // constants. If two random keys produced equal I, the private DAGs would
        // merge; avalanche says they do not.
        let mut prev = Hmac64Key::new(b"seed-0").inner;
        for i in 1..32u32 {
            let k = Hmac64Key::new(format!("seed-{i}").as_bytes());
            assert!(hamming8(prev, k.inner) > 160);
            prev = k.inner;
        }
    }
}
