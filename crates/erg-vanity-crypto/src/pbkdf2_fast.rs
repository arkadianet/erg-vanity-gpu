//! PBKDF2-HMAC-SHA512 expressed as NMAC over a specialized HMAC-64 compressor.
//!
//! Layering PBKDF2 → HMAC → SHA-512 is dropped. After one ipad/opad compress
//! per password, the iteration is:
//!   U ← Compress_O(pad64(Compress_I(pad64(U))))
//!   T ← T ⊕ U
//! where Compress_* is [`crate::sha512_hmac64::compress_hmac64`].

use crate::sha512::{self, H_INIT};
use crate::sha512_hmac64::{
    compress16, compress_hmac64_generic, hmac64, hmac64_x2, hmac_from_mid, pack_be16, unpack_be8,
};

const IPAD: u64 = 0x3636_3636_3636_3636;
const OPAD: u64 = 0x5c5c_5c5c_5c5c_5c5c;
const HLEN: usize = 64;

/// Cached ipad/opad SHA-512 midstates for one password.
#[derive(Clone, Copy)]
pub struct Hmac64Key {
    pub inner: [u64; 8],
    pub outer: [u64; 8],
}

impl Hmac64Key {
    pub fn new(password: &[u8]) -> Self {
        let mut block = [0u8; 128];
        if password.len() > 128 {
            block[..64].copy_from_slice(&sha512::digest(password));
        } else {
            block[..password.len()].copy_from_slice(password);
        }
        let words = pack_be16(&block);
        let mut ipad = [0u64; 16];
        let mut opad = [0u64; 16];
        for i in 0..16 {
            ipad[i] = words[i] ^ IPAD;
            opad[i] = words[i] ^ OPAD;
        }
        Self {
            inner: compress16(H_INIT, ipad),
            outer: compress16(H_INIT, opad),
        }
    }
}

fn xor8(a: [u64; 8], b: [u64; 8]) -> [u64; 8] {
    [
        a[0] ^ b[0],
        a[1] ^ b[1],
        a[2] ^ b[2],
        a[3] ^ b[3],
        a[4] ^ b[4],
        a[5] ^ b[5],
        a[6] ^ b[6],
        a[7] ^ b[7],
    ]
}

fn block_u1(key: &Hmac64Key, salt: &[u8], block_num: u32) -> [u64; 8] {
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&block_num.to_be_bytes());
    hmac_from_mid(key.inner, key.outer, &msg)
}

/// One PBKDF2 block using the specialized HMAC-64 compressor.
pub fn derive_block(key: &Hmac64Key, salt: &[u8], iterations: u32, block_num: u32) -> [u64; 8] {
    debug_assert!(iterations >= 1);
    let mut u = block_u1(key, salt, block_num);
    let mut acc = u;
    for _ in 1..iterations {
        u = hmac64(key.inner, key.outer, u);
        acc = xor8(acc, u);
    }
    acc
}

/// Same as [`derive_block`] but the loop uses the unspecialized 64-byte compressor.
pub fn derive_block_generic(
    key: &Hmac64Key,
    salt: &[u8],
    iterations: u32,
    block_num: u32,
) -> [u64; 8] {
    debug_assert!(iterations >= 1);
    let mut u = block_u1(key, salt, block_num);
    let mut acc = u;
    for _ in 1..iterations {
        u = compress_hmac64_generic(key.outer, compress_hmac64_generic(key.inner, u));
        acc = xor8(acc, u);
    }
    acc
}

/// RFC 8018 PBKDF2-HMAC-SHA512 (specialized inner loop).
pub fn derive(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    assert!(iterations >= 1, "PBKDF2 iterations must be >= 1");
    let key = Hmac64Key::new(password);
    let num_blocks = output.len().div_ceil(HLEN);
    for block_idx in 0..num_blocks {
        let words = derive_block(&key, salt, iterations, (block_idx + 1) as u32);
        let bytes = unpack_be8(words);
        let start = block_idx * HLEN;
        let end = (start + HLEN).min(output.len());
        output[start..end].copy_from_slice(&bytes[..end - start]);
    }
}

/// Two independent derivations with interleaved HMAC-64 compressions.
pub fn derive_pair(
    password_a: &[u8],
    salt_a: &[u8],
    password_b: &[u8],
    salt_b: &[u8],
    iterations: u32,
    out_a: &mut [u8; 64],
    out_b: &mut [u8; 64],
) {
    assert!(iterations >= 1, "PBKDF2 iterations must be >= 1");
    let key_a = Hmac64Key::new(password_a);
    let key_b = Hmac64Key::new(password_b);
    let mut ua = block_u1(&key_a, salt_a, 1);
    let mut ub = block_u1(&key_b, salt_b, 1);
    let mut acc_a = ua;
    let mut acc_b = ub;
    for _ in 1..iterations {
        let pair = hmac64_x2(
            [key_a.inner, key_b.inner],
            [key_a.outer, key_b.outer],
            [ua, ub],
        );
        ua = pair[0];
        ub = pair[1];
        acc_a = xor8(acc_a, ua);
        acc_b = xor8(acc_b, ub);
    }
    *out_a = unpack_be8(acc_a);
    *out_b = unpack_be8(acc_b);
}

/// BIP39: salt `"mnemonic"`, 2048 iterations, 64-byte output.
pub fn derive_bip39(mnemonic: &[u8], passphrase: &[u8]) -> [u8; 64] {
    let mut salt = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase);
    let mut out = [0u8; 64];
    derive(mnemonic, &salt, 2048, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pbkdf2 as layered;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn bip39_vectors() {
        let mnemonic = b"abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";
        assert_eq!(
            to_hex(&derive_bip39(mnemonic, b"")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
        assert_eq!(
            to_hex(&derive_bip39(mnemonic, b"TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn matches_layered_and_crate() {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let cases: &[(&[u8], &[u8], u32, usize)] = &[
            (b"password", b"salt", 1, 64),
            (b"password", b"salt", 2, 64),
            (b"password", b"salt", 64, 32),
            (b"", b"salt", 3, 64),
            (b"password", b"", 3, 64),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                8,
                100,
            ),
            (&[0u8; 200], b"mnemonic", 4, 64),
        ];
        for &(pw, salt, iters, out_len) in cases {
            let mut fast = vec![0u8; out_len];
            let mut reference = vec![0u8; out_len];
            let mut crate_out = vec![0u8; out_len];
            derive(pw, salt, iters, &mut fast);
            layered::derive_reference(pw, salt, iters, &mut reference);
            pbkdf2_hmac::<Sha512>(pw, salt, iters, &mut crate_out);
            assert_eq!(fast, reference, "layered mismatch");
            assert_eq!(fast, crate_out, "crate mismatch");
        }
    }

    #[test]
    fn randomized_against_crate() {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let mut rng = 0xC0FFEE_u64;
        let next = |rng: &mut u64| {
            *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            *rng
        };

        for i in 0..250 {
            let pw_len = (next(&mut rng) as usize) % 180;
            let salt_len = (next(&mut rng) as usize) % 140;
            let iters = match i % 7 {
                0 => 1,
                1 => 2,
                2 => 3,
                3 => 8,
                4 => 16,
                5 => 64,
                _ => 128,
            };
            let out_len = [16, 32, 64, 65, 80, 128][i % 6];

            let mut pw = vec![0u8; pw_len];
            let mut salt = vec![0u8; salt_len];
            for b in pw.iter_mut().chain(salt.iter_mut()) {
                *b = (next(&mut rng) >> 24) as u8;
            }

            let mut fast = vec![0u8; out_len];
            let mut crate_out = vec![0u8; out_len];
            derive(&pw, &salt, iters, &mut fast);
            pbkdf2_hmac::<Sha512>(&pw, &salt, iters, &mut crate_out);
            assert_eq!(
                fast, crate_out,
                "mismatch i={i} pw_len={pw_len} salt_len={salt_len} iters={iters} out={out_len}"
            );
        }
    }

    #[test]
    fn generic_loop_matches_specialized() {
        let key = Hmac64Key::new(b"mnemonic words here");
        let a = derive_block(&key, b"mnemonic", 32, 1);
        let b = derive_block_generic(&key, b"mnemonic", 32, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn pair_matches_singles() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        derive_pair(
            b"alpha",
            b"mnemonic",
            b"bravo",
            b"mnemonicX",
            16,
            &mut a,
            &mut b,
        );
        let mut a2 = [0u8; 64];
        let mut b2 = [0u8; 64];
        derive(b"alpha", b"mnemonic", 16, &mut a2);
        derive(b"bravo", b"mnemonicX", 16, &mut b2);
        assert_eq!(a, a2);
        assert_eq!(b, b2);
    }

    #[test]
    fn bip39_2048_against_crate() {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let mnemonic =
            b"legal winner thank year wave sausage worth useful legal winner thank yellow";
        let salt = b"mnemonic";
        let fast = derive_bip39(mnemonic, b"");
        let mut crate_out = [0u8; 64];
        pbkdf2_hmac::<Sha512>(mnemonic, salt, 2048, &mut crate_out);
        assert_eq!(fast, crate_out);
    }

    fn nsec_per_seed<F: FnMut()>(iters: u32, seeds: u32, mut body: F) -> f64 {
        let start = std::time::Instant::now();
        for _ in 0..seeds {
            body();
        }
        start.elapsed().as_secs_f64() * 1e9 / f64::from(seeds * iters.max(1)) * f64::from(iters)
    }

    /// Run with `ERG_PBKDF2_BENCH=1 cargo test -p erg-vanity-crypto bench_candidates --release -- --nocapture`.
    #[test]
    fn bench_candidates() {
        if std::env::var("ERG_PBKDF2_BENCH").ok().as_deref() != Some("1") {
            return;
        }

        let pw = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let salt = b"mnemonic";
        let key = Hmac64Key::new(pw);
        let seeds = 8u32;
        let iters = 2048u32;

        // Warmup
        let _ = derive_block(&key, salt, 32, 1);
        let _ = derive_block_generic(&key, salt, 32, 1);
        let mut discard = [0u8; 64];
        layered::derive_reference(pw, salt, 8, &mut discard);

        let spec = nsec_per_seed(iters, seeds, || {
            std::hint::black_box(derive_block(&key, salt, iters, 1));
        });
        let generic = nsec_per_seed(iters, seeds, || {
            std::hint::black_box(derive_block_generic(&key, salt, iters, 1));
        });
        let layered_ns = nsec_per_seed(iters, 2, || {
            let mut out = [0u8; 64];
            layered::derive_reference(pw, salt, iters, &mut out);
            std::hint::black_box(out);
        });
        let pair = nsec_per_seed(iters, seeds / 2, || {
            let mut a = [0u8; 64];
            let mut b = [0u8; 64];
            derive_pair(pw, salt, pw, b"mnemonicX", iters, &mut a, &mut b);
            std::hint::black_box((a, b));
        }) / 2.0;

        eprintln!("PBKDF2-HMAC-SHA512 2048-iter, 64-byte DK (CPU)");
        eprintln!("  specialized HMAC-64:     {spec:.0} ns/seed");
        eprintln!("  generic HMAC-64 midstate:{generic:.0} ns/seed");
        eprintln!("  layered HMAC+alloc:      {layered_ns:.0} ns/seed");
        eprintln!("  interleaved pair /2:     {pair:.0} ns/seed");
        eprintln!("  spec vs generic: {:+.2}%", (spec / generic - 1.0) * 100.0);
        eprintln!("  pair vs spec:    {:+.2}%", (pair / spec - 1.0) * 100.0);
    }
}
