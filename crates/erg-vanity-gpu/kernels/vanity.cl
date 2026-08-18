// vanity.cl - Main vanity address search kernel
//
// Full pipeline: entropy → BIP39 seed → BIP32 key → pubkey → Ergo address → pattern check
//
// Requires all other kernels concatenated before this:
//   sha256.cl, sha512.cl, hmac_sha512.cl, pbkdf2.cl,
//   secp256k1_fe.cl, secp256k1_scalar.cl, secp256k1_point.cl,
//   blake2b.cl, base58.cl, bip39.cl, bip32.cl

// Hit structure: stores entropy that produced a matching address
// Padded to 64 bytes for alignment and easy host-side mapping
// Uses uint[8] to match Rust's GpuHit layout (entropy as LE u32 words)
// MUST match Rust GpuHit struct exactly!
typedef struct {
    uint entropy_words[8];  // 32 bytes as LE u32 words
    uint work_item_id;      // 4 bytes
    uint address_index;     // 4 bytes: BIP44 index <i> in m/44'/429'/0'/0/<i>
    uint pattern_index;     // 4 bytes: which pattern matched
    uint _pad[5];           // 20 bytes padding (32 + 4 + 4 + 4 + 20 = 64 bytes)
} VanityHit;

// Generate entropy from work item ID, counter, and salt
// Uses Blake2b to properly mix all inputs into 32 bytes
inline void generate_entropy(
    uint gid,
    ulong counter_start,
    __global const uchar* salt,   // 32 bytes
    __private uchar* entropy      // 32 bytes out
) {
    ulong counter = counter_start + (ulong)gid;

    // msg = salt (32) || counter_le (8) = 40 bytes (must match CPU)
    uchar msg[40];

    for (int i = 0; i < 32; i++) msg[i] = salt[i];

    for (int i = 0; i < 8; i++) msg[32 + i] = (uchar)(counter >> (8 * i));

    blake2b_256(msg, 40u, entropy);
}

// Build Ergo P2PK address from compressed public key
// addr_bytes: 38 bytes output (1 prefix + 33 pubkey + 4 checksum)
inline void build_ergo_address(
    __private const uchar* pubkey,  // 33 bytes compressed
    __private uchar* addr_bytes     // 38 bytes output
) {
    // Mainnet P2PK prefix = 0x01
    addr_bytes[0] = 0x01u;

    // Copy pubkey
    for (int i = 0; i < 33; i++) {
        addr_bytes[1 + i] = pubkey[i];
    }

    // Compute checksum: first 4 bytes of Blake2b-256(prefix || pubkey)
    uchar checksum[4];
    ergo_checksum(addr_bytes, checksum);

    addr_bytes[34] = checksum[0];
    addr_bytes[35] = checksum[1];
    addr_bytes[36] = checksum[2];
    addr_bytes[37] = checksum[3];
}

// PBKDF2 is isolated so the 2048-iter HMAC loop is not compiled into the
// same entry as secp/BIP32 (those force 255 regs + stack spills on sm_86).
__kernel void vanity_seed(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* words8,
    __global const uchar* word_lens,
    __global uchar* seeds
) {
    uint gid = get_global_id(0);
    uchar entropy[32];
    generate_entropy(gid, counter_start, salt, entropy);
    uchar seed[64];
    bip39_entropy_to_seed(entropy, words8, word_lens, seed);
    __global uchar* out = seeds + ((ulong)gid * 64ul);
    for (int i = 0; i < 64; i++) out[i] = seed[i];
}

// BIP32 + k·G + address match. Seeds come from vanity_seed.
// First match wins by (address_index ascending, pattern list order).
__kernel void vanity_search(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* seeds,
    __global const char* patterns,
    __global const uint* pattern_offsets,
    __global const uint* pattern_lens,
    uint num_patterns,
    uint ignore_case,
    uint num_indices,
    __global VanityHit* hits,
    __global volatile int* hit_count,
    uint max_hits,
    __global const uint* comb
) {
    uint gid = get_global_id(0);

    uchar seed[64];
    __global const uchar* in = seeds + ((ulong)gid * 64ul);
    for (int i = 0; i < 64; i++) seed[i] = in[i];

    // Step 3: Derive to external chain m/44'/429'/0'/0 (done ONCE, amortizes cost)
    uchar external_key[32], external_chain_code[32];
    if (bip32_derive_ergo_external_chain_comb(seed, external_key, external_chain_code, comb) != 0) {
        // Invalid key (astronomically rare), skip this work item
        return;
    }

    // Parent pubkey is identical for every address index under this seed.
    uchar external_pub[33];
    if (priv_to_compressed_pubkey_comb(external_key, external_pub, comb) != 0) {
        return;
    }

    // Step 4-6: Loop over address indices (outer) and patterns (inner)
    // First match wins by (address_index ascending, pattern list order)
    for (uint addr_idx = 0; addr_idx < num_indices; addr_idx++) {
        // Derive key for this address index: m/44'/429'/0'/0/<addr_idx>
        uchar private_key[32];
        if (bip32_derive_address_index_from_pub(
                external_key, external_chain_code, external_pub, addr_idx, private_key
            ) != 0) {
            continue;  // Skip invalid (astronomically rare)
        }

        // Private key → public key
        uint key_limbs[8];
        sc_from_bytes(key_limbs, private_key);

        uint point[24];
        pt_mul_generator_comb(point, key_limbs, comb);

        uchar pubkey[33];
        if (pt_to_compressed_pubkey(pubkey, point) != 0) {
            continue;  // Point at infinity (shouldn't happen)
        }

        // Build Ergo address
        uchar addr_bytes[38];
        build_ergo_address(pubkey, addr_bytes);

        // Check each pattern (inner loop)
        for (uint p = 0; p < num_patterns; p++) {
            uint offset = pattern_offsets[p];
            int len = (int)pattern_lens[p];

            int match;
            if (ignore_case) {
                match = base58_check_prefix_global_icase(addr_bytes, &patterns[offset], len);
            } else {
                match = base58_check_prefix_global(addr_bytes, &patterns[offset], len);
            }

            if (match) {
                // Match found! Recompute entropy (cheap vs PBKDF2) for CPU verify.
                uchar entropy[32];
                generate_entropy(gid, counter_start, salt, entropy);
                uint hit_idx = (uint)atomic_inc(hit_count);
                if (hit_idx < max_hits) {
                    for (int w = 0; w < 8; w++) {
                        int o = w * 4;
                        uint x =
                            ((uint)entropy[o + 0]) |
                            ((uint)entropy[o + 1] << 8) |
                            ((uint)entropy[o + 2] << 16) |
                            ((uint)entropy[o + 3] << 24);
                        hits[hit_idx].entropy_words[w] = x;
                    }
                    hits[hit_idx].work_item_id = gid;
                    hits[hit_idx].address_index = addr_idx;
                    hits[hit_idx].pattern_index = p;
                }
                // First match wins - exit both loops
                return;
            }
        }
    }
}

// Simplified kernel for testing: derives address from given entropy
// (No pattern matching, outputs intermediate values for verification)
__kernel void vanity_derive_address(
    __global const uchar* entropy_in,     // 32 bytes input entropy
    __global const uchar* words8,
    __global const uchar* word_lens,
    __global uchar* seed_out,             // 64 bytes
    __global uchar* private_key_out,      // 32 bytes
    __global uchar* pubkey_out,           // 33 bytes
    __global uchar* addr_bytes_out,       // 38 bytes
    __global int* error_out,              // Error code (0 = success)
    __global const uint* comb
) {
    if (get_global_id(0) != 0u) return;

    // Copy entropy to private memory
    uchar entropy[32];
    for (int i = 0; i < 32; i++) {
        entropy[i] = entropy_in[i];
    }

    // BIP39: entropy → seed
    uchar seed[64];
    bip39_entropy_to_seed(entropy, words8, word_lens, seed);
    for (int i = 0; i < 64; i++) {
        seed_out[i] = seed[i];
    }

    // BIP32: seed → private key (same comb k·G as vanity_search)
    uchar external_key[32], external_chain_code[32];
    int err = bip32_derive_ergo_external_chain_comb(
        seed, external_key, external_chain_code, comb
    );
    uchar private_key[32];
    if (err == 0) {
        uchar external_pub[33];
        if (priv_to_compressed_pubkey_comb(external_key, external_pub, comb) != 0) {
            err = 5;
        } else {
            err = bip32_derive_address_index_from_pub(
                external_key, external_chain_code, external_pub, 0u, private_key
            );
            if (err != 0) err = 6;
        }
    }
    *error_out = err;
    if (err != 0) return;

    for (int i = 0; i < 32; i++) {
        private_key_out[i] = private_key[i];
    }

    // Private key → public key
    uint key_limbs[8];
    sc_from_bytes(key_limbs, private_key);

    uint point[24];
    pt_mul_generator_comb(point, key_limbs, comb);

    uchar pubkey[33];
    if (pt_to_compressed_pubkey(pubkey, point) != 0) {
        *error_out = 100;
        return;
    }

    for (int i = 0; i < 33; i++) {
        pubkey_out[i] = pubkey[i];
    }

    // Build address
    uchar addr_bytes[38];
    build_ergo_address(pubkey, addr_bytes);

    for (int i = 0; i < 38; i++) {
        addr_bytes_out[i] = addr_bytes[i];
    }
}
