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
typedef struct {
    uint entropy_words[8];  // 32 bytes as LE u32 words
    uint work_item_id;
    uint _pad[7];  // 32 + 4 + 28 = 64 bytes
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

    // msg = salt (32) || counter_le (8) || gid_le (4) = 44 bytes
    uchar msg[44];

    for (int i = 0; i < 32; i++) msg[i] = salt[i];

    // little-endian counter
    for (int i = 0; i < 8; i++) msg[32 + i] = (uchar)(counter >> (8 * i));

    // little-endian gid
    msg[40] = (uchar)(gid);
    msg[41] = (uchar)(gid >> 8);
    msg[42] = (uchar)(gid >> 16);
    msg[43] = (uchar)(gid >> 24);

    // Fill all 32 bytes of entropy deterministically
    blake2b_256(msg, 44u, entropy);
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

// Main vanity search kernel
__kernel void vanity_search(
    // Entropy generation
    __global const uchar* salt,           // 32 bytes
    ulong counter_start,                  // Starting counter value
    // Wordlist (for BIP39)
    __global const uchar* words8,         // 2048 * 8 bytes
    __global const uchar* word_lens,      // 2048 bytes
    // Pattern matching
    __global const char* pattern,         // Null-terminated prefix to match
    uint pattern_len,                     // Length of pattern
    // Output
    __global VanityHit* hits,             // Hit buffer
    __global volatile int* hit_count,     // Atomic counter
    uint max_hits                         // Max hits to store
) {
    uint gid = get_global_id(0);

    // Step 1: Generate entropy
    uchar entropy[32];
    generate_entropy(gid, counter_start, salt, entropy);

    // Step 2: Entropy → BIP39 seed (PBKDF2 - dominant cost)
    uchar seed[64];
    bip39_entropy_to_seed(entropy, words8, word_lens, seed);

    // Step 3: BIP32 derivation → final private key
    uchar private_key[32];
    int bip32_err = bip32_derive_ergo(seed, private_key);
    if (bip32_err != 0) {
        // Invalid key (astronomically rare), skip this work item
        return;
    }

    // Step 4: Private key → public key
    uint key_limbs[8];
    sc_from_bytes(key_limbs, private_key);

    uint point[24];
    pt_mul_generator(point, key_limbs);

    uchar pubkey[33];
    if (pt_to_compressed_pubkey(pubkey, point) != 0) {
        // Point at infinity (shouldn't happen with valid key)
        return;
    }

    // Step 5: Build Ergo address
    uchar addr_bytes[38];
    build_ergo_address(pubkey, addr_bytes);

    // Step 6: Check if address matches pattern
    if (base58_check_prefix_global(addr_bytes, pattern, (int)pattern_len)) {
        // Match found! Store hit with entropy packed as LE u32 words
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
    __global int* error_out               // Error code (0 = success)
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

    // BIP32: seed → private key
    uchar private_key[32];
    int err = bip32_derive_ergo(seed, private_key);
    *error_out = err;
    if (err != 0) return;

    for (int i = 0; i < 32; i++) {
        private_key_out[i] = private_key[i];
    }

    // Private key → public key
    uint key_limbs[8];
    sc_from_bytes(key_limbs, private_key);

    uint point[24];
    pt_mul_generator(point, key_limbs);

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
