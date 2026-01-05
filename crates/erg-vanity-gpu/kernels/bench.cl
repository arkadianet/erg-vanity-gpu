// bench.cl - Benchmark kernels for timing individual pipeline stages
//
// Requires all production kernels concatenated before this:
//   sha256.cl, sha512.cl, hmac_sha512.cl, pbkdf2.cl,
//   secp256k1_fe.cl, secp256k1_scalar.cl, secp256k1_point.cl,
//   blake2b.cl, base58.cl, bip39.cl, bip32.cl
//
// Each kernel uses exact production codepaths to measure realistic timing.

// Generate entropy from work item ID, counter, and salt
// Uses Blake2b to properly mix all inputs into 32 bytes
// COPIED VERBATIM from vanity.cl to ensure identical behavior
inline void bench_generate_entropy(
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

// Generate a deterministic 64-byte seed from (salt, counter_start, gid)
// Used by BIP32/secp/base58 benches to skip PBKDF2 overhead
inline void bench_generate_seed(
    uint gid,
    ulong counter_start,
    __global const uchar* salt,
    __private uchar* seed
) {
    // Hash twice to get 64 bytes deterministically
    uchar entropy[32];
    bench_generate_entropy(gid, counter_start, salt, entropy);
    blake2b_256(entropy, 32u, seed);        // First 32 bytes
    entropy[0] ^= 0xFFu;  // Perturb
    blake2b_256(entropy, 32u, seed + 32);   // Last 32 bytes
}

//=============================================================================
// Kernel 1: PBKDF2 (BIP39 seed derivation) - dominant cost
//
// Uses EXACT production codepath: bip39_entropy_to_seed which calls:
//   - mnemonic_to_password (SHA-256 checksum, word lookup, streaming)
//   - pbkdf2_sha512 with 2048 iterations and "mnemonic" salt
//=============================================================================
__kernel void bench_pbkdf2(
    __global const uchar* salt,           // 32 bytes entropy generation salt
    ulong counter_start,
    __global const uchar* words8,         // BIP39 wordlist (2048 * 8 bytes)
    __global const uchar* word_lens,      // Word lengths (2048 bytes)
    uint num_indices,                     // Unused for PBKDF2, but kept for uniformity
    __global uint* checksums
) {
    uint gid = get_global_id(0);

    // Generate entropy (same as production)
    uchar entropy[32];
    bench_generate_entropy(gid, counter_start, salt, entropy);

    // EXACT production call: entropy -> mnemonic -> PBKDF2 -> seed
    // This is the same function called in vanity_search
    uchar seed[64];
    bip39_entropy_to_seed(entropy, words8, word_lens, seed);

    // Fold result to prevent optimization
    uint checksum = 0;
    for (int i = 0; i < 64; i++) {
        checksum ^= ((uint)seed[i]) << ((i & 3) * 8);
    }
    checksums[gid] = checksum;
}

//=============================================================================
// Kernel 2: BIP32 derivation (m/44'/429'/0'/0 + num_indices address derivations)
//
// Uses EXACT production codepath:
//   - bip32_derive_ergo_external_chain (master + 4 child derivations)
//   - bip32_derive_address_index (1 normal derivation per index)
//=============================================================================
__kernel void bench_bip32(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* words8,         // Unused, kept for uniform signature
    __global const uchar* word_lens,      // Unused
    uint num_indices,
    __global uint* checksums
) {
    uint gid = get_global_id(0);

    // Generate deterministic 64-byte seed (skip PBKDF2 for this benchmark)
    uchar seed[64];
    bench_generate_seed(gid, counter_start, salt, seed);

    // EXACT production: derive external chain m/44'/429'/0'/0
    uchar external_key[32], external_chain_code[32];
    if (bip32_derive_ergo_external_chain(seed, external_key, external_chain_code) != 0) {
        checksums[gid] = 0xDEAD0001u;
        return;
    }

    // EXACT production: derive each address index (same loop as vanity_search)
    uint checksum = 0;
    for (uint addr_idx = 0; addr_idx < num_indices; addr_idx++) {
        uchar private_key[32];
        if (bip32_derive_address_index(external_key, external_chain_code,
                                        addr_idx, private_key) != 0) {
            continue;
        }
        for (int j = 0; j < 32; j++) checksum ^= private_key[j];
    }
    checksums[gid] = checksum;
}

//=============================================================================
// Kernel 3: secp256k1 pubkey derivation
//
// Uses EXACT production codepath:
//   - sc_from_bytes (parse private key as scalar)
//   - pt_mul_generator (scalar multiplication with generator)
//   - pt_to_compressed_pubkey (33-byte compressed format)
//=============================================================================
__kernel void bench_secp256k1(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* words8,
    __global const uchar* word_lens,
    uint num_indices,
    __global uint* checksums
) {
    uint gid = get_global_id(0);

    // Generate base private key deterministically
    uchar base_privkey[32];
    bench_generate_entropy(gid, counter_start, salt, base_privkey);

    uint checksum = 0;
    for (uint addr_idx = 0; addr_idx < num_indices; addr_idx++) {
        // Derive unique private key for each index (simulate BIP32 output)
        uchar privkey[32];
        for (int i = 0; i < 32; i++) privkey[i] = base_privkey[i];
        privkey[0] ^= (uchar)addr_idx;
        privkey[1] ^= (uchar)(addr_idx >> 8);

        // EXACT production: private key -> public key
        uint key_limbs[8];
        sc_from_bytes(key_limbs, privkey);

        uint point[24];
        pt_mul_generator(point, key_limbs);

        uchar pubkey[33];
        if (pt_to_compressed_pubkey(pubkey, point) != 0) {
            continue;
        }

        for (int j = 0; j < 33; j++) checksum ^= pubkey[j];
    }
    checksums[gid] = checksum;
}

//=============================================================================
// Kernel 4: Base58 encoding + Blake2b checksum
//
// Uses EXACT production codepath:
//   - ergo_checksum (Blake2b-256 of prefix+pubkey, first 4 bytes) from blake2b.cl
//   - base58_encode_address (full 38-byte -> ~51 char Base58 encoding) from base58.cl
//
// Note: Production uses base58_check_prefix_global for pattern matching,
// which internally does Base58 encoding. We directly call base58_encode_address
// here to measure the full encoding cost.
//=============================================================================
__kernel void bench_base58(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* words8,
    __global const uchar* word_lens,
    uint num_indices,
    __global uint* checksums
) {
    uint gid = get_global_id(0);

    // Generate base pubkey deterministically
    uchar base_pubkey[33];
    bench_generate_entropy(gid, counter_start, salt, base_pubkey);
    base_pubkey[32] = (uchar)(gid ^ 0xA5u);  // deterministic last byte (entropy only fills 32)
    base_pubkey[0] = 0x02u;  // Valid compressed pubkey prefix

    uint checksum = 0;
    for (uint addr_idx = 0; addr_idx < num_indices; addr_idx++) {
        // Create unique pubkey for each index
        uchar pubkey[33];
        for (int i = 0; i < 33; i++) pubkey[i] = base_pubkey[i];
        pubkey[1] ^= (uchar)addr_idx;

        // Build Ergo address bytes (same as production build_ergo_address)
        uchar addr_bytes[38];
        addr_bytes[0] = 0x01u;  // Mainnet P2PK prefix
        for (int i = 0; i < 33; i++) addr_bytes[1 + i] = pubkey[i];

        // EXACT production: Blake2b checksum (from blake2b.cl)
        uchar cs[4];
        ergo_checksum(addr_bytes, cs);
        addr_bytes[34] = cs[0];
        addr_bytes[35] = cs[1];
        addr_bytes[36] = cs[2];
        addr_bytes[37] = cs[3];

        // EXACT production: Full Base58 encoding (38 bytes -> ~51 chars)
        char b58_out[60];  // Enough for 38 bytes -> ~51 chars + margin
        int b58_len = base58_encode_address(addr_bytes, b58_out);

        // Fold encoded result to prevent optimization
        for (int j = 0; j < b58_len; j++) checksum ^= (uchar)b58_out[j];
    }
    checksums[gid] = checksum;
}
