// bip32.cl - BIP32 hierarchical deterministic key derivation
//
// Requires: sha512.cl, hmac_sha512.cl, secp256k1_fe.cl, secp256k1_scalar.cl, secp256k1_point.cl
//
// Implements master key derivation and child derivation (hardened + normal).
// For Ergo path m/44'/429'/0'/0/0: 3 hardened + 2 normal derivations.

#define BIP32_HARDENED 0x80000000u

// Master key derivation from 64-byte BIP39 seed.
// Uses HMAC-SHA512("Bitcoin seed", seed).
// key_out: 32 bytes, chain_code_out: 32 bytes
// Returns 0 on success, 1 if key is invalid (>= n or zero)
inline int bip32_master_key(
    __private const uchar* seed,
    __private uchar* key_out,
    __private uchar* chain_code_out
) {
    // HMAC-SHA512("Bitcoin seed", seed)
    uchar hmac_key[12];
    hmac_key[0] = (uchar)'B';
    hmac_key[1] = (uchar)'i';
    hmac_key[2] = (uchar)'t';
    hmac_key[3] = (uchar)'c';
    hmac_key[4] = (uchar)'o';
    hmac_key[5] = (uchar)'i';
    hmac_key[6] = (uchar)'n';
    hmac_key[7] = (uchar)' ';
    hmac_key[8] = (uchar)'s';
    hmac_key[9] = (uchar)'e';
    hmac_key[10] = (uchar)'e';
    hmac_key[11] = (uchar)'d';

    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, hmac_key, 12u);

    uchar hmac_out[64];
    hmac_sha512(&ctx, seed, 64u, hmac_out);

    // IL = first 32 bytes (private key)
    // IR = last 32 bytes (chain code)
    for (int i = 0; i < 32; i++) {
        key_out[i] = hmac_out[i];
        chain_code_out[i] = hmac_out[32 + i];
    }

    // Validate key: must be < n and != 0
    uint key_limbs[8];
    sc_from_bytes(key_limbs, key_out);

    if (sc_is_zero(key_limbs) || sc_gte_n(key_limbs)) {
        return 1;
    }

    return 0;
}

// Hardened child derivation.
// Data = 0x00 || parent_key || index (37 bytes)
// Returns 0 on success, 1 if derived key is invalid
inline int bip32_derive_hardened(
    __private const uchar* parent_key,
    __private const uchar* parent_chain_code,
    uint index,
    __private uchar* child_key,
    __private uchar* child_chain_code
) {
    // Build data: 0x00 || key || index
    uchar data[37];
    data[0] = 0x00u;
    for (int i = 0; i < 32; i++) {
        data[1 + i] = parent_key[i];
    }
    data[33] = (uchar)(index >> 24);
    data[34] = (uchar)(index >> 16);
    data[35] = (uchar)(index >> 8);
    data[36] = (uchar)(index);

    // HMAC-SHA512(chain_code, data)
    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, parent_chain_code, 32u);

    uchar hmac_out[64];
    hmac_sha512(&ctx, data, 37u, hmac_out);

    // Parse IL as scalar
    uint il_limbs[8];
    sc_from_bytes(il_limbs, hmac_out);

    // Check IL is valid (< n and != 0)
    if (sc_is_zero(il_limbs) || sc_gte_n(il_limbs)) {
        return 1;
    }

    // Parse parent key as scalar
    uint parent_limbs[8];
    sc_from_bytes(parent_limbs, parent_key);

    // Child key = IL + parent_key (mod n)
    uint child_limbs[8];
    sc_add(child_limbs, il_limbs, parent_limbs);

    if (sc_is_zero(child_limbs)) {
        return 1;
    }

    // Convert child key to bytes
    sc_to_bytes(child_key, child_limbs);

    // Chain code = IR (last 32 bytes)
    for (int i = 0; i < 32; i++) {
        child_chain_code[i] = hmac_out[32 + i];
    }

    return 0;
}

// Normal (non-hardened) child derivation.
// Data = compressed_pubkey || index (37 bytes)
// Returns 0 on success, 1 if derived key is invalid
inline int bip32_derive_normal(
    __private const uchar* parent_key,
    __private const uchar* parent_chain_code,
    uint index,
    __private uchar* child_key,
    __private uchar* child_chain_code
) {
    // Compute public key from parent private key
    uint parent_limbs[8];
    sc_from_bytes(parent_limbs, parent_key);

    uint point[24];
    pt_mul_generator(point, parent_limbs);

    uchar pubkey[33];
    if (pt_to_compressed_pubkey(pubkey, point) != 0) {
        return 1;  // Point at infinity (shouldn't happen)
    }

    // Build data: pubkey || index
    uchar data[37];
    for (int i = 0; i < 33; i++) {
        data[i] = pubkey[i];
    }
    data[33] = (uchar)(index >> 24);
    data[34] = (uchar)(index >> 16);
    data[35] = (uchar)(index >> 8);
    data[36] = (uchar)(index);

    // HMAC-SHA512(chain_code, data)
    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, parent_chain_code, 32u);

    uchar hmac_out[64];
    hmac_sha512(&ctx, data, 37u, hmac_out);

    // Parse IL as scalar
    uint il_limbs[8];
    sc_from_bytes(il_limbs, hmac_out);

    if (sc_is_zero(il_limbs) || sc_gte_n(il_limbs)) {
        return 1;
    }

    // Child key = IL + parent_key (mod n)
    uint child_limbs[8];
    sc_add(child_limbs, il_limbs, parent_limbs);

    if (sc_is_zero(child_limbs)) {
        return 1;
    }

    sc_to_bytes(child_key, child_limbs);

    for (int i = 0; i < 32; i++) {
        child_chain_code[i] = hmac_out[32 + i];
    }

    return 0;
}

// Ergo derivation path: m/44'/429'/0'/0/0
// Derives final private key from BIP39 seed.
// Returns 0 on success, non-zero on error
inline int bip32_derive_ergo(
    __private const uchar* seed,
    __private uchar* final_key
) {
    uchar key[32], chain_code[32];
    uchar child_key[32], child_chain_code[32];

    // Master key
    if (bip32_master_key(seed, key, chain_code) != 0) {
        return 1;
    }

    // m/44' (hardened)
    if (bip32_derive_hardened(key, chain_code, BIP32_HARDENED | 44u,
                               child_key, child_chain_code) != 0) {
        return 2;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = child_key[i];
        chain_code[i] = child_chain_code[i];
    }

    // m/44'/429' (hardened)
    if (bip32_derive_hardened(key, chain_code, BIP32_HARDENED | 429u,
                               child_key, child_chain_code) != 0) {
        return 3;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = child_key[i];
        chain_code[i] = child_chain_code[i];
    }

    // m/44'/429'/0' (hardened)
    if (bip32_derive_hardened(key, chain_code, BIP32_HARDENED | 0u,
                               child_key, child_chain_code) != 0) {
        return 4;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = child_key[i];
        chain_code[i] = child_chain_code[i];
    }

    // m/44'/429'/0'/0 (normal)
    if (bip32_derive_normal(key, chain_code, 0u,
                             child_key, child_chain_code) != 0) {
        return 5;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = child_key[i];
        chain_code[i] = child_chain_code[i];
    }

    // m/44'/429'/0'/0/0 (normal)
    if (bip32_derive_normal(key, chain_code, 0u,
                             child_key, child_chain_code) != 0) {
        return 6;
    }

    // Output final key
    for (int i = 0; i < 32; i++) {
        final_key[i] = child_key[i];
    }

    return 0;
}
