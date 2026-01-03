// pbkdf2_test.cl - test kernel wrapper
//
// Expected to be concatenated after sha512.cl, hmac_sha512.cl, and pbkdf2.cl.

// Test kernel for PBKDF2-HMAC-SHA512
// Max password: 128 bytes, max salt: 256 bytes
__kernel void pbkdf2_test(
    __global const uchar* password,
    const uint password_len,
    __global const uchar* salt,
    const uint salt_len,
    const uint iterations,
    __global uchar* output   // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    // Reject inputs that exceed buffer sizes
    if (password_len > 128u || salt_len > 256u) {
        for (int i = 0; i < 64; i++) output[i] = 0u;
        return;
    }

    // Copy password to private memory
    uchar priv_password[128];
    for (uint i = 0u; i < password_len; i++) {
        priv_password[i] = password[i];
    }

    // Copy salt to private memory
    uchar priv_salt[256];
    for (uint i = 0u; i < salt_len; i++) {
        priv_salt[i] = salt[i];
    }

    // Compute PBKDF2
    uchar seed[64];
    pbkdf2_sha512(priv_password, password_len, priv_salt, salt_len, iterations, seed);

    for (int i = 0; i < 64; i++) {
        output[i] = seed[i];
    }
}

// Test kernel for BIP39-specific PBKDF2 (handles long mnemonics)
// Max mnemonic: 512 bytes, max salt: 256 bytes
__kernel void pbkdf2_bip39_test(
    __global const uchar* mnemonic,
    const uint mnemonic_len,
    __global const uchar* salt,
    const uint salt_len,
    __global uchar* output   // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    // Reject inputs that exceed buffer sizes
    if (mnemonic_len > 512u || salt_len > 256u) {
        for (int i = 0; i < 64; i++) output[i] = 0u;
        return;
    }

    // Copy mnemonic to private memory
    uchar priv_mnemonic[512];
    for (uint i = 0u; i < mnemonic_len; i++) {
        priv_mnemonic[i] = mnemonic[i];
    }

    // Copy salt to private memory
    uchar priv_salt[256];
    for (uint i = 0u; i < salt_len; i++) {
        priv_salt[i] = salt[i];
    }

    // Compute BIP39 PBKDF2
    uchar seed[64];
    pbkdf2_bip39(priv_mnemonic, mnemonic_len, priv_salt, salt_len, seed);

    for (int i = 0; i < 64; i++) {
        output[i] = seed[i];
    }
}

// Test kernel for vanity-optimized PBKDF2-HMAC-SHA512
// Max password: 512 bytes
__kernel void pbkdf2_vanity_test(
    __global const uchar* password,
    const uint password_len,
    __global uchar* output   // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    if (password_len > 512u) {
        for (int i = 0; i < 64; i++) output[i] = 0u;
        return;
    }

    uchar priv_password[512];
    for (uint i = 0u; i < password_len; i++) {
        priv_password[i] = password[i];
    }

    uchar seed[64];
    pbkdf2_sha512_vanity(priv_password, password_len, seed);

    for (int i = 0; i < 64; i++) {
        output[i] = seed[i];
    }
}
