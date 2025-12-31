// PBKDF2-HMAC-SHA512 library for OpenCL
//
// Expected to be concatenated after sha512.cl and hmac_sha512.cl.
// Used for BIP39 seed derivation (2048 iterations, 64-byte output).

// Max salt length (passphrase of 256 bytes should cover any sane use case)
#define PBKDF2_SALT_MAX 256u

// PBKDF2-HMAC-SHA512 for BIP39 seed derivation.
//
// password: the mnemonic string (already hashed to 64 bytes if > 128 bytes)
// password_len: length of password (max 128 for this implementation)
// salt: "mnemonic" + passphrase
// salt_len: length of salt (max PBKDF2_SALT_MAX)
// iterations: 2048 for BIP39 (must be >= 1)
// out: 64-byte output seed
//
// For BIP39, we only need block 1 (64 bytes), so this is simplified.
// Returns zeros if preconditions violated:
//   - password_len > 128 (caller must pre-hash long passwords)
//   - salt_len > PBKDF2_SALT_MAX
//   - iterations == 0
inline void pbkdf2_sha512(__private const uchar* password, uint password_len,
                          __private const uchar* salt, uint salt_len,
                          uint iterations,
                          __private uchar* out) {
    // Precondition checks
    if (password_len > 128u || salt_len > PBKDF2_SALT_MAX || iterations == 0u) {
        for (int i = 0; i < 64; i++) out[i] = 0u;
        return;
    }

    // Initialize HMAC context with password (key)
    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, password, password_len);

    // U1 = HMAC(password, salt || INT(1))
    // Build salt || block_num (block_num = 1 for first 64 bytes)
    uchar salt_block[PBKDF2_SALT_MAX + 4u];
    for (uint i = 0u; i < salt_len; i++) {
        salt_block[i] = salt[i];
    }
    // Append block number (big-endian, always 1 for 64-byte output)
    salt_block[salt_len] = 0u;
    salt_block[salt_len + 1u] = 0u;
    salt_block[salt_len + 2u] = 0u;
    salt_block[salt_len + 3u] = 1u;

    uchar u[64];
    hmac_sha512(&ctx, salt_block, salt_len + 4u, u);

    // result = U1
    for (int i = 0; i < 64; i++) {
        out[i] = u[i];
    }

    // U2 ... U_iterations, XOR into result
    for (uint iter = 1u; iter < iterations; iter++) {
        // U_i = HMAC(password, U_{i-1})
        hmac_sha512(&ctx, u, 64u, u);

        // result ^= U_i
        for (int i = 0; i < 64; i++) {
            out[i] ^= u[i];
        }
    }
}

// BIP39-specific wrapper: handles long mnemonics by pre-hashing.
//
// mnemonic: the mnemonic string (may exceed 128 bytes for 24-word)
// mnemonic_len: length of mnemonic
// salt: "mnemonic" + passphrase
// salt_len: length of salt (max PBKDF2_SALT_MAX)
// out: 64-byte output seed
inline void pbkdf2_bip39(__private const uchar* mnemonic, uint mnemonic_len,
                         __private const uchar* salt, uint salt_len,
                         __private uchar* out) {
    // If mnemonic > 128 bytes, hash it first per HMAC spec
    uchar key[128];
    uint key_len;

    if (mnemonic_len > 128u) {
        // Hash the long mnemonic with SHA-512 to get 64-byte key
        // Use streaming SHA-512 for arbitrary-length mnemonic
        Sha512State state;
        sha512_init(&state);

        uint full_blocks = mnemonic_len / 128u;
        uint remainder = mnemonic_len % 128u;

        for (uint b = 0u; b < full_blocks; b++) {
            sha512_compress(&state, mnemonic + b * 128u);
            state.total_len += 128ul;
        }

        sha512_final(&state, mnemonic + full_blocks * 128u, remainder, key);
        key_len = 64u;
    } else {
        // Use mnemonic directly as key
        for (uint i = 0u; i < mnemonic_len; i++) {
            key[i] = mnemonic[i];
        }
        key_len = mnemonic_len;
    }

    // Run PBKDF2 with 2048 iterations
    pbkdf2_sha512(key, key_len, salt, salt_len, 2048u, out);
}
