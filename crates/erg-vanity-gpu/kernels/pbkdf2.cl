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

    uchar u_bytes[64];
    hmac_sha512(&ctx, salt_block, salt_len + 4u, u_bytes);

    // Pack U1 into ulong8 (NVIDIA treats as register pack, not addressable array)
    ulong8 u = (ulong8)(
        pack_be64(u_bytes[0],  u_bytes[1],  u_bytes[2],  u_bytes[3],
                  u_bytes[4],  u_bytes[5],  u_bytes[6],  u_bytes[7]),
        pack_be64(u_bytes[8],  u_bytes[9],  u_bytes[10], u_bytes[11],
                  u_bytes[12], u_bytes[13], u_bytes[14], u_bytes[15]),
        pack_be64(u_bytes[16], u_bytes[17], u_bytes[18], u_bytes[19],
                  u_bytes[20], u_bytes[21], u_bytes[22], u_bytes[23]),
        pack_be64(u_bytes[24], u_bytes[25], u_bytes[26], u_bytes[27],
                  u_bytes[28], u_bytes[29], u_bytes[30], u_bytes[31]),
        pack_be64(u_bytes[32], u_bytes[33], u_bytes[34], u_bytes[35],
                  u_bytes[36], u_bytes[37], u_bytes[38], u_bytes[39]),
        pack_be64(u_bytes[40], u_bytes[41], u_bytes[42], u_bytes[43],
                  u_bytes[44], u_bytes[45], u_bytes[46], u_bytes[47]),
        pack_be64(u_bytes[48], u_bytes[49], u_bytes[50], u_bytes[51],
                  u_bytes[52], u_bytes[53], u_bytes[54], u_bytes[55]),
        pack_be64(u_bytes[56], u_bytes[57], u_bytes[58], u_bytes[59],
                  u_bytes[60], u_bytes[61], u_bytes[62], u_bytes[63])
    );

    // Accumulator as ulong8 - no arrays in hot path
    ulong8 acc = u;

    // U2 ... U_iterations: use specialized 64-byte HMAC path with ulong8
    // Loop runs 2047 times for iterations=2048
    // No arrays, no pack/unpack - everything stays in registers
    for (uint iter = 1u; iter < iterations; iter++) {
        u = hmac_sha512_msg64_u8(&ctx, u);
        acc = acc ^ u;
    }

    // Unpack final accumulator to output
    unpack_be64(acc.s0, &out[0]);
    unpack_be64(acc.s1, &out[8]);
    unpack_be64(acc.s2, &out[16]);
    unpack_be64(acc.s3, &out[24]);
    unpack_be64(acc.s4, &out[32]);
    unpack_be64(acc.s5, &out[40]);
    unpack_be64(acc.s6, &out[48]);
    unpack_be64(acc.s7, &out[56]);
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
