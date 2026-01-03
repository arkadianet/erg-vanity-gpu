// HMAC-SHA512 library for OpenCL
//
// Expected to be concatenated after sha512.cl in the program source.
// Used by PBKDF2-HMAC-SHA512 for BIP39 seed derivation.

// HMAC-SHA512 block size
#define HMAC_BLOCK_SIZE 128u

// ipad/opad constants
#define IPAD ((uchar)0x36u)
#define OPAD ((uchar)0x5cu)

// HMAC-SHA512 context with precomputed padded keys
// For PBKDF2, we reuse the same key across 2048 iterations,
// so precomputing i_key_pad and o_key_pad is a big win.
typedef struct {
    uchar i_key_pad[128];  // key XOR ipad
    uchar o_key_pad[128];  // key XOR opad
} HmacSha512Ctx;

// HMAC-SHA512 midstate context for fast fixed-length messages.
// Stores SHA-512 state after compressing i_key_pad and o_key_pad.
typedef struct {
    ulong inner_midstate[8];
    ulong outer_midstate[8];
} HmacSha512MidstateCtx;

// Initialize HMAC context with key.
// If key_len > 128, caller must hash it first and pass the 64-byte hash.
// (BIP39 mnemonics can exceed 128 bytes, so the caller handles this.)
inline void hmac_sha512_init(__private HmacSha512Ctx* ctx,
                             const __private uchar* key, uint key_len) {
    // Zero-pad key to block size, then XOR with ipad/opad
    for (uint i = 0u; i < HMAC_BLOCK_SIZE; i++) {
        uchar k = (i < key_len) ? key[i] : 0u;
        ctx->i_key_pad[i] = k ^ IPAD;
        ctx->o_key_pad[i] = k ^ OPAD;
    }
}

// Initialize HMAC midstate context with key.
// Handles long keys by hashing them to 64 bytes per HMAC spec.
inline void hmac_sha512_midstate_init(__private HmacSha512MidstateCtx* ctx,
                                      const __private uchar* key, uint key_len) {
    uchar block[128];
    uchar hashed_key[64];
    const __private uchar* key_ptr = key;
    uint actual_key_len = key_len;

    if (key_len > 128u) {
        Sha512State hash_state;
        sha512_init(&hash_state);

        uint full_blocks = key_len / 128u;
        uint remainder = key_len % 128u;

        for (uint b = 0u; b < full_blocks; b++) {
            sha512_compress(&hash_state, key + b * 128u);
            hash_state.total_len += 128ul;
        }

        sha512_final(&hash_state, key + full_blocks * 128u, remainder, hashed_key);
        key_ptr = hashed_key;
        actual_key_len = 64u;
    }

    for (uint i = 0u; i < HMAC_BLOCK_SIZE; i++) {
        uchar k = (i < actual_key_len) ? key_ptr[i] : 0u;
        block[i] = k ^ IPAD;
    }

    Sha512State state;
    sha512_init(&state);
    sha512_compress(&state, block);
    for (int i = 0; i < 8; i++) {
        ctx->inner_midstate[i] = state.h[i];
    }

    for (int i = 0; i < 128; i++) {
        block[i] ^= 0x6au;
    }

    sha512_init(&state);
    sha512_compress(&state, block);
    for (int i = 0; i < 8; i++) {
        ctx->outer_midstate[i] = state.h[i];
    }
}

// HMAC-SHA512 for 12-byte message using midstate context.
inline void hmac_sha512_msg12(__private HmacSha512MidstateCtx* ctx,
                              const __private uchar* msg12,
                              __private uchar* out) {
    uchar block[128];

    block[0] = msg12[0];
    block[1] = msg12[1];
    block[2] = msg12[2];
    block[3] = msg12[3];
    block[4] = msg12[4];
    block[5] = msg12[5];
    block[6] = msg12[6];
    block[7] = msg12[7];
    block[8] = msg12[8];
    block[9] = msg12[9];
    block[10] = msg12[10];
    block[11] = msg12[11];
    block[12] = 0x80u;
    for (int i = 13; i < 120; i++) block[i] = 0u;
    block[120] = 0u;
    block[121] = 0u;
    block[122] = 0u;
    block[123] = 0u;
    block[124] = 0u;
    block[125] = 0u;
    block[126] = 0x04u;
    block[127] = 0x60u;

    Sha512State state;
    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->inner_midstate[i];
    }
    sha512_compress(&state, block);

    for (int i = 0; i < 8; i++) {
        unpack_be64(state.h[i], &block[i * 8]);
    }
    block[64] = 0x80u;
    for (int i = 65; i < 120; i++) block[i] = 0u;
    block[120] = 0u;
    block[121] = 0u;
    block[122] = 0u;
    block[123] = 0u;
    block[124] = 0u;
    block[125] = 0u;
    block[126] = 0x06u;
    block[127] = 0x00u;

    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->outer_midstate[i];
    }
    sha512_compress(&state, block);
    for (int i = 0; i < 8; i++) {
        unpack_be64(state.h[i], &out[i * 8]);
    }
}

// HMAC-SHA512 for 64-byte message using midstate context.
inline void hmac_sha512_msg64(__private HmacSha512MidstateCtx* ctx,
                              const __private uchar* msg64,
                              __private uchar* out) {
    uchar block[128];

    for (int i = 0; i < 64; i++) block[i] = msg64[i];
    block[64] = 0x80u;
    for (int i = 65; i < 120; i++) block[i] = 0u;
    block[120] = 0u;
    block[121] = 0u;
    block[122] = 0u;
    block[123] = 0u;
    block[124] = 0u;
    block[125] = 0u;
    block[126] = 0x06u;
    block[127] = 0x00u;

    Sha512State state;
    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->inner_midstate[i];
    }
    sha512_compress(&state, block);

    for (int i = 0; i < 8; i++) {
        unpack_be64(state.h[i], &block[i * 8]);
    }
    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->outer_midstate[i];
    }
    sha512_compress(&state, block);
    for (int i = 0; i < 8; i++) {
        unpack_be64(state.h[i], &out[i * 8]);
    }
}

// Compute HMAC-SHA512 using preinitialized context.
// HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
//
// Inner hash: streams i_key_pad (128 bytes) || data (arbitrary length)
// Outer hash: o_key_pad (128 bytes) || inner_hash (64 bytes) = 192 bytes
//
// No artificial length limit on data - bounded only by caller's private memory.
inline void hmac_sha512(__private HmacSha512Ctx* ctx,
                        const __private uchar* data, uint data_len,
                        __private uchar* out) {
    // Inner hash: H(i_key_pad || data)
    Sha512State state;
    sha512_init(&state);

    // Compress the i_key_pad block (always exactly 128 bytes)
    sha512_compress(&state, ctx->i_key_pad);
    state.total_len = 128ul;

    // Compress any full 128-byte blocks of data
    uint full_blocks = data_len / 128u;
    uint remainder = data_len % 128u;

    for (uint b = 0u; b < full_blocks; b++) {
        sha512_compress(&state, data + b * 128u);
        state.total_len += 128ul;
    }

    // Finalize with remainder
    uchar inner_hash[64];
    sha512_final(&state, data + full_blocks * 128u, remainder, inner_hash);

    // Outer hash: H(o_key_pad || inner_hash)
    // o_key_pad is 128 bytes, inner_hash is 64 bytes
    sha512_two_blocks(ctx->o_key_pad, inner_hash, 64u, out);
}

// Convenience: single-shot HMAC-SHA512 for keys <= 128 bytes
// For longer keys, caller must hash first.
inline void hmac_sha512_oneshot(const __private uchar* key, uint key_len,
                                const __private uchar* data, uint data_len,
                                __private uchar* out) {
    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, key, key_len);
    hmac_sha512(&ctx, data, data_len, out);
}
