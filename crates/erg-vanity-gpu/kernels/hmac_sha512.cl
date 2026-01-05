// HMAC-SHA512 library for OpenCL
//
// Expected to be concatenated after sha512.cl in the program source.
// Used by PBKDF2-HMAC-SHA512 for BIP39 seed derivation.

// HMAC-SHA512 block size
#define HMAC_BLOCK_SIZE 128u

// ipad/opad constants
#define IPAD ((uchar)0x36u)
#define OPAD ((uchar)0x5cu)

// HMAC-SHA512 context with cached SHA-512 midstates.
// For PBKDF2, we reuse the same key across 2048 iterations.
// Caching the SHA-512 state after compressing ipad/opad blocks
// eliminates 2 redundant compressions per HMAC call.
typedef struct {
    ulong inner_h[8];       // SHA-512 state after compressing ipad
    ulong inner_total_len;  // Cached total_len (128 after ipad compress)
    ulong outer_h[8];       // SHA-512 state after compressing opad
    ulong outer_total_len;  // Cached total_len (128 after opad compress)
} HmacSha512Ctx;

// Initialize HMAC context with key.
// If key_len > 128, caller must hash it first and pass the 64-byte hash.
// (BIP39 mnemonics can exceed 128 bytes, so the caller handles this.)
inline void hmac_sha512_init(__private HmacSha512Ctx* ctx,
                             const __private uchar* key, uint key_len) {
    // Single pad buffer to reduce register pressure on NVIDIA
    uchar pad[128];
    Sha512State st;

    // Build ipad: zero-pad key to block size, XOR with 0x36
    for (uint i = 0u; i < HMAC_BLOCK_SIZE; i++) {
        uchar k = (i < key_len) ? key[i] : 0u;
        pad[i] = k ^ IPAD;
    }

    // Compress ipad and cache the resulting state
    sha512_init(&st);
    sha512_compress(&st, pad);
    st.total_len = 128ul;
    for (int i = 0; i < 8; i++) {
        ctx->inner_h[i] = st.h[i];
    }
    ctx->inner_total_len = st.total_len;

    // Transform ipad to opad in-place: (k ^ 0x36) ^ 0x6a = k ^ 0x5c
    for (uint i = 0u; i < HMAC_BLOCK_SIZE; i++) {
        pad[i] ^= (IPAD ^ OPAD);  // 0x36 ^ 0x5c = 0x6a
    }

    // Compress opad and cache the resulting state
    sha512_init(&st);
    sha512_compress(&st, pad);
    st.total_len = 128ul;
    for (int i = 0; i < 8; i++) {
        ctx->outer_h[i] = st.h[i];
    }
    ctx->outer_total_len = st.total_len;
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
    Sha512State state;

    // Restore cached inner state (ipad already compressed)
    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->inner_h[i];
    }
    state.total_len = ctx->inner_total_len;

    // Compress any full 128-byte blocks of data
    uint full_blocks = data_len / 128u;
    uint remainder = data_len % 128u;

    for (uint b = 0u; b < full_blocks; b++) {
        sha512_compress(&state, data + b * 128u);
        state.total_len += 128ul;
    }

    // Finalize inner hash with remainder
    uchar inner_hash[64];
    sha512_final(&state, data + full_blocks * 128u, remainder, inner_hash);

    // Restore cached outer state (opad already compressed)
    for (int i = 0; i < 8; i++) {
        state.h[i] = ctx->outer_h[i];
    }
    state.total_len = ctx->outer_total_len;

    // Finalize outer hash: H(o_key_pad || inner_hash)
    sha512_final(&state, inner_hash, 64u, out);
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

// ============================================================================
// Specialized HMAC for exactly 64-byte message (PBKDF2 iterations 2..2048)
// ============================================================================

// HMAC-SHA512 for 64-byte message as ulong8, returns ulong8.
// No arrays, no pointers in hot path - keeps everything in registers.
// Uses cached midstates to skip ipad/opad compression.
static inline ulong8 hmac_sha512_msg64_u8(__private HmacSha512Ctx* ctx, ulong8 msg) {
    Sha512State s;

    // Inner hash: restore cached state (ipad already compressed)
    s.h[0] = ctx->inner_h[0]; s.h[1] = ctx->inner_h[1];
    s.h[2] = ctx->inner_h[2]; s.h[3] = ctx->inner_h[3];
    s.h[4] = ctx->inner_h[4]; s.h[5] = ctx->inner_h[5];
    s.h[6] = ctx->inner_h[6]; s.h[7] = ctx->inner_h[7];
    s.total_len = ctx->inner_total_len;
    ulong8 inner = sha512_final_from_u8(&s, msg);

    // Outer hash: restore cached state (opad already compressed)
    s.h[0] = ctx->outer_h[0]; s.h[1] = ctx->outer_h[1];
    s.h[2] = ctx->outer_h[2]; s.h[3] = ctx->outer_h[3];
    s.h[4] = ctx->outer_h[4]; s.h[5] = ctx->outer_h[5];
    s.h[6] = ctx->outer_h[6]; s.h[7] = ctx->outer_h[7];
    s.total_len = ctx->outer_total_len;
    return sha512_final_from_u8(&s, inner);
}
