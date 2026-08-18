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
    ulong8 inner_h;         // SHA-512 state after compressing ipad
    ulong8 outer_h;         // SHA-512 state after compressing opad
    ulong inner_total_len;  // Cached total_len (128 after ipad compress)
    ulong outer_total_len;  // Cached total_len (128 after opad compress)
} HmacSha512Ctx;

// Load 8 key bytes as a big-endian word, zero-padded past key_len.
inline ulong hmac_load_key_word(const __private uchar* key, uint key_len, uint off) {
    ulong v = 0ul;
    for (uint i = 0u; i < 8u; i++) {
        uchar b = (off + i < key_len) ? key[off + i] : 0u;
        v = (v << 8) | (ulong)b;
    }
    return v;
}

#define HMAC_IPAD64 0x3636363636363636ul
#define HMAC_OPAD64 0x5c5c5c5c5c5c5c5cul

// Initialize HMAC context with key.
// If key_len > 128, caller must hash it first and pass the 64-byte hash.
// (BIP39 mnemonics can exceed 128 bytes, so the caller handles this.)
inline void hmac_sha512_init(__private HmacSha512Ctx* ctx,
                             const __private uchar* key, uint key_len) {
    ulong w0  = hmac_load_key_word(key, key_len, 0u)   ^ HMAC_IPAD64;
    ulong w1  = hmac_load_key_word(key, key_len, 8u)   ^ HMAC_IPAD64;
    ulong w2  = hmac_load_key_word(key, key_len, 16u)  ^ HMAC_IPAD64;
    ulong w3  = hmac_load_key_word(key, key_len, 24u)  ^ HMAC_IPAD64;
    ulong w4  = hmac_load_key_word(key, key_len, 32u)  ^ HMAC_IPAD64;
    ulong w5  = hmac_load_key_word(key, key_len, 40u)  ^ HMAC_IPAD64;
    ulong w6  = hmac_load_key_word(key, key_len, 48u)  ^ HMAC_IPAD64;
    ulong w7  = hmac_load_key_word(key, key_len, 56u)  ^ HMAC_IPAD64;
    ulong w8  = hmac_load_key_word(key, key_len, 64u)  ^ HMAC_IPAD64;
    ulong w9  = hmac_load_key_word(key, key_len, 72u)  ^ HMAC_IPAD64;
    ulong w10 = hmac_load_key_word(key, key_len, 80u)  ^ HMAC_IPAD64;
    ulong w11 = hmac_load_key_word(key, key_len, 88u)  ^ HMAC_IPAD64;
    ulong w12 = hmac_load_key_word(key, key_len, 96u)  ^ HMAC_IPAD64;
    ulong w13 = hmac_load_key_word(key, key_len, 104u) ^ HMAC_IPAD64;
    ulong w14 = hmac_load_key_word(key, key_len, 112u) ^ HMAC_IPAD64;
    ulong w15 = hmac_load_key_word(key, key_len, 120u) ^ HMAC_IPAD64;

    Sha512State st;
    sha512_init(&st);
    ctx->inner_h = sha512_compress_mid16(
        sha512_state_mid(&st),
        w0, w1, w2, w3, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15);
    ctx->inner_total_len = 128ul;

    // (k ^ ipad) ^ (ipad ^ opad) = k ^ opad
    w0  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w1  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w2  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w3  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w4  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w5  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w6  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w7  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w8  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w9  ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w10 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w11 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w12 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w13 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w14 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);
    w15 ^= (HMAC_IPAD64 ^ HMAC_OPAD64);

    sha512_init(&st);
    ctx->outer_h = sha512_compress_mid16(
        sha512_state_mid(&st),
        w0, w1, w2, w3, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15);
    ctx->outer_total_len = 128ul;
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
    state.h[0] = ctx->inner_h.s0; state.h[1] = ctx->inner_h.s1;
    state.h[2] = ctx->inner_h.s2; state.h[3] = ctx->inner_h.s3;
    state.h[4] = ctx->inner_h.s4; state.h[5] = ctx->inner_h.s5;
    state.h[6] = ctx->inner_h.s6; state.h[7] = ctx->inner_h.s7;
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
    state.h[0] = ctx->outer_h.s0; state.h[1] = ctx->outer_h.s1;
    state.h[2] = ctx->outer_h.s2; state.h[3] = ctx->outer_h.s3;
    state.h[4] = ctx->outer_h.s4; state.h[5] = ctx->outer_h.s5;
    state.h[6] = ctx->outer_h.s6; state.h[7] = ctx->outer_h.s7;
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
    ulong8 inner = sha512_final_from_mid_u8(ctx->inner_h, ctx->inner_total_len, msg);
    return sha512_final_from_mid_u8(ctx->outer_h, ctx->outer_total_len, inner);
}
