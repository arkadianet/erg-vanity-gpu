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

// ============================================================================
// Specialized HMAC for exactly 64-byte message (PBKDF2 iterations 2..2048)
// ============================================================================

// HMAC-SHA512 for 64-byte message as ulong8, returns ulong8.
// No arrays, no pointers in hot path - keeps everything in registers.
static inline ulong8 hmac_sha512_msg64_u8(__private HmacSha512Ctx* ctx, ulong8 msg) {
    Sha512State s;

    // Inner hash: H(i_key_pad || msg)
    sha512_init(&s);
    sha512_compress(&s, ctx->i_key_pad);
    s.total_len = 128ul;
    ulong8 inner = sha512_final_from_u8(&s, msg);

    // Outer hash: H(o_key_pad || inner)
    sha512_init(&s);
    sha512_compress(&s, ctx->o_key_pad);
    s.total_len = 128ul;
    return sha512_final_from_u8(&s, inner);
}
