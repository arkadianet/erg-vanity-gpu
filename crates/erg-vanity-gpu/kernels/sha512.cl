// SHA-512 library for OpenCL
//
// Multi-block support for HMAC-SHA512 / PBKDF2.

// SHA-512 round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
__constant ulong K512[80] = {
    0x428a2f98d728ae22ul, 0x7137449123ef65cdul, 0xb5c0fbcfec4d3b2ful, 0xe9b5dba58189dbbcul,
    0x3956c25bf348b538ul, 0x59f111f1b605d019ul, 0x923f82a4af194f9bul, 0xab1c5ed5da6d8118ul,
    0xd807aa98a3030242ul, 0x12835b0145706fbeul, 0x243185be4ee4b28cul, 0x550c7dc3d5ffb4e2ul,
    0x72be5d74f27b896ful, 0x80deb1fe3b1696b1ul, 0x9bdc06a725c71235ul, 0xc19bf174cf692694ul,
    0xe49b69c19ef14ad2ul, 0xefbe4786384f25e3ul, 0x0fc19dc68b8cd5b5ul, 0x240ca1cc77ac9c65ul,
    0x2de92c6f592b0275ul, 0x4a7484aa6ea6e483ul, 0x5cb0a9dcbd41fbd4ul, 0x76f988da831153b5ul,
    0x983e5152ee66dfabul, 0xa831c66d2db43210ul, 0xb00327c898fb213ful, 0xbf597fc7beef0ee4ul,
    0xc6e00bf33da88fc2ul, 0xd5a79147930aa725ul, 0x06ca6351e003826ful, 0x142929670a0e6e70ul,
    0x27b70a8546d22ffcul, 0x2e1b21385c26c926ul, 0x4d2c6dfc5ac42aedul, 0x53380d139d95b3dful,
    0x650a73548baf63deul, 0x766a0abb3c77b2a8ul, 0x81c2c92e47edaee6ul, 0x92722c851482353bul,
    0xa2bfe8a14cf10364ul, 0xa81a664bbc423001ul, 0xc24b8b70d0f89791ul, 0xc76c51a30654be30ul,
    0xd192e819d6ef5218ul, 0xd69906245565a910ul, 0xf40e35855771202aul, 0x106aa07032bbd1b8ul,
    0x19a4c116b8d2d0c8ul, 0x1e376c085141ab53ul, 0x2748774cdf8eeb99ul, 0x34b0bcb5e19b48a8ul,
    0x391c0cb3c5c95a63ul, 0x4ed8aa4ae3418acbul, 0x5b9cca4f7763e373ul, 0x682e6ff3d6b2b8a3ul,
    0x748f82ee5defb2fcul, 0x78a5636f43172f60ul, 0x84c87814a1f0ab72ul, 0x8cc702081a6439ecul,
    0x90befffa23631e28ul, 0xa4506cebde82bde9ul, 0xbef9a3f7b2c67915ul, 0xc67178f2e372532bul,
    0xca273eceea26619cul, 0xd186b8c721c0c207ul, 0xeada7dd6cde0eb1eul, 0xf57d4f7fee6ed178ul,
    0x06f067aa72176fbaul, 0x0a637dc5a2c898a6ul, 0x113f9804bef90daeul, 0x1b710b35131c471bul,
    0x28db77f523047d84ul, 0x32caab7b40c72493ul, 0x3c9ebe0a15c9bebcul, 0x431d67c49c100d4cul,
    0x4cc5d4becb3e42b6ul, 0x597f299cfc657e2aul, 0x5fcb6fab3ad6faecul, 0x6c44198c4a475817ul
};

// SHA-512 initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
__constant ulong H512_INIT[8] = {
    0x6a09e667f3bcc908ul, 0xbb67ae8584caa73bul,
    0x3c6ef372fe94f82bul, 0xa54ff53a5f1d36f1ul,
    0x510e527fade682d1ul, 0x9b05688c2b3e6c1ful,
    0x1f83d9abfb41bd6bul, 0x5be0cd19137e2179ul
};

// Rotate right for 64-bit
#define ROTR64(x, n) rotate((x), (ulong)(64ul - (n)))

// SHA-512 functions
#define CH64(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x)      (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x)      (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x)     (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x)     (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

// Pack 8 bytes (big-endian) into a ulong
inline ulong pack_be64(uchar b0, uchar b1, uchar b2, uchar b3,
                       uchar b4, uchar b5, uchar b6, uchar b7) {
    return ((ulong)b0 << 56) | ((ulong)b1 << 48) | ((ulong)b2 << 40) | ((ulong)b3 << 32) |
           ((ulong)b4 << 24) | ((ulong)b5 << 16) | ((ulong)b6 << 8)  | (ulong)b7;
}

// Unpack ulong to 8 bytes (big-endian)
inline void unpack_be64(ulong val, __private uchar* out) {
    out[0] = (uchar)(val >> 56);
    out[1] = (uchar)(val >> 48);
    out[2] = (uchar)(val >> 40);
    out[3] = (uchar)(val >> 32);
    out[4] = (uchar)(val >> 24);
    out[5] = (uchar)(val >> 16);
    out[6] = (uchar)(val >> 8);
    out[7] = (uchar)val;
}

// SHA-512 state structure
typedef struct {
    ulong h[8];       // Current hash state
    ulong total_len;  // Total bytes processed (for final padding)
} Sha512State;

// Initialize SHA-512 state
inline void sha512_init(__private Sha512State* state) {
    for (int i = 0; i < 8; i++) {
        state->h[i] = H512_INIT[i];
    }
    state->total_len = 0ul;
}

// SHA-512 round macro for scalar schedule (single-line, no backslash fragility)
#define SHA512_ROUND(i, Wi) do { ulong t1 = h + EP1_64(e) + CH64(e, f, g) + K512[(i)] + (Wi); ulong t2 = EP0_64(a) + MAJ64(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; } while (0)

// Full-block compress from 16 message words. Rotating schedule, no W[80].
inline ulong8 sha512_compress_mid16(
    ulong8 mid,
    ulong w0, ulong w1, ulong w2, ulong w3,
    ulong w4, ulong w5, ulong w6, ulong w7,
    ulong w8, ulong w9, ulong w10, ulong w11,
    ulong w12, ulong w13, ulong w14, ulong w15
) {
    ulong a = mid.s0, b = mid.s1, c = mid.s2, d = mid.s3;
    ulong e = mid.s4, f = mid.s5, g = mid.s6, h = mid.s7;

    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);
        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    return (ulong8)(mid.s0 + a, mid.s1 + b, mid.s2 + c, mid.s3 + d,
                    mid.s4 + e, mid.s5 + f, mid.s6 + g, mid.s7 + h);
}

inline ulong8 sha512_state_mid(__private const Sha512State* state) {
    return (ulong8)(state->h[0], state->h[1], state->h[2], state->h[3],
                    state->h[4], state->h[5], state->h[6], state->h[7]);
}

inline void sha512_state_from_mid(__private Sha512State* state, ulong8 mid) {
    state->h[0] = mid.s0; state->h[1] = mid.s1; state->h[2] = mid.s2; state->h[3] = mid.s3;
    state->h[4] = mid.s4; state->h[5] = mid.s5; state->h[6] = mid.s6; state->h[7] = mid.s7;
}

// Compress one 128-byte (1024-bit) block into state
inline void sha512_compress(__private Sha512State* state, const __private uchar* block) {
    ulong w0  = pack_be64(block[0],  block[1],  block[2],  block[3],
                          block[4],  block[5],  block[6],  block[7]);
    ulong w1  = pack_be64(block[8],  block[9],  block[10], block[11],
                          block[12], block[13], block[14], block[15]);
    ulong w2  = pack_be64(block[16], block[17], block[18], block[19],
                          block[20], block[21], block[22], block[23]);
    ulong w3  = pack_be64(block[24], block[25], block[26], block[27],
                          block[28], block[29], block[30], block[31]);
    ulong w4  = pack_be64(block[32], block[33], block[34], block[35],
                          block[36], block[37], block[38], block[39]);
    ulong w5  = pack_be64(block[40], block[41], block[42], block[43],
                          block[44], block[45], block[46], block[47]);
    ulong w6  = pack_be64(block[48], block[49], block[50], block[51],
                          block[52], block[53], block[54], block[55]);
    ulong w7  = pack_be64(block[56], block[57], block[58], block[59],
                          block[60], block[61], block[62], block[63]);
    ulong w8  = pack_be64(block[64], block[65], block[66], block[67],
                          block[68], block[69], block[70], block[71]);
    ulong w9  = pack_be64(block[72], block[73], block[74], block[75],
                          block[76], block[77], block[78], block[79]);
    ulong w10 = pack_be64(block[80], block[81], block[82], block[83],
                          block[84], block[85], block[86], block[87]);
    ulong w11 = pack_be64(block[88], block[89], block[90], block[91],
                          block[92], block[93], block[94], block[95]);
    ulong w12 = pack_be64(block[96], block[97], block[98], block[99],
                          block[100], block[101], block[102], block[103]);
    ulong w13 = pack_be64(block[104], block[105], block[106], block[107],
                          block[108], block[109], block[110], block[111]);
    ulong w14 = pack_be64(block[112], block[113], block[114], block[115],
                          block[116], block[117], block[118], block[119]);
    ulong w15 = pack_be64(block[120], block[121], block[122], block[123],
                          block[124], block[125], block[126], block[127]);

    sha512_state_from_mid(state, sha512_compress_mid16(
        sha512_state_mid(state),
        w0, w1, w2, w3, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15));
}

// Finalize SHA-512 and output 64-byte digest
// Handles padding for the final partial block.
// remaining_data: up to 127 bytes of unprocessed data
// remaining_len: length of remaining_data (0..127)
inline void sha512_final(__private Sha512State* state,
                         const __private uchar* remaining_data,
                         uint remaining_len,
                         __private uchar* out) {
    ulong total_bits = (state->total_len + remaining_len) * 8ul;

    // Build final block(s)
    uchar block[128];

    // Copy remaining data
    for (uint i = 0u; i < remaining_len; i++) {
        block[i] = remaining_data[i];
    }

    // Append 0x80
    block[remaining_len] = 0x80u;

    // Zero-fill
    for (uint i = remaining_len + 1u; i < 128u; i++) {
        block[i] = 0u;
    }

    // If remaining_len >= 112, we need two blocks
    if (remaining_len >= 112u) {
        // First block: data + 0x80 + zeros
        sha512_compress(state, block);

        // Second block: all zeros + length
        for (int i = 0; i < 128; i++) {
            block[i] = 0u;
        }
    }

    // Append 128-bit length (we only use low 64 bits since total_len is ulong)
    // High 64 bits = 0 for messages < 2^64 bits
    block[112] = 0u;
    block[113] = 0u;
    block[114] = 0u;
    block[115] = 0u;
    block[116] = 0u;
    block[117] = 0u;
    block[118] = 0u;
    block[119] = 0u;
    unpack_be64(total_bits, &block[120]);

    sha512_compress(state, block);

    // Output hash as bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        unpack_be64(state->h[i], &out[i * 8]);
    }
}

// Convenience: SHA-512 of data that fits in 1 block (data_len <= 111 bytes)
// Returns zeros if data_len > 111 (precondition violation).
inline void sha512_single_block(const __private uchar* data, uint data_len, __private uchar* out) {
    if (data_len > 111u) {
        for (int i = 0; i < 64; i++) out[i] = 0u;
        return;
    }

    Sha512State state;
    sha512_init(&state);
    sha512_final(&state, data, data_len, out);
}

// SHA-512 of exactly 2 blocks (total_len = 128 + block2_len, block2_len <= 111)
// First block is full 128 bytes, second is partial (fits in one padded block).
// Returns zeros if block2_len > 111 (precondition violation).
inline void sha512_two_blocks(const __private uchar* block1,
                              const __private uchar* block2, uint block2_len,
                              __private uchar* out) {
    if (block2_len > 111u) {
        for (int i = 0; i < 64; i++) out[i] = 0u;
        return;
    }

    Sha512State state;
    sha512_init(&state);
    sha512_compress(&state, block1);
    state.total_len = 128ul;
    sha512_final(&state, block2, block2_len, out);
}

// ============================================================================
// Specialized 64-byte finalization helpers for PBKDF2 fast path
// Uses 16 SCALAR ulongs (not an array) to keep schedule in registers.
// The W[16] array approach gets punted to local memory by NVIDIA.
// ============================================================================

// Finalize SHA-512 with exactly 64 bytes remaining, output as 8× ulong.
// Uses 16 scalar ulongs with explicit rotation to stay in registers.
// Updates state->h[] for consistency with other finalize functions.
inline void sha512_final_64_words(__private Sha512State* state,
                                  const __private uchar* msg64,
                                  __private ulong* out_words) {
    // 16 scalar schedule words - NO ARRAY (avoids local memory)
    ulong w0  = pack_be64(msg64[0],  msg64[1],  msg64[2],  msg64[3],
                          msg64[4],  msg64[5],  msg64[6],  msg64[7]);
    ulong w1  = pack_be64(msg64[8],  msg64[9],  msg64[10], msg64[11],
                          msg64[12], msg64[13], msg64[14], msg64[15]);
    ulong w2  = pack_be64(msg64[16], msg64[17], msg64[18], msg64[19],
                          msg64[20], msg64[21], msg64[22], msg64[23]);
    ulong w3  = pack_be64(msg64[24], msg64[25], msg64[26], msg64[27],
                          msg64[28], msg64[29], msg64[30], msg64[31]);
    ulong w4  = pack_be64(msg64[32], msg64[33], msg64[34], msg64[35],
                          msg64[36], msg64[37], msg64[38], msg64[39]);
    ulong w5  = pack_be64(msg64[40], msg64[41], msg64[42], msg64[43],
                          msg64[44], msg64[45], msg64[46], msg64[47]);
    ulong w6  = pack_be64(msg64[48], msg64[49], msg64[50], msg64[51],
                          msg64[52], msg64[53], msg64[54], msg64[55]);
    ulong w7  = pack_be64(msg64[56], msg64[57], msg64[58], msg64[59],
                          msg64[60], msg64[61], msg64[62], msg64[63]);
    ulong w8  = 0x8000000000000000ul;  // 0x80 padding
    ulong w9  = 0ul;
    ulong w10 = 0ul;
    ulong w11 = 0ul;
    ulong w12 = 0ul;
    ulong w13 = 0ul;
    ulong w14 = 0ul;
    ulong w15 = (state->total_len + 64ul) * 8ul;  // bit length

    ulong a = state->h[0], b = state->h[1], c = state->h[2], d = state->h[3];
    ulong e = state->h[4], f = state->h[5], g = state->h[6], h = state->h[7];

    // Rounds 0-63: round + schedule update with rotation
    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);

        // Compute next schedule word and rotate
        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    // Rounds 64-79: unrolled, no rotation needed
    // After 64 rotations, w0..w15 contain W64..W79
    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    // Update state and output as words
    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;

    out_words[0] = state->h[0]; out_words[1] = state->h[1];
    out_words[2] = state->h[2]; out_words[3] = state->h[3];
    out_words[4] = state->h[4]; out_words[5] = state->h[5];
    out_words[6] = state->h[6]; out_words[7] = state->h[7];
}

// Finalize SHA-512 where 64-byte message is already 8× ulong, output as bytes.
// Uses 16 scalar ulongs with rotation. Updates state->h[].
inline void sha512_final_from_words(__private Sha512State* state,
                                    const __private ulong* msg_words,
                                    __private uchar* out) {
    // 16 scalar schedule words from msg_words + padding
    ulong w0  = msg_words[0];
    ulong w1  = msg_words[1];
    ulong w2  = msg_words[2];
    ulong w3  = msg_words[3];
    ulong w4  = msg_words[4];
    ulong w5  = msg_words[5];
    ulong w6  = msg_words[6];
    ulong w7  = msg_words[7];
    ulong w8  = 0x8000000000000000ul;
    ulong w9  = 0ul;
    ulong w10 = 0ul;
    ulong w11 = 0ul;
    ulong w12 = 0ul;
    ulong w13 = 0ul;
    ulong w14 = 0ul;
    ulong w15 = (state->total_len + 64ul) * 8ul;

    ulong a = state->h[0], b = state->h[1], c = state->h[2], d = state->h[3];
    ulong e = state->h[4], f = state->h[5], g = state->h[6], h = state->h[7];

    // Rounds 0-63: round + schedule update with rotation
    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);

        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    // Rounds 64-79: unrolled
    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    // Update state and output as bytes
    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;

    for (int i = 0; i < 8; i++) {
        unpack_be64(state->h[i], &out[i * 8]);
    }
}

// Finalize SHA-512 where 64-byte message is already 8× ulong, output as 8× ulong.
// Uses 16 scalar ulongs with rotation. Updates state->h[].
inline void sha512_final_from_words_to_words(__private Sha512State* state,
                                              const __private ulong* msg_words,
                                              __private ulong* out_words) {
    // 16 scalar schedule words from msg_words + padding
    ulong w0  = msg_words[0];
    ulong w1  = msg_words[1];
    ulong w2  = msg_words[2];
    ulong w3  = msg_words[3];
    ulong w4  = msg_words[4];
    ulong w5  = msg_words[5];
    ulong w6  = msg_words[6];
    ulong w7  = msg_words[7];
    ulong w8  = 0x8000000000000000ul;
    ulong w9  = 0ul;
    ulong w10 = 0ul;
    ulong w11 = 0ul;
    ulong w12 = 0ul;
    ulong w13 = 0ul;
    ulong w14 = 0ul;
    ulong w15 = (state->total_len + 64ul) * 8ul;

    ulong a = state->h[0], b = state->h[1], c = state->h[2], d = state->h[3];
    ulong e = state->h[4], f = state->h[5], g = state->h[6], h = state->h[7];

    // Rounds 0-63: round + schedule update with rotation
    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);

        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    // Rounds 64-79: unrolled
    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    // Update state and output as words
    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;

    out_words[0] = state->h[0]; out_words[1] = state->h[1];
    out_words[2] = state->h[2]; out_words[3] = state->h[3];
    out_words[4] = state->h[4]; out_words[5] = state->h[5];
    out_words[6] = state->h[6]; out_words[7] = state->h[7];
}

// ============================================================================
// ulong8 variants - return vectors instead of writing to arrays.
// NVIDIA treats ulong8 as register pack, avoiding local memory traps.
// ============================================================================

// Finalize SHA-512 with exactly 64 bytes remaining, return as ulong8.
inline ulong8 sha512_final_64_u8(__private Sha512State* state,
                                  const __private uchar* msg64) {
    ulong w0  = pack_be64(msg64[0],  msg64[1],  msg64[2],  msg64[3],
                          msg64[4],  msg64[5],  msg64[6],  msg64[7]);
    ulong w1  = pack_be64(msg64[8],  msg64[9],  msg64[10], msg64[11],
                          msg64[12], msg64[13], msg64[14], msg64[15]);
    ulong w2  = pack_be64(msg64[16], msg64[17], msg64[18], msg64[19],
                          msg64[20], msg64[21], msg64[22], msg64[23]);
    ulong w3  = pack_be64(msg64[24], msg64[25], msg64[26], msg64[27],
                          msg64[28], msg64[29], msg64[30], msg64[31]);
    ulong w4  = pack_be64(msg64[32], msg64[33], msg64[34], msg64[35],
                          msg64[36], msg64[37], msg64[38], msg64[39]);
    ulong w5  = pack_be64(msg64[40], msg64[41], msg64[42], msg64[43],
                          msg64[44], msg64[45], msg64[46], msg64[47]);
    ulong w6  = pack_be64(msg64[48], msg64[49], msg64[50], msg64[51],
                          msg64[52], msg64[53], msg64[54], msg64[55]);
    ulong w7  = pack_be64(msg64[56], msg64[57], msg64[58], msg64[59],
                          msg64[60], msg64[61], msg64[62], msg64[63]);
    ulong w8  = 0x8000000000000000ul;
    ulong w9  = 0ul;
    ulong w10 = 0ul;
    ulong w11 = 0ul;
    ulong w12 = 0ul;
    ulong w13 = 0ul;
    ulong w14 = 0ul;
    ulong w15 = (state->total_len + 64ul) * 8ul;

    ulong a = state->h[0], b = state->h[1], c = state->h[2], d = state->h[3];
    ulong e = state->h[4], f = state->h[5], g = state->h[6], h = state->h[7];

    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);
        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;

    return (ulong8)(state->h[0], state->h[1], state->h[2], state->h[3],
                    state->h[4], state->h[5], state->h[6], state->h[7]);
}

// PBKDF2 hot path: finalize from midstate + 64-byte ulong8 message.
// No Sha512State writeback — HMAC restores midstate every iteration.
inline ulong8 sha512_final_from_mid_u8(ulong8 mid, ulong total_len, ulong8 msg) {
    ulong w0  = msg.s0;
    ulong w1  = msg.s1;
    ulong w2  = msg.s2;
    ulong w3  = msg.s3;
    ulong w4  = msg.s4;
    ulong w5  = msg.s5;
    ulong w6  = msg.s6;
    ulong w7  = msg.s7;
    ulong w8  = 0x8000000000000000ul;
    ulong w9  = 0ul;
    ulong w10 = 0ul;
    ulong w11 = 0ul;
    ulong w12 = 0ul;
    ulong w13 = 0ul;
    ulong w14 = 0ul;
    ulong w15 = (total_len + 64ul) * 8ul;

    ulong a = mid.s0, b = mid.s1, c = mid.s2, d = mid.s3;
    ulong e = mid.s4, f = mid.s5, g = mid.s6, h = mid.s7;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        SHA512_ROUND(i, w0);
        ulong newW = SIG1_64(w14) + w9 + SIG0_64(w1) + w0;
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = newW;
    }

    SHA512_ROUND(64, w0);  SHA512_ROUND(65, w1);
    SHA512_ROUND(66, w2);  SHA512_ROUND(67, w3);
    SHA512_ROUND(68, w4);  SHA512_ROUND(69, w5);
    SHA512_ROUND(70, w6);  SHA512_ROUND(71, w7);
    SHA512_ROUND(72, w8);  SHA512_ROUND(73, w9);
    SHA512_ROUND(74, w10); SHA512_ROUND(75, w11);
    SHA512_ROUND(76, w12); SHA512_ROUND(77, w13);
    SHA512_ROUND(78, w14); SHA512_ROUND(79, w15);

    return (ulong8)(mid.s0 + a, mid.s1 + b, mid.s2 + c, mid.s3 + d,
                    mid.s4 + e, mid.s5 + f, mid.s6 + g, mid.s7 + h);
}

// Finalize SHA-512 where 64-byte message is ulong8, return as ulong8.
inline ulong8 sha512_final_from_u8(__private Sha512State* state, ulong8 msg) {
    ulong8 mid = (ulong8)(state->h[0], state->h[1], state->h[2], state->h[3],
                          state->h[4], state->h[5], state->h[6], state->h[7]);
    ulong8 out = sha512_final_from_mid_u8(mid, state->total_len, msg);
    state->h[0] = out.s0; state->h[1] = out.s1; state->h[2] = out.s2; state->h[3] = out.s3;
    state->h[4] = out.s4; state->h[5] = out.s5; state->h[6] = out.s6; state->h[7] = out.s7;
    return out;
}

#undef SHA512_ROUND
#undef ROTR64
