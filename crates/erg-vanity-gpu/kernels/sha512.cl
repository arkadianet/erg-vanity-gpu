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
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

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

// Compress one 128-byte (1024-bit) block into state
// Block must be in private memory
inline void sha512_compress(__private Sha512State* state, const __private uchar* block) {
    // Prepare message schedule W[0..79]
    ulong W[80];

    // First 16 words from block (big-endian)
    for (int i = 0; i < 16; i++) {
        int idx = i * 8;
        W[i] = pack_be64(block[idx], block[idx+1], block[idx+2], block[idx+3],
                         block[idx+4], block[idx+5], block[idx+6], block[idx+7]);
    }

    // Extend to 80 words
    for (int i = 16; i < 80; i++) {
        W[i] = SIG1_64(W[i-2]) + W[i-7] + SIG0_64(W[i-15]) + W[i-16];
    }

    // Initialize working variables
    ulong a = state->h[0];
    ulong b = state->h[1];
    ulong c = state->h[2];
    ulong d = state->h[3];
    ulong e = state->h[4];
    ulong f = state->h[5];
    ulong g = state->h[6];
    ulong h = state->h[7];

    // 80 rounds
    for (int i = 0; i < 80; i++) {
        ulong t1 = h + EP1_64(e) + CH64(e, f, g) + K512[i] + W[i];
        ulong t2 = EP0_64(a) + MAJ64(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add compressed chunk to current state
    state->h[0] += a;
    state->h[1] += b;
    state->h[2] += c;
    state->h[3] += d;
    state->h[4] += e;
    state->h[5] += f;
    state->h[6] += g;
    state->h[7] += h;
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
