// blake2b.cl - Blake2b-256 implementation (RFC 7693)
//
// Used for Ergo address checksum computation.
// Optimized for short inputs (34 bytes = prefix + compressed pubkey).

// Blake2b initialization vector
__constant ulong BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ul,
    0xbb67ae8584caa73bul,
    0x3c6ef372fe94f82bul,
    0xa54ff53a5f1d36f1ul,
    0x510e527fade682d1ul,
    0x9b05688c2b3e6c1ful,
    0x1f83d9abfb41bd6bul,
    0x5be0cd19137e2179ul
};

// Sigma permutation table for message schedule (12 rounds)
__constant uchar BLAKE2B_SIGMA[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}
};

// Rotate right for 64-bit
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// G mixing function
inline void blake2b_g(__private ulong* v, int a, int b, int c, int d, ulong x, ulong y) {
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = ROTR64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR64(v[b] ^ v[c], 63);
}

// Compress a single block
// h: state (8 x ulong)
// block: message block (128 bytes, zero-padded if needed)
// t: byte count
// last: true if this is the last block
inline void blake2b_compress(__private ulong* h, __private const uchar* block, ulong t, int last) {
    // Parse message block into 16 words (little-endian)
    ulong m[16];
    for (int i = 0; i < 16; i++) {
        int off = i * 8;
        m[i] = ((ulong)block[off]) |
               ((ulong)block[off + 1] << 8) |
               ((ulong)block[off + 2] << 16) |
               ((ulong)block[off + 3] << 24) |
               ((ulong)block[off + 4] << 32) |
               ((ulong)block[off + 5] << 40) |
               ((ulong)block[off + 6] << 48) |
               ((ulong)block[off + 7] << 56);
    }

    // Initialize working vector
    ulong v[16];
    for (int i = 0; i < 8; i++) {
        v[i] = h[i];
        v[i + 8] = BLAKE2B_IV[i];
    }

    // XOR with counter (low 64 bits only, t_hi = 0 for small inputs)
    v[12] ^= t;
    // v[13] ^= 0; // t_hi = 0

    // Invert if last block
    if (last) {
        v[14] = ~v[14];
    }

    // 12 rounds of mixing
    for (int round = 0; round < 12; round++) {
        blake2b_g(v, 0, 4,  8, 12, m[BLAKE2B_SIGMA[round][ 0]], m[BLAKE2B_SIGMA[round][ 1]]);
        blake2b_g(v, 1, 5,  9, 13, m[BLAKE2B_SIGMA[round][ 2]], m[BLAKE2B_SIGMA[round][ 3]]);
        blake2b_g(v, 2, 6, 10, 14, m[BLAKE2B_SIGMA[round][ 4]], m[BLAKE2B_SIGMA[round][ 5]]);
        blake2b_g(v, 3, 7, 11, 15, m[BLAKE2B_SIGMA[round][ 6]], m[BLAKE2B_SIGMA[round][ 7]]);
        blake2b_g(v, 0, 5, 10, 15, m[BLAKE2B_SIGMA[round][ 8]], m[BLAKE2B_SIGMA[round][ 9]]);
        blake2b_g(v, 1, 6, 11, 12, m[BLAKE2B_SIGMA[round][10]], m[BLAKE2B_SIGMA[round][11]]);
        blake2b_g(v, 2, 7,  8, 13, m[BLAKE2B_SIGMA[round][12]], m[BLAKE2B_SIGMA[round][13]]);
        blake2b_g(v, 3, 4,  9, 14, m[BLAKE2B_SIGMA[round][14]], m[BLAKE2B_SIGMA[round][15]]);
    }

    // Finalize state
    for (int i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

// Blake2b-256 digest for short inputs (< 128 bytes, single block)
// input: data to hash
// input_len: length of data (must be < 128)
// output: 32-byte hash output
inline void blake2b_256(__private const uchar* input, uint input_len, __private uchar* output) {
    // Initialize state with parameter block
    // h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen
    // For Blake2b-256 with no key: h[0] ^= 0x01010000 ^ 32 = 0x01010020
    ulong h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = BLAKE2B_IV[i];
    }
    h[0] ^= 0x01010020ul;

    // Prepare single block (zero-padded)
    uchar block[128];
    for (int i = 0; i < 128; i++) {
        block[i] = (i < (int)input_len) ? input[i] : 0u;
    }

    // Compress (single block, final)
    blake2b_compress(h, block, (ulong)input_len, 1);

    // Extract first 32 bytes of output (little-endian)
    for (int i = 0; i < 4; i++) {
        ulong word = h[i];
        int off = i * 8;
        output[off] = (uchar)(word);
        output[off + 1] = (uchar)(word >> 8);
        output[off + 2] = (uchar)(word >> 16);
        output[off + 3] = (uchar)(word >> 24);
        output[off + 4] = (uchar)(word >> 32);
        output[off + 5] = (uchar)(word >> 40);
        output[off + 6] = (uchar)(word >> 48);
        output[off + 7] = (uchar)(word >> 56);
    }
}

// Compute 4-byte checksum for Ergo address
// Inputs: prefix (1 byte) + pubkey (33 bytes) = 34 bytes total
// Returns first 4 bytes of Blake2b-256(input)
inline void ergo_checksum(__private const uchar* data, __private uchar* checksum) {
    uchar hash[32];
    blake2b_256(data, 34u, hash);
    checksum[0] = hash[0];
    checksum[1] = hash[1];
    checksum[2] = hash[2];
    checksum[3] = hash[3];
}
