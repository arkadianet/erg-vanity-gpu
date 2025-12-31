// SHA-256 library for OpenCL
//
// Single-block only (data_len <= 55 bytes) - optimized for BIP39 checksum.
// For BIP39, we hash 32-byte entropy to get 8 checksum bits.

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
__constant uint K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
__constant uint H256_INIT[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

// Rotate right
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)       (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)      (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

// Pack 4 bytes (big-endian) into a uint
inline uint pack_be32(uchar b0, uchar b1, uchar b2, uchar b3) {
    return ((uint)b0 << 24) | ((uint)b1 << 16) | ((uint)b2 << 8) | (uint)b3;
}

// SHA-256 single-block hash (data_len <= 55 bytes)
//
// If data_len > 55, outputs all zeros (invalid - caller violated precondition).
// This is a safety check; the vanity pipeline should never trigger it.
//
// Output: 8 x uint in big-endian word order (standard SHA-256 output format)
//
// NOTE: Uses __private address space. Callers must copy data to private memory first.
inline void sha256_single_block(const __private uchar* data, uint data_len, __private uint* out) {
    // Enforce precondition: single block requires data_len <= 55
    // (message + 0x80 + padding + 8-byte length must fit in 64 bytes)
    if (data_len > 55u) {
        for (int i = 0; i < 8; i++) out[i] = 0u;
        return;
    }

    // Build padded message block (16 x uint = 64 bytes)
    uint block[16];
    for (int i = 0; i < 16; i++) block[i] = 0u;

    // Copy data as big-endian 32-bit words
    uint full_words = data_len / 4u;
    for (uint i = 0; i < full_words; i++) {
        block[i] = pack_be32(data[i*4u], data[i*4u+1u], data[i*4u+2u], data[i*4u+3u]);
    }

    // Handle remaining bytes + append 0x80
    uint rem = data_len % 4u;
    uint word_idx = full_words;
    if (rem == 0u) {
        block[word_idx] = 0x80000000u;
    } else if (rem == 1u) {
        block[word_idx] = pack_be32(data[word_idx*4u], 0x80u, 0u, 0u);
    } else if (rem == 2u) {
        block[word_idx] = pack_be32(data[word_idx*4u], data[word_idx*4u+1u], 0x80u, 0u);
    } else { // rem == 3
        block[word_idx] = pack_be32(data[word_idx*4u], data[word_idx*4u+1u], data[word_idx*4u+2u], 0x80u);
    }

    // Append 64-bit length in bits (big-endian) at block[14..15]
    block[14] = 0u;                   // High 32 bits (always 0 for data_len <= 55)
    block[15] = data_len * 8u;        // Low 32 bits (length in bits)

    // Message schedule (expand 16 words to 64)
    uint W[64];
    for (int i = 0; i < 16; i++) W[i] = block[i];
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    // Initialize working variables
    uint a = H256_INIT[0];
    uint b = H256_INIT[1];
    uint c = H256_INIT[2];
    uint d = H256_INIT[3];
    uint e = H256_INIT[4];
    uint f = H256_INIT[5];
    uint g = H256_INIT[6];
    uint h = H256_INIT[7];

    // 64 rounds of compression
    for (int i = 0; i < 64; i++) {
        uint t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        uint t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Output final hash (big-endian word order)
    out[0] = H256_INIT[0] + a;
    out[1] = H256_INIT[1] + b;
    out[2] = H256_INIT[2] + c;
    out[3] = H256_INIT[3] + d;
    out[4] = H256_INIT[4] + e;
    out[5] = H256_INIT[5] + f;
    out[6] = H256_INIT[6] + g;
    out[7] = H256_INIT[7] + h;
}

// Get first byte of SHA-256 hash (for BIP39 checksum extraction)
//
// BIP39 uses the first (entropy_bits / 32) bits as checksum.
// For 256-bit entropy: 8 checksum bits = first byte of hash.
//
// NOTE: Returns 0 if data_len > 55 (precondition violation in sha256_single_block).
// This could silently "match" a 0x00 checksum byte if caller misuses it.
// Vanity pipeline always passes 32-byte entropy, so this is not a concern there.
//
// NOTE: Uses __private address space. Callers must copy data to private memory first.
inline uchar sha256_first_byte(const __private uchar* data, uint data_len) {
    uint out[8];
    sha256_single_block(data, data_len, out);
    return (uchar)(out[0] >> 24);
}
