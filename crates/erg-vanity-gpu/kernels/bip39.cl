// bip39.cl - BIP39 mnemonic generation and seed derivation
//
// Converts 256-bit entropy to 24-word mnemonic, then derives 64-byte seed.
// Requires: sha256.cl, sha512.cl, hmac_sha512.cl, pbkdf2.cl
//
// Wordlist is passed as buffer args, NOT embedded in kernel source.

// Extract 11-bit word index from entropy+checksum bits
// word_num: 0-23
// entropy: 32 bytes, checksum_byte: first byte of SHA-256(entropy)
inline uint get_word_index(
    __private const uchar* entropy,
    uchar checksum_byte,
    int word_num
) {
    // 264 bits total: 256 entropy + 8 checksum
    // Each word uses 11 bits starting at word_num * 11
    int bit_start = word_num * 11;
    int byte_start = bit_start / 8;
    int bit_offset = bit_start % 8;

    // Get 3 bytes starting at byte_start (handles crossing byte boundaries)
    // Cast to uint to avoid sign-extension issues
    uint b0, b1, b2;

    b0 = (byte_start < 32) ? (uint)entropy[byte_start] : (uint)checksum_byte;
    b1 = (byte_start + 1 < 32) ? (uint)entropy[byte_start + 1] :
         ((byte_start + 1 == 32) ? (uint)checksum_byte : 0u);
    b2 = (byte_start + 2 < 32) ? (uint)entropy[byte_start + 2] :
         ((byte_start + 2 == 32) ? (uint)checksum_byte : 0u);

    // Combine into 24 bits and extract 11 bits at bit_offset
    uint combined = (b0 << 16) | (b1 << 8) | b2;
    uint shift = 24 - 11 - bit_offset;
    uint index = (combined >> shift) & 0x7FFu;

    return index;
}

// Stream mnemonic to derive PBKDF2 password material
// Handles both cases:
//   - If mnemonic_len <= 128: output raw mnemonic bytes
//   - If mnemonic_len > 128: output SHA-512(mnemonic) digest (64 bytes)
//
// password_out: receives password bytes (up to 128), written directly during stream
// Returns: password length (either mnemonic_len or 64)
inline uint mnemonic_to_password(
    __private const uchar* entropy,
    __global const uchar* words8,
    __global const uchar* word_lens,
    __private uchar* password_out
) {
    // Compute SHA-256 checksum of entropy
    uint sha256_state[8];
    uchar entropy_padded[64];
    for (int i = 0; i < 32; i++) entropy_padded[i] = entropy[i];
    for (int i = 32; i < 64; i++) entropy_padded[i] = 0u;

    sha256_single_block(entropy_padded, 32u, sha256_state);
    uchar checksum_byte = (uchar)(sha256_state[0] >> 24);

    // Stream mnemonic while:
    // 1. Writing first 128 bytes directly to password_out
    // 2. Maintaining SHA-512 state for full hash (used if > 128)

    Sha512State sha_state;
    sha512_init(&sha_state);
    uchar sha_block[128];
    int sha_block_pos = 0;

    uint total_bytes = 0u;

    for (int w = 0; w < 24; w++) {
        uint idx = get_word_index(entropy, checksum_byte, w);
        __global const uchar* word_ptr = words8 + idx * 8;
        uint word_len = (uint)word_lens[idx];
        if (word_len > 8u) word_len = 8u;  // Guard against bad data

        // Stream each byte of word
        for (uint i = 0u; i < word_len; i++) {
            uchar byte_val = word_ptr[i];

            // Write directly to password_out if still < 128
            if (total_bytes < 128u) {
                password_out[total_bytes] = byte_val;
            }

            // Always feed to SHA-512
            sha_block[sha_block_pos++] = byte_val;
            if (sha_block_pos == 128) {
                sha512_compress(&sha_state, sha_block);
                sha_block_pos = 0;
            }

            total_bytes++;
        }

        // Add space after word (except last)
        if (w < 23) {
            uchar space = (uchar)' ';

            if (total_bytes < 128u) {
                password_out[total_bytes] = space;
            }

            sha_block[sha_block_pos++] = space;
            if (sha_block_pos == 128) {
                sha512_compress(&sha_state, sha_block);
                sha_block_pos = 0;
            }

            total_bytes++;
        }
    }

    // Decide which password to use
    if (total_bytes <= 128u) {
        // password_out already contains the mnemonic bytes
        return total_bytes;
    } else {
        // Finalize SHA-512 and use digest
        // Pad current block
        sha_block[sha_block_pos++] = 0x80u;

        if (sha_block_pos > 112) {
            while (sha_block_pos < 128) sha_block[sha_block_pos++] = 0u;
            sha512_compress(&sha_state, sha_block);
            sha_block_pos = 0;
        }

        while (sha_block_pos < 112) sha_block[sha_block_pos++] = 0u;

        // Append length in bits (big-endian, 128-bit)
        ulong bit_len = (ulong)total_bytes * 8ul;
        for (int i = 0; i < 8; i++) sha_block[112 + i] = 0u;
        for (int i = 0; i < 8; i++) {
            sha_block[120 + i] = (uchar)(bit_len >> (56 - i * 8));
        }

        sha512_compress(&sha_state, sha_block);

        // Convert state to bytes (big-endian)
        for (int i = 0; i < 8; i++) {
            ulong word = sha_state.h[i];
            password_out[i * 8 + 0] = (uchar)(word >> 56);
            password_out[i * 8 + 1] = (uchar)(word >> 48);
            password_out[i * 8 + 2] = (uchar)(word >> 40);
            password_out[i * 8 + 3] = (uchar)(word >> 32);
            password_out[i * 8 + 4] = (uchar)(word >> 24);
            password_out[i * 8 + 5] = (uchar)(word >> 16);
            password_out[i * 8 + 6] = (uchar)(word >> 8);
            password_out[i * 8 + 7] = (uchar)(word);
        }
        return 64u;
    }
}

// Derive BIP39 seed from entropy (no passphrase)
// entropy: 32 bytes
// seed: 64 bytes output
// words8: wordlist data (2048 * 8 bytes)
// word_lens: word lengths (2048 bytes)
inline void bip39_entropy_to_seed(
    __private const uchar* entropy,
    __global const uchar* words8,
    __global const uchar* word_lens,
    __private uchar* seed
) {
    // Get password (mnemonic or its hash)
    uchar password[128];
    uint password_len = mnemonic_to_password(entropy, words8, word_lens, password);

    // Salt is "mnemonic" (no passphrase for vanity generation)
    uchar salt[8];
    salt[0] = (uchar)'m';
    salt[1] = (uchar)'n';
    salt[2] = (uchar)'e';
    salt[3] = (uchar)'m';
    salt[4] = (uchar)'o';
    salt[5] = (uchar)'n';
    salt[6] = (uchar)'i';
    salt[7] = (uchar)'c';

    // PBKDF2 with 2048 iterations
    pbkdf2_sha512(password, password_len, salt, 8u, 2048u, seed);
}
