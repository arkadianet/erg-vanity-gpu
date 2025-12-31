// sha512_test.cl - test kernel wrapper
//
// Expected to be concatenated after sha512.cl in the program source.

// Test kernel: single-block SHA-512 (data_len <= 111)
__kernel void sha512_test_single(
    __global const uchar* input,
    const uint input_len,
    __global uchar* output   // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    // Copy to private memory
    // sha512_single_block checks len > 111 and returns zeros, so no OOB risk
    uint len = input_len;
    uchar msg[111];
    uint copy_len = (len <= 111u) ? len : 111u;

    for (uint i = 0u; i < copy_len; i++) {
        msg[i] = input[i];
    }

    uchar digest[64];
    sha512_single_block(msg, len, digest);

    for (int i = 0; i < 64; i++) {
        output[i] = digest[i];
    }
}

// Test kernel: two-block SHA-512 (one full 128-byte block + remainder 0..111)
// Total message length: 128 <= total_len <= 239
__kernel void sha512_test_two_blocks(
    __global const uchar* block1,      // exactly 128 bytes
    __global const uchar* block2,      // up to 111 bytes
    const uint block2_len,
    __global uchar* output             // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    // Reject misuse safely (do NOT clamp silently)
    if (block2_len > 111u) {
        for (int i = 0; i < 64; i++) output[i] = 0u;
        return;
    }

    uchar b1[128];
    for (int i = 0; i < 128; i++) {
        b1[i] = block1[i];
    }

    uchar b2[111];
    for (uint i = 0u; i < block2_len; i++) {
        b2[i] = block2[i];
    }

    uchar digest[64];
    sha512_two_blocks(b1, b2, block2_len, digest);

    for (int i = 0; i < 64; i++) {
        output[i] = digest[i];
    }
}
