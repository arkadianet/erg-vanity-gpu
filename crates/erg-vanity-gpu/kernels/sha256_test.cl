// sha256_test.cl - test kernel wrapper
//
// Expected to be concatenated after sha256.cl in the program source.
// Do NOT use #include - Rust handles source concatenation.

__kernel void sha256_test(
    __global const uchar* input,
    const uint input_len,
    __global uint* output   // 8 words
) {
    if (get_global_id(0) != 0u) return;

    // Let library handle len > 55 (returns zeros) - don't mask misuse
    uint len = input_len;

    // Copy to private memory so sha256_single_block(__private ...) is happy
    // Clamp copy to avoid buffer overrun, but pass real len so library rejects misuse
    uchar msg[55];
    uint copy_len = len;
    if (copy_len > 55u) copy_len = 55u;

    for (uint i = 0u; i < copy_len; i++) {
        msg[i] = input[i];
    }

    uint digest[8];
    sha256_single_block(msg, len, digest);

    for (int i = 0; i < 8; i++) {
        output[i] = digest[i];
    }
}
