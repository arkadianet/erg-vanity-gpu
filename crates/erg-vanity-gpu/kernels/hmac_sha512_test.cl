// hmac_sha512_test.cl - test kernel wrapper
//
// Expected to be concatenated after sha512.cl and hmac_sha512.cl in the program source.

// Test kernel for HMAC-SHA512
// Max key: 128 bytes, max data: 256 bytes (returns zeros if exceeded)
__kernel void hmac_sha512_test(
    __global const uchar* key,
    const uint key_len,
    __global const uchar* data,
    const uint data_len,
    __global uchar* output   // 64 bytes
) {
    if (get_global_id(0) != 0u) return;

    // Reject inputs that exceed test buffer sizes
    if (key_len > 128u || data_len > 256u) {
        for (int i = 0; i < 64; i++) output[i] = 0u;
        return;
    }

    // Copy key to private memory
    uchar priv_key[128];
    for (uint i = 0u; i < key_len; i++) {
        priv_key[i] = key[i];
    }

    // Copy data to private memory
    uchar priv_data[256];
    for (uint i = 0u; i < data_len; i++) {
        priv_data[i] = data[i];
    }

    // Compute HMAC
    uchar digest[64];
    hmac_sha512_oneshot(priv_key, key_len, priv_data, data_len, digest);

    for (int i = 0; i < 64; i++) {
        output[i] = digest[i];
    }
}
