// blake2b_test.cl - test kernel wrapper for Blake2b-256
//
// Expected to be concatenated after blake2b.cl

// Expected Blake2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
__constant uchar EXPECTED_EMPTY[32] = {
    (uchar)0x0e, (uchar)0x57, (uchar)0x51, (uchar)0xc0, (uchar)0x26, (uchar)0xe5, (uchar)0x43, (uchar)0xb2,
    (uchar)0xe8, (uchar)0xab, (uchar)0x2e, (uchar)0xb0, (uchar)0x60, (uchar)0x99, (uchar)0xda, (uchar)0xa1,
    (uchar)0xd1, (uchar)0xe5, (uchar)0xdf, (uchar)0x47, (uchar)0x77, (uchar)0x8f, (uchar)0x77, (uchar)0x87,
    (uchar)0xfa, (uchar)0xab, (uchar)0x45, (uchar)0xcd, (uchar)0xf1, (uchar)0x2f, (uchar)0xe3, (uchar)0xa8
};

// Expected Blake2b-256("abc") = bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
__constant uchar EXPECTED_ABC[32] = {
    (uchar)0xbd, (uchar)0xdd, (uchar)0x81, (uchar)0x3c, (uchar)0x63, (uchar)0x42, (uchar)0x39, (uchar)0x72,
    (uchar)0x31, (uchar)0x71, (uchar)0xef, (uchar)0x3f, (uchar)0xee, (uchar)0x98, (uchar)0x57, (uchar)0x9b,
    (uchar)0x94, (uchar)0x96, (uchar)0x4e, (uchar)0x3b, (uchar)0xb1, (uchar)0xcb, (uchar)0x3e, (uchar)0x42,
    (uchar)0x72, (uchar)0x62, (uchar)0xc8, (uchar)0xc0, (uchar)0x68, (uchar)0xd5, (uchar)0x23, (uchar)0x19
};

// Test kernel for Blake2b-256
__kernel void blake2b_test(
    __global const uchar* input,
    uint input_len,
    __global uchar* output
) {
    if (get_global_id(0) != 0u) return;

    // Copy input to private memory (zero-padded)
    uchar priv_input[128];
    for (uint i = 0u; i < 128u; i++) {
        priv_input[i] = (i < input_len) ? input[i] : 0u;
    }

    uchar hash[32];
    blake2b_256(priv_input, input_len, hash);

    for (int i = 0; i < 32; i++) {
        output[i] = hash[i];
    }
}

// Self-test kernel
// Returns 0 if all tests pass, non-zero otherwise (bit mask of failed tests)
__kernel void blake2b_self_test(__global uint* result) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;
    int eq;
    uchar hash[32];

    // Test 1: Blake2b-256("") - empty string
    uchar empty[1];
    blake2b_256(empty, 0u, hash);
    eq = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != EXPECTED_EMPTY[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 0);
    }

    // Test 2: Blake2b-256("abc")
    uchar abc[3];
    abc[0] = (uchar)'a';
    abc[1] = (uchar)'b';
    abc[2] = (uchar)'c';
    blake2b_256(abc, 3u, hash);
    eq = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != EXPECTED_ABC[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 1);
    }

    // Test 3: ergo_checksum produces first 4 bytes of hash
    // Use 34 bytes of test data
    uchar test_data[34];
    test_data[0] = 0x01u;  // mainnet P2PK prefix
    for (int i = 1; i < 34; i++) {
        test_data[i] = (uchar)i;
    }

    uchar full_hash[32];
    blake2b_256(test_data, 34u, full_hash);

    uchar checksum[4];
    ergo_checksum(test_data, checksum);

    eq = 1;
    for (int i = 0; i < 4; i++) {
        if (checksum[i] != full_hash[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 2);
    }

    *result = failures;
}
