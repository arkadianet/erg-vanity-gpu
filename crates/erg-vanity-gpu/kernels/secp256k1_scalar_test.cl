// secp256k1_scalar_test.cl - test kernel wrapper for scalar arithmetic
//
// Expected to be concatenated after secp256k1_scalar.cl in the program source.

// Test vectors as file-scope constants
// n-1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
__constant uchar N_MINUS_1_BYTES[32] = {
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF,
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFE,
    (uchar)0xBA, (uchar)0xAE, (uchar)0xDC, (uchar)0xE6, (uchar)0xAF, (uchar)0x48, (uchar)0xA0, (uchar)0x3B,
    (uchar)0xBF, (uchar)0xD2, (uchar)0x5E, (uchar)0x8C, (uchar)0xD0, (uchar)0x36, (uchar)0x41, (uchar)0x40
};

// Test value A = 0xDEADBEEF...
__constant uchar SC_TEST_A_BYTES[32] = {
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE
};

// Test value B = 0x12345678...
__constant uchar SC_TEST_B_BYTES[32] = {
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF
};

// Helper: copy from __constant to __private
inline void sc_from_constant_bytes(__private uint* r, __constant const uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        r[i] = ((uint)bytes[off] << 24) |
               ((uint)bytes[off + 1] << 16) |
               ((uint)bytes[off + 2] << 8) |
               ((uint)bytes[off + 3]);
    }
}

// Comprehensive self-test kernel for scalar arithmetic
// Returns 0 if all tests pass, non-zero otherwise (bit mask of failed tests)
__kernel void sc_self_test(__global uint* result) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;

    uint one[8], zero[8], n_minus_1[8], tmp[8], tmp2[8];
    sc_one(one);
    sc_zero(zero);
    sc_from_constant_bytes(n_minus_1, N_MINUS_1_BYTES);

    // Test 1: 1 + 0 == 1
    sc_add(tmp, one, zero);
    int eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != one[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 0);
    }

    // Test 2: (n-1) + 1 == 0 (mod n)
    sc_add(tmp, n_minus_1, one);
    if (!sc_is_zero(tmp)) {
        failures |= (1u << 1);
    }

    // Test 3: 0 - 1 == n-1 (mod n)
    sc_sub(tmp, zero, one);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != n_minus_1[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 2);
    }

    // Test 4: -1 == n-1 (mod n)
    sc_neg(tmp, one);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != n_minus_1[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 3);
    }

    // Test 5: a + (-a) == 0
    uint test_a[8];
    sc_from_constant_bytes(test_a, SC_TEST_A_BYTES);
    sc_neg(tmp, test_a);
    sc_add(tmp2, test_a, tmp);
    if (!sc_is_zero(tmp2)) {
        failures |= (1u << 4);
    }

    // Test 6: (a + b) - b == a
    uint test_b[8];
    sc_from_constant_bytes(test_b, SC_TEST_B_BYTES);
    sc_add(tmp, test_a, test_b);
    sc_sub(tmp2, tmp, test_b);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp2[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 5);
    }

    // Test 7: (a - b) + b == a
    sc_sub(tmp, test_a, test_b);
    sc_add(tmp2, tmp, test_b);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp2[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 6);
    }

    // Test 8: -(-a) == a
    sc_neg(tmp, test_a);
    sc_neg(tmp2, tmp);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp2[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 7);
    }

    // Test 9: 2 * 3 == 6
    uint two[8], three[8], six[8];
    sc_zero(two); two[0] = 2u;
    sc_zero(three); three[0] = 3u;
    sc_zero(six); six[0] = 6u;
    sc_mul(tmp, two, three);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != six[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 8);
    }

    // Test 10: a * b == b * a (commutativity)
    uint ab[8], ba[8];
    sc_mul(ab, test_a, test_b);
    sc_mul(ba, test_b, test_a);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (ab[i] != ba[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 9);
    }

    // Test 11: 1 * a == a
    sc_mul(tmp, one, test_a);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 10);
    }

    // Test 12: 0 * a == 0
    sc_mul(tmp, zero, test_a);
    if (!sc_is_zero(tmp)) {
        failures |= (1u << 11);
    }

    // Test 13: (n-1) + (n-1) == n-2 (overflow path: forces carry=1)
    uint n_minus_2[8];
    sc_sub(n_minus_2, n_minus_1, one);     // n-2
    sc_add(tmp, n_minus_1, n_minus_1);     // should overflow internally
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != n_minus_2[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 12);
    }

    // Test 14: (n-1) * (n-1) == 1  (since (-1)^2 = 1 mod n)
    sc_mul(tmp, n_minus_1, n_minus_1);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != one[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 13);
    }

    *result = failures;
}
