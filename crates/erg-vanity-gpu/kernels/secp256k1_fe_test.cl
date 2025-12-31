// secp256k1_fe_test.cl - test kernel wrapper for field arithmetic
//
// Expected to be concatenated after secp256k1_fe.cl in the program source.

// Test vectors as file-scope constants for portability
// p-1 = 0xFFFFFFFF...FFFFFFFE FFFFFC2E
__constant uchar P_MINUS_1_BYTES[32] = {
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF,
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF,
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFF,
    (uchar)0xFF, (uchar)0xFF, (uchar)0xFF, (uchar)0xFE, (uchar)0xFF, (uchar)0xFF, (uchar)0xFC, (uchar)0x2E
};

// Test value A = 0xDEADBEEF...
__constant uchar TEST_A_BYTES[32] = {
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE,
    (uchar)0xDE, (uchar)0xAD, (uchar)0xBE, (uchar)0xEF, (uchar)0xCA, (uchar)0xFE, (uchar)0xBA, (uchar)0xBE
};

// Test value B = 0x12345678...
__constant uchar TEST_B_BYTES[32] = {
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF,
    (uchar)0x12, (uchar)0x34, (uchar)0x56, (uchar)0x78, (uchar)0x90, (uchar)0xAB, (uchar)0xCD, (uchar)0xEF
};

// Test operations
#define FE_TEST_MUL     0u
#define FE_TEST_SQR     1u
#define FE_TEST_ADD     2u
#define FE_TEST_SUB     3u
#define FE_TEST_NEG     4u
#define FE_TEST_INV     5u

// Test kernel for field arithmetic
// Performs one operation on two 32-byte inputs, writes 32-byte output
__kernel void fe_test(
    uint operation,
    __global const uchar* input_a,
    __global const uchar* input_b,
    __global uchar* output
) {
    if (get_global_id(0) != 0u) return;

    uchar priv_a[32];
    uchar priv_b[32];
    for (int i = 0; i < 32; i++) {
        priv_a[i] = input_a[i];
        priv_b[i] = input_b[i];
    }

    uint a[8], b[8], r[8];
    fe_from_bytes(a, priv_a);
    fe_from_bytes(b, priv_b);

    switch (operation) {
        case FE_TEST_MUL:
            fe_mul(r, a, b);
            break;
        case FE_TEST_SQR:
            fe_sqr(r, a);
            break;
        case FE_TEST_ADD:
            fe_add(r, a, b);
            break;
        case FE_TEST_SUB:
            fe_sub(r, a, b);
            break;
        case FE_TEST_NEG:
            fe_neg(r, a);
            break;
        case FE_TEST_INV:
            fe_inv(r, a);
            break;
        default:
            fe_zero(r);
            break;
    }

    uchar result[32];
    fe_to_bytes(result, r);
    for (int i = 0; i < 32; i++) {
        output[i] = result[i];
    }
}

// Comprehensive self-test kernel
// Returns 0 if all tests pass, non-zero otherwise (bit mask of failed tests)
// Bit 31: overflow detected during checked multiply
__kernel void fe_self_test(__global uint* result) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;
    uint any_mul_error = 0u;

    uint one[8], p_minus_1[8], tmp[8], tmp2[8];
    fe_one(one);
    fe_from_constant_bytes(p_minus_1, P_MINUS_1_BYTES);

    // Test 1: 1 * 1 == 1
    fe_mul_checked(tmp, one, one, &any_mul_error);
    if (tmp[0] != 1u || tmp[1] != 0u || tmp[2] != 0u || tmp[3] != 0u ||
        tmp[4] != 0u || tmp[5] != 0u || tmp[6] != 0u || tmp[7] != 0u) {
        failures |= (1u << 0);
    }

    // Test 2: (p-1) + 1 == 0 (mod p)
    fe_add(tmp, p_minus_1, one);
    if (!fe_is_zero(tmp)) {
        failures |= (1u << 1);
    }

    // Test 3: (p-1) * (p-1) == 1 (mod p)
    // Because (p-1) ≡ -1, and (-1)^2 = 1
    fe_mul_checked(tmp, p_minus_1, p_minus_1, &any_mul_error);
    if (tmp[0] != 1u || tmp[1] != 0u || tmp[2] != 0u || tmp[3] != 0u ||
        tmp[4] != 0u || tmp[5] != 0u || tmp[6] != 0u || tmp[7] != 0u) {
        failures |= (1u << 2);
    }

    // Test 4: inv(1) == 1
    fe_inv(tmp, one);
    if (tmp[0] != 1u || tmp[1] != 0u || tmp[2] != 0u || tmp[3] != 0u ||
        tmp[4] != 0u || tmp[5] != 0u || tmp[6] != 0u || tmp[7] != 0u) {
        failures |= (1u << 3);
    }

    // Test 5: inv(p-1) == p-1
    fe_inv(tmp, p_minus_1);
    int eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp[i] != p_minus_1[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 4);
    }

    // Test 6: a * inv(a) == 1 for a = 2
    uint two[8];
    fe_zero(two);
    two[0] = 2u;
    fe_inv(tmp, two);
    fe_mul_checked(tmp2, two, tmp, &any_mul_error);
    if (tmp2[0] != 1u || tmp2[1] != 0u || tmp2[2] != 0u || tmp2[3] != 0u ||
        tmp2[4] != 0u || tmp2[5] != 0u || tmp2[6] != 0u || tmp2[7] != 0u) {
        failures |= (1u << 5);
    }

    // Test 7: a * inv(a) == 1 for a = 0xdeadbeef...
    uint test_a[8];
    fe_from_constant_bytes(test_a, TEST_A_BYTES);
    fe_inv(tmp, test_a);
    fe_mul_checked(tmp2, test_a, tmp, &any_mul_error);
    if (tmp2[0] != 1u || tmp2[1] != 0u || tmp2[2] != 0u || tmp2[3] != 0u ||
        tmp2[4] != 0u || tmp2[5] != 0u || tmp2[6] != 0u || tmp2[7] != 0u) {
        failures |= (1u << 6);
    }

    // Test 8: (a + b) - b == a
    uint test_b[8];
    fe_from_constant_bytes(test_b, TEST_B_BYTES);
    fe_add(tmp, test_a, test_b);
    fe_sub(tmp2, tmp, test_b);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp2[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 7);
    }

    // Test 9: -(-a) == a
    fe_neg(tmp, test_a);
    fe_neg(tmp2, tmp);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (tmp2[i] != test_a[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 8);
    }

    // Test 10: a * b == b * a (commutativity)
    uint ab[8], ba[8];
    fe_mul_checked(ab, test_a, test_b, &any_mul_error);
    fe_mul_checked(ba, test_b, test_a, &any_mul_error);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (ab[i] != ba[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 9);
    }

    // Bit 31: any overflow detected during checked multiplies
    if (any_mul_error != 0u) {
        failures |= (1u << 31);
    }

    *result = failures;
}
