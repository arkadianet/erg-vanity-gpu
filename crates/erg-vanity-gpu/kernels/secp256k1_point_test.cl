// secp256k1_point_test.cl - test kernel wrapper for point operations
//
// Expected to be concatenated after secp256k1_fe.cl, secp256k1_scalar.cl,
// and secp256k1_point.cl.

// Known result: 2*G x-coordinate (big-endian bytes)
// From k256 reference: 2*G.x = 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
__constant uchar TWO_G_X_BYTES[32] = {
    (uchar)0xc6, (uchar)0x04, (uchar)0x7f, (uchar)0x94, (uchar)0x41, (uchar)0xed, (uchar)0x7d, (uchar)0x6d,
    (uchar)0x30, (uchar)0x45, (uchar)0x40, (uchar)0x6e, (uchar)0x95, (uchar)0xc0, (uchar)0x7c, (uchar)0xd8,
    (uchar)0x5c, (uchar)0x77, (uchar)0x8e, (uchar)0x4b, (uchar)0x8c, (uchar)0xef, (uchar)0x3c, (uchar)0xa7,
    (uchar)0xab, (uchar)0xac, (uchar)0x09, (uchar)0xb9, (uchar)0x5c, (uchar)0x70, (uchar)0x9e, (uchar)0xe5
};

// Known result: 3*G x-coordinate (big-endian bytes)
// From k256 reference: 3*G.x = 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
__constant uchar THREE_G_X_BYTES[32] = {
    (uchar)0xf9, (uchar)0x30, (uchar)0x8a, (uchar)0x01, (uchar)0x92, (uchar)0x58, (uchar)0xc3, (uchar)0x10,
    (uchar)0x49, (uchar)0x34, (uchar)0x4f, (uchar)0x85, (uchar)0xf8, (uchar)0x9d, (uchar)0x52, (uchar)0x29,
    (uchar)0xb5, (uchar)0x31, (uchar)0xc8, (uchar)0x45, (uchar)0x83, (uchar)0x6f, (uchar)0x99, (uchar)0xb0,
    (uchar)0x86, (uchar)0x01, (uchar)0xf1, (uchar)0x13, (uchar)0xbc, (uchar)0xe0, (uchar)0x36, (uchar)0xf9
};

// Comprehensive self-test kernel for point operations
// Returns 0 if all tests pass, non-zero otherwise (bit mask of failed tests)
__kernel void pt_self_test(__global uint* result) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;
    int eq;

    uint g[24], inf[24];
    pt_generator(g);
    pt_infinity(inf);

    // Test 1: G is not at infinity
    if (pt_is_infinity(g)) {
        failures |= (1u << 0);
    }

    // Test 2: infinity is at infinity
    if (!pt_is_infinity(inf)) {
        failures |= (1u << 1);
    }

    // Get G in affine form for comparisons
    uint gx[8], gy[8];
    int g_affine_ok = (pt_to_affine(gx, gy, g) == 0);
    if (!g_affine_ok) {
        failures |= (1u << 14);  // G affine conversion failed
        *result = failures;
        return;
    }

    // Test 3: G + infinity = G
    uint tmp[24];
    pt_add(tmp, g, inf);
    uint tmpx[8], tmpy[8];
    if (pt_to_affine(tmpx, tmpy, tmp) != 0) {
        failures |= (1u << 2);
    } else {
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (gx[i] != tmpx[i] || gy[i] != tmpy[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 2);
        }
    }

    // Test 4: infinity + G = G
    pt_add(tmp, inf, g);
    if (pt_to_affine(tmpx, tmpy, tmp) != 0) {
        failures |= (1u << 3);
    } else {
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (gx[i] != tmpx[i] || gy[i] != tmpy[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 3);
        }
    }

    // Test 5: G + G = 2G (via addition) equals double(G) (via doubling)
    uint two_g_add[24];
    pt_add(two_g_add, g, g);
    uint two_g_dbl[24];
    pt_double(two_g_dbl, g);

    uint x1[8], y1[8], x2[8], y2[8];
    if (pt_to_affine(x1, y1, two_g_add) != 0 || pt_to_affine(x2, y2, two_g_dbl) != 0) {
        failures |= (1u << 4);
    } else {
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (x1[i] != x2[i] || y1[i] != y2[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 4);
        }
    }

    // Test 6: 2G matches known x-coordinate (only if Test 5 succeeded)
    if ((failures & (1u << 4)) == 0u) {
        uint two_g_x_expected[8];
        fe_from_constant_bytes(two_g_x_expected, TWO_G_X_BYTES);
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (x2[i] != two_g_x_expected[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 5);
        }
    }

    // Test 7: 1 * G = G (scalar mult identity)
    uint one[8];
    sc_one(one);
    uint one_g[24];
    pt_mul(one_g, one, g);
    if (pt_to_affine(tmpx, tmpy, one_g) != 0) {
        failures |= (1u << 6);
    } else {
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (gx[i] != tmpx[i] || gy[i] != tmpy[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 6);
        }
    }

    // Test 8: 2 * G matches double(G)
    uint two[8];
    sc_zero(two);
    two[0] = 2u;
    uint two_g_mul[24];
    pt_mul(two_g_mul, two, g);
    if (pt_to_affine(x1, y1, two_g_mul) != 0) {
        failures |= (1u << 7);
    } else {
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (x1[i] != x2[i] || y1[i] != y2[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 7);
        }
    }

    // Test 9: 3 * G matches known x-coordinate
    uint three[8];
    sc_zero(three);
    three[0] = 3u;
    uint three_g[24];
    pt_mul(three_g, three, g);
    uint three_g_x[8], three_g_y[8];
    if (pt_to_affine(three_g_x, three_g_y, three_g) != 0) {
        failures |= (1u << 8);
    } else {
        uint three_g_x_expected[8];
        fe_from_constant_bytes(three_g_x_expected, THREE_G_X_BYTES);
        eq = 1;
        for (int i = 0; i < 8; i++) {
            if (three_g_x[i] != three_g_x_expected[i]) eq = 0;
        }
        if (!eq) {
            failures |= (1u << 8);
        }
    }

    // Test 10: 0 * G = infinity
    uint zero[8];
    sc_zero(zero);
    uint zero_g[24];
    pt_mul(zero_g, zero, g);
    if (!pt_is_infinity(zero_g)) {
        failures |= (1u << 9);
    }

    // Test 11: G is on the curve (y² = x³ + 7)
    uint gy2[8], gx3[8], b[8], gx3_plus_b[8];
    fe_sqr(gy2, gy);
    fe_sqr(gx3, gx);
    fe_mul(gx3, gx3, gx);
    fe_zero(b);
    b[0] = 7u;
    fe_add(gx3_plus_b, gx3, b);
    eq = 1;
    for (int i = 0; i < 8; i++) {
        if (gy2[i] != gx3_plus_b[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 10);
    }

    // Test 12: pt_to_compressed_pubkey returns success
    uchar pubkey[33];
    int err = pt_to_compressed_pubkey(pubkey, g);
    if (err != 0) {
        failures |= (1u << 11);
    }

    // Test 13: compressed pubkey prefix is 0x02 or 0x03
    if (pubkey[0] != (uchar)0x02 && pubkey[0] != (uchar)0x03) {
        failures |= (1u << 12);
    }

    // Test 14: compressed pubkey x bytes match Gx
    uchar gx_bytes[32];
    fe_to_bytes(gx_bytes, gx);
    eq = 1;
    for (int i = 0; i < 32; i++) {
        if (pubkey[i + 1] != gx_bytes[i]) eq = 0;
    }
    if (!eq) {
        failures |= (1u << 13);
    }

    *result = failures;
}
