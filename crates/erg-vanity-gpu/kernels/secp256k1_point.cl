// secp256k1_point.cl - Elliptic curve point operations in Jacobian coordinates
//
// secp256k1 curve: y² = x³ + 7 over GF(p)
// Jacobian: (X, Y, Z) represents affine (X/Z², Y/Z³)
// Point at infinity has Z = 0.
//
// Requires: secp256k1_fe.cl and secp256k1_scalar.cl to be concatenated before this.

// Generator point G (affine x-coordinate, big-endian bytes)
__constant uchar GX_BYTES[32] = {
    (uchar)0x79, (uchar)0xBE, (uchar)0x66, (uchar)0x7E, (uchar)0xF9, (uchar)0xDC, (uchar)0xBB, (uchar)0xAC,
    (uchar)0x55, (uchar)0xA0, (uchar)0x62, (uchar)0x95, (uchar)0xCE, (uchar)0x87, (uchar)0x0B, (uchar)0x07,
    (uchar)0x02, (uchar)0x9B, (uchar)0xFC, (uchar)0xDB, (uchar)0x2D, (uchar)0xCE, (uchar)0x28, (uchar)0xD9,
    (uchar)0x59, (uchar)0xF2, (uchar)0x81, (uchar)0x5B, (uchar)0x16, (uchar)0xF8, (uchar)0x17, (uchar)0x98
};

// Generator point G (affine y-coordinate, big-endian bytes)
__constant uchar GY_BYTES[32] = {
    (uchar)0x48, (uchar)0x3A, (uchar)0xDA, (uchar)0x77, (uchar)0x26, (uchar)0xA3, (uchar)0xC4, (uchar)0x65,
    (uchar)0x5D, (uchar)0xA4, (uchar)0xFB, (uchar)0xFC, (uchar)0x0E, (uchar)0x11, (uchar)0x08, (uchar)0xA8,
    (uchar)0xFD, (uchar)0x17, (uchar)0xB4, (uchar)0x48, (uchar)0xA6, (uchar)0x85, (uchar)0x54, (uchar)0x19,
    (uchar)0x9C, (uchar)0x47, (uchar)0xD0, (uchar)0x8F, (uchar)0xFB, (uchar)0x10, (uchar)0xD4, (uchar)0xB8
};

// G_TABLE[256] is concatenated from g_table.cl before this file.

// Point structure: 3 field elements (X, Y, Z) in Jacobian coordinates
// We pass points as arrays of 24 uints (3 * 8 limbs)
// Layout: [X[0..7], Y[0..7], Z[0..7]]

// Set point to infinity (Z = 0)
inline void pt_infinity(__private uint* p) {
    // X = 1, Y = 1, Z = 0
    fe_one(p);           // X
    fe_one(p + 8);       // Y
    fe_zero(p + 16);     // Z
}

// Check if point is at infinity
inline int pt_is_infinity(__private const uint* p) {
    return fe_is_zero(p + 16);  // Z == 0
}

// Copy point
inline void pt_copy(__private uint* r, __private const uint* p) {
    for (int i = 0; i < 24; i++) r[i] = p[i];
}

// Load generator point G
inline void pt_generator(__private uint* p) {
    fe_from_constant_bytes(p, GX_BYTES);       // X = Gx
    fe_from_constant_bytes(p + 8, GY_BYTES);   // Y = Gy
    fe_one(p + 16);                            // Z = 1 (affine point)
}

// Point doubling: r = 2*p
// Uses standard Jacobian doubling formulas for a=0 curves.
inline void pt_double(__private uint* r, __private const uint* p) {
    if (pt_is_infinity(p) || fe_is_zero(p + 8)) {
        pt_infinity(r);
        return;
    }

    __private const uint* px = p;
    __private const uint* py = p + 8;
    __private const uint* pz = p + 16;

    uint y2[8], s[8], m[8], x2[8];
    uint t1[8], t2[8];

    // Y²
    fe_sqr(y2, py);

    // S = 4*X*Y²
    fe_mul(s, px, y2);
    fe_add(s, s, s);  // 2*X*Y²
    fe_add(s, s, s);  // 4*X*Y²

    // M = 3*X² (since a=0 for secp256k1)
    fe_sqr(x2, px);
    fe_add(m, x2, x2);  // 2*X²
    fe_add(m, m, x2);   // 3*X²

    // X3 = M² - 2*S
    fe_sqr(t1, m);          // M²
    fe_sub(t1, t1, s);      // M² - S
    fe_sub(r, t1, s);       // M² - 2*S = X3

    // Y3 = M*(S - X3) - 8*Y⁴
    fe_sqr(t1, y2);         // Y⁴
    fe_add(t1, t1, t1);     // 2*Y⁴
    fe_add(t1, t1, t1);     // 4*Y⁴
    fe_add(t1, t1, t1);     // 8*Y⁴

    fe_sub(t2, s, r);       // S - X3
    fe_mul(t2, m, t2);      // M*(S - X3)
    fe_sub(r + 8, t2, t1);  // M*(S - X3) - 8*Y⁴ = Y3

    // Z3 = 2*Y*Z
    fe_mul(t1, py, pz);
    fe_add(r + 16, t1, t1); // 2*Y*Z = Z3
}

// Point addition: r = p1 + p2
// Uses standard Jacobian addition formulas.
inline void pt_add(__private uint* r, __private const uint* p1, __private const uint* p2) {
    if (pt_is_infinity(p1)) {
        pt_copy(r, p2);
        return;
    }
    if (pt_is_infinity(p2)) {
        pt_copy(r, p1);
        return;
    }

    __private const uint* x1 = p1;
    __private const uint* y1 = p1 + 8;
    __private const uint* z1 = p1 + 16;
    __private const uint* x2 = p2;
    __private const uint* y2 = p2 + 8;
    __private const uint* z2 = p2 + 16;

    uint z1_2[8], z2_2[8], z1_3[8], z2_3[8];
    uint u1[8], u2[8], s1[8], s2[8];
    uint h[8], rr[8], h2[8], h3[8];
    uint u1_h2[8], t1[8];

    // Z1², Z2²
    fe_sqr(z1_2, z1);
    fe_sqr(z2_2, z2);

    // Z1³, Z2³
    fe_mul(z1_3, z1_2, z1);
    fe_mul(z2_3, z2_2, z2);

    // U1 = X1*Z2², U2 = X2*Z1²
    fe_mul(u1, x1, z2_2);
    fe_mul(u2, x2, z1_2);

    // S1 = Y1*Z2³, S2 = Y2*Z1³
    fe_mul(s1, y1, z2_3);
    fe_mul(s2, y2, z1_3);

    // H = U2 - U1
    fe_sub(h, u2, u1);

    // R = S2 - S1
    fe_sub(rr, s2, s1);

    // If H = 0:
    if (fe_is_zero(h)) {
        if (fe_is_zero(rr)) {
            // Points are equal, do doubling
            pt_double(r, p1);
            return;
        } else {
            // Points are inverses, return infinity
            pt_infinity(r);
            return;
        }
    }

    // H², H³
    fe_sqr(h2, h);
    fe_mul(h3, h2, h);

    // U1*H²
    fe_mul(u1_h2, u1, h2);

    // X3 = R² - H³ - 2*U1*H²
    fe_sqr(t1, rr);          // R²
    fe_sub(t1, t1, h3);      // R² - H³
    fe_sub(t1, t1, u1_h2);   // R² - H³ - U1*H²
    fe_sub(r, t1, u1_h2);    // R² - H³ - 2*U1*H² = X3

    // Y3 = R*(U1*H² - X3) - S1*H³
    fe_sub(t1, u1_h2, r);    // U1*H² - X3
    fe_mul(t1, rr, t1);      // R*(U1*H² - X3)
    fe_mul(h3, s1, h3);      // S1*H³ (reuse h3)
    fe_sub(r + 8, t1, h3);   // Y3

    // Z3 = H*Z1*Z2
    fe_mul(t1, h, z1);
    fe_mul(r + 16, t1, z2);  // Z3
}

// Jacobian + affine add (p2 has Z=1). Table points are affine.
inline void pt_add_mixed(__private uint* r, __private const uint* p1, __private const uint* p2) {
    if (pt_is_infinity(p1)) {
        pt_copy(r, p2);
        return;
    }
    if (pt_is_infinity(p2)) {
        pt_copy(r, p1);
        return;
    }

    __private const uint* x1 = p1;
    __private const uint* y1 = p1 + 8;
    __private const uint* z1 = p1 + 16;
    __private const uint* x2 = p2;
    __private const uint* y2 = p2 + 8;

    uint z1_2[8], z1_3[8];
    uint u2[8], s2[8];
    uint h[8], rr[8], h2[8], h3[8];
    uint u1_h2[8], t1[8];

    fe_sqr(z1_2, z1);
    fe_mul(z1_3, z1_2, z1);
    fe_mul(u2, x2, z1_2);
    fe_mul(s2, y2, z1_3);

    fe_sub(h, u2, x1);
    fe_sub(rr, s2, y1);

    if (fe_is_zero(h)) {
        if (fe_is_zero(rr)) {
            pt_double(r, p1);
            return;
        }
        pt_infinity(r);
        return;
    }

    fe_sqr(h2, h);
    fe_mul(h3, h2, h);
    fe_mul(u1_h2, x1, h2);

    fe_sqr(t1, rr);
    fe_sub(t1, t1, h3);
    fe_sub(t1, t1, u1_h2);
    fe_sub(r, t1, u1_h2);

    fe_sub(t1, u1_h2, r);
    fe_mul(t1, rr, t1);
    fe_mul(h3, y1, h3);
    fe_sub(r + 8, t1, h3);

    fe_mul(r + 16, h, z1);
}

// Scalar multiplication: r = k * p
// Uses double-and-add algorithm, processing from LSB to MSB.
inline void pt_mul(__private uint* r, __private const uint* k, __private const uint* p) {
    if (sc_is_zero(k) || pt_is_infinity(p)) {
        pt_infinity(r);
        return;
    }

    uchar k_bytes[32];
    sc_to_bytes(k_bytes, k);

    uint result[24], base[24];
    uint tmp_add[24], tmp_dbl[24];  // Hoist outside loop to reduce register pressure
    pt_infinity(result);
    pt_copy(base, p);

    // Process from LSB to MSB
    for (int byte_idx = 31; byte_idx >= 0; byte_idx--) {
        uchar b = k_bytes[byte_idx];
        for (int bit = 0; bit < 8; bit++) {
            if (((b >> bit) & 1u) == 1u) {
                pt_add(tmp_add, result, base);
                pt_copy(result, tmp_add);
            }
            pt_double(tmp_dbl, base);
            pt_copy(base, tmp_dbl);
        }
    }

    pt_copy(r, result);
}

// 8-bit comb: COMB[w][b] = b · (2^{8*(31-w)} G), affine XY (16 uints).
// Window 0 = MSB of sc_to_bytes. b=0 is infinity (not stored).
#define COMB_XY_LIMBS 16u
#define COMB_WINDOW_STRIDE (256u * 16u)

inline void comb_select(
    __private uint* p,
    __global const uint* comb,
    uint window,
    uchar b
) {
    if (b == 0) {
        pt_infinity(p);
        return;
    }
    uint off = window * COMB_WINDOW_STRIDE + (uint)b * COMB_XY_LIMBS;
    for (int j = 0; j < 16; j++) p[j] = comb[off + (uint)j];
    fe_one(p + 16);
}

// k·G = T_0[k0] + … + T_31[k31]: 31 mixed adds, 0 doubles.
inline void pt_mul_generator_comb(
    __private uint* r,
    __private const uint* k,
    __global const uint* comb
) {
    uchar k_bytes[32];
    sc_to_bytes(k_bytes, k);

    uint buf0[24], buf1[24], selected[24];
    __private uint* acc = buf0;
    __private uint* tmp = buf1;

    comb_select(acc, comb, 0u, k_bytes[0]);
    for (int w = 1; w < 32; w++) {
        comb_select(selected, comb, (uint)w, k_bytes[w]);
        pt_add_mixed(tmp, acc, selected);
        { __private uint* swap = acc; acc = tmp; tmp = swap; }
    }

    pt_copy(r, acc);
}

inline void pt_mul_generator_table(
    __private uint* r,
    __private const uint* k,
    __local const uint* g_table
) {
    uchar k_bytes[32];
    sc_to_bytes(k_bytes, k);

    uint buf0[24], buf1[24], selected[24];
    __private uint* acc = buf0;
    __private uint* tmp = buf1;

    for (int j = 0; j < 24; j++) acc[j] = g_table[(uint)k_bytes[0] * 24u + (uint)j];

    for (int byte_idx = 1; byte_idx < 32; byte_idx++) {
        for (int i = 0; i < 8; i++) {
            pt_double(tmp, acc);
            __private uint* swap = acc; acc = tmp; tmp = swap;
        }
        for (int j = 0; j < 24; j++) {
            selected[j] = g_table[(uint)k_bytes[byte_idx] * 24u + (uint)j];
        }
        pt_add_mixed(tmp, acc, selected);
        { __private uint* swap = acc; acc = tmp; tmp = swap; }
    }

    pt_copy(r, acc);
}

inline void pt_mul_generator(__private uint* r, __private const uint* k) {
    uchar k_bytes[32];
    sc_to_bytes(k_bytes, k);

    uint buf0[24], buf1[24], selected[24];
    __private uint* acc = buf0;
    __private uint* tmp = buf1;

    for (int j = 0; j < 24; j++) acc[j] = G_TABLE[k_bytes[0]][j];

    for (int byte_idx = 1; byte_idx < 32; byte_idx++) {
        for (int i = 0; i < 8; i++) {
            pt_double(tmp, acc);
            __private uint* swap = acc; acc = tmp; tmp = swap;
        }
        for (int j = 0; j < 24; j++) selected[j] = G_TABLE[k_bytes[byte_idx]][j];
        pt_add_mixed(tmp, acc, selected);
        { __private uint* swap = acc; acc = tmp; tmp = swap; }
    }

    pt_copy(r, acc);
}

// Convert to affine coordinates
// Returns 0 on success, 1 if point is at infinity
inline int pt_to_affine(__private uint* x_out, __private uint* y_out, __private const uint* p) {
    if (pt_is_infinity(p)) {
        return 1;
    }

    __private const uint* px = p;
    __private const uint* py = p + 8;
    __private const uint* pz = p + 16;

    uint z_inv[8], z_inv2[8], z_inv3[8];
    fe_inv(z_inv, pz);
    fe_sqr(z_inv2, z_inv);
    fe_mul(z_inv3, z_inv2, z_inv);

    fe_mul(x_out, px, z_inv2);
    fe_mul(y_out, py, z_inv3);

    return 0;
}

// Get compressed public key (33 bytes) from point
// Format: 0x02 if y is even, 0x03 if y is odd, followed by 32-byte x
// Returns 0 on success, 1 if point is at infinity
inline int pt_to_compressed_pubkey(__private uchar* pubkey, __private const uint* p) {
    uint x[8], y[8];
    if (pt_to_affine(x, y, p) != 0) {
        return 1;
    }

    // Check if y is odd (look at least significant bit of least significant limb)
    pubkey[0] = (y[0] & 1u) ? (uchar)0x03 : (uchar)0x02;

    // Write x in big-endian
    fe_to_bytes(pubkey + 1, x);

    return 0;
}

// Private key (32 bytes) → compressed pubkey (33 bytes).
inline int priv_to_compressed_pubkey(
    __private const uchar* privkey,
    __private uchar* pubkey
) {
    uint limbs[8];
    sc_from_bytes(limbs, privkey);
    uint point[24];
    pt_mul_generator(point, limbs);
    return pt_to_compressed_pubkey(pubkey, point);
}

inline int priv_to_compressed_pubkey_table(
    __private const uchar* privkey,
    __private uchar* pubkey,
    __local const uint* g_table
) {
    uint limbs[8];
    sc_from_bytes(limbs, privkey);
    uint point[24];
    pt_mul_generator_table(point, limbs, g_table);
    return pt_to_compressed_pubkey(pubkey, point);
}

inline int priv_to_compressed_pubkey_comb(
    __private const uchar* privkey,
    __private uchar* pubkey,
    __global const uint* comb
) {
    uint limbs[8];
    sc_from_bytes(limbs, privkey);
    uint point[24];
    pt_mul_generator_comb(point, limbs, comb);
    return pt_to_compressed_pubkey(pubkey, point);
}
