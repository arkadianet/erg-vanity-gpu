// secp256k1_scalar.cl - Scalar arithmetic modulo curve order n
//
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// Uses 8x32-bit limbs in little-endian order.
// Standalone module (no dependencies on secp256k1_fe.cl).
//
// Note: sc_mul uses bit-by-bit reduction (1024 modular adds). Slow reference impl.

// Curve order n as 8x32-bit limbs (little-endian)
__constant uint SECP256K1_N[8] = {
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// 2^256 - n (for handling overflow in addition)
// Used when a + b >= 2^256: result = (a + b) mod n = low_256_bits + K
__constant uint SECP256K1_K[8] = {
    0x2FC9BEBFu, 0x402DA173u, 0x50B75FC4u, 0x45512319u,
    0x00000001u, 0u, 0u, 0u
};

// Zero scalar
inline void sc_zero(__private uint* r) {
    for (int i = 0; i < 8; i++) r[i] = 0u;
}

// One scalar
inline void sc_one(__private uint* r) {
    r[0] = 1u;
    for (int i = 1; i < 8; i++) r[i] = 0u;
}

// Copy scalar
inline void sc_copy(__private uint* r, __private const uint* a) {
    for (int i = 0; i < 8; i++) r[i] = a[i];
}

// Check if scalar is zero
inline int sc_is_zero(__private const uint* a) {
    uint acc = 0u;
    for (int i = 0; i < 8; i++) acc |= a[i];
    return acc == 0u;
}

// Check if a >= n (returns 1 if true, 0 if false)
inline int sc_gte_n(__private const uint* a) {
    // Compare from high to low limb
    for (int i = 7; i >= 0; i--) {
        if (a[i] > SECP256K1_N[i]) return 1;
        if (a[i] < SECP256K1_N[i]) return 0;
    }
    return 1; // Equal to n
}

// Subtract n from a: r = a - n
// Assumes a >= n
inline void sc_sub_n(__private uint* r, __private const uint* a) {
    ulong borrow = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong bi = (ulong)SECP256K1_N[i] + borrow;
        ulong ai = (ulong)a[i];
        ulong diff = ai - bi;
        r[i] = (uint)(diff & 0xFFFFFFFFul);
        borrow = (ai < bi) ? 1ul : 0ul;
    }
}

// Add n to a: r = a + n
inline void sc_add_n(__private uint* r, __private const uint* a) {
    ulong carry = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a[i] + (ulong)SECP256K1_N[i] + carry;
        r[i] = (uint)(sum & 0xFFFFFFFFul);
        carry = sum >> 32;
    }
}

// Add K (2^256 - n) to a: r = a + K
inline void sc_add_k(__private uint* r, __private const uint* a) {
    ulong carry = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a[i] + (ulong)SECP256K1_K[i] + carry;
        r[i] = (uint)(sum & 0xFFFFFFFFul);
        carry = sum >> 32;
    }
}

// Scalar addition: r = a + b (mod n)
inline void sc_add(__private uint* r, __private const uint* a, __private const uint* b) {
    ulong carry = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a[i] + (ulong)b[i] + carry;
        r[i] = (uint)(sum & 0xFFFFFFFFul);
        carry = sum >> 32;
    }

    if (carry == 0ul) {
        // No overflow: just check if r >= n
        if (sc_gte_n(r)) {
            sc_sub_n(r, r);
        }
    } else {
        // Overflow: S = r + 2^256, so S mod n = r + (2^256 - n) = r + K
        sc_add_k(r, r);
        // Defensive: handle non-canonical inputs
        if (sc_gte_n(r)) {
            sc_sub_n(r, r);
        }
    }
}

// Scalar subtraction: r = a - b (mod n)
inline void sc_sub(__private uint* r, __private const uint* a, __private const uint* b) {
    ulong borrow = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong bi = (ulong)b[i] + borrow;
        ulong ai = (ulong)a[i];
        ulong diff = ai - bi;
        r[i] = (uint)(diff & 0xFFFFFFFFul);
        borrow = (ai < bi) ? 1ul : 0ul;
    }

    // If borrowed, add n back
    if (borrow != 0ul) {
        sc_add_n(r, r);
    }
}

// Scalar negation: r = -a (mod n)
inline void sc_neg(__private uint* r, __private const uint* a) {
    if (sc_is_zero(a)) {
        sc_zero(r);
        return;
    }

    // r = n - a
    ulong borrow = 0ul;
    for (int i = 0; i < 8; i++) {
        ulong ai = (ulong)a[i] + borrow;
        ulong ni = (ulong)SECP256K1_N[i];
        ulong diff = ni - ai;
        r[i] = (uint)(diff & 0xFFFFFFFFul);
        borrow = (ni < ai) ? 1ul : 0ul;
    }
}

// Load scalar from big-endian bytes
inline void sc_from_bytes(__private uint* r, __private const uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        r[i] = ((uint)bytes[off] << 24) |
               ((uint)bytes[off + 1] << 16) |
               ((uint)bytes[off + 2] << 8) |
               ((uint)bytes[off + 3]);
    }
}

// Store scalar to big-endian bytes
inline void sc_to_bytes(__private uchar* bytes, __private const uint* a) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        bytes[off] = (uchar)(a[i] >> 24);
        bytes[off + 1] = (uchar)(a[i] >> 16);
        bytes[off + 2] = (uchar)(a[i] >> 8);
        bytes[off + 3] = (uchar)(a[i]);
    }
}

// Scalar multiplication: r = a * b (mod n)
// NOTE: Uses bit-by-bit reduction (1024 modular adds). Slow reference impl.
inline void sc_mul(__private uint* r, __private const uint* a, __private const uint* b) {
    // 512-bit product in 16x32-bit limbs
    uint wide[16];
    for (int i = 0; i < 16; i++) wide[i] = 0u;

    // Schoolbook multiplication with 64-bit accumulator
    for (int i = 0; i < 8; i++) {
        ulong carry = 0ul;
        for (int j = 0; j < 8; j++) {
            int idx = i + j;
            ulong prod = (ulong)a[i] * (ulong)b[j];
            ulong sum = (ulong)wide[idx] + prod + carry;
            wide[idx] = (uint)(sum & 0xFFFFFFFFul);
            carry = sum >> 32;
        }
        // Propagate remaining carry
        int k = i + 8;
        while (carry != 0ul && k < 16) {
            ulong sum = (ulong)wide[k] + carry;
            wide[k] = (uint)(sum & 0xFFFFFFFFul);
            carry = sum >> 32;
            k++;
        }
    }

    // Bit-by-bit reduction: rem = (rem * 2 + bit) mod n
    // Process 512 bits from MSB to LSB
    uint rem[8];
    sc_zero(rem);

    uint one[8];
    sc_one(one);

    for (int limb_idx = 15; limb_idx >= 0; limb_idx--) {
        uint limb = wide[limb_idx];
        for (int bit_idx = 31; bit_idx >= 0; bit_idx--) {
            // rem = rem * 2 = rem + rem
            sc_add(rem, rem, rem);

            // If bit is set, rem = rem + 1
            if (((limb >> bit_idx) & 1u) == 1u) {
                sc_add(rem, rem, one);
            }
        }
    }

    sc_copy(r, rem);
}

// Scalar squaring: r = a^2 (mod n)
inline void sc_sqr(__private uint* r, __private const uint* a) {
    sc_mul(r, a, a);
}
