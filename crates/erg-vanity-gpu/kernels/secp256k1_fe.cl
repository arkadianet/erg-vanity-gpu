// secp256k1 field arithmetic for OpenCL
//
// Field element: 256-bit integer mod p
// p = 2^256 - 2^32 - 977 = 0xFFFFFFFF...FFFFFFFE FFFFFC2F
//
// Representation: 8 x 32-bit limbs, little-endian (limb 0 is least significant)
//
// Key reduction identity: 2^256 ≡ 2^32 + 977 (mod p)

// The secp256k1 field prime in 8 limbs (little-endian)
#define FE_P0 0xFFFFFC2Fu
#define FE_P1 0xFFFFFFFEu
#define FE_P2 0xFFFFFFFFu
#define FE_P3 0xFFFFFFFFu
#define FE_P4 0xFFFFFFFFu
#define FE_P5 0xFFFFFFFFu
#define FE_P6 0xFFFFFFFFu
#define FE_P7 0xFFFFFFFFu

// Reduction constant: 2^256 ≡ 2^32 + 977 (mod p)
#define FE_R_LOW 977ul

// Copy field element
inline void fe_copy(__private uint* dst, __private const uint* src) {
    for (int i = 0; i < 8; i++) {
        dst[i] = src[i];
    }
}

// Set to zero
inline void fe_zero(__private uint* r) {
    for (int i = 0; i < 8; i++) {
        r[i] = 0u;
    }
}

// Set to one
inline void fe_one(__private uint* r) {
    r[0] = 1u;
    for (int i = 1; i < 8; i++) {
        r[i] = 0u;
    }
}

// Check if zero
inline bool fe_is_zero(__private const uint* a) {
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0u;
}

// Compare a >= p (returns 1 if true, 0 if false)
inline uint fe_gte_p(__private const uint* a) {
    if (a[7] > FE_P7) return 1u;
    if (a[7] < FE_P7) return 0u;
    if (a[6] > FE_P6) return 1u;
    if (a[6] < FE_P6) return 0u;
    if (a[5] > FE_P5) return 1u;
    if (a[5] < FE_P5) return 0u;
    if (a[4] > FE_P4) return 1u;
    if (a[4] < FE_P4) return 0u;
    if (a[3] > FE_P3) return 1u;
    if (a[3] < FE_P3) return 0u;
    if (a[2] > FE_P2) return 1u;
    if (a[2] < FE_P2) return 0u;
    if (a[1] > FE_P1) return 1u;
    if (a[1] < FE_P1) return 0u;
    if (a[0] >= FE_P0) return 1u;
    return 0u;
}

// Subtract p from a: r = a - p (assumes a >= p)
inline void fe_sub_p(__private uint* r, __private const uint* a) {
    ulong borrow = 0ul;
    ulong diff;

    diff = (ulong)a[0] - (ulong)FE_P0 - borrow;
    r[0] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[1] - (ulong)FE_P1 - borrow;
    r[1] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[2] - (ulong)FE_P2 - borrow;
    r[2] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[3] - (ulong)FE_P3 - borrow;
    r[3] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[4] - (ulong)FE_P4 - borrow;
    r[4] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[5] - (ulong)FE_P5 - borrow;
    r[5] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[6] - (ulong)FE_P6 - borrow;
    r[6] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)a[7] - (ulong)FE_P7 - borrow;
    r[7] = (uint)diff;
}

// Add p to a: r = a + p
inline void fe_add_p(__private uint* r, __private const uint* a) {
    ulong carry = 0ul;
    ulong sum;

    sum = (ulong)a[0] + (ulong)FE_P0 + carry;
    r[0] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[1] + (ulong)FE_P1 + carry;
    r[1] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[2] + (ulong)FE_P2 + carry;
    r[2] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[3] + (ulong)FE_P3 + carry;
    r[3] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[4] + (ulong)FE_P4 + carry;
    r[4] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[5] + (ulong)FE_P5 + carry;
    r[5] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[6] + (ulong)FE_P6 + carry;
    r[6] = (uint)sum;
    carry = sum >> 32;

    sum = (ulong)a[7] + (ulong)FE_P7 + carry;
    r[7] = (uint)sum;
}

// Normalize: reduce to [0, p) with exactly two conditional subtractions
inline void fe_normalize(__private uint* a) {
    uint tmp[8];

    if (fe_gte_p(a)) {
        fe_sub_p(tmp, a);
        fe_copy(a, tmp);
    }

    if (fe_gte_p(a)) {
        fe_sub_p(tmp, a);
        fe_copy(a, tmp);
    }
}

// Addition: r = a + b mod p
inline void fe_add(__private uint* r, __private const uint* a, __private const uint* b) {
    ulong carry = 0ul;

    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a[i] + (ulong)b[i] + carry;
        r[i] = (uint)sum;
        carry = sum >> 32;
    }

    // If carry, reduce: carry * 2^256 ≡ carry * (2^32 + 977)
    if (carry) {
        ulong c = (ulong)r[0] + FE_R_LOW;
        r[0] = (uint)c;
        c = (ulong)r[1] + (c >> 32) + 1ul;
        r[1] = (uint)c;
        c >>= 32;

        for (int i = 2; i < 8; i++) {
            c += (ulong)r[i];
            r[i] = (uint)c;
            c >>= 32;
        }
    }

    fe_normalize(r);
}

// Subtraction: r = a - b mod p
inline void fe_sub(__private uint* r, __private const uint* a, __private const uint* b) {
    ulong borrow = 0ul;

    for (int i = 0; i < 8; i++) {
        ulong diff = (ulong)a[i] - (ulong)b[i] - borrow;
        r[i] = (uint)diff;
        borrow = (diff >> 63) & 1ul;
    }

    if (borrow) {
        fe_add_p(r, r);
    }
}

// Negation: r = -a mod p
inline void fe_neg(__private uint* r, __private const uint* a) {
    if (fe_is_zero(a)) {
        fe_zero(r);
        return;
    }

    ulong borrow = 0ul;
    ulong diff;

    diff = (ulong)FE_P0 - (ulong)a[0] - borrow;
    r[0] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P1 - (ulong)a[1] - borrow;
    r[1] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P2 - (ulong)a[2] - borrow;
    r[2] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P3 - (ulong)a[3] - borrow;
    r[3] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P4 - (ulong)a[4] - borrow;
    r[4] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P5 - (ulong)a[5] - borrow;
    r[5] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P6 - (ulong)a[6] - borrow;
    r[6] = (uint)diff;
    borrow = (diff >> 63) & 1ul;

    diff = (ulong)FE_P7 - (ulong)a[7] - borrow;
    r[7] = (uint)diff;
}

// Helper: propagate carries through u[0..9]
// Returns carry out of u[9] (should be 0 for valid inputs)
inline ulong fe_propagate_10(__private ulong* u) {
    ulong c = 0ul;
    for (int i = 0; i < 10; i++) {
        u[i] += c;
        c = u[i] >> 32;
        u[i] &= 0xFFFFFFFFul;
    }
    return c;
}

// Debug version: accumulates error flag if carry escapes limb 9
// Uses |= to accumulate, caller should init error_flag to 0 before first call
inline ulong fe_propagate_10_checked(__private ulong* u, __private uint* error_flag) {
    ulong c = fe_propagate_10(u);
    if (c != 0ul) {
        *error_flag |= 1u;
    }
    return c;
}

// Helper: fold u[8] and u[9] into lower limbs
// u[8] (limb8): contributes 977*u[8] to u[0], u[8] to u[1]
// u[9] (limb9): contributes 977*u[9] to u[1], u[9] to u[2]
inline void fe_fold_high(__private ulong* u) {
    ulong u8 = u[8];
    ulong u9 = u[9];
    u[8] = 0ul;
    u[9] = 0ul;

    u[0] += u8 * FE_R_LOW;
    u[1] += u8;
    u[1] += u9 * FE_R_LOW;
    u[2] += u9;
}

// Multiplication: r = a * b mod p
//
// Uses column-by-column accumulation with simulated 128-bit accumulator,
// then reduces using the identity 2^256 ≡ 2^32 + 977 (mod p).
inline void fe_mul(__private uint* r, __private const uint* a, __private const uint* b) {
    // === Phase 1: Column-by-column 512-bit multiply ===
    uint t[16];

    ulong carry_lo = 0ul;
    ulong carry_hi = 0ul;

    for (int k = 0; k < 16; k++) {
        ulong acc_lo = carry_lo;
        ulong acc_hi = carry_hi;

        int i_min = (k > 7) ? (k - 7) : 0;
        int i_max = (k < 8) ? k : 7;

        for (int i = i_min; i <= i_max; i++) {
            int j = k - i;
            ulong prod = (ulong)a[i] * (ulong)b[j];

            ulong old_lo = acc_lo;
            acc_lo += prod;
            acc_hi += (acc_lo < old_lo);
        }

        t[k] = (uint)(acc_lo & 0xFFFFFFFFul);
        carry_lo = (acc_lo >> 32) | (acc_hi << 32);
        carry_hi = acc_hi >> 32;
    }

    // === Phase 2: Reduction using 10-limb working array ===
    //
    // For high limb t[k] (k = 8..15):
    //   t[k] * 2^(32*k) = t[k] * 2^(32*(k-8)) * 2^256
    //                   ≡ t[k] * 2^(32*(k-8)) * (2^32 + 977) (mod p)
    //
    // This contributes:
    //   + 977 * t[k] to limb (k-8)
    //   + t[k] to limb (k-7)

    ulong u[10];
    for (int i = 0; i < 8; i++) {
        u[i] = (ulong)t[i];
    }
    u[8] = 0ul;
    u[9] = 0ul;

    // Fold each high limb into u
    for (int k = 8; k < 16; k++) {
        ulong hk = (ulong)t[k];
        u[k - 8] += hk * FE_R_LOW;
        u[k - 7] += hk;
    }

    // Fixed reduction passes: propagate then fold
    fe_propagate_10(u); fe_fold_high(u);
    fe_propagate_10(u); fe_fold_high(u);
    fe_propagate_10(u); fe_fold_high(u);
    fe_propagate_10(u); fe_fold_high(u);

    // Stabilize: propagate can regenerate u[8]/u[9], so fold them again
    fe_propagate_10(u);
    if ((u[8] | u[9]) != 0ul) { fe_fold_high(u); fe_propagate_10(u); }
    if ((u[8] | u[9]) != 0ul) { fe_fold_high(u); fe_propagate_10(u); }

    // Copy result (u[8] and u[9] are now 0)
    for (int i = 0; i < 8; i++) {
        r[i] = (uint)u[i];
    }

    // Two conditional subtractions of p
    fe_normalize(r);
}

// Multiplication with overflow checking for debug/test builds
// Accumulates into *error_flag (caller must init to 0 before first call):
//   bit 0: carry escaped 10-limb window during propagation
//   bit 1: carry remained after 512-bit multiply (should never happen)
//   bit 2: u[8]/u[9] still non-zero after stabilization (should never happen)
inline void fe_mul_checked(__private uint* r,
                           __private const uint* a,
                           __private const uint* b,
                           __private uint* error_flag) {

    // === Phase 1: Column-by-column 512-bit multiply ===
    uint t[16];

    ulong carry_lo = 0ul;
    ulong carry_hi = 0ul;

    for (int k = 0; k < 16; k++) {
        ulong acc_lo = carry_lo;
        ulong acc_hi = carry_hi;

        int i_min = (k > 7) ? (k - 7) : 0;
        int i_max = (k < 8) ? k : 7;

        for (int i = i_min; i <= i_max; i++) {
            int j = k - i;
            ulong prod = (ulong)a[i] * (ulong)b[j];

            ulong old_lo = acc_lo;
            acc_lo += prod;
            acc_hi += (acc_lo < old_lo);
        }

        t[k] = (uint)(acc_lo & 0xFFFFFFFFul);
        carry_lo = (acc_lo >> 32) | (acc_hi << 32);
        carry_hi = acc_hi >> 32;
    }

    // Check: 256x256 -> 512 should have no carry beyond column 15
    if ((carry_lo | carry_hi) != 0ul) {
        *error_flag |= 2u;
    }

    // === Phase 2: Reduction ===
    ulong u[10];
    for (int i = 0; i < 8; i++) {
        u[i] = (ulong)t[i];
    }
    u[8] = 0ul;
    u[9] = 0ul;

    for (int k = 8; k < 16; k++) {
        ulong hk = (ulong)t[k];
        u[k - 8] += hk * FE_R_LOW;
        u[k - 7] += hk;
    }

    // Fixed reduction passes with overflow checking
    fe_propagate_10_checked(u, error_flag); fe_fold_high(u);
    fe_propagate_10_checked(u, error_flag); fe_fold_high(u);
    fe_propagate_10_checked(u, error_flag); fe_fold_high(u);
    fe_propagate_10_checked(u, error_flag); fe_fold_high(u);

    // Stabilize
    fe_propagate_10_checked(u, error_flag);
    if ((u[8] | u[9]) != 0ul) { fe_fold_high(u); fe_propagate_10_checked(u, error_flag); }
    if ((u[8] | u[9]) != 0ul) { fe_fold_high(u); fe_propagate_10_checked(u, error_flag); }

    // Final check: u[8] and u[9] must be zero
    if ((u[8] | u[9]) != 0ul) {
        *error_flag |= 4u;
    }

    for (int i = 0; i < 8; i++) {
        r[i] = (uint)u[i];
    }

    fe_normalize(r);
}

// Square: r = a^2 mod p
inline void fe_sqr(__private uint* r, __private const uint* a) {
    fe_mul(r, a, a);
}

// Modular inversion: r = a^(-1) mod p
// Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
inline void fe_inv(__private uint* r, __private const uint* a) {
    if (fe_is_zero(a)) {
        fe_zero(r);
        return;
    }

    uint exp[8] = {
        0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
    };

    uint result[8];
    fe_one(result);

    uint base[8];
    fe_copy(base, a);

    for (int limb = 0; limb < 8; limb++) {
        uint e = exp[limb];
        for (int bit = 0; bit < 32; bit++) {
            if (e & 1u) {
                fe_mul(result, result, base);
            }
            fe_sqr(base, base);
            e >>= 1;
        }
    }

    fe_copy(r, result);
}

// Convert big-endian bytes to field element
inline void fe_from_bytes(__private uint* r, __private const uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        r[i] = ((uint)bytes[off] << 24) |
               ((uint)bytes[off + 1] << 16) |
               ((uint)bytes[off + 2] << 8) |
               ((uint)bytes[off + 3]);
    }
}

// Convert big-endian bytes from __constant memory to field element
inline void fe_from_constant_bytes(__private uint* r, __constant const uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        r[i] = ((uint)bytes[off] << 24) |
               ((uint)bytes[off + 1] << 16) |
               ((uint)bytes[off + 2] << 8) |
               ((uint)bytes[off + 3]);
    }
}

// Convert field element to big-endian bytes
inline void fe_to_bytes(__private uchar* bytes, __private const uint* a) {
    for (int i = 0; i < 8; i++) {
        int off = (7 - i) * 4;
        uint limb = a[i];
        bytes[off] = (uchar)(limb >> 24);
        bytes[off + 1] = (uchar)(limb >> 16);
        bytes[off + 2] = (uchar)(limb >> 8);
        bytes[off + 3] = (uchar)limb;
    }
}
