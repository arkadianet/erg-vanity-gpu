// base58.cl - Base58 encoding for Ergo addresses
//
// Bitcoin/Ergo alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
// Used to encode the 38-byte address (prefix + pubkey + checksum) to ~51 chars.

__constant char BASE58_ALPHABET[58] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J',
    'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z'
};

// Convert uppercase to lowercase for case-insensitive matching
inline char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

// Reverse lookup: ASCII -> Base58 index (0-57), or 0xFF for invalid
__constant uchar BASE58_DECODE[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 0-7
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 8-15
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 16-23
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 24-31
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 32-39
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 40-47
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // 48-55: '0'-'7' ('0' invalid, '1'=0)
    0x07, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 56-63: '8'-'9', then non-alnum
    0xFF, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,  // 64-71: '@', 'A'-'G'
    0x10, 0xFF, 0x11, 0x12, 0x13, 0x14, 0x15, 0xFF,  // 72-79: 'H', 'I'(inv), 'J'-'O'(inv)
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,  // 80-87: 'P'-'W'
    0x1E, 0x1F, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 88-95: 'X'-'Z', then non-alpha
    0xFF, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,  // 96-103: '`', 'a'-'g'
    0x28, 0x29, 0x2A, 0x2B, 0xFF, 0x2C, 0x2D, 0x2E,  // 104-111: 'h'-'l'(inv), 'm'-'o'
    0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,  // 112-119: 'p'-'w'
    0x37, 0x38, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF   // 120-127: 'x'-'z', then invalid
};

// ---- Grouped-base (58^4) prefix checking for fixed 38-byte payloads ----
// Using base 58^4 = 11,316,496 reduces inner loop from ~52 digits to 13 limbs
#define B58_GBASE 11316496u  // 58^4
#define B58_POW3  195112u    // 58^3
#define B58_POW2  3364u      // 58^2
#define B58_POW1  58u        // 58^1

// Safe ASCII to base58 digit conversion (handles uchar table with 0xFF as invalid)
static inline int b58_ascii_to_digit(const char c) {
    const uchar uc = (uchar)c;
    if (uc >= 128) return -1;
    const uchar d = BASE58_DECODE[uc];     // 0..57 or 0xFF
    return (d == (uchar)0xFF) ? -1 : (int)d;
}

// Case-insensitive digit matching
static inline int b58_char_matches_digit_icase(const char c, const uint digit) {
    int d = b58_ascii_to_digit(c);
    if ((uint)d == digit) return 1;

    if (c >= 'a' && c <= 'z') {
        d = b58_ascii_to_digit((char)(c - 32));
        return ((uint)d == digit);
    }
    if (c >= 'A' && c <= 'Z') {
        d = b58_ascii_to_digit((char)(c + 32));
        return ((uint)d == digit);
    }
    return 0;
}

// Extract 4 base58 digits (MSD -> LSD) from a base-58^4 limb
static inline uint4 b58_group_to_digits4(uint x) {
    uint d3 = x / B58_POW3; x -= d3 * B58_POW3;
    uint d2 = x / B58_POW2; x -= d2 * B58_POW2;
    uint d1 = x / B58_POW1; x -= d1 * B58_POW1;
    uint d0 = x;
    return (uint4)(d3, d2, d1, d0);
}

// Get digit at index 0-3 from uint4
static inline uint b58_get_digit_from4(const uint4 v, const int idx) {
    return (idx == 0) ? v.s0 : (idx == 1) ? v.s1 : (idx == 2) ? v.s2 : v.s3;
}

// Fast case-sensitive prefix check for exactly 38-byte addresses using grouped limbs
static inline int base58_check_prefix_38_grouped_global_cs(
    __private const uchar* addr_bytes,   // exactly 38 bytes
    __global  const char*  prefix,
    const int prefix_len
) {
    if (prefix_len <= 0) return 1;

    // Leading zero bytes => leading '1' chars in Base58
    int leading_zeros = 0;
    #pragma unroll
    for (int i = 0; i < 38; i++) {
        if (addr_bytes[i] == 0) leading_zeros++;
        else break;
    }

    // Count required leading '1's in prefix
    int p = 0;
    while (p < prefix_len && prefix[p] == '1') p++;
    if (p > leading_zeros) return 0;
    if (p == prefix_len) return 1;  // prefix is all '1's and we have enough leading zeros

    // Convert remaining bytes (after leading zeros) into base 58^4 limbs (little-endian)
    // 38 bytes => <= 52 base58 digits => <= 13 limbs of 4 digits each
    uint limbs[13];
    #pragma unroll
    for (int i = 0; i < 13; i++) limbs[i] = 0;

    int limb_len = 0;

    #pragma unroll
    for (int i = 0; i < 38; i++) {
        if (i < leading_zeros) continue;

        uint carry = (uint)addr_bytes[i];

        // Fixed upper bound (13) for unroll-friendliness
        #pragma unroll
        for (int j = 0; j < 13; j++) {
            if (j < limb_len) {
                const uint v = limbs[j] * 256u + carry;
                limbs[j] = v % B58_GBASE;
                carry    = v / B58_GBASE;
            }
        }

        if (carry != 0u) {
            limbs[limb_len++] = carry;
        }
    }

    // If value part is zero, only '1's exist (handled above already)
    if (limb_len == 0) return 0;

    // Compute total digit count of the value part (excluding leading_zeros '1's)
    const uint ms_val = limbs[limb_len - 1];
    const int ms_digits =
        (ms_val >= B58_POW3) ? 4 :
        (ms_val >= B58_POW2) ? 3 :
        (ms_val >= B58_POW1) ? 2 : 1;

    const int total_digits = ms_digits + 4 * (limb_len - 1);
    const int need = prefix_len - p;
    if (need > total_digits) return 0;

    // Compare prefix digits against MS base58 digits from limbs
    int limb_i = limb_len - 1;
    uint4 digs = b58_group_to_digits4(limbs[limb_i]);

    // For the most significant limb, skip leading zero digits
    int di = 4 - ms_digits;

    for (int k = 0; k < need; k++) {
        const uint digit = b58_get_digit_from4(digs, di);

        const int want = b58_ascii_to_digit(prefix[p + k]);
        if (want < 0) return 0;
        if ((uint)want != digit) return 0;

        di++;
        if (di == 4) {
            limb_i--;
            if (limb_i < 0) break;
            digs = b58_group_to_digits4(limbs[limb_i]);
            di = 0;
        }
    }

    return 1;
}

// Fast case-insensitive prefix check for exactly 38-byte addresses using grouped limbs
static inline int base58_check_prefix_38_grouped_global_icase(
    __private const uchar* addr_bytes,   // exactly 38 bytes
    __global  const char*  prefix,
    const int prefix_len
) {
    if (prefix_len <= 0) return 1;

    int leading_zeros = 0;
    #pragma unroll
    for (int i = 0; i < 38; i++) {
        if (addr_bytes[i] == 0) leading_zeros++;
        else break;
    }

    int p = 0;
    while (p < prefix_len && prefix[p] == '1') p++;
    if (p > leading_zeros) return 0;
    if (p == prefix_len) return 1;

    uint limbs[13];
    #pragma unroll
    for (int i = 0; i < 13; i++) limbs[i] = 0;

    int limb_len = 0;

    #pragma unroll
    for (int i = 0; i < 38; i++) {
        if (i < leading_zeros) continue;

        uint carry = (uint)addr_bytes[i];

        #pragma unroll
        for (int j = 0; j < 13; j++) {
            if (j < limb_len) {
                const uint v = limbs[j] * 256u + carry;
                limbs[j] = v % B58_GBASE;
                carry    = v / B58_GBASE;
            }
        }

        if (carry != 0u) {
            limbs[limb_len++] = carry;
        }
    }

    if (limb_len == 0) return 0;

    const uint ms_val = limbs[limb_len - 1];
    const int ms_digits =
        (ms_val >= B58_POW3) ? 4 :
        (ms_val >= B58_POW2) ? 3 :
        (ms_val >= B58_POW1) ? 2 : 1;

    const int total_digits = ms_digits + 4 * (limb_len - 1);
    const int need = prefix_len - p;
    if (need > total_digits) return 0;

    int limb_i = limb_len - 1;
    uint4 digs = b58_group_to_digits4(limbs[limb_i]);
    int di = 4 - ms_digits;

    for (int k = 0; k < need; k++) {
        const uint digit = b58_get_digit_from4(digs, di);

        if (!b58_char_matches_digit_icase(prefix[p + k], digit)) return 0;

        di++;
        if (di == 4) {
            limb_i--;
            if (limb_i < 0) break;
            digs = b58_group_to_digits4(limbs[limb_i]);
            di = 0;
        }
    }

    return 1;
}

// Encode bytes to Base58
// input: raw bytes (up to 64)
// input_len: number of bytes
// output: Base58 string (up to 88 chars for 64 bytes)
// Returns: length of encoded string
inline int base58_encode(
    __private const uchar* input,
    int input_len,
    __private char* output
) {
    // Count leading zeros
    int leading_zeros = 0;
    while (leading_zeros < input_len && input[leading_zeros] == 0u) {
        leading_zeros++;
    }

    // Working buffer (enough for 64 bytes -> ~88 base58 chars)
    uchar buf[90];
    int buf_len = 0;

    // Convert to base58 using repeated division
    // Start from first non-zero byte
    for (int i = leading_zeros; i < input_len; i++) {
        int carry = (int)input[i];
        for (int j = 0; j < buf_len; j++) {
            carry += (int)buf[j] * 256;
            buf[j] = (uchar)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            buf[buf_len++] = (uchar)(carry % 58);
            carry /= 58;
        }
    }

    // Build output: leading '1's + reversed buffer
    int out_len = 0;
    for (int i = 0; i < leading_zeros; i++) {
        output[out_len++] = '1';
    }
    for (int i = buf_len - 1; i >= 0; i--) {
        output[out_len++] = BASE58_ALPHABET[buf[i]];
    }

    return out_len;
}

// Shared logic for base58 prefix check - used by both __constant and __global variants
// PREFIX_LOAD(i) macro must be defined before expanding this
#define BASE58_CHECK_PREFIX_BODY(PREFIX_LOAD)                                   \
    int leading_zeros = 0;                                                      \
    while (leading_zeros < 38 && addr_bytes[leading_zeros] == 0u)               \
        leading_zeros++;                                                        \
                                                                                \
    int prefix_ones = 0;                                                        \
    while (prefix_ones < prefix_len && PREFIX_LOAD(prefix_ones) == '1')         \
        prefix_ones++;                                                          \
                                                                                \
    if (prefix_ones == prefix_len)                                              \
        return (leading_zeros >= prefix_ones) ? 1 : 0;                          \
                                                                                \
    if (leading_zeros != prefix_ones)                                           \
        return 0;                                                               \
                                                                                \
    uchar buf[53];                                                              \
    int buf_len = 0;                                                            \
    for (int i = leading_zeros; i < 38; i++) {                                  \
        int carry = (int)addr_bytes[i];                                         \
        for (int j = 0; j < buf_len; j++) {                                     \
            carry += (int)buf[j] * 256;                                         \
            buf[j] = (uchar)(carry % 58);                                       \
            carry /= 58;                                                        \
        }                                                                       \
        while (carry > 0) {                                                     \
            if (buf_len >= 53) return 0;                                        \
            buf[buf_len++] = (uchar)(carry % 58);                               \
            carry /= 58;                                                        \
        }                                                                       \
    }                                                                           \
                                                                                \
    for (int i = prefix_ones; i < prefix_len; i++) {                            \
        char expected = PREFIX_LOAD(i);                                         \
        uchar decoded = BASE58_DECODE[(int)expected];                           \
        int digit_idx = buf_len - 1 - (i - prefix_ones);                        \
        if (digit_idx < 0 || decoded == 0xFFu || buf[digit_idx] != decoded)     \
            return 0;                                                           \
    }                                                                           \
    return 1;

// Check if Base58-encoded address starts with a given prefix (__constant version)
// Used by test kernels with compile-time constant patterns
inline int base58_check_prefix(
    __private const uchar* addr_bytes,
    __constant const char* prefix,
    int prefix_len
) {
#define PREFIX_LOAD(i) prefix[i]
    BASE58_CHECK_PREFIX_BODY(PREFIX_LOAD)
#undef PREFIX_LOAD
}

// Check if Base58-encoded address starts with a given prefix (__global version)
// Generic implementation - used as fallback for non-38-byte addresses
inline int base58_check_prefix_global_generic(
    __private const uchar* addr_bytes,
    __global const char* prefix,
    int prefix_len
) {
#define PREFIX_LOAD(i) prefix[i]
    BASE58_CHECK_PREFIX_BODY(PREFIX_LOAD)
#undef PREFIX_LOAD
}

#undef BASE58_CHECK_PREFIX_BODY

// Case-insensitive prefix check (__global version)
// Generic implementation - used as fallback for non-38-byte addresses
// Pattern MUST be pre-lowercased by CPU. We lowercase each generated Base58 char for comparison.
inline int base58_check_prefix_global_icase_generic(
    __private const uchar* addr_bytes,
    __global const char* prefix,       // Pre-lowercased pattern
    int prefix_len
) {
    // Count leading zeros in address
    int leading_zeros = 0;
    while (leading_zeros < 38 && addr_bytes[leading_zeros] == 0u)
        leading_zeros++;

    // Count leading '1's in pattern
    int prefix_ones = 0;
    while (prefix_ones < prefix_len && prefix[prefix_ones] == '1')
        prefix_ones++;

    // If pattern is all '1's, just check leading zeros count
    if (prefix_ones == prefix_len)
        return (leading_zeros >= prefix_ones) ? 1 : 0;

    // Leading zero count must match leading '1' count
    if (leading_zeros != prefix_ones)
        return 0;

    // Convert address bytes to Base58 digits (values 0-57, stored in buf)
    uchar buf[53];
    int buf_len = 0;
    for (int i = leading_zeros; i < 38; i++) {
        int carry = (int)addr_bytes[i];
        for (int j = 0; j < buf_len; j++) {
            carry += (int)buf[j] * 256;
            buf[j] = (uchar)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            if (buf_len >= 53) return 0;
            buf[buf_len++] = (uchar)(carry % 58);
            carry /= 58;
        }
    }

    // Compare: convert each Base58 digit to char, lowercase it, compare to pattern
    for (int i = prefix_ones; i < prefix_len; i++) {
        char expected = prefix[i];  // Already lowercase from CPU
        int digit_idx = buf_len - 1 - (i - prefix_ones);
        if (digit_idx < 0)
            return 0;

        // Get the actual Base58 character for this digit
        char actual = BASE58_ALPHABET[buf[digit_idx]];
        // Lowercase for case-insensitive comparison
        char actual_lower = to_lower(actual);

        if (actual_lower != expected)
            return 0;
    }
    return 1;
}

// ---- Wrapper functions: route to fast path for 38-byte addresses ----
// These maintain the original API while using the optimized grouped-limb implementation

// Case-sensitive prefix check (__global version) - uses fast path
inline int base58_check_prefix_global(
    __private const uchar* addr_bytes,
    __global const char* prefix,
    int prefix_len
) {
    // Fast path for 38-byte Ergo addresses (this API always assumes 38 bytes)
    return base58_check_prefix_38_grouped_global_cs(addr_bytes, prefix, prefix_len);
}

// Case-insensitive prefix check (__global version) - uses fast path
inline int base58_check_prefix_global_icase(
    __private const uchar* addr_bytes,
    __global const char* prefix,
    int prefix_len
) {
    // Fast path for 38-byte Ergo addresses (this API always assumes 38 bytes)
    return base58_check_prefix_38_grouped_global_icase(addr_bytes, prefix, prefix_len);
}

// Full Base58 encode for 38-byte address
// Returns encoded length (typically 51 chars for Ergo mainnet P2PK)
inline int base58_encode_address(
    __private const uchar* addr_bytes,
    __private char* output
) {
    return base58_encode(addr_bytes, 38, output);
}
