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
// Used by vanity kernel where pattern is passed at runtime
inline int base58_check_prefix_global(
    __private const uchar* addr_bytes,
    __global const char* prefix,
    int prefix_len
) {
#define PREFIX_LOAD(i) prefix[i]
    BASE58_CHECK_PREFIX_BODY(PREFIX_LOAD)
#undef PREFIX_LOAD
}

#undef BASE58_CHECK_PREFIX_BODY

// Full Base58 encode for 38-byte address
// Returns encoded length (typically 51 chars for Ergo mainnet P2PK)
inline int base58_encode_address(
    __private const uchar* addr_bytes,
    __private char* output
) {
    return base58_encode(addr_bytes, 38, output);
}
