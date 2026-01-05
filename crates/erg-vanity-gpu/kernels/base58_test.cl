// base58_test.cl - test kernel wrapper for Base58 encoding
//
// Expected to be concatenated after base58.cl

// Test prefixes for matching
__constant char TEST_PREFIX_9[2] = {'9', '\0'};
__constant char TEST_PREFIX_9f[3] = {'9', 'f', '\0'};
__constant char TEST_PREFIX_1[2] = {'1', '\0'};
__constant char TEST_PREFIX_11[3] = {'1', '1', '\0'};
__constant char TEST_PREFIX_1a[3] = {'1', 'a', '\0'};

// Test kernel for Base58 encoding
// input: raw bytes
// input_len: number of bytes
// output: encoded string (up to 88 chars)
// output_len: pointer to store encoded length
__kernel void base58_test(
    __global const uchar* input,
    uint input_len,
    __global char* output,
    __global int* output_len
) {
    if (get_global_id(0) != 0u) return;

    // Copy input to private memory
    uchar priv_input[64];
    for (uint i = 0u; i < 64u; i++) {
        priv_input[i] = (i < input_len) ? input[i] : 0u;
    }

    char encoded[90];
    int len = base58_encode(priv_input, (int)input_len, encoded);

    for (int i = 0; i < len; i++) {
        output[i] = encoded[i];
    }
    *output_len = len;
}

// Self-test kernel
// Returns 0 if all tests pass, non-zero otherwise (bit mask of failed tests)
__kernel void base58_self_test(__global uint* result) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;

    // Test 1: Encode empty -> empty
    {
        uchar empty[1];
        char out[8];
        int len = base58_encode(empty, 0, out);
        if (len != 0) {
            failures |= (1u << 0);
        }
    }

    // Test 2: Encode single zero byte -> "1"
    {
        uchar zero[1];
        zero[0] = 0u;
        char out[8];
        int len = base58_encode(zero, 1, out);
        if (len != 1 || out[0] != '1') {
            failures |= (1u << 1);
        }
    }

    // Test 3: Encode two zero bytes -> "11"
    {
        uchar zeros[2];
        zeros[0] = 0u;
        zeros[1] = 0u;
        char out[8];
        int len = base58_encode(zeros, 2, out);
        if (len != 2 || out[0] != '1' || out[1] != '1') {
            failures |= (1u << 2);
        }
    }

    // Test 4: Encode 0x01 -> "2"
    {
        uchar one[1];
        one[0] = 1u;
        char out[8];
        int len = base58_encode(one, 1, out);
        if (len != 1 || out[0] != '2') {
            failures |= (1u << 3);
        }
    }

    // Test 5: Encode 0x39 (57) -> "z" (last char)
    {
        uchar val[1];
        val[0] = 57u;
        char out[8];
        int len = base58_encode(val, 1, out);
        if (len != 1 || out[0] != 'z') {
            failures |= (1u << 4);
        }
    }

    // Test 6: Encode 0x3A (58) -> "21"
    {
        uchar val[1];
        val[0] = 58u;
        char out[8];
        int len = base58_encode(val, 1, out);
        if (len != 2 || out[0] != '2' || out[1] != '1') {
            failures |= (1u << 5);
        }
    }

    // Test 7: Mainnet P2PK prefix byte 0x01 should produce address starting with "9"
    // Construct a fake 38-byte address: 0x01 + 33 zeros + 4 zero checksum
    {
        uchar addr[38];
        addr[0] = 0x01u;
        for (int i = 1; i < 38; i++) addr[i] = 0u;

        char out[60];
        int len = base58_encode_address(addr, out);

        // Should start with '9' (since 0x01 != 0x00)
        if (len < 1 || out[0] != '9') {
            failures |= (1u << 6);
        }
    }

    // Test 8: base58_check_prefix with "9" prefix
    {
        uchar addr[38];
        addr[0] = 0x01u;
        for (int i = 1; i < 38; i++) addr[i] = 0u;

        if (!base58_check_prefix(addr, TEST_PREFIX_9, 1)) {
            failures |= (1u << 7);
        }
    }

    // Test 9: base58_check_prefix consistency with full encode
    {
        uchar addr[38];
        addr[0] = 0x01u;
        for (int i = 1; i < 38; i++) addr[i] = 0u;

        // "9f" won't match because second char depends on rest of address
        // Full encode will reveal if it actually starts with "9f"
        char out[60];
        int len = base58_encode_address(addr, out);

        int expected_match = (len >= 2 && out[0] == '9' && out[1] == 'f') ? 1 : 0;
        int actual_match = base58_check_prefix(addr, TEST_PREFIX_9f, 2);

        if (actual_match != expected_match) {
            failures |= (1u << 8);
        }
    }

    // Test 10: Leading zeros -> leading '1's
    {
        uchar addr[38];
        addr[0] = 0u;  // Leading zero
        addr[1] = 0x01u;
        for (int i = 2; i < 38; i++) addr[i] = 0u;

        char out[60];
        int len = base58_encode_address(addr, out);

        if (len < 1 || out[0] != '1') {
            failures |= (1u << 9);
        }

        // Should match prefix "1"
        if (!base58_check_prefix(addr, TEST_PREFIX_1, 1)) {
            failures |= (1u << 10);
        }
    }

    // Test 11: Two leading zeros -> "11" prefix
    {
        uchar addr[38];
        addr[0] = 0u;
        addr[1] = 0u;
        addr[2] = 0x01u;
        for (int i = 3; i < 38; i++) addr[i] = 0u;

        char out[60];
        int len = base58_encode_address(addr, out);

        if (len < 2 || out[0] != '1' || out[1] != '1') {
            failures |= (1u << 11);
        }

        // Should match prefix "11"
        if (!base58_check_prefix(addr, TEST_PREFIX_11, 2)) {
            failures |= (1u << 12);
        }

        // Should also match prefix "1" (>= check for all-ones prefix)
        if (!base58_check_prefix(addr, TEST_PREFIX_1, 1)) {
            failures |= (1u << 13);
        }
    }

    // Test 14: Mainnet prefix (no leading zeros) should NOT match "1" prefix
    {
        uchar addr[38];
        addr[0] = 0x01u;  // Non-zero prefix
        for (int i = 1; i < 38; i++) addr[i] = 0xFFu;  // Non-zero data

        // This has 0 leading zeros, so should not match "1" prefix
        if (base58_check_prefix(addr, TEST_PREFIX_1, 1)) {
            failures |= (1u << 14);
        }
    }

    // Test 15: Two leading zeros must NOT match "1a" (the false positive bug test)
    // Address encodes to "11...", which != "1a..."
    {
        uchar addr[38];
        addr[0] = 0u;
        addr[1] = 0u;
        addr[2] = 0x01u;
        for (int i = 3; i < 38; i++) addr[i] = 0u;

        if (base58_check_prefix(addr, TEST_PREFIX_1a, 2)) {
            failures |= (1u << 15);
        }
    }

    // Test 16: Leading zero address must NOT match "9" prefix
    // Address with leading zero encodes to "1...", which != "9..."
    {
        uchar addr[38];
        addr[0] = 0u;      // leading zero
        addr[1] = 0x01u;
        for (int i = 2; i < 38; i++) addr[i] = 0u;

        if (base58_check_prefix(addr, TEST_PREFIX_9, 1)) {
            failures |= (1u << 16);
        }
    }

    *result = failures;
}

// ---- Fast vs Generic comparison test ----
// Properly compares base58_check_prefix_38_grouped_global_* (fast) vs *_generic
//
// Failure bitmap layout:
//   bits 0-15:  CS mismatch for samples 0-15
//   bits 16-31: ICASE mismatch for samples 0-15
//
// Sample patterns:
//   0: typical Ergo address (0x01 prefix + patterned data)
//   1: one leading zero (0x00, 0x01, 0x00...)
//   2: all zeros
//   3: one non-zero at end
//   4: two leading zeros (0x00, 0x00, 0x01, 0x00...)
//   5-15: pseudo-random

__kernel void base58_fast_vs_generic_test(
    __global const char* prefix,      // Case-sensitive prefix
    __global const char* prefix_lc,   // Lowercased prefix (for icase generic)
    int prefix_len,
    __global uint* result
) {
    if (get_global_id(0) != 0u) return;

    uint failures = 0u;

    for (int sample = 0; sample < 16; sample++) {
        uchar addr[38];

        if (sample == 0) {
            // Typical Ergo address
            addr[0] = 0x01u;
            for (int i = 1; i < 38; i++) addr[i] = (uchar)(i * 7);
        } else if (sample == 1) {
            // One leading zero
            addr[0] = 0u;
            addr[1] = 0x01u;
            for (int i = 2; i < 38; i++) addr[i] = 0u;
        } else if (sample == 2) {
            // All zeros
            for (int i = 0; i < 38; i++) addr[i] = 0u;
        } else if (sample == 3) {
            // One non-zero at end
            for (int i = 0; i < 37; i++) addr[i] = 0u;
            addr[37] = 0x01u;
        } else if (sample == 4) {
            // Two leading zeros
            addr[0] = 0u;
            addr[1] = 0u;
            addr[2] = 0x01u;
            for (int i = 3; i < 38; i++) addr[i] = 0u;
        } else {
            // Pseudo-random
            for (int i = 0; i < 38; i++) {
                addr[i] = (uchar)(((sample - 5) * 17 + i * 31 + 42) & 0xFF);
            }
        }

        // Case-sensitive: fast vs generic
        int fast_cs = base58_check_prefix_38_grouped_global_cs(addr, prefix, prefix_len);
        int gen_cs = base58_check_prefix_global_generic(addr, prefix, prefix_len);
        if (fast_cs != gen_cs) failures |= (1u << sample);

        // Case-insensitive: fast vs generic (both use lowercased prefix)
        int fast_i = base58_check_prefix_38_grouped_global_icase(addr, prefix_lc, prefix_len);
        int gen_i = base58_check_prefix_global_icase_generic(addr, prefix_lc, prefix_len);
        if (fast_i != gen_i) failures |= (1u << (16 + sample));
    }

    *result = failures;
}
