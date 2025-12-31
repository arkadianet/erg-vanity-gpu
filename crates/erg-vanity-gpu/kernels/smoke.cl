// Smoke test kernel - verifies GPU pipeline works before adding crypto.
//
// Each work item:
// 1. Reads salt and counter_start
// 2. Computes entropy = salt XOR (counter_start + global_id)
// 3. If entropy[0] matches pattern[0], stores a hit

// Hit structure - must match Rust GpuHit (64 bytes)
typedef struct {
    uint entropy_words[8];  // 32 bytes
    uint work_item_id;      // 4 bytes
    uint _pad[7];           // 28 bytes
} Hit;

__kernel void smoke_test(
    __global const uchar* salt,          // 32 bytes
    __global const ulong* counter_start, // starting counter
    __global const uchar* pattern,       // pattern to match
    __global const uint* pattern_len,    // pattern length
    __global Hit* hits,                  // hit buffer
    volatile __global uint* hit_count,   // atomic hit counter
    const uint max_hits                  // max hits allowed
) {
    uint gid = get_global_id(0);
    ulong counter = counter_start[0] + gid;

    // Compute "entropy" by XORing salt with counter bytes
    // This is NOT real entropy - just a smoke test
    uchar entropy[32];
    for (int i = 0; i < 32; i++) {
        entropy[i] = salt[i];
    }
    // XOR in counter (little-endian)
    for (int i = 0; i < 8; i++) {
        entropy[i] ^= (uchar)((counter >> (i * 8)) & 0xFF);
    }

    // Check if first byte matches first pattern byte
    uint plen = pattern_len[0];
    bool match = true;
    for (uint i = 0; i < plen && i < 32; i++) {
        if (entropy[i] != pattern[i]) {
            match = false;
            break;
        }
    }

    if (match && plen > 0) {
        // Atomically reserve a slot
        uint idx = atomic_inc(hit_count);
        if (idx < max_hits) {
            // Store the hit
            for (int i = 0; i < 8; i++) {
                hits[idx].entropy_words[i] =
                    ((uint)entropy[i*4 + 0]) |
                    ((uint)entropy[i*4 + 1] << 8) |
                    ((uint)entropy[i*4 + 2] << 16) |
                    ((uint)entropy[i*4 + 3] << 24);
            }
            hits[idx].work_item_id = gid;
        }
    }
}
