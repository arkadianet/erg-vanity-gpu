# GPU Implementation

OpenCL kernel implementation details, derived from source code.

## Kernel Files

<!-- Source: glob crates/erg-vanity-gpu/kernels/*.cl -->

**Location:** `crates/erg-vanity-gpu/kernels/`

**Total:** 23 files

### Production Kernels

| File | Purpose |
|------|---------|
| `sha256.cl` | SHA-256 hash |
| `sha512.cl` | SHA-512 hash |
| `hmac_sha512.cl` | HMAC-SHA512 |
| `pbkdf2.cl` | PBKDF2-HMAC-SHA512 (BIP39 seed) |
| `blake2b.cl` | Blake2b-256 hash |
| `base58.cl` | Base58 encoding and pattern matching |
| `bip39.cl` | Entropy to seed |
| `bip32.cl` | Key derivation |
| `secp256k1_fe.cl` | Field element arithmetic |
| `secp256k1_scalar.cl` | Scalar arithmetic |
| `secp256k1_point.cl` | Point operations |
| `vanity.cl` | Main search kernel |
| `bench.cl` | Benchmark kernels |
| `smoke.cl` | Smoke test kernel |

### Test Kernels

| File | Purpose |
|------|---------|
| `sha256_test.cl` | SHA-256 tests |
| `sha512_test.cl` | SHA-512 tests |
| `hmac_sha512_test.cl` | HMAC-SHA512 tests |
| `pbkdf2_test.cl` | PBKDF2 tests |
| `blake2b_test.cl` | Blake2b tests |
| `base58_test.cl` | Base58 tests |
| `secp256k1_fe_test.cl` | Field element tests |
| `secp256k1_scalar_test.cl` | Scalar tests |
| `secp256k1_point_test.cl` | Point tests |

## Kernel Entrypoints

<!-- Source: grep "__kernel" crates/erg-vanity-gpu/kernels/*.cl -->

### Production Kernels (6)

| Function | File:Line | Purpose |
|----------|-----------|---------|
| `vanity_search` | `vanity.cl:77` | Main vanity address search |
| `vanity_derive_address` | `vanity.cl:176` | Single address derivation (testing) |
| `bench_pbkdf2` | `bench.cl:62` | PBKDF2 benchmark |
| `bench_bip32` | `bench.cl:96` | BIP32 benchmark |
| `bench_secp256k1` | `bench.cl:138` | secp256k1 benchmark |
| `bench_base58` | `bench.cl:188` | Base58 benchmark |

### Test Kernels (15)

| Function | File:Line |
|----------|-----------|
| `smoke_test` | `smoke.cl:15` |
| `sha256_test` | `sha256_test.cl:6` |
| `sha512_test_single` | `sha512_test.cl:6` |
| `sha512_test_two_blocks` | `sha512_test.cl:33` |
| `hmac_sha512_test` | `hmac_sha512_test.cl:7` |
| `pbkdf2_test` | `pbkdf2_test.cl:7` |
| `pbkdf2_bip39_test` | `pbkdf2_test.cl:46` |
| `blake2b_test` | `blake2b_test.cl:22` |
| `blake2b_self_test` | `blake2b_test.cl:45` |
| `base58_test` | `base58_test.cl:17` |
| `base58_self_test` | `base58_test.cl:42` |
| `fe_test` | `secp256k1_fe_test.cl:40` |
| `fe_self_test` | `secp256k1_fe_test.cl:93` |
| `sc_self_test` | `secp256k1_scalar_test.cl:43` |
| `pt_self_test` | `secp256k1_point_test.cl:26` |

## Kernel Compilation

<!-- Source: crates/erg-vanity-gpu/src/kernel.rs -->

### Compilation Pipeline

Kernels are compiled at runtime by concatenating source files in dependency order.

```rust
// kernel.rs - Production kernel order
sha256 → sha512 → hmac_sha512 → pbkdf2 →
secp256k1_fe → secp256k1_scalar → secp256k1_point →
blake2b → base58 → bip39 → bip32 → vanity
```

### Compiler Flags

<!-- Source: kernel.rs:54-84 -->

| Flag | Condition | Purpose |
|------|-----------|---------|
| `-cl-std=CL1.2` | Always | OpenCL 1.2 standard |
| `-cl-nv-verbose` | NVIDIA + `ERG_CL_VERBOSE=1` | Print register usage, spills |

### Environment Variable

<!-- Source: kernel.rs:58 -->

```rust
let verbose = std::env::var("ERG_CL_VERBOSE")
    .map(|v| v == "1")
    .unwrap_or(false);
```

When `ERG_CL_VERBOSE=1` is set and device vendor contains "NVIDIA":
- Adds `-cl-nv-verbose` compiler flag
- Prints compilation diagnostics to stderr
- Shows register usage and spill information

## Memory Layout

<!-- Source: crates/erg-vanity-gpu/src/buffers.rs -->

### Constants

```rust
// buffers.rs:9
pub const MAX_HITS: usize = 1024;

// buffers.rs:12
pub const ENTROPY_SIZE: usize = 32;

// buffers.rs:15
pub const MAX_PATTERN_DATA: usize = 1024;

// buffers.rs:18
pub const MAX_PATTERNS: usize = 64;
```

### Buffer Allocations

<!-- Source: buffers.rs:70-126 -->

| Buffer | Size | Access | Purpose |
|--------|------|--------|---------|
| `salt` | 32 bytes | read-only | Entropy generation salt |
| `patterns` | 1024 bytes | read-only | Concatenated pattern strings |
| `pattern_offsets` | 64 × u32 | read-only | Byte offset of each pattern |
| `pattern_lens` | 64 × u32 | read-only | Length of each pattern |
| `hits` | 1024 × 64 bytes | write-only | Match results |
| `hit_count` | 1 × i32 | read-write | Atomic hit counter |

### Hit Record Structure

<!-- Source: buffers.rs:23-36 -->

```c
// GPU-side structure (64 bytes, 16-byte aligned)
typedef struct {
    uint entropy_words[8];  // 32 bytes - little-endian u32
    uint work_item_id;      // 4 bytes
    uint address_index;     // 4 bytes - BIP44 index
    uint pattern_index;     // 4 bytes - which pattern matched
    uint _pad[5];           // 20 bytes - padding to 64 bytes
} VanityHit;
```

## Device Selection

<!-- Source: crates/erg-vanity-gpu/src/context.rs -->

### Device Enumeration

```rust
// context.rs:122-200
pub fn enumerate_devices() -> Result<Vec<DeviceInfo>, GpuError>
```

Iterates all OpenCL platforms, collects GPU devices with:
- Global index (for CLI selection)
- Platform/device indices
- Name, vendor, compute units
- Memory sizes

### DeviceInfo Structure

<!-- Source: context.rs:23-46 -->

```rust
pub struct DeviceInfo {
    pub global_idx: usize,
    pub platform_idx: usize,
    pub device_idx: usize,
    pub platform_name: String,
    pub device_name: String,
    pub vendor: String,
    pub compute_units: u32,
    pub max_work_group_size: usize,
    pub global_mem_size: u64,
    pub local_mem_size: u64,
}
```

### Context Creation

<!-- Source: context.rs:60-120 -->

| Method | Purpose |
|--------|---------|
| `GpuContext::new()` | First available GPU |
| `GpuContext::with_device(idx)` | Specific device by global index |
| `GpuContext::with_device_profiling(idx)` | With profiling enabled (for benchmarks) |

## GPU Errors

<!-- Source: context.rs:8-21 -->

```rust
pub enum GpuError {
    NoPlatforms,                           // No OpenCL platforms found
    NoDevices,                             // No GPU devices found
    DeviceIndexOutOfRange(usize, usize),   // Index out of range
    Ocl(ocl::Error),                       // OpenCL error
    Other(String),                         // Other errors
}
```

## Pipeline Configuration

<!-- Source: crates/erg-vanity-gpu/src/pipeline.rs -->

### VanityConfig

<!-- Source: pipeline.rs:10-29 -->

```rust
pub struct VanityConfig {
    pub batch_size: usize,    // Default: 262,144 (1 << 18)
    pub ignore_case: bool,    // Default: false
    pub num_indices: u32,     // Default: 1
}
```

### Kernel Dispatch

<!-- Source: pipeline.rs:180-240 -->

- Global work size: `batch_size`
- Local work size: Unspecified (driver-selected)
- Each work item processes one entropy value
- Each work item checks `num_indices` address indices

## Optimizations

### PBKDF2 Fast Path

<!-- Source: pbkdf2.cl comments -->

- Uses `ulong8` vector type for 64-byte HMAC output
- NVIDIA treats `ulong8` as register pack (avoids local memory spills)
- Specialized `hmac_sha512_msg64_u8()` for 64-byte messages

### Generator Table

<!-- Source: secp256k1_point.cl -->

- 4-bit windowed scalar multiplication for generator point
- Precomputed table of 16 × G multiples

---

## Verification Checklist

- [x] Kernel files: `glob crates/erg-vanity-gpu/kernels/*.cl`
- [x] Kernel entrypoints: `grep "__kernel" *.cl`
- [x] Environment variable: `kernel.rs:58`
- [x] Memory layout: `buffers.rs:9-126`
- [x] Device enumeration: `context.rs:122-200`
- [x] GPU errors: `context.rs:8-21`
- [x] Pipeline config: `pipeline.rs:10-29`
