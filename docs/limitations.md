# Limitations

Known limitations, TODO/FIXME items, and gaps identified in code analysis.

## TODO/FIXME/UNIMPLEMENTED Scan

**Scan command:** `grep -rniE "TODO|FIXME|UNIMPLEMENTED|XXX|HACK" .`

**Result:** No matches found.

The codebase contains no TODO, FIXME, UNIMPLEMENTED, XXX, or HACK comments.

## unsafe Usage Summary

All `unsafe` blocks in the codebase are for OpenCL FFI:

<!-- Source: grep "unsafe" crates/ -->

| File | Count | Purpose |
|------|-------|---------|
| `kernel.rs` | 13 | OpenCL kernel enqueue via `ocl` crate |
| `pipeline.rs` | 2 | OpenCL kernel enqueue |
| `bench.rs` | 3 | OpenCL kernel enqueue |
| `buffers.rs` | 1 | `unsafe impl OclPrm for GpuHit` |

**Total:** 19 unsafe blocks

All unsafe usage is required for FFI with the OpenCL C library.

## Architectural Limitations

### Single Address Type

- Only P2PK (Pay-to-Public-Key) addresses supported
- No P2SH or other Ergo address types

**Evidence:** `crates/erg-vanity-address/src/p2pk.rs` is the only address encoder.

### Single Derivation Path

- Fixed to `m/44'/429'/0'/0/{index}`
- No configurable account, change, or custom paths

**Evidence:** `crates/erg-vanity-bip/src/bip44.rs` hardcodes Ergo coin type 429.

### Mainnet Only (CLI)

- Pattern validation enforces mainnet constraints (first char '9')
- Testnet not supported via CLI

**Evidence:** `main.rs:130` requires first char to be '9'.

### No JSON Output

- All output is plain text
- No structured data export

**Evidence:** No JSON serialization in `main.rs` output functions.

### No Resume/Checkpoint

- Cannot resume interrupted searches
- No state persistence

**Evidence:** No file I/O for state in codebase.

## Resource Limits

<!-- Source: crates/erg-vanity-gpu/src/buffers.rs:9-18 -->

| Limit | Value | Source |
|-------|-------|--------|
| Max hits per batch | 1024 | `buffers.rs:9` |
| Max patterns | 64 | `buffers.rs:18` |
| Max pattern data | 1024 bytes | `buffers.rs:15` |
| Max pattern length | 32 chars | `main.rs:20` |
| Max BIP44 indices | 100 | `main.rs:601` |

### Hit Buffer Overflow

When more than 1024 matches occur in a single batch:
- Extra hits are dropped
- Warning printed: "hits dropped due to buffer overflow"

**Evidence:** `main.rs:533-536`, `pipeline.rs` hit counting logic.

## Platform Limitations

### OpenCL Required

- Requires OpenCL runtime
- Requires GPU device with OpenCL support

**Evidence:** All GPU functionality depends on `ocl` crate.

### Stack Size Requirement

- OpenCL kernel compilation requires larger stack
- Default stack may cause test failures

**Evidence:** `.cargo/config.toml:7` sets `RUST_MIN_STACK=16777216`.

## Performance Considerations

### PBKDF2 Bottleneck

- PBKDF2 (2048 rounds) dominates GPU time (~85%)
- Cannot be parallelized per-seed

**Evidence:** Benchmark output shows PBKDF2 as largest component.

### Single Batch Size

- Batch size fixed at 262,144 for search mode
- Only benchmark mode allows custom batch size

**Evidence:** `main.rs:621` hardcodes `1 << 18`.

## Unknown from Code

The following could not be determined from code analysis:

| Item | Status |
|------|--------|
| AMD GPU performance | Unknown - no AMD-specific optimizations documented |
| Intel GPU support | Unknown - no Intel-specific code paths |
| Minimum OpenCL version | Unknown - uses `-cl-std=CL1.2` but runtime may vary |
| Memory requirements | Unknown - no explicit memory calculations |
| Maximum pattern complexity | Unknown - regex/wildcards not implemented |

## Feature Gaps

Based on common vanity generator features not present:

| Feature | Status |
|---------|--------|
| Regex patterns | Not implemented |
| Suffix matching | Not implemented |
| Multiple account derivation | Not implemented |
| Passphrase support | Not implemented |
| Progress persistence | Not implemented |
| Web UI | Not implemented |

---

## Verification Checklist

- [x] TODO/FIXME scan: `grep -rniE "TODO|FIXME|UNIMPLEMENTED|XXX|HACK" .`
- [x] unsafe usage: `grep -rn "unsafe" crates/`
- [x] Limits: `buffers.rs:9-18`, `main.rs:20,601`
- [x] Stack requirement: `.cargo/config.toml:7`
