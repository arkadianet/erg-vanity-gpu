# Security

Security considerations derived from code analysis.

## Warning

> **Early Development**
>
> This project is in early development. The cryptographic implementations (BIP39, BIP32, secp256k1, etc.) were written from scratch and may contain bugs.
>
> **Use at your own risk.** Do not use generated addresses for significant funds without independently verifying the mnemonic produces the expected address using trusted software.

## Entropy Sources

### CLI (GPU Mode)

<!-- Source: crates/erg-vanity-cli/src/main.rs:358 -->

```rust
// main.rs:358
rand::thread_rng().fill_bytes(&mut salt);
```

- Uses `rand::thread_rng()` (platform-specific CSPRNG)
- Generates 32-byte salt
- Entropy derived on GPU via Blake2b(salt || counter || work_item_id)

### GPU Pipeline

<!-- Source: crates/erg-vanity-gpu/src/pipeline.rs:107 -->

```rust
// pipeline.rs:107
rand::thread_rng().fill_bytes(&mut salt);
```

Same as CLI mode.

### CPU Parallel Mode

<!-- Source: crates/erg-vanity-cpu/src/parallel.rs:43 -->

```rust
// parallel.rs:43
OsRng.fill_bytes(&mut salt);
```

- Uses `OsRng` (OS-provided entropy)
- Entropy extended via per-thread counter

### CPU Generator

<!-- Source: crates/erg-vanity-cpu/src/generator.rs:12, 45 -->

```rust
// generator.rs:12
use rand::{CryptoRng, RngCore};

// generator.rs:45
rng.fill_bytes(&mut entropy);
```

- Accepts any `RngCore + CryptoRng` implementation
- Caller controls entropy source

## Key Material Handling

### Memory Only

Based on code analysis, private keys and mnemonics are:
- Generated in memory
- Printed to stdout immediately
- Not written to files

No file I/O for sensitive material found in:
- `crates/erg-vanity-cli/src/main.rs`
- `crates/erg-vanity-cpu/src/generator.rs`
- `crates/erg-vanity-gpu/src/pipeline.rs`

### Output Contains Sensitive Data

<!-- Source: main.rs:310-317 -->

Match output includes:
- `Mnemonic: {24 words}` - Can recover all funds
- `Entropy: {hex}` - Can derive mnemonic
- `Address: {base58}` - Public, not sensitive

**Recommendation:** Treat stdout as sensitive when matches are found.

## unsafe Code Usage

### Crates with #![forbid(unsafe_code)]

<!-- Source: grep "#!\[forbid(unsafe_code)\]" -->

| Crate | Files |
|-------|-------|
| `erg-vanity-core` | All |
| `erg-vanity-crypto` | All |
| `erg-vanity-bip` | All |
| `erg-vanity-address` | All |
| `erg-vanity-cpu` | All |

### Crates with unsafe Blocks

<!-- Source: grep "unsafe" -->

| File | Lines | Context |
|------|-------|---------|
| `kernel.rs` | :375, :449, :513, :597, :678, :759, :830, :882, :945, :1021, :1098, :1160, :1334 | OpenCL kernel enqueue |
| `pipeline.rs` | :204, :231 | OpenCL kernel enqueue |
| `bench.rs` | :179, :297, :312 | OpenCL kernel enqueue |
| `buffers.rs` | :39 | `unsafe impl ocl::OclPrm for GpuHit` |

All unsafe usage is for OpenCL FFI via the `ocl` crate:
- `kernel.cmd().enq()` - Kernel execution
- `unsafe impl OclPrm` - Buffer element type trait

## Validation

### ergo-lib Reference

<!-- Source: Cargo.toml:55, crates/erg-vanity-cpu/tests/ergo_lib_validation.rs -->

CPU implementation is tested against `ergo-lib =0.28.0`:
- Entropy → Address derivation
- Mnemonic generation

### Cryptographic Component Tests

Each crypto primitive is tested against standard library implementations:
- SHA-256/512 vs `sha2` crate
- HMAC vs `hmac` crate
- PBKDF2 vs `pbkdf2` crate
- Blake2b vs `blake2` crate
- Base58 vs `bs58` crate
- secp256k1 vs `k256` crate

## Recommendations

1. **Independent Verification:** Before using generated addresses for significant funds, verify the mnemonic produces the expected address using trusted software (e.g., official Ergo wallet).

2. **Secure Terminal:** When running the tool, ensure stdout is not being logged or captured by untrusted processes.

3. **Memory Clearing:** The current implementation does not explicitly zero sensitive memory after use. Consider this for high-security use cases.

4. **GPU Memory:** GPU memory containing entropy/keys is deallocated but not explicitly zeroed. Consider this for multi-tenant GPU environments.

## Unknown from Code

The following security properties could not be verified from code:

- Whether `rand::thread_rng()` is properly seeded on all platforms
- GPU memory isolation between processes
- Timing side-channel resistance in cryptographic operations
- Stack/register clearing after function returns

---

## Verification Checklist

- [x] Entropy sources: `main.rs:358`, `pipeline.rs:107`, `parallel.rs:43`, `generator.rs:45`
- [x] Key material storage: Verified no file I/O for keys
- [x] unsafe usage: Grep for `unsafe` in codebase
- [x] Validation tests: `ergo_lib_validation.rs`, dev-dependencies in crypto crate
