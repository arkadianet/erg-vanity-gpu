# Development Guide

Build, test, and contribution instructions derived from source code.

## Prerequisites

### Rust Toolchain

<!-- Source: Cargo.toml:15 -->

- **Edition:** 2021
- **Toolchain:** Stable (no nightly features required)

### OpenCL Development Headers

<!-- Source: .github/workflows/ci.yml:23, 34, 58 -->

Required packages (Ubuntu/Debian):
```bash
sudo apt-get install ocl-icd-opencl-dev opencl-headers
```

## Building

### Release Build

```bash
cargo build --release -p erg-vanity-cli
```

Binary location: `./target/release/erg-vanity`

### Debug Build

```bash
cargo build -p erg-vanity-cli
```

### All Crates

```bash
cargo build --workspace
```

## Release Profile

<!-- Source: Cargo.toml:57-60 -->

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
```

## Testing

### Run All Tests

```bash
cargo test --workspace
```

### Stack Size Configuration

<!-- Source: .cargo/config.toml:1-7 -->

OpenCL kernel compilation requires a larger stack. The repository includes automatic configuration:

```toml
# .cargo/config.toml
[env]
RUST_MIN_STACK = "16777216"
```

No manual environment variable needed.

### Manual Stack Override

If needed:
```bash
RUST_MIN_STACK=16777216 cargo test
```

## Linting

### Format Check

```bash
cargo fmt --all --check
```

### Format Fix

```bash
cargo fmt --all
```

### Clippy

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

## CI Pipeline

<!-- Source: .github/workflows/ci.yml:14-59 -->

| Job | Commands |
|-----|----------|
| `check` | `cargo check --workspace --all-targets` |
| `test` | `cargo test --workspace` |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |

All jobs run on `ubuntu-latest` with:
- `dtolnay/rust-toolchain@stable`
- OpenCL headers installed

## Validation Tests

### ergo-lib Validation

<!-- Source: crates/erg-vanity-cpu/tests/ergo_lib_validation.rs -->

Tests CPU implementation against reference `ergo-lib` library:

```bash
cargo test -p erg-vanity-cpu ergo_lib_validation
```

Tests verify:
- Entropy → Address derivation matches reference
- Mnemonic generation matches bip39 crate

### GPU Kernel Tests

<!-- Source: crates/erg-vanity-gpu/src/kernel.rs (test modules) -->

```bash
cargo test -p erg-vanity-gpu
```

Tests each cryptographic kernel against reference implementations.

## Feature Flags

### erg-vanity-gpu

<!-- Source: crates/erg-vanity-gpu/Cargo.toml -->

| Feature | Purpose |
|---------|---------|
| `test-kernels` | Include test kernels in build |

## Adding New Features

### New CLI Option

1. Add field to `Args` struct in `crates/erg-vanity-cli/src/main.rs:33`
2. Add clap attributes (`#[arg(...)]`)
3. Add validation logic if needed
4. Update usage in `main()` function

### New Pattern Validation

1. Modify `validate_pattern()` in `main.rs:91-179`
2. Add constants to `main.rs:14-26` if needed
3. Update error messages

### New GPU Kernel

1. Create `.cl` file in `crates/erg-vanity-gpu/kernels/`
2. Add `include_str!()` in `kernel.rs` sources module
3. Add to compilation chain in `GpuProgram::vanity()`
4. Create test kernel in `*_test.cl`
5. Add test in `kernel.rs` test module

### New Benchmark Component

1. Add kernel to `bench.cl`
2. Add `ComponentStats` field in `bench.rs`
3. Update `run_bench_on_device()` and `print_bench_results()`

## Binary: gen_g_table

<!-- Source: crates/erg-vanity-gpu/src/bin/gen_g_table.rs -->

Utility to generate precomputed generator table for windowed scalar multiplication:

```bash
cargo run -p erg-vanity-gpu --bin gen_g_table
```

## Environment Variables

| Variable | Purpose | Source |
|----------|---------|--------|
| `ERG_CL_VERBOSE` | Enable NVIDIA OpenCL diagnostics | `kernel.rs:58` |
| `RUST_MIN_STACK` | Stack size for tests | `.cargo/config.toml:7` |

---

## Verification Checklist

- [x] Edition: `Cargo.toml:15`
- [x] OpenCL packages: `.github/workflows/ci.yml:23`
- [x] Release profile: `Cargo.toml:57-60`
- [x] Stack config: `.cargo/config.toml:7`
- [x] CI jobs: `.github/workflows/ci.yml:14-59`
- [x] Validation tests: `crates/erg-vanity-cpu/tests/ergo_lib_validation.rs`
- [x] gen_g_table: `crates/erg-vanity-gpu/src/bin/gen_g_table.rs`
