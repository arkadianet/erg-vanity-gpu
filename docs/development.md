# Development

Author: arkadianet

Hub usage is in the [README](../README.md). This page is for building, testing, and GPU work.

## Build and test

```bash
cargo build --release -p erg-vanity-cli
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

PowerShell: use `;` between commands, not `&&`.

`.cargo/config.toml` sets `RUST_MIN_STACK=16777216` (OpenCL compile). Windows MSVC/GNU targets also raise the link stack.

GPU kernel tests skip unless `ERG_RUN_GPU_TESTS=1`:

```bash
# Unix
ERG_RUN_GPU_TESTS=1 cargo test -p erg-vanity-gpu

# PowerShell
$env:ERG_RUN_GPU_TESTS=1; cargo test -p erg-vanity-gpu
```

Release profile: LTO, `codegen-units = 1`, `opt-level = 3`.

CI (`ubuntu-latest`): check, test, rustfmt, clippy. OpenCL headers are installed; runners have no GPU, so kernel tests stay skipped.

## Crates

```text
erg-vanity-cli  → engine, gui, gpu (bench)
erg-vanity-gui  → engine (eframe/egui)
erg-vanity-engine → cpu, gpu, address, ergo-lib verify
erg-vanity-gpu  → bip, address, crypto, core   (+ cpu for tests)
erg-vanity-cpu  → bip, address, crypto, core
erg-vanity-bip / address → crypto → core
```

`erg-vanity` with no patterns opens the GUI (`--no-gui` to skip).

## GPU kernels

Sources live in `crates/erg-vanity-gpu/kernels/`. They are concatenated at runtime (`-cl-std=CL1.2`):

`sha256` → `sha512` → `hmac_sha512` → `pbkdf2` → `secp256k1_fe` → `secp256k1_scalar` → `g_table` → `secp256k1_point` → `blake2b` → `base58` → `bip39` → `bip32` → `vanity`

`g_table.cl` is the 8-bit windowed *k*·G table (regenerate with `cargo run -p erg-vanity-gpu --bin gen_g_table`).

NVIDIA compile diagnostics:

```bash
ERG_CL_VERBOSE=1 cargo test -p erg-vanity-gpu
```

Limits that matter when changing kernels: 1024 hits/batch, 64 patterns, 1024 bytes of pattern data, `--index` max 100. Default batch is device-chosen for search; `--bench` defaults to 262144.

## Benchmarks

`--bench` times isolated PBKDF2, BIP32, secp256k1, and Base58 kernels (event timestamps). PBKDF2 is per seed; the others scale with `--index`.

`--bench` is not live search. On RTX 3080 Ti (19 Aug 2026, `--index 1`) isolated PBKDF2 is ~1600 ns/seed (~56–64% of isolated time), BIP32 ~628 ns, secp ~285 ns. Live search is ~600k seeds/s (measured ~590–610k after comb + batched W; earlier baselines ~330k then ~368k then ~455k).

## Environment

| Variable | Purpose |
|----------|---------|
| `ERG_CL_VERBOSE=1` | NVIDIA OpenCL register/spill log |
| `ERG_RUN_GPU_TESTS=1` | Run OpenCL kernel unit tests |
| `RUST_MIN_STACK` | Set automatically via `.cargo/config.toml` |
