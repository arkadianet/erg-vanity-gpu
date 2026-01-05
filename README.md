# erg-vanity-gpu

[![CI](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml/badge.svg)](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml)

GPU-accelerated Ergo vanity address generator using OpenCL.

Generate Ergo addresses matching custom prefixes at high speed using your GPU. Supports multi-GPU configurations, case-insensitive matching, and multiple patterns simultaneously.

> **WARNING: Early Development**
>
> This project is in early development. While initial testing looks promising, the code has not been audited or extensively tested. The cryptographic implementations (BIP39, BIP32, secp256k1, etc.) were written from scratch and may contain bugs.
>
> **Use at your own risk.** Do not use generated addresses for significant funds without independently verifying the mnemonic produces the expected address using trusted software (e.g., official Ergo wallet).

## Features

- **GPU-accelerated** - OpenCL-based parallel address generation
- **Multi-GPU support** - Use multiple GPUs simultaneously
- **Multiple patterns** - Search for up to 64 patterns at once
- **Case-insensitive** - Optional case-insensitive matching
- **BIP44 compliant** - Standard derivation path `m/44'/429'/0'/0/{index}`
- **Benchmark mode** - Per-component GPU timing analysis

## Installation

### Prerequisites

- Rust 2021 edition (stable toolchain)
- OpenCL runtime and development headers

**Ubuntu/Debian:**
```bash
sudo apt-get install ocl-icd-opencl-dev opencl-headers
```

**macOS:**
```bash
# OpenCL is included with macOS
```

**Windows:**
```bash
# Install GPU vendor's OpenCL SDK (NVIDIA CUDA Toolkit, AMD ROCm, or Intel OpenCL)
```

### Build

```bash
git clone https://github.com/arkadianet/erg-vanity-gpu.git
cd erg-vanity-gpu
cargo build --release -p erg-vanity-cli
```

The binary is at `./target/release/erg-vanity`.

## Usage

### Basic Examples

```bash
# Find an address starting with "9err"
./target/release/erg-vanity 9err

# Multiple patterns (finds any match)
./target/release/erg-vanity -p 9err,9ego,9fun

# Case-insensitive search
./target/release/erg-vanity -p 9ErGo -i

# Find 5 matching addresses
./target/release/erg-vanity -p 9err -n 5

# Time-limited search (60 seconds)
./target/release/erg-vanity -p 9err --duration-secs 60
```

### Multi-GPU Usage

```bash
# List available GPUs
./target/release/erg-vanity --list-devices

# Use specific GPUs by index
./target/release/erg-vanity -p 9err --devices 0,1

# Use all available GPUs
./target/release/erg-vanity -p 9err --devices all
```

### Advanced Options

```bash
# Check multiple BIP44 address indices per seed (increases matches per seed)
./target/release/erg-vanity -p 9err --index 10

# Combined: all GPUs, case-insensitive, 5 matches, 10 indices per seed
./target/release/erg-vanity -p 9err --devices all -i -n 5 --index 10
```

## CLI Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-p, --pattern <patterns>` | String | (required) | Comma-separated patterns to search |
| `-i, --ignore-case` | Flag | `false` | Case-insensitive matching |
| `-n, --max-results <N>` | Integer | `1` | Stop after finding N matches |
| `--index <N>` | Integer | `1` | BIP44 indices per seed (1-100) |
| `--devices <list>` | String | `0` | Device indices (e.g., `0,1,2`) or `all` |
| `--duration-secs <N>` | Integer | - | Maximum runtime in seconds |
| `--list-devices` | Flag | - | List available GPUs and exit |
| `--bench` | Flag | - | Run GPU microbenchmark |
| `--bench-iters <N>` | Integer | `100` | Benchmark iterations |
| `--bench-warmup <N>` | Integer | `5` | Benchmark warmup iterations |
| `--bench-batch-size <N>` | Integer | `262144` | Benchmark batch size |
| `--bench-validate` | Flag | `false` | Validate benchmark outputs |

See [docs/cli-reference.md](docs/cli-reference.md) for complete documentation.

### Pattern Rules

Ergo mainnet P2PK addresses have specific constraints:

- **First character:** Must be `9`
- **Second character:** Must be `e`, `f`, `g`, `h`, or `i`
- **Valid characters:** Base58 alphabet (no `0`, `O`, `I`, `l`)
- **Maximum length:** 32 characters per pattern
- **Maximum patterns:** 64

**Valid examples:** `9e`, `9err`, `9ergo`, `9fUN`, `9heLLo`

**Invalid examples:** `9a` (wrong second char), `9eO` (invalid Base58), `8err` (wrong first char)

## Output Format

When a match is found:

```
=== Match 1 ===
Device:   0
Address:  9errK7Qa3oBVHbS4uGFPSe7ETvfHkZGcskV1gqGf6fqLUPAamo
Pattern:  9err
Path:     m/44'/429'/0'/0/0
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
Entropy:  0000000000000000000000000000000000000000000000000000000000000000
```

| Field | Description |
|-------|-------------|
| `Device` | GPU index that found the match |
| `Address` | Generated Ergo P2PK address |
| `Pattern` | Which pattern matched |
| `Path` | BIP44 derivation path |
| `Mnemonic` | 24-word recovery phrase (**SENSITIVE**) |
| `Entropy` | 32-byte hex seed (**SENSITIVE**) |

See [docs/output-format.md](docs/output-format.md) for all output formats.

## Benchmarking

Measure per-component GPU performance:

```bash
# Basic benchmark
./target/release/erg-vanity --bench

# With validation (ensures kernels produce correct output)
./target/release/erg-vanity --bench --bench-validate

# Custom configuration
./target/release/erg-vanity --bench --bench-iters 200 --bench-batch-size 524288
```

**Example output:**
```
GPU microbench (event timestamps), batch=262144, iters=100, num_indices=1

Device 0: NVIDIA Corporation - NVIDIA GeForce RTX 3080 Ti
PBKDF2:       4521.3 ms (85.2%)  avg   45.213 ms   172473 ns/seed
secp256k1:     421.7 ms ( 7.9%)  avg    4.217 ms    16083 ns/addr
BIP32:         312.5 ms ( 5.9%)  avg    3.125 ms    11921 ns/addr
Base58:         52.1 ms ( 1.0%)  avg    0.521 ms     1987 ns/addr
TOTAL:        5307.6 ms
```

See [docs/benchmarking.md](docs/benchmarking.md) for details.

## Project Structure

```
erg-vanity-gpu/
├── crates/
│   ├── erg-vanity-core/      # BIP39 wordlist, error types
│   ├── erg-vanity-crypto/    # SHA, HMAC, PBKDF2, secp256k1, Blake2b, Base58
│   ├── erg-vanity-bip/       # BIP39/BIP32/BIP44 implementation
│   ├── erg-vanity-address/   # Ergo P2PK address encoding
│   ├── erg-vanity-cpu/       # CPU reference implementation
│   ├── erg-vanity-gpu/       # OpenCL kernels and GPU pipeline
│   │   └── kernels/          # 23 OpenCL kernel files
│   └── erg-vanity-cli/       # CLI binary
└── docs/                     # Documentation
```

See [docs/architecture.md](docs/architecture.md) for crate dependencies and data flow.

## Development

### Building

```bash
# Debug build
cargo build -p erg-vanity-cli

# Release build (optimized)
cargo build --release -p erg-vanity-cli

# Build all crates
cargo build --workspace
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p erg-vanity-gpu
```

The repository includes `.cargo/config.toml` which automatically sets `RUST_MIN_STACK=16777216` for OpenCL kernel compilation.

### Linting

```bash
# Check formatting
cargo fmt --all --check

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings
```

See [docs/development.md](docs/development.md) for contribution guidelines.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ERG_CL_VERBOSE=1` | Enable NVIDIA OpenCL compiler diagnostics (register usage, spills) |

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Reference](docs/cli-reference.md) | Complete CLI argument documentation |
| [Output Formats](docs/output-format.md) | All stdout/stderr output specifications |
| [Architecture](docs/architecture.md) | Crate structure, dependencies, data flow |
| [GPU Implementation](docs/gpu-implementation.md) | OpenCL kernels, memory layout, device selection |
| [Development](docs/development.md) | Build, test, CI, contribution guide |
| [Benchmarking](docs/benchmarking.md) | GPU benchmark mode and interpretation |
| [Security](docs/security.md) | Entropy sources, key handling, unsafe audit |
| [Limitations](docs/limitations.md) | Known limitations, resource constraints |
| [Glossary](docs/glossary.md) | Term definitions with code references |

## How It Works

1. **Entropy Generation:** Random 32-byte salt combined with counter via Blake2b
2. **BIP39:** Entropy → SHA-256 checksum → 24-word mnemonic
3. **PBKDF2:** Mnemonic → 64-byte seed (2048 rounds HMAC-SHA512)
4. **BIP32:** Seed → Master key → Derive `m/44'/429'/0'/0/{index}`
5. **secp256k1:** Private key → Compressed public key (33 bytes)
6. **Address:** Prefix + pubkey + Blake2b checksum → Base58 encoding
7. **Pattern Match:** Compare address prefix against patterns

The GPU parallelizes steps 1-7 across thousands of work items simultaneously.

## Performance

Performance depends on GPU model and pattern length. Longer patterns are rarer and take longer to find.

| GPU | Approximate Rate |
|-----|------------------|
| RTX 3080 Ti | ~330K addr/s |
| RTX 4090 | ~500K addr/s (estimated) |

**Expected search times (RTX 3080 Ti, single pattern):**

| Pattern Length | Combinations | Expected Time |
|----------------|--------------|---------------|
| 4 chars (`9err`) | ~200K | < 1 second |
| 5 chars (`9ergo`) | ~11M | ~30 seconds |
| 6 chars (`9ergoo`) | ~650M | ~30 minutes |
| 7 chars | ~38B | ~1.3 days |

## Security

- **Entropy:** Uses `rand::thread_rng()` (platform CSPRNG)
- **Memory only:** Keys never written to disk
- **Validation:** Tested against `ergo-lib` reference implementation

See [docs/security.md](docs/security.md) for details.

## License

MIT

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Run `cargo fmt` and `cargo clippy`
4. Add tests for new functionality
5. Submit a pull request

See [docs/development.md](docs/development.md) for details.
