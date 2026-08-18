# erg-vanity-gpu

[![CI](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml/badge.svg)](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml)

GPU-accelerated Ergo vanity address generator (OpenCL). Prefix search uses the GPU when OpenCL is available; otherwise the CPU path runs. Suffix and contains matching are CPU-only.

This is the surviving repo for arkadianet vanity tools. The older CPU/GUI project [ergo-vanitygen-rust](https://github.com/arkadianet/ergo-vanitygen-rust) is superseded here.

> **Early development — use at your own risk.**
>
> Crypto (BIP39, BIP32, secp256k1, …) was written from scratch and is not audited. Do not store significant funds on a generated address until you independently verify the mnemonic in trusted software (for example the official Ergo wallet).
>
> **Mnemonics and entropy are secrets.** Treat match output as a wallet dump. `Debug` redacts them; stdout does not.

## Features

- GPU prefix search (OpenCL); CPU fallback when no GPU is present
- Suffix / contains matching (`-e` / `--contains`) — CPU only
- Desktop GUI — run `erg-vanity` with no patterns
- `--estimate` before a long search
- Multi-GPU (`--devices 0,1` or `all`)
- Multiple patterns (up to 64; longest prefix wins)
- BIP44 path `m/44'/429'/0'/0/{index}` (default `--index 1`)

## Install

**Prerequisites:** Rust stable (2021 edition) and an OpenCL runtime.

```bash
# Ubuntu/Debian
sudo apt-get install ocl-icd-opencl-dev opencl-headers

# macOS: OpenCL is included
# Windows: install the GPU vendor OpenCL SDK (NVIDIA CUDA, AMD, or Intel)
```

```bash
git clone https://github.com/arkadianet/erg-vanity-gpu.git
cd erg-vanity-gpu
cargo build --release -p erg-vanity-cli
```

Binary: `./target/release/erg-vanity` (Windows: `.\target\release\erg-vanity.exe`).

PowerShell chains commands with `;`, not `&&`.

## Run

```bash
# Prefix search (GPU if available)
./target/release/erg-vanity 9err
./target/release/erg-vanity -p 9err,9ego,9fun
./target/release/erg-vanity -p 9ErGo -i
./target/release/erg-vanity -p 9err -n 5
./target/release/erg-vanity -p 9err --duration-secs 60

# CPU-only suffix
./target/release/erg-vanity -p cafe -e --devices cpu

# Difficulty estimate
./target/release/erg-vanity -p 9ergo --estimate

# Desktop GUI
./target/release/erg-vanity
```

`--index` defaults to **1** (`m/44'/429'/0'/0/0`). Pass `--index N` (1–100) if you want extra address slots on the same seed. Do not raise the default.

### Devices

```bash
./target/release/erg-vanity --list-devices
./target/release/erg-vanity -p 9err --devices 0,1
./target/release/erg-vanity -p 9err --devices all
./target/release/erg-vanity -p 9err --devices cpu
```

Default `--devices` is `auto` (GPU if present, else CPU).

### CLI

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --pattern <patterns>` | (required for CLI) | Comma-separated patterns |
| `[PATTERN]` | — | Legacy single positional pattern |
| `-e, --suffix` | off | Match at end of address (CPU) |
| `--contains` | off | Match anywhere (CPU) |
| `-i, --ignore-case` | off | Case-insensitive |
| `-n, --max-results <N>` | `1` | Stop after N matches |
| `--index <N>` | `1` | BIP44 indices per seed (1–100) |
| `--devices <list>` | `auto` | `auto`, `0,1`, `all`, or `cpu` |
| `--batch-size <N>` | device default | Search batch size |
| `--estimate` | off | Print difficulty and exit |
| `--no-gui` | off | Do not open the GUI |
| `--duration-secs <N>` | — | Maximum runtime |
| `--list-devices` | — | List GPUs and exit |
| `--bench` | off | GPU microbenchmark |
| `--bench-iters <N>` | `100` | Timed iterations |
| `--bench-warmup <N>` | `5` | Warmup iterations |
| `--bench-batch-size <N>` | `262144` | Bench batch size |
| `--bench-num-indices <N>` | from `--index` | Bench address indices |
| `--bench-validate` | off | Check bench kernels for degenerate output |

Exit codes: `0` success, `1` runtime error, `2` bad arguments / invalid pattern.

### Pattern rules

Prefix (GPU) patterns must look like a mainnet P2PK start:

- First character `9`
- Second character `e`, `f`, `g`, `h`, or `i` (uppercase allowed with `-i`)
- Base58 only (no `0`, `O`, `I`, `l`)
- Max 32 characters per pattern, 64 patterns, 1024 bytes total

Valid: `9e`, `9err`, `9ergo`, `9fUN`, `9heLLo`

Invalid prefix: `9a` (second char), `9eO` (Base58), `8err` (first char)

Suffix / contains skip the `9e`–`9i` prefix rule.

## Output

```
=== Match 1 ===
Device:   0
Address:  9errK7Qa3oBVHbS4uGFPSe7ETvfHkZGcskV1gqGf6fqLUPAamo
Pattern:  9err
Path:     m/44'/429'/0'/0/0
Mnemonic: … 24 words …
Entropy:  … 64 hex chars …
```

`Mnemonic` and `Entropy` recover the wallet. Every shown hit is re-checked with `ergo-lib` before print.

Progress goes to stderr: `Checked: N (rate addr/s) [found/target]`.

## Performance

Measured **RTX 3080 Ti**, 18 Aug 2026, default `--index 1`, after 8-bit windowed *k*·G:

| Mode | Result |
|------|--------|
| Live search | ~368k seeds/s (earlier live baseline ~330k) |
| Isolated PBKDF2 | ~1600 ns/seed (~56–64% of isolated time) |
| Isolated BIP32 | ~628 ns/addr |
| Isolated secp256k1 | ~285 ns/addr |

`--bench` times isolated kernels (OpenCL event timestamps). Isolated PBKDF2 share is **not** ~85% and **not** ~172 µs/seed — those figures are stale.

```bash
./target/release/erg-vanity --bench
./target/release/erg-vanity --bench --bench-validate
```

Expected wait for a **single** prefix on a 3080 Ti at ~368k seeds/s:

| Pattern | Combinations | Expected time |
|---------|--------------|---------------|
| 4 chars (`9err`) | ~200K | < 1 second |
| 5 chars (`9ergo`) | ~11M | ~30 seconds |
| 6 chars (`9ergoo`) | ~650M | ~30 minutes |
| 7 chars | ~38B | ~1.2 days |

Rates vary by GPU, driver, and pattern. RTX 4090 is higher; we have not published a current measurement.

## How it works

1. Entropy from CSPRNG salt + counter (Blake2b on GPU)
2. BIP39: 24-word mnemonic
3. PBKDF2-HMAC-SHA512 (2048 rounds) → seed
4. BIP32/44: `m/44'/429'/0'/0/{index}`
5. secp256k1 compressed pubkey
6. Ergo P2PK (Blake2b checksum + Base58)
7. Pattern match

GPU work items run that pipeline in parallel. P2PK mainnet only; path is not configurable. Short patterns can overflow the 1024-hit GPU buffer (a warning is printed).

## Docs

| Document | Contents |
|----------|----------|
| [Security](docs/security.md) | Secrets, Debug redaction, entropy, verification |
| [Development](docs/development.md) | Build, test, CI, GPU kernels, crate map |

## License

MIT. Author: arkadianet.

Contributions welcome: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and tests. See [docs/development.md](docs/development.md).
