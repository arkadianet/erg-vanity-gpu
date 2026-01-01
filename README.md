# erg-vanity-gpu

[![CI](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml/badge.svg)](https://github.com/arkadianet/erg-vanity-gpu/actions/workflows/ci.yml)

GPU-accelerated Ergo vanity address generator using OpenCL.

> **WARNING: Early Development**
>
> This project is in early development. While initial testing looks promising, the code has not been audited or extensively tested. The cryptographic implementations (BIP39, BIP32, secp256k1, etc.) were written from scratch and may contain bugs.
>
> **Use at your own risk.** Do not use generated addresses for significant funds without independently verifying the mnemonic produces the expected address using trusted software (e.g., official Ergo wallet).

## Usage

```bash
cargo build --release -p erg-vanity-cli
./target/release/erg-vanity [OPTIONS] [PATTERN]
```

### Options

| Option | Description |
|--------|-------------|
| `-p, --pattern <patterns>` | Comma-separated patterns (e.g., `9err,9ego`) |
| `-i, --ignore-case` | Case-insensitive matching |
| `-n, --max-results <N>` | Number of matches to find (default: 1, `--num` alias) |
| `--index <N>` | BIP44 indices per seed: `m/44'/429'/0'/0/{0..N-1}` (default: 1) |
| `--list-devices` | List available OpenCL devices and exit |
| `--devices <csv\|all>` | Comma-separated device indices or `all` (default: `0`) |
| `--duration-secs <S>` | Stop after `S` seconds |

### Examples

```bash
# Find address starting with 9err
./target/release/erg-vanity 9err

# Multiple patterns, case-insensitive, find 3 matches
./target/release/erg-vanity -p 9err,9ego -i -n 3

# Check first 10 address indices per seed
./target/release/erg-vanity -p 9ergo --index 10

# List devices and search across all GPUs for 2 matches or up to 60 seconds
./target/release/erg-vanity --list-devices
./target/release/erg-vanity -p 9err --devices all --max-results 2 --duration-secs 60
```

Ergo mainnet P2PK addresses start with `9e`, `9f`, `9g`, `9h`, or `9i`.

## Performance

~270K addresses/second on RTX 3080 Ti.

## Testing

```bash
cargo test
```

OpenCL kernel compilation can require a larger stack than the default. The repo includes `.cargo/config.toml` which sets `RUST_MIN_STACK=16777216` automatically, so no manual environment variables are needed.

## Project Structure

- `erg-vanity-core` - Shared types, BIP39 wordlist
- `erg-vanity-crypto` - SHA-256/512, HMAC, PBKDF2, secp256k1, Blake2b, Base58
- `erg-vanity-bip` - BIP39/BIP32/BIP44 implementation
- `erg-vanity-address` - Ergo P2PK address encoding
- `erg-vanity-cpu` - CPU reference implementation
- `erg-vanity-gpu` - OpenCL kernels and pipeline
- `erg-vanity-cli` - CLI interface

## License

MIT
