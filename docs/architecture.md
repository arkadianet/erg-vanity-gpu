# Architecture

Workspace structure and crate dependencies, derived from `Cargo.toml` files.

## Workspace Structure

<!-- Source: Cargo.toml:3-11 -->

```
erg-vanity-gpu/
├── Cargo.toml          # Workspace root
├── crates/
│   ├── erg-vanity-core/
│   ├── erg-vanity-crypto/
│   ├── erg-vanity-bip/
│   ├── erg-vanity-address/
│   ├── erg-vanity-cpu/
│   ├── erg-vanity-gpu/
│   └── erg-vanity-cli/
```

## Crate Dependency Graph

```
                    ┌─────────────────┐
                    │  erg-vanity-cli │
                    │   (binary)      │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │ erg-vanity-core │  │  erg-vanity-cpu │  │  erg-vanity-gpu │
    └─────────────────┘  └────────┬────────┘  └────────┬────────┘
                                  │                     │
              ┌───────────────────┼─────────────────────┤
              │                   │                     │
              ▼                   ▼                     ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │ erg-vanity-core │  │ erg-vanity-bip  │  │ erg-vanity-addr │
    └─────────────────┘  └────────┬────────┘  └────────┬────────┘
                                  │                     │
                         ┌────────┴────────┐   ┌───────┴───────┐
                         ▼                 ▼   ▼               ▼
               ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
               │ erg-vanity-core │  │erg-vanity-crypto│  │ erg-vanity-core │
               └─────────────────┘  └────────┬────────┘  └─────────────────┘
                                             │
                                             ▼
                                   ┌─────────────────┐
                                   │ erg-vanity-core │
                                   └─────────────────┘
```

## Crate Details

### erg-vanity-core

<!-- Source: crates/erg-vanity-core/Cargo.toml -->

**Dependencies:** None (leaf crate)

**Purpose:** Core types, traits, and BIP39 wordlist

**Public Modules:**
- `error.rs` - Error types
- `wordlist.rs` - BIP39 English wordlist (2048 words)

### erg-vanity-crypto

<!-- Source: crates/erg-vanity-crypto/Cargo.toml:10 -->

**Dependencies:** `erg-vanity-core`

**Purpose:** Cryptographic primitives

**Public Modules:**
- `sha256.rs` - SHA-256
- `sha512.rs` - SHA-512
- `hmac.rs` - HMAC-SHA512
- `pbkdf2.rs` - PBKDF2-HMAC-SHA512
- `blake2b.rs` - Blake2b-256
- `base58.rs` - Base58 encoding
- `secp256k1/` - Elliptic curve cryptography
  - `field.rs` - Field element (Fp)
  - `scalar.rs` - Scalar (Fn)
  - `point.rs` - Curve points
  - `pubkey.rs` - Public key operations

### erg-vanity-bip

<!-- Source: crates/erg-vanity-bip/Cargo.toml:10-11 -->

**Dependencies:** `erg-vanity-core`, `erg-vanity-crypto`

**Purpose:** BIP39/BIP32/BIP44 implementations

**Public Modules:**
- `bip39.rs` - Entropy to mnemonic with NFKD normalization
- `bip32.rs` - Hierarchical deterministic key derivation
- `bip44.rs` - Standard derivation paths

### erg-vanity-address

<!-- Source: crates/erg-vanity-address/Cargo.toml:10-11 -->

**Dependencies:** `erg-vanity-core`, `erg-vanity-crypto`

**Purpose:** Ergo P2PK address encoding

**Public Modules:**
- `network.rs` - Network types (Mainnet, Testnet)
- `p2pk.rs` - P2PK address encoding with Blake2b checksum

### erg-vanity-cpu

<!-- Source: crates/erg-vanity-cpu/Cargo.toml:10-13 -->

**Dependencies:** `erg-vanity-core`, `erg-vanity-crypto`, `erg-vanity-bip`, `erg-vanity-address`

**Purpose:** CPU reference implementation

**Public Modules:**
- `generator.rs` - Single-threaded address generation
- `matcher.rs` - Pattern matching
- `parallel.rs` - Multi-threaded search via rayon

### erg-vanity-gpu

<!-- Source: crates/erg-vanity-gpu/Cargo.toml:15-18, 26 -->

**Dependencies:** `erg-vanity-core`, `erg-vanity-crypto`, `erg-vanity-bip`, `erg-vanity-address`

**Dev Dependencies:** `erg-vanity-cpu` (for validation tests)

**Purpose:** OpenCL GPU-accelerated implementation

**Public Modules:**
- `context.rs` - OpenCL context, device enumeration
- `kernel.rs` - Kernel compilation
- `buffers.rs` - GPU memory management
- `pipeline.rs` - Vanity search pipeline
- `hits.rs` - Hit verification
- `wordlist.rs` - GPU wordlist buffers
- `bench.rs` - Microbenchmark runner

### erg-vanity-cli

<!-- Source: crates/erg-vanity-cli/Cargo.toml:14-16 -->

**Dependencies:** `erg-vanity-core`, `erg-vanity-cpu`, `erg-vanity-gpu`

**Purpose:** Command-line interface

**Binary:** `erg-vanity`

## Data Flow

```
┌─────────────┐
│   Entropy   │ 32 bytes random
│  (random)   │
└──────┬──────┘
       │ SHA-256 checksum
       ▼
┌─────────────┐
│  Mnemonic   │ 24 words (BIP39)
│   (BIP39)   │
└──────┬──────┘
       │ PBKDF2-HMAC-SHA512 (2048 rounds)
       ▼
┌─────────────┐
│    Seed     │ 64 bytes
│   (BIP39)   │
└──────┬──────┘
       │ HMAC-SHA512
       ▼
┌─────────────┐
│ Master Key  │ 32 bytes private key + 32 bytes chain code
│   (BIP32)   │
└──────┬──────┘
       │ Derive: m/44'/429'/0'/0/{index}
       ▼
┌─────────────┐
│ Child Key   │ 32 bytes private key
│   (BIP44)   │
└──────┬──────┘
       │ secp256k1 scalar multiplication
       ▼
┌─────────────┐
│ Public Key  │ 33 bytes compressed
│ (secp256k1) │
└──────┬──────┘
       │ 0x01 + pubkey + Blake2b checksum
       ▼
┌─────────────┐
│   Address   │ 51 chars Base58
│  (P2PK)     │
└─────────────┘
```

### Code Path References

| Stage | CPU Source | GPU Source |
|-------|------------|------------|
| Entropy | `generator.rs` (rand) | `vanity.cl` (blake2b from salt+counter) |
| BIP39 | `bip39.rs` | `bip39.cl` |
| PBKDF2 | `pbkdf2.rs` | `pbkdf2.cl` |
| BIP32 | `bip32.rs` | `bip32.cl` |
| secp256k1 | `secp256k1/*.rs` | `secp256k1_*.cl` |
| Address | `p2pk.rs` | `base58.cl` |

## Validation Strategy

<!-- Source: crates/erg-vanity-cpu/tests/ergo_lib_validation.rs -->

1. CPU implementation tested against `ergo-lib =0.28.0` (`Cargo.toml:55`)
2. GPU results verified against CPU implementation
3. Each cryptographic component has unit tests against reference implementations

---

## Verification Checklist

- [x] Workspace members: `Cargo.toml:3-11`
- [x] Dependency graph: Individual crate `Cargo.toml` files
- [x] Crate purposes: Module inspection
- [x] ergo-lib version: `Cargo.toml:55`
