# Glossary

Terms used in the codebase, derived from symbol names and documentation comments.

## Address Terms

### address

<!-- Source: main.rs:313, pipeline.rs VanityResult -->

Base58-encoded Ergo P2PK address string. Example: `9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA`

### address_index

<!-- Source: buffers.rs:30-31, main.rs:315 -->

BIP44 derivation index for the address path `m/44'/429'/0'/0/{index}`. Range: 0 to num_indices-1.

### P2PK

<!-- Source: crates/erg-vanity-address/src/p2pk.rs -->

Pay-to-Public-Key. Ergo address type that pays to a compressed public key.

## Key Derivation Terms

### entropy

<!-- Source: buffers.rs:11-12, generator.rs -->

32 bytes (256 bits) of random data used to generate a BIP39 mnemonic. Stored as 8 little-endian u32 words on GPU.

### mnemonic

<!-- Source: generator.rs, main.rs:316 -->

24-word BIP39 phrase derived from entropy. Can recover the entire wallet.

### seed

<!-- Source: bip39.rs, bip32.rs -->

64-byte value derived from mnemonic via PBKDF2-HMAC-SHA512 (2048 rounds). Used for BIP32 key derivation.

### master_key / master

<!-- Source: bip32.rs -->

Root key derived from seed. 32 bytes private key + 32 bytes chain code.

### chain_code

<!-- Source: bip32.rs -->

32 bytes used with private key for hierarchical derivation. Right half of HMAC-SHA512 output.

### private_key

<!-- Source: bip32.rs, generator.rs -->

32-byte scalar on secp256k1 curve. Used to derive public key.

### public_key / pubkey

<!-- Source: secp256k1/pubkey.rs, p2pk.rs -->

33-byte compressed point on secp256k1 curve. Prefix 0x02 or 0x03 + 32-byte x-coordinate.

## Pattern Terms

### pattern

<!-- Source: main.rs, buffers.rs -->

User-specified prefix to search for in generated addresses. Must start with '9' and valid second char for mainnet.

### pattern_index

<!-- Source: buffers.rs:32-33 -->

Index into the pattern list that matched a generated address.

### ignore_case

<!-- Source: main.rs:47, pipeline.rs -->

When true, pattern matching is case-insensitive. Patterns normalized to lowercase.

## GPU Terms

### batch

<!-- Source: pipeline.rs, bench.rs -->

Number of work items processed in a single GPU kernel execution. Default: 262,144.

### batch_size

<!-- Source: pipeline.rs:12 -->

Configuration for batch size. Determines global work size for kernel dispatch.

### device

<!-- Source: context.rs -->

OpenCL GPU device. Identified by global index across all platforms.

### device_index / global_idx

<!-- Source: context.rs:26-27 -->

Zero-indexed identifier for GPU device selection. Assigned sequentially across all platforms.

### hit

<!-- Source: buffers.rs:20-36 -->

GPU record of a matching address. 64-byte structure containing entropy, work_item_id, address_index, pattern_index.

### hit_count

<!-- Source: buffers.rs:64-65 -->

Atomic counter incremented by GPU when a match is found.

### work_item_id

<!-- Source: buffers.rs:28-29 -->

OpenCL work item (thread) ID that found a match. Used for result deduplication.

### salt

<!-- Source: buffers.rs:54, main.rs:358 -->

32-byte random value used to derive per-work-item entropy on GPU via Blake2b(salt || counter || work_item_id).

### counter

<!-- Source: pipeline.rs -->

64-bit value incremented by batch_size each iteration. Combined with salt and work_item_id for entropy generation.

## BIP Terms

### BIP32

<!-- Source: crates/erg-vanity-bip/src/bip32.rs -->

Bitcoin Improvement Proposal 32: Hierarchical Deterministic Wallets.

### BIP39

<!-- Source: crates/erg-vanity-bip/src/bip39.rs -->

Bitcoin Improvement Proposal 39: Mnemonic code for generating deterministic keys.

### BIP44

<!-- Source: crates/erg-vanity-bip/src/bip44.rs -->

Bitcoin Improvement Proposal 44: Multi-Account Hierarchy for Deterministic Wallets.

### hardened derivation

<!-- Source: bip32.rs -->

Child key derivation using index >= 2^31. Indicated by `'` in path (e.g., `44'`).

### normal derivation

<!-- Source: bip32.rs -->

Child key derivation using index < 2^31. No apostrophe in path.

## Crypto Terms

### Base58

<!-- Source: crates/erg-vanity-crypto/src/base58.rs -->

Encoding using 58 characters (0-9, A-Z, a-z excluding 0, O, I, l).

### Blake2b

<!-- Source: crates/erg-vanity-crypto/src/blake2b.rs -->

Cryptographic hash function. Used for address checksum (first 4 bytes of Blake2b-256).

### HMAC

<!-- Source: crates/erg-vanity-crypto/src/hmac.rs -->

Hash-based Message Authentication Code. Used with SHA-512 for key derivation.

### PBKDF2

<!-- Source: crates/erg-vanity-crypto/src/pbkdf2.rs -->

Password-Based Key Derivation Function 2. Used with HMAC-SHA512, 2048 rounds for BIP39.

### secp256k1

<!-- Source: crates/erg-vanity-crypto/src/secp256k1/ -->

Elliptic curve used for Ergo (and Bitcoin) public key cryptography.

### checksum

<!-- Source: p2pk.rs, blake2b.cl -->

First 4 bytes of Blake2b-256 hash, appended to address data before Base58 encoding.

## Network Terms

### Mainnet

<!-- Source: crates/erg-vanity-address/src/network.rs -->

Ergo main network. P2PK addresses start with '9'.

### Testnet

<!-- Source: crates/erg-vanity-address/src/network.rs -->

Ergo test network. P2PK addresses start with '3'.

---

## Verification Checklist

- [x] Terms: Derived from struct names, function names, and doc comments
- [x] Definitions: Based on code implementation
- [x] Sources: File paths referenced for each term
