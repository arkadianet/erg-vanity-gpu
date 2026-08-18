# Security

Author: arkadianet

> Early development. Implementations are not audited. Verify any funded mnemonic in the official Ergo wallet (or other trusted software) before use.

## Secrets

A match prints a 24-word BIP39 mnemonic and 32-byte entropy. Either is enough to spend. Treat stdout, terminal scrollback, and logs as a wallet dump.

`Debug` on `VanityResult` and `GeneratedAddress` prints `<redacted>` for mnemonic, entropy, and private key. The CLI still prints the real mnemonic on a hit — that is intentional.

Keys stay in memory. They are not written to disk by this tool. Memory (CPU and GPU) is not explicitly zeroed after use.

## Entropy

Search salt comes from the platform CSPRNG (`rand::thread_rng()` / `OsRng`). GPU work items then derive per-item entropy with Blake2b(salt ‖ counter ‖ work_item_id).

## Verification

- CPU primitives are tested against `sha2`, `hmac`, `pbkdf2`, `blake2`, `bs58`, `k256`, and `ergo-lib` 0.28.0.
- Every hit shown to the user is re-derived with `ergo-lib` before it is printed.

That does not replace an independent wallet check for funds.

## `unsafe`

Leaf crates (`core`, `crypto`, `bip`, `address`, `cpu`) forbid `unsafe`. Remaining `unsafe` is OpenCL FFI via the `ocl` crate (kernel enqueue and buffer element types).
