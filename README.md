# erg-vanity-gpu

GPU-accelerated Ergo vanity address generator using OpenCL.

> **WARNING: Early Development**
>
> This project is in early development. While initial testing looks promising, the code has not been audited or extensively tested. The cryptographic implementations (BIP39, BIP32, secp256k1, etc.) were written from scratch and may contain bugs.
>
> **Use at your own risk.** Do not use generated addresses for significant funds without independently verifying the mnemonic produces the expected address using trusted software (e.g., official Ergo wallet).

## Usage

```bash
cargo build --release -p erg-vanity-cli
./target/release/erg-vanity <prefix>
```

Example:
```bash
./target/release/erg-vanity 9err
```

Ergo mainnet P2PK addresses start with `9e`, `9f`, `9g`, `9h`, or `9i`.

## Performance

~270K addresses/second on RTX 3080 Ti.

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
