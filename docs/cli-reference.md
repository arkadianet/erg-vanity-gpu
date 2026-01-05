# CLI Reference

Complete command-line interface documentation for `erg-vanity`.

## Binary

<!-- Source: crates/erg-vanity-cli/Cargo.toml, crates/erg-vanity-cli/src/main.rs -->

- **Name:** `erg-vanity`
- **Package:** `erg-vanity-cli`
- **Source:** `crates/erg-vanity-cli/src/main.rs`

## Arguments

All arguments extracted from clap `#[derive(Parser)]` struct.

<!-- Source: crates/erg-vanity-cli/src/main.rs:28-88 -->

### Device Selection

| Argument | Source Line | Type | Default | Description |
|----------|-------------|------|---------|-------------|
| `--list-devices` | `:35` | `bool` | `false` | List all available OpenCL devices and exit |
| `--devices <list>` | `:39` | `String` | `"0"` | Comma-separated device indices to use, or `"all"` |

### Pattern Matching

| Argument | Source Line | Type | Default | Description |
|----------|-------------|------|---------|-------------|
| `-p, --pattern <patterns>` | `:43` | `Vec<String>` | (required) | Pattern(s) to search for (comma-separated) |
| `-i, --ignore-case` | `:47` | `bool` | `false` | Case-insensitive matching |

### Search Control

| Argument | Source Line | Type | Default | Constraints | Description |
|----------|-------------|------|---------|-------------|-------------|
| `-n, --max-results <N>` | `:51` | `usize` | `1` | min: 1 (`:607`) | Maximum matches before stopping |
| `--index <N>` | `:55` | `u32` | `1` | min: 1, max: 100 (`:597-603`) | BIP44 indices per seed |
| `--duration-secs <N>` | `:59` | `Option<u64>` | `None` | - | Maximum runtime in seconds |

### Benchmark Mode

| Argument | Source Line | Type | Default | Description |
|----------|-------------|------|---------|-------------|
| `--bench` | `:63` | `bool` | `false` | Run GPU microbenchmark and exit |
| `--bench-iters <N>` | `:67` | `u32` | `100` | Number of benchmark iterations |
| `--bench-warmup <N>` | `:71` | `u32` | `5` | Warmup iterations before timing |
| `--bench-batch-size <N>` | `:75` | `Option<usize>` | `262144` | Batch size for benchmark |
| `--bench-num-indices <N>` | `:79` | `Option<u32>` | (from `--index`) | Address indices for benchmark |
| `--bench-validate` | `:83` | `bool` | `false` | Validate benchmark results |

### Positional Arguments

| Argument | Source Line | Type | Default | Description |
|----------|-------------|------|---------|-------------|
| `[PATTERN]` | `:87` | `Option<String>` | `None` | Legacy: single pattern as positional argument |

## Pattern Validation

<!-- Source: crates/erg-vanity-cli/src/main.rs:91-179 -->

### Constants

<!-- Source: crates/erg-vanity-cli/src/main.rs:14-26 -->

```rust
// main.rs:14
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// main.rs:17
const VALID_SECOND_CHARS: &[char] = &['e', 'f', 'g', 'h', 'i'];

// main.rs:20
const MAX_PATTERN_LEN: usize = 32;

// main.rs:23
const MAX_PATTERNS: usize = 64;

// main.rs:26
const MAX_PATTERN_DATA: usize = 1024;
```

### Validation Rules

1. **Non-empty** (`main.rs:95-97`): Pattern must not be empty
2. **Length limit** (`main.rs:98-105`): Maximum 32 characters
3. **ASCII only** (`main.rs:107-113`): Non-ASCII characters rejected
4. **Base58 alphabet** (`main.rs:115-124`): Characters must be in `BASE58_ALPHABET`
5. **First char '9'** (`main.rs:129-135`): Ergo mainnet P2PK addresses start with `9`
6. **Second char validation** (`main.rs:137-170`):
   - If pattern length >= 2, second char must be in `VALID_SECOND_CHARS`
   - With `--ignore-case`, uppercase `E/F/G/H/I` are normalized to lowercase
   - Without `--ignore-case`, uppercase second char produces helpful error

### Aggregate Validation

<!-- Source: crates/erg-vanity-cli/src/main.rs:181-231 -->

- **Pattern count** (`main.rs:206-213`): Maximum 64 patterns
- **Total data size** (`main.rs:215-222`): Combined patterns must not exceed 1024 bytes

## Exit Codes

<!-- Source: crates/erg-vanity-cli/src/main.rs -->

| Code | Meaning | Source Lines |
|------|---------|--------------|
| `0` | Success | (implicit) |
| `1` | Runtime error (device error, search failed) | `:549`, `:578`, `:657` |
| `2` | Validation error (invalid pattern, bad arguments) | `:560`, `:592`, `:599`, `:602`, `:609`, `:616` |

## Examples

All examples use flags exactly as defined in clap.

```bash
# Single pattern (positional)
./target/release/erg-vanity 9err

# Single pattern (flag)
./target/release/erg-vanity -p 9err

# Multiple patterns
./target/release/erg-vanity -p 9err,9ego,9fun

# Case-insensitive matching
./target/release/erg-vanity -p 9ERR -i

# Find 5 matches
./target/release/erg-vanity -p 9err -n 5

# Check multiple BIP44 indices per seed
./target/release/erg-vanity -p 9err --index 10

# Time-limited search
./target/release/erg-vanity -p 9err --duration-secs 60

# Use all GPUs
./target/release/erg-vanity -p 9err --devices all

# Use specific GPUs
./target/release/erg-vanity -p 9err --devices 0,2

# List available devices
./target/release/erg-vanity --list-devices

# Run benchmark
./target/release/erg-vanity --bench

# Benchmark with validation
./target/release/erg-vanity --bench --bench-validate
```

---

## Verification Checklist

- [x] CLI options: `crates/erg-vanity-cli/src/main.rs:28-88`
- [x] Defaults: `default_value` / `default_value_t` attributes in struct
- [x] Constraints: `main.rs:597-609` (index bounds), `main.rs:607-609` (max_results)
- [x] Pattern validation: `main.rs:91-179`
- [x] Exit codes: `std::process::exit()` calls in `main.rs`
