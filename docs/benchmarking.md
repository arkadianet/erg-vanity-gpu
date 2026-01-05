# Benchmarking

GPU microbenchmark mode documentation, derived from source code.

## Running Benchmarks

### Basic Benchmark

```bash
./target/release/erg-vanity --bench
```

### With Validation

```bash
./target/release/erg-vanity --bench --bench-validate
```

### Custom Configuration

```bash
./target/release/erg-vanity --bench \
    --bench-iters 200 \
    --bench-warmup 10 \
    --bench-batch-size 524288 \
    --bench-num-indices 5
```

### Multi-Device Benchmark

```bash
./target/release/erg-vanity --bench --devices all
./target/release/erg-vanity --bench --devices 0,1
```

## CLI Flags

<!-- Source: crates/erg-vanity-cli/src/main.rs:63-84 -->

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--bench` | bool | `false` | Run GPU microbenchmark and exit |
| `--bench-iters <N>` | u32 | `100` | Number of timed iterations |
| `--bench-warmup <N>` | u32 | `5` | Warmup iterations before timing |
| `--bench-batch-size <N>` | usize | `262144` | Work items per batch |
| `--bench-num-indices <N>` | u32 | (from `--index`) | BIP44 indices per seed |
| `--bench-validate` | bool | `false` | Validate kernel outputs |

## Configuration Struct

<!-- Source: crates/erg-vanity-gpu/src/bench.rs:12-37 -->

```rust
pub struct BenchConfig {
    pub batch_size: usize,    // Default: 262,144 (1 << 18)
    pub num_indices: u32,     // Default: 1
    pub iters: u32,           // Default: 100
    pub warmup: u32,          // Default: 5
    pub validate: bool,       // Default: false
}
```

## Benchmark Components

<!-- Source: bench.rs:53-61 -->

Four GPU pipeline stages are timed independently:

| Component | Kernel | Scales with num_indices |
|-----------|--------|-------------------------|
| PBKDF2 | `bench_pbkdf2` | No (once per seed) |
| BIP32 | `bench_bip32` | Yes |
| secp256k1 | `bench_secp256k1` | Yes |
| Base58 | `bench_base58` | Yes |

## Output Format

<!-- Source: bench.rs:337-474 -->

### Header

```
GPU microbench (event timestamps), batch={batch_size}, iters={iters}, num_indices={num_indices}
```

### Per-Device Table

```
Device {idx}: {vendor} - {device_name}
{Component}:  {total_ms} ms ({percent}%)  avg {avg_ms} ms  {per_unit} ns/{unit}
...
TOTAL:        {total_ms} ms
```

### Per-Unit Metrics

| Component | Unit | Calculation |
|-----------|------|-------------|
| PBKDF2 | ns/seed | `total_ns / (iters × batch_size)` |
| BIP32 | ns/addr | `total_ns / (iters × batch_size × num_indices)` |
| secp256k1 | ns/addr | `total_ns / (iters × batch_size × num_indices)` |
| Base58 | ns/addr | `total_ns / (iters × batch_size × num_indices)` |

### Multi-Device Combined Table

When multiple devices are benchmarked:

```
Combined ({count} devices):
{Component}:  {total_ms} ms ({percent}%)  avg {avg_ms} ms  {per_unit} ns/{unit}
...
TOTAL:        {total_ms} ms
```

## Validation Mode

<!-- Source: bench.rs:166-187 -->

When `--bench-validate` is used:

1. Runs each kernel once with unique counter offset
2. Reads back checksum buffer
3. Checks for degenerate cases:
   - All zeros (kernel optimized away)
   - All identical (kernel not varying input)
4. Prints validation output:

```
Validating kernel outputs (checking for optimization artifacts)...

  {Component}: first {N} checksums:
    {hex1} {hex2} ... {hexN}
    unique={count}, xor_fold={hex}, all_zero={bool}, all_identical={bool}

Validation passed. All kernels producing varied, non-zero output.
```

### Validation Errors

<!-- Source: bench.rs:257-268 -->

| Error | Meaning |
|-------|---------|
| `all checksums are zero` | Kernel may be optimized away |
| `all checksums identical` | Kernel may not be varying input |

## Timing Method

<!-- Source: bench.rs:273-335 -->

Uses OpenCL event profiling:

1. Create event for each kernel enqueue
2. Wait for event completion
3. Read `ProfilingInfo::Start` and `ProfilingInfo::End` timestamps
4. Calculate: `elapsed_ns = end - start`

### Profiling Validation

```rust
// bench.rs:322-326
if start == 0 || end == 0 || end <= start {
    return Err(GpuError::Other(
        "profiling timestamps invalid; is CL_QUEUE_PROFILING_ENABLE set?".into(),
    ));
}
```

## Benchmark Kernels

<!-- Source: crates/erg-vanity-gpu/kernels/bench.cl -->

| Kernel | Line | Description |
|--------|------|-------------|
| `bench_pbkdf2` | `:62` | Full PBKDF2 with seed output |
| `bench_bip32` | `:96` | External chain + index derivation |
| `bench_secp256k1` | `:138` | Public key derivation × num_indices |
| `bench_base58` | `:188` | Full address encoding × num_indices |

### Kernel Signature

All benchmark kernels have uniform signature:

```c
__kernel void bench_{component}(
    __global const uchar* salt,
    ulong counter_start,
    __global const uchar* words8,
    __global const uchar* word_lens,
    uint num_indices,
    __global uint* checksums
);
```

## Example Output

```
GPU microbench (event timestamps), batch=262144, iters=100, num_indices=1

Device 0: NVIDIA Corporation - NVIDIA GeForce RTX 3080 Ti
PBKDF2:       4521.3 ms (85.2%)  avg   45.213 ms   172473 ns/seed
secp256k1:     421.7 ms ( 7.9%)  avg    4.217 ms    16083 ns/addr
BIP32:         312.5 ms ( 5.9%)  avg    3.125 ms    11921 ns/addr
Base58:         52.1 ms ( 1.0%)  avg    0.521 ms     1987 ns/addr
TOTAL:        5307.6 ms
```

---

## Verification Checklist

- [x] CLI flags: `main.rs:63-84`
- [x] BenchConfig: `bench.rs:12-37`
- [x] Components: `bench.rs:53-61`
- [x] Output format: `bench.rs:337-474`
- [x] Validation: `bench.rs:166-187`
- [x] Timing method: `bench.rs:273-335`
- [x] Kernel signatures: `bench.cl:62-188`
