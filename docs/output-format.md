# Output Formats

Exact output formats produced by `erg-vanity`, derived from source code.

## Match Output (stdout)

<!-- Source: crates/erg-vanity-cli/src/main.rs:297-318 -->

When a matching address is found, the following is printed to stdout:

```
=== Match {match_num} ===
Device:   {device_index}
Address:  {address}
Pattern:  {pattern}
Path:     m/44'/429'/0'/0/{address_index}
Mnemonic: {mnemonic}
Entropy:  {hex_entropy}
```

### Field Descriptions

| Field | Source | Format |
|-------|--------|--------|
| `match_num` | `:311` | Integer, 1-indexed |
| `device_index` | `:312` | Integer, 0-indexed global device index |
| `address` | `:313` | Base58-encoded Ergo P2PK address |
| `pattern` | `:314` | Original pattern from user input |
| `address_index` | `:315` | BIP44 address index (0 to num_indices-1) |
| `mnemonic` | `:316` | 24-word BIP39 mnemonic phrase |
| `hex_entropy` | `:317` | 64-character hex string (32 bytes) |

### Code Reference

```rust
// main.rs:310-317
println!();
println!("=== Match {} ===", match_num);
println!("Device:   {}", device_index);
println!("Address:  {}", result.address);
println!("Pattern:  {}", pattern);
println!("Path:     m/44'/429'/0'/0/{}", result.address_index);
println!("Mnemonic: {}", result.mnemonic);
println!("Entropy:  {}", hex::encode(result.entropy));
```

## Device List Output (stdout)

<!-- Source: crates/erg-vanity-cli/src/main.rs:233-250 -->

When `--list-devices` is used:

```
[{global_idx}] {vendor} - {device_name} (platform: {platform_name})
```

If no devices found:
```
No OpenCL GPU devices found.
```

### Code Reference

```rust
// main.rs:237
println!("No OpenCL GPU devices found.");

// main.rs:241-247
println!(
    "[{}] {} - {} (platform: {})",
    info.global_idx,
    info.vendor.trim(),
    info.device_name.trim(),
    info.platform_name.trim()
);
```

## Progress Output (stderr)

<!-- Source: crates/erg-vanity-cli/src/main.rs:504-514 -->

During search, updates every ~1 second to stderr:

```
Checked: {count} ({rate} addr/s) [{found}/{target}]
```

### Code Reference

```rust
// main.rs:508-510
eprint!(
    "\rChecked: {} ({:.0} addr/s) [{}/{}]   ",
    checked, rate, results_found, self.max_results
);
```

## Search Summary (stderr)

<!-- Source: crates/erg-vanity-cli/src/main.rs:525-537 -->

After search completes:

```
Found {count} match(es) in {duration}s ({total} addresses checked)
```

If hits were dropped due to buffer overflow:

```
Warning: {dropped} hits dropped due to buffer overflow (pattern too short?)
```

### Code Reference

```rust
// main.rs:526-530
eprintln!(
    "Found {} match(es) in {:.1}s ({} addresses checked)",
    results_found,
    start.elapsed().as_secs_f64(),
    total_checked.load(Ordering::Relaxed)
);

// main.rs:533-536
eprintln!(
    "Warning: {} hits dropped due to buffer overflow (pattern too short?)",
    dropped_hits_total
);
```

## Search Initialization (stderr)

<!-- Source: crates/erg-vanity-cli/src/main.rs:626-644 -->

Before search starts:

```
Searching for {count} pattern(s): {patterns:?}
Case-insensitive: {ignore_case}
Indices per seed: {num_indices} (m/44'/429'/0'/0/{0..num_indices-1})
Target matches: {max_results}
Devices: {device_indices:?}
Batch size: {batch_size}
Duration limit: {secs}s
```

### Code Reference

```rust
// main.rs:627-644
eprintln!("Searching for {} pattern(s): {:?}", original_patterns.len(), original_patterns);
eprintln!("Case-insensitive: {}", args.ignore_case);
eprintln!("Indices per seed: {} (m/44'/429'/0'/0/{{0..{}}})", args.num_indices, args.num_indices - 1);
eprintln!("Target matches: {}", args.max_results);
eprintln!("Devices: {:?}", device_indices);
eprintln!("Batch size: {}", cfg.batch_size);
if let Some(secs) = args.duration_secs {
    eprintln!("Duration limit: {}s", secs);
}
```

## Error Messages (stderr)

<!-- Source: crates/erg-vanity-cli/src/main.rs -->

All errors printed via `eprintln!("Error: {}", ...)`:

| Error Type | Example | Source |
|------------|---------|--------|
| Device list error | `Error: {err}` | `:548` |
| Device parse error | `Error: {err}` | `:559` |
| Benchmark error | `Error benchmarking device {}: {}` | `:577` |
| Pattern error | `Error: {e}` | `:591` |
| Index too low | `Error: --index must be at least 1` | `:598` |
| Index too high | `Error: --index {} exceeds maximum of 100` | `:602` |
| Max results error | `Error: -n/--max-results must be at least 1` | `:608` |
| Device parse error | `Error: {err}` | `:615` |
| Search failure | `Search failed: {err}` | `:656` |

## Hit Buffer Structure

<!-- Source: crates/erg-vanity-gpu/src/buffers.rs:20-36 -->

Internal GPU hit record structure (not directly visible to users):

```rust
#[repr(C, align(16))]
pub struct GpuHit {
    pub entropy_words: [u32; 8],  // 32 bytes, little-endian
    pub work_item_id: u32,        // 4 bytes
    pub address_index: u32,       // 4 bytes
    pub pattern_index: u32,       // 4 bytes
    pub _pad: [u32; 5],           // 20 bytes padding
}  // Total: 64 bytes
```

### Field Details

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| `entropy_words` | 0 | 32 bytes | Entropy as 8 little-endian u32 words |
| `work_item_id` | 32 | 4 bytes | GPU work item that found match |
| `address_index` | 36 | 4 bytes | BIP44 index `m/44'/429'/0'/0/{i}` |
| `pattern_index` | 40 | 4 bytes | Index into pattern list |
| `_pad` | 44 | 20 bytes | Padding to 64-byte alignment |

## Benchmark Output

<!-- Source: crates/erg-vanity-gpu/src/bench.rs:337-474 -->

See [Benchmarking](benchmarking.md) for detailed benchmark output format.

## JSON Output

**Not implemented.** No JSON output format exists in the codebase.

---

## Verification Checklist

- [x] Match output: `main.rs:310-317`
- [x] Device list: `main.rs:237`, `main.rs:241-247`
- [x] Progress output: `main.rs:508-510`
- [x] Summary output: `main.rs:526-536`
- [x] Initialization output: `main.rs:627-644`
- [x] Error messages: `eprintln!` calls in `main.rs`
- [x] Hit buffer structure: `buffers.rs:20-36`
- [x] JSON: verified not present
