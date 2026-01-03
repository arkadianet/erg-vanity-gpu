use clap::Parser;
use erg_vanity_gpu::context::GpuContext;
use erg_vanity_gpu::pipeline::{VanityConfig, VanityPipeline, VanityResult};
use rand::RngCore;
use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// Base58 alphabet (excluding 0, O, I, l)
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Valid second characters for Ergo mainnet P2PK addresses
const VALID_SECOND_CHARS: &[char] = &['e', 'f', 'g', 'h', 'i'];

/// Maximum pattern length
const MAX_PATTERN_LEN: usize = 32;

/// Maximum number of patterns
const MAX_PATTERNS: usize = 64;

/// Maximum total pattern data size
const MAX_PATTERN_DATA: usize = 1024;

#[derive(Parser, Debug)]
#[command(
    name = "erg-vanity",
    about = "GPU-accelerated Ergo vanity address generator"
)]
struct Args {
    /// List all available OpenCL devices and exit
    #[arg(long = "list-devices", default_value_t = false)]
    list_devices: bool,

    /// Comma-separated device indices to use, or "all"
    #[arg(long = "devices", default_value = "0")]
    devices: String,

    /// Pattern(s) to search for (comma-separated, e.g., "9err,9ego")
    #[arg(short = 'p', long = "pattern", value_delimiter = ',')]
    patterns: Vec<String>,

    /// Case-insensitive matching
    #[arg(short = 'i', long = "ignore-case", default_value_t = false)]
    ignore_case: bool,

    /// Maximum number of matches to find before stopping
    #[arg(short = 'n', long = "max-results", alias = "num", default_value_t = 1)]
    max_results: usize,

    /// Number of BIP44 address indices to check per seed (m/44'/429'/0'/0/{0..N-1})
    #[arg(long = "index", default_value_t = 1)]
    num_indices: u32,

    /// Maximum duration to run before stopping (seconds)
    #[arg(long = "duration-secs")]
    duration_secs: Option<u64>,

    /// Run GPU microbenchmark and exit
    #[arg(long = "bench", default_value_t = false)]
    bench: bool,

    /// Number of benchmark iterations
    #[arg(long = "bench-iters", default_value_t = 100)]
    bench_iters: u32,

    /// Warmup iterations before timing
    #[arg(long = "bench-warmup", default_value_t = 5)]
    bench_warmup: u32,

    /// Batch size for benchmark (default: 262144)
    #[arg(long = "bench-batch-size")]
    bench_batch_size: Option<usize>,

    /// Number of address indices for benchmark (default: from --index)
    #[arg(long = "bench-num-indices")]
    bench_num_indices: Option<u32>,

    /// Validate benchmark kernels by reading back checksums (sanity check)
    #[arg(long = "bench-validate", default_value_t = false)]
    bench_validate: bool,

    /// Legacy: single pattern as positional argument
    #[arg()]
    pattern: Option<String>,
}

/// Validate a single pattern for Ergo mainnet P2PK addresses.
/// Returns the normalized pattern (lowercased if ignore_case).
fn validate_pattern(pattern: &str, ignore_case: bool) -> Result<String, String> {
    // Check length
    if pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!(
            "pattern '{}' too long: {} chars exceeds {} limit",
            pattern,
            pattern.len(),
            MAX_PATTERN_LEN
        ));
    }

    // Check ASCII only
    if !pattern.is_ascii() {
        return Err(format!(
            "pattern '{}' contains non-ASCII characters",
            pattern
        ));
    }

    // Check all chars are valid Base58
    for c in pattern.chars() {
        if !BASE58_ALPHABET.contains(c) {
            return Err(format!(
                "pattern '{}' contains invalid Base58 character '{}' \
                 (valid: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)",
                pattern, c
            ));
        }
    }

    // Ergo mainnet P2PK gating
    let chars: Vec<char> = pattern.chars().collect();

    // First char must be '9'
    if chars[0] != '9' {
        return Err(format!(
            "invalid pattern '{}': mainnet P2PK addresses start with 9e/9f/9g/9h/9i (or just '9')",
            pattern
        ));
    }

    // If len >= 2, second char must be e/f/g/h/i
    if chars.len() >= 2 {
        let second = if ignore_case {
            chars[1].to_ascii_lowercase()
        } else {
            chars[1]
        };

        if !VALID_SECOND_CHARS.contains(&second) {
            if ignore_case {
                return Err(format!(
                    "invalid pattern '{}': mainnet P2PK addresses start with 9e/9f/9g/9h/9i (or just '9')",
                    pattern
                ));
            } else {
                // Check if it's an uppercase version of valid chars
                let upper_valid: Vec<char> = VALID_SECOND_CHARS
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                if upper_valid.contains(&chars[1]) {
                    return Err(format!(
                        "invalid pattern '{}': second char '{}' is uppercase but --ignore-case not set \
                         (use -i or lowercase to 9{}...)",
                        pattern, chars[1], chars[1].to_ascii_lowercase()
                    ));
                } else {
                    return Err(format!(
                        "invalid pattern '{}': mainnet P2PK addresses start with 9e/9f/9g/9h/9i (or just '9')",
                        pattern
                    ));
                }
            }
        }
    }

    // Normalize pattern if ignore_case
    if ignore_case {
        Ok(pattern.to_lowercase())
    } else {
        Ok(pattern.to_string())
    }
}

/// Parse and validate all patterns from CLI args.
/// Returns (original_patterns, normalized_patterns).
fn parse_patterns(args: &Args) -> Result<(Vec<String>, Vec<String>), String> {
    let mut originals: Vec<String> = Vec::new();

    // Add patterns from -p flag (trim whitespace, ignore empty)
    for p in &args.patterns {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            originals.push(trimmed.to_string());
        }
    }

    // Append positional pattern if provided
    if let Some(ref p) = args.pattern {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            originals.push(trimmed.to_string());
        }
    }

    if originals.is_empty() {
        return Err("at least one pattern is required (-p or positional)".to_string());
    }

    // Check number of patterns
    if originals.len() > MAX_PATTERNS {
        return Err(format!(
            "too many patterns: {} exceeds {} limit",
            originals.len(),
            MAX_PATTERNS
        ));
    }

    // Check total pattern data size
    let total_len: usize = originals.iter().map(|p| p.len()).sum();
    if total_len > MAX_PATTERN_DATA {
        return Err(format!(
            "pattern data too large: {} bytes exceeds {} limit",
            total_len, MAX_PATTERN_DATA
        ));
    }

    // Validate each pattern and build normalized list
    let mut normalized = Vec::with_capacity(originals.len());
    for pattern in &originals {
        normalized.push(validate_pattern(pattern, args.ignore_case)?);
    }

    Ok((originals, normalized))
}

/// Enumerate GPUs and print a user-friendly list for `--list-devices`.
fn list_devices() -> Result<(), String> {
    let devices = GpuContext::enumerate_devices().map_err(|e| e.to_string())?;
    if devices.is_empty() {
        println!("No OpenCL GPU devices found.");
        return Ok(());
    }
    for info in devices {
        println!(
            "[{}] {} - {} (platform: {})",
            info.global_idx,
            info.vendor.trim(),
            info.device_name.trim(),
            info.platform_name.trim()
        );
    }
    Ok(())
}

/// Parse the `--devices` argument into a sorted, deduplicated list of indices.
fn parse_device_list(devices_arg: &str) -> Result<Vec<usize>, String> {
    let devices = GpuContext::enumerate_devices().map_err(|e| e.to_string())?;
    if devices.is_empty() {
        return Err("no OpenCL GPU devices found".to_string());
    }
    let mut available_indices: Vec<usize> = devices.iter().map(|info| info.global_idx).collect();
    available_indices.sort_unstable();
    let available_set: HashSet<usize> = available_indices.iter().copied().collect();

    let normalized = devices_arg.trim().to_ascii_lowercase();
    let mut indices = if normalized == "all" {
        available_indices.clone()
    } else {
        let mut parsed = Vec::new();
        for part in devices_arg.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let idx: usize = trimmed.parse().map_err(|_| {
                format!(
                    "invalid device index '{}': expected integer or 'all'",
                    trimmed
                )
            })?;
            if !available_set.contains(&idx) {
                return Err(format!(
                    "device index {} not found (available: {:?})",
                    idx, available_indices
                ));
            }
            parsed.push(idx);
        }
        if parsed.is_empty() {
            return Err("no device indices provided".to_string());
        }
        parsed
    };

    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// Print a vanity match result in a consistent, user-facing format.
fn print_result(
    result: &VanityResult,
    original_patterns: &[String],
    match_num: usize,
    device_index: usize,
) {
    let pattern_idx = result.pattern_index as usize;
    let pattern = original_patterns
        .get(pattern_idx)
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");

    println!();
    println!("=== Match {} ===", match_num);
    println!("Device:   {}", device_index);
    println!("Address:  {}", result.address);
    println!("Pattern:  {}", pattern);
    println!("Path:     m/44'/429'/0'/0/{}", result.address_index);
    println!("Mnemonic: {}", result.mnemonic);
    println!("Entropy:  {}", hex::encode(result.entropy));
}

enum WorkerMessage {
    /// A device produced a verified match.
    Hit {
        device_index: usize,
        result: VanityResult,
    },
    /// A device encountered a fatal error and should halt the search.
    Error {
        device_index: usize,
        message: String,
    },
    /// Final stats for a device when its worker exits.
    Stats {
        device_index: usize,
        hits_dropped_total: u64,
    },
}

/// Coordinates vanity search workers across multiple GPU devices.
struct MultiGpuRunner {
    /// Runtime configuration applied to every GPU pipeline.
    cfg: VanityConfig,
    /// Global device indices selected via `--devices`.
    device_indices: Vec<usize>,
    /// Normalized patterns for GPU matching.
    normalized_patterns: Arc<Vec<String>>,
    /// Original user-provided patterns for display.
    original_patterns: Vec<String>,
    /// Maximum number of matches to find before stopping.
    max_results: usize,
    /// Optional time limit for the run.
    duration: Option<Duration>,
}

impl MultiGpuRunner {
    /// Run the vanity search across all configured GPU devices.
    fn run(self) -> Result<(), String> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let counter = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let total_checked = Arc::new(AtomicU64::new(0));

        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        let mut handles = Vec::new();

        for device_index in &self.device_indices {
            let device_index = *device_index;
            let patterns = Arc::clone(&self.normalized_patterns);
            let cfg = self.cfg.clone();
            let tx = tx.clone();
            let counter = Arc::clone(&counter);
            let stop = Arc::clone(&stop);
            let total_checked = Arc::clone(&total_checked);
            let salt = salt;

            let handle = thread::spawn(move || {
                let mut pipeline = match VanityPipeline::new_with_device_and_salt(
                    &patterns,
                    cfg.clone(),
                    device_index,
                    salt,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Error {
                            device_index,
                            message: e.to_string(),
                        });
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                };

                while !stop.load(Ordering::Relaxed) {
                    let counter_start = counter.fetch_add(cfg.batch_size as u64, Ordering::Relaxed);
                    let batch_results = match pipeline.run_batch_with_counter(counter_start) {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = tx.send(WorkerMessage::Error {
                                device_index,
                                message: e.to_string(),
                            });
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    };

                    total_checked.fetch_add(
                        (cfg.batch_size as u64) * (cfg.num_indices as u64),
                        Ordering::Relaxed,
                    );

                    for result in batch_results {
                        if tx
                            .send(WorkerMessage::Hit {
                                device_index,
                                result,
                            })
                            .is_err()
                        {
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                let _ = tx.send(WorkerMessage::Stats {
                    device_index,
                    hits_dropped_total: pipeline.hits_dropped_total(),
                });
            });

            handles.push(handle);
        }

        drop(tx);

        if let Some(duration) = self.duration {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                thread::sleep(duration);
                stop.store(true, Ordering::Relaxed);
            });
        }

        let start = Instant::now();
        let mut last_report = Instant::now();
        let mut results_found = 0usize;
        let mut dropped_hits_total = 0u64;
        let mut first_error: Option<String> = None;

        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(message) => match message {
                    WorkerMessage::Hit {
                        device_index,
                        result,
                    } => {
                        if results_found >= self.max_results {
                            stop.store(true, Ordering::Relaxed);
                            continue;
                        }
                        results_found += 1;
                        print_result(
                            &result,
                            &self.original_patterns,
                            results_found,
                            device_index,
                        );
                        if results_found >= self.max_results {
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                    WorkerMessage::Error {
                        device_index,
                        message,
                    } => {
                        if first_error.is_none() {
                            first_error =
                                Some(format!("Device {} error: {}", device_index, message));
                        }
                        eprintln!("Device {} error: {}", device_index, message);
                        stop.store(true, Ordering::Relaxed);
                    }
                    WorkerMessage::Stats {
                        device_index,
                        hits_dropped_total,
                    } => {
                        if hits_dropped_total > 0 {
                            eprintln!();
                            eprintln!(
                                "Device {} dropped {} hits due to buffer overflow",
                                device_index, hits_dropped_total
                            );
                        }
                        dropped_hits_total = dropped_hits_total.saturating_add(hits_dropped_total);
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            if last_report.elapsed().as_secs_f64() >= 1.0 {
                let elapsed = start.elapsed().as_secs_f64();
                let checked = total_checked.load(Ordering::Relaxed);
                let rate = checked as f64 / elapsed.max(0.001);
                eprint!(
                    "\rChecked: {} ({:.0} addr/s) [{}/{}]   ",
                    checked, rate, results_found, self.max_results
                );
                io::stderr().flush().ok();
                last_report = Instant::now();
            }
        }

        for handle in handles {
            let _ = handle.join();
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        eprintln!();
        eprintln!(
            "Found {} match(es) in {:.1}s ({} addresses checked)",
            results_found,
            start.elapsed().as_secs_f64(),
            total_checked.load(Ordering::Relaxed)
        );
        if dropped_hits_total > 0 {
            eprintln!(
                "Warning: {} hits dropped due to buffer overflow (pattern too short?)",
                dropped_hits_total
            );
        }

        Ok(())
    }
}

fn main() {
    let args = Args::parse();

    if args.list_devices {
        if let Err(err) = list_devices() {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
        return;
    }

    // Benchmark mode - runs before pattern validation
    if args.bench {
        let device_indices = match parse_device_list(&args.devices) {
            Ok(list) => list,
            Err(err) => {
                eprintln!("Error: {}", err);
                std::process::exit(2);
            }
        };

        let cfg = erg_vanity_gpu::bench::BenchConfig {
            batch_size: args.bench_batch_size.unwrap_or(1 << 18),
            num_indices: args.bench_num_indices.unwrap_or(args.num_indices),
            iters: args.bench_iters,
            warmup: args.bench_warmup,
            validate: args.bench_validate,
        };

        let mut results = Vec::new();
        for device_index in &device_indices {
            match erg_vanity_gpu::bench::run_bench_on_device(*device_index, &cfg) {
                Ok(stats) => results.push(stats),
                Err(e) => {
                    eprintln!("Error benchmarking device {}: {}", device_index, e);
                    std::process::exit(1);
                }
            }
        }

        erg_vanity_gpu::bench::print_bench_results(&results, &cfg);
        return;
    }

    // Parse and validate patterns
    let (original_patterns, normalized_patterns) = match parse_patterns(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    };

    // Validate num_indices
    if args.num_indices == 0 {
        eprintln!("Error: --index must be at least 1");
        std::process::exit(2);
    }
    if args.num_indices > 100 {
        eprintln!("Error: --index {} exceeds maximum of 100", args.num_indices);
        std::process::exit(2);
    }

    // Validate max_results
    if args.max_results == 0 {
        eprintln!("Error: -n/--max-results must be at least 1");
        std::process::exit(2);
    }

    let device_indices = match parse_device_list(&args.devices) {
        Ok(list) => list,
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(2);
        }
    };

    let cfg = VanityConfig {
        batch_size: 1 << 18, // 262,144
        ignore_case: args.ignore_case,
        num_indices: args.num_indices,
    };

    // Print search summary (show original patterns as user typed them)
    eprintln!(
        "Searching for {} pattern(s): {:?}",
        original_patterns.len(),
        original_patterns
    );
    eprintln!("Case-insensitive: {}", args.ignore_case);
    eprintln!(
        "Indices per seed: {} (m/44'/429'/0'/0/{{0..{}}})",
        args.num_indices,
        args.num_indices - 1
    );
    eprintln!("Target matches: {}", args.max_results);
    eprintln!("Devices: {:?}", device_indices);
    eprintln!("Batch size: {}", cfg.batch_size);
    if let Some(secs) = args.duration_secs {
        eprintln!("Duration limit: {}s", secs);
    }
    eprintln!();

    let runner = MultiGpuRunner {
        cfg,
        device_indices,
        normalized_patterns: Arc::new(normalized_patterns),
        original_patterns,
        max_results: args.max_results,
        duration: args.duration_secs.map(Duration::from_secs),
    };

    if let Err(err) = runner.run() {
        eprintln!("Search failed: {}", err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_validator_accepts_valid() {
        // Should accept valid patterns
        assert!(validate_pattern("9", false).is_ok());
        assert!(validate_pattern("9f", false).is_ok());
        assert!(validate_pattern("9err", false).is_ok());
        assert!(validate_pattern("9ego", false).is_ok());
        // Note: Base58 excludes 'l' (lowercase L), so use uppercase L or digit 1
        assert!(validate_pattern("9heLLoWor1d", false).is_ok());
    }

    #[test]
    fn test_pattern_validator_rejects_invalid_second_char() {
        // 9a, 9b, 9c, 9d are invalid (second char must be e-i)
        assert!(validate_pattern("9a", false).is_err());
        assert!(validate_pattern("9b", false).is_err());
        assert!(validate_pattern("9A", false).is_err());
    }

    #[test]
    fn test_pattern_validator_rejects_invalid_base58() {
        // 0, O, I, l are not in Base58 alphabet
        assert!(validate_pattern("90", false).is_err());
        assert!(validate_pattern("9fO", false).is_err());
        assert!(validate_pattern("9fI", false).is_err());
        assert!(validate_pattern("9fl", false).is_err()); // lowercase l
    }

    #[test]
    fn test_pattern_validator_rejects_non_ascii() {
        assert!(validate_pattern("9f\u{00e9}", false).is_err()); // é
    }

    #[test]
    fn test_ignore_case_normalization() {
        // With ignore_case, 9F should be accepted and normalized to 9f
        let result = validate_pattern("9F", true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "9f");

        let result = validate_pattern("9Err", true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "9err");

        // Without ignore_case, 9F should be rejected with helpful error
        let result = validate_pattern("9F", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase"));
    }
}
