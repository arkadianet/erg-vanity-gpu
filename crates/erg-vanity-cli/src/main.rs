use clap::Parser;
use erg_vanity_gpu::pipeline::{VanityConfig, VanityPipeline, VanityResult};
use std::io::{self, Write};
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
    /// Pattern(s) to search for (comma-separated, e.g., "9err,9ego")
    #[arg(short = 'p', long = "pattern", value_delimiter = ',')]
    patterns: Vec<String>,

    /// Case-insensitive matching
    #[arg(short = 'i', long = "ignore-case", default_value_t = false)]
    ignore_case: bool,

    /// Number of matches to find before stopping
    #[arg(short = 'n', long = "num", default_value_t = 1)]
    num_matches: usize,

    /// Number of BIP44 address indices to check per seed (m/44'/429'/0'/0/{0..N-1})
    #[arg(long = "index", default_value_t = 1)]
    num_indices: u32,

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

fn print_result(result: &VanityResult, original_patterns: &[String], match_num: usize) {
    let pattern_idx = result.pattern_index as usize;
    let pattern = original_patterns
        .get(pattern_idx)
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");

    println!();
    println!("=== Match {} ===", match_num);
    println!("Address:  {}", result.address);
    println!("Pattern:  {}", pattern);
    println!("Path:     m/44'/429'/0'/0/{}", result.address_index);
    println!("Mnemonic: {}", result.mnemonic);
    println!("Entropy:  {}", hex::encode(result.entropy));
}

fn main() {
    let args = Args::parse();

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

    // Validate num_matches
    if args.num_matches == 0 {
        eprintln!("Error: -n/--num must be at least 1");
        std::process::exit(2);
    }

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
    eprintln!("Target matches: {}", args.num_matches);
    eprintln!("Batch size: {}", cfg.batch_size);

    // Pass normalized patterns to pipeline (lowercased if ignore_case)
    let mut pipe = match VanityPipeline::new(&normalized_patterns, cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("GPU init failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Device: {}", pipe.device_info());
    eprintln!();

    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut results: Vec<VanityResult> = Vec::new();

    loop {
        match pipe.run_batch() {
            Ok(batch_results) => {
                for result in batch_results {
                    print_result(&result, &original_patterns, results.len() + 1);
                    results.push(result);

                    if results.len() >= args.num_matches {
                        break;
                    }
                }

                if results.len() >= args.num_matches {
                    break;
                }

                // Progress report every ~1 second
                if last_report.elapsed().as_secs_f64() >= 1.0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let checked = pipe.addresses_checked();
                    let rate = checked as f64 / elapsed;
                    eprint!(
                        "\rChecked: {} ({:.0} addr/s) [{}/{}]   ",
                        checked,
                        rate,
                        results.len(),
                        args.num_matches
                    );
                    io::stderr().flush().ok();
                    last_report = Instant::now();
                }
            }
            Err(e) => {
                eprintln!("\nSearch failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    eprintln!();
    eprintln!(
        "Found {} match(es) in {:.1}s ({} addresses checked)",
        results.len(),
        start.elapsed().as_secs_f64(),
        pipe.addresses_checked()
    );

    // Warn about dropped hits (short prefix = many matches = buffer overflow)
    let dropped = pipe.hits_dropped_total();
    if dropped > 0 {
        eprintln!(
            "Warning: {} hits dropped due to buffer overflow (pattern too short?)",
            dropped
        );
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
