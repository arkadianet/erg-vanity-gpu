use clap::Parser;
use erg_vanity_cpu::MatchType;
use erg_vanity_engine::{
    estimate_pattern, format_time, list_gpu_devices, run_search, Backend, SearchEvent,
    SearchRequest,
};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "erg-vanity",
    about = "GPU-accelerated Ergo vanity address generator"
)]
struct Args {
    /// List all available OpenCL devices and exit
    #[arg(long = "list-devices", default_value_t = false)]
    list_devices: bool,

    /// Device indices (e.g. 0,1), "all", or "cpu"
    #[arg(long = "devices", default_value = "0")]
    devices: String,

    /// Pattern(s) to search for (comma-separated, e.g. 9err,9ego)
    #[arg(short = 'p', long = "pattern", value_delimiter = ',')]
    patterns: Vec<String>,

    /// Match at the end of the address (CPU)
    #[arg(short = 'e', long = "suffix", default_value_t = false)]
    suffix: bool,

    /// Match anywhere in the address (CPU)
    #[arg(long = "contains", default_value_t = false)]
    contains: bool,

    /// Case-insensitive matching
    #[arg(short = 'i', long = "ignore-case", default_value_t = false)]
    ignore_case: bool,

    /// Maximum number of matches to find before stopping
    #[arg(short = 'n', long = "max-results", alias = "num", default_value_t = 1)]
    max_results: usize,

    /// BIP44 address indices per seed (m/44'/429'/0'/0/{0..N-1})
    #[arg(long = "index", default_value_t = 1)]
    num_indices: u32,

    /// Maximum duration to run before stopping (seconds)
    #[arg(long = "duration-secs")]
    duration_secs: Option<u64>,

    /// Search batch size (GPU default: device recommended; CPU default: 256)
    #[arg(long = "batch-size")]
    batch_size: Option<usize>,

    /// Estimate difficulty and exit
    #[arg(long = "estimate", default_value_t = false)]
    estimate: bool,

    /// Do not open the GUI when no patterns are given
    #[arg(long = "no-gui", default_value_t = false)]
    no_gui: bool,

    /// Run GPU microbenchmark and exit
    #[arg(long = "bench", default_value_t = false)]
    bench: bool,

    /// Number of benchmark iterations
    #[arg(long = "bench-iters", default_value_t = 100)]
    bench_iters: u32,

    /// Warmup iterations before timing
    #[arg(long = "bench-warmup", default_value_t = 5)]
    bench_warmup: u32,

    /// Batch size for benchmark
    #[arg(long = "bench-batch-size")]
    bench_batch_size: Option<usize>,

    /// Address indices for benchmark
    #[arg(long = "bench-num-indices")]
    bench_num_indices: Option<u32>,

    /// Validate benchmark kernels
    #[arg(long = "bench-validate", default_value_t = false)]
    bench_validate: bool,

    /// Legacy: single pattern as positional argument
    #[arg()]
    pattern: Option<String>,
}

fn match_type(args: &Args) -> Result<MatchType, String> {
    match (args.suffix, args.contains) {
        (true, true) => Err("use only one of --suffix or --contains".into()),
        (true, false) => Ok(MatchType::Suffix),
        (false, true) => Ok(MatchType::Contains),
        (false, false) => Ok(MatchType::Prefix),
    }
}

fn collect_patterns(args: &Args) -> Vec<String> {
    let mut out = Vec::new();
    for p in &args.patterns {
        let t = p.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    if let Some(ref p) = args.pattern {
        let t = p.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    out
}

fn parse_backend(devices_arg: &str) -> Result<Backend, String> {
    let normalized = devices_arg.trim().to_ascii_lowercase();
    if normalized == "cpu" {
        return Ok(Backend::Cpu);
    }
    if normalized == "all" {
        return Ok(Backend::Gpu {
            devices: Vec::new(),
        });
    }
    let mut parsed = Vec::new();
    for part in devices_arg.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let idx: usize = trimmed.parse().map_err(|_| {
            format!("invalid device index '{trimmed}': expected integer, 'all', or 'cpu'")
        })?;
        parsed.push(idx);
    }
    if parsed.is_empty() {
        return Err("no device indices provided".into());
    }
    parsed.sort_unstable();
    parsed.dedup();
    Ok(Backend::Gpu { devices: parsed })
}

fn print_hit(hit: &erg_vanity_engine::Hit, originals: &[String], match_num: usize) {
    let pattern = originals
        .get(hit.pattern_index as usize)
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");
    println!();
    println!("=== Match {match_num} ===");
    println!("Device:   {}", hit.device_label);
    println!("Address:  {}", hit.address);
    println!("Pattern:  {pattern}");
    println!("Path:     m/44'/429'/0'/0/{}", hit.address_index);
    println!("Mnemonic: {}", hit.mnemonic);
    println!("Entropy:  {}", hex::encode(hit.entropy));
}

fn run_estimate(patterns: &[String], match_type: MatchType) {
    println!("Difficulty Estimation");
    println!("====================");
    for p in patterns {
        let est = estimate_pattern(p, match_type);
        println!("\nPattern: \"{p}\"");
        if est.has_invalid_chars {
            println!(
                "Impossible: invalid Base58 characters: {}",
                est.invalid_chars.iter().collect::<String>()
            );
        } else {
            println!("Estimated attempts: {:.0}", est.attempts_needed);
            println!(
                "  At 10,000 addr/s: {}",
                format_time(est.attempts_needed / 10_000.0)
            );
            println!(
                "  At 330,000 addr/s: {}",
                format_time(est.attempts_needed / 330_000.0)
            );
        }
    }
}

fn main() {
    let args = Args::parse();

    if args.list_devices {
        match list_gpu_devices() {
            Ok(list) if list.is_empty() => println!("No OpenCL GPU devices found."),
            Ok(list) => {
                for line in list {
                    println!("{line}");
                }
            }
            Err(err) => {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.bench {
        let backend = match parse_backend(&args.devices) {
            Ok(Backend::Gpu { devices }) => devices,
            Ok(Backend::Cpu) | Ok(Backend::Auto) => {
                eprintln!("Error: --bench requires GPU devices");
                std::process::exit(2);
            }
            Err(err) => {
                eprintln!("Error: {err}");
                std::process::exit(2);
            }
        };
        let device_indices = if backend.is_empty() {
            match erg_vanity_gpu::context::GpuContext::enumerate_devices() {
                Ok(d) => d.iter().map(|i| i.global_idx).collect(),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(2);
                }
            }
        } else {
            backend
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
                    eprintln!("Error benchmarking device {device_index}: {e}");
                    std::process::exit(1);
                }
            }
        }
        erg_vanity_gpu::bench::print_bench_results(&results, &cfg);
        return;
    }

    let match_type = match match_type(&args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(2);
        }
    };

    let patterns = collect_patterns(&args);

    if args.estimate {
        if patterns.is_empty() {
            eprintln!("Error: --estimate requires -p");
            std::process::exit(2);
        }
        run_estimate(&patterns, match_type);
        return;
    }

    if patterns.is_empty() && !args.no_gui {
        if let Err(e) = erg_vanity_gui::run() {
            eprintln!("Error running GUI: {e}");
            std::process::exit(1);
        }
        return;
    }

    let backend = match parse_backend(&args.devices) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(2);
        }
    };

    let req = SearchRequest {
        patterns: patterns.clone(),
        match_type,
        ignore_case: args.ignore_case,
        max_results: args.max_results,
        num_indices: args.num_indices,
        duration: args.duration_secs.map(Duration::from_secs),
        backend,
        batch_size: args.batch_size,
    };

    if let Err(e) = req.validate() {
        eprintln!("Error: {e}");
        std::process::exit(2);
    }

    eprintln!(
        "Searching for {} pattern(s): {:?}",
        patterns.len(),
        patterns
    );
    eprintln!("Match type: {:?}", match_type);
    eprintln!("Case-insensitive: {}", args.ignore_case);
    eprintln!(
        "Indices per seed: {} (m/44'/429'/0'/0/{{0..{}}})",
        args.num_indices,
        args.num_indices - 1
    );
    eprintln!("Target matches: {}", args.max_results);
    if let Some(secs) = args.duration_secs {
        eprintln!("Duration limit: {secs}s");
    }
    eprintln!();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        if stop_c.swap(true, Ordering::Relaxed) {
            std::process::exit(1);
        }
        eprintln!("\nCtrl+C received, stopping…");
    });

    let (tx, rx) = mpsc::channel();
    let stop_t = Arc::clone(&stop);
    let handle = std::thread::spawn(move || run_search(req, tx, stop_t));

    let mut found = 0usize;
    let mut exit_err: Option<String> = None;
    while let Ok(ev) = rx.recv() {
        match ev {
            SearchEvent::Hit(hit) => {
                found += 1;
                print_hit(&hit, &patterns, found);
            }
            SearchEvent::Progress {
                checked,
                rate,
                found,
            } => {
                eprint!(
                    "\rChecked: {checked} ({rate:.0} addr/s) [{found}/{}]   ",
                    args.max_results
                );
                let _ = io::stderr().flush();
            }
            SearchEvent::Dropped { count } => {
                eprintln!();
                eprintln!(
                    "Warning: {count} hits dropped due to buffer overflow (pattern too short?)"
                );
            }
            SearchEvent::Error { message } => {
                exit_err = Some(message);
            }
            SearchEvent::Done {
                checked,
                found,
                elapsed,
            } => {
                eprintln!();
                eprintln!(
                    "Found {found} match(es) in {:.1}s ({checked} addresses checked)",
                    elapsed.as_secs_f64()
                );
            }
        }
    }
    let _ = handle.join();
    if let Some(err) = exit_err {
        eprintln!("Search failed: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_cpu() {
        assert!(matches!(parse_backend("cpu").unwrap(), Backend::Cpu));
    }

    #[test]
    fn backend_devices() {
        let Backend::Gpu { devices } = parse_backend("0,2,2").unwrap() else {
            panic!("expected gpu");
        };
        assert_eq!(devices, vec![0, 2]);
    }
}
