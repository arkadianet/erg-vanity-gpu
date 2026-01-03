//! GPU microbenchmark runner.
//!
//! Measures per-component GPU kernel time for PBKDF2, BIP32, secp256k1, and Base58
//! stages using OpenCL event profiling timestamps.

use crate::context::{DeviceInfo, GpuContext, GpuError};
use crate::kernel::GpuProgram;
use crate::wordlist::WordlistBuffers;
use ocl::enums::ProfilingInfo;
use ocl::{Buffer, Event, Kernel, MemFlags};

/// Benchmark configuration.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Number of work items per batch.
    pub batch_size: usize,
    /// Number of BIP44 address indices to check per seed.
    pub num_indices: u32,
    /// Number of timed iterations per component.
    pub iters: u32,
    /// Number of warmup iterations before timing.
    pub warmup: u32,
    /// If true, read back checksums to validate kernels aren't optimized away.
    pub validate: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            batch_size: 1 << 18, // 262,144
            num_indices: 1,
            iters: 100,
            warmup: 5,
            validate: false,
        }
    }
}

/// Per-component timing stats.
#[derive(Debug, Clone, Default)]
pub struct ComponentStats {
    /// Total time in nanoseconds across all iterations.
    pub total_ns: u64,
    /// Number of iterations.
    pub count: u32,
}

/// Results from benchmarking a single device.
#[derive(Debug, Clone)]
pub struct DeviceBenchStats {
    /// Device information.
    pub device_info: DeviceInfo,
    /// PBKDF2 (BIP39 seed derivation) stats.
    pub pbkdf2: ComponentStats,
    /// BIP32 key derivation stats.
    pub bip32: ComponentStats,
    /// secp256k1 pubkey derivation stats.
    pub secp256k1: ComponentStats,
    /// Base58 encoding stats.
    pub base58: ComponentStats,
}

impl DeviceBenchStats {
    /// Total time across all components in nanoseconds.
    pub fn total_ns(&self) -> u64 {
        self.pbkdf2.total_ns + self.bip32.total_ns + self.secp256k1.total_ns + self.base58.total_ns
    }
}

/// Run benchmark on a specific device.
pub fn run_bench_on_device(
    device_index: usize,
    cfg: &BenchConfig,
) -> Result<DeviceBenchStats, GpuError> {
    // Create context with profiling enabled
    let ctx = GpuContext::with_device_profiling(device_index)?;
    let queue = ctx.queue();
    let device_info = ctx.info().clone();

    // Compile benchmark program
    let program = GpuProgram::bench(&ctx)?;

    // Allocate buffers ONCE - reused across all kernels and iterations
    let salt_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_only())
        .len(32)
        .build()?;

    // Checksum buffer - write_only unless validating (then we read back)
    let checksum_flags = if cfg.validate {
        MemFlags::new().read_write()
    } else {
        MemFlags::new().write_only()
    };
    let checksum_buf = Buffer::<u32>::builder()
        .queue(queue.clone())
        .flags(checksum_flags)
        .len(cfg.batch_size)
        .build()?;

    // Upload BIP39 wordlist (required for PBKDF2 kernel, passed to others for uniform signature)
    let wordlist = WordlistBuffers::upload(queue)?;

    // Upload dummy salt once
    let salt = [0x42u8; 32];
    salt_buf.write(&salt[..]).enq()?;
    queue.finish()?; // Wait for upload before benchmarking

    // Build all kernels ONCE upfront
    // global_work_size = cfg.batch_size (same as production)
    // local_work_size left unspecified (let driver choose, same as production)
    // All kernels have uniform signature: (salt, counter, words8, word_lens, num_indices, checksums)
    let kernel_pbkdf2 = Kernel::builder()
        .program(program.program())
        .name("bench_pbkdf2")
        .queue(queue.clone())
        .global_work_size(cfg.batch_size)
        .arg(&salt_buf)
        .arg(0u64) // counter_start - will be updated each iteration
        .arg(&wordlist.words8)
        .arg(&wordlist.lens)
        .arg(cfg.num_indices)
        .arg(&checksum_buf)
        .build()?;

    let kernel_bip32 = Kernel::builder()
        .program(program.program())
        .name("bench_bip32")
        .queue(queue.clone())
        .global_work_size(cfg.batch_size)
        .arg(&salt_buf)
        .arg(0u64)
        .arg(&wordlist.words8)
        .arg(&wordlist.lens)
        .arg(cfg.num_indices)
        .arg(&checksum_buf)
        .build()?;

    let kernel_secp256k1 = Kernel::builder()
        .program(program.program())
        .name("bench_secp256k1")
        .queue(queue.clone())
        .global_work_size(cfg.batch_size)
        .arg(&salt_buf)
        .arg(0u64)
        .arg(&wordlist.words8)
        .arg(&wordlist.lens)
        .arg(cfg.num_indices)
        .arg(&checksum_buf)
        .build()?;

    let kernel_base58 = Kernel::builder()
        .program(program.program())
        .name("bench_base58")
        .queue(queue.clone())
        .global_work_size(cfg.batch_size)
        .arg(&salt_buf)
        .arg(0u64)
        .arg(&wordlist.words8)
        .arg(&wordlist.lens)
        .arg(cfg.num_indices)
        .arg(&checksum_buf)
        .build()?;

    // Optional validation: run each kernel once and verify checksums aren't degenerate
    if cfg.validate {
        println!("\nValidating kernel outputs (checking for optimization artifacts)...\n");

        // Run each kernel once with unique counter offset
        for (kernel, label, offset) in [
            (&kernel_pbkdf2, "PBKDF2", 0u64),
            (&kernel_bip32, "BIP32", 1_000_000_000u64),
            (&kernel_secp256k1, "secp256k1", 2_000_000_000u64),
            (&kernel_base58, "Base58", 3_000_000_000u64),
        ] {
            kernel.set_arg(1, offset)?;
            let mut event = Event::empty();
            unsafe {
                kernel.cmd().enew(&mut event).enq()?;
            }
            event.wait_for().map_err(ocl::Error::from)?;
            validate_checksums(&checksum_buf, queue, label, cfg.batch_size)?;
        }

        println!("\nValidation passed. All kernels producing varied, non-zero output.\n");
    }

    // Run each kernel: warmup then timed iterations
    // Each component gets a different counter offset to avoid any cross-component caching
    let pbkdf2 = run_kernel_bench(&kernel_pbkdf2, cfg, 0)?;
    let bip32 = run_kernel_bench(&kernel_bip32, cfg, 1_000_000_000)?;
    let secp256k1 = run_kernel_bench(&kernel_secp256k1, cfg, 2_000_000_000)?;
    let base58 = run_kernel_bench(&kernel_base58, cfg, 3_000_000_000)?;

    Ok(DeviceBenchStats {
        device_info,
        pbkdf2,
        bip32,
        secp256k1,
        base58,
    })
}

/// Validate checksums by reading back first 16 values and checking for degenerate cases.
fn validate_checksums(
    checksum_buf: &Buffer<u32>,
    queue: &ocl::Queue,
    label: &str,
    batch_size: usize,
) -> Result<(), GpuError> {
    const MAX_N: usize = 16;

    // Use known batch_size rather than trusting buffer API
    let n = std::cmp::min(MAX_N, batch_size);
    if n == 0 {
        return Err(GpuError::Other(format!(
            "{label}: batch_size is 0, cannot validate"
        )));
    }

    // Ensure kernel has finished before reading
    queue.finish()?;

    // Read first n checksums
    let mut checksums = vec![0u32; n];
    checksum_buf.read(&mut checksums).len(n).enq()?;
    queue.finish()?;

    // Compute stats
    let all_zero = checksums.iter().all(|&x| x == 0);
    let all_identical = checksums.iter().all(|&x| x == checksums[0]);
    let unique_count = {
        let mut sorted = checksums.clone();
        sorted.sort();
        sorted.dedup();
        sorted.len()
    };
    let xor_fold = checksums.iter().fold(0u32, |acc, &x| acc ^ x);

    // Print results
    println!("  {}: first {} checksums:", label, n);
    print!("    ");
    for (i, cs) in checksums.iter().enumerate() {
        print!("{:08x}", cs);
        if i < n - 1 {
            print!(" ");
        }
    }
    println!();
    println!(
        "    unique={}, xor_fold={:08x}, all_zero={}, all_identical={}",
        unique_count, xor_fold, all_zero, all_identical
    );

    // Fail on degenerate cases
    if all_zero {
        return Err(GpuError::Other(format!(
            "{label}: all checksums are zero - kernel may be optimized away"
        )));
    }
    // Only meaningful when we read >1 value
    if n > 1 && all_identical {
        return Err(GpuError::Other(format!(
            "{label}: all checksums identical ({:08x}) - kernel may not be varying input",
            checksums[0]
        )));
    }

    Ok(())
}

/// Extract nanosecond timestamp from OpenCL profiling info.
fn extract_profiling_ns(event: &Event, info: ProfilingInfo) -> Result<u64, GpuError> {
    use ocl::enums::ProfilingInfoResult;
    match event.profiling_info(info)? {
        ProfilingInfoResult::Queued(ns)
        | ProfilingInfoResult::Submit(ns)
        | ProfilingInfoResult::Start(ns)
        | ProfilingInfoResult::End(ns) => Ok(ns),
    }
}

/// Run warmup + timed iterations for a single kernel.
/// counter_offset is added to the base counter to ensure different components use different data.
fn run_kernel_bench(
    kernel: &Kernel,
    cfg: &BenchConfig,
    counter_offset: u64,
) -> Result<ComponentStats, GpuError> {
    // Warmup: enqueue with varying counter to avoid caching effects
    for iter in 0..cfg.warmup {
        let counter_start = counter_offset + (iter as u64) * (cfg.batch_size as u64);
        kernel.set_arg(1, counter_start)?;

        let mut event = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut event).enq()?;
        }
        event.wait_for().map_err(ocl::Error::from)?;
    }

    // Timed iterations using OpenCL event profiling
    // Use different counter_start each iteration to avoid caching/constant folding
    let mut total_ns = 0u64;
    for iter in 0..cfg.iters {
        let counter_start =
            counter_offset + ((cfg.warmup as u64) + (iter as u64)) * (cfg.batch_size as u64);
        kernel.set_arg(1, counter_start)?;

        let mut event = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut event).enq()?;
        }
        event.wait_for().map_err(ocl::Error::from)?;

        // Read profiling timestamps (nanoseconds)
        let start = extract_profiling_ns(&event, ProfilingInfo::Start)?;
        let end = extract_profiling_ns(&event, ProfilingInfo::End)?;

        // Validate profiling timestamps
        if start == 0 || end == 0 || end <= start {
            return Err(GpuError::Other(
                "profiling timestamps invalid; is CL_QUEUE_PROFILING_ENABLE set?".into(),
            ));
        }

        total_ns += end - start;
    }

    Ok(ComponentStats {
        total_ns,
        count: cfg.iters,
    })
}

/// Print benchmark results for multiple devices.
pub fn print_bench_results(results: &[DeviceBenchStats], cfg: &BenchConfig) {
    println!(
        "\nGPU microbench (event timestamps), batch={}, iters={}, num_indices={}\n",
        cfg.batch_size, cfg.iters, cfg.num_indices
    );

    for stats in results {
        print_device_table(stats, cfg);
        println!();
    }

    if results.len() > 1 {
        print_combined_table(results, cfg);
    }
}

fn print_device_table(stats: &DeviceBenchStats, cfg: &BenchConfig) {
    println!(
        "Device {}: {} - {}",
        stats.device_info.global_idx,
        stats.device_info.vendor.trim(),
        stats.device_info.device_name.trim()
    );

    let total = stats.total_ns() as f64;
    let seeds_per_component = (cfg.iters as u64) * (cfg.batch_size as u64);
    let addrs_per_component = seeds_per_component * (cfg.num_indices as u64);

    // Components and whether they scale with num_indices
    let components: [(&str, &ComponentStats, bool); 4] = [
        ("PBKDF2", &stats.pbkdf2, false),      // PBKDF2 runs once per seed
        ("BIP32", &stats.bip32, true),         // Scales with num_indices
        ("secp256k1", &stats.secp256k1, true), // Scales with num_indices
        ("Base58", &stats.base58, true),       // Scales with num_indices
    ];

    // Sort by total time descending
    let mut sorted: Vec<_> = components.iter().collect();
    sorted.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));

    for (name, cs, scales_with_indices) in sorted {
        let ms = cs.total_ns as f64 / 1_000_000.0;
        let pct = if total > 0.0 {
            cs.total_ns as f64 / total * 100.0
        } else {
            0.0
        };
        let avg_ms = cs.total_ns as f64 / cs.count.max(1) as f64 / 1_000_000.0;

        // Per-unit cost
        let (per_unit_ns, unit_name) = if *scales_with_indices {
            (cs.total_ns as f64 / addrs_per_component as f64, "addr")
        } else {
            (cs.total_ns as f64 / seeds_per_component as f64, "seed")
        };

        println!(
            "{:<12} {:>8.1} ms ({:>5.1}%)  avg {:>8.3} ms  {:>6.0} ns/{}",
            format!("{}:", name),
            ms,
            pct,
            avg_ms,
            per_unit_ns,
            unit_name
        );
    }

    println!("{:<12} {:>8.1} ms", "TOTAL:", total / 1_000_000.0);
}

fn print_combined_table(results: &[DeviceBenchStats], cfg: &BenchConfig) {
    println!("Combined ({} devices):", results.len());

    // Sum stats across all devices
    let mut combined_pbkdf2 = ComponentStats::default();
    let mut combined_bip32 = ComponentStats::default();
    let mut combined_secp = ComponentStats::default();
    let mut combined_base58 = ComponentStats::default();

    for stats in results {
        combined_pbkdf2.total_ns += stats.pbkdf2.total_ns;
        combined_pbkdf2.count += stats.pbkdf2.count;
        combined_bip32.total_ns += stats.bip32.total_ns;
        combined_bip32.count += stats.bip32.count;
        combined_secp.total_ns += stats.secp256k1.total_ns;
        combined_secp.count += stats.secp256k1.count;
        combined_base58.total_ns += stats.base58.total_ns;
        combined_base58.count += stats.base58.count;
    }

    let total = combined_pbkdf2.total_ns
        + combined_bip32.total_ns
        + combined_secp.total_ns
        + combined_base58.total_ns;

    let num_devices = results.len() as u64;
    let seeds_per_component = (cfg.iters as u64) * (cfg.batch_size as u64) * num_devices;
    let addrs_per_component = seeds_per_component * (cfg.num_indices as u64);

    let components: [(&str, &ComponentStats, bool); 4] = [
        ("PBKDF2", &combined_pbkdf2, false),
        ("BIP32", &combined_bip32, true),
        ("secp256k1", &combined_secp, true),
        ("Base58", &combined_base58, true),
    ];

    let mut sorted: Vec<_> = components.iter().collect();
    sorted.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));

    for (name, cs, scales_with_indices) in sorted {
        let ms = cs.total_ns as f64 / 1_000_000.0;
        let pct = if total > 0 {
            cs.total_ns as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        let avg_ms = cs.total_ns as f64 / cs.count.max(1) as f64 / 1_000_000.0;

        let (per_unit_ns, unit_name) = if *scales_with_indices {
            (cs.total_ns as f64 / addrs_per_component as f64, "addr")
        } else {
            (cs.total_ns as f64 / seeds_per_component as f64, "seed")
        };

        println!(
            "{:<12} {:>8.1} ms ({:>5.1}%)  avg {:>8.3} ms  {:>6.0} ns/{}",
            format!("{}:", name),
            ms,
            pct,
            avg_ms,
            per_unit_ns,
            unit_name
        );
    }

    println!("{:<12} {:>8.1} ms", "TOTAL:", total as f64 / 1_000_000.0);
}
