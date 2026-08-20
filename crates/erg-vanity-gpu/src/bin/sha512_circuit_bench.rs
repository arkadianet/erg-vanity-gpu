//! Research A/B of HMAC-64 SHA-512 candidates on the OpenCL device.
//!
//! cargo run --release --locked -p erg-vanity-gpu --bin sha512_circuit_bench
//!
//! Optional args: [batch] [iters] [warmup] [timed]
//! Env: SHA512_BENCH_BATCH, SHA512_BENCH_ITERS, SHA512_BENCH_WARMUP,
//!      SHA512_BENCH_TIMED, SHA512_BENCH_LOCAL, SHA512_BENCH_SKIP_PROD=1,
//!      SHA512_BENCH_OUT=<path>
//!
//! Does not change the production vanity kernel.
//! Author: arkadianet

use erg_vanity_crypto::sha512_isa::{pad64_isa_cost, predicted_expand_speedup};
use erg_vanity_gpu::sha512_research::{
    format_report, run_report, BenchConfig, Recommendation,
};

fn main() {
    // SAFETY: process-global, set before any OpenCL compile thread starts.
    unsafe {
        std::env::set_var("ERG_CL_VERBOSE", "1");
    }
    println!("SHA-512 circuit research bench (production kernels unchanged)");
    println!(
        "modeled pad64 cost generic={} specialized={} predicted expand cut={:.2}%",
        pad64_isa_cost(false).total(),
        pad64_isa_cost(true).total(),
        predicted_expand_speedup() * 100.0
    );
    println!("README 3080 Ti isolated PBKDF2 baseline: ~1600 ns/seed");

    let cfg = BenchConfig::from_env_args();
    println!(
        "planned launch batch={} iters={} warmup={} timed={} local={:?} time_prod={}",
        cfg.batch, cfg.iters, cfg.warmup, cfg.timed, cfg.local, cfg.time_prod
    );

    match run_report(&cfg) {
        Ok(report) => {
            println!();
            let text = format_report(&report);
            print!("{text}");
            for v in &report.variants {
                if !v.build_log.trim().is_empty() {
                    println!("--- build log {} ---\n{}", v.name, v.build_log);
                }
            }
            if let Some(p) = &report.prod_pbkdf2 {
                if !p.build_log.trim().is_empty() {
                    println!("--- build log bench_pbkdf2 ---\n{}", p.build_log);
                }
            }
            if let Ok(path) = std::env::var("SHA512_BENCH_OUT") {
                if let Err(e) = std::fs::write(&path, &text) {
                    eprintln!("failed to write {path}: {e}");
                }
            }
            if report.variants.iter().any(|r| !r.exact) {
                std::process::exit(2);
            }
            if report.recommendation == Recommendation::Implement {
                std::process::exit(0);
            }
        }
        Err(e) => {
            eprintln!("no GPU bench: {e}");
            eprintln!("CPU exactness: cargo test --locked -p erg-vanity-crypto sha512_isa");
            eprintln!("=== DECISION ===");
            eprintln!("recommendation=CONTINUE");
            eprintln!(
                "reason=no OpenCL GPU on this machine; RTX ns/seed + SASS/PTX still required"
            );
        }
    }
}
