//! Research A/B of HMAC-64 SHA-512 candidates on the OpenCL device.
//!
//! cargo run -p erg-vanity-gpu --bin sha512_circuit_bench
//!
//! Does not change the production vanity kernel.
//! Author: arkadianet

use erg_vanity_crypto::sha512_isa::{pad64_isa_cost, predicted_expand_speedup};

fn main() {
    println!("SHA-512 circuit research bench (production kernels unchanged)");
    println!(
        "modeled pad64 cost generic={} specialized={} predicted expand cut={:.2}%",
        pad64_isa_cost(false).total(),
        pad64_isa_cost(true).total(),
        predicted_expand_speedup() * 100.0
    );

    match erg_vanity_gpu::sha512_research::run_all(4096, 2048, 2, 8) {
        Ok(rows) => {
            println!();
            for r in &rows {
                println!(
                    "{:<24}  {:7.1} ns/seed  exact={}  runs={}",
                    r.name, r.ns_per_seed, r.exact, r.runs
                );
                if !r.build_log.trim().is_empty() {
                    println!("--- build log {} ---\n{}", r.name, r.build_log);
                }
            }
            if rows.iter().any(|r| !r.exact) {
                std::process::exit(2);
            }
            if let (Some(base), Some(best)) = (
                rows.first(),
                rows.iter()
                    .min_by(|a, b| a.ns_per_seed.partial_cmp(&b.ns_per_seed).unwrap()),
            ) {
                let speedup = base.ns_per_seed / best.ns_per_seed;
                println!(
                    "\nbest={}  speedup vs prod={:.3}x ({:.1}%)",
                    best.name,
                    speedup,
                    (speedup - 1.0) * 100.0
                );
            }
        }
        Err(e) => {
            eprintln!("no GPU bench: {e}");
            eprintln!("CPU exactness: cargo test --locked -p erg-vanity-crypto sha512_isa");
        }
    }
}
