use erg_vanity_gpu::pipeline::{VanityConfig, VanityPipeline};
use std::io::{self, Write};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let pattern = args.next().unwrap_or_else(|| {
        eprintln!("Usage: erg-vanity-cli <base58_prefix>");
        eprintln!("Example: erg-vanity-cli 9abc");
        std::process::exit(2);
    });

    if pattern.is_empty() {
        eprintln!("Error: pattern must not be empty");
        std::process::exit(2);
    }

    // Ergo mainnet P2PK addresses start with 9e, 9f, 9g, 9h, or 9i
    // (determined by Base58 encoding of prefix byte 0x01)
    if !pattern.starts_with('9') {
        eprintln!("Error: Ergo mainnet addresses start with '9', pattern '{}' can never match", pattern);
        std::process::exit(2);
    }

    if pattern.len() >= 2 {
        let second_char = pattern.chars().nth(1).unwrap();
        if !matches!(second_char, 'e' | 'f' | 'g' | 'h' | 'i') {
            eprintln!("Error: Ergo mainnet P2PK addresses start with 9e, 9f, 9g, 9h, or 9i");
            eprintln!("Pattern '{}' can never match", pattern);
            std::process::exit(2);
        }
    }

    let cfg = VanityConfig::default();

    eprintln!("Searching for prefix: {}", pattern);
    eprintln!("Batch size: {}", cfg.batch_size);

    let mut pipe = match VanityPipeline::new(&pattern, cfg) {
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

    loop {
        match pipe.run_batch() {
            Ok(Some(found)) => {
                eprintln!();
                println!("Found!");
                println!("Address:  {}", found.address);
                println!("Mnemonic: {}", found.mnemonic);
                println!();
                println!("Entropy:  {}", hex::encode(found.entropy));
                println!("Work item: {}", found.work_item_id);
                println!("Checked: {} addresses in {:.1}s",
                    pipe.addresses_checked(),
                    start.elapsed().as_secs_f64()
                );
                break;
            }
            Ok(None) => {
                // Progress report every ~1 second
                if last_report.elapsed().as_secs_f64() >= 1.0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let checked = pipe.addresses_checked();
                    let rate = checked as f64 / elapsed;
                    eprint!("\rChecked: {} ({:.0} addr/s)   ", checked, rate);
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
}
