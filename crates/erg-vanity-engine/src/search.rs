//! Search orchestration: pick GPU or CPU, stream events.

use crate::verify::verify_hit_ergo_lib;
use erg_vanity_address::Network;
use erg_vanity_cpu::{search_counter_range, MatchType, Pattern};
use erg_vanity_gpu::context::GpuContext;
use erg_vanity_gpu::pipeline::{VanityConfig, VanityPipeline};
use rand::RngCore;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_PATTERN_LEN: usize = 32;
pub const MAX_PATTERNS: usize = 64;
pub const MAX_PATTERN_DATA: usize = 1024;

const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const VALID_SECOND: &[char] = &['e', 'f', 'g', 'h', 'i'];

/// Which backend should run the search.
#[derive(Debug, Clone)]
pub enum Backend {
    /// GPU if present (prefix only), otherwise CPU.
    Auto,
    /// Force CPU.
    Cpu,
    /// Specific GPU device indices, or all GPUs if empty after resolve.
    Gpu { devices: Vec<usize> },
}

/// A verified vanity hit.
#[derive(Clone)]
pub struct Hit {
    pub address: String,
    pub mnemonic: String,
    pub entropy: [u8; 32],
    pub address_index: u32,
    pub pattern_index: u32,
    pub device_label: String,
}

/// Events emitted while a search runs.
#[derive(Clone)]
pub enum SearchEvent {
    Progress {
        checked: u64,
        rate: f64,
        found: usize,
    },
    Hit(Hit),
    Dropped {
        count: u64,
    },
    Error {
        message: String,
    },
    Done {
        checked: u64,
        found: usize,
        elapsed: Duration,
    },
}

/// Full search request from CLI or GUI.
#[derive(Clone)]
pub struct SearchRequest {
    pub patterns: Vec<String>,
    pub match_type: MatchType,
    pub ignore_case: bool,
    pub max_results: usize,
    pub num_indices: u32,
    pub duration: Option<Duration>,
    pub backend: Backend,
    pub batch_size: Option<usize>,
}

impl SearchRequest {
    /// Validate patterns and limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.patterns.is_empty() {
            return Err("at least one pattern is required".into());
        }
        if self.patterns.len() > MAX_PATTERNS {
            return Err(format!(
                "too many patterns: {} exceeds {}",
                self.patterns.len(),
                MAX_PATTERNS
            ));
        }
        let total: usize = self.patterns.iter().map(|p| p.len()).sum();
        if total > MAX_PATTERN_DATA {
            return Err(format!("pattern data too large: {total} bytes"));
        }
        if self.max_results == 0 {
            return Err("--max-results must be at least 1".into());
        }
        if self.num_indices == 0 {
            return Err("--index must be at least 1".into());
        }
        if self.num_indices > 100 {
            return Err(format!(
                "--index {} exceeds maximum of 100",
                self.num_indices
            ));
        }
        for p in &self.patterns {
            validate_pattern(p, self.match_type, self.ignore_case)?;
        }
        Ok(())
    }
}

/// Validate one pattern. Prefix mode requires a full-address `9e`–`9i` start.
pub fn validate_pattern(
    pattern: &str,
    match_type: MatchType,
    ignore_case: bool,
) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".into());
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!(
            "pattern '{pattern}' too long: {} exceeds {MAX_PATTERN_LEN}",
            pattern.len()
        ));
    }
    if !pattern.is_ascii() {
        return Err(format!("pattern '{pattern}' contains non-ASCII characters"));
    }
    for c in pattern.chars() {
        if !BASE58.contains(c) {
            return Err(format!(
                "pattern '{pattern}' contains invalid Base58 character '{c}'"
            ));
        }
    }
    if match_type != MatchType::Prefix {
        return Ok(());
    }
    let chars: Vec<char> = pattern.chars().collect();
    if chars[0] != '9' {
        return Err(format!(
            "invalid pattern '{pattern}': prefix patterns are full addresses and start with 9e/9f/9g/9h/9i"
        ));
    }
    if chars.len() >= 2 {
        let second = if ignore_case {
            chars[1].to_ascii_lowercase()
        } else {
            chars[1]
        };
        if !VALID_SECOND.contains(&second) {
            return Err(format!(
                "invalid pattern '{pattern}': mainnet P2PK addresses start with 9e/9f/9g/9h/9i"
            ));
        }
    }
    Ok(())
}

/// Run a search, sending events to `tx` until stop, duration, or max results.
pub fn run_search(req: SearchRequest, tx: Sender<SearchEvent>, stop: Arc<AtomicBool>) {
    if let Err(e) = req.validate() {
        let _ = tx.send(SearchEvent::Error { message: e });
        return;
    }

    let use_gpu = match (&req.backend, req.match_type) {
        (_, MatchType::Suffix | MatchType::Contains) => false,
        (Backend::Cpu, _) => false,
        (Backend::Gpu { .. }, MatchType::Prefix) => true,
        (Backend::Auto, MatchType::Prefix) => gpu_available(),
    };

    if use_gpu {
        run_gpu(&req, tx, stop);
    } else {
        run_cpu(&req, tx, stop);
    }
}

fn gpu_available() -> bool {
    GpuContext::enumerate_devices()
        .map(|d| !d.is_empty())
        .unwrap_or(false)
}

fn compiled_patterns(req: &SearchRequest) -> Vec<Pattern> {
    req.patterns
        .iter()
        .map(|p| Pattern::new(p.clone(), req.match_type).ignore_case(req.ignore_case))
        .collect()
}

fn accept_hit(
    hit: Hit,
    tx: &Sender<SearchEvent>,
    found: &mut usize,
    max: usize,
    stop: &AtomicBool,
) {
    if !verify_hit_ergo_lib(&hit.entropy, hit.address_index, &hit.address) {
        eprintln!(
            "Warning: hit failed ergo-lib verify (addr={}, index={}); dropping",
            hit.address, hit.address_index
        );
        return;
    }
    if *found >= max {
        stop.store(true, Ordering::Relaxed);
        return;
    }
    *found += 1;
    let _ = tx.send(SearchEvent::Hit(hit));
    if *found >= max {
        stop.store(true, Ordering::Relaxed);
    }
}

fn run_cpu(req: &SearchRequest, tx: Sender<SearchEvent>, stop: Arc<AtomicBool>) {
    let patterns = compiled_patterns(req);
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let counter = Arc::new(AtomicU64::new(0));
    let batch = req.batch_size.unwrap_or(256) as u64;
    let start = Instant::now();
    let mut found = 0usize;
    let mut checked = 0u64;
    let mut last_report = Instant::now();

    if let Some(d) = req.duration {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(d);
            stop.store(true, Ordering::Relaxed);
        });
    }

    while !stop.load(Ordering::Relaxed) && found < req.max_results {
        let start_id = counter.fetch_add(batch, Ordering::Relaxed);
        if let Some(hit) = search_counter_range(
            &patterns,
            Network::Mainnet,
            req.num_indices,
            &salt,
            start_id,
            batch,
            &stop,
        ) {
            accept_hit(
                Hit {
                    address: hit.generated.address,
                    mnemonic: hit.generated.mnemonic,
                    entropy: hit.entropy,
                    address_index: hit.generated.address_index,
                    pattern_index: hit.pattern_index,
                    device_label: "cpu".into(),
                },
                &tx,
                &mut found,
                req.max_results,
                &stop,
            );
        }
        checked += batch * req.num_indices as u64;
        if last_report.elapsed().as_secs_f64() >= 1.0 {
            let rate = checked as f64 / start.elapsed().as_secs_f64().max(0.001);
            let _ = tx.send(SearchEvent::Progress {
                checked,
                rate,
                found,
            });
            last_report = Instant::now();
        }
    }

    let _ = tx.send(SearchEvent::Done {
        checked,
        found,
        elapsed: start.elapsed(),
    });
}

enum WorkerMsg {
    Hit(Hit),
    Error { device: usize, message: String },
    Stats { dropped: u64 },
}

fn resolve_gpu_devices(backend: &Backend) -> Result<Vec<usize>, String> {
    let devices = GpuContext::enumerate_devices().map_err(|e| e.to_string())?;
    if devices.is_empty() {
        return Err("no OpenCL GPU devices found".into());
    }
    let available: Vec<usize> = devices.iter().map(|d| d.global_idx).collect();
    match backend {
        Backend::Gpu { devices: list } if !list.is_empty() => {
            for idx in list {
                if !available.contains(idx) {
                    return Err(format!(
                        "device index {idx} not found (available: {available:?})"
                    ));
                }
            }
            Ok(list.clone())
        }
        _ => Ok(available),
    }
}

fn run_gpu(req: &SearchRequest, tx: Sender<SearchEvent>, stop: Arc<AtomicBool>) {
    let devices = match resolve_gpu_devices(&req.backend) {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.send(SearchEvent::Error { message: e });
            return;
        }
    };

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let default_batch = GpuContext::with_device(devices[0])
        .ok()
        .map(|ctx| ctx.recommended_batch_size())
        .unwrap_or(1 << 18);
    let batch_size = req.batch_size.unwrap_or(default_batch);
    let cfg = VanityConfig {
        batch_size,
        ignore_case: req.ignore_case,
        num_indices: req.num_indices,
    };

    let counter = Arc::new(AtomicU64::new(0));
    let total_checked = Arc::new(AtomicU64::new(0));
    let (wtx, wrx) = std::sync::mpsc::channel::<WorkerMsg>();
    let mut handles = Vec::new();

    for device_index in devices {
        let patterns = req.patterns.clone();
        let cfg = cfg.clone();
        let wtx = wtx.clone();
        let counter = Arc::clone(&counter);
        let stop = Arc::clone(&stop);
        let total_checked = Arc::clone(&total_checked);
        let handle = thread::spawn(move || {
            let mut pipeline = match VanityPipeline::new_with_device_and_salt(
                &patterns,
                cfg.clone(),
                device_index,
                salt,
            ) {
                Ok(p) => p,
                Err(e) => {
                    let _ = wtx.send(WorkerMsg::Error {
                        device: device_index,
                        message: e.to_string(),
                    });
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
            };
            while !stop.load(Ordering::Relaxed) {
                let counter_start = counter.fetch_add(cfg.batch_size as u64, Ordering::Relaxed);
                let batch = match pipeline.run_batch_with_counter(counter_start) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = wtx.send(WorkerMsg::Error {
                            device: device_index,
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
                for result in batch {
                    if wtx
                        .send(WorkerMsg::Hit(Hit {
                            address: result.address,
                            mnemonic: result.mnemonic,
                            entropy: result.entropy,
                            address_index: result.address_index,
                            pattern_index: result.pattern_index,
                            device_label: format!("gpu:{device_index}"),
                        }))
                        .is_err()
                    {
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
            let _ = wtx.send(WorkerMsg::Stats {
                dropped: pipeline.hits_dropped_total(),
            });
        });
        handles.push(handle);
    }
    drop(wtx);

    if let Some(d) = req.duration {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(d);
            stop.store(true, Ordering::Relaxed);
        });
    }

    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut found = 0usize;
    let mut dropped_total = 0u64;
    let mut first_error: Option<String> = None;

    loop {
        match wrx.recv_timeout(Duration::from_millis(200)) {
            Ok(WorkerMsg::Hit(hit)) => {
                accept_hit(hit, &tx, &mut found, req.max_results, &stop);
            }
            Ok(WorkerMsg::Error { device, message }) => {
                if first_error.is_none() {
                    first_error = Some(format!("Device {device} error: {message}"));
                }
                stop.store(true, Ordering::Relaxed);
            }
            Ok(WorkerMsg::Stats { dropped }) => {
                dropped_total = dropped_total.saturating_add(dropped);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if last_report.elapsed().as_secs_f64() >= 1.0 {
            let checked = total_checked.load(Ordering::Relaxed);
            let rate = checked as f64 / start.elapsed().as_secs_f64().max(0.001);
            let _ = tx.send(SearchEvent::Progress {
                checked,
                rate,
                found,
            });
            last_report = Instant::now();
        }
    }

    for h in handles {
        let _ = h.join();
    }

    if dropped_total > 0 {
        let _ = tx.send(SearchEvent::Dropped {
            count: dropped_total,
        });
    }
    if let Some(message) = first_error {
        let _ = tx.send(SearchEvent::Error { message });
    }
    let _ = tx.send(SearchEvent::Done {
        checked: total_checked.load(Ordering::Relaxed),
        found,
        elapsed: start.elapsed(),
    });
}

/// List OpenCL GPUs for `--list-devices`.
pub fn list_gpu_devices() -> Result<Vec<String>, String> {
    let devices = GpuContext::enumerate_devices().map_err(|e| e.to_string())?;
    Ok(devices
        .into_iter()
        .map(|info| {
            format!(
                "[{}] {} - {} (platform: {})",
                info.global_idx,
                info.vendor.trim(),
                info.device_name.trim(),
                info.platform_name.trim()
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_rejects_wrong_second_char() {
        assert!(validate_pattern("9a", MatchType::Prefix, false).is_err());
        assert!(validate_pattern("9err", MatchType::Prefix, false).is_ok());
    }

    #[test]
    fn suffix_allows_non_prefix() {
        assert!(validate_pattern("cafe", MatchType::Suffix, false).is_ok());
    }
}
