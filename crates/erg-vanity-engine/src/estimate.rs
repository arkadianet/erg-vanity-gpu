//! Difficulty estimates for vanity patterns.

use erg_vanity_cpu::MatchType;
use erg_vanity_gpu::context::GpuContext;

use crate::search::Backend;

/// Conservative CPU addr/s. Not measured.
pub const CPU_ASSUMED_RATE: f64 = 10_000.0;

/// Measured RTX 3080 Ti `--index 1` seeds/s on current main (~590–610k). Scale baseline.
pub const GPU_BASELINE_SEEDS_PER_SEC: f64 = 600_000.0;

/// OpenCL compute units reported for a 3080 Ti.
pub const GPU_BASELINE_COMPUTE_UNITS: f64 = 80.0;

/// Typical 3080 Ti boost clock (MHz). Used only when OpenCL reports a max clock.
const GPU_BASELINE_CLOCK_MHZ: f64 = 1665.0;

/// Same as the 3080 Ti `--index 1` baseline. Labels interpolate this constant.
pub const GPU_ASSUMED_RATE: f64 = GPU_BASELINE_SEEDS_PER_SEC;

/// OpenCL GPU facts used for a one-shot rate guess (no bench).
#[derive(Debug, Clone)]
pub struct GpuDeviceHint {
    pub index: usize,
    pub name: String,
    pub vendor: String,
    pub platform: String,
    pub compute_units: u32,
    pub max_clock_mhz: Option<u32>,
}

impl GpuDeviceHint {
    pub fn display_line(&self) -> String {
        format!(
            "[{}] {} - {} (platform: {})",
            self.index,
            self.vendor.trim(),
            self.name.trim(),
            self.platform.trim()
        )
    }

    pub fn short_name(&self) -> String {
        short_device_name(&self.name)
    }
}

/// Pre-search throughput guess. Live search should use the measured rate instead.
#[derive(Debug, Clone)]
pub struct RateGuess {
    pub addr_per_sec: f64,
    pub seeds_per_sec: f64,
    pub label: String,
    pub is_gpu: bool,
    pub num_indices: u32,
}

impl RateGuess {
    pub fn note(&self) -> String {
        if !self.is_gpu {
            return "guess from CPU".into();
        }
        if self.num_indices > 1 {
            format!(
                "guess from {} · {} BIP44 slots",
                self.label, self.num_indices
            )
        } else {
            format!("guess from {}", self.label)
        }
    }
}

/// Estimated effort for a pattern.
#[derive(Debug, Clone)]
pub struct PatternEstimate {
    pub attempts_needed: f64,
    pub has_invalid_chars: bool,
    pub invalid_chars: Vec<char>,
}

/// List OpenCL GPUs once. Callers should cache this; do not bench on every keystroke.
pub fn list_gpu_device_hints() -> Result<Vec<GpuDeviceHint>, String> {
    let devices = GpuContext::enumerate_devices().map_err(|e| e.to_string())?;
    Ok(devices
        .into_iter()
        .map(|d| GpuDeviceHint {
            index: d.global_idx,
            name: d.device_name,
            vendor: d.vendor,
            platform: d.platform_name,
            compute_units: d.compute_units,
            max_clock_mhz: d.max_clock_mhz,
        })
        .collect())
}

/// Guess `--index 1` seeds/s for one GPU from the name table or CU scaling.
///
/// Name table first (3080 Ti / 3080 / 3070 / 4090 / Apple). Unknown cards:
/// `compute_units / 80 * 600k`, then `clock / 1665` if OpenCL reports a max clock.
/// That fallback is a guess, not a measurement.
pub fn guess_gpu_seeds_per_sec(device: &GpuDeviceHint) -> f64 {
    if let Some(rate) = name_table_seeds_per_sec(device) {
        return rate;
    }
    let cu = (device.compute_units as f64).max(1.0);
    let mut seeds = cu / GPU_BASELINE_COMPUTE_UNITS * GPU_BASELINE_SEEDS_PER_SEC;
    if let Some(clock) = device.max_clock_mhz {
        if clock > 0 {
            seeds *= clock as f64 / GPU_BASELINE_CLOCK_MHZ;
        }
    }
    seeds
}

/// Pick a pre-search addr/s guess. `addr/s = seeds/s × index`. Suffix/contains and
/// `--devices cpu` stay on the conservative CPU rate.
pub fn guess_rate_for(
    devices: &[GpuDeviceHint],
    backend: &Backend,
    match_type: MatchType,
    num_indices: u32,
) -> RateGuess {
    let num_indices = num_indices.max(1);
    let use_gpu = match (backend, match_type) {
        (_, MatchType::Suffix | MatchType::Contains) => false,
        (Backend::Cpu, _) => false,
        (Backend::Gpu { .. } | Backend::Auto, MatchType::Prefix) => true,
    };
    let selected = select_gpu_hints(devices, backend);
    if !use_gpu || selected.is_empty() {
        return RateGuess {
            addr_per_sec: CPU_ASSUMED_RATE,
            seeds_per_sec: CPU_ASSUMED_RATE,
            label: "CPU".into(),
            is_gpu: false,
            num_indices,
        };
    }
    let seeds_per_sec: f64 = selected.iter().map(guess_gpu_seeds_per_sec).sum();
    RateGuess {
        addr_per_sec: seeds_per_sec * num_indices as f64,
        seeds_per_sec,
        label: gpu_guess_label(&selected),
        is_gpu: true,
        num_indices,
    }
}

fn select_gpu_hints(devices: &[GpuDeviceHint], backend: &Backend) -> Vec<GpuDeviceHint> {
    match backend {
        Backend::Cpu => Vec::new(),
        Backend::Gpu { devices: list } if !list.is_empty() => devices
            .iter()
            .filter(|d| list.contains(&d.index))
            .cloned()
            .collect(),
        _ => devices.to_vec(),
    }
}

fn gpu_guess_label(devices: &[GpuDeviceHint]) -> String {
    match devices {
        [] => "GPU".into(),
        [one] => one.short_name(),
        many if many.iter().all(|d| d.short_name() == many[0].short_name()) => {
            format!("{}× {}", many.len(), many[0].short_name())
        }
        many => format!("{} GPUs", many.len()),
    }
}

fn short_device_name(name: &str) -> String {
    let t = name.trim();
    for prefix in [
        "NVIDIA GeForce ",
        "NVIDIA ",
        "AMD Radeon ",
        "AMD ",
        "Intel(R) ",
        "Intel ",
    ] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }
    t.to_string()
}

fn name_table_seeds_per_sec(device: &GpuDeviceHint) -> Option<f64> {
    let n = device.name.to_ascii_lowercase();
    let v = device.vendor.to_ascii_lowercase();
    if n.contains("3080") && n.contains("ti") {
        return Some(GPU_BASELINE_SEEDS_PER_SEC);
    }
    if n.contains("3080") {
        return Some(GPU_BASELINE_SEEDS_PER_SEC * 68.0 / GPU_BASELINE_COMPUTE_UNITS);
    }
    if n.contains("3070") {
        return Some(GPU_BASELINE_SEEDS_PER_SEC * 46.0 / GPU_BASELINE_COMPUTE_UNITS);
    }
    if n.contains("4090") {
        return Some(GPU_BASELINE_SEEDS_PER_SEC * 128.0 / GPU_BASELINE_COMPUTE_UNITS);
    }
    if v.contains("apple") || n.contains("apple") {
        return Some(80_000.0);
    }
    None
}

/// Estimate attempts for a Base58 pattern at the given match type.
pub fn estimate_pattern(
    pattern: &str,
    match_type: MatchType,
    ignore_case: bool,
) -> PatternEstimate {
    let mut invalid_chars = Vec::new();
    for c in pattern.chars() {
        if !is_base58_char(c) && !invalid_chars.contains(&c) {
            invalid_chars.push(c);
        }
    }
    if !invalid_chars.is_empty() {
        return PatternEstimate {
            attempts_needed: f64::INFINITY,
            has_invalid_chars: true,
            invalid_chars,
        };
    }

    let n = pattern.len() as f64;
    let mut attempts = match match_type {
        MatchType::Prefix => {
            if n <= 1.0 {
                1.0
            } else {
                // After leading '9', second char is one of 5, then 58 each
                5.0 * 58.0f64.powf((n - 2.0).max(0.0))
            }
        }
        MatchType::Suffix => 58.0f64.powf(n),
        MatchType::Contains => {
            let avg_len = 51.0;
            let positions = (avg_len - n + 1.0).max(1.0);
            58.0f64.powf(n) / positions
        }
    };

    if ignore_case {
        for c in pattern.chars() {
            if has_base58_case_pair(c) {
                attempts /= 2.0;
            }
        }
    }

    PatternEstimate {
        attempts_needed: attempts * 1.2,
        has_invalid_chars: false,
        invalid_chars: Vec::new(),
    }
}

/// Format seconds as a short human string.
pub fn format_time(seconds: f64) -> String {
    if seconds.is_infinite() {
        "impossible".to_string()
    } else if seconds < 1.0 {
        "less than a second".to_string()
    } else if seconds < 60.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else {
        format!("{:.1} days", seconds / 86400.0)
    }
}

/// Group a rate or attempt count with thousands separators.
pub fn format_rate(rate: f64) -> String {
    if !rate.is_finite() {
        return "impossible".into();
    }
    let s = format!("{:.0}", rate);
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn is_base58_char(c: char) -> bool {
    matches!(c,
        '1'..='9' |
        'A'..='H' | 'J'..='N' | 'P'..='Z' |
        'a'..='k' | 'm'..='z'
    )
}

fn has_base58_case_pair(c: char) -> bool {
    if !c.is_ascii_alphabetic() {
        return false;
    }
    let lo = c.to_ascii_lowercase();
    let hi = c.to_ascii_uppercase();
    lo != hi && is_base58_char(lo) && is_base58_char(hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(name: &str, compute_units: u32, max_clock_mhz: Option<u32>) -> GpuDeviceHint {
        GpuDeviceHint {
            index: 0,
            name: name.into(),
            vendor: "NVIDIA".into(),
            platform: "NVIDIA CUDA".into(),
            compute_units,
            max_clock_mhz,
        }
    }

    #[test]
    fn prefix_longer_is_harder() {
        let a = estimate_pattern("9e", MatchType::Prefix, false);
        let b = estimate_pattern("9ergo", MatchType::Prefix, false);
        assert!(b.attempts_needed > a.attempts_needed);
    }

    #[test]
    fn invalid_chars_are_impossible() {
        let e = estimate_pattern("9eO", MatchType::Prefix, false);
        assert!(e.has_invalid_chars);
        assert!(e.attempts_needed.is_infinite());
    }

    #[test]
    fn suffix_has_no_position_divisor() {
        let suffix = estimate_pattern("cafe", MatchType::Suffix, false);
        let contains = estimate_pattern("cafe", MatchType::Contains, false);
        assert!(suffix.attempts_needed > contains.attempts_needed);
    }

    #[test]
    fn ignore_case_is_easier() {
        let sensitive = estimate_pattern("9ergo", MatchType::Prefix, false);
        let insensitive = estimate_pattern("9ergo", MatchType::Prefix, true);
        assert!(insensitive.attempts_needed < sensitive.attempts_needed);
    }

    #[test]
    fn name_table_3080_ti_is_baseline() {
        let d = hint("NVIDIA GeForce RTX 3080 Ti", 80, None);
        assert_eq!(guess_gpu_seeds_per_sec(&d), GPU_BASELINE_SEEDS_PER_SEC);
        assert_eq!(d.short_name(), "RTX 3080 Ti");
    }

    #[test]
    fn name_table_3080_and_4090_scale() {
        let rtx3080 = guess_gpu_seeds_per_sec(&hint("NVIDIA GeForce RTX 3080", 68, None));
        let rtx3070 = guess_gpu_seeds_per_sec(&hint("NVIDIA GeForce RTX 3070", 46, None));
        let rtx4090 = guess_gpu_seeds_per_sec(&hint("NVIDIA GeForce RTX 4090", 128, None));
        assert!((rtx3080 - 510_000.0).abs() < 1.0);
        assert!((rtx3070 - 345_000.0).abs() < 1.0);
        assert!((rtx4090 - 960_000.0).abs() < 1.0);
    }

    #[test]
    fn apple_is_conservative() {
        let d = GpuDeviceHint {
            index: 0,
            name: "Apple M1".into(),
            vendor: "Apple".into(),
            platform: "Apple".into(),
            compute_units: 8,
            max_clock_mhz: None,
        };
        assert_eq!(guess_gpu_seeds_per_sec(&d), 80_000.0);
    }

    #[test]
    fn unknown_card_scales_from_compute_units() {
        let eighty = hint("Some Unknown GPU", 80, None);
        let forty = hint("Some Unknown GPU", 40, None);
        assert!((guess_gpu_seeds_per_sec(&eighty) - GPU_BASELINE_SEEDS_PER_SEC).abs() < 1.0);
        assert!((guess_gpu_seeds_per_sec(&forty) - GPU_BASELINE_SEEDS_PER_SEC / 2.0).abs() < 1.0);
    }

    #[test]
    fn clock_scales_unknown_card() {
        let d = hint("Some Unknown GPU", 80, Some(833));
        let seeds = guess_gpu_seeds_per_sec(&d);
        assert!((seeds - GPU_BASELINE_SEEDS_PER_SEC * 833.0 / 1665.0).abs() < 1.0);
    }

    #[test]
    fn addr_rate_is_seeds_times_index() {
        let d = hint("NVIDIA GeForce RTX 3080 Ti", 80, None);
        let one = guess_rate_for(
            std::slice::from_ref(&d),
            &Backend::Auto,
            MatchType::Prefix,
            1,
        );
        let hundred = guess_rate_for(
            std::slice::from_ref(&d),
            &Backend::Auto,
            MatchType::Prefix,
            100,
        );
        assert!((one.addr_per_sec - GPU_BASELINE_SEEDS_PER_SEC).abs() < 1.0);
        assert!((hundred.addr_per_sec - GPU_BASELINE_SEEDS_PER_SEC * 100.0).abs() < 1.0);
        assert!(hundred.note().contains("100 BIP44 slots"));
        assert!(one.note().contains("RTX 3080 Ti"));
        assert!(!one.note().contains("slots"));
    }

    #[test]
    fn suffix_and_cpu_backend_use_cpu_rate() {
        let d = hint("NVIDIA GeForce RTX 3080 Ti", 80, None);
        let suffix = guess_rate_for(
            std::slice::from_ref(&d),
            &Backend::Auto,
            MatchType::Suffix,
            1,
        );
        let cpu = guess_rate_for(
            std::slice::from_ref(&d),
            &Backend::Cpu,
            MatchType::Prefix,
            1,
        );
        assert_eq!(suffix.addr_per_sec, CPU_ASSUMED_RATE);
        assert_eq!(cpu.addr_per_sec, CPU_ASSUMED_RATE);
        assert!(!suffix.is_gpu);
        assert_eq!(suffix.note(), "guess from CPU");
    }

    #[test]
    fn format_rate_tracks_assumed_constants() {
        assert_eq!(
            format_rate(CPU_ASSUMED_RATE)
                .replace(',', "")
                .parse::<f64>()
                .unwrap(),
            CPU_ASSUMED_RATE
        );
        assert_eq!(
            format_rate(GPU_ASSUMED_RATE)
                .replace(',', "")
                .parse::<f64>()
                .unwrap(),
            GPU_ASSUMED_RATE
        );
        assert_eq!(GPU_ASSUMED_RATE, GPU_BASELINE_SEEDS_PER_SEC);
    }
}
