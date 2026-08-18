//! Multi-threaded vanity address generator.

#![forbid(unsafe_code)]

use crate::generator::{generate_address_from_entropy_at, GeneratedAddress};
use crate::matcher::{first_match, Pattern};
use erg_vanity_address::Network;
use erg_vanity_crypto::entropy::from_salt_counter;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Result of a vanity search.
pub struct SearchResult {
    /// The matching address (if found)
    pub result: Option<GeneratedAddress>,
    /// Which pattern matched (index into the pattern list)
    pub pattern_index: u32,
    /// Number of attempts *reserved* (batch-based) while searching
    pub attempts: u64,
}

/// A single verified CPU hit.
#[derive(Clone)]
pub struct CpuHit {
    pub generated: GeneratedAddress,
    pub entropy: [u8; 32],
    pub pattern_index: u32,
}

/// Search for a vanity address matching the pattern.
///
/// Runs until a match is found or `stop` is set to true.
/// Uses all available CPU cores via rayon.
pub fn search(
    pattern: &Pattern,
    network: Network,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> SearchResult {
    search_many(std::slice::from_ref(pattern), network, 1, stop, counter)
}

/// Search multiple patterns, checking `num_indices` BIP44 indices per seed.
pub fn search_many(
    patterns: &[Pattern],
    network: Network,
    num_indices: u32,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> SearchResult {
    if patterns.is_empty() || patterns.iter().any(|p| p.validate().is_err()) {
        return SearchResult {
            result: None,
            pattern_index: 0,
            attempts: 0,
        };
    }

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    search_with_salt(patterns, network, num_indices, stop, counter, &salt)
}

fn search_with_salt(
    patterns: &[Pattern],
    network: Network,
    num_indices: u32,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    salt: &[u8; 32],
) -> SearchResult {
    let batch_size = 256u64;
    let mut total_attempts = 0u64;
    let num_indices = num_indices.max(1);

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let start = counter.fetch_add(batch_size, Ordering::Relaxed);
        let found = search_counter_range(
            patterns,
            network,
            num_indices,
            salt,
            start,
            batch_size,
            &stop,
        );

        total_attempts = total_attempts.saturating_add(batch_size * num_indices as u64);

        if let Some(hit) = found {
            stop.store(true, Ordering::Relaxed);
            return SearchResult {
                result: Some(hit.generated),
                pattern_index: hit.pattern_index,
                attempts: total_attempts,
            };
        }
    }

    SearchResult {
        result: None,
        pattern_index: 0,
        attempts: total_attempts,
    }
}

/// Scan a reserved counter range. Used by the engine for batched CPU search.
pub fn search_counter_range(
    patterns: &[Pattern],
    network: Network,
    num_indices: u32,
    salt: &[u8; 32],
    start: u64,
    batch_size: u64,
    stop: &AtomicBool,
) -> Option<CpuHit> {
    (start..start.saturating_add(batch_size))
        .into_par_iter()
        .find_map_any(|attempt_id| {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let entropy = from_salt_counter(salt, attempt_id);
            for addr_idx in 0..num_indices {
                let result = generate_address_from_entropy_at(&entropy, network, addr_idx).ok()?;
                if let Some(pattern_index) = first_match(patterns, &result.address) {
                    return Some(CpuHit {
                        generated: result,
                        entropy,
                        pattern_index: pattern_index as u32,
                    });
                }
            }
            None
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_from_counter_matches_crypto_helper() {
        let salt = [7u8; 32];
        assert_eq!(
            from_salt_counter(&salt, 12345),
            from_salt_counter(&salt, 12345)
        );
        assert_ne!(from_salt_counter(&salt, 1), from_salt_counter(&salt, 2));
    }

    #[test]
    fn test_search_with_easy_pattern() {
        let pattern = Pattern::prefix("9");
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));

        let result = search(&pattern, Network::Mainnet, stop, counter);

        assert!(result.result.is_some());
        assert!(result.result.unwrap().address.starts_with('9'));
    }

    #[test]
    fn test_search_stops_when_signaled() {
        let pattern = Pattern::prefix("9zzzzzzzzzzzzzzzzzzz");
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));

        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop_clone.store(true, Ordering::Relaxed);
        });

        let result = search(&pattern, Network::Mainnet, stop, counter);

        assert!(result.result.is_none());
        assert!(result.attempts > 0);
    }

    #[test]
    fn test_search_invalid_pattern_returns_immediately() {
        let pattern = Pattern::prefix("0invalid");
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));

        let result = search(&pattern, Network::Mainnet, stop, counter);

        assert!(result.result.is_none());
        assert_eq!(result.attempts, 0);
    }
}
