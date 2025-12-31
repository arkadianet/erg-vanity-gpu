//! Multi-threaded vanity address generator.

#![forbid(unsafe_code)]

use crate::generator::{generate_address_from_entropy, GeneratedAddress};
use crate::matcher::Pattern;
use erg_vanity_address::Network;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;

/// Result of a vanity search.
pub struct SearchResult {
    /// The matching address (if found)
    pub result: Option<GeneratedAddress>,
    /// Number of attempts *reserved* (batch-based) while searching
    pub attempts: u64,
}

/// Search for a vanity address matching the pattern.
///
/// Runs until a match is found or `stop` is set to true.
/// Uses all available CPU cores via rayon.
///
/// NOTE: entropy is derived from a per-search random salt + counter, so keys are not predictable.
pub fn search(
    pattern: &Pattern,
    network: Network,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> SearchResult {
    if pattern.validate().is_err() {
        return SearchResult {
            result: None,
            attempts: 0,
        };
    }

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    search_with_salt(pattern, network, stop, counter, &salt)
}

fn search_with_salt(
    pattern: &Pattern,
    network: Network,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    salt: &[u8; 32],
) -> SearchResult {
    let batch_size = 1000u64;
    let mut total_attempts = 0u64;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Allocate a unique range of attempt ids
        let start = counter.fetch_add(batch_size, Ordering::Relaxed);

        let found: Option<GeneratedAddress> = (start..start + batch_size)
            .into_par_iter()
            .find_map_any(|attempt_id| {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }

                let entropy = entropy_from_counter(attempt_id, salt);
                let result = generate_address_from_entropy(&entropy, network).ok()?;

                if pattern.matches(&result.address) {
                    Some(result)
                } else {
                    None
                }
            });

        total_attempts = total_attempts.saturating_add(batch_size);

        if let Some(addr) = found {
            stop.store(true, Ordering::Relaxed);
            return SearchResult {
                result: Some(addr),
                attempts: total_attempts,
            };
        }
    }

    SearchResult {
        result: None,
        attempts: total_attempts,
    }
}

/// Convert an attempt id into 32 bytes of entropy using a per-search salt.
///
/// entropy = blake2b256(salt || attempt_id_le)
fn entropy_from_counter(counter: u64, salt: &[u8; 32]) -> [u8; 32] {
    use erg_vanity_crypto::blake2b;

    let mut buf = [0u8; 40]; // 32 salt + 8 counter
    buf[..32].copy_from_slice(salt);
    buf[32..40].copy_from_slice(&counter.to_le_bytes());
    blake2b::digest(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_from_counter_deterministic_with_fixed_salt() {
        let salt = [7u8; 32];
        let e1 = entropy_from_counter(12345, &salt);
        let e2 = entropy_from_counter(12345, &salt);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_entropy_from_counter_different() {
        let salt = [7u8; 32];
        let e1 = entropy_from_counter(1, &salt);
        let e2 = entropy_from_counter(2, &salt);
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_search_with_easy_pattern() {
        let pattern = Pattern::prefix("9"); // mainnet P2PK addresses start with 9
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
        let pattern = Pattern::prefix("0invalid"); // '0' is not base58
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));

        let result = search(&pattern, Network::Mainnet, stop, counter);

        assert!(result.result.is_none());
        assert_eq!(result.attempts, 0);
    }
}
