//! GPU pipeline orchestration for vanity address search.

use crate::buffers::{GpuBuffers, GpuHit, MAX_HITS};
use crate::context::{GpuContext, GpuError};
use crate::kernel::GpuProgram;
use crate::wordlist::WordlistBuffers;
use ocl::Kernel;
use rand::RngCore;

/// Configuration for vanity search.
#[derive(Debug, Clone)]
pub struct VanityConfig {
    /// Number of work items per batch (tune for your GPU).
    pub batch_size: usize,
    /// Case-insensitive matching.
    pub ignore_case: bool,
    /// Number of BIP44 address indices to check per seed (m/44'/429'/0'/0/{0..N-1}).
    pub num_indices: u32,
}

impl Default for VanityConfig {
    fn default() -> Self {
        Self {
            batch_size: 1 << 18, // 262,144 - conservative default
            ignore_case: false,
            num_indices: 1,
        }
    }
}

/// Sort results deterministically for stable output ordering.
///
/// GPU hit write order is nondeterministic due to `atomic_inc` across work items.
/// This produces stable output for a batch.
///
/// Sorting key (ascending):
/// 1) address_index
/// 2) pattern_index
/// 3) work_item_id (tie-breaker)
pub(crate) fn sort_results_deterministically(results: &mut [VanityResult]) {
    results.sort_by(|a, b| {
        a.address_index
            .cmp(&b.address_index)
            .then_with(|| a.pattern_index.cmp(&b.pattern_index))
            .then_with(|| a.work_item_id.cmp(&b.work_item_id))
    });
}

/// Prepare patterns for GPU upload.
///
/// When `ignore_case` is true, returns lowercased patterns (GPU kernel expects pre-lowercased).
/// When false, returns None (caller should use original patterns directly to avoid cloning).
pub(crate) fn prepare_patterns_for_gpu(
    patterns: &[String],
    ignore_case: bool,
) -> Option<Vec<String>> {
    if ignore_case {
        Some(patterns.iter().map(|p| p.to_ascii_lowercase()).collect())
    } else {
        None
    }
}

/// Result of a successful vanity search.
#[derive(Debug, Clone)]
pub struct VanityResult {
    /// The entropy that produced the matching address.
    pub entropy: [u8; 32],
    /// The work item ID that found this hit.
    pub work_item_id: u32,
    /// The BIP44 address index <i> in m/44'/429'/0'/0/<i>.
    pub address_index: u32,
    /// Index into the pattern list that matched.
    pub pattern_index: u32,
    /// The Ergo address (Base58 encoded).
    pub address: String,
    /// The BIP39 mnemonic (24 words).
    pub mnemonic: String,
}

/// GPU-accelerated vanity address search pipeline.
pub struct VanityPipeline {
    ctx: GpuContext,
    #[allow(dead_code)]
    program: GpuProgram,
    buffers: GpuBuffers,
    #[allow(dead_code)]
    wordlist: WordlistBuffers,
    kernel: Kernel,
    patterns: Vec<String>,
    #[allow(dead_code)]
    num_patterns: u32,
    ignore_case: bool,
    num_indices: u32,
    #[allow(dead_code)]
    salt: [u8; 32],
    counter: u64,
    cfg: VanityConfig,
    addresses_checked: u64,
    hits_dropped_total: u64,
}

impl VanityPipeline {
    /// Create a new vanity search pipeline.
    pub fn new(patterns: &[String], cfg: VanityConfig) -> Result<Self, GpuError> {
        if patterns.is_empty() {
            return Err(GpuError::Other("at least one pattern required".to_string()));
        }

        let ctx = GpuContext::new()?;
        let program = GpuProgram::vanity(&ctx)?;
        let queue = ctx.queue();

        // Allocate buffers
        let buffers = GpuBuffers::new(&ctx, cfg.batch_size)?;
        let wordlist = WordlistBuffers::upload(queue)?;

        // Generate random salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        buffers.upload_salt(&salt)?;

        // Upload patterns (lowercase for GPU if ignore_case, keep originals for display)
        let patterns_for_gpu_storage = prepare_patterns_for_gpu(patterns, cfg.ignore_case);
        let patterns_for_gpu: &[String] = patterns_for_gpu_storage.as_deref().unwrap_or(patterns);
        let num_patterns = buffers.upload_patterns(patterns_for_gpu)? as u32;

        // Build kernel with all arguments matching vanity_search signature:
        // salt, counter_start, words8, word_lens,
        // patterns, pattern_offsets, pattern_lens, num_patterns, ignore_case, num_indices,
        // hits, hit_count, max_hits
        let kernel = Kernel::builder()
            .program(program.program())
            .name("vanity_search")
            .queue(queue.clone())
            .global_work_size(cfg.batch_size)
            .arg(&buffers.salt) // arg 0: salt
            .arg(0u64) // arg 1: counter_start (scalar, updated each batch)
            .arg(&wordlist.words8) // arg 2: words8
            .arg(&wordlist.lens) // arg 3: word_lens
            .arg(&buffers.patterns) // arg 4: patterns
            .arg(&buffers.pattern_offsets) // arg 5: pattern_offsets
            .arg(&buffers.pattern_lens) // arg 6: pattern_lens
            .arg(num_patterns) // arg 7: num_patterns
            .arg(if cfg.ignore_case { 1u32 } else { 0u32 }) // arg 8: ignore_case
            .arg(cfg.num_indices) // arg 9: num_indices
            .arg(&buffers.hits) // arg 10: hits
            .arg(&buffers.hit_count) // arg 11: hit_count
            .arg(MAX_HITS as u32) // arg 12: max_hits
            .build()?;

        Ok(Self {
            ctx,
            program,
            buffers,
            wordlist,
            kernel,
            patterns: patterns.to_vec(),
            num_patterns,
            ignore_case: cfg.ignore_case,
            num_indices: cfg.num_indices,
            salt,
            counter: 0,
            cfg,
            addresses_checked: 0,
            hits_dropped_total: 0,
        })
    }

    /// Get the GPU device info.
    pub fn device_info(&self) -> &crate::context::DeviceInfo {
        self.ctx.info()
    }

    /// Get the number of addresses checked so far.
    pub fn addresses_checked(&self) -> u64 {
        self.addresses_checked
    }

    /// Get the total number of hits dropped due to buffer overflow.
    pub fn hits_dropped_total(&self) -> u64 {
        self.hits_dropped_total
    }

    /// Run one batch of the search.
    /// Returns all verified matches from this batch.
    pub fn run_batch(&mut self) -> Result<Vec<VanityResult>, GpuError> {
        // Reset hit counter
        self.buffers.reset_hits()?;

        // Update counter_start (arg index 1)
        self.kernel.set_arg(1, self.counter)?;

        // Run kernel
        unsafe {
            self.kernel.enq()?;
        }
        self.ctx.queue().finish()?;

        // Update counter for next batch
        // Each work item checks num_indices addresses
        self.counter = self.counter.wrapping_add(self.cfg.batch_size as u64);
        self.addresses_checked += (self.cfg.batch_size as u64) * (self.num_indices as u64);

        // Check for hits (read raw count, may exceed MAX_HITS)
        let raw_hit_count = self.buffers.read_hit_count()? as usize;
        let hit_count = raw_hit_count.min(MAX_HITS);

        // Track dropped hits (don't spam warnings here - caller can check hits_dropped_total)
        if raw_hit_count > MAX_HITS {
            self.hits_dropped_total += (raw_hit_count - MAX_HITS) as u64;
        }

        if hit_count == 0 {
            return Ok(Vec::new());
        }

        let hits = self.buffers.read_hits(hit_count)?;

        // Verify each hit on CPU
        let mut results = Vec::new();
        for hit in hits {
            if let Some(result) = self.verify_hit(&hit)? {
                results.push(result);
            }
        }

        // Sort for stable output (GPU atomic_inc order is nondeterministic)
        sort_results_deterministically(&mut results);

        Ok(results)
    }

    /// Search until a match is found (blocking).
    pub fn search_blocking(&mut self) -> Result<VanityResult, GpuError> {
        loop {
            let results = self.run_batch()?;
            if let Some(result) = results.into_iter().next() {
                return Ok(result);
            }
        }
    }

    /// Verify a hit on CPU and return the result if valid.
    fn verify_hit(&self, hit: &GpuHit) -> Result<Option<VanityResult>, GpuError> {
        use erg_vanity_address::encode_p2pk_mainnet;
        use erg_vanity_bip::bip32::ExtendedPrivateKey;
        use erg_vanity_bip::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
        use erg_vanity_bip::bip44::derive_ergo_key;
        use erg_vanity_crypto::secp256k1::pubkey::PublicKey;
        use erg_vanity_crypto::secp256k1::scalar::Scalar;

        let entropy = hit.entropy_bytes();

        // Derive mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| GpuError::Other(format!("mnemonic error: {}", e)))?;

        // Derive seed
        let seed = mnemonic_to_seed(&mnemonic, "");

        // Derive master key
        let master = ExtendedPrivateKey::from_seed(&seed)
            .map_err(|e| GpuError::Other(format!("bip32 error: {:?}", e)))?;

        // Derive Ergo key at m/44'/429'/0'/0/<address_index>
        let ergo_key = derive_ergo_key(&master, 0, 0, hit.address_index)
            .map_err(|e| GpuError::Other(format!("bip44 error: {:?}", e)))?;

        // Get public key
        let privkey = *ergo_key.private_key();
        let scalar = Scalar::from_bytes(&privkey)
            .ok_or_else(|| GpuError::Other("invalid scalar".to_string()))?;
        let pubkey = PublicKey::from_private_key(&scalar)
            .ok_or_else(|| GpuError::Other("invalid pubkey".to_string()))?;

        // Encode address
        let address = encode_p2pk_mainnet(pubkey.as_bytes());

        // Verify prefix match (must mirror ignore_case exactly, use ASCII-only compare)
        let pattern_idx = hit.pattern_index as usize;
        let pattern = self.patterns.get(pattern_idx).ok_or_else(|| {
            GpuError::Other(format!("pattern_index {} out of range", pattern_idx))
        })?;

        let matches = if self.ignore_case {
            // ASCII-only case-insensitive compare (no Unicode, no allocation)
            address
                .get(..pattern.len())
                .map(|prefix| prefix.eq_ignore_ascii_case(pattern))
                .unwrap_or(false)
        } else {
            address.starts_with(pattern)
        };

        if matches {
            Ok(Some(VanityResult {
                entropy,
                work_item_id: hit.work_item_id,
                address_index: hit.address_index,
                pattern_index: hit.pattern_index,
                address,
                mnemonic,
            }))
        } else {
            // False positive (shouldn't happen with correct GPU code)
            eprintln!(
                "Warning: GPU hit did not verify on CPU (addr={}, pattern={}, index={}, icase={})",
                address, pattern, hit.address_index, self.ignore_case
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_compiles() {
        // Skip if no GPU available
        let Some(_ctx) = crate::context::try_ctx() else {
            return;
        };

        let cfg = VanityConfig {
            batch_size: 1024,
            ignore_case: false,
            num_indices: 1,
        };

        let pipe = VanityPipeline::new(&["9".to_string()], cfg).expect("pipeline creation failed");
        println!("Pipeline created: {}", pipe.device_info());
    }

    /// Helper to create a dummy VanityResult for ordering tests (no GPU needed).
    fn dummy_result(work_item_id: u32, address_index: u32, pattern_index: u32) -> VanityResult {
        VanityResult {
            entropy: [0u8; 32],
            work_item_id,
            address_index,
            pattern_index,
            address: String::new(),
            mnemonic: String::new(),
        }
    }

    #[test]
    fn test_sort_results_deterministically_basic() {
        // Scrambled input simulating nondeterministic GPU atomic_inc order
        let mut results = vec![
            dummy_result(100, 2, 0),
            dummy_result(50, 0, 1),
            dummy_result(200, 1, 0),
            dummy_result(75, 0, 0),
            dummy_result(25, 1, 1),
        ];

        sort_results_deterministically(&mut results);

        // Expected order: address_index ASC, pattern_index ASC, work_item_id ASC
        // (0,0,75), (0,1,50), (1,0,200), (1,1,25), (2,0,100)
        assert_eq!(
            results
                .iter()
                .map(|r| (r.address_index, r.pattern_index, r.work_item_id))
                .collect::<Vec<_>>(),
            vec![(0, 0, 75), (0, 1, 50), (1, 0, 200), (1, 1, 25), (2, 0, 100)]
        );
    }

    #[test]
    fn test_sort_results_deterministically_ties() {
        // Test tie-breaking: same address_index, different pattern_index
        // and same (address_index, pattern_index), different work_item_id
        let mut results = vec![
            dummy_result(300, 0, 2),
            dummy_result(100, 0, 1),
            dummy_result(200, 0, 1), // tie on (0,1), work_item_id breaks it
            dummy_result(50, 0, 0),
        ];

        sort_results_deterministically(&mut results);

        // Expected: (0,0,50), (0,1,100), (0,1,200), (0,2,300)
        assert_eq!(
            results
                .iter()
                .map(|r| (r.address_index, r.pattern_index, r.work_item_id))
                .collect::<Vec<_>>(),
            vec![(0, 0, 50), (0, 1, 100), (0, 1, 200), (0, 2, 300)]
        );
    }

    #[test]
    fn test_sort_results_deterministically_empty() {
        let mut results: Vec<VanityResult> = vec![];
        sort_results_deterministically(&mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn test_sort_results_deterministically_single() {
        let mut results = vec![dummy_result(42, 5, 3)];
        sort_results_deterministically(&mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(
            (
                results[0].address_index,
                results[0].pattern_index,
                results[0].work_item_id
            ),
            (5, 3, 42)
        );
    }

    #[test]
    fn test_prepare_patterns_for_gpu_lowercases_when_ignore_case() {
        let patterns = vec!["9ABC".to_string(), "9eRgO".to_string()];

        // ignore_case=true: returns lowercased patterns
        let lowered = prepare_patterns_for_gpu(&patterns, true).unwrap();
        assert_eq!(lowered, vec!["9abc", "9ergo"]);

        // ignore_case=false: returns None (use originals directly)
        let none = prepare_patterns_for_gpu(&patterns, false);
        assert!(none.is_none());
    }
}
