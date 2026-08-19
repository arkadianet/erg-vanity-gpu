//! GPU pipeline orchestration for vanity address search.

use crate::buffers::{GpuBuffers, GpuHit, MAX_HITS};
use crate::comb::CombTableBuffer;
use crate::context::{GpuContext, GpuError};
use crate::kernel::GpuProgram;
use crate::wordlist::WordlistBuffers;
use erg_vanity_cpu::{MatchType, Pattern};
use ocl::enums::{KernelWorkGroupInfo, KernelWorkGroupInfoResult};
use ocl::Kernel;
use rand::RngCore;
use std::fmt;

/// Configuration for vanity search.
#[derive(Debug, Clone)]
pub struct VanityConfig {
    /// Number of work items per batch (tune for your GPU).
    pub batch_size: usize,
    /// Case-insensitive matching.
    pub ignore_case: bool,
    /// Number of BIP44 address indices to check per seed (m/44'/429'/0'/0/{0..N-1}).
    pub num_indices: u32,
    /// CPU verify match mode. The OpenCL kernel still searches prefixes.
    pub match_type: MatchType,
}

impl Default for VanityConfig {
    fn default() -> Self {
        Self {
            batch_size: 1 << 18, // 262,144 - conservative default
            ignore_case: false,
            num_indices: 1,
            match_type: MatchType::Prefix,
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
#[derive(Clone)]
pub struct VanityResult {
    /// The entropy that produced the matching address.
    pub entropy: [u8; 32],
    /// The work item ID that found this hit.
    pub work_item_id: u32,
    /// The BIP44 address index <i> in m/44'/429'/0'/0/<i>.
    pub address_index: u32,
    /// Index into the original pattern list that matched.
    pub pattern_index: u32,
    /// The Ergo address (Base58 encoded).
    pub address: String,
    /// The BIP39 mnemonic (24 words).
    pub mnemonic: String,
}

impl fmt::Debug for VanityResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VanityResult")
            .field("address", &self.address)
            .field("address_index", &self.address_index)
            .field("pattern_index", &self.pattern_index)
            .field("work_item_id", &self.work_item_id)
            .field("entropy", &"<redacted>")
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

/// Sort patterns longest-first so a short prefix cannot starve a longer one.
///
/// Returns (sorted patterns, map from sorted index → original index).
pub(crate) fn sort_patterns_longest_first(patterns: &[String]) -> (Vec<String>, Vec<u32>) {
    let mut order: Vec<usize> = (0..patterns.len()).collect();
    order.sort_by(|&a, &b| patterns[b].len().cmp(&patterns[a].len()).then(a.cmp(&b)));
    let sorted = order.iter().map(|&i| patterns[i].clone()).collect();
    let map = order.iter().map(|&i| i as u32).collect();
    (sorted, map)
}

fn local_size_for(batch: usize, recommended: usize) -> usize {
    let mut ls = recommended.min(batch).max(1);
    while !batch.is_multiple_of(ls) {
        ls /= 2;
        if ls == 0 {
            return 1;
        }
    }
    ls
}

fn kernel_work_group_limit(kernel: &Kernel, device: ocl::Device, fallback: usize) -> usize {
    match kernel.wg_info(device, KernelWorkGroupInfo::WorkGroupSize) {
        Ok(KernelWorkGroupInfoResult::WorkGroupSize(n)) if n > 0 => n,
        _ => fallback,
    }
}

/// GPU-accelerated vanity address search pipeline.
pub struct VanityPipeline {
    ctx: GpuContext,
    #[allow(dead_code)]
    program: GpuProgram,
    buffers: GpuBuffers,
    #[allow(dead_code)]
    wordlist: WordlistBuffers,
    #[allow(dead_code)]
    comb: CombTableBuffer,
    seed_kernel: Kernel,
    kernel: Kernel,
    patterns: Vec<String>,
    /// Maps GPU/sorted pattern index back to the caller's original order.
    pattern_index_map: Vec<u32>,
    #[allow(dead_code)]
    num_patterns: u32,
    ignore_case: bool,
    match_type: MatchType,
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
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::new_with_device_and_salt(patterns, cfg, 0, salt)
    }

    /// Create a new vanity search pipeline on a specific device with a shared salt.
    pub fn new_with_device_and_salt(
        patterns: &[String],
        cfg: VanityConfig,
        device_index: usize,
        salt: [u8; 32],
    ) -> Result<Self, GpuError> {
        if patterns.is_empty() {
            return Err(GpuError::Other("at least one pattern required".to_string()));
        }

        let ctx = GpuContext::with_device(device_index)?;
        let program = GpuProgram::vanity(&ctx)?;
        let queue = ctx.queue();
        let comb = CombTableBuffer::upload(queue)?;

        // Allocate buffers
        let buffers = GpuBuffers::new(&ctx, cfg.batch_size)?;
        let wordlist = WordlistBuffers::upload(queue)?;

        buffers.upload_salt(&salt)?;

        // Longest first, then lowercase for GPU if ignore_case
        let (sorted, pattern_index_map) = sort_patterns_longest_first(patterns);
        let patterns_for_gpu_storage = prepare_patterns_for_gpu(&sorted, cfg.ignore_case);
        let patterns_for_gpu: &[String] = patterns_for_gpu_storage.as_deref().unwrap_or(&sorted);
        let num_patterns = buffers.upload_patterns(patterns_for_gpu)? as u32;

        let recommended = ctx.recommended_work_group_size();
        let local = local_size_for(cfg.batch_size, recommended);

        // vanity_seed: salt, counter_start, words8, word_lens, seeds
        let mut seed_kernel = Kernel::builder()
            .program(program.program())
            .name("vanity_seed")
            .queue(queue.clone())
            .global_work_size(cfg.batch_size)
            .local_work_size(local)
            .arg(&buffers.salt)
            .arg(0u64)
            .arg(&wordlist.words8)
            .arg(&wordlist.lens)
            .arg(&buffers.seeds)
            .build()?;

        // vanity_search: salt, counter_start, seeds, patterns..., hits
        let mut kernel = Kernel::builder()
            .program(program.program())
            .name("vanity_search")
            .queue(queue.clone())
            .global_work_size(cfg.batch_size)
            .local_work_size(local)
            .arg(&buffers.salt)
            .arg(0u64)
            .arg(&buffers.seeds)
            .arg(&buffers.patterns)
            .arg(&buffers.pattern_offsets)
            .arg(&buffers.pattern_lens)
            .arg(num_patterns)
            .arg(if cfg.ignore_case { 1u32 } else { 0u32 })
            .arg(cfg.num_indices)
            .arg(&buffers.hits)
            .arg(&buffers.hit_count)
            .arg(MAX_HITS as u32)
            .arg(&comb.table)
            .build()?;

        let device = ctx.device();
        let capped = recommended
            .min(kernel_work_group_limit(&seed_kernel, device, recommended))
            .min(kernel_work_group_limit(&kernel, device, recommended));
        let local = local_size_for(cfg.batch_size, capped);
        seed_kernel.set_default_local_work_size(local.into());
        kernel.set_default_local_work_size(local.into());

        Ok(Self {
            ctx,
            program,
            buffers,
            wordlist,
            comb,
            seed_kernel,
            kernel,
            patterns: patterns.to_vec(),
            pattern_index_map,
            num_patterns,
            ignore_case: cfg.ignore_case,
            match_type: cfg.match_type,
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

        // Update counter_start (arg index 1) on both kernels
        self.seed_kernel.set_arg(1, self.counter)?;
        self.kernel.set_arg(1, self.counter)?;

        unsafe {
            self.seed_kernel.enq()?;
            self.kernel.enq()?;
        }

        // Update counter for next batch
        // Counter is per-seed: each work item uses counter_start + gid.
        // Each seed checks num_indices addresses.
        self.counter = self.counter.wrapping_add(self.cfg.batch_size as u64);
        self.addresses_checked += (self.cfg.batch_size as u64) * (self.num_indices as u64);

        self.collect_results()
    }

    /// Run one batch using an externally managed counter.
    /// Counter is per-seed: each work item uses counter_start + gid.
    pub fn run_batch_with_counter(
        &mut self,
        counter_start: u64,
    ) -> Result<Vec<VanityResult>, GpuError> {
        // Reset hit counter
        self.buffers.reset_hits()?;

        self.seed_kernel.set_arg(1, counter_start)?;
        self.kernel.set_arg(1, counter_start)?;

        unsafe {
            self.seed_kernel.enq()?;
            self.kernel.enq()?;
        }

        self.addresses_checked += (self.cfg.batch_size as u64) * (self.num_indices as u64);

        self.collect_results()
    }

    fn collect_results(&mut self) -> Result<Vec<VanityResult>, GpuError> {
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
    ///
    /// Derivation errors are dropped (not fatal) so one bad hit cannot stop
    /// a multi-GPU run. OpenCL enqueue/read errors stay fatal at the caller.
    fn verify_hit(&self, hit: &GpuHit) -> Result<Option<VanityResult>, GpuError> {
        match self.try_verify_hit(hit) {
            Ok(v) => Ok(v),
            Err(e) => {
                eprintln!("Warning: GPU hit failed CPU verify ({e}); dropping");
                Ok(None)
            }
        }
    }

    fn try_verify_hit(&self, hit: &GpuHit) -> Result<Option<VanityResult>, GpuError> {
        use erg_vanity_address::encode_p2pk_mainnet;
        use erg_vanity_bip::bip32::ExtendedPrivateKey;
        use erg_vanity_bip::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
        use erg_vanity_bip::bip44::derive_ergo_key;
        use erg_vanity_crypto::secp256k1::pubkey::PublicKey;
        use erg_vanity_crypto::secp256k1::scalar::Scalar;

        let entropy = hit.entropy_bytes();

        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| GpuError::Other(format!("mnemonic error: {}", e)))?;

        let seed = mnemonic_to_seed(&mnemonic, "");

        let master = ExtendedPrivateKey::from_seed(&seed)
            .map_err(|e| GpuError::Other(format!("bip32 error: {:?}", e)))?;

        let ergo_key = derive_ergo_key(&master, 0, 0, hit.address_index)
            .map_err(|e| GpuError::Other(format!("bip44 error: {:?}", e)))?;

        let privkey = *ergo_key.private_key();
        let scalar = Scalar::from_bytes(&privkey)
            .ok_or_else(|| GpuError::Other("invalid scalar".to_string()))?;
        let pubkey = PublicKey::from_private_key(&scalar)
            .ok_or_else(|| GpuError::Other("invalid pubkey".to_string()))?;

        let address = encode_p2pk_mainnet(pubkey.as_bytes());

        let sorted_idx = hit.pattern_index as usize;
        let original_idx = *self
            .pattern_index_map
            .get(sorted_idx)
            .ok_or_else(|| GpuError::Other(format!("pattern_index {} out of range", sorted_idx)))?;
        let pattern = self.patterns.get(original_idx as usize).ok_or_else(|| {
            GpuError::Other(format!(
                "original pattern_index {} out of range",
                original_idx
            ))
        })?;

        let matcher = Pattern::new(pattern.clone(), self.match_type).ignore_case(self.ignore_case);
        let matches = matcher.matches(&address);

        if matches {
            Ok(Some(VanityResult {
                entropy,
                work_item_id: hit.work_item_id,
                address_index: hit.address_index,
                pattern_index: original_idx,
                address,
                mnemonic,
            }))
        } else {
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
    fn local_size_divides_batch_and_respects_cap() {
        assert_eq!(local_size_for(4096, 256), 256);
        assert_eq!(local_size_for(1000, 256), 8);
        assert_eq!(local_size_for(1024, 2048), 1024);
        assert_eq!(local_size_for(1000, 1), 1);
    }

    #[test]
    fn test_sort_patterns_longest_first() {
        let patterns = vec!["9e".into(), "9ergo".into(), "9er".into()];
        let (sorted, map) = sort_patterns_longest_first(&patterns);
        assert_eq!(sorted, vec!["9ergo", "9er", "9e"]);
        assert_eq!(map, vec![1, 2, 0]);
    }

    #[test]
    fn test_vanity_result_debug_redacts_secrets() {
        let result = dummy_result(1, 0, 0);
        let debug = format!("{:?}", result);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("abandon"));
    }

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
            match_type: MatchType::Prefix,
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
            address: "9test".into(),
            mnemonic: "secret-words-here".into(),
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
