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
}

impl Default for VanityConfig {
    fn default() -> Self {
        Self {
            batch_size: 1 << 18, // 262,144 - conservative default
        }
    }
}

/// Result of a successful vanity search.
#[derive(Debug, Clone)]
pub struct VanityResult {
    /// The entropy that produced the matching address.
    pub entropy: [u8; 32],
    /// The work item ID that found this hit.
    pub work_item_id: u32,
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
    wordlist: WordlistBuffers,
    kernel: Kernel,
    pattern: String,
    salt: [u8; 32],
    counter: u64,
    cfg: VanityConfig,
    addresses_checked: u64,
}

impl VanityPipeline {
    /// Create a new vanity search pipeline.
    pub fn new(pattern: &str, cfg: VanityConfig) -> Result<Self, GpuError> {
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

        // Upload pattern
        buffers.upload_pattern(pattern.as_bytes())?;

        // Build kernel with all arguments matching vanity_search signature:
        // salt, counter_start, words8, word_lens, pattern, pattern_len, hits, hit_count, max_hits
        let kernel = Kernel::builder()
            .program(program.program())
            .name("vanity_search")
            .queue(queue.clone())
            .global_work_size(cfg.batch_size)
            .arg(&buffers.salt)              // arg 0: salt
            .arg(0u64)                       // arg 1: counter_start (will be updated)
            .arg(&wordlist.words8)           // arg 2: words8
            .arg(&wordlist.lens)             // arg 3: word_lens
            .arg(&buffers.pattern)           // arg 4: pattern
            .arg(pattern.len() as u32)       // arg 5: pattern_len
            .arg(&buffers.hits)              // arg 6: hits
            .arg(&buffers.hit_count)         // arg 7: hit_count
            .arg(MAX_HITS as u32)            // arg 8: max_hits
            .build()?;

        Ok(Self {
            ctx,
            program,
            buffers,
            wordlist,
            kernel,
            pattern: pattern.to_string(),
            salt,
            counter: 0,
            cfg,
            addresses_checked: 0,
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

    /// Run one batch of the search.
    /// Returns Some(result) if a match was found, None otherwise.
    pub fn run_batch(&mut self) -> Result<Option<VanityResult>, GpuError> {
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
        self.counter = self.counter.wrapping_add(self.cfg.batch_size as u64);
        self.addresses_checked += self.cfg.batch_size as u64;

        // Check for hits (clamp defensively even though overflow "can't happen")
        let mut hit_count = self.buffers.read_hit_count()? as usize;
        hit_count = hit_count.min(MAX_HITS);
        if hit_count == 0 {
            return Ok(None);
        }

        let hits = self.buffers.read_hits(hit_count)?;

        // Verify each hit on CPU
        for hit in hits {
            if let Some(result) = self.verify_hit(&hit)? {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Search until a match is found (blocking).
    pub fn search_blocking(&mut self) -> Result<VanityResult, GpuError> {
        loop {
            if let Some(result) = self.run_batch()? {
                return Ok(result);
            }
        }
    }

    /// Verify a hit on CPU and return the result if valid.
    fn verify_hit(&self, hit: &GpuHit) -> Result<Option<VanityResult>, GpuError> {
        use erg_vanity_address::encode_p2pk_mainnet;
        use erg_vanity_bip::bip32::ExtendedPrivateKey;
        use erg_vanity_bip::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
        use erg_vanity_bip::bip44::derive_ergo_first_key;
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

        // Derive Ergo key at m/44'/429'/0'/0/0
        let ergo_key = derive_ergo_first_key(&master)
            .map_err(|e| GpuError::Other(format!("bip44 error: {:?}", e)))?;

        // Get public key
        let privkey = *ergo_key.private_key();
        let scalar = Scalar::from_bytes(&privkey)
            .ok_or_else(|| GpuError::Other("invalid scalar".to_string()))?;
        let pubkey = PublicKey::from_private_key(&scalar)
            .ok_or_else(|| GpuError::Other("invalid pubkey".to_string()))?;

        // Encode address
        let address = encode_p2pk_mainnet(pubkey.as_bytes());

        // Verify prefix match
        if address.starts_with(&self.pattern) {
            Ok(Some(VanityResult {
                entropy,
                work_item_id: hit.work_item_id,
                address,
                mnemonic,
            }))
        } else {
            // False positive (shouldn't happen with correct GPU code)
            eprintln!(
                "Warning: GPU hit did not verify on CPU (addr={}, pattern={})",
                address, self.pattern
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
        // Just test that we can create a pipeline
        let cfg = VanityConfig {
            batch_size: 1024,
        };

        match VanityPipeline::new("9", cfg) {
            Ok(pipe) => {
                println!("Pipeline created: {}", pipe.device_info());
            }
            Err(e) => {
                println!("No GPU available: {}", e);
            }
        }
    }
}
