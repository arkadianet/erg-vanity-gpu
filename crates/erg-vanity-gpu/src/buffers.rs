//! GPU buffer management.
//!
//! Pre-allocated buffers for vanity address generation pipeline.

use crate::context::{GpuContext, GpuError};
use ocl::{Buffer, MemFlags};

/// Maximum number of hits that can be stored per batch.
pub const MAX_HITS: usize = 1024;

/// Size of entropy in bytes (256-bit for 24-word mnemonic).
pub const ENTROPY_SIZE: usize = 32;

/// Maximum total size of pattern data (concatenated patterns).
pub const MAX_PATTERN_DATA: usize = 1024;

/// Maximum number of patterns.
pub const MAX_PATTERNS: usize = 64;

/// A hit record from the GPU.
///
/// Padded to 64 bytes for clean GPU alignment.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C, align(16))]
pub struct GpuHit {
    /// The entropy that produced a matching address (as u32 words)
    pub entropy_words: [u32; 8], // 32 bytes
    /// The work item ID that found this hit
    pub work_item_id: u32, // 4 bytes
    /// The BIP44 address index <i> in m/44'/429'/0'/0/<i>
    pub address_index: u32, // 4 bytes
    /// Index into the pattern list that matched
    pub pattern_index: u32, // 4 bytes
    /// Padding to 64 bytes
    pub _pad: [u32; 5], // 20 bytes
}

// Required for ocl::Buffer<GpuHit>
unsafe impl ocl::OclPrm for GpuHit {}

impl GpuHit {
    /// Get entropy as bytes.
    pub fn entropy_bytes(&self) -> [u8; ENTROPY_SIZE] {
        let mut bytes = [0u8; ENTROPY_SIZE];
        for (i, word) in self.entropy_words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

/// Pre-allocated GPU buffers for the vanity pipeline.
pub struct GpuBuffers {
    /// Salt for entropy derivation (32 bytes, read-only)
    pub salt: Buffer<u8>,
    /// Concatenated patterns (no NUL terminators, max 1KB)
    pub patterns: Buffer<u8>,
    /// Offset of each pattern in the patterns buffer
    pub pattern_offsets: Buffer<u32>,
    /// Length of each pattern
    pub pattern_lens: Buffer<u32>,
    /// Hit buffer for matches (write-only from GPU)
    pub hits: Buffer<GpuHit>,
    /// Atomic hit counter (i32 to match kernel's `volatile int*`)
    pub hit_count: Buffer<i32>,
    /// Batch size this was allocated for
    batch_size: usize,
}

impl GpuBuffers {
    /// Allocate buffers for a given batch size.
    pub fn new(ctx: &GpuContext, batch_size: usize) -> Result<Self, GpuError> {
        let queue = ctx.queue();

        // Salt buffer (32 bytes)
        let salt = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(ENTROPY_SIZE)
            .build()?;

        // Patterns buffer (concatenated, max 1KB)
        let patterns = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(MAX_PATTERN_DATA)
            .build()?;

        // Pattern offsets (max 64 patterns)
        let pattern_offsets = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(MAX_PATTERNS)
            .build()?;

        // Pattern lengths (max 64 patterns)
        let pattern_lens = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(MAX_PATTERNS)
            .build()?;

        // Hit buffer
        let hits = Buffer::<GpuHit>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(MAX_HITS)
            .build()?;

        // Hit counter (i32 to match kernel's `volatile int*`)
        let hit_count = Buffer::<i32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_write())
            .len(1)
            .build()?;

        Ok(Self {
            salt,
            patterns,
            pattern_offsets,
            pattern_lens,
            hits,
            hit_count,
            batch_size,
        })
    }

    /// Upload salt to GPU.
    pub fn upload_salt(&self, salt: &[u8; ENTROPY_SIZE]) -> Result<(), GpuError> {
        self.salt.write(&salt[..]).enq()?;
        Ok(())
    }

    /// Upload multiple patterns to GPU.
    ///
    /// Validates limits and populates patterns, pattern_offsets, and pattern_lens buffers.
    /// Returns the number of patterns uploaded.
    pub fn upload_patterns(&self, patterns: &[String]) -> Result<usize, GpuError> {
        // Validate number of patterns
        if patterns.is_empty() {
            return Err(GpuError::Other("at least one pattern required".to_string()));
        }
        if patterns.len() > MAX_PATTERNS {
            return Err(GpuError::Other(format!(
                "too many patterns: {} exceeds {} limit",
                patterns.len(),
                MAX_PATTERNS
            )));
        }

        // Build concatenated pattern data
        let mut data = Vec::with_capacity(MAX_PATTERN_DATA);
        let mut offsets = Vec::with_capacity(patterns.len());
        let mut lens = Vec::with_capacity(patterns.len());

        for pattern in patterns {
            let offset = data.len();
            let len = pattern.len();

            offsets.push(offset as u32);
            lens.push(len as u32);
            data.extend_from_slice(pattern.as_bytes());
        }

        // Validate total size
        if data.len() > MAX_PATTERN_DATA {
            return Err(GpuError::Other(format!(
                "pattern data too large: {} bytes exceeds {} limit",
                data.len(),
                MAX_PATTERN_DATA
            )));
        }

        // Pad data to buffer size
        data.resize(MAX_PATTERN_DATA, 0);
        self.patterns.write(&data).enq()?;

        // Pad and upload offsets
        let mut offset_data = vec![0u32; MAX_PATTERNS];
        offset_data[..offsets.len()].copy_from_slice(&offsets);
        self.pattern_offsets.write(&offset_data).enq()?;

        // Pad and upload lengths
        let mut len_data = vec![0u32; MAX_PATTERNS];
        len_data[..lens.len()].copy_from_slice(&lens);
        self.pattern_lens.write(&len_data).enq()?;

        Ok(patterns.len())
    }

    /// Reset hit counter to 0.
    pub fn reset_hits(&self) -> Result<(), GpuError> {
        self.hit_count.write(&[0i32][..]).enq()?;
        Ok(())
    }

    /// Read hit count from GPU.
    pub fn read_hit_count(&self) -> Result<u32, GpuError> {
        let mut count = [0i32; 1];
        self.hit_count.read(&mut count[..]).enq()?;
        Ok(count[0] as u32)
    }

    /// Read hits from GPU.
    pub fn read_hits(&self, count: usize) -> Result<Vec<GpuHit>, GpuError> {
        let count = count.min(MAX_HITS);
        let mut hits = vec![GpuHit::default(); count];
        if count > 0 {
            self.hits.read(&mut hits).enq()?;
        }
        Ok(hits)
    }

    /// Get the batch size these buffers were allocated for.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_hit_size() {
        // Ensure the struct is properly sized for GPU (64 bytes, aligned)
        assert_eq!(std::mem::size_of::<GpuHit>(), 64);
    }

    #[test]
    fn test_entropy_bytes_roundtrip() {
        let hit = GpuHit {
            entropy_words: [
                0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718, 0x191a1b1c,
                0x1d1e1f20,
            ],
            ..Default::default()
        };
        let bytes = hit.entropy_bytes();
        assert_eq!(bytes[0], 0x04); // LE: low byte first
        assert_eq!(bytes[3], 0x01);
    }

    #[test]
    fn test_gpu_hit_new_fields() {
        let hit = GpuHit {
            address_index: 5,
            pattern_index: 2,
            ..Default::default()
        };
        assert_eq!(hit.address_index, 5);
        assert_eq!(hit.pattern_index, 2);
    }
}
