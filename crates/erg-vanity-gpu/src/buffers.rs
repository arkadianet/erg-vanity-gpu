//! GPU buffer management.
//!
//! Pre-allocated buffers for vanity address generation pipeline.

use crate::context::{GpuContext, GpuError};
use ocl::{Buffer, MemFlags};

/// Maximum number of hits that can be stored per batch.
pub const MAX_HITS: usize = 1024;

/// Size of entropy in bytes (256-bit for 24-word mnemonic).
pub const ENTROPY_SIZE: usize = 32;

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
    /// Padding to 64 bytes
    pub _pad: [u32; 7], // 28 bytes
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
    /// Starting counter value (u64, read-only)
    pub counter_start: Buffer<u64>,
    /// Pattern to match (variable length, read-only)
    pub pattern: Buffer<u8>,
    /// Pattern length
    pub pattern_len: Buffer<u32>,
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

        // Counter start (single u64)
        let counter_start = Buffer::<u64>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(1)
            .build()?;

        // Pattern buffer (max 64 chars should be plenty)
        let pattern = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(64)
            .build()?;

        // Pattern length
        let pattern_len = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(1)
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
            counter_start,
            pattern,
            pattern_len,
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

    /// Upload counter start to GPU.
    pub fn upload_counter(&self, start: u64) -> Result<(), GpuError> {
        self.counter_start.write(&[start][..]).enq()?;
        Ok(())
    }

    /// Upload pattern to GPU.
    pub fn upload_pattern(&self, pattern: &[u8]) -> Result<(), GpuError> {
        let len = pattern.len().min(64) as u32;
        let mut padded = [0u8; 64];
        padded[..pattern.len().min(64)].copy_from_slice(&pattern[..pattern.len().min(64)]);
        self.pattern.write(&padded[..]).enq()?;
        self.pattern_len.write(&[len][..]).enq()?;
        Ok(())
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
        let mut hit = GpuHit::default();
        hit.entropy_words = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                            0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
        let bytes = hit.entropy_bytes();
        assert_eq!(bytes[0], 0x04); // LE: low byte first
        assert_eq!(bytes[3], 0x01);
    }
}
