//! Host-side fixed-base comb table for k·G.
//!
//! Layout: `COMB_WINDOWS` windows × `COMB_ENTRIES` entries × 16 little-endian
//! u32 limbs (affine X||Y). Window 0 holds the top `COMB_TOP_BITS` bits of
//! `sc_to_bytes`; the rest hold `COMB_BITS` each. Entry 0 is unused (infinity).
//!
//! `COMB_BITS` must match `gen_g_table.rs` and `secp256k1_point.cl`;
//! `comb_table_matches_kernel_layout` checks the derived sizes against the
//! committed table.
//!
//! Regenerate with: cargo run -p erg-vanity-gpu --bin gen_g_table

use crate::context::GpuError;
use ocl::{flags::MemFlags, Buffer, Queue};

pub const COMB_BITS: usize = 11;
pub const COMB_WINDOWS: usize = 256_usize.div_ceil(COMB_BITS);
pub const COMB_ENTRIES: usize = 1 << COMB_BITS;
pub const COMB_TOP_BITS: usize = 256 - (COMB_WINDOWS - 1) * COMB_BITS;
pub const COMB_XY_LIMBS: usize = 16;

/// The kernel reads window 0 as `k_bytes[0] >> (8 - COMB_TOP_BITS)`, which only
/// works while window 0 fits in the scalar's first byte. True for COMB_BITS >= 8.
const _: () = assert!(COMB_TOP_BITS >= 1 && COMB_TOP_BITS <= 8);
pub const COMB_TABLE_U32S: usize = COMB_WINDOWS * COMB_ENTRIES * COMB_XY_LIMBS;
pub const COMB_TABLE_BYTES: &[u8] = include_bytes!("../kernels/comb_table.bin");

/// Uploaded `__global` comb table (~1.7 MB).
pub struct CombTableBuffer {
    pub table: Buffer<u32>,
}

pub fn load_comb_table() -> Vec<u32> {
    assert_eq!(
        COMB_TABLE_BYTES.len(),
        COMB_TABLE_U32S * 4,
        "comb_table.bin size"
    );
    COMB_TABLE_BYTES
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect()
}

impl CombTableBuffer {
    pub fn upload(queue: &Queue) -> Result<Self, GpuError> {
        let words = load_comb_table();
        let table = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR)
            .len(words.len())
            .copy_host_slice(&words)
            .build()?;
        Ok(Self { table })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_GX: [u32; 8] = [
        0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC,
        0x79BE667E,
    ];
    const EXPECTED_GY: [u32; 8] = [
        0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465,
        0x483ADA77,
    ];

    #[test]
    fn comb_table_lsb_one_is_g() {
        let words = load_comb_table();
        // The last window holds the low bits, so its entry 1 is G itself.
        let off = ((COMB_WINDOWS - 1) * COMB_ENTRIES + 1) * COMB_XY_LIMBS;
        assert_eq!(&words[off..off + 8], &EXPECTED_GX);
        assert_eq!(&words[off + 8..off + 16], &EXPECTED_GY);
    }

    /// The committed table is a binary blob, so its size is the only thing
    /// tying it to COMB_BITS. If they disagree the kernel would read garbage
    /// at some window offset rather than fail to build.
    #[test]
    fn comb_table_matches_kernel_layout() {
        assert_eq!(COMB_TABLE_BYTES.len(), COMB_TABLE_U32S * 4);
    }
}
