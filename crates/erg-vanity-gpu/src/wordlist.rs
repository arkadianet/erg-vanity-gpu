//! BIP39 wordlist data for GPU upload.
//!
//! The wordlist is stored as fixed-width 8-byte entries (zero-padded)
//! plus a separate length array. This avoids embedding huge constant
//! arrays in OpenCL source which can cause compiler issues.

use erg_vanity_core::WORDLIST;
use ocl::{flags::MemFlags, Buffer, Queue, Result as OclResult};

/// Fixed width for each word entry (BIP39 English max is 8 chars).
pub const WORD_WIDTH: usize = 8;

/// Number of words in BIP39 English wordlist.
pub const WORD_COUNT: usize = 2048;

/// Total size of packed word data.
pub const WORDS_DATA_SIZE: usize = WORD_COUNT * WORD_WIDTH;

/// Total size of word lengths array.
pub const WORD_LENS_SIZE: usize = WORD_COUNT;

/// Generate packed wordlist data (2048 * 8 bytes).
/// Each word is zero-padded to 8 bytes.
pub fn generate_words_data() -> Vec<u8> {
    let mut data = vec![0u8; WORDS_DATA_SIZE];

    debug_assert_eq!(WORDLIST.len(), WORD_COUNT);

    for (i, word) in WORDLIST.iter().enumerate() {
        let bytes = word.as_bytes();
        assert!(
            bytes.len() <= WORD_WIDTH,
            "BIP39 word too long at idx {}: {} (len={})",
            i,
            word,
            bytes.len()
        );

        let offset = i * WORD_WIDTH;
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    data
}

/// Generate word lengths array (2048 bytes).
pub fn generate_word_lens() -> Vec<u8> {
    debug_assert_eq!(WORDLIST.len(), WORD_COUNT);
    WORDLIST.iter().map(|w| w.len() as u8).collect()
}

/// GPU buffers for the BIP39 wordlist.
pub struct WordlistBuffers {
    pub words8: Buffer<u8>,
    pub lens: Buffer<u8>,
}

impl WordlistBuffers {
    /// Upload wordlist data to GPU.
    pub fn upload(queue: &Queue) -> OclResult<Self> {
        let words = generate_words_data();
        let lens = generate_word_lens();

        let words8 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR)
            .len(words.len())
            .copy_host_slice(&words)
            .build()?;

        let lens_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::READ_ONLY | MemFlags::COPY_HOST_PTR)
            .len(lens.len())
            .copy_host_slice(&lens)
            .build()?;

        Ok(Self {
            words8,
            lens: lens_buf,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_data_size() {
        let data = generate_words_data();
        assert_eq!(data.len(), WORDS_DATA_SIZE);
    }

    #[test]
    fn test_word_lens_size() {
        let lens = generate_word_lens();
        assert_eq!(lens.len(), WORD_LENS_SIZE);
    }

    #[test]
    fn test_first_word() {
        let data = generate_words_data();
        let lens = generate_word_lens();

        // First word is "abandon" (7 chars)
        assert_eq!(lens[0], 7);
        assert_eq!(&data[0..7], b"abandon");
        assert_eq!(data[7], 0u8); // zero-padded
    }

    #[test]
    fn test_word_lookup() {
        let data = generate_words_data();
        let lens = generate_word_lens();

        // Word 2047 (last) is "zoo" (3 chars)
        let idx = 2047;
        let offset = idx * WORD_WIDTH;
        let len = lens[idx] as usize;
        assert_eq!(len, 3);
        assert_eq!(&data[offset..offset + len], b"zoo");
    }

    #[test]
    fn test_all_words_valid_length() {
        let lens = generate_word_lens();
        for (i, &len) in lens.iter().enumerate() {
            assert!(
                len >= 3 && len <= 8,
                "Word {} has invalid length {}",
                i,
                len
            );
        }
    }

    #[test]
    fn test_padding_is_zero() {
        let data = generate_words_data();
        let lens = generate_word_lens();

        for i in 0..WORD_COUNT {
            let offset = i * WORD_WIDTH;
            let len = lens[i] as usize;
            for b in &data[offset + len..offset + WORD_WIDTH] {
                assert_eq!(*b, 0u8, "non-zero padding at word {}", i);
            }
        }
    }
}
