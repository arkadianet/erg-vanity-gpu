//! OpenCL kernel compilation and execution.

use crate::context::{GpuContext, GpuError};
use ocl::Program;

/// Kernel source files embedded at compile time.
pub mod sources {
    // Production kernels
    pub const SHA256: &str = include_str!("../kernels/sha256.cl");
    pub const SHA512: &str = include_str!("../kernels/sha512.cl");
    pub const HMAC_SHA512: &str = include_str!("../kernels/hmac_sha512.cl");
    pub const PBKDF2: &str = include_str!("../kernels/pbkdf2.cl");
    pub const SECP256K1_FE: &str = include_str!("../kernels/secp256k1_fe.cl");
    pub const SECP256K1_SCALAR: &str = include_str!("../kernels/secp256k1_scalar.cl");
    pub const SECP256K1_POINT: &str = include_str!("../kernels/secp256k1_point.cl");
    pub const BLAKE2B: &str = include_str!("../kernels/blake2b.cl");
    pub const BASE58: &str = include_str!("../kernels/base58.cl");
    pub const BIP39: &str = include_str!("../kernels/bip39.cl");
    pub const BIP32: &str = include_str!("../kernels/bip32.cl");
    pub const VANITY: &str = include_str!("../kernels/vanity.cl");

    // Test kernels (unit tests OR integration tests with --features test-kernels)
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const SHA256_TEST: &str = include_str!("../kernels/sha256_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const SHA512_TEST: &str = include_str!("../kernels/sha512_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const HMAC_SHA512_TEST: &str = include_str!("../kernels/hmac_sha512_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const PBKDF2_TEST: &str = include_str!("../kernels/pbkdf2_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const SECP256K1_FE_TEST: &str = include_str!("../kernels/secp256k1_fe_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const SECP256K1_SCALAR_TEST: &str =
        include_str!("../kernels/secp256k1_scalar_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const SECP256K1_POINT_TEST: &str =
        include_str!("../kernels/secp256k1_point_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const BLAKE2B_TEST: &str = include_str!("../kernels/blake2b_test.cl");
    #[cfg(any(test, feature = "test-kernels"))]
    pub(crate) const BASE58_TEST: &str = include_str!("../kernels/base58_test.cl");
}

/// Compiled OpenCL program with kernels.
pub struct GpuProgram {
    program: Program,
}

impl GpuProgram {
    /// Compile a program from source.
    pub fn from_source(ctx: &GpuContext, source: &str) -> Result<Self, GpuError> {
        let program = Program::builder()
            .src(source)
            .devices(ctx.device())
            .cmplr_opt("-cl-std=CL1.2")
            .build(ctx.context())?;

        Ok(Self { program })
    }

    /// Compile the SHA-256 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn sha256_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!("{}\n{}", sources::SHA256, sources::SHA256_TEST);
        Self::from_source(ctx, &combined)
    }

    /// Compile the SHA-512 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn sha512_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!("{}\n{}", sources::SHA512, sources::SHA512_TEST);
        Self::from_source(ctx, &combined)
    }

    /// Compile the HMAC-SHA512 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn hmac_sha512_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!(
            "{}\n{}\n{}",
            sources::SHA512,
            sources::HMAC_SHA512,
            sources::HMAC_SHA512_TEST
        );
        Self::from_source(ctx, &combined)
    }

    /// Compile the PBKDF2 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn pbkdf2_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!(
            "{}\n{}\n{}\n{}",
            sources::SHA512,
            sources::HMAC_SHA512,
            sources::PBKDF2,
            sources::PBKDF2_TEST
        );
        Self::from_source(ctx, &combined)
    }

    /// Compile the secp256k1 field test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn secp256k1_fe_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!("{}\n{}", sources::SECP256K1_FE, sources::SECP256K1_FE_TEST);
        Self::from_source(ctx, &combined)
    }

    /// Compile the secp256k1 scalar test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn secp256k1_scalar_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!(
            "{}\n{}",
            sources::SECP256K1_SCALAR,
            sources::SECP256K1_SCALAR_TEST
        );
        Self::from_source(ctx, &combined)
    }

    /// Compile the secp256k1 point test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn secp256k1_point_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!(
            "{}\n{}\n{}\n{}",
            sources::SECP256K1_FE,
            sources::SECP256K1_SCALAR,
            sources::SECP256K1_POINT,
            sources::SECP256K1_POINT_TEST
        );
        Self::from_source(ctx, &combined)
    }

    /// Compile the Blake2b-256 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn blake2b_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!("{}\n{}", sources::BLAKE2B, sources::BLAKE2B_TEST);
        Self::from_source(ctx, &combined)
    }

    /// Compile the Base58 test program.
    #[cfg(any(test, feature = "test-kernels"))]
    pub fn base58_test(ctx: &GpuContext) -> Result<Self, GpuError> {
        let combined = format!("{}\n{}", sources::BASE58, sources::BASE58_TEST);
        Self::from_source(ctx, &combined)
    }

    /// Compile the full vanity address search program.
    ///
    /// Concatenates all required kernels in dependency order:
    /// sha256 → sha512 → hmac_sha512 → pbkdf2 → secp256k1 → blake2b → base58 → bip39 → bip32 → vanity
    pub fn vanity(ctx: &GpuContext) -> Result<Self, GpuError> {
        // Pre-allocate to avoid reallocations on multi-hundred-KB source blob.
        let mut combined = String::with_capacity(
            sources::SHA256.len()
                + sources::SHA512.len()
                + sources::HMAC_SHA512.len()
                + sources::PBKDF2.len()
                + sources::SECP256K1_FE.len()
                + sources::SECP256K1_SCALAR.len()
                + sources::SECP256K1_POINT.len()
                + sources::BLAKE2B.len()
                + sources::BASE58.len()
                + sources::BIP39.len()
                + sources::BIP32.len()
                + sources::VANITY.len()
                + 1024, // comment separators + newlines
        );

        // Separators make compiler errors readable.

        combined.push_str("// === sha256.cl ===\n");
        combined.push_str(sources::SHA256);
        combined.push_str("\n\n// === sha512.cl ===\n");
        combined.push_str(sources::SHA512);
        combined.push_str("\n\n// === hmac_sha512.cl ===\n");
        combined.push_str(sources::HMAC_SHA512);
        combined.push_str("\n\n// === pbkdf2.cl ===\n");
        combined.push_str(sources::PBKDF2);

        combined.push_str("\n\n// === secp256k1_fe.cl ===\n");
        combined.push_str(sources::SECP256K1_FE);
        combined.push_str("\n\n// === secp256k1_scalar.cl ===\n");
        combined.push_str(sources::SECP256K1_SCALAR);
        combined.push_str("\n\n// === secp256k1_point.cl ===\n");
        combined.push_str(sources::SECP256K1_POINT);

        combined.push_str("\n\n// === blake2b.cl ===\n");
        combined.push_str(sources::BLAKE2B);
        combined.push_str("\n\n// === base58.cl ===\n");
        combined.push_str(sources::BASE58);

        combined.push_str("\n\n// === bip39.cl ===\n");
        combined.push_str(sources::BIP39);
        combined.push_str("\n\n// === bip32.cl ===\n");
        combined.push_str(sources::BIP32);

        combined.push_str("\n\n// === vanity.cl ===\n");
        combined.push_str(sources::VANITY);
        combined.push('\n');

        Self::from_source(ctx, &combined)
    }

    /// Get the underlying program.
    pub fn program(&self) -> &Program {
        &self.program
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocl::{Buffer, MemFlags};
    use std::sync::{Mutex, OnceLock};

    // Serialize GPU tests to avoid driver/context conflicts
    static GPU_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_gpu() -> std::sync::MutexGuard<'static, ()> {
        GPU_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    // Run test with larger stack (OpenCL compiler can blow past default stack)
    const BIG_TEST_STACK: usize = 16 * 1024 * 1024;

    #[inline]
    fn run_with_big_stack<F>(stack_bytes: usize, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = std::thread::Builder::new()
            .name("gpu-kernel-test".into())
            .stack_size(stack_bytes)
            .spawn(f)
            .expect("failed to spawn test thread with larger stack");

        if let Err(e) = handle.join() {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn test_sha512_abc() {
        let _guard = lock_gpu();
        // SHA-512("abc") - single block test
        const EXPECTED: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        let program = GpuProgram::sha512_test(&ctx).expect("Failed to compile SHA-512 kernel");
        let queue = ctx.queue();

        let input = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        // Upload "abc"
        let mut input_data = [0u8; 128];
        input_data[0] = b'a';
        input_data[1] = b'b';
        input_data[2] = b'c';
        input.write(&input_data[..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("sha512_test_single")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&input)
            .arg(3u32)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        println!("SHA-512(\"abc\") first 16 bytes: {:02x?}", &result[..16]);
        assert_eq!(result, EXPECTED, "SHA-512 single-block mismatch");
        println!("SHA-512 single-block test passed!");
    }

    #[test]
    fn test_sha512_two_blocks() {
        let _guard = lock_gpu();
        // SHA-512(b"a" * 200) - two block test (128 + 72 bytes)
        const EXPECTED: [u8; 64] = [
            0x4b, 0x11, 0x45, 0x9c, 0x33, 0xf5, 0x2a, 0x22, 0xee, 0x82, 0x36, 0x78, 0x27, 0x14,
            0xc1, 0x50, 0xa3, 0xb2, 0xc6, 0x09, 0x94, 0xe9, 0xac, 0xee, 0x17, 0xfe, 0x68, 0x94,
            0x7a, 0x3e, 0x67, 0x89, 0xf3, 0x1e, 0x76, 0x68, 0x39, 0x45, 0x92, 0xda, 0x7b, 0xef,
            0x82, 0x7c, 0xdd, 0xca, 0x88, 0xc4, 0xe6, 0xf8, 0x6e, 0x4d, 0xf7, 0xed, 0x1a, 0xe6,
            0xcb, 0xa7, 0x1f, 0x3e, 0x98, 0xfa, 0xee, 0x9f,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        let program = GpuProgram::sha512_test(&ctx).expect("Failed to compile SHA-512 kernel");
        let queue = ctx.queue();

        let block1 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let block2 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        // Upload 200 'a's: first 128 in block1, remaining 72 in block2
        let block1_data = [b'a'; 128];
        let mut block2_data = [0u8; 128];
        block2_data[..72].fill(b'a');
        block1.write(&block1_data[..]).enq().unwrap();
        block2.write(&block2_data[..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("sha512_test_two_blocks")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&block1)
            .arg(&block2)
            .arg(72u32)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        println!("SHA-512(\"a\"*200) first 16 bytes: {:02x?}", &result[..16]);
        assert_eq!(result, EXPECTED, "SHA-512 two-block mismatch");
        println!("SHA-512 two-block test passed!");
    }

    #[test]
    fn test_sha512_two_blocks_precondition() {
        let _guard = lock_gpu();
        // Verify that block2_len > 111 returns all zeros (precondition violation)
        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        let program = GpuProgram::sha512_test(&ctx).expect("Failed to compile SHA-512 kernel");
        let queue = ctx.queue();

        let block1 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let block2 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        // Fill with non-zero data
        block1.write(&[0xaa; 128][..]).enq().unwrap();
        block2.write(&[0xbb; 128][..]).enq().unwrap();

        // Initialize output with non-zero to verify it gets zeroed
        output.write(&[0xff; 64][..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("sha512_test_two_blocks")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&block1)
            .arg(&block2)
            .arg(112u32) // Violates precondition (> 111)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        assert_eq!(
            result, [0u8; 64],
            "Precondition violation should return zeros"
        );
        println!("SHA-512 precondition test passed!");
    }

    #[test]
    fn test_pbkdf2_bip39() {
        let _guard = lock_gpu();
        // BIP39 test vector: mnemonic "abandon" x 11 + "about", no passphrase
        // Salt = "mnemonic" (no passphrase)
        const EXPECTED: [u8; 64] = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        let program = GpuProgram::pbkdf2_test(&ctx).expect("Failed to compile PBKDF2 kernel");
        let queue = ctx.queue();

        let password_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(512)
            .build()
            .unwrap();

        let salt_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(256)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        // BIP39 test: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let salt = b"mnemonic";

        let mut password_data = [0u8; 512];
        password_data[..mnemonic.len()].copy_from_slice(mnemonic);
        password_buf.write(&password_data[..]).enq().unwrap();

        let mut salt_data = [0u8; 256];
        salt_data[..salt.len()].copy_from_slice(salt);
        salt_buf.write(&salt_data[..]).enq().unwrap();

        // Use pbkdf2_bip39_test since mnemonic is < 128 bytes but we want to test the BIP39 path
        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("pbkdf2_bip39_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&password_buf)
            .arg(mnemonic.len() as u32)
            .arg(&salt_buf)
            .arg(salt.len() as u32)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        println!("PBKDF2 BIP39 seed first 16 bytes: {:02x?}", &result[..16]);
        assert_eq!(result, EXPECTED, "PBKDF2 BIP39 mismatch");
        println!("PBKDF2 BIP39 test passed!");
    }

    #[test]
    fn test_hmac_sha512_rfc4231() {
        let _guard = lock_gpu();
        // RFC 4231 Test Case 1: key = 0x0b repeated 20 times, data = "Hi There"
        const EXPECTED: [u8; 64] = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        let program =
            GpuProgram::hmac_sha512_test(&ctx).expect("Failed to compile HMAC-SHA512 kernel");
        let queue = ctx.queue();

        let key_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let data_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(256)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";

        let mut key_data = [0u8; 128];
        key_data[..20].copy_from_slice(&key);
        key_buf.write(&key_data[..]).enq().unwrap();

        let mut data_padded = [0u8; 256];
        data_padded[..data.len()].copy_from_slice(data);
        data_buf.write(&data_padded[..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("hmac_sha512_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&key_buf)
            .arg(20u32)
            .arg(&data_buf)
            .arg(data.len() as u32)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        println!(
            "HMAC-SHA512 RFC4231 Case 1 first 16 bytes: {:02x?}",
            &result[..16]
        );
        assert_eq!(result, EXPECTED, "HMAC-SHA512 mismatch");
        println!("HMAC-SHA512 test passed!");
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case2() {
        let _guard = lock_gpu();
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        const EXPECTED: [u8; 64] = [
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
            0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
            0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03,
            0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
            0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        let program =
            GpuProgram::hmac_sha512_test(&ctx).expect("Failed to compile HMAC-SHA512 kernel");
        let queue = ctx.queue();

        let key_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(128)
            .build()
            .unwrap();

        let data_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(256)
            .build()
            .unwrap();

        let output = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(64)
            .build()
            .unwrap();

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let mut key_data = [0u8; 128];
        key_data[..key.len()].copy_from_slice(key);
        key_buf.write(&key_data[..]).enq().unwrap();

        let mut data_padded = [0u8; 256];
        data_padded[..data.len()].copy_from_slice(data);
        data_buf.write(&data_padded[..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("hmac_sha512_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&key_buf)
            .arg(key.len() as u32)
            .arg(&data_buf)
            .arg(data.len() as u32)
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u8; 64];
        output.read(&mut result[..]).enq().unwrap();

        println!(
            "HMAC-SHA512 RFC4231 Case 2 first 16 bytes: {:02x?}",
            &result[..16]
        );
        assert_eq!(result, EXPECTED, "HMAC-SHA512 Case 2 mismatch");
        println!("HMAC-SHA512 Case 2 test passed!");
    }

    #[test]
    fn test_sha256_abc() {
        let _guard = lock_gpu();
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // As u32 words (big-endian word order):
        const EXPECTED: [u32; 8] = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        // Compile SHA-256 test program
        let program = GpuProgram::sha256_test(&ctx).expect("Failed to compile SHA-256 kernel");

        // Create buffers
        let queue = ctx.queue();

        let input = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_only())
            .len(64)
            .build()
            .unwrap();

        let output = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().write_only())
            .len(8)
            .build()
            .unwrap();

        // Upload "abc"
        let mut input_data = [0u8; 64];
        input_data[0] = b'a';
        input_data[1] = b'b';
        input_data[2] = b'c';
        input.write(&input_data[..]).enq().unwrap();

        // Create and run kernel
        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("sha256_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&input)
            .arg(3u32) // input_len
            .arg(&output)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        // Read result
        let mut result = [0u32; 8];
        output.read(&mut result[..]).enq().unwrap();

        println!("SHA-256(\"abc\") GPU result:");
        for (i, word) in result.iter().enumerate() {
            println!("  [{}] 0x{:08x} (expected 0x{:08x})", i, word, EXPECTED[i]);
        }

        assert_eq!(result, EXPECTED, "SHA-256 mismatch");
        println!("SHA-256 test passed!");
    }

    #[test]
    fn test_secp256k1_fe_self_test() {
        let _guard = lock_gpu();

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        let program =
            GpuProgram::secp256k1_fe_test(&ctx).expect("Failed to compile secp256k1_fe kernel");
        let queue = ctx.queue();

        // Single u32 for result bitmap
        let result_buf = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_write())
            .len(1)
            .build()
            .unwrap();

        // Initialize with non-zero to ensure it gets written
        result_buf.write(&[0xFFFF_FFFFu32][..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("fe_self_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&result_buf)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u32; 1];
        result_buf.read(&mut result[..]).enq().unwrap();
        queue.finish().unwrap();

        let failures = result[0];
        println!("secp256k1 FE self-test result: 0x{:08x}", failures);

        if failures != 0 {
            // Decode which tests failed
            for bit in 0..10 {
                if failures & (1 << bit) != 0 {
                    println!("  FAIL: test {} failed", bit + 1);
                }
            }
            if failures & (1 << 31) != 0 {
                println!("  FAIL: overflow detected during checked multiply");
            }
            panic!(
                "secp256k1 field self-test failed with bitmap 0x{:08x}",
                failures
            );
        }

        println!("secp256k1 FE self-test passed (all 10 tests)!");
    }

    #[test]
    fn test_secp256k1_scalar_self_test() {
        let _guard = lock_gpu();

        let Some(ctx) = crate::context::try_ctx() else {
            return;
        };

        println!("Using GPU: {}", ctx.info());

        let program = GpuProgram::secp256k1_scalar_test(&ctx)
            .expect("Failed to compile secp256k1_scalar kernel");
        let queue = ctx.queue();

        let result_buf = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(MemFlags::new().read_write())
            .len(1)
            .build()
            .unwrap();

        result_buf.write(&[0xFFFF_FFFFu32][..]).enq().unwrap();

        let kernel = ocl::Kernel::builder()
            .program(program.program())
            .name("sc_self_test")
            .queue(queue.clone())
            .global_work_size(1)
            .arg(&result_buf)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }
        queue.finish().unwrap();

        let mut result = [0u32; 1];
        result_buf.read(&mut result[..]).enq().unwrap();
        queue.finish().unwrap();

        let failures = result[0];
        println!("secp256k1 scalar self-test result: 0x{:08x}", failures);

        if failures != 0 {
            const TEST_NAMES: [&str; 14] = [
                "1+0==1",
                "(n-1)+1==0",
                "0-1==n-1",
                "-1==n-1",
                "a+(-a)==0",
                "(a+b)-b==a",
                "(a-b)+b==a",
                "-(-a)==a",
                "2*3==6",
                "a*b==b*a",
                "1*a==a",
                "0*a==0",
                "(n-1)+(n-1)==n-2 (overflow)",
                "(n-1)*(n-1)==1",
            ];
            for (bit, name) in TEST_NAMES.iter().enumerate() {
                if failures & (1 << bit) != 0 {
                    println!("  FAIL: test {}: {}", bit + 1, name);
                }
            }
            panic!(
                "secp256k1 scalar self-test failed with bitmap 0x{:08x}",
                failures
            );
        }

        println!("secp256k1 scalar self-test passed (all 14 tests)!");
    }

    #[test]
    fn test_secp256k1_point_self_test() {
        run_with_big_stack(BIG_TEST_STACK, || {
            let _guard = lock_gpu();

            let Some(ctx) = crate::context::try_ctx() else {
                return;
            };

            println!("Using GPU: {}", ctx.info());

            let program = GpuProgram::secp256k1_point_test(&ctx)
                .expect("Failed to compile secp256k1_point kernel");
            let queue = ctx.queue();

            let result_buf = Buffer::<u32>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().read_write())
                .len(1)
                .build()
                .unwrap();

            result_buf.write(&[0xFFFF_FFFFu32][..]).enq().unwrap();

            let kernel = ocl::Kernel::builder()
                .program(program.program())
                .name("pt_self_test")
                .queue(queue.clone())
                .global_work_size(1)
                .arg(&result_buf)
                .build()
                .unwrap();

            unsafe {
                kernel.enq().unwrap();
            }
            queue.finish().unwrap();

            let mut result = [0u32; 1];
            result_buf.read(&mut result[..]).enq().unwrap();
            queue.finish().unwrap();

            let failures = result[0];
            println!("secp256k1 point self-test result: 0x{:08x}", failures);

            if failures != 0 {
                const TEST_NAMES: [&str; 15] = [
                    "G is not infinity",
                    "infinity is infinity",
                    "G + infinity = G",
                    "infinity + G = G",
                    "G + G = double(G)",
                    "2G matches known x",
                    "1 * G = G",
                    "2 * G = double(G)",
                    "3 * G matches known x",
                    "0 * G = infinity",
                    "G is on curve (y²=x³+7)",
                    "pt_to_compressed_pubkey ok",
                    "pubkey prefix 0x02/0x03",
                    "pubkey x bytes match Gx",
                    "G affine conversion failed",
                ];
                for (bit, name) in TEST_NAMES.iter().enumerate() {
                    if failures & (1u32 << bit) != 0 {
                        println!("  FAIL: test {}: {}", bit + 1, name);
                    }
                }
                panic!(
                    "secp256k1 point self-test failed with bitmap 0x{:08x}",
                    failures
                );
            }

            println!("secp256k1 point self-test passed (all 15 tests)!");
        });
    }

    #[test]
    fn test_blake2b_self_test() {
        run_with_big_stack(BIG_TEST_STACK, || {
            let _guard = lock_gpu();

            let Some(ctx) = crate::context::try_ctx() else {
                return;
            };

            println!("Using GPU: {}", ctx.info());

            let program = GpuProgram::blake2b_test(&ctx).expect("Failed to compile Blake2b kernel");
            let queue = ctx.queue();

            let result_buf = Buffer::<u32>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().read_write())
                .len(1)
                .build()
                .unwrap();

            result_buf.write(&[0xFFFF_FFFFu32][..]).enq().unwrap();

            let kernel = ocl::Kernel::builder()
                .program(program.program())
                .name("blake2b_self_test")
                .queue(queue.clone())
                .global_work_size(1)
                .arg(&result_buf)
                .build()
                .unwrap();

            unsafe {
                kernel.enq().unwrap();
            }
            queue.finish().unwrap();

            let mut result = [0u32; 1];
            result_buf.read(&mut result[..]).enq().unwrap();
            queue.finish().unwrap();

            let failures = result[0];
            println!("Blake2b self-test result: 0x{:08x}", failures);

            if failures != 0 {
                const TEST_NAMES: [&str; 3] = [
                    "Blake2b-256(\"\") matches known hash",
                    "Blake2b-256(\"abc\") matches known hash",
                    "ergo_checksum matches first 4 bytes of full hash",
                ];
                for (bit, name) in TEST_NAMES.iter().enumerate() {
                    if failures & (1u32 << bit) != 0 {
                        println!("  FAIL: test {}: {}", bit + 1, name);
                    }
                }
                panic!("Blake2b self-test failed with bitmap 0x{:08x}", failures);
            }

            println!("Blake2b self-test passed (all 3 tests)!");
        });
    }

    #[test]
    fn test_base58_self_test() {
        run_with_big_stack(BIG_TEST_STACK, || {
            let _guard = lock_gpu();

            let Some(ctx) = crate::context::try_ctx() else {
                return;
            };

            println!("Using GPU: {}", ctx.info());

            let program = GpuProgram::base58_test(&ctx).expect("Failed to compile Base58 kernel");
            let queue = ctx.queue();

            let result_buf = Buffer::<u32>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().read_write())
                .len(1)
                .build()
                .unwrap();

            result_buf.write(&[0xFFFF_FFFFu32][..]).enq().unwrap();

            let kernel = ocl::Kernel::builder()
                .program(program.program())
                .name("base58_self_test")
                .queue(queue.clone())
                .global_work_size(1)
                .arg(&result_buf)
                .build()
                .unwrap();

            unsafe {
                kernel.enq().unwrap();
            }
            queue.finish().unwrap();

            let mut result = [0u32; 1];
            result_buf.read(&mut result[..]).enq().unwrap();
            queue.finish().unwrap();

            let failures = result[0];
            println!("Base58 self-test result: 0x{:08x}", failures);

            if failures != 0 {
                const TEST_NAMES: [&str; 17] = [
                    "encode empty -> empty",
                    "encode 0x00 -> \"1\"",
                    "encode 0x00 0x00 -> \"11\"",
                    "encode 0x01 -> \"2\"",
                    "encode 0x39 (57) -> \"z\"",
                    "encode 0x3A (58) -> \"21\"",
                    "mainnet P2PK prefix -> starts with \"9\"",
                    "check_prefix \"9\" matches",
                    "check_prefix \"9f\" consistency",
                    "1 leading zero -> \"1\" prefix",
                    "1 leading zero matches \"1\"",
                    "2 leading zeros -> \"11\" prefix",
                    "2 leading zeros matches \"11\"",
                    "2 leading zeros matches \"1\" (>= for all-ones)",
                    "no leading zeros must NOT match \"1\"",
                    "2 leading zeros must NOT match \"1a\" (false positive test)",
                    "1 leading zero must NOT match \"9\" (leading zero test)",
                ];
                for (bit, name) in TEST_NAMES.iter().enumerate() {
                    if failures & (1u32 << bit) != 0 {
                        println!("  FAIL: test {}: {}", bit + 1, name);
                    }
                }
                panic!("Base58 self-test failed with bitmap 0x{:08x}", failures);
            }

            println!("Base58 self-test passed (all 17 tests)!");
        });
    }

    #[test]
    fn test_base58_fast_vs_generic() {
        run_with_big_stack(BIG_TEST_STACK, || {
            let _guard = lock_gpu();

            let Some(ctx) = crate::context::try_ctx() else {
                return;
            };

            println!("Using GPU: {}", ctx.info());

            let program =
                GpuProgram::base58_test(&ctx).expect("Failed to compile Base58 kernel");
            let queue = ctx.queue();

            // Test multiple prefixes (including mixed-case stress test)
            let prefixes = ["9", "9a", "9Z", "111", "9abcdefgh", "9ABCdefGHi", "111111111111"];

            for prefix in prefixes {
                let prefix_lc = prefix.to_ascii_lowercase();
                let prefix_bytes = prefix.as_bytes();
                let prefix_lc_bytes = prefix_lc.as_bytes();

                let prefix_buf = Buffer::<u8>::builder()
                    .queue(queue.clone())
                    .flags(MemFlags::new().read_only())
                    .len(prefix_bytes.len())
                    .build()
                    .unwrap();
                prefix_buf.write(prefix_bytes).enq().unwrap();

                let prefix_lc_buf = Buffer::<u8>::builder()
                    .queue(queue.clone())
                    .flags(MemFlags::new().read_only())
                    .len(prefix_lc_bytes.len())
                    .build()
                    .unwrap();
                prefix_lc_buf.write(prefix_lc_bytes).enq().unwrap();

                let result_buf = Buffer::<u32>::builder()
                    .queue(queue.clone())
                    .flags(MemFlags::new().read_write())
                    .len(1)
                    .build()
                    .unwrap();
                result_buf.write(&[0u32][..]).enq().unwrap();

                let kernel = ocl::Kernel::builder()
                    .program(program.program())
                    .name("base58_fast_vs_generic_test")
                    .queue(queue.clone())
                    .global_work_size(1)
                    .arg(&prefix_buf)
                    .arg(&prefix_lc_buf)
                    .arg(prefix_bytes.len() as i32)
                    .arg(&result_buf)
                    .build()
                    .unwrap();

                unsafe {
                    kernel.enq().unwrap();
                }
                queue.finish().unwrap();

                let mut result = [0u32; 1];
                result_buf.read(&mut result[..]).enq().unwrap();
                queue.finish().unwrap();

                let failures = result[0];
                if failures != 0 {
                    // Decode failure bits
                    let cs_failures = failures & 0xFFFF;
                    let icase_failures = (failures >> 16) & 0xFFFF;
                    panic!(
                        "Base58 fast-vs-generic test failed for prefix '{}': \
                         CS failures=0x{:04x}, ICASE failures=0x{:04x}",
                        prefix, cs_failures, icase_failures
                    );
                }
                println!("  Prefix '{}': OK", prefix);
            }

            println!("Base58 fast-vs-generic test passed for all prefixes!");
        });
    }

    #[test]
    fn test_vanity_cpu_gpu_consistency() {
        run_with_big_stack(BIG_TEST_STACK, || {
            let _guard = lock_gpu();

            let Some(ctx) = crate::context::try_ctx() else {
                return;
            };

            println!("Using GPU: {}", ctx.info());

            // Compile vanity program
            let program = GpuProgram::vanity(&ctx).expect("Failed to compile vanity kernel");
            let queue = ctx.queue();

            // Test vectors:
            // - [0x00; 32]: "abandon abandon ... art" - long mnemonic (>128 bytes, uses SHA-512 hash path)
            // - [0xff; 32]: "zoo zoo ... wrong" - short words (<=128 bytes, uses raw mnemonic path)
            let test_vectors: [([u8; 32], &str); 2] = [
                ([0x00; 32], "long mnemonic (>128 bytes)"),
                ([0xff; 32], "short mnemonic (<=128 bytes)"),
            ];

            use crate::wordlist::WordlistBuffers;
            use erg_vanity_bip::bip32::ExtendedPrivateKey;
            use erg_vanity_bip::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
            use erg_vanity_bip::bip44::derive_ergo_first_key;
            use erg_vanity_crypto::blake2b;
            use erg_vanity_crypto::secp256k1::pubkey::PublicKey;
            use erg_vanity_crypto::secp256k1::scalar::Scalar;

            let wordlist = WordlistBuffers::upload(queue).expect("upload wordlist");

            // Create reusable buffers
            let entropy_buf = Buffer::<u8>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().read_only())
                .len(32)
                .build()
                .unwrap();

            let seed_buf = Buffer::<u8>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().write_only())
                .len(64)
                .build()
                .unwrap();

            let private_key_buf = Buffer::<u8>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().write_only())
                .len(32)
                .build()
                .unwrap();

            let pubkey_buf = Buffer::<u8>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().write_only())
                .len(33)
                .build()
                .unwrap();

            let addr_bytes_buf = Buffer::<u8>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().write_only())
                .len(38)
                .build()
                .unwrap();

            let error_buf = Buffer::<i32>::builder()
                .queue(queue.clone())
                .flags(MemFlags::new().write_only())
                .len(1)
                .build()
                .unwrap();

            for (entropy, description) in test_vectors.iter().copied() {
                println!("\n=== Testing {} ===", description);

                // === CPU derivation ===
                let mnemonic = entropy_to_mnemonic(&entropy).expect("mnemonic from entropy");
                println!("Mnemonic length: {} bytes", mnemonic.len());
                println!(
                    "Mnemonic (first 50 chars): {}...",
                    &mnemonic[..50.min(mnemonic.len())]
                );

                let cpu_seed = mnemonic_to_seed(&mnemonic, "");
                println!("CPU seed (first 16 bytes): {:02x?}", &cpu_seed[..16]);

                let master = ExtendedPrivateKey::from_seed(&cpu_seed).expect("master from seed");
                let ergo_key = derive_ergo_first_key(&master).expect("derive ergo key");
                let cpu_private_key = *ergo_key.private_key(); // Copy to owned array
                println!(
                    "CPU private key (first 16 bytes): {:02x?}",
                    &cpu_private_key[..16]
                );

                let scalar = Scalar::from_bytes(&cpu_private_key).expect("valid scalar");
                let cpu_pubkey = PublicKey::from_private_key(&scalar).expect("pubkey from scalar");
                println!("CPU pubkey: {:02x?}", cpu_pubkey.as_bytes());

                // Build expected address bytes (1 prefix + 33 pubkey + 4 checksum = 38 bytes)
                // blake2b::digest returns Blake2b-256 (32 bytes) per our implementation
                let mut cpu_addr_bytes = [0u8; 38];
                cpu_addr_bytes[0] = 0x01; // mainnet P2PK
                cpu_addr_bytes[1..34].copy_from_slice(cpu_pubkey.as_bytes());
                let hash = blake2b::digest(&cpu_addr_bytes[..34]);
                cpu_addr_bytes[34..38].copy_from_slice(&hash[..4]);
                println!("CPU addr_bytes (first 16): {:02x?}", &cpu_addr_bytes[..16]);

                // === GPU derivation ===
                entropy_buf.write(&entropy[..]).enq().unwrap();

                let kernel = ocl::Kernel::builder()
                    .program(program.program())
                    .name("vanity_derive_address")
                    .queue(queue.clone())
                    .global_work_size(1)
                    .arg(&entropy_buf)
                    .arg(&wordlist.words8)
                    .arg(&wordlist.lens)
                    .arg(&seed_buf)
                    .arg(&private_key_buf)
                    .arg(&pubkey_buf)
                    .arg(&addr_bytes_buf)
                    .arg(&error_buf)
                    .build()
                    .unwrap();

                unsafe {
                    kernel.enq().unwrap();
                }
                queue.finish().unwrap();

                // Read GPU results
                let mut gpu_seed = [0u8; 64];
                let mut gpu_private_key = [0u8; 32];
                let mut gpu_pubkey = [0u8; 33];
                let mut gpu_addr_bytes = [0u8; 38];
                let mut gpu_error = [0i32; 1];

                seed_buf.read(&mut gpu_seed[..]).enq().unwrap();
                private_key_buf
                    .read(&mut gpu_private_key[..])
                    .enq()
                    .unwrap();
                pubkey_buf.read(&mut gpu_pubkey[..]).enq().unwrap();
                addr_bytes_buf.read(&mut gpu_addr_bytes[..]).enq().unwrap();
                error_buf.read(&mut gpu_error[..]).enq().unwrap();
                queue.finish().unwrap(); // Ensure reads complete before comparing

                println!("GPU seed (first 16 bytes): {:02x?}", &gpu_seed[..16]);
                println!(
                    "GPU private key (first 16 bytes): {:02x?}",
                    &gpu_private_key[..16]
                );
                println!("GPU pubkey: {:02x?}", &gpu_pubkey);
                println!("GPU addr_bytes (first 16): {:02x?}", &gpu_addr_bytes[..16]);
                println!("GPU error: {}", gpu_error[0]);

                // === Compare results ===
                assert_eq!(
                    gpu_error[0], 0,
                    "GPU derivation returned error for {}",
                    description
                );
                assert_eq!(gpu_seed, cpu_seed, "Seed mismatch for {}", description);
                assert_eq!(
                    gpu_private_key, cpu_private_key,
                    "Private key mismatch for {}",
                    description
                );
                assert_eq!(
                    gpu_pubkey,
                    *cpu_pubkey.as_bytes(),
                    "Pubkey mismatch for {}",
                    description
                );
                assert_eq!(
                    gpu_addr_bytes, cpu_addr_bytes,
                    "Address bytes mismatch for {}",
                    description
                );

                println!("PASSED: {}", description);
            }

            println!("\nCPU/GPU consistency test passed for all vectors!");
        });
    }
}
