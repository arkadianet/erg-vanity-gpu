//! Scalar arithmetic modulo curve order n.
//!
//! n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//! Used for private key operations. BIP32 derivation needs add mod n.

#![forbid(unsafe_code)]

/// The secp256k1 curve order n.
/// Represented as 4 x 64-bit limbs in little-endian order.
const N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// Scalar element in Z/nZ where n is the secp256k1 curve order.
/// Used for private keys and scalar multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar {
    limbs: [u64; 4],
}

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// One scalar.
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };

    /// Create scalar from 4 limbs (little-endian).
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create scalar from bytes (big-endian).
    /// Returns None if value >= n.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let limbs = [
            u64::from_be_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30],
                bytes[31],
            ]),
            u64::from_be_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22],
                bytes[23],
            ]),
            u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        ];

        let s = Self { limbs };
        if s.gte_n() {
            None
        } else {
            Some(s)
        }
    }

    /// Convert to bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&self.limbs[3].to_be_bytes());
        bytes[8..16].copy_from_slice(&self.limbs[2].to_be_bytes());
        bytes[16..24].copy_from_slice(&self.limbs[1].to_be_bytes());
        bytes[24..32].copy_from_slice(&self.limbs[0].to_be_bytes());
        bytes
    }

    /// Check if self >= n.
    fn gte_n(&self) -> bool {
        for i in (0..4).rev() {
            if self.limbs[i] > N[i] {
                return true;
            }
            if self.limbs[i] < N[i] {
                return false;
            }
        }
        true // equal to n
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }

    /// Addition: self + other (mod n).
    pub fn add(&self, other: &Self) -> Self {
        let (r0, c0) = self.limbs[0].overflowing_add(other.limbs[0]);
        let (r1, c1) = self.limbs[1].carrying_add(other.limbs[1], c0);
        let (r2, c2) = self.limbs[2].carrying_add(other.limbs[2], c1);
        let (r3, c3) = self.limbs[3].carrying_add(other.limbs[3], c2);

        let mut result = Self {
            limbs: [r0, r1, r2, r3],
        };

        if c3 || result.gte_n() {
            result = result.sub_n();
        }

        result
    }

    /// Subtract n from self.
    fn sub_n(&self) -> Self {
        let (r0, b0) = self.limbs[0].overflowing_sub(N[0]);
        let (r1, b1) = self.limbs[1].borrowing_sub(N[1], b0);
        let (r2, b2) = self.limbs[2].borrowing_sub(N[2], b1);
        let (r3, _) = self.limbs[3].borrowing_sub(N[3], b2);
        Self {
            limbs: [r0, r1, r2, r3],
        }
    }

    /// Subtraction: self - other (mod n).
    pub fn sub(&self, other: &Self) -> Self {
        let (r0, b0) = self.limbs[0].overflowing_sub(other.limbs[0]);
        let (r1, b1) = self.limbs[1].borrowing_sub(other.limbs[1], b0);
        let (r2, b2) = self.limbs[2].borrowing_sub(other.limbs[2], b1);
        let (r3, b3) = self.limbs[3].borrowing_sub(other.limbs[3], b2);

        let mut result = Self {
            limbs: [r0, r1, r2, r3],
        };

        if b3 {
            result = result.add_n();
        }

        result
    }

    /// Add n to self.
    fn add_n(&self) -> Self {
        let (r0, c0) = self.limbs[0].overflowing_add(N[0]);
        let (r1, c1) = self.limbs[1].carrying_add(N[1], c0);
        let (r2, c2) = self.limbs[2].carrying_add(N[2], c1);
        let (r3, _) = self.limbs[3].carrying_add(N[3], c2);
        Self {
            limbs: [r0, r1, r2, r3],
        }
    }

    /// Negation: -self (mod n).
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            *self
        } else {
            let (r0, b0) = N[0].overflowing_sub(self.limbs[0]);
            let (r1, b1) = N[1].borrowing_sub(self.limbs[1], b0);
            let (r2, b2) = N[2].borrowing_sub(self.limbs[2], b1);
            let (r3, _) = N[3].borrowing_sub(self.limbs[3], b2);
            Self {
                limbs: [r0, r1, r2, r3],
            }
        }
    }

    /// Multiplication: self * other (mod n).
    pub fn mul(&self, other: &Self) -> Self {
        // 512-bit product as 8x64 limbs (little endian)
        let mut wide = [0u64; 8];

        for i in 0..4 {
            let mut carry: u128 = 0;

            for j in 0..4 {
                let idx = i + j;
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128);
                let lo = prod as u64;
                let hi = (prod >> 64) as u64;

                let acc = (wide[idx] as u128) + (lo as u128) + carry;
                wide[idx] = acc as u64;
                carry = (acc >> 64) + (hi as u128);
            }

            let mut k = i + 4;
            while carry != 0 {
                debug_assert!(k < 8, "512-bit multiply overflow");
                let acc = (wide[k] as u128) + carry;
                wide[k] = acc as u64;
                carry = acc >> 64;
                k += 1;
            }
        }

        Self::reduce_wide(&wide)
    }

    /// Reduce 512-bit number mod n using bit-by-bit reduction.
    /// Uses rem = (rem * 2 + bit) mod n, processing from MSB to LSB.
    fn reduce_wide(wide: &[u64; 8]) -> Self {
        let mut rem = Self::ZERO;

        // Process all 512 bits from MSB to LSB
        for limb_idx in (0..8).rev() {
            let limb = wide[limb_idx];
            for bit_idx in (0..64).rev() {
                // rem = (rem * 2) mod n
                rem = rem.add(&rem);

                // rem = (rem + bit) mod n
                if ((limb >> bit_idx) & 1) == 1 {
                    rem = rem.add(&Self::ONE);
                }
            }
        }

        rem
    }

    /// Square: self^2 (mod n).
    pub fn square(&self) -> Self {
        self.mul(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_hex(s: &str) -> Scalar {
        let bytes = hex::decode(s).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Scalar::from_bytes(&arr).unwrap()
    }

    #[test]
    fn test_n_constant() {
        // Verify N is correct
        let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let bytes = hex::decode(n_hex).unwrap();

        assert_eq!(N[0], 0xBFD25E8CD0364141);
        assert_eq!(N[1], 0xBAAEDCE6AF48A03B);
        assert_eq!(N[2], 0xFFFFFFFFFFFFFFFE);
        assert_eq!(N[3], 0xFFFFFFFFFFFFFFFF);

        // from_bytes should reject n itself
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        assert!(Scalar::from_bytes(&arr).is_none());
    }

    #[test]
    fn test_add_sub_identity() {
        let a = scalar_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        let b = scalar_from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // (a + b) - b == a
        assert_eq!(a.add(&b).sub(&b), a);

        // (a - b) + b == a
        assert_eq!(a.sub(&b).add(&b), a);
    }

    #[test]
    fn test_add_wrap() {
        // Test addition that wraps around n
        let almost_n =
            scalar_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
        let two =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000002");

        // almost_n + 2 should wrap: (n-1) + 2 = n + 1 ≡ 1 (mod n)
        assert_eq!(almost_n.add(&two), Scalar::ONE);
    }

    #[test]
    fn test_sub_wrap() {
        // Test subtraction that wraps below zero
        let one = Scalar::ONE;
        let two =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000002");

        // 1 - 2 = -1 ≡ n - 1 (mod n)
        let result = one.sub(&two);
        let expected =
            scalar_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_neg() {
        let a = scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(a.add(&a.neg()), Scalar::ZERO);

        let b = scalar_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        assert_eq!(b.add(&b.neg()), Scalar::ZERO);
    }

    #[test]
    fn test_mul_simple() {
        let two =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000002");
        let three =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000003");
        let six =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000006");

        assert_eq!(two.mul(&three), six);
    }

    #[test]
    fn test_mul_commutative() {
        let a = scalar_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        let b = scalar_from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_against_k256() {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::{FieldBytes, Scalar as K256Scalar};

        fn k256_from_bytes(b: [u8; 32]) -> K256Scalar {
            Option::<K256Scalar>::from(K256Scalar::from_repr(FieldBytes::from(b))).unwrap()
        }

        let test_values = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", // n-1
        ];

        for hex_a in &test_values {
            for hex_b in &test_values {
                let a = scalar_from_hex(hex_a);
                let b = scalar_from_hex(hex_b);

                let a_bytes = a.to_bytes();
                let b_bytes = b.to_bytes();

                let k256_a = k256_from_bytes(a_bytes);
                let k256_b = k256_from_bytes(b_bytes);

                // Test mul
                let our_mul = a.mul(&b);
                let k256_mul = k256_a * k256_b;
                let k256_mul_bytes: [u8; 32] = k256_mul.to_repr().into();
                assert_eq!(
                    our_mul.to_bytes(),
                    k256_mul_bytes,
                    "mul mismatch for {hex_a} * {hex_b}"
                );

                // Test add
                let our_add = a.add(&b);
                let k256_add = k256_a + k256_b;
                let k256_add_bytes: [u8; 32] = k256_add.to_repr().into();
                assert_eq!(
                    our_add.to_bytes(),
                    k256_add_bytes,
                    "add mismatch for {hex_a} + {hex_b}"
                );

                // Test sub
                let our_sub = a.sub(&b);
                let k256_sub = k256_a - k256_b;
                let k256_sub_bytes: [u8; 32] = k256_sub.to_repr().into();
                assert_eq!(
                    our_sub.to_bytes(),
                    k256_sub_bytes,
                    "sub mismatch for {hex_a} - {hex_b}"
                );
            }
        }
    }
}
