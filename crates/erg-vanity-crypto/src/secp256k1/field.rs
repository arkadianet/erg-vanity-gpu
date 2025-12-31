//! Prime field arithmetic for secp256k1.
//! p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

#![forbid(unsafe_code)]

/// The secp256k1 field prime p = 2^256 - 2^32 - 977.
/// Represented as 4 x 64-bit limbs in little-endian order.
const P: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// p - 2 for Fermat inversion.
const P_MINUS_2: [u64; 4] = [
    0xFFFFFFFEFFFFFC2D,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Field element in secp256k1's prime field GF(p).
/// Stored as 4 x 64-bit limbs in little-endian order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    limbs: [u64; 4],
}

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// One element.
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };

    /// Create field element from 4 limbs (little-endian).
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create field element from bytes (big-endian).
    /// Returns None if value >= p.
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

        let fe = Self { limbs };
        if fe.gte_p() {
            None
        } else {
            Some(fe)
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

    /// Check if self >= p.
    fn gte_p(&self) -> bool {
        for i in (0..4).rev() {
            if self.limbs[i] > P[i] {
                return true;
            }
            if self.limbs[i] < P[i] {
                return false;
            }
        }
        true // equal to p
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }

    /// Addition: self + other (mod p).
    pub fn add(&self, other: &Self) -> Self {
        let (r0, c0) = self.limbs[0].overflowing_add(other.limbs[0]);
        let (r1, c1) = self.limbs[1].carrying_add(other.limbs[1], c0);
        let (r2, c2) = self.limbs[2].carrying_add(other.limbs[2], c1);
        let (r3, c3) = self.limbs[3].carrying_add(other.limbs[3], c2);

        let mut result = Self {
            limbs: [r0, r1, r2, r3],
        };

        if c3 || result.gte_p() {
            result = result.sub_p();
        }

        result
    }

    /// Subtract p from self.
    fn sub_p(&self) -> Self {
        let (r0, b0) = self.limbs[0].overflowing_sub(P[0]);
        let (r1, b1) = self.limbs[1].borrowing_sub(P[1], b0);
        let (r2, b2) = self.limbs[2].borrowing_sub(P[2], b1);
        let (r3, _) = self.limbs[3].borrowing_sub(P[3], b2);
        Self {
            limbs: [r0, r1, r2, r3],
        }
    }

    /// Subtraction: self - other (mod p).
    pub fn sub(&self, other: &Self) -> Self {
        let (r0, b0) = self.limbs[0].overflowing_sub(other.limbs[0]);
        let (r1, b1) = self.limbs[1].borrowing_sub(other.limbs[1], b0);
        let (r2, b2) = self.limbs[2].borrowing_sub(other.limbs[2], b1);
        let (r3, b3) = self.limbs[3].borrowing_sub(other.limbs[3], b2);

        let mut result = Self {
            limbs: [r0, r1, r2, r3],
        };

        if b3 {
            result = result.add_p();
        }

        result
    }

    /// Add p to self.
    fn add_p(&self) -> Self {
        let (r0, c0) = self.limbs[0].overflowing_add(P[0]);
        let (r1, c1) = self.limbs[1].carrying_add(P[1], c0);
        let (r2, c2) = self.limbs[2].carrying_add(P[2], c1);
        let (r3, _) = self.limbs[3].carrying_add(P[3], c2);
        Self {
            limbs: [r0, r1, r2, r3],
        }
    }

    /// Negation: -self (mod p).
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            *self
        } else {
            let (r0, b0) = P[0].overflowing_sub(self.limbs[0]);
            let (r1, b1) = P[1].borrowing_sub(self.limbs[1], b0);
            let (r2, b2) = P[2].borrowing_sub(self.limbs[2], b1);
            let (r3, _) = P[3].borrowing_sub(self.limbs[3], b2);
            Self {
                limbs: [r0, r1, r2, r3],
            }
        }
    }

    /// Multiplication: self * other (mod p).
    /// Uses carry-safe schoolbook multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        // 512-bit product as 8x64 limbs (little endian)
        let mut wide = [0u64; 8];

        for i in 0..4 {
            let mut carry: u128 = 0;

            for j in 0..4 {
                let idx = i + j;

                // 64x64 -> 128, split into lo/hi
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128);
                let lo = prod as u64;
                let hi = (prod >> 64) as u64;

                // Accumulate lo + carry into wide[idx]
                let acc = (wide[idx] as u128) + (lo as u128) + carry;
                wide[idx] = acc as u64;

                // New carry: high part of acc + hi
                carry = (acc >> 64) + (hi as u128);
            }

            // Spill carry into following limbs
            let mut k = i + 4;
            while carry != 0 {
                debug_assert!(k < 8, "512-bit multiply overflow");
                let acc = (wide[k] as u128) + carry;
                wide[k] = acc as u64;
                carry = acc >> 64;
                k += 1;
            }
        }

        Self::reduce(&wide)
    }

    /// Square: self^2 (mod p).
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Reduce 512-bit number mod p.
    /// Uses: 2^256 ≡ 2^32 + 977 (mod p).
    fn reduce(wide: &[u64; 8]) -> Self {
        // We reduce t[4..8] * 2^256 by replacing with t[4..8] * (2^32 + 977)
        let mut acc = [0u128; 5];

        // Add low 256 bits
        acc[0] = wide[0] as u128;
        acc[1] = wide[1] as u128;
        acc[2] = wide[2] as u128;
        acc[3] = wide[3] as u128;

        // Add high * 977
        acc[0] += (wide[4] as u128) * 977;
        acc[1] += (wide[5] as u128) * 977;
        acc[2] += (wide[6] as u128) * 977;
        acc[3] += (wide[7] as u128) * 977;

        // Add high * 2^32 (shift left by 32 bits)
        // Carry propagation will handle overflow from each limb to the next
        acc[0] += (wide[4] as u128) << 32;
        acc[1] += (wide[5] as u128) << 32;
        acc[2] += (wide[6] as u128) << 32;
        acc[3] += (wide[7] as u128) << 32;

        // Propagate carries
        let mut result = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            carry += acc[i];
            result[i] = carry as u64;
            carry >>= 64;
        }

        // If result[4] != 0, reduce again
        while result[4] != 0 {
            let overflow = result[4] as u128;
            result[4] = 0;

            // Add overflow * (2^32 + 977)
            carry = (result[0] as u128) + overflow * 977 + (overflow << 32);
            result[0] = carry as u64;
            carry >>= 64;

            carry += result[1] as u128;
            result[1] = carry as u64;
            carry >>= 64;

            carry += result[2] as u128;
            result[2] = carry as u64;
            carry >>= 64;

            carry += result[3] as u128;
            result[3] = carry as u64;
            carry >>= 64;

            result[4] = carry as u64;
        }

        let mut fe = Self {
            limbs: [result[0], result[1], result[2], result[3]],
        };

        // Final reduction if >= p (may need multiple subtractions)
        while fe.gte_p() {
            fe = fe.sub_p();
        }

        fe
    }

    /// Exponentiation: self^exp (mod p).
    /// Uses square-and-multiply.
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;

        for &limb in exp.iter() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }

        result
    }

    /// Multiplicative inverse: self^(-1) (mod p).
    /// Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p.
    pub fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(&P_MINUS_2))
    }

    /// Check if self is odd (least significant bit is 1).
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe_from_hex(s: &str) -> FieldElement {
        let bytes = hex::decode(s).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        FieldElement::from_bytes(&arr).unwrap()
    }

    #[test]
    fn test_p_constant() {
        // Verify P is correct: 2^256 - 2^32 - 977
        let p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let bytes = hex::decode(p_hex).unwrap();

        assert_eq!(P[0], 0xFFFFFFFEFFFFFC2F);
        assert_eq!(P[1], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(P[2], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(P[3], 0xFFFFFFFFFFFFFFFF);

        // from_bytes should reject p itself
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        assert!(FieldElement::from_bytes(&arr).is_none());
    }

    #[test]
    fn test_add_sub_identity() {
        let a = fe_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        let b = fe_from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // (a + b) - b == a
        assert_eq!(a.add(&b).sub(&b), a);

        // (a - b) + b == a
        assert_eq!(a.sub(&b).add(&b), a);
    }

    #[test]
    fn test_mul_commutative() {
        let a = fe_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        let b = fe_from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_mul_distributive() {
        let a = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000005");
        let b = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000003");
        let c = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000007");

        // a * (b + c) == a*b + a*c
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
    }

    #[test]
    fn test_mul_simple() {
        let two = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000002");
        let three = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000003");
        let six = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000006");

        assert_eq!(two.mul(&three), six);
    }

    #[test]
    fn test_inv() {
        let a = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(a.mul(&a.inv().unwrap()), FieldElement::ONE);
    }

    #[test]
    fn test_inv_large() {
        let a = fe_from_hex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe");
        assert_eq!(a.mul(&a.inv().unwrap()), FieldElement::ONE);
    }

    #[test]
    fn test_neg() {
        let a = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(a.add(&a.neg()), FieldElement::ZERO);
    }

    #[test]
    fn test_zero_inv() {
        assert!(FieldElement::ZERO.inv().is_none());
    }

    #[test]
    fn test_square() {
        let a = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000003");
        let nine = fe_from_hex("0000000000000000000000000000000000000000000000000000000000000009");
        assert_eq!(a.square(), nine);
    }

    #[test]
    fn test_mul_high_limbs() {
        // Test with values that have high limbs set (stress test for carry)
        let a = fe_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFF0000");
        let b = fe_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFF0000");
        let result = a.mul(&b);
        // Verify: a * a^(-1) == 1
        assert_eq!(result.mul(&result.inv().unwrap()), FieldElement::ONE);
    }

    #[test]
    fn test_against_k256() {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::{FieldBytes, FieldElement as K256Fe};

        fn k256_from_bytes(b: [u8; 32]) -> K256Fe {
            Option::<K256Fe>::from(K256Fe::from_repr(FieldBytes::from(b))).unwrap()
        }

        // Test several random-ish values
        let test_values = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFF0000",
        ];

        for hex_a in &test_values {
            for hex_b in &test_values {
                let a = fe_from_hex(hex_a);
                let b = fe_from_hex(hex_b);

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
