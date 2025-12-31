//! Elliptic curve point operations in Jacobian coordinates.
//!
//! secp256k1 curve: y² = x³ + 7 over GF(p)
//! Jacobian: (X, Y, Z) represents affine (X/Z², Y/Z³)

#![forbid(unsafe_code)]

use super::field::FieldElement;
use super::scalar::Scalar;

/// Generator point G (affine x-coordinate).
const GX: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

/// Generator point G (affine y-coordinate).
const GY: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

/// Point on secp256k1 in Jacobian coordinates.
/// (X, Y, Z) represents affine point (X/Z², Y/Z³).
/// Point at infinity has Z = 0.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl Point {
    /// Point at infinity (identity element).
    pub const INFINITY: Self = Self {
        x: FieldElement::ONE,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Create point from Jacobian coordinates.
    pub const fn from_jacobian(x: FieldElement, y: FieldElement, z: FieldElement) -> Self {
        Self { x, y, z }
    }

    /// Create point from affine coordinates (x, y).
    /// Does not validate that the point is on the curve.
    pub fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            z: FieldElement::ONE,
        }
    }

    /// Generator point G.
    pub fn generator() -> Self {
        Self::from_affine(FieldElement::from_limbs(GX), FieldElement::from_limbs(GY))
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates (x, y).
    /// Returns None for point at infinity.
    pub fn to_affine(&self) -> Option<(FieldElement, FieldElement)> {
        if self.is_infinity() {
            return None;
        }

        let z_inv = self.z.inv()?;
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);

        let x = self.x.mul(&z_inv2);
        let y = self.y.mul(&z_inv3);

        Some((x, y))
    }

    /// Point doubling: 2P.
    /// Uses standard Jacobian doubling formulas for a=0 curves.
    pub fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::INFINITY;
        }

        // S = 4*X*Y²
        let y2 = self.y.square();
        let s = self.x.mul(&y2).mul(&FieldElement::from_limbs([4, 0, 0, 0]));

        // M = 3*X² (since a=0 for secp256k1)
        let x2 = self.x.square();
        let m = x2.mul(&FieldElement::from_limbs([3, 0, 0, 0]));

        // X3 = M² - 2*S
        let m2 = m.square();
        let x3 = m2.sub(&s).sub(&s);

        // Y3 = M*(S - X3) - 8*Y⁴
        let y4 = y2.square();
        let y4_8 = y4.mul(&FieldElement::from_limbs([8, 0, 0, 0]));
        let y3 = m.mul(&s.sub(&x3)).sub(&y4_8);

        // Z3 = 2*Y*Z
        let z3 = self
            .y
            .mul(&self.z)
            .mul(&FieldElement::from_limbs([2, 0, 0, 0]));

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition: P1 + P2.
    /// Uses standard Jacobian addition formulas.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }

        let z1_2 = self.z.square();
        let z2_2 = other.z.square();
        let z1_3 = z1_2.mul(&self.z);
        let z2_3 = z2_2.mul(&other.z);

        // U1 = X1*Z2², U2 = X2*Z1²
        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);

        // S1 = Y1*Z2³, S2 = Y2*Z1³
        let s1 = self.y.mul(&z2_3);
        let s2 = other.y.mul(&z1_3);

        // H = U2 - U1
        let h = u2.sub(&u1);

        // R = S2 - S1
        let r = s2.sub(&s1);

        // If H = 0:
        if h.is_zero() {
            if r.is_zero() {
                // Points are equal, do doubling
                return self.double();
            } else {
                // Points are inverses, return infinity
                return Self::INFINITY;
            }
        }

        let h2 = h.square();
        let h3 = h2.mul(&h);

        // X3 = R² - H³ - 2*U1*H²
        let u1_h2 = u1.mul(&h2);
        let x3 = r.square().sub(&h3).sub(&u1_h2).sub(&u1_h2);

        // Y3 = R*(U1*H² - X3) - S1*H³
        let y3 = r.mul(&u1_h2.sub(&x3)).sub(&s1.mul(&h3));

        // Z3 = H*Z1*Z2
        let z3 = h.mul(&self.z).mul(&other.z);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Scalar multiplication: k * P.
    /// Uses double-and-add algorithm.
    pub fn mul(&self, k: &Scalar) -> Self {
        if k.is_zero() || self.is_infinity() {
            return Self::INFINITY;
        }

        let k_bytes = k.to_bytes();
        let mut result = Self::INFINITY;
        let mut base = *self;

        // Process from LSB to MSB
        for byte in k_bytes.iter().rev() {
            let b = *byte;
            for bit in 0..8 {
                if ((b >> bit) & 1) == 1 {
                    result = result.add(&base);
                }
                base = base.double();
            }
        }

        result
    }

    /// Multiply generator G by scalar k: k * G.
    pub fn mul_generator(k: &Scalar) -> Self {
        Self::generator().mul(k)
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity() && other.is_infinity() {
            return true;
        }
        if self.is_infinity() || other.is_infinity() {
            return false;
        }

        // Compare in affine: X1/Z1² = X2/Z2² and Y1/Z1³ = Y2/Z2³
        // Cross-multiply: X1*Z2² = X2*Z1² and Y1*Z2³ = Y2*Z1³
        let z1_2 = self.z.square();
        let z2_2 = other.z.square();
        let z1_3 = z1_2.mul(&self.z);
        let z2_3 = z2_2.mul(&other.z);

        let lhs_x = self.x.mul(&z2_2);
        let rhs_x = other.x.mul(&z1_2);
        let lhs_y = self.y.mul(&z2_3);
        let rhs_y = other.y.mul(&z1_3);

        lhs_x == rhs_x && lhs_y == rhs_y
    }
}

impl Eq for Point {}

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
    fn test_generator_on_curve() {
        // Verify G is on the curve: y² = x³ + 7
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();

        let y2 = y.square();
        let x3 = x.square().mul(&x);
        let b = FieldElement::from_limbs([7, 0, 0, 0]);
        let x3_plus_7 = x3.add(&b);

        assert_eq!(y2, x3_plus_7, "Generator not on curve");
    }

    #[test]
    fn test_infinity_identity() {
        let g = Point::generator();
        let inf = Point::INFINITY;

        // G + O = G
        assert_eq!(g.add(&inf), g);

        // O + G = G
        assert_eq!(inf.add(&g), g);

        // O + O = O
        assert!(inf.add(&inf).is_infinity());
    }

    #[test]
    fn test_double() {
        let g = Point::generator();
        let g2 = g.double();

        // 2G should be on the curve
        let (x, y) = g2.to_affine().unwrap();
        let y2 = y.square();
        let b = FieldElement::from_limbs([7, 0, 0, 0]);
        let x3_plus_7 = x.square().mul(&x).add(&b);
        assert_eq!(y2, x3_plus_7, "2G not on curve");

        // G + G = 2G
        let g_plus_g = g.add(&g);
        assert_eq!(g_plus_g, g2);
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = Point::generator();
        let one = Scalar::ONE;

        let result = g.mul(&one);
        assert_eq!(result, g);
    }

    #[test]
    fn test_scalar_mul_two() {
        let g = Point::generator();
        let two =
            scalar_from_hex("0000000000000000000000000000000000000000000000000000000000000002");

        let result = g.mul(&two);
        let expected = g.double();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_against_k256() {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{FieldBytes, ProjectivePoint, Scalar as K256Scalar};

        fn k256_scalar_from_bytes(b: [u8; 32]) -> K256Scalar {
            Option::<K256Scalar>::from(K256Scalar::from_repr(FieldBytes::from(b))).unwrap()
        }

        let test_scalars = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];

        for hex_k in &test_scalars {
            let k = scalar_from_hex(hex_k);
            let our_point = Point::mul_generator(&k);
            let (our_x, our_y) = our_point.to_affine().unwrap();

            let k256_k = k256_scalar_from_bytes(k.to_bytes());
            let k256_point = ProjectivePoint::GENERATOR * k256_k;
            let k256_affine = k256_point.to_affine();
            let k256_encoded = k256_affine.to_encoded_point(false);

            #[allow(deprecated)]
            let k256_x: [u8; 32] = k256_encoded.x().unwrap().as_slice().try_into().unwrap();
            #[allow(deprecated)]
            let k256_y: [u8; 32] = k256_encoded.y().unwrap().as_slice().try_into().unwrap();

            assert_eq!(our_x.to_bytes(), k256_x, "x mismatch for k = {hex_k}");
            assert_eq!(our_y.to_bytes(), k256_y, "y mismatch for k = {hex_k}");
        }
    }
}
