//! Public key generation: P = k*G -> compressed 33-byte format.
//!
//! Compressed format: [prefix][x-coordinate]
//! - prefix: 0x02 if y is even, 0x03 if y is odd
//! - x-coordinate: 32 bytes big-endian

#![forbid(unsafe_code)]

use super::point::Point;
use super::scalar::Scalar;

/// Compressed public key (33 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 33],
}

impl PublicKey {
    /// Generate public key from private key (scalar).
    /// Returns None if private key is zero.
    pub fn from_private_key(private_key: &Scalar) -> Option<Self> {
        if private_key.is_zero() {
            return None;
        }

        let point = Point::mul_generator(private_key);
        let (x, y) = point.to_affine()?;

        let mut bytes = [0u8; 33];

        // Prefix: 0x02 for even y, 0x03 for odd y
        bytes[0] = if y.is_odd() { 0x03 } else { 0x02 };

        // X-coordinate (32 bytes big-endian)
        bytes[1..33].copy_from_slice(&x.to_bytes());

        Some(Self { bytes })
    }

    /// Get the raw 33-byte compressed public key.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.bytes
    }

    /// Convert to 33-byte array.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.bytes
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
    fn test_pubkey_from_one() {
        // Private key = 1 -> Public key = G
        let one = Scalar::ONE;
        let pubkey = PublicKey::from_private_key(&one).unwrap();

        // G's y is even, so prefix should be 0x02
        // G's x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let expected_x =
            hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap();

        assert_eq!(pubkey.bytes[0], 0x02);
        assert_eq!(&pubkey.bytes[1..33], expected_x.as_slice());
    }

    #[test]
    fn test_zero_private_key() {
        let zero = Scalar::ZERO;
        assert!(PublicKey::from_private_key(&zero).is_none());
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
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", // n-1
        ];

        for hex_k in &test_scalars {
            let k = scalar_from_hex(hex_k);
            let our_pubkey = PublicKey::from_private_key(&k).unwrap();

            let k256_k = k256_scalar_from_bytes(k.to_bytes());
            let k256_point = ProjectivePoint::GENERATOR * k256_k;
            let k256_affine = k256_point.to_affine();
            let k256_compressed = k256_affine.to_encoded_point(true);

            assert_eq!(
                our_pubkey.as_bytes(),
                k256_compressed.as_bytes(),
                "pubkey mismatch for k = {hex_k}"
            );
        }
    }
}
