use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid entropy length {got}: expected one of 16, 20, 24, 28, or 32 bytes")]
    InvalidEntropyLength { got: usize },

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid word in mnemonic: {0}")]
    InvalidWord(String),

    #[error("invalid checksum")]
    InvalidChecksum,

    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("scalar out of range")]
    ScalarOutOfRange,

    #[error("point at infinity")]
    PointAtInfinity,
}
