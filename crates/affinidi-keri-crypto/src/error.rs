//! Error types for affinidi-keri-crypto.

use thiserror::Error;

/// Errors that can occur in cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// An error from the CESR layer.
    #[error("CESR error: {0}")]
    Cesr(#[from] affinidi_cesr::CesrError),

    /// The provided key material has an unexpected size.
    #[error("invalid key size: expected {expected}, got {got}")]
    InvalidKeySize { expected: usize, got: usize },

    /// The signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The digest does not match the expected value.
    #[error("digest mismatch")]
    DigestMismatch,

    /// An unsupported or unrecognized algorithm code was provided.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// An error during key derivation (e.g., Argon2).
    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    /// Generic conversion or serialization error.
    #[error("conversion error: {0}")]
    Conversion(String),

    /// Missing verfer needed for verification.
    #[error("no verfer set for signature verification")]
    MissingVerfer,

    /// Invalid signature bytes.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid key bytes.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}
