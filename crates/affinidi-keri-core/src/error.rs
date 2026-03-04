//! Core error types for the KERI protocol engine.

use thiserror::Error;

/// Errors that can occur in core KERI operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// An error from the CESR layer.
    #[error("CESR error: {0}")]
    Cesr(#[from] affinidi_cesr::CesrError),

    /// An error from the crypto layer.
    #[error("crypto error: {0}")]
    Crypto(#[from] affinidi_keri_crypto::CryptoError),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// CBOR serialization/deserialization error.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// MessagePack serialization/deserialization error.
    #[error("MessagePack error: {0}")]
    MsgPack(String),

    /// The event type (ilk) is unexpected or unsupported.
    #[error("unexpected event type: {0}")]
    UnexpectedIlk(String),

    /// A required field is missing from the event.
    #[error("missing field: {0}")]
    MissingField(String),

    /// The SAID (self-addressing identifier) does not match.
    #[error("SAID verification failed")]
    SaidMismatch,

    /// The sequence number is out of order.
    #[error("out of order sequence number: expected {expected}, got {got}")]
    OutOfOrder { expected: u64, got: u64 },

    /// Signature threshold not met.
    #[error("signature threshold not met")]
    ThresholdNotMet,

    /// A duplicate event was detected.
    #[error("duplicate event at sn {0}")]
    DuplicateEvent(u64),

    /// The identifier prefix is invalid or unrecognized.
    #[error("invalid prefix: {0}")]
    InvalidPrefix(String),

    /// A version string could not be parsed.
    #[error("invalid version: {0}")]
    InvalidVersion(String),

    /// A parsing error occurred.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Generic validation error.
    #[error("validation error: {0}")]
    Validation(String),
}
