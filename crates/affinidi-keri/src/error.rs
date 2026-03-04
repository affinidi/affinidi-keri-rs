use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeriError {
    #[error("CESR error: {0}")]
    Cesr(#[from] affinidi_cesr::CesrError),

    #[error("crypto error: {0}")]
    Crypto(#[from] affinidi_keri_crypto::CryptoError),

    #[error("core error: {0}")]
    Core(#[from] affinidi_keri_core::CoreError),

    #[error("database error: {0}")]
    Db(#[from] affinidi_keri_db::DbError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("identifier not found: {0}")]
    NotFound(String),

    #[error("identifier already exists: {0}")]
    AlreadyExists(String),
}
