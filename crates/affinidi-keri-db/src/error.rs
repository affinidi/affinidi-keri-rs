use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Database(String),

    #[error("key not found: {0}")]
    NotFound(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("LMDB error: {0}")]
    Lmdb(String),

    #[error("transaction error: {0}")]
    Transaction(String),

    #[error("duplicate entry: {0}")]
    Duplicate(String),
}

impl From<heed::Error> for DbError {
    fn from(e: heed::Error) -> Self {
        DbError::Lmdb(e.to_string())
    }
}
