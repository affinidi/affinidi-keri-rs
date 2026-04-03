//! Siger: indexed signature.
//!
//! Indexed signatures carry both the raw signature bytes and the index of the
//! signing key within a key set. CESR codes:
//! - `"A"` / `"B"` - Ed25519 (current-only / both)
//! - `"C"` / `"D"` - ECDSA secp256k1 (current-only / both)
//! - `"E"` / `"F"` - ECDSA secp256r1 (current-only / both)
//! - `"2A"` - `"2F"` - Big-index variants (same algorithms)
//! - `"3A"` / `"3B"` - Ed448

use crate::error::CryptoError;
use crate::verfer::Verfer;
use affinidi_cesr::Indexer;

/// An indexed signature, wrapping a CESR `Indexer` primitive.
///
/// Siger represents a signature that is associated with a key index
/// within a signing key set. It is used for controller and witness
/// indexed signature groups.
#[derive(Debug, Clone)]
pub struct Siger {
    /// The underlying CESR indexer (code + index + ondex + raw signature bytes).
    indexer: Indexer,
    /// Optional associated verfer (public key) for verification.
    verfer: Option<Verfer>,
}

impl Siger {
    /// Create a new Siger from an indexer code, index, ondex, and raw signature bytes.
    pub fn new(
        code: &str,
        index: usize,
        ondex: Option<usize>,
        raw: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let indexer = Indexer::new(code, index, ondex, raw)?;
        Ok(Self {
            indexer,
            verfer: None,
        })
    }

    /// Create a Siger with an associated Verfer.
    pub fn new_with_verfer(
        code: &str,
        index: usize,
        ondex: Option<usize>,
        raw: Vec<u8>,
        verfer: Verfer,
    ) -> Result<Self, CryptoError> {
        let indexer = Indexer::new(code, index, ondex, raw)?;
        Ok(Self {
            indexer,
            verfer: Some(verfer),
        })
    }

    /// Create a Siger from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let indexer = Indexer::from_qb64(qb64)?;
        Ok(Self {
            indexer,
            verfer: None,
        })
    }

    /// Set the verfer (public key) for verification.
    pub fn set_verfer(&mut self, verfer: Verfer) {
        self.verfer = Some(verfer);
    }

    /// The CESR indexer code identifying the signature algorithm.
    pub fn code(&self) -> &str {
        self.indexer.code()
    }

    /// The key index in the current signing key set.
    pub fn index(&self) -> usize {
        self.indexer.index()
    }

    /// The key index in the prior key set, if applicable.
    pub fn ondex(&self) -> Option<usize> {
        self.indexer.ondex()
    }

    /// The raw signature bytes.
    pub fn raw(&self) -> &[u8] {
        self.indexer.raw()
    }

    /// The associated verfer, if set.
    pub fn verfer(&self) -> Option<&Verfer> {
        self.verfer.as_ref()
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.indexer.qb64()?)
    }

    /// Verify this indexed signature over a message using the stored verfer.
    ///
    /// # Errors
    /// Returns `CryptoError::MissingVerfer` if no verfer has been set.
    pub fn verify(&self, message: &[u8]) -> Result<bool, CryptoError> {
        let verfer = self.verfer.as_ref().ok_or(CryptoError::MissingVerfer)?;
        verfer.verify(message, self.indexer.raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siger_new() {
        let raw = vec![0xAAu8; 64];
        let siger = Siger::new("A", 0, None, raw.clone()).unwrap();
        assert_eq!(siger.code(), "A");
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), None);
        assert_eq!(siger.raw(), raw.as_slice());
    }

    #[test]
    fn test_siger_qb64_roundtrip() {
        let raw = vec![0x42u8; 64];
        let siger = Siger::new("A", 3, None, raw.clone()).unwrap();
        let qb64 = siger.qb64().unwrap();

        let siger2 = Siger::from_qb64(&qb64).unwrap();
        assert_eq!(siger2.code(), "A");
        assert_eq!(siger2.index(), 3);
        assert_eq!(siger2.raw(), raw.as_slice());
    }

    #[test]
    fn test_siger_with_verfer() {
        let raw = vec![0x77u8; 64];
        let pubkey_raw = vec![0u8; 32]; // placeholder
        let verfer = Verfer::new("D", pubkey_raw).unwrap();
        let siger = Siger::new_with_verfer("A", 0, None, raw, verfer).unwrap();
        assert!(siger.verfer().is_some());
    }

    #[test]
    fn test_siger_verify_ed25519() {
        use ed25519_dalek::Signer;

        let seed: [u8; 32] = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();
        let message = b"siger verify test";

        let sig = signing_key.sign(message);
        let verfer = Verfer::new("D", pubkey).unwrap();
        let siger = Siger::new_with_verfer("A", 0, None, sig.to_bytes().to_vec(), verfer).unwrap();

        assert!(siger.verify(message).unwrap());
        assert!(!siger.verify(b"wrong").unwrap());
    }

    #[test]
    fn test_siger_verify_missing_verfer() {
        let raw = vec![0u8; 64];
        let siger = Siger::new("A", 0, None, raw).unwrap();
        assert!(siger.verify(b"anything").is_err());
    }

    #[test]
    fn test_siger_both_code() {
        let raw = vec![0x77u8; 64];
        let siger = Siger::new("B", 1, Some(2), raw).unwrap();
        assert_eq!(siger.code(), "B");
        assert_eq!(siger.index(), 1);
        assert_eq!(siger.ondex(), Some(2));
    }
}
