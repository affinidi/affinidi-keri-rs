//! Cigar: non-indexed (standalone) signature.
//!
//! Supported CESR codes:
//! - `"0B"` - Ed25519 signature (64 bytes)
//! - `"0C"` - ECDSA secp256k1 signature (64 bytes)
//! - `"0I"` - ECDSA secp256r1 signature (64 bytes)

use affinidi_cesr::Matter;
use crate::error::CryptoError;
use crate::verfer::Verfer;

/// A non-indexed signature, wrapping a CESR `Matter` primitive.
///
/// Cigar represents a standalone signature that is not associated with a
/// key index. It is typically used in non-transferable receipt couples
/// (verfer + cigar).
#[derive(Debug, Clone)]
pub struct Cigar {
    /// The underlying CESR matter (code + raw signature bytes).
    matter: Matter,
    /// Optional associated verfer (public key) for verification.
    verfer: Option<Verfer>,
}

impl Cigar {
    /// Create a new Cigar from a CESR code and raw signature bytes.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        let matter = Matter::new(code, raw)?;
        Ok(Self {
            matter,
            verfer: None,
        })
    }

    /// Create a Cigar with an associated Verfer.
    pub fn new_with_verfer(code: &str, raw: Vec<u8>, verfer: Verfer) -> Result<Self, CryptoError> {
        let matter = Matter::new(code, raw)?;
        Ok(Self {
            matter,
            verfer: Some(verfer),
        })
    }

    /// Create a Cigar from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self {
            matter,
            verfer: None,
        })
    }

    /// Set the verfer (public key) for verification.
    pub fn set_verfer(&mut self, verfer: Verfer) {
        self.verfer = Some(verfer);
    }

    /// The CESR code identifying the signature algorithm.
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// The raw signature bytes.
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// The associated verfer, if set.
    pub fn verfer(&self) -> Option<&Verfer> {
        self.verfer.as_ref()
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.matter.qb64()?)
    }

    /// Verify this signature over a message using the stored verfer.
    ///
    /// # Errors
    /// Returns `CryptoError::MissingVerfer` if no verfer has been set.
    pub fn verify(&self, message: &[u8]) -> Result<bool, CryptoError> {
        let verfer = self.verfer.as_ref().ok_or(CryptoError::MissingVerfer)?;
        verfer.verify(message, self.matter.raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cigar_new() {
        let raw = vec![0xABu8; 64];
        let cigar = Cigar::new("0B", raw.clone()).unwrap();
        assert_eq!(cigar.code(), "0B");
        assert_eq!(cigar.raw(), raw.as_slice());
        assert!(cigar.verfer().is_none());
    }

    #[test]
    fn test_cigar_qb64_roundtrip() {
        let raw = vec![0x42u8; 64];
        let cigar = Cigar::new("0B", raw.clone()).unwrap();
        let qb64 = cigar.qb64().unwrap();

        let cigar2 = Cigar::from_qb64(&qb64).unwrap();
        assert_eq!(cigar2.code(), "0B");
        assert_eq!(cigar2.raw(), raw.as_slice());
    }

    #[test]
    fn test_cigar_verify_ed25519() {
        use ed25519_dalek::Signer;

        let seed: [u8; 32] = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();
        let message = b"cigar verify test";

        let sig = signing_key.sign(message);
        let verfer = Verfer::new("D", pubkey).unwrap();
        let cigar = Cigar::new_with_verfer("0B", sig.to_bytes().to_vec(), verfer).unwrap();

        assert!(cigar.verify(message).unwrap());
        assert!(!cigar.verify(b"wrong message").unwrap());
    }

    #[test]
    fn test_cigar_verify_missing_verfer() {
        let raw = vec![0u8; 64];
        let cigar = Cigar::new("0B", raw).unwrap();
        assert!(cigar.verify(b"anything").is_err());
    }

    #[test]
    fn test_cigar_set_verfer() {
        use ed25519_dalek::Signer;

        let seed: [u8; 32] = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();
        let message = b"set verfer test";

        let sig = signing_key.sign(message);
        let verfer = Verfer::new("D", pubkey).unwrap();

        let mut cigar = Cigar::new("0B", sig.to_bytes().to_vec()).unwrap();
        assert!(cigar.verfer().is_none());

        cigar.set_verfer(verfer);
        assert!(cigar.verfer().is_some());
        assert!(cigar.verify(message).unwrap());
    }
}
