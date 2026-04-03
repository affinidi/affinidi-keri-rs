//! Prefixer: AID prefix derivation.
//!
//! Prefixer represents the self-addressing or self-certifying identifier
//! prefix for a KERI autonomic identifier. It can be derived either as:
//! - A **basic** prefix: the public key itself (the verfer's qb64 IS the prefix)
//! - A **self-addressing** prefix: a digest (SAID) of the inception event data

use affinidi_cesr::Matter;
use subtle::ConstantTimeEq;

use crate::diger::Diger;
use crate::error::CryptoError;
use crate::verfer::Verfer;

/// An Autonomic Identifier (AID) prefix, wrapping a CESR `Matter` primitive.
///
/// Prefixer represents the self-addressing or self-certifying identifier
/// prefix for a KERI autonomic identifier. It is derived from the inception
/// event or from a public key, depending on the derivation method.
#[derive(Debug, Clone)]
pub struct Prefixer {
    /// The underlying CESR matter (code + raw prefix bytes).
    matter: Matter,
}

impl Prefixer {
    /// Create a new Prefixer from a CESR code and raw bytes.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        let matter = Matter::new(code, raw)?;
        Ok(Self { matter })
    }

    /// Create a Prefixer from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self { matter })
    }

    /// Create a basic (non-self-addressing) prefix from a Verfer.
    ///
    /// The prefix is simply the Verfer's public key with the same CESR code.
    /// This is used for basic (non-self-addressing) AIDs where the identifier
    /// is the public key itself.
    pub fn new_basic(verfer: &Verfer) -> Result<Self, CryptoError> {
        let matter = Matter::new(verfer.code(), verfer.raw().to_vec())?;
        Ok(Self { matter })
    }

    /// Create a self-addressing prefix by computing a SAID digest of inception event data.
    ///
    /// # Arguments
    /// * `code` - The digest algorithm code (e.g., `"E"` for Blake3-256,
    ///   `"I"` for SHA2-256).
    /// * `ked` - The raw bytes of the key event data (inception event) to digest.
    ///   The `i` field (prefix) should be set to a placeholder of the correct size
    ///   before computing the SAID.
    ///
    /// The resulting Prefixer has the same code and raw bytes as the digest.
    pub fn new_self_addressing(code: &str, ked: &[u8]) -> Result<Self, CryptoError> {
        let diger = Diger::from_data(code, ked)?;
        let matter = Matter::new(code, diger.raw().to_vec())?;
        Ok(Self { matter })
    }

    /// The CESR code identifying the prefix derivation method.
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// The raw prefix bytes.
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.matter.qb64()?)
    }

    /// Verify that this prefix matches a given verfer (for basic prefixes).
    pub fn verify_basic(&self, verfer: &Verfer) -> bool {
        let code_eq = self
            .matter
            .code()
            .as_bytes()
            .ct_eq(verfer.code().as_bytes());
        let raw_eq = self.matter.raw().ct_eq(verfer.raw());
        (code_eq & raw_eq).into()
    }

    /// Verify that this prefix matches the SAID of given key event data
    /// (for self-addressing prefixes).
    pub fn verify_self_addressing(&self, ked: &[u8]) -> Result<bool, CryptoError> {
        let diger = Diger::from_data(self.matter.code(), ked)?;
        Ok(diger.raw().ct_eq(self.matter.raw()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefixer_basic() {
        let seed: [u8; 32] = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();

        let verfer = Verfer::new("D", pubkey.clone()).unwrap();
        let prefixer = Prefixer::new_basic(&verfer).unwrap();

        assert_eq!(prefixer.code(), "D");
        assert_eq!(prefixer.raw(), pubkey.as_slice());
        assert!(prefixer.verify_basic(&verfer));

        // qb64 should match verfer's qb64
        assert_eq!(prefixer.qb64().unwrap(), verfer.qb64().unwrap());
    }

    #[test]
    fn test_prefixer_self_addressing() {
        let ked = b"{\"v\":\"KERI10JSON000000_\",\"i\":\"\",\"s\":\"0\",\"t\":\"icp\"}";

        let prefixer = Prefixer::new_self_addressing("E", ked).unwrap();
        assert_eq!(prefixer.code(), "E");
        assert_eq!(prefixer.raw().len(), 32);

        // Verifying the same data should succeed
        assert!(prefixer.verify_self_addressing(ked).unwrap());

        // Different data should fail
        assert!(!prefixer.verify_self_addressing(b"different data").unwrap());
    }

    #[test]
    fn test_prefixer_qb64_roundtrip() {
        let raw = vec![0xABu8; 32];
        let prefixer = Prefixer::new("E", raw.clone()).unwrap();
        let qb64 = prefixer.qb64().unwrap();

        let prefixer2 = Prefixer::from_qb64(&qb64).unwrap();
        assert_eq!(prefixer2.code(), "E");
        assert_eq!(prefixer2.raw(), raw.as_slice());
    }

    #[test]
    fn test_prefixer_basic_non_transferable() {
        let seed: [u8; 32] = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();

        let verfer = Verfer::new("B", pubkey).unwrap();
        let prefixer = Prefixer::new_basic(&verfer).unwrap();

        assert_eq!(prefixer.code(), "B");
        assert!(prefixer.verify_basic(&verfer));
    }

    #[test]
    fn test_prefixer_basic_mismatch() {
        let seed1: [u8; 32] = [1u8; 32];
        let seed2: [u8; 32] = [2u8; 32];
        let sk1 = ed25519_dalek::SigningKey::from_bytes(&seed1);
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&seed2);
        let pk1 = sk1.verifying_key().to_bytes().to_vec();
        let pk2 = sk2.verifying_key().to_bytes().to_vec();

        let verfer1 = Verfer::new("D", pk1).unwrap();
        let verfer2 = Verfer::new("D", pk2).unwrap();
        let prefixer = Prefixer::new_basic(&verfer1).unwrap();

        assert!(prefixer.verify_basic(&verfer1));
        assert!(!prefixer.verify_basic(&verfer2));
    }

    #[test]
    fn test_prefixer_self_addressing_sha256() {
        let ked = b"test inception event data";
        let prefixer = Prefixer::new_self_addressing("I", ked).unwrap();
        assert_eq!(prefixer.code(), "I");
        assert!(prefixer.verify_self_addressing(ked).unwrap());
    }
}
