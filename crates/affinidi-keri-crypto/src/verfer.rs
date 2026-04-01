//! Verfer: public verification key wrapper.
//!
//! Supported CESR codes:
//! - `"B"` - Ed25519 non-transferable prefix (32-byte public key)
//! - `"D"` - Ed25519 transferable prefix (32-byte public key)
//! - `"1AAA"` - ECDSA secp256k1 non-transferable (33-byte compressed public key)
//! - `"1AAB"` - ECDSA secp256k1 transferable (33-byte compressed public key)
//! - `"1AAI"` - ECDSA secp256r1 non-transferable (33-byte compressed public key)
//! - `"1AAJ"` - ECDSA secp256r1 transferable (33-byte compressed public key)

use affinidi_cesr::Matter;
use crate::error::CryptoError;

/// A public verification key, wrapping a CESR `Matter` primitive.
///
/// Verfer holds a public key and its associated CESR code, enabling
/// signature verification against messages.
#[derive(Debug, Clone)]
pub struct Verfer {
    /// The underlying CESR matter (code + raw public key bytes).
    matter: Matter,
}

impl Verfer {
    /// Create a new Verfer from a CESR code and raw public key bytes.
    ///
    /// # Errors
    /// Returns `CryptoError::UnsupportedAlgorithm` if the code is not a known
    /// verification key code, or `CryptoError::Cesr` if the raw bytes do not
    /// match the expected size for that code.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        Self::validate_code(code)?;
        let matter = Matter::new(code, raw)?;
        Ok(Self { matter })
    }

    /// Create a Verfer from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let matter = Matter::from_qb64(qb64)?;
        Self::validate_code(matter.code())?;
        Ok(Self { matter })
    }

    /// The CESR code identifying the key algorithm.
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// The raw public key bytes.
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.matter.qb64()?)
    }

    /// Whether this verfer uses a transferable code.
    pub fn transferable(&self) -> bool {
        matches!(self.matter.code(), "D" | "1AAB" | "1AAJ")
    }

    /// Verify a signature over a message using this public key.
    ///
    /// # Arguments
    /// * `message` - The message that was signed.
    /// * `signature` - The raw signature bytes (64 bytes for all supported algorithms).
    ///
    /// # Returns
    /// `Ok(true)` if verification succeeds, `Ok(false)` if the signature is invalid
    /// but well-formed, or `Err` if the key/signature bytes cannot be parsed.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        match self.matter.code() {
            "B" | "D" => self.verify_ed25519(message, signature),
            "1AAA" | "1AAB" => self.verify_secp256k1(message, signature),
            "1AAI" | "1AAJ" => self.verify_secp256r1(message, signature),
            code => Err(CryptoError::UnsupportedAlgorithm(code.to_string())),
        }
    }

    /// Verify an Ed25519 signature.
    fn verify_ed25519(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use ed25519_dalek::Verifier;

        let key_bytes: [u8; 32] = self.matter.raw().try_into().map_err(|_| {
            CryptoError::InvalidKeySize {
                expected: 32,
                got: self.matter.raw().len(),
            }
        })?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::InvalidKey("invalid Ed25519 public key".into()))?;

        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            CryptoError::InvalidSignature("invalid Ed25519 signature length".into())
        })?;
        let sig = Signature::from_bytes(&sig_bytes);

        match verifying_key.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify an ECDSA secp256k1 signature.
    fn verify_secp256k1(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(self.matter.raw())
            .map_err(|_| CryptoError::InvalidKey("invalid secp256k1 public key".into()))?;

        let sig = Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature("invalid secp256k1 signature".into()))?;

        match verifying_key.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify an ECDSA secp256r1 signature.
    fn verify_secp256r1(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(self.matter.raw())
            .map_err(|_| CryptoError::InvalidKey("invalid secp256r1 public key".into()))?;

        let sig = Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature("invalid secp256r1 signature".into()))?;

        match verifying_key.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Validate that the code is a supported verfer code.
    fn validate_code(code: &str) -> Result<(), CryptoError> {
        match code {
            "B" | "D" | "1AAA" | "1AAB" | "1AAI" | "1AAJ" => Ok(()),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "unsupported verfer code: {code}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verfer_new_ed25519() {
        // Generate a valid Ed25519 public key from a known seed
        let seed: [u8; 32] = [
            0x9f, 0x7b, 0xa8, 0x12, 0x34, 0x56, 0x78, 0x9a,
            0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();

        let verfer = Verfer::new("D", pubkey.clone()).unwrap();
        assert_eq!(verfer.code(), "D");
        assert_eq!(verfer.raw(), pubkey.as_slice());
        assert!(verfer.transferable());
    }

    #[test]
    fn test_verfer_qb64_roundtrip() {
        let seed: [u8; 32] = [1u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();

        let verfer = Verfer::new("B", pubkey.clone()).unwrap();
        let qb64 = verfer.qb64().unwrap();

        let verfer2 = Verfer::from_qb64(&qb64).unwrap();
        assert_eq!(verfer2.code(), "B");
        assert_eq!(verfer2.raw(), pubkey.as_slice());
        assert!(!verfer2.transferable());
    }

    #[test]
    fn test_verfer_ed25519_verify() {
        use ed25519_dalek::Signer;

        let seed: [u8; 32] = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes().to_vec();
        let message = b"test message for Ed25519";

        let sig = signing_key.sign(message);
        let verfer = Verfer::new("D", pubkey).unwrap();

        assert!(verfer.verify(message, &sig.to_bytes()).unwrap());
        // Tamper with message to ensure failure
        assert!(!verfer.verify(b"wrong message", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn test_verfer_secp256k1_verify() {
        use k256::ecdsa::{SigningKey, signature::Signer};

        let secret = [7u8; 32];
        let sk = SigningKey::from_slice(&secret).unwrap();
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_bytes().to_vec();

        let message = b"test message for secp256k1";
        let sig: k256::ecdsa::Signature = sk.sign(message);

        let verfer = Verfer::new("1AAB", pubkey).unwrap();
        assert!(verfer.verify(message, &sig.to_bytes()).unwrap());
        assert!(!verfer.verify(b"wrong", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn test_verfer_secp256r1_verify() {
        use p256::ecdsa::{SigningKey, signature::Signer};

        let secret = [9u8; 32];
        let sk = SigningKey::from_slice(&secret).unwrap();
        let vk = sk.verifying_key();
        let pubkey = vk.to_encoded_point(true).as_bytes().to_vec();

        let message = b"test message for secp256r1";
        let sig: p256::ecdsa::Signature = sk.sign(message);

        let verfer = Verfer::new("1AAJ", pubkey).unwrap();
        assert!(verfer.verify(message, &sig.to_bytes()).unwrap());
        assert!(!verfer.verify(b"wrong", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn test_verfer_unsupported_code() {
        assert!(Verfer::new("ZZ", vec![0u8; 32]).is_err());
    }
}
