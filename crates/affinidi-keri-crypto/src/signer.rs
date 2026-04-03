//! Signer: private signing key.
//!
//! The signer holds a private key (with zeroize-on-drop) and derives the
//! corresponding public verification key (`Verfer`). It can produce both
//! non-indexed (`Cigar`) and indexed (`Siger`) signatures.
//!
//! Supported private key codes:
//! - `"A"` - Ed25519 private key (32 bytes) -> Verfer code `"D"` (transferable)
//!   or `"B"` (non-transferable), Cigar code `"0B"`, Siger code `"A"`/`"B"`
//! - `"1AAA"` / `"1AAB"` - secp256k1 private key (32 bytes) ->
//!   Verfer code `"1AAB"` (transferable) or `"1AAA"` (non-transferable),
//!   Cigar code `"0C"`, Siger code `"C"`/`"D"`
//! - `"1AAI"` / `"1AAJ"` - secp256r1 private key (32 bytes) ->
//!   Verfer code `"1AAJ"` (transferable) or `"1AAI"` (non-transferable),
//!   Cigar code `"0I"`, Siger code `"E"`/`"F"`

use crate::cigar::Cigar;
use crate::error::CryptoError;
use crate::siger::Siger;
use crate::verfer::Verfer;
use zeroize::Zeroize;

/// A private signing key.
///
/// Signer wraps a private key with zeroize-on-drop protection and provides
/// methods to derive the public key (`Verfer`) and to sign messages.
#[derive(Debug)]
pub struct Signer {
    /// The raw private key bytes (zeroized on drop).
    raw: ZeroVec,
    /// The CESR code for the private key algorithm.
    code: String,
    /// Whether this signer uses a transferable prefix.
    transferable: bool,
    /// The corresponding public verification key.
    verfer: Verfer,
}

/// A wrapper around `Vec<u8>` that zeroizes on drop.
struct ZeroVec(Vec<u8>);

impl std::fmt::Debug for ZeroVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroVec([REDACTED; {}])", self.0.len())
    }
}

impl Drop for ZeroVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Signer {
    /// Create a new Signer from a CESR code and raw private key bytes.
    ///
    /// The corresponding `Verfer` (public key) is derived from the private key.
    /// By default, the signer is transferable.
    ///
    /// # Supported codes
    /// - `"A"` - Ed25519 (32-byte private key seed)
    /// - `"1AAA"` or `"1AAB"` - secp256k1 (32-byte scalar)
    /// - `"1AAI"` or `"1AAJ"` - secp256r1 (32-byte scalar)
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        Self::new_with_transferable(code, raw, true)
    }

    /// Create a new Signer with explicit transferability.
    pub fn new_with_transferable(
        code: &str,
        raw: Vec<u8>,
        transferable: bool,
    ) -> Result<Self, CryptoError> {
        let verfer = Self::derive_verfer(code, &raw, transferable)?;
        Ok(Self {
            raw: ZeroVec(raw),
            code: code.to_string(),
            transferable,
            verfer,
        })
    }

    /// The CESR code identifying the signing algorithm.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The raw private key bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw.0
    }

    /// Whether this signer uses a transferable prefix.
    pub fn transferable(&self) -> bool {
        self.transferable
    }

    /// The corresponding public verification key.
    pub fn verfer(&self) -> &Verfer {
        &self.verfer
    }

    /// Sign a message, producing a non-indexed `Cigar` signature.
    ///
    /// The Cigar carries the verfer for verification context.
    pub fn sign(&self, message: &[u8]) -> Result<Cigar, CryptoError> {
        let sig_raw = self.sign_raw(message)?;
        let sig_code = self.cigar_code();
        Cigar::new_with_verfer(sig_code, sig_raw, self.verfer.clone())
    }

    /// Sign a message, producing an indexed `Siger` signature.
    ///
    /// # Arguments
    /// * `message` - The message to sign.
    /// * `index` - The key index in the current signing set.
    /// * `only` - If true, use the "current only" indexed code (A/C/E).
    ///   If false, use the "both" indexed code (B/D/F) with `ondex == index`.
    pub fn sign_indexed(
        &self,
        message: &[u8],
        index: usize,
        only: bool,
    ) -> Result<Siger, CryptoError> {
        let sig_raw = self.sign_raw(message)?;
        let (sig_code, ondex) = if only {
            (self.siger_current_code(), None)
        } else {
            (self.siger_both_code(), Some(index))
        };
        Siger::new_with_verfer(sig_code, index, ondex, sig_raw, self.verfer.clone())
    }

    /// Produce the raw signature bytes.
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self.algorithm() {
            Algorithm::Ed25519 => self.sign_ed25519(message),
            Algorithm::Secp256k1 => self.sign_secp256k1(message),
            Algorithm::Secp256r1 => self.sign_secp256r1(message),
        }
    }

    /// Ed25519 signing.
    fn sign_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ed25519_dalek::Signer;

        let seed: [u8; 32] =
            self.raw
                .0
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    got: self.raw.0.len(),
                })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// secp256k1 signing.
    fn sign_secp256k1(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use k256::ecdsa::{SigningKey, signature::Signer};

        let signing_key = SigningKey::from_slice(&self.raw.0)
            .map_err(|_| CryptoError::InvalidKey("invalid signing key".into()))?;
        let sig: k256::ecdsa::Signature = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// secp256r1 signing.
    fn sign_secp256r1(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::{SigningKey, signature::Signer};

        let signing_key = SigningKey::from_slice(&self.raw.0)
            .map_err(|_| CryptoError::InvalidKey("invalid signing key".into()))?;
        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Derive the public verification key from the private key.
    fn derive_verfer(code: &str, raw: &[u8], transferable: bool) -> Result<Verfer, CryptoError> {
        match Self::algorithm_from_code(code)? {
            Algorithm::Ed25519 => {
                let seed: [u8; 32] = raw.try_into().map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    got: raw.len(),
                })?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let pubkey = signing_key.verifying_key().to_bytes().to_vec();
                let verfer_code = if transferable { "D" } else { "B" };
                Verfer::new(verfer_code, pubkey)
            }
            Algorithm::Secp256k1 => {
                use k256::ecdsa::SigningKey;

                let signing_key = SigningKey::from_slice(raw)
                    .map_err(|_| CryptoError::InvalidKey("invalid signing key".into()))?;
                let pubkey = signing_key.verifying_key().to_sec1_bytes().to_vec();
                let verfer_code = if transferable { "1AAB" } else { "1AAA" };
                Verfer::new(verfer_code, pubkey)
            }
            Algorithm::Secp256r1 => {
                use p256::ecdsa::SigningKey;

                let signing_key = SigningKey::from_slice(raw)
                    .map_err(|_| CryptoError::InvalidKey("invalid signing key".into()))?;
                let pubkey = signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                let verfer_code = if transferable { "1AAJ" } else { "1AAI" };
                Verfer::new(verfer_code, pubkey)
            }
        }
    }

    /// Determine the algorithm from the signer code.
    fn algorithm(&self) -> Algorithm {
        // This cannot fail because we validated in the constructor.
        Self::algorithm_from_code(&self.code).unwrap()
    }

    /// Map a signer code to its algorithm family.
    fn algorithm_from_code(code: &str) -> Result<Algorithm, CryptoError> {
        match code {
            "A" => Ok(Algorithm::Ed25519),
            "1AAA" | "1AAB" => Ok(Algorithm::Secp256k1),
            "1AAI" | "1AAJ" => Ok(Algorithm::Secp256r1),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "unsupported signer code: {code}"
            ))),
        }
    }

    /// Get the Cigar (non-indexed signature) CESR code.
    fn cigar_code(&self) -> &str {
        match self.algorithm() {
            Algorithm::Ed25519 => "0B",
            Algorithm::Secp256k1 => "0C",
            Algorithm::Secp256r1 => "0I",
        }
    }

    /// Get the Siger "current only" indexed signature CESR code.
    fn siger_current_code(&self) -> &str {
        match self.algorithm() {
            Algorithm::Ed25519 => "A",
            Algorithm::Secp256k1 => "C",
            Algorithm::Secp256r1 => "E",
        }
    }

    /// Get the Siger "both" indexed signature CESR code.
    fn siger_both_code(&self) -> &str {
        match self.algorithm() {
            Algorithm::Ed25519 => "B",
            Algorithm::Secp256k1 => "D",
            Algorithm::Secp256r1 => "F",
        }
    }
}

/// Internal enum for algorithm classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_ed25519_new() {
        let seed: [u8; 32] = [
            0x9f, 0x7b, 0xa8, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55,
        ];
        let signer = Signer::new("A", seed.to_vec()).unwrap();
        assert_eq!(signer.code(), "A");
        assert_eq!(signer.raw().len(), 32);
        assert!(signer.transferable());
        assert_eq!(signer.verfer().code(), "D");
        assert_eq!(signer.verfer().raw().len(), 32);
    }

    #[test]
    fn test_signer_ed25519_non_transferable() {
        let seed = [1u8; 32];
        let signer = Signer::new_with_transferable("A", seed.to_vec(), false).unwrap();
        assert!(!signer.transferable());
        assert_eq!(signer.verfer().code(), "B");
    }

    #[test]
    fn test_signer_ed25519_sign_verify() {
        let seed = [42u8; 32];
        let signer = Signer::new("A", seed.to_vec()).unwrap();
        let message = b"Ed25519 signer test message";

        // Non-indexed signature
        let cigar = signer.sign(message).unwrap();
        assert_eq!(cigar.code(), "0B");
        assert_eq!(cigar.raw().len(), 64);
        assert!(cigar.verify(message).unwrap());
        assert!(!cigar.verify(b"wrong").unwrap());

        // Indexed signature (current only)
        let siger = signer.sign_indexed(message, 0, true).unwrap();
        assert_eq!(siger.code(), "A");
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), None);
        assert!(siger.verify(message).unwrap());

        // Indexed signature (both)
        let siger = signer.sign_indexed(message, 2, false).unwrap();
        assert_eq!(siger.code(), "B");
        assert_eq!(siger.index(), 2);
        assert_eq!(siger.ondex(), Some(2));
        assert!(siger.verify(message).unwrap());
    }

    #[test]
    fn test_signer_ed25519_qb64_roundtrip() {
        let seed = [7u8; 32];
        let signer = Signer::new("A", seed.to_vec()).unwrap();
        let message = b"qb64 roundtrip test";

        let cigar = signer.sign(message).unwrap();
        let qb64 = cigar.qb64().unwrap();

        let cigar2 = Cigar::from_qb64(&qb64).unwrap();
        assert_eq!(cigar2.code(), "0B");
        assert_eq!(cigar2.raw(), cigar.raw());
    }

    #[test]
    fn test_signer_secp256k1_sign_verify() {
        let secret = [7u8; 32];
        let signer = Signer::new("1AAB", secret.to_vec()).unwrap();
        assert_eq!(signer.verfer().code(), "1AAB");
        assert_eq!(signer.verfer().raw().len(), 33);

        let message = b"secp256k1 signer test message";

        let cigar = signer.sign(message).unwrap();
        assert_eq!(cigar.code(), "0C");
        assert_eq!(cigar.raw().len(), 64);
        assert!(cigar.verify(message).unwrap());
        assert!(!cigar.verify(b"wrong").unwrap());

        let siger = signer.sign_indexed(message, 1, true).unwrap();
        assert_eq!(siger.code(), "C");
        assert!(siger.verify(message).unwrap());
    }

    #[test]
    fn test_signer_secp256k1_non_transferable() {
        let secret = [7u8; 32];
        let signer = Signer::new_with_transferable("1AAA", secret.to_vec(), false).unwrap();
        assert_eq!(signer.verfer().code(), "1AAA");
    }

    #[test]
    fn test_signer_secp256r1_sign_verify() {
        let secret = [9u8; 32];
        let signer = Signer::new("1AAJ", secret.to_vec()).unwrap();
        assert_eq!(signer.verfer().code(), "1AAJ");
        assert_eq!(signer.verfer().raw().len(), 33);

        let message = b"secp256r1 signer test message";

        let cigar = signer.sign(message).unwrap();
        assert_eq!(cigar.code(), "0I");
        assert_eq!(cigar.raw().len(), 64);
        assert!(cigar.verify(message).unwrap());
        assert!(!cigar.verify(b"wrong").unwrap());

        let siger = signer.sign_indexed(message, 0, false).unwrap();
        assert_eq!(siger.code(), "F");
        assert!(siger.verify(message).unwrap());
    }

    #[test]
    fn test_signer_secp256r1_non_transferable() {
        let secret = [9u8; 32];
        let signer = Signer::new_with_transferable("1AAI", secret.to_vec(), false).unwrap();
        assert_eq!(signer.verfer().code(), "1AAI");
    }

    #[test]
    fn test_signer_unsupported_code() {
        assert!(Signer::new("ZZ", vec![0u8; 32]).is_err());
    }

    #[test]
    fn test_signer_invalid_key_size() {
        assert!(Signer::new("A", vec![0u8; 16]).is_err());
    }

    #[test]
    fn test_signer_verfer_consistency() {
        // Verify that the verfer derived by the signer matches manual derivation
        let seed = [42u8; 32];
        let signer = Signer::new("A", seed.to_vec()).unwrap();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected_pubkey = signing_key.verifying_key().to_bytes();

        assert_eq!(signer.verfer().raw(), expected_pubkey.as_slice());
    }
}
