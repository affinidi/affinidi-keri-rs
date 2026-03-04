//! Salter: salt and Argon2id key derivation.
//!
//! Salter wraps a CESR `Matter` containing random salt bytes and provides
//! methods to derive signing keys using Argon2id stretching. The salt
//! is combined with a path string to produce deterministic key material.
//!
//! Tier levels control Argon2id parameters:
//! - `"low"` - fast, low memory (m=65536, t=2, p=1)
//! - `"med"` - moderate (m=262144, t=3, p=1)
//! - `"high"` - slow, high memory (m=1048576, t=4, p=1)

use affinidi_cesr::Matter;
use crate::error::CryptoError;
use crate::signer::Signer;

/// Default salt code in CESR (128-bit random salt, code "0A").
const SALT_CODE: &str = "0A";

/// A salt used for deterministic key derivation.
///
/// Salter wraps a CESR `Matter` containing random salt bytes and provides
/// methods to derive signing keys and other secrets using Argon2id stretching.
#[derive(Debug, Clone)]
pub struct Salter {
    /// The underlying CESR matter (code + raw salt bytes).
    matter: Matter,
}

impl Salter {
    /// Create a new Salter from a CESR code and raw salt bytes.
    ///
    /// Typical code is `"0A"` (16-byte salt encoded as 2-char CESR code with 88 total
    /// qb64 chars). The raw bytes should be 16 bytes for a 128-bit salt.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        let matter = Matter::new(code, raw)?;
        Ok(Self { matter })
    }

    /// Generate a new random Salter with a 16-byte random salt.
    pub fn new_random() -> Result<Self, CryptoError> {
        use rand::RngCore;
        let mut raw = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut raw);
        Self::new(SALT_CODE, raw)
    }

    /// Create a Salter from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self { matter })
    }

    /// The CESR code identifying the salt type.
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// The raw salt bytes.
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.matter.qb64()?)
    }

    /// Derive a `Signer` from this salt using Argon2id key stretching.
    ///
    /// # Arguments
    /// * `code` - The signer code (e.g., `"A"` for Ed25519).
    /// * `path` - A derivation path string (used as associated data / salt extension).
    /// * `tier` - The Argon2id tier: `"low"`, `"med"`, or `"high"`.
    /// * `transferable` - Whether the derived signer should be transferable.
    ///
    /// The Argon2id output is used as the raw private key seed for the signer.
    pub fn signer(
        &self,
        code: &str,
        path: &str,
        tier: &str,
        transferable: bool,
    ) -> Result<Signer, CryptoError> {
        let key_size = Self::key_size_for_code(code)?;
        let seed = self.stretch(path, tier, key_size)?;
        Signer::new_with_transferable(code, seed, transferable)
    }

    /// Stretch the salt with a path using Argon2id to produce `output_len` bytes.
    pub fn stretch(
        &self,
        path: &str,
        tier: &str,
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use argon2::Argon2;

        let params = Self::tier_params(tier, output_len)?;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        // The path is used as the "password" and the salt raw bytes as the salt.
        let password = path.as_bytes();
        let salt = self.matter.raw();

        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

        Ok(output)
    }

    /// Get Argon2id parameters for a given tier.
    fn tier_params(tier: &str, output_len: usize) -> Result<argon2::Params, CryptoError> {
        let (m_cost, t_cost, p_cost) = match tier {
            "low" => (65536, 2, 1),      // ~64 MiB, 2 iterations
            "med" => (262144, 3, 1),     // ~256 MiB, 3 iterations
            "high" => (1048576, 4, 1),   // ~1 GiB, 4 iterations
            _ => {
                return Err(CryptoError::KeyDerivation(format!(
                    "unknown tier: {tier}, expected 'low', 'med', or 'high'"
                )));
            }
        };

        argon2::Params::new(m_cost, t_cost, p_cost, Some(output_len))
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))
    }

    /// Get the expected key size for a signer code.
    fn key_size_for_code(code: &str) -> Result<usize, CryptoError> {
        match code {
            "A" => Ok(32),           // Ed25519: 32-byte seed
            "1AAA" | "1AAB" => Ok(32), // secp256k1: 32-byte scalar
            "1AAI" | "1AAJ" => Ok(32), // secp256r1: 32-byte scalar
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "unsupported signer code for key derivation: {code}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salter_new() {
        let raw = vec![0xABu8; 16];
        let salter = Salter::new("0A", raw.clone()).unwrap();
        assert_eq!(salter.code(), "0A");
        assert_eq!(salter.raw(), raw.as_slice());
    }

    #[test]
    fn test_salter_new_random() {
        let salter1 = Salter::new_random().unwrap();
        let salter2 = Salter::new_random().unwrap();
        assert_eq!(salter1.code(), "0A");
        assert_eq!(salter1.raw().len(), 16);
        // Two random salts should (almost certainly) differ.
        assert_ne!(salter1.raw(), salter2.raw());
    }

    #[test]
    fn test_salter_qb64_roundtrip() {
        let raw = vec![0x42u8; 16];
        let salter = Salter::new("0A", raw.clone()).unwrap();
        let qb64 = salter.qb64().unwrap();

        let salter2 = Salter::from_qb64(&qb64).unwrap();
        assert_eq!(salter2.code(), "0A");
        assert_eq!(salter2.raw(), raw.as_slice());
    }

    #[test]
    fn test_salter_derive_ed25519_signer() {
        let salt_raw = vec![0x01u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer = salter.signer("A", "", "low", true).unwrap();
        assert_eq!(signer.code(), "A");
        assert_eq!(signer.verfer().code(), "D");
        assert_eq!(signer.raw().len(), 32);
    }

    #[test]
    fn test_salter_derive_deterministic() {
        // Same salt + path + tier should produce the same signer
        let salt_raw = vec![0x42u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer1 = salter.signer("A", "0", "low", true).unwrap();
        let signer2 = salter.signer("A", "0", "low", true).unwrap();

        assert_eq!(signer1.raw(), signer2.raw());
        assert_eq!(
            signer1.verfer().qb64().unwrap(),
            signer2.verfer().qb64().unwrap()
        );
    }

    #[test]
    fn test_salter_different_paths_different_keys() {
        let salt_raw = vec![0x42u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer1 = salter.signer("A", "0", "low", true).unwrap();
        let signer2 = salter.signer("A", "1", "low", true).unwrap();

        assert_ne!(signer1.raw(), signer2.raw());
    }

    #[test]
    fn test_salter_derive_secp256k1() {
        let salt_raw = vec![0x01u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer = salter.signer("1AAB", "", "low", true).unwrap();
        assert_eq!(signer.verfer().code(), "1AAB");
    }

    #[test]
    fn test_salter_derive_secp256r1() {
        let salt_raw = vec![0x01u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer = salter.signer("1AAJ", "", "low", true).unwrap();
        assert_eq!(signer.verfer().code(), "1AAJ");
    }

    #[test]
    fn test_salter_derived_signer_can_sign() {
        let salt_raw = vec![0x01u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();

        let signer = salter.signer("A", "", "low", true).unwrap();
        let message = b"salter derived key test";

        let cigar = signer.sign(message).unwrap();
        assert!(cigar.verify(message).unwrap());
    }

    #[test]
    fn test_salter_invalid_tier() {
        let salt_raw = vec![0x01u8; 16];
        let salter = Salter::new("0A", salt_raw).unwrap();
        assert!(salter.signer("A", "", "invalid", true).is_err());
    }
}
