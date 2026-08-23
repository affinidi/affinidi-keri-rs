//! Diger: digest wrapper.
//!
//! Supported CESR codes (256-bit digests, 1-char code, 44-char qb64):
//! - `"E"` - Blake3-256
//! - `"F"` - Blake2b-256
//! - `"G"` - Blake2s-256
//! - `"H"` - SHA3-256
//! - `"I"` - SHA2-256
//!
//! Supported CESR codes (512-bit digests, 2-char code, 88-char qb64):
//! - `"0D"` - Blake3-512 (truncated from Blake3 XOF)
//! - `"0E"` - Blake2b-512
//! - `"0F"` - SHA3-512
//! - `"0G"` - SHA2-512

use affinidi_cesr::Matter;
use subtle::ConstantTimeEq;

use crate::error::CryptoError;

/// A cryptographic digest, wrapping a CESR `Matter` primitive.
///
/// Diger holds a digest value (hash output) and its associated CESR code,
/// identifying the hash algorithm used (Blake3-256, SHA2-256, etc.).
#[derive(Debug, Clone)]
pub struct Diger {
    /// The underlying CESR matter (code + raw digest bytes).
    matter: Matter,
}

impl Diger {
    /// Create a new Diger from a CESR code and pre-computed raw digest bytes.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CryptoError> {
        Self::validate_code(code)?;
        let matter = Matter::new(code, raw)?;
        Ok(Self { matter })
    }

    /// Compute the digest of `data` using the algorithm identified by `code`.
    ///
    /// # Errors
    /// Returns `CryptoError::UnsupportedAlgorithm` if the code is not a known
    /// digest code.
    pub fn from_data(code: &str, data: &[u8]) -> Result<Self, CryptoError> {
        let raw = Self::compute_digest(code, data)?;
        let matter = Matter::new(code, raw)?;
        Ok(Self { matter })
    }

    /// Create a Diger from a qb64-encoded string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CryptoError> {
        let matter = Matter::from_qb64(qb64)?;
        Self::validate_code(matter.code())?;
        Ok(Self { matter })
    }

    /// The CESR code identifying the digest algorithm.
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// The raw digest bytes.
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// The underlying CESR Matter.
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Encode as a qb64 string.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.matter.qb64()?)
    }

    /// Verify that `data` produces the same digest as stored in this Diger.
    ///
    /// Recomputes the digest using the same algorithm and compares.
    pub fn verify(&self, data: &[u8]) -> Result<bool, CryptoError> {
        let recomputed = Self::compute_digest(self.matter.code(), data)?;
        Ok(recomputed.ct_eq(self.matter.raw()).into())
    }

    /// Compute a digest for the given code and data.
    fn compute_digest(code: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match code {
            "E" => Ok(Self::blake3_256(data)),
            "F" => Ok(Self::blake2b_256(data)),
            "G" => Ok(Self::blake2s_256(data)),
            "H" => Ok(Self::sha3_256(data)),
            "I" => Ok(Self::sha2_256(data)),
            "0D" => Ok(Self::blake3_512(data)),
            "0E" => Ok(Self::blake2b_512(data)),
            "0F" => Ok(Self::sha3_512(data)),
            "0G" => Ok(Self::sha2_512(data)),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "unsupported digest code: {code}"
            ))),
        }
    }

    /// Blake3-256: 32-byte digest.
    fn blake3_256(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    /// Blake3-512: 64-byte output from Blake3 XOF.
    fn blake3_512(data: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output.to_vec()
    }

    /// Blake2b-256: 32-byte digest.
    fn blake2b_256(data: &[u8]) -> Vec<u8> {
        use blake2::Digest;
        let hash = blake2::Blake2b::<blake2::digest::consts::U32>::digest(data);
        hash.to_vec()
    }

    /// Blake2b-512: 64-byte digest.
    fn blake2b_512(data: &[u8]) -> Vec<u8> {
        use blake2::Digest;
        let hash = blake2::Blake2b::<blake2::digest::consts::U64>::digest(data);
        hash.to_vec()
    }

    /// Blake2s-256: 32-byte digest.
    fn blake2s_256(data: &[u8]) -> Vec<u8> {
        use blake2::Digest;
        let hash = blake2::Blake2s256::digest(data);
        hash.to_vec()
    }

    /// SHA3-256: 32-byte digest.
    fn sha3_256(data: &[u8]) -> Vec<u8> {
        use sha3::Digest;
        let hash = sha3::Sha3_256::digest(data);
        hash.to_vec()
    }

    /// SHA3-512: 64-byte digest.
    fn sha3_512(data: &[u8]) -> Vec<u8> {
        use sha3::Digest;
        let hash = sha3::Sha3_512::digest(data);
        hash.to_vec()
    }

    /// SHA2-256: 32-byte digest.
    fn sha2_256(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(data);
        hash.to_vec()
    }

    /// SHA2-512: 64-byte digest.
    fn sha2_512(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let hash = sha2::Sha512::digest(data);
        hash.to_vec()
    }

    /// Validate that the code is a supported digest code.
    fn validate_code(code: &str) -> Result<(), CryptoError> {
        match code {
            "E" | "F" | "G" | "H" | "I" | "0D" | "0E" | "0F" | "0G" => Ok(()),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "unsupported digest code: {code}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diger_blake3_256() {
        let data = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let diger = Diger::from_data("E", data).unwrap();
        let qb64 = diger.qb64().unwrap();
        assert_eq!(qb64, "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux");
        assert!(diger.verify(data).unwrap());
        assert!(!diger.verify(b"wrong data").unwrap());
    }

    #[test]
    fn test_diger_blake3_256_roundtrip() {
        let data = b"hello world";
        let diger = Diger::from_data("E", data).unwrap();
        let qb64 = diger.qb64().unwrap();

        let diger2 = Diger::from_qb64(&qb64).unwrap();
        assert_eq!(diger2.code(), "E");
        assert_eq!(diger2.raw(), diger.raw());
        assert!(diger2.verify(data).unwrap());
    }

    #[test]
    fn test_diger_sha2_256() {
        let data = b"test data for SHA2-256";
        let diger = Diger::from_data("I", data).unwrap();
        assert_eq!(diger.code(), "I");
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
        assert!(!diger.verify(b"tampered").unwrap());
    }

    #[test]
    fn test_diger_sha3_256() {
        let data = b"test data for SHA3-256";
        let diger = Diger::from_data("H", data).unwrap();
        assert_eq!(diger.code(), "H");
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_blake2b_256() {
        let data = b"test data for Blake2b-256";
        let diger = Diger::from_data("F", data).unwrap();
        assert_eq!(diger.code(), "F");
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_blake2s_256() {
        let data = b"test data for Blake2s-256";
        let diger = Diger::from_data("G", data).unwrap();
        assert_eq!(diger.code(), "G");
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_blake3_512() {
        let data = b"test data for Blake3-512";
        let diger = Diger::from_data("0D", data).unwrap();
        assert_eq!(diger.code(), "0D");
        assert_eq!(diger.raw().len(), 64);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_blake2b_512() {
        let data = b"test data for Blake2b-512";
        let diger = Diger::from_data("0E", data).unwrap();
        assert_eq!(diger.code(), "0E");
        assert_eq!(diger.raw().len(), 64);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_sha3_512() {
        let data = b"test data for SHA3-512";
        let diger = Diger::from_data("0F", data).unwrap();
        assert_eq!(diger.code(), "0F");
        assert_eq!(diger.raw().len(), 64);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_sha2_512() {
        let data = b"test data for SHA2-512";
        let diger = Diger::from_data("0G", data).unwrap();
        assert_eq!(diger.code(), "0G");
        assert_eq!(diger.raw().len(), 64);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_new_precomputed() {
        let raw = vec![0xABu8; 32];
        let diger = Diger::new("E", raw.clone()).unwrap();
        assert_eq!(diger.code(), "E");
        assert_eq!(diger.raw(), raw.as_slice());
    }

    #[test]
    fn test_diger_unsupported_code() {
        assert!(Diger::from_data("ZZ", b"data").is_err());
    }
}
