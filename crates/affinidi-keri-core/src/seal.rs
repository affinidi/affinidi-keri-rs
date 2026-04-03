//! Seal types for anchoring data in KERI events.
//!
//! Seals are small data structures embedded in event anchors (`a` field) that
//! reference other data: digests, Merkle roots, events, or event locations.

use serde::{Deserialize, Serialize};

/// A digest seal anchoring an arbitrary digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealDigest {
    /// The digest value (qb64-encoded).
    #[serde(rename = "d")]
    pub digest: String,
}

/// A root seal anchoring a Merkle tree root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRoot {
    /// The root digest (qb64-encoded).
    #[serde(rename = "rd")]
    pub root: String,
}

/// An event seal referencing another identifier's event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealEvent {
    /// The identifier prefix of the referenced event.
    #[serde(rename = "i")]
    pub prefix: String,
    /// The sequence number of the referenced event (hex string).
    #[serde(rename = "s")]
    pub sn: String,
    /// The digest (SAID) of the referenced event.
    #[serde(rename = "d")]
    pub digest: String,
}

/// A location seal referencing a specific event in a KEL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealLocation {
    /// The identifier prefix.
    #[serde(rename = "i")]
    pub prefix: String,
    /// The sequence number (hex string).
    #[serde(rename = "s")]
    pub sn: String,
    /// The event type (ilk tag).
    #[serde(rename = "t")]
    pub ilk: String,
    /// The prior event digest.
    #[serde(rename = "p")]
    pub prior: String,
}

/// Any seal type used in KERI anchoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seal {
    /// A digest seal.
    Digest(SealDigest),
    /// A root seal.
    Root(SealRoot),
    /// An event seal.
    Event(SealEvent),
    /// A location seal.
    Location(SealLocation),
}

impl Seal {
    /// Convert this seal to a JSON value.
    pub fn to_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            Seal::Digest(s) => serde_json::to_value(s),
            Seal::Root(s) => serde_json::to_value(s),
            Seal::Event(s) => serde_json::to_value(s),
            Seal::Location(s) => serde_json::to_value(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_digest_serialize() {
        let seal = SealDigest {
            digest: "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_".into(),
        };
        let json = serde_json::to_string(&seal).unwrap();
        assert_eq!(
            json,
            r#"{"d":"EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_"}"#
        );
    }

    #[test]
    fn test_seal_digest_deserialize() {
        let json = r#"{"d":"EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_"}"#;
        let seal: SealDigest = serde_json::from_str(json).unwrap();
        assert_eq!(seal.digest, "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_");
    }

    #[test]
    fn test_seal_root_serialize() {
        let seal = SealRoot {
            root: "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_".into(),
        };
        let json = serde_json::to_string(&seal).unwrap();
        assert_eq!(
            json,
            r#"{"rd":"EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_"}"#
        );
    }

    #[test]
    fn test_seal_event_serialize() {
        let seal = SealEvent {
            prefix: "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_".into(),
            sn: "0".into(),
            digest: "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_".into(),
        };
        let json = serde_json::to_string(&seal).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["i"], "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_");
        assert_eq!(parsed["s"], "0");
        assert_eq!(parsed["d"], "EBfxc4RiVY6saIFmUfEtG2F1HgVBhMiS36e2dNEb091_");
    }

    #[test]
    fn test_seal_event_deserialize() {
        let json = r#"{"i":"prefix","s":"1","d":"digest"}"#;
        let seal: SealEvent = serde_json::from_str(json).unwrap();
        assert_eq!(seal.prefix, "prefix");
        assert_eq!(seal.sn, "1");
        assert_eq!(seal.digest, "digest");
    }

    #[test]
    fn test_seal_location_serialize() {
        let seal = SealLocation {
            prefix: "prefix".into(),
            sn: "0".into(),
            ilk: "icp".into(),
            prior: "prior_digest".into(),
        };
        let json = serde_json::to_string(&seal).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["i"], "prefix");
        assert_eq!(parsed["s"], "0");
        assert_eq!(parsed["t"], "icp");
        assert_eq!(parsed["p"], "prior_digest");
    }

    #[test]
    fn test_seal_enum_to_json() {
        let seal = Seal::Digest(SealDigest {
            digest: "abc123".into(),
        });
        let val = seal.to_json_value().unwrap();
        assert_eq!(val["d"], "abc123");
    }
}
