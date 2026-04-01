//! KERI event structures.
//!
//! Each event type is a flat struct with `serde` renames matching the KERI
//! single-letter field convention. Fields are defined in the canonical order
//! that KERI expects, which is preserved by `serde_json` when serializing
//! structs (fields are emitted in declaration order).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ilk::Ilk;
use crate::threshold::ThresholdValue;

/// Inception event body.
///
/// Field order: v, t, d, i, s, kt, k, nt, n, bt, b, c, a
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InceptionEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "icp").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier (digest of the event).
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix (same as SAID for self-addressing AIDs).
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number (as hex string, "0" for inception).
    #[serde(rename = "s")]
    pub sn: String,
    /// Signing threshold.
    #[serde(rename = "kt")]
    pub keys_threshold: ThresholdValue,
    /// Current signing keys (qb64-encoded).
    #[serde(rename = "k")]
    pub keys: Vec<String>,
    /// Next keys threshold.
    #[serde(rename = "nt")]
    pub next_threshold: ThresholdValue,
    /// Next key digests (qb64-encoded).
    #[serde(rename = "n")]
    pub next_keys: Vec<String>,
    /// Backer (witness) threshold.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Backer (witness) prefixes.
    #[serde(rename = "b")]
    pub backers: Vec<String>,
    /// Configuration traits.
    #[serde(rename = "c")]
    pub config: Vec<String>,
    /// Anchored data seals.
    #[serde(rename = "a")]
    pub anchors: Vec<serde_json::Value>,
}

/// Rotation event body.
///
/// Field order: v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "rot").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier.
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix.
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number (hex string).
    #[serde(rename = "s")]
    pub sn: String,
    /// Prior event SAID.
    #[serde(rename = "p")]
    pub prior_said: String,
    /// Signing threshold.
    #[serde(rename = "kt")]
    pub keys_threshold: ThresholdValue,
    /// Current signing keys (qb64-encoded).
    #[serde(rename = "k")]
    pub keys: Vec<String>,
    /// Next keys threshold.
    #[serde(rename = "nt")]
    pub next_threshold: ThresholdValue,
    /// Next key digests (qb64-encoded).
    #[serde(rename = "n")]
    pub next_keys: Vec<String>,
    /// Backer (witness) threshold.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Witnesses to remove.
    #[serde(rename = "br")]
    pub backers_remove: Vec<String>,
    /// Witnesses to add.
    #[serde(rename = "ba")]
    pub backers_add: Vec<String>,
    /// Configuration traits.
    #[serde(rename = "c")]
    pub config: Vec<String>,
    /// Anchored data seals.
    #[serde(rename = "a")]
    pub anchors: Vec<serde_json::Value>,
}

/// Interaction event body.
///
/// Field order: v, t, d, i, s, p, a
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "ixn").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier.
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix.
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number (hex string).
    #[serde(rename = "s")]
    pub sn: String,
    /// Prior event SAID.
    #[serde(rename = "p")]
    pub prior_said: String,
    /// Anchored data seals.
    #[serde(rename = "a")]
    pub anchors: Vec<serde_json::Value>,
}

/// Delegated inception event body.
///
/// Same as inception but with an additional `di` field for the delegator prefix.
/// Field order: v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di
///
/// # Security
/// TODO: Processing delegated events requires verifying that the delegator's
/// KEL contains an anchored seal authorizing this delegation. Without this
/// check, any party can claim delegation from any delegator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedInceptionEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "dip").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier.
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix.
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number (hex string, "0" for inception).
    #[serde(rename = "s")]
    pub sn: String,
    /// Signing threshold.
    #[serde(rename = "kt")]
    pub keys_threshold: ThresholdValue,
    /// Current signing keys (qb64-encoded).
    #[serde(rename = "k")]
    pub keys: Vec<String>,
    /// Next keys threshold.
    #[serde(rename = "nt")]
    pub next_threshold: ThresholdValue,
    /// Next key digests (qb64-encoded).
    #[serde(rename = "n")]
    pub next_keys: Vec<String>,
    /// Backer (witness) threshold.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Backer (witness) prefixes.
    #[serde(rename = "b")]
    pub backers: Vec<String>,
    /// Configuration traits.
    #[serde(rename = "c")]
    pub config: Vec<String>,
    /// Anchored data seals.
    #[serde(rename = "a")]
    pub anchors: Vec<serde_json::Value>,
    /// Delegator identifier prefix.
    #[serde(rename = "di")]
    pub delegator: String,
}

/// Delegated rotation event body.
///
/// Same as rotation but with an additional `di` field for the delegator prefix.
/// Field order: v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a, di
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedRotationEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "drt").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier.
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix.
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number (hex string).
    #[serde(rename = "s")]
    pub sn: String,
    /// Prior event SAID.
    #[serde(rename = "p")]
    pub prior_said: String,
    /// Signing threshold.
    #[serde(rename = "kt")]
    pub keys_threshold: ThresholdValue,
    /// Current signing keys (qb64-encoded).
    #[serde(rename = "k")]
    pub keys: Vec<String>,
    /// Next keys threshold.
    #[serde(rename = "nt")]
    pub next_threshold: ThresholdValue,
    /// Next key digests (qb64-encoded).
    #[serde(rename = "n")]
    pub next_keys: Vec<String>,
    /// Backer (witness) threshold.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Witnesses to remove.
    #[serde(rename = "br")]
    pub backers_remove: Vec<String>,
    /// Witnesses to add.
    #[serde(rename = "ba")]
    pub backers_add: Vec<String>,
    /// Configuration traits.
    #[serde(rename = "c")]
    pub config: Vec<String>,
    /// Anchored data seals.
    #[serde(rename = "a")]
    pub anchors: Vec<serde_json::Value>,
    /// Delegator identifier prefix.
    #[serde(rename = "di")]
    pub delegator: String,
}

/// Receipt event body.
///
/// A receipt acknowledges a specific event by referencing it via
/// its prefix, sequence number, and SAID.
///
/// Field order: v, t, d, i, s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEvent {
    /// Version string.
    #[serde(rename = "v")]
    pub version: String,
    /// Event type (always "rct").
    #[serde(rename = "t")]
    pub ilk: String,
    /// Self-Addressing Identifier (digest of this receipt).
    #[serde(rename = "d")]
    pub said: String,
    /// Identifier prefix of the receipted event.
    #[serde(rename = "i")]
    pub prefix: String,
    /// Sequence number of the receipted event (hex string).
    #[serde(rename = "s")]
    pub sn: String,
}

/// A KERI key event (any type).
#[derive(Debug, Clone)]
pub enum KeyEvent {
    /// Inception event.
    Inception(InceptionEvent),
    /// Rotation event.
    Rotation(RotationEvent),
    /// Interaction event.
    Interaction(InteractionEvent),
    /// Delegated inception event.
    DelegatedInception(DelegatedInceptionEvent),
    /// Delegated rotation event.
    DelegatedRotation(DelegatedRotationEvent),
}

impl KeyEvent {
    /// Return the ilk of this event.
    pub fn ilk(&self) -> Ilk {
        match self {
            Self::Inception(_) => Ilk::Icp,
            Self::Rotation(_) => Ilk::Rot,
            Self::Interaction(_) => Ilk::Ixn,
            Self::DelegatedInception(_) => Ilk::Dip,
            Self::DelegatedRotation(_) => Ilk::Drt,
        }
    }

    /// Return the sequence number as a u64 (parsing the hex string).
    ///
    /// # Errors
    /// Returns `CoreError::Validation` if the sequence number is not valid hex.
    pub fn sn(&self) -> Result<u64, CoreError> {
        let sn_str = match self {
            Self::Inception(e) => &e.sn,
            Self::Rotation(e) => &e.sn,
            Self::Interaction(e) => &e.sn,
            Self::DelegatedInception(e) => &e.sn,
            Self::DelegatedRotation(e) => &e.sn,
        };
        u64::from_str_radix(sn_str, 16)
            .map_err(|_| CoreError::Validation(format!("invalid sequence number: {sn_str}")))
    }

    /// Return the prefix.
    pub fn prefix(&self) -> &str {
        match self {
            Self::Inception(e) => &e.prefix,
            Self::Rotation(e) => &e.prefix,
            Self::Interaction(e) => &e.prefix,
            Self::DelegatedInception(e) => &e.prefix,
            Self::DelegatedRotation(e) => &e.prefix,
        }
    }

    /// Return the SAID.
    pub fn said(&self) -> &str {
        match self {
            Self::Inception(e) => &e.said,
            Self::Rotation(e) => &e.said,
            Self::Interaction(e) => &e.said,
            Self::DelegatedInception(e) => &e.said,
            Self::DelegatedRotation(e) => &e.said,
        }
    }

    /// Return the version string.
    pub fn version(&self) -> &str {
        match self {
            Self::Inception(e) => &e.version,
            Self::Rotation(e) => &e.version,
            Self::Interaction(e) => &e.version,
            Self::DelegatedInception(e) => &e.version,
            Self::DelegatedRotation(e) => &e.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::Threshold;

    #[test]
    fn test_inception_event_serialize_field_order() {
        let event = InceptionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "icp".into(),
            said: "".into(),
            prefix: "".into(),
            sn: "0".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DKey1".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["EDigest1".into()],
            backer_threshold: "0".into(),
            backers: vec![],
            config: vec![],
            anchors: vec![],
        };

        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify all expected fields are present
        assert!(val.get("v").is_some());
        assert!(val.get("t").is_some());
        assert!(val.get("d").is_some());
        assert!(val.get("i").is_some());
        assert!(val.get("s").is_some());
        assert!(val.get("kt").is_some());
        assert!(val.get("k").is_some());
        assert!(val.get("nt").is_some());
        assert!(val.get("n").is_some());
        assert!(val.get("bt").is_some());
        assert!(val.get("b").is_some());
        assert!(val.get("c").is_some());
        assert!(val.get("a").is_some());

        // Verify field order in the raw JSON string
        let v_pos = json.find("\"v\"").unwrap();
        let t_pos = json.find("\"t\"").unwrap();
        let d_pos = json.find("\"d\"").unwrap();
        let i_pos = json.find("\"i\"").unwrap();
        let s_pos = json.find("\"s\"").unwrap();
        let kt_pos = json.find("\"kt\"").unwrap();
        let k_pos = json.find("\"k\"").unwrap();

        assert!(v_pos < t_pos);
        assert!(t_pos < d_pos);
        assert!(d_pos < i_pos);
        assert!(i_pos < s_pos);
        assert!(s_pos < kt_pos);
        assert!(kt_pos < k_pos);
    }

    #[test]
    fn test_inception_event_deserialize() {
        let json = r#"{
            "v": "KERI10JSON0000fd_",
            "t": "icp",
            "d": "SAID_VALUE",
            "i": "PREFIX_VALUE",
            "s": "0",
            "kt": "1",
            "k": ["DKey1"],
            "nt": "1",
            "n": ["EDigest1"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        }"#;

        let event: InceptionEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.version, "KERI10JSON0000fd_");
        assert_eq!(event.ilk, "icp");
        assert_eq!(event.said, "SAID_VALUE");
        assert_eq!(event.prefix, "PREFIX_VALUE");
        assert_eq!(event.sn, "0");
        assert_eq!(event.keys, vec!["DKey1"]);
        assert_eq!(event.next_keys, vec!["EDigest1"]);
    }

    #[test]
    fn test_rotation_event_serialize() {
        let event = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "PRIOR_SAID".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DNewKey".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["ENextDigest".into()],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["t"], "rot");
        assert_eq!(val["p"], "PRIOR_SAID");
        assert!(val.get("br").is_some());
        assert!(val.get("ba").is_some());
    }

    #[test]
    fn test_interaction_event_serialize() {
        let event = InteractionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "ixn".into(),
            said: "".into(),
            prefix: "PREFIX".into(),
            sn: "2".into(),
            prior_said: "PRIOR_SAID".into(),
            anchors: vec![],
        };

        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["t"], "ixn");
        assert_eq!(val["p"], "PRIOR_SAID");
    }

    #[test]
    fn test_delegated_inception_event_serialize() {
        let event = DelegatedInceptionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "dip".into(),
            said: "".into(),
            prefix: "".into(),
            sn: "0".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DKey1".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["EDigest1".into()],
            backer_threshold: "0".into(),
            backers: vec![],
            config: vec![],
            anchors: vec![],
            delegator: "DELEGATOR_PREFIX".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["t"], "dip");
        assert_eq!(val["di"], "DELEGATOR_PREFIX");
    }

    #[test]
    fn test_key_event_enum() {
        let event = InceptionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "icp".into(),
            said: "SAID".into(),
            prefix: "PREFIX".into(),
            sn: "0".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![],
            backer_threshold: "0".into(),
            backers: vec![],
            config: vec![],
            anchors: vec![],
        };

        let ke = KeyEvent::Inception(event);
        assert_eq!(ke.ilk(), Ilk::Icp);
        assert_eq!(ke.sn().unwrap(), 0);
        assert_eq!(ke.prefix(), "PREFIX");
        assert_eq!(ke.said(), "SAID");
    }

    #[test]
    fn test_receipt_event_serialize() {
        let event = ReceiptEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rct".into(),
            said: "SAID_VALUE".into(),
            prefix: "PREFIX_VALUE".into(),
            sn: "0".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["v"], "KERI10JSON000000_");
        assert_eq!(val["t"], "rct");
        assert_eq!(val["d"], "SAID_VALUE");
        assert_eq!(val["i"], "PREFIX_VALUE");
        assert_eq!(val["s"], "0");

        // Verify field order
        let v_pos = json.find("\"v\"").unwrap();
        let t_pos = json.find("\"t\"").unwrap();
        let d_pos = json.find("\"d\"").unwrap();
        let i_pos = json.find("\"i\"").unwrap();
        let s_pos = json.find("\"s\"").unwrap();
        assert!(v_pos < t_pos);
        assert!(t_pos < d_pos);
        assert!(d_pos < i_pos);
        assert!(i_pos < s_pos);
    }

    #[test]
    fn test_receipt_event_deserialize() {
        let json = r#"{
            "v": "KERI10JSON0000fd_",
            "t": "rct",
            "d": "RECEIPT_SAID",
            "i": "EVENT_PREFIX",
            "s": "a"
        }"#;

        let event: ReceiptEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.version, "KERI10JSON0000fd_");
        assert_eq!(event.ilk, "rct");
        assert_eq!(event.said, "RECEIPT_SAID");
        assert_eq!(event.prefix, "EVENT_PREFIX");
        assert_eq!(event.sn, "a");
    }

    #[test]
    fn test_weighted_threshold_in_event() {
        let json = r#"{
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": [["1/2", "1/2", "1/2"]],
            "k": ["DKey1", "DKey2", "DKey3"],
            "nt": "1",
            "n": ["EDigest1"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        }"#;

        let event: InceptionEvent = serde_json::from_str(json).unwrap();
        match &event.keys_threshold.0 {
            Threshold::Weighted(clauses) => {
                assert_eq!(clauses.len(), 1);
                assert_eq!(clauses[0].len(), 3);
            }
            _ => panic!("expected weighted threshold"),
        }
    }
}
