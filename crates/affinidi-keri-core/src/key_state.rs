//! Key state tracking for KERI identifiers.
//!
//! KeyState captures the current authoritative state of a KERI
//! identifier at a given point in its key event log.

use crate::error::CoreError;
use crate::event::{InceptionEvent, InteractionEvent, RotationEvent};
use crate::threshold::Threshold;

/// The current key state of a KERI identifier.
///
/// This is the computed result of processing a key event log (KEL)
/// up to and including a specific establishment event.
#[derive(Debug, Clone)]
pub struct KeyState {
    /// The identifier prefix (qb64-encoded).
    pub prefix: String,
    /// The current sequence number.
    pub sn: u64,
    /// The SAID of the latest establishment event.
    pub said: String,
    /// The current signing threshold.
    pub threshold: Threshold,
    /// The current signing keys (qb64-encoded).
    pub keys: Vec<String>,
    /// The next key digests (qb64-encoded).
    pub next_keys: Vec<String>,
    /// The next signing threshold.
    pub next_threshold: Threshold,
    /// Backer (witness) threshold.
    pub backer_threshold: usize,
    /// Current backers/witnesses (qb64-encoded prefixes).
    pub backers: Vec<String>,
    /// Configuration traits.
    pub config: Vec<String>,
    /// The digest of the last event processed.
    pub last_event_digest: String,
    /// Whether this identifier is delegated.
    pub delegated: bool,
}

impl KeyState {
    /// Create a new default/empty key state for a given prefix.
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            sn: 0,
            said: String::new(),
            threshold: Threshold::Simple(0),
            keys: Vec::new(),
            next_keys: Vec::new(),
            next_threshold: Threshold::Simple(0),
            backer_threshold: 0,
            backers: Vec::new(),
            config: Vec::new(),
            last_event_digest: String::new(),
            delegated: false,
        }
    }

    /// Create initial key state from an inception event.
    ///
    /// # Errors
    /// Returns `CoreError` if the event fields cannot be parsed.
    pub fn from_inception(event: &InceptionEvent) -> Result<Self, CoreError> {
        let sn = parse_sn(&event.sn)?;
        if sn != 0 {
            return Err(CoreError::Validation(format!(
                "inception event must have sn=0, got {sn}"
            )));
        }

        let threshold = event.keys_threshold.0.clone();
        let next_threshold = event.next_threshold.0.clone();

        let backer_threshold = parse_backer_threshold(&event.backer_threshold)?;

        Ok(Self {
            prefix: event.prefix.clone(),
            sn: 0,
            said: event.said.clone(),
            threshold,
            keys: event.keys.clone(),
            next_keys: event.next_keys.clone(),
            next_threshold,
            backer_threshold,
            backers: event.backers.clone(),
            config: event.config.clone(),
            last_event_digest: event.said.clone(),
            delegated: false,
        })
    }

    /// Apply a rotation event to produce a new key state.
    ///
    /// This validates that the rotation is properly sequenced and updates
    /// keys, thresholds, and witness lists.
    ///
    /// # Errors
    /// Returns `CoreError` if the rotation event is invalid relative to current state.
    pub fn apply_rotation(&self, event: &RotationEvent) -> Result<Self, CoreError> {
        let sn = parse_sn(&event.sn)?;
        if sn != self.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.sn + 1,
                got: sn,
            });
        }

        if event.prefix != self.prefix {
            return Err(CoreError::InvalidPrefix(format!(
                "rotation prefix '{}' does not match state prefix '{}'",
                event.prefix, self.prefix
            )));
        }

        if event.prior_said != self.last_event_digest {
            return Err(CoreError::Validation(format!(
                "prior SAID mismatch: expected '{}', got '{}'",
                self.last_event_digest, event.prior_said
            )));
        }

        let threshold = event.keys_threshold.0.clone();
        let next_threshold = event.next_threshold.0.clone();
        let backer_threshold = parse_backer_threshold(&event.backer_threshold)?;

        // Compute new backer list: remove then add
        let mut new_backers = self.backers.clone();
        new_backers.retain(|b| !event.backers_remove.contains(b));
        for b in &event.backers_add {
            if !new_backers.contains(b) {
                new_backers.push(b.clone());
            }
        }

        Ok(Self {
            prefix: self.prefix.clone(),
            sn,
            said: event.said.clone(),
            threshold,
            keys: event.keys.clone(),
            next_keys: event.next_keys.clone(),
            next_threshold,
            backer_threshold,
            backers: new_backers,
            config: event.config.clone(),
            last_event_digest: event.said.clone(),
            delegated: self.delegated,
        })
    }

    /// Apply an interaction event to produce a new key state.
    ///
    /// Interaction events only update the sequence number and last event digest.
    /// They do not change keys, thresholds, or witnesses.
    ///
    /// # Errors
    /// Returns `CoreError` if the interaction event is invalid relative to current state.
    pub fn apply_interaction(&self, event: &InteractionEvent) -> Result<Self, CoreError> {
        let sn = parse_sn(&event.sn)?;
        if sn != self.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.sn + 1,
                got: sn,
            });
        }

        if event.prefix != self.prefix {
            return Err(CoreError::InvalidPrefix(format!(
                "interaction prefix '{}' does not match state prefix '{}'",
                event.prefix, self.prefix
            )));
        }

        if event.prior_said != self.last_event_digest {
            return Err(CoreError::Validation(format!(
                "prior SAID mismatch: expected '{}', got '{}'",
                self.last_event_digest, event.prior_said
            )));
        }

        let mut new_state = self.clone();
        new_state.sn = sn;
        new_state.last_event_digest = event.said.clone();
        Ok(new_state)
    }
}

/// Parse a sequence number from its hex string representation.
fn parse_sn(sn_str: &str) -> Result<u64, CoreError> {
    u64::from_str_radix(sn_str, 16)
        .map_err(|_| CoreError::Validation(format!("invalid sequence number: {sn_str}")))
}

/// Parse a backer threshold from its string representation.
fn parse_backer_threshold(bt_str: &str) -> Result<usize, CoreError> {
    bt_str
        .parse::<usize>()
        .map_err(|_| CoreError::Validation(format!("invalid backer threshold: {bt_str}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::ThresholdValue;

    fn make_inception(prefix: &str, keys: Vec<String>, next_keys: Vec<String>) -> InceptionEvent {
        InceptionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "icp".into(),
            said: "SAID_ICP".into(),
            prefix: prefix.into(),
            sn: "0".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys,
            next_threshold: ThresholdValue::from(1usize),
            next_keys,
            backer_threshold: "0".into(),
            backers: vec![],
            config: vec![],
            anchors: vec![],
        }
    }

    #[test]
    fn test_key_state_from_inception() {
        let icp = make_inception(
            "PREFIX",
            vec!["DKey1".into()],
            vec!["EDigest1".into()],
        );
        let state = KeyState::from_inception(&icp).unwrap();
        assert_eq!(state.prefix, "PREFIX");
        assert_eq!(state.sn, 0);
        assert_eq!(state.said, "SAID_ICP");
        assert_eq!(state.keys, vec!["DKey1"]);
        assert_eq!(state.next_keys, vec!["EDigest1"]);
        assert_eq!(state.threshold, Threshold::Simple(1));
        assert!(!state.delegated);
    }

    #[test]
    fn test_key_state_from_inception_non_zero_sn() {
        let mut icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        icp.sn = "1".into();
        assert!(KeyState::from_inception(&icp).is_err());
    }

    #[test]
    fn test_apply_rotation() {
        let icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DNewKey".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["ENewDigest".into()],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        let new_state = state.apply_rotation(&rot).unwrap();
        assert_eq!(new_state.sn, 1);
        assert_eq!(new_state.keys, vec!["DNewKey"]);
        assert_eq!(new_state.next_keys, vec!["ENewDigest"]);
        assert_eq!(new_state.said, "SAID_ROT");
        assert_eq!(new_state.last_event_digest, "SAID_ROT");
    }

    #[test]
    fn test_apply_rotation_wrong_sn() {
        let icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "5".into(), // should be 1
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DNewKey".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["ENewDigest".into()],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        assert!(state.apply_rotation(&rot).is_err());
    }

    #[test]
    fn test_apply_rotation_wrong_prior() {
        let icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "WRONG_PRIOR".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DNewKey".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["ENewDigest".into()],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        assert!(state.apply_rotation(&rot).is_err());
    }

    #[test]
    fn test_apply_interaction() {
        let icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        let state = KeyState::from_inception(&icp).unwrap();

        let ixn = InteractionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "ixn".into(),
            said: "SAID_IXN".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            anchors: vec![],
        };

        let new_state = state.apply_interaction(&ixn).unwrap();
        assert_eq!(new_state.sn, 1);
        assert_eq!(new_state.last_event_digest, "SAID_IXN");
        // Keys should be unchanged after interaction
        assert_eq!(new_state.keys, vec!["DKey1"]);
        assert_eq!(new_state.next_keys, vec!["EDigest1"]);
    }

    #[test]
    fn test_apply_interaction_wrong_sn() {
        let icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        let state = KeyState::from_inception(&icp).unwrap();

        let ixn = InteractionEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "ixn".into(),
            said: "SAID_IXN".into(),
            prefix: "PREFIX".into(),
            sn: "3".into(), // should be 1
            prior_said: "SAID_ICP".into(),
            anchors: vec![],
        };

        assert!(state.apply_interaction(&ixn).is_err());
    }

    #[test]
    fn test_rotation_with_witness_changes() {
        let mut icp = make_inception("PREFIX", vec!["DKey1".into()], vec!["EDigest1".into()]);
        icp.backers = vec!["BWit1".into(), "BWit2".into()];
        icp.backer_threshold = "2".into();
        let state = KeyState::from_inception(&icp).unwrap();
        assert_eq!(state.backers, vec!["BWit1", "BWit2"]);

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec!["DNewKey".into()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec!["ENewDigest".into()],
            backer_threshold: "2".into(),
            backers_remove: vec!["BWit1".into()],
            backers_add: vec!["BWit3".into()],
            config: vec![],
            anchors: vec![],
        };

        let new_state = state.apply_rotation(&rot).unwrap();
        assert_eq!(new_state.backers, vec!["BWit2", "BWit3"]);
    }
}
