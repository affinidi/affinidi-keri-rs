//! Key state tracking for KERI identifiers.
//!
//! KeyState captures the current authoritative state of a KERI
//! identifier at a given point in its key event log.

use affinidi_keri_crypto::{Diger, Verfer};

use crate::error::CoreError;
use crate::event::{
    DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
    RotationEvent,
};
use crate::threshold::Threshold;

/// The current key state of a KERI identifier.
///
/// This is the computed result of processing a key event log (KEL)
/// up to and including a specific establishment event.
///
/// `#[non_exhaustive]`: this is a *returned* type — callers read it rather than
/// construct it — so sealing it costs nothing and lets key state carry more
/// about an identifier later without a breaking release. Build one with
/// [`KeyState::new`] or one of the `from_*` constructors.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// The delegator's prefix, for a delegated identifier.
    ///
    /// Retained so a later delegated rotation can be checked against the same
    /// delegator the identifier was incepted under — a `drt` naming a
    /// different delegator is an attempt to move control, not a rotation.
    pub delegator: Option<String>,
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
            delegator: None,
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

        // Validate backer threshold is satisfiable
        if backer_threshold > event.backers.len() {
            return Err(CoreError::Validation(format!(
                "backer threshold ({backer_threshold}) exceeds backer count ({})",
                event.backers.len()
            )));
        }

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
            delegator: None,
        })
    }

    /// Derive the initial key state from a delegated inception event.
    ///
    /// The delegator's authorisation is **not** checked here — that needs the
    /// delegator's KEL, which this type has no access to. Callers must go
    /// through `Kever::new_delegated`, which verifies the anchoring seal
    /// before this is reached.
    ///
    /// # Errors
    /// Returns `CoreError` if the event is not a well-formed inception.
    pub fn from_delegated_inception(event: &DelegatedInceptionEvent) -> Result<Self, CoreError> {
        let sn = parse_sn(&event.sn)?;
        if sn != 0 {
            return Err(CoreError::Validation(format!(
                "delegated inception event must have sn=0, got {sn}"
            )));
        }
        if event.delegator.is_empty() {
            return Err(CoreError::Validation(
                "delegated inception names no delegator (empty `di`)".into(),
            ));
        }

        let backer_threshold = parse_backer_threshold(&event.backer_threshold)?;
        if backer_threshold > event.backers.len() {
            return Err(CoreError::Validation(format!(
                "backer threshold ({backer_threshold}) exceeds backer count ({})",
                event.backers.len()
            )));
        }

        Ok(Self {
            prefix: event.prefix.clone(),
            sn: 0,
            said: event.said.clone(),
            threshold: event.keys_threshold.0.clone(),
            keys: event.keys.clone(),
            next_keys: event.next_keys.clone(),
            next_threshold: event.next_threshold.0.clone(),
            backer_threshold,
            backers: event.backers.clone(),
            config: event.config.clone(),
            last_event_digest: event.said.clone(),
            delegated: true,
            delegator: Some(event.delegator.clone()),
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

        // Verify next-key commitments: each rotation key must match a
        // digest committed to in the previous establishment event.
        verify_next_key_commitment(&event.keys, &self.next_keys)?;

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

        // Validate backer threshold is satisfiable
        if backer_threshold > new_backers.len() {
            return Err(CoreError::Validation(format!(
                "backer threshold ({backer_threshold}) exceeds backer count ({})",
                new_backers.len()
            )));
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
            delegator: self.delegator.clone(),
        })
    }

    /// Apply a delegated rotation event to produce a new key state.
    ///
    /// As with `from_delegated_inception`, the delegator's authorisation is
    /// verified by `Kever::verify_update_delegated`, not here.
    ///
    /// # Errors
    /// Returns `CoreError` if the rotation is invalid relative to the current
    /// state, or names a different delegator than the identifier was incepted
    /// under.
    pub fn apply_delegated_rotation(
        &self,
        event: &DelegatedRotationEvent,
    ) -> Result<Self, CoreError> {
        if !self.delegated {
            return Err(CoreError::Validation(
                "delegated rotation applied to an identifier that was not delegated".into(),
            ));
        }
        match self.delegator.as_deref() {
            Some(known) if known == event.delegator => {}
            Some(known) => {
                return Err(CoreError::Validation(format!(
                    "delegated rotation names delegator '{}' but the identifier was \
                     incepted under '{known}'",
                    event.delegator,
                )));
            }
            None => {
                return Err(CoreError::Validation(
                    "delegated identifier has no recorded delegator".into(),
                ));
            }
        }

        // The delegation-specific checks above are the only difference; the
        // rest of a `drt` is a `rot` and must satisfy exactly the same rules,
        // including the pre-rotation commitment.
        let as_rotation = RotationEvent {
            version: event.version.clone(),
            ilk: event.ilk.clone(),
            said: event.said.clone(),
            prefix: event.prefix.clone(),
            sn: event.sn.clone(),
            prior_said: event.prior_said.clone(),
            keys_threshold: event.keys_threshold.clone(),
            keys: event.keys.clone(),
            next_threshold: event.next_threshold.clone(),
            next_keys: event.next_keys.clone(),
            backer_threshold: event.backer_threshold.clone(),
            backers_remove: event.backers_remove.clone(),
            backers_add: event.backers_add.clone(),
            config: event.config.clone(),
            anchors: event.anchors.clone(),
        };
        self.apply_rotation(&as_rotation)
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

/// Verify that each rotation key matches a next-key digest commitment.
///
/// The rotation keys (`keys`) must correspond positionally to the
/// committed digests (`next_keys`) from the prior establishment event.
/// Each key is hashed using the algorithm indicated by the digest's CESR
/// code, and the result must match the committed digest.
fn verify_next_key_commitment(keys: &[String], next_keys: &[String]) -> Result<(), CoreError> {
    if keys.len() != next_keys.len() {
        return Err(CoreError::Validation(format!(
            "rotation key count ({}) does not match next-key commitment count ({})",
            keys.len(),
            next_keys.len()
        )));
    }

    for (i, (key_qb64, digest_qb64)) in keys.iter().zip(next_keys.iter()).enumerate() {
        let verfer = Verfer::from_qb64(key_qb64).map_err(|e| {
            CoreError::Validation(format!("invalid rotation key at index {i}: {e}"))
        })?;

        let diger = Diger::from_qb64(digest_qb64).map_err(|e| {
            CoreError::Validation(format!("invalid next-key digest at index {i}: {e}"))
        })?;

        // The commitment is a digest of the key's **qb64** form, not its raw
        // bytes: that is what keripy commits to, so digesting the raw bytes
        // rejects every rotation produced by the rest of the ecosystem.
        // `Verfer::from_qb64` above is what validates the key itself.
        let _ = &verfer;
        let matches = diger.verify(key_qb64.as_bytes()).map_err(|e| {
            CoreError::Validation(format!(
                "failed to verify next-key commitment at index {i}: {e}"
            ))
        })?;

        if !matches {
            return Err(CoreError::Validation(format!(
                "rotation key at index {i} does not match next-key commitment"
            )));
        }
    }

    Ok(())
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
    use affinidi_keri_crypto::Signer;

    /// Create a key qb64 and its next-key digest qb64 from a seed.
    fn make_key_pair(seed: [u8; 32]) -> (String, String) {
        let signer = Signer::new("A", seed.to_vec()).unwrap();
        let verfer = signer.verfer();
        let key_qb64 = verfer.qb64().unwrap();
        let digest_qb64 = Diger::from_data("E", key_qb64.as_bytes())
            .unwrap()
            .qb64()
            .unwrap();
        (key_qb64, digest_qb64)
    }

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
        let (key, digest) = make_key_pair([1u8; 32]);
        let icp = make_inception("PREFIX", vec![key.clone()], vec![digest.clone()]);
        let state = KeyState::from_inception(&icp).unwrap();
        assert_eq!(state.prefix, "PREFIX");
        assert_eq!(state.sn, 0);
        assert_eq!(state.said, "SAID_ICP");
        assert_eq!(state.keys, vec![key]);
        assert_eq!(state.next_keys, vec![digest]);
        assert_eq!(state.threshold, Threshold::Simple(1));
        assert!(!state.delegated);
    }

    #[test]
    fn test_key_state_from_inception_non_zero_sn() {
        let (key, digest) = make_key_pair([1u8; 32]);
        let mut icp = make_inception("PREFIX", vec![key], vec![digest]);
        icp.sn = "1".into();
        assert!(KeyState::from_inception(&icp).is_err());
    }

    #[test]
    fn test_apply_rotation() {
        // Inception key pair
        let (icp_key, _) = make_key_pair([1u8; 32]);
        // Next key pair — committed in inception, revealed in rotation
        let (next_key, next_digest) = make_key_pair([2u8; 32]);
        // Key pair for the rotation's own next commitment
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![next_key.clone()],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest.clone()],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        let new_state = state.apply_rotation(&rot).unwrap();
        assert_eq!(new_state.sn, 1);
        assert_eq!(new_state.keys, vec![next_key]);
        assert_eq!(new_state.next_keys, vec![next_next_digest]);
        assert_eq!(new_state.said, "SAID_ROT");
        assert_eq!(new_state.last_event_digest, "SAID_ROT");
    }

    #[test]
    fn test_apply_rotation_wrong_key_commitment() {
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (_, next_digest) = make_key_pair([2u8; 32]);
        // Use a different key that does NOT match the committed digest
        let (wrong_key, _) = make_key_pair([99u8; 32]);
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![wrong_key],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        let err = state.apply_rotation(&rot).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match next-key commitment"),
            "expected commitment mismatch error, got: {err}"
        );
    }

    #[test]
    fn test_apply_rotation_wrong_key_count() {
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (_, next_digest) = make_key_pair([2u8; 32]);
        let (next_key, _) = make_key_pair([2u8; 32]);
        let (extra_key, _) = make_key_pair([4u8; 32]);
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![next_key, extra_key],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest],
            backer_threshold: "0".into(),
            backers_remove: vec![],
            backers_add: vec![],
            config: vec![],
            anchors: vec![],
        };

        let err = state.apply_rotation(&rot).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match next-key commitment count"),
            "expected count mismatch error, got: {err}"
        );
    }

    #[test]
    fn test_apply_rotation_wrong_sn() {
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (next_key, next_digest) = make_key_pair([2u8; 32]);
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "5".into(), // should be 1
            prior_said: "SAID_ICP".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![next_key],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest],
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
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (next_key, next_digest) = make_key_pair([2u8; 32]);
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
        let state = KeyState::from_inception(&icp).unwrap();

        let rot = RotationEvent {
            version: "KERI10JSON000000_".into(),
            ilk: "rot".into(),
            said: "SAID_ROT".into(),
            prefix: "PREFIX".into(),
            sn: "1".into(),
            prior_said: "WRONG_PRIOR".into(),
            keys_threshold: ThresholdValue::from(1usize),
            keys: vec![next_key],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest],
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
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (_, next_digest) = make_key_pair([2u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key.clone()], vec![next_digest.clone()]);
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
        assert_eq!(new_state.keys, vec![icp_key]);
        assert_eq!(new_state.next_keys, vec![next_digest]);
    }

    #[test]
    fn test_apply_interaction_wrong_sn() {
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (_, next_digest) = make_key_pair([2u8; 32]);

        let icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
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
        let (icp_key, _) = make_key_pair([1u8; 32]);
        let (next_key, next_digest) = make_key_pair([2u8; 32]);
        let (_, next_next_digest) = make_key_pair([3u8; 32]);

        let mut icp = make_inception("PREFIX", vec![icp_key], vec![next_digest]);
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
            keys: vec![next_key],
            next_threshold: ThresholdValue::from(1usize),
            next_keys: vec![next_next_digest],
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
