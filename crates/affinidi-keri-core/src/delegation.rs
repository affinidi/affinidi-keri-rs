//! Delegation: verifying that a delegator authorised a delegated event.
//!
//! A delegated identifier's events (`dip`, `drt`) name their delegator in the
//! `di` field. That claim is worth nothing on its own — anyone can write any
//! prefix there. The event is only authorised if the **delegator's own KEL**
//! contains an event anchoring a seal that points back at it.
//!
//! The delegated event carries a *seal source couple* attachment naming which
//! of the delegator's events does the anchoring: `(sequence number, SAID)`.
//! Verification is therefore:
//!
//! 1. Read the seal source couple attached to the delegated event.
//! 2. Fetch the anchors from the delegator's event at that (sn, SAID) — but
//!    only if that event is already part of a **verified** KEL.
//! 3. Require one of those anchors to be an event seal naming this exact
//!    delegated event: its prefix, its sequence number and its SAID.
//!
//! Step 2 is why this cannot live inside `Kever`: a `Kever` tracks one
//! identifier and has no way to fetch, still less verify, another one's KEL.
//! The lookup is supplied by the caller through [`DelegatorAnchors`], and the
//! contract on that trait is the whole security boundary — an implementation
//! that returns anchors from an *unverified* KEL makes delegation checking
//! meaningless while appearing to work.

use affinidi_cesr::Matter;

use crate::error::CoreError;
use crate::seal::SealEvent;

/// Which event in the delegator's KEL is claimed to authorise a delegated
/// event, as carried by the delegated event's seal source couple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationProof {
    /// Sequence number of the delegator's anchoring event.
    pub sn: u64,
    /// SAID of the delegator's anchoring event.
    pub said: String,
}

impl DelegationProof {
    /// Build a proof from a seal source couple as parsed from a CESR stream.
    ///
    /// The couple is `(sequence number, SAID)`, both qb64. The sequence number
    /// is a CESR number primitive, not a decimal string.
    ///
    /// # Errors
    /// Returns `CoreError::ParseError` if either member is malformed, or if the
    /// sequence number does not fit in a `u64`.
    pub fn from_seal_source_couple(sn_qb64: &str, said_qb64: &str) -> Result<Self, CoreError> {
        let matter = Matter::from_qb64(sn_qb64).map_err(|e| {
            CoreError::ParseError(format!("invalid seal source sequence number: {e}"))
        })?;

        // CESR number primitives are big-endian, left-padded. Anything set
        // above the low 8 bytes is a sequence number we cannot represent, and
        // silently truncating it would point the check at the wrong event.
        let raw = matter.raw();
        let (high, low) = raw.split_at(raw.len().saturating_sub(8));
        if high.iter().any(|b| *b != 0) {
            return Err(CoreError::ParseError(
                "seal source sequence number exceeds u64".into(),
            ));
        }
        let mut buf = [0u8; 8];
        buf[8 - low.len()..].copy_from_slice(low);
        let sn = u64::from_be_bytes(buf);

        // Parse only to reject anything that is not a well-formed primitive;
        // the qb64 form is what the delegator's event will be matched on.
        Matter::from_qb64(said_qb64)
            .map_err(|e| CoreError::ParseError(format!("invalid seal source SAID: {e}")))?;

        Ok(Self {
            sn,
            said: said_qb64.to_string(),
        })
    }
}

/// Supplies the seals anchored in a delegator's **verified** key event log.
///
/// # Contract
///
/// `anchors_at` must return `Some` only for an event that the implementation
/// has already verified as part of the delegator's KEL — signatures checked
/// against the delegator's key state at that point, prior-event digest chain
/// intact. Returning anchors from an event that merely *parsed* defeats the
/// entire check: an attacker who can get an unverified event in front of the
/// resolver can then claim delegation from anyone.
///
/// Return `Ok(None)` when the event is not present, which is a normal outcome
/// — the delegated event may simply have arrived before its anchor.
pub trait DelegatorAnchors {
    /// The seals anchored (the `a` field) in `delegator`'s verified event at
    /// `sn` whose SAID is `said`.
    ///
    /// # Errors
    /// Returns `CoreError` if the lookup itself fails. "Not found" is
    /// `Ok(None)`, not an error.
    fn anchors_at(
        &self,
        delegator: &str,
        sn: u64,
        said: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, CoreError>;
}

/// Verify that `delegator` authorised the delegated event identified by
/// (`delegatee`, `sn`, `said`).
///
/// # Errors
/// Returns `CoreError::Validation` if the delegator's anchoring event is not
/// available, or is available but anchors no seal naming this exact event.
pub fn verify_delegation(
    delegatee: &str,
    sn: u64,
    said: &str,
    delegator: &str,
    proof: &DelegationProof,
    source: &dyn DelegatorAnchors,
) -> Result<(), CoreError> {
    if delegator.is_empty() {
        return Err(CoreError::Validation(
            "delegated event names no delegator (empty `di`)".into(),
        ));
    }
    if delegator == delegatee {
        return Err(CoreError::Validation(
            "delegated event names itself as its own delegator".into(),
        ));
    }

    let Some(anchors) = source.anchors_at(delegator, proof.sn, &proof.said)? else {
        return Err(CoreError::Validation(format!(
            "delegator '{delegator}' has no verified event at sn {} with SAID '{}' to \
             anchor the delegation of '{delegatee}'",
            proof.sn, proof.said,
        )));
    };

    // The delegator anchors the delegated event by its sequence number in hex,
    // which is how KERI writes `s` throughout.
    let expected_sn = format!("{sn:x}");

    let matched = anchors.iter().any(|anchor| {
        serde_json::from_value::<SealEvent>(anchor.clone()).is_ok_and(|seal| {
            seal.prefix == delegatee && seal.digest == said && seal.sn == expected_sn
        })
    });

    if !matched {
        return Err(CoreError::Validation(format!(
            "delegator '{delegator}' event at sn {} anchors no seal for '{delegatee}' \
             at sn {sn} with SAID '{said}'",
            proof.sn,
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DELEGATOR: &str = "EDelegatorPrefix000000000000000000000000000";
    const DELEGATEE: &str = "EDelegateePrefix000000000000000000000000000";
    const EVENT_SAID: &str = "EDelegatedEventSaid00000000000000000000000000";

    struct Anchors(Option<Vec<serde_json::Value>>);

    impl DelegatorAnchors for Anchors {
        fn anchors_at(
            &self,
            _delegator: &str,
            _sn: u64,
            _said: &str,
        ) -> Result<Option<Vec<serde_json::Value>>, CoreError> {
            Ok(self.0.clone())
        }
    }

    fn proof() -> DelegationProof {
        DelegationProof {
            sn: 1,
            said: "EAnchoringEventSaid0000000000000000000000000".to_string(),
        }
    }

    fn seal(prefix: &str, sn: &str, digest: &str) -> serde_json::Value {
        json!({ "i": prefix, "s": sn, "d": digest })
    }

    #[test]
    fn accepts_a_matching_event_seal() {
        let source = Anchors(Some(vec![seal(DELEGATEE, "0", EVENT_SAID)]));
        verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATOR, &proof(), &source)
            .expect("matching seal should authorise the delegation");
    }

    #[test]
    fn accepts_a_seal_among_others() {
        let source = Anchors(Some(vec![
            json!({ "d": "ESomeDigestSeal000000000000000000000000000000" }),
            seal(
                "EOtherPrefix00000000000000000000000000000000",
                "0",
                EVENT_SAID,
            ),
            seal(DELEGATEE, "0", EVENT_SAID),
        ]));
        verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATOR, &proof(), &source)
            .expect("a matching seal alongside others should still authorise");
    }

    #[test]
    fn rejects_when_the_delegator_event_is_absent() {
        let source = Anchors(None);
        let err = verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATOR, &proof(), &source)
            .expect_err("no anchoring event means no authorisation");
        assert!(err.to_string().contains("no verified event"), "{err}");
    }

    #[test]
    fn rejects_a_seal_for_a_different_identifier() {
        let source = Anchors(Some(vec![seal(
            "EOtherPrefix00000000000000000000000000000000",
            "0",
            EVENT_SAID,
        )]));
        assert!(verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATOR, &proof(), &source).is_err());
    }

    #[test]
    fn rejects_a_seal_for_a_different_event() {
        let source = Anchors(Some(vec![seal(
            DELEGATEE,
            "0",
            "EDifferentEventSaid00000000000000000000000000",
        )]));
        assert!(verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATOR, &proof(), &source).is_err());
    }

    #[test]
    fn rejects_a_seal_at_a_different_sequence_number() {
        // The seal names sn 0 while the event being checked is sn 1: a replay
        // of an earlier authorisation must not authorise a later event.
        let source = Anchors(Some(vec![seal(DELEGATEE, "0", EVENT_SAID)]));
        assert!(verify_delegation(DELEGATEE, 1, EVENT_SAID, DELEGATOR, &proof(), &source).is_err());
    }

    #[test]
    fn sequence_numbers_are_matched_in_hex() {
        // sn 26 is "1a", not "26" — matching decimally would reject a valid
        // seal (or, worse, accept the wrong one).
        let source = Anchors(Some(vec![seal(DELEGATEE, "1a", EVENT_SAID)]));
        verify_delegation(DELEGATEE, 26, EVENT_SAID, DELEGATOR, &proof(), &source)
            .expect("sequence numbers are hex in KERI");
    }

    #[test]
    fn rejects_an_empty_delegator() {
        let source = Anchors(Some(vec![seal(DELEGATEE, "0", EVENT_SAID)]));
        assert!(verify_delegation(DELEGATEE, 0, EVENT_SAID, "", &proof(), &source).is_err());
    }

    #[test]
    fn rejects_self_delegation() {
        let source = Anchors(Some(vec![seal(DELEGATEE, "0", EVENT_SAID)]));
        assert!(
            verify_delegation(DELEGATEE, 0, EVENT_SAID, DELEGATEE, &proof(), &source).is_err(),
            "an identifier must not be able to authorise its own delegation",
        );
    }

    #[test]
    fn parses_a_seal_source_couple() {
        // 0A + 22 base64 chars = a 16-byte number primitive; this one is 1.
        let sn_qb64 = "0AAAAAAAAAAAAAAAAAAAAAAB";
        let said = "EAnchoringEventSaid0000000000000000000000000";
        let parsed = DelegationProof::from_seal_source_couple(sn_qb64, said)
            .expect("well-formed couple should parse");
        assert_eq!(parsed.sn, 1);
        assert_eq!(parsed.said, said);
    }

    #[test]
    fn parses_a_zero_sequence_number() {
        let parsed =
            DelegationProof::from_seal_source_couple("0AAAAAAAAAAAAAAAAAAAAAAA", EVENT_SAID)
                .expect("sn 0 should parse");
        assert_eq!(parsed.sn, 0);
    }

    #[test]
    fn rejects_a_malformed_seal_source_couple() {
        assert!(DelegationProof::from_seal_source_couple("not-qb64", EVENT_SAID).is_err());
        assert!(
            DelegationProof::from_seal_source_couple("0AAAAAAAAAAAAAAAAAAAAAAB", "nope").is_err()
        );
    }
}
