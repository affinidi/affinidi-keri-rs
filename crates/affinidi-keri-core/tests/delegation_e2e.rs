//! End-to-end delegation: real signed `dip` and `drt` events, checked against
//! a delegator's anchoring seals.
//!
//! The point of these tests is the negative cases. A `dip` names its delegator
//! in the `di` field, which is a string the delegated identifier writes about
//! itself — so the interesting question is never "does a valid delegation
//! verify", it is "what happens when the anchor is missing, wrong, or for a
//! different event".

use affinidi_keri_core::delegation::{DelegationProof, DelegatorAnchors};
use affinidi_keri_core::error::CoreError;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_crypto::{Diger, Signer, Verfer};
use serde_json::json;

const DELEGATOR: &str = "EDelegator00000000000000000000000000000000AB";
const ANCHOR_SAID: &str = "EAnchorEvent000000000000000000000000000000AB";

fn signer(seed: u8) -> Signer {
    Signer::new("A", [seed; 32].to_vec()).expect("valid signer")
}

fn next_key_digest(s: &Signer) -> String {
    let key = s.verfer().qb64().expect("verfer qb64");
    Diger::from_data("E", key.as_bytes())
        .expect("digest")
        .qb64()
        .expect("qb64")
}

/// Fix the `v` field size before computing the SAID, so the SAID covers the
/// bytes the event will actually be serialized as.
fn fix_version_string(sad: &mut serde_json::Value) {
    let placeholder = "#".repeat(44);
    let self_addressing = sad.get("d") == sad.get("i");
    let (d, i) = (sad["d"].clone(), sad["i"].clone());
    sad["d"] = json!(placeholder);
    if self_addressing {
        sad["i"] = json!(placeholder);
    }
    let len = serde_json::to_vec(sad).expect("serialize").len();
    sad["v"] = json!(format!("KERI10JSON{len:06x}_"));
    sad["d"] = d;
    sad["i"] = i;
}

fn delegated_inception(current: &Signer, next: &Signer, delegator: &str) -> Serder {
    let mut sad = json!({
        "v": "KERI10JSON000000_",
        "t": "dip",
        "d": "",
        "i": "",
        "s": "0",
        "kt": "1",
        "k": [current.verfer().qb64().expect("qb64")],
        "nt": "1",
        "n": [next_key_digest(next)],
        "bt": "0",
        "b": [],
        "c": [],
        "a": [],
        "di": delegator,
    });
    fix_version_string(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

fn delegated_rotation(
    prefix: &str,
    sn: u64,
    prior: &str,
    current: &Signer,
    next: &Signer,
    delegator: &str,
) -> Serder {
    let mut sad = json!({
        "v": "KERI10JSON000000_",
        "t": "drt",
        "d": "",
        "i": prefix,
        "s": format!("{sn:x}"),
        "p": prior,
        "kt": "1",
        "k": [current.verfer().qb64().expect("qb64")],
        "nt": "1",
        "n": [next_key_digest(next)],
        "bt": "0",
        "br": [],
        "ba": [],
        "c": [],
        "a": [],
        "di": delegator,
    });
    fix_version_string(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

fn verfers(s: &Signer) -> Vec<Verfer> {
    vec![Verfer::from_qb64(&s.verfer().qb64().expect("qb64")).expect("verfer")]
}

fn sign(serder: &Serder, s: &Signer) -> Vec<affinidi_keri_crypto::Siger> {
    vec![s.sign_indexed(serder.raw(), 0, true).expect("sign")]
}

fn proof() -> DelegationProof {
    DelegationProof {
        sn: 3,
        said: ANCHOR_SAID.to_string(),
    }
}

/// A delegator whose verified KEL anchors exactly the seals it is given.
struct Delegator {
    seals: Vec<serde_json::Value>,
}

impl Delegator {
    fn anchoring(prefix: &str, sn: u64, said: &str) -> Self {
        Self {
            seals: vec![json!({ "i": prefix, "s": format!("{sn:x}"), "d": said })],
        }
    }

    fn anchoring_nothing() -> Self {
        Self { seals: Vec::new() }
    }
}

impl DelegatorAnchors for Delegator {
    fn anchors_at(
        &self,
        _delegator: &str,
        _sn: u64,
        _said: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, CoreError> {
        Ok(Some(self.seals.clone()))
    }
}

/// A delegator with no event at the location the proof names.
struct NoSuchEvent;

impl DelegatorAnchors for NoSuchEvent {
    fn anchors_at(
        &self,
        _delegator: &str,
        _sn: u64,
        _said: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, CoreError> {
        Ok(None)
    }
}

#[test]
fn anchored_delegated_inception_verifies() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let kever = Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
        .expect("an anchored delegated inception must verify");

    assert_eq!(kever.sn(), 0);
    assert_eq!(kever.prefix(), prefix);
    assert!(kever.state().delegated);
    assert_eq!(kever.state().delegator.as_deref(), Some(DELEGATOR));
}

#[test]
fn unanchored_delegated_inception_is_rejected() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);

    // The event is perfectly well formed and correctly signed by its own keys.
    // The only thing missing is the delegator's authorisation — which is the
    // entire point.
    let err = Kever::new_delegated(
        &dip,
        &sign(&dip, &cur),
        &verfers(&cur),
        &proof(),
        &NoSuchEvent,
    )
    .expect_err("a delegation with no anchor must not verify");
    assert!(err.to_string().contains("no verified event"), "{err}");
}

#[test]
fn delegator_anchoring_a_different_event_is_rejected() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    // The delegator anchors *something* for this identifier, but not this
    // event. Accepting it would let any past authorisation authorise any
    // future event.
    let source = Delegator::anchoring(&prefix, 0, "ESomeOtherEvent0000000000000000000000000AB");
    assert!(
        Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source).is_err()
    );
}

#[test]
fn delegator_anchoring_a_different_identifier_is_rejected() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);

    let source = Delegator::anchoring(
        "ESomeoneElse000000000000000000000000000000AB",
        0,
        &dip.said().expect("said"),
    );
    assert!(
        Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source).is_err()
    );
}

#[test]
fn delegator_anchoring_nothing_is_rejected() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);

    let source = Delegator::anchoring_nothing();
    assert!(
        Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source).is_err()
    );
}

#[test]
fn a_dip_is_refused_by_the_plain_inception_path() {
    let (cur, next) = (signer(1), signer(2));
    let dip = delegated_inception(&cur, &next, DELEGATOR);

    // The safe default: the path that cannot check delegation must not accept
    // a delegated event at all, and must say what to use instead.
    let err = Kever::new(&dip, &sign(&dip, &cur), &verfers(&cur))
        .expect_err("plain inception must refuse a dip");
    assert!(err.to_string().contains("new_delegated"), "{err}");
}

#[test]
fn anchored_delegated_rotation_verifies() {
    let (cur, next, after) = (signer(1), signer(2), signer(3));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let mut kever =
        Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
            .expect("inception verifies");

    let drt = delegated_rotation(
        &prefix,
        1,
        &kever.state().last_event_digest,
        &next,
        &after,
        DELEGATOR,
    );
    let rot_source = Delegator::anchoring(&prefix, 1, &drt.said().expect("said"));
    let state = kever
        .verify_update_delegated(&drt, &sign(&drt, &next), &proof(), &rot_source)
        .expect("an anchored delegated rotation must verify");
    kever.apply_verified_update(state);

    assert_eq!(kever.sn(), 1);
    assert_eq!(
        kever.state().keys,
        vec![next.verfer().qb64().expect("qb64")],
        "rotation should install the pre-rotated key",
    );
    assert_eq!(kever.state().delegator.as_deref(), Some(DELEGATOR));
}

#[test]
fn unanchored_delegated_rotation_is_rejected() {
    let (cur, next, after) = (signer(1), signer(2), signer(3));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let kever = Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
        .expect("inception verifies");

    let drt = delegated_rotation(
        &prefix,
        1,
        &kever.state().last_event_digest,
        &next,
        &after,
        DELEGATOR,
    );
    // Only the inception is anchored. A delegator that approved the inception
    // has not thereby approved every rotation that follows it.
    assert!(
        kever
            .verify_update_delegated(&drt, &sign(&drt, &next), &proof(), &source)
            .is_err()
    );
}

#[test]
fn delegated_rotation_under_a_different_delegator_is_rejected() {
    let (cur, next, after) = (signer(1), signer(2), signer(3));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let kever = Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
        .expect("inception verifies");

    // A rotation that swaps the delegator is an attempt to move control out
    // from under the original delegator, not a rotation.
    let usurper = "EUsurper0000000000000000000000000000000000AB";
    let drt = delegated_rotation(
        &prefix,
        1,
        &kever.state().last_event_digest,
        &next,
        &after,
        usurper,
    );
    let rot_source = Delegator::anchoring(&prefix, 1, &drt.said().expect("said"));
    let err = kever
        .verify_update_delegated(&drt, &sign(&drt, &next), &proof(), &rot_source)
        .expect_err("changing delegator mid-KEL must be refused");
    assert!(err.to_string().contains("incepted under"), "{err}");
}

#[test]
fn a_drt_is_refused_by_the_plain_update_path() {
    let (cur, next, after) = (signer(1), signer(2), signer(3));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let kever = Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
        .expect("inception verifies");

    let drt = delegated_rotation(
        &prefix,
        1,
        &kever.state().last_event_digest,
        &next,
        &after,
        DELEGATOR,
    );
    let err = kever
        .verify_update(&drt, &sign(&drt, &next))
        .expect_err("plain update must refuse a drt");
    assert!(err.to_string().contains("verify_update_delegated"), "{err}");
}

#[test]
fn a_delegated_rotation_still_honours_the_pre_rotation_commitment() {
    let (cur, next, after) = (signer(1), signer(2), signer(3));
    let dip = delegated_inception(&cur, &next, DELEGATOR);
    let prefix = dip.prefix().expect("prefix");

    let source = Delegator::anchoring(&prefix, 0, &dip.said().expect("said"));
    let kever = Kever::new_delegated(&dip, &sign(&dip, &cur), &verfers(&cur), &proof(), &source)
        .expect("inception verifies");

    // Rotate to a key that was never pre-rotated to, and have the delegator
    // anchor it. Delegator approval must not substitute for the pre-rotation
    // commitment.
    let uncommitted = signer(9);
    let drt = delegated_rotation(
        &prefix,
        1,
        &kever.state().last_event_digest,
        &uncommitted,
        &after,
        DELEGATOR,
    );
    let rot_source = Delegator::anchoring(&prefix, 1, &drt.said().expect("said"));
    assert!(
        kever
            .verify_update_delegated(&drt, &sign(&drt, &uncommitted), &proof(), &rot_source)
            .is_err(),
        "an anchored rotation to an uncommitted key must still be refused",
    );
}
