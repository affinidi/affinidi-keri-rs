//! Conformance against keripy's KERI v2 implementation.
//!
//! Every fixture in `fixtures/keripy-v2` was built by keripy, published the
//! way keripy replays a log, and re-read by keripy (see the README there).
//! This test reads each one the way a resolver does — parse the stream, feed
//! it to `Kever` event by event — and requires the key state keripy reached,
//! field for field. Where a scenario must be refused, it requires the refusal
//! at that event and the state from before it.
//!
//! Positions referred to (P1–P8) are those of "did:webs on KERI v2"
//! (OpenVTC/verifiable-trust-infrastructure,
//! docs/05-design-notes/did-webs-keri-v2.md).

use std::path::{Path, PathBuf};

use affinidi_keri_core::CoreError;
use affinidi_keri_core::delegation::{DelegationProof, DelegatorAnchors};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, ParsedMessage};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::Verfer;
use serde_json::Value;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keripy-v2")
}

struct Fixture {
    expect: String,
    keripy: Value,
    published: Vec<u8>,
    submitted: Option<Vec<u8>>,
}

fn fixture(name: &str) -> Fixture {
    let json: Value =
        serde_json::from_slice(&std::fs::read(dir().join(format!("{name}.json"))).unwrap())
            .unwrap();
    Fixture {
        expect: json["expect"].as_str().unwrap().to_string(),
        keripy: json["keripy"].clone(),
        published: std::fs::read(dir().join(format!("{name}.cesr"))).unwrap(),
        submitted: std::fs::read(dir().join(format!("{name}.submitted.cesr"))).ok(),
    }
}

/// What feeding a stream to `Kever` produced.
struct Replay {
    kever: Kever,
    /// The last accepted event's ilk and protocol version.
    last_ilk: String,
    last_version: String,
    /// The last accepted establishment event's sequence number.
    establishment_sn: u64,
    /// The first refused event, if any: its index and the error.
    refused: Option<(usize, CoreError)>,
}

fn version_of(msg: &ParsedMessage) -> String {
    let v = msg.serder.version.as_ref().expect("a version string");
    format!("{}.{}", v.major, v.minor)
}

/// Feed messages to `Kever` in order, stopping at the first refusal.
fn replay(messages: &[ParsedMessage]) -> Replay {
    let icp = &messages[0];
    let verfers: Vec<Verfer> = icp.serder.sad()["k"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| Verfer::from_qb64(k.as_str().unwrap()).unwrap())
        .collect();
    let kever = Kever::new(&icp.serder, icp.controller_sigs(), &verfers)
        .expect("keripy's inception verifies");
    let mut out = Replay {
        kever,
        last_ilk: icp.serder.ilk().unwrap(),
        last_version: version_of(icp),
        establishment_sn: 0,
        refused: None,
    };
    for (i, msg) in messages.iter().enumerate().skip(1) {
        match out.kever.update(&msg.serder, msg.controller_sigs()) {
            Ok(()) => {
                out.last_ilk = msg.serder.ilk().unwrap();
                out.last_version = version_of(msg);
                if out.last_ilk == "rot" {
                    out.establishment_sn = out.kever.sn();
                }
            }
            Err(e) => {
                out.refused = Some((i, e));
                break;
            }
        }
    }
    out
}

/// Require exactly the key state keripy reached.
fn assert_state(name: &str, r: &Replay, k: &Value) {
    let s = r.kever.state();
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(s.prefix, k["prefix"].as_str().unwrap(), "{name}: prefix");
    assert_eq!(s.sn, k["sn"].as_u64().unwrap(), "{name}: sn");
    assert_eq!(
        s.last_event_digest,
        k["said"].as_str().unwrap(),
        "{name}: said"
    );
    assert_eq!(r.last_ilk, k["ilk"].as_str().unwrap(), "{name}: ilk");
    assert_eq!(
        r.last_version,
        k["version"].as_str().unwrap(),
        "{name}: version"
    );
    assert_eq!(s.keys, strings(&k["keys"]), "{name}: keys");
    assert_eq!(s.next_keys, strings(&k["n"]), "{name}: n");
    // keripy writes a single-clause weighted threshold flat (["1/2","1"]);
    // compare thresholds, not their spelling.
    assert_eq!(
        s.threshold,
        Threshold::from_json_value(&k["kt"]).unwrap(),
        "{name}: kt"
    );
    assert_eq!(
        s.next_threshold,
        Threshold::from_json_value(&k["nt"]).unwrap(),
        "{name}: nt"
    );
    assert_eq!(
        (r.establishment_sn, s.said.as_str()),
        (
            k["establishment"]["sn"].as_u64().unwrap(),
            k["establishment"]["said"].as_str().unwrap()
        ),
        "{name}: establishment event"
    );
}

/// A scenario keripy accepted, and a conforming verifier must accept too.
fn accepts(name: &str) {
    let f = fixture(name);
    assert_eq!(f.expect, "accept", "{name}");
    let messages = parser::parse_all(&f.published)
        .unwrap_or_else(|e| panic!("{name}: keripy's stream must parse: {e}"));
    for m in &messages {
        assert!(!m.has_uninterpreted_attachments(), "{name}");
    }
    let r = replay(&messages);
    if let Some((i, e)) = &r.refused {
        panic!("{name}: event {i} must verify: {e}");
    }
    assert_state(name, &r, &f.keripy);
}

#[test]
fn v1_basic() {
    // A counter-less stream is v1 (P1); keripy's own parser needs telling.
    accepts("v1-basic");
}

#[test]
fn v2_basic() {
    accepts("v2-basic");
}

#[test]
fn v2_multisig_2_of_3() {
    accepts("v2-multisig-2of3");
}

#[test]
fn v2_recovery_key_alone_rotates() {
    accepts("v2-recovery-by-k");
}

#[test]
fn v2_routine_and_recovery_keys_rotate() {
    accepts("v2-recovery-by-r-and-k");
}

#[test]
fn a_kel_migrated_from_v1_to_v2_verifies() {
    // keripy republishes the v1 events under the v2 genus, with 2.x
    // attachments: attachments follow the stream, bodies carry their own
    // version (P2).
    let f = fixture("migrated-v1-to-v2");
    let messages = parser::parse_all(&f.published).unwrap();
    let versions: Vec<String> = messages.iter().map(version_of).collect();
    assert_eq!(versions, ["1.0", "1.0", "2.0", "2.0"]);
    accepts("migrated-v1-to-v2");
}

#[test]
fn the_routine_key_alone_cannot_rotate() {
    let f = fixture("v2-recovery-routine-alone");
    assert_eq!(f.expect, "refuse-rotation");

    // keripy publishes only what it accepted: its stream stops before the
    // rotation, and both read it to the same state.
    let published = replay(&parser::parse_all(&f.published).unwrap());
    assert!(published.refused.is_none());
    assert_state("routine-alone (published)", &published, &f.keripy);

    // The stream as submitted carries the rotation signed by R' alone. It
    // meets the rotation's own kt but not the prior nt [["1/2","1"]].
    let submitted = parser::parse_all(f.submitted.as_ref().unwrap()).unwrap();
    let r = replay(&submitted);
    match &r.refused {
        Some((2, CoreError::ThresholdNotMet)) => {}
        other => panic!("the rotation at event 2 must be refused for its threshold, got {other:?}"),
    }
    assert_state("routine-alone (submitted)", &r, &f.keripy);
}

#[test]
fn a_kel_never_goes_down_a_version() {
    // DIVERGENCE: keripy accepts a v1 ixn after a v2 icp (its state is at sn
    // 1). Refusing it is VTI's position (P2), recorded on
    // kswg-did-method-webs-specification#216.
    let f = fixture("downgrade-v2-to-v1");
    assert_eq!(f.expect, "refuse-event-1");
    assert_eq!(f.keripy["sn"], 1, "keripy accepted the decrease");

    for (label, stream) in [
        ("published", &f.published),
        ("submitted", f.submitted.as_ref().unwrap()),
    ] {
        let messages = parser::parse_all(stream).unwrap();
        let r = replay(&messages);
        match &r.refused {
            Some((1, CoreError::Validation(msg))) if msg.contains("lower protocol version") => {}
            other => {
                panic!("{label}: event 1 must be refused as a version decrease, got {other:?}")
            }
        }
        let s = r.kever.state();
        assert_eq!(s.sn, 0, "{label}");
        assert_eq!(s.prefix, f.keripy["prefix"].as_str().unwrap());
        assert_eq!(s.said, f.keripy["establishment"]["said"].as_str().unwrap());
        assert_eq!(s.protocol_major, 2);
    }
}

#[test]
fn v2_basic_native() {
    // keripy's default body kind is native CESR (P8).
    accepts("v2-basic-native");
}

#[test]
fn v2_native_recovery() {
    // A weighted threshold, a configuration trait and seals of every type,
    // natively; then the recovery key's rotation.
    let f = fixture("v2-native-recovery");
    let messages = parser::parse_all(&f.published).unwrap();
    let seals = messages[1].serder.sad()["a"].as_array().unwrap();
    assert_eq!(seals.len(), 7);
    assert_eq!(
        messages[0].serder.sad()["c"].to_json_value(),
        serde_json::json!(["DND"])
    );
    accepts("v2-native-recovery");
}

#[test]
fn native_bodies_verify_through_the_owned_sad_paths() {
    // `new_from_parts` and `verify_update_owned` take the SAD apart from the
    // raw bytes; the SAID must still be computed over the body's own kind.
    let f = fixture("v2-native-recovery");
    let mut messages = parser::parse_all(&f.published).unwrap();
    let verfers: Vec<Verfer> = messages[0].serder.sad()["k"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| Verfer::from_qb64(k.as_str().unwrap()).unwrap())
        .collect();
    let icp = &mut messages[0];
    let sad = icp.serder.take_sad();
    let mut kever =
        Kever::new_from_parts(icp.serder.raw(), sad, icp.controller_sigs(), &verfers).unwrap();
    for m in messages.iter_mut().skip(1) {
        let sad = m.serder.take_sad();
        let next = kever
            .verify_update_owned(m.serder.raw(), sad, m.controller_sigs())
            .unwrap();
        kever.apply_verified_update(next);
    }
    assert_eq!(kever.state().sn, f.keripy["sn"].as_u64().unwrap());
    assert_eq!(
        kever.state().last_event_digest,
        f.keripy["said"].as_str().unwrap()
    );
}

/// The anchors in a delegator's KEL, verified by replaying it.
struct VerifiedDelegator {
    prefix: String,
    events: Vec<(u64, String, Vec<affinidi_keri_core::SadValue>)>,
}

impl DelegatorAnchors for VerifiedDelegator {
    fn anchors_at(
        &self,
        delegator: &str,
        sn: u64,
        said: &str,
    ) -> Result<Option<Vec<affinidi_keri_core::SadValue>>, CoreError> {
        if delegator != self.prefix {
            return Ok(None);
        }
        Ok(self
            .events
            .iter()
            .find(|(s, d, _)| *s == sn && d == said)
            .map(|(_, _, seals)| seals.clone()))
    }
}

#[test]
fn v2_native_delegated() {
    let f = fixture("v2-native-delegated");
    let json: Value =
        serde_json::from_slice(&std::fs::read(dir().join("v2-native-delegated.json")).unwrap())
            .unwrap();
    let messages = parser::parse_all(&f.published).unwrap();
    let delegator = json["delegator"]["prefix"].as_str().unwrap();
    let (theirs, ours): (Vec<_>, Vec<_>) = messages
        .into_iter()
        .partition(|m| m.serder.prefix().unwrap() == delegator);

    // The delegator's KEL, verified, gives the anchors.
    let r = replay(&theirs);
    assert!(r.refused.is_none(), "{:?}", r.refused);
    assert_state("delegator", &r, &json["delegator"]);
    let anchors = VerifiedDelegator {
        prefix: delegator.into(),
        events: theirs
            .iter()
            .map(|m| {
                let seals = m.serder.sad()["a"].as_array().cloned().unwrap_or_default();
                (m.serder.sn().unwrap(), m.serder.said().unwrap(), seals)
            })
            .collect(),
    };

    // The delegate: its dip and drt each name the anchoring event.
    let proof = |m: &ParsedMessage| {
        let [(sn, said)] = m.seal_source_couples() else {
            panic!("one seal source couple");
        };
        DelegationProof::from_seal_source_couple(sn, said).unwrap()
    };
    let dip = &ours[0];
    let verfers: Vec<Verfer> = dip.serder.sad()["k"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| Verfer::from_qb64(k.as_str().unwrap()).unwrap())
        .collect();
    let kever = Kever::new_delegated(
        &dip.serder,
        dip.controller_sigs(),
        &verfers,
        &proof(dip),
        &anchors,
    )
    .expect("keripy's dip verifies");
    let s = kever.state();
    assert_eq!(s.prefix, f.keripy["prefix"].as_str().unwrap());
    assert_eq!(s.sn, 0);

    // An anchor for a different event does not authorise the dip.
    let elsewhere = DelegationProof::from_seal_source_couple("MAAC", &anchors.events[2].1).unwrap();
    assert!(
        Kever::new_delegated(
            &dip.serder,
            dip.controller_sigs(),
            &verfers,
            &elsewhere,
            &anchors
        )
        .is_err()
    );

    // keripy's drt: a rotation's fields, no `di`. The delegator is the one
    // the dip named, and it anchored this rotation too.
    let drt = &ours[1];
    let mut kever = kever;
    let state = kever
        .verify_update_delegated(&drt.serder, drt.controller_sigs(), &proof(drt), &anchors)
        .expect("keripy's drt verifies");
    kever.apply_verified_update(state);
    let s = kever.state();
    let k = &f.keripy;
    assert_eq!(s.sn, k["sn"].as_u64().unwrap());
    assert_eq!(s.last_event_digest, k["said"].as_str().unwrap());
    assert_eq!(s.said, k["establishment"]["said"].as_str().unwrap());
    let keys: Vec<&str> = k["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(s.keys, keys);
    let next: Vec<&str> = k["n"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(s.next_keys, next);
    assert_eq!(s.delegator.as_deref(), Some(delegator));

    // The dip's anchor does not authorise the drt.
    assert!(
        kever
            .verify_update_delegated(&drt.serder, drt.controller_sigs(), &proof(dip), &anchors)
            .is_err()
    );
}

#[test]
fn endorsed_replies_are_composed_as_keripy_composes_them() {
    // Two `rpy` messages endorsed under the key state of the rotation at sn 1:
    // a `-X` group whose sequence number is a 2.x `Number` (`MAAB`), not the
    // 1.x `Seqner`. Recomposing each from what was parsed must give keripy's
    // bytes, with the genus-version counter `compose_endorsed` writes first.
    let name = "v2-endorsed-replies";
    let f = fixture(name);
    assert_eq!(f.expect, "accept");
    let messages = parser::parse_all(&f.published).unwrap();
    let (kel, replies): (Vec<_>, Vec<_>) = messages
        .into_iter()
        .partition(|m| m.serder.ilk().unwrap() != "rpy");
    let r = replay(&kel);
    assert!(r.refused.is_none(), "{name}: the KEL verifies");
    assert_state(name, &r, &f.keripy);
    assert_eq!(replies.len(), 2);

    let text = std::str::from_utf8(&f.published).unwrap();
    for reply in &replies {
        let [group] = reply.trans_idx_sig_groups() else {
            panic!("{name}: one endorsement per reply");
        };
        assert_eq!(group.sn, "MAAB", "{name}: sn as a 2.x Number");
        assert_eq!(
            group.said,
            r.kever.state().said,
            "{name}: names the rotation"
        );

        let body = std::str::from_utf8(reply.serder.raw()).unwrap();
        let start = text.find(body).unwrap();
        let end = text[start + 1..]
            .find("{\"v\":")
            .map_or(text.len(), |i| start + 1 + i);
        let mut expected = b"-_AAACAA".to_vec();
        expected.extend_from_slice(&f.published[start..end]);

        let ours = affinidi_keri_core::composer::compose_endorsed(
            &reply.serder,
            &group.prefix,
            1,
            &group.said,
            &group.sigs,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(ours).unwrap(),
            String::from_utf8(expected).unwrap(),
            "{name}: {}",
            reply.serder.sad()["r"]
        );
    }
}

#[test]
fn a_rotation_reordering_its_committed_keys_verifies() {
    // keripy signs a key whose prior position differs from its new one with
    // `2A` (both lists, its own ondex), and a key the prior event did not
    // commit to current-only (`B`). The ondex comes from the code.
    accepts("v2-reordered-rotation");
    let f = fixture("v2-reordered-rotation");
    let messages = parser::parse_all(&f.published).unwrap();
    let sigs: Vec<(String, usize, Option<usize>)> = messages[1]
        .controller_sigs()
        .iter()
        .map(|s| (s.code().to_string(), s.index(), s.ondex()))
        .collect();
    assert_eq!(
        sigs,
        [
            ("2A".to_string(), 0, Some(1)),
            ("2A".to_string(), 1, Some(0)),
            ("B".to_string(), 2, None),
        ]
    );
}

#[test]
fn a_rotation_supersedes_interaction_events_after_the_last_establishment() {
    // P7. keripy publishes the superseded ixn 2 and then K's rotation at sn 2,
    // whose prior is ixn 1. A reader reaches keripy's state: the rotation, at
    // sn 2, with ixn 2 gone.
    accepts("v2-superseding-recovery");
    let f = fixture("v2-superseding-recovery");
    let ilks: Vec<String> = parser::parse_all(&f.published)
        .unwrap()
        .iter()
        .map(|m| m.serder.ilk().unwrap())
        .collect();
    assert_eq!(
        ilks,
        ["icp", "ixn", "ixn", "rot"],
        "the superseded event is published"
    );
}

#[test]
fn a_rotation_never_supersedes_a_rotation() {
    let f = fixture("v2-rotation-cannot-supersede-rotation");
    assert_eq!(f.expect, "refuse-event-2");
    let r = replay(&parser::parse_all(f.submitted.as_ref().unwrap()).unwrap());
    match &r.refused {
        Some((2, CoreError::Validation(msg))) if msg.contains("stale rotation") => {}
        other => panic!("the second rotation at sn 1 must be refused as stale, got {other:?}"),
    }
    assert_state("rotation-cannot-supersede-rotation", &r, &f.keripy);
}

#[test]
fn a_recovery_cannot_reach_back_past_the_last_establishment() {
    let f = fixture("v2-stale-recovery");
    assert_eq!(f.expect, "refuse-event-3");
    let r = replay(&parser::parse_all(f.submitted.as_ref().unwrap()).unwrap());
    match &r.refused {
        Some((3, CoreError::Validation(msg))) if msg.contains("stale rotation") => {}
        other => {
            panic!("a rotation at sn 1 after the rotation at sn 1 must be stale, got {other:?}")
        }
    }
    assert_state("stale-recovery", &r, &f.keripy);
}

#[test]
fn every_fixture_is_covered() {
    let mut names: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".json").map(str::to_string)
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "downgrade-v2-to-v1",
            "migrated-v1-to-v2",
            "v1-basic",
            "v2-basic",
            "v2-basic-native",
            "v2-endorsed-replies",
            "v2-multisig-2of3",
            "v2-native-delegated",
            "v2-native-messages",
            "v2-native-recovery",
            "v2-recovery-by-k",
            "v2-recovery-by-r-and-k",
            "v2-recovery-routine-alone",
            "v2-reordered-rotation",
            "v2-rotation-cannot-supersede-rotation",
            "v2-stale-recovery",
            "v2-superseding-recovery",
        ],
        "a fixture was added or removed: give it a test above"
    );
}
