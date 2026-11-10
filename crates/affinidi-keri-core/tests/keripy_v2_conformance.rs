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
fn native_cesr_bodies_are_refused_by_name() {
    // TODO(P8): read native CESR bodies before the integration leaves alpha.
    // keripy accepts this stream (its default body kind is CESR); until then
    // it must fail closed, by name, rather than be skipped.
    let f = fixture("v2-basic-native");
    assert_eq!(f.expect, "accept");
    match parser::parse_all(&f.published) {
        Err(CoreError::Unsupported(msg)) => {
            assert_eq!(msg, "native CESR bodies not yet supported");
        }
        other => panic!(
            "expected the native-CESR refusal, got {:?}",
            other.map(|m| m.len())
        ),
    }
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
            "v2-multisig-2of3",
            "v2-recovery-by-k",
            "v2-recovery-by-r-and-k",
            "v2-recovery-routine-alone",
        ],
        "a fixture was added or removed: give it a test above"
    );
}
