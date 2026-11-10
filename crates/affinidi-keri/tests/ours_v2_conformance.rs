//! The key event logs our controller writes for keripy to verify
//! (`tests/fixtures/ours-v2/`, checked by `verify_ours.py`).
//!
//! keripy can't run in CI, so this holds the other half: the committed files
//! are exactly what the controller writes today (a change to the output must
//! be regenerated and re-verified by keripy), and our own verifier reaches the
//! same state the files record.

mod conformance;

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{Attachment, parse_all};
use affinidi_keri_crypto::Verfer;
use conformance::scenarios;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ours-v2");

/// Run a stream through `Kever`; return it and the first refusal, if any.
fn verify(stream: &[u8]) -> (Kever, Option<String>) {
    let mut kever: Option<Kever> = None;
    for msg in parse_all(stream).expect("stream parses") {
        let sigs = msg
            .attachments
            .into_iter()
            .find_map(|a| match a {
                Attachment::ControllerSigs(s) => Some(s),
                _ => None,
            })
            .expect("controller signatures");
        match kever.as_mut() {
            None => {
                let verfers: Vec<Verfer> = msg.serder.sad()["k"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| Verfer::from_qb64(k.as_str().unwrap()).unwrap())
                    .collect();
                kever = Some(Kever::new(&msg.serder, &sigs, &verfers).expect("inception"));
            }
            Some(k) => {
                if let Err(e) = k.update(&msg.serder, &sigs) {
                    return (kever.unwrap(), Some(e.to_string()));
                }
            }
        }
    }
    (kever.expect("a log"), None)
}

#[test]
fn the_committed_files_are_what_the_controller_writes() {
    for s in scenarios::all() {
        let stream = std::fs::read(format!("{DIR}/{}.cesr", s.name))
            .unwrap_or_else(|e| panic!("{}.cesr: {e}", s.name));
        assert!(
            stream == s.stream,
            "{}.cesr differs from what the controller writes now: regenerate with \
             `cargo run -p affinidi-keri --example emit_conformance` and re-run verify_ours.py",
            s.name
        );
        let json = std::fs::read_to_string(format!("{DIR}/{}.json", s.name)).unwrap();
        assert_eq!(json, scenarios::json_for(&s), "{}.json", s.name);
    }
}

#[test]
fn our_verifier_reaches_the_recorded_state() {
    for s in scenarios::all() {
        let (kever, refused) = verify(&s.stream);
        match s.expect {
            "accept" => assert!(refused.is_none(), "{}: refused: {refused:?}", s.name),
            "refuse-rotation" => assert!(refused.is_some(), "{}: accepted", s.name),
            other => panic!("{}: unknown expectation {other}", s.name),
        }
        let st = kever.state();
        assert_eq!(
            Value::from(st.prefix.clone()),
            s.state["prefix"],
            "{}",
            s.name
        );
        assert_eq!(Value::from(st.sn), s.state["sn"], "{}", s.name);
        assert_eq!(
            Value::from(st.last_event_digest.clone()),
            s.state["said"],
            "{}",
            s.name
        );
        assert_eq!(
            serde_json::to_value(&st.keys).unwrap(),
            s.state["keys"],
            "{}",
            s.name
        );
        assert_eq!(
            serde_json::to_value(&st.next_keys).unwrap(),
            s.state["n"],
            "{}",
            s.name
        );
        assert_eq!(
            Value::from(format!("{}.0", st.protocol_major)),
            s.state["version"],
            "{}",
            s.name
        );
    }
}

#[test]
fn every_committed_stream_is_a_scenario() {
    let names: Vec<String> = scenarios::all()
        .iter()
        .map(|s| s.name.to_string())
        .collect();
    for entry in std::fs::read_dir(DIR).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        if let Some(name) = file.strip_suffix(".cesr") {
            assert!(names.iter().any(|n| n == name), "{file} has no scenario");
        }
    }
}
