//! Native CESR message bodies (P8 of "did:webs on KERI v2",
//! OpenVTC/verifiable-trust-infrastructure docs/05-design-notes/did-webs-keri-v2.md).
//!
//! `fixtures/keripy-v2/v2-native-messages.json` holds one native body of each
//! message type keripy reads natively, with the SAD keripy reads from it. A
//! reader must read the same SAD and accept the same SAID; and refuse a body
//! that is not exactly what keripy would write for that SAD.

use std::path::Path;

use affinidi_keri_core::CoreError;
use affinidi_keri_core::parser;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use serde_json::Value;

struct Message {
    name: String,
    raw: String,
    sad: Value,
    said: String,
}

fn messages() -> Vec<Message> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keripy-v2/v2-native-messages.json");
    let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| Message {
            name: m["name"].as_str().unwrap().into(),
            raw: m["raw"].as_str().unwrap().into(),
            sad: m["sad"].clone(),
            said: m["said"].as_str().unwrap().into(),
        })
        .collect()
}

/// A 2.x stream of the bodies alone.
fn stream(bodies: &[&str]) -> Vec<u8> {
    let mut out = b"-_AAACAA".to_vec();
    for b in bodies {
        out.extend_from_slice(b.as_bytes());
    }
    out
}

#[test]
fn every_native_body_reads_to_keripys_sad() {
    let all = messages();
    assert_eq!(all.len(), 15, "a message was added or removed");
    for m in &all {
        let serder = Serder::from_raw(m.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{}: keripy's body must read: {e}", m.name));
        assert_eq!(serder.kind(), SerializationKind::Cesr, "{}", m.name);
        assert_eq!(serder.size(), m.raw.len(), "{}", m.name);
        assert_eq!(serder.sad().to_json_value(), m.sad, "{}: SAD", m.name);
        assert_eq!(serder.said().unwrap(), m.said, "{}", m.name);
    }
}

#[test]
fn a_stream_of_native_bodies_parses_message_by_message() {
    let all = messages();
    let bodies: Vec<&str> = all.iter().map(|m| m.raw.as_str()).collect();
    let parsed = parser::parse_all(&stream(&bodies)).unwrap();
    assert_eq!(parsed.len(), all.len());
    for (p, m) in parsed.iter().zip(&all) {
        assert_eq!(p.serder.raw(), m.raw.as_bytes(), "{}", m.name);
        assert!(p.attachments.is_empty(), "{}", m.name);
    }
}

#[test]
fn every_native_said_verifies_as_keripy_computes_it() {
    // An ACDC (`acm`) SAID is over its most compact form, which the registry
    // reader checks; a receipt's `d` is the receipted event's SAID, not its
    // own (keripy: `rct` has no SAID fields). Every other message's SAID is
    // over the body itself.
    for m in messages()
        .iter()
        .filter(|m| !m.name.starts_with("acm") && m.name != "rct")
    {
        let serder = Serder::from_raw(m.raw.as_bytes()).unwrap();
        serder
            .verify_said("E")
            .unwrap_or_else(|e| panic!("{}: SAID: {e}", m.name));
    }
}

#[test]
fn a_native_body_writes_back_to_its_own_bytes() {
    for m in messages() {
        let serder = Serder::from_raw(m.raw.as_bytes()).unwrap();
        let rewritten = Serder::new(SerializationKind::Cesr, serder.sad().clone()).unwrap();
        assert_eq!(rewritten.raw(), m.raw.as_bytes(), "{}", m.name);
        assert_eq!(rewritten.version, serder.version, "{}", m.name);
    }
}

/// The body with `from` replaced by `to`, once.
fn edited(raw: &str, from: &str, to: &str) -> String {
    assert_eq!(raw.matches(from).count(), 1, "{from:?} must occur once");
    raw.replacen(from, to, 1)
}

fn find(name: &str) -> Message {
    messages().into_iter().find(|m| m.name == name).unwrap()
}

#[test]
fn a_tampered_body_fails_its_said() {
    // The route of a reply, changed in place: same length, still canonical.
    let m = find("rpy-loc-scheme");
    let route = "4AADA-loc-scheme";
    let tampered = edited(&m.raw, route, "4AADA-loc-schemX");
    let serder = Serder::from_raw(tampered.as_bytes()).unwrap();
    assert_eq!(serder.sad()["r"].as_str(), Some("/loc/schemX"));
    assert!(matches!(
        serder.verify_said("E"),
        Err(CoreError::SaidMismatch)
    ));
}

#[test]
fn a_non_canonical_encoding_is_refused() {
    // `s` of a receipt written as a `Tall` number (`R`, five bytes), where
    // keripy writes the smallest code (`M`). keripy reads both, but refuses a
    // body that does not write back to itself; so does this reader.
    let m = find("rct");
    let tall = edited(&m.raw, "MAAK", "RAAAAAAK");
    // The body group grows by one quadlet.
    let tall = edited(&tall, "-FAb", "-FAc");
    match Serder::from_raw(tall.as_bytes()) {
        Err(CoreError::ParseError(msg)) => assert!(msg.contains("canonical"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_body_group_of_the_wrong_type_is_refused() {
    let m = find("rct");
    // A generic map group where a fixed-field body belongs.
    let wrong = edited(&m.raw, "-FAb", "-IAb");
    assert!(Serder::from_raw(wrong.as_bytes()).is_err());
    assert!(parser::parse_all(&stream(&[&wrong])).is_err());
    // A KERI message as a field map.
    let map = edited(&m.raw, "-FAb", "-GAb");
    assert!(Serder::from_raw(map.as_bytes()).is_err());
}

#[test]
fn a_body_with_bytes_after_its_last_field_is_refused() {
    let m = find("rct");
    let longer = format!("{}MAAA", edited(&m.raw, "-FAb", "-FAc"));
    assert!(Serder::from_raw(longer.as_bytes()).is_err());
}

#[test]
fn a_truncated_body_is_refused() {
    let m = find("rpy-every-value");
    assert!(Serder::from_raw(&m.raw.as_bytes()[..m.raw.len() - 4]).is_err());
}

#[test]
fn a_native_body_is_not_read_in_a_1x_stream() {
    // No genus-version counter: the stream is 1.x (P1), where `-F` is not a
    // message body.
    let m = find("rct");
    assert!(parser::parse_all(m.raw.as_bytes()).is_err());
}

#[test]
fn a_version_1_native_body_is_refused() {
    // The version field naming KERI 1.0 (`KERIBAA`): native CESR exists only
    // in version 2.
    let m = find("rct");
    let v1 = edited(&m.raw, "0OKERICAACAA", "0OKERIBAACAA");
    assert!(Serder::from_raw(v1.as_bytes()).is_err());
}
