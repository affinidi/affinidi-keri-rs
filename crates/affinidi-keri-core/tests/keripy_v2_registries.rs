//! Credential registries, checked against streams keripy built.
//!
//! Each fixture in `tests/fixtures/keripy-v2-registries/` is an issuer's
//! published stream: its KEL, a v2 registry, a v2 designated-aliases ACDC and
//! its blindable updates, composed with keripy's `messagize`. Its `.json`
//! records what a conforming reader must conclude (`expect`) and what
//! keripy's registry verifier concluded from the same objects (`keripy`).
//! See that directory's README for where the two differ, and why.

use std::path::PathBuf;

use affinidi_keri_core::parser::{self, ParsedMessage};
use affinidi_keri_core::registry::{self, IssuerLog, RegistryError, Status};
use serde_json::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keripy-v2-registries")
}

struct Fixture {
    expect: String,
    issuer: String,
    schema: String,
    credential: String,
    limit: Option<u64>,
    messages: Vec<ParsedMessage>,
}

fn load(name: &str) -> Fixture {
    let json: Value =
        serde_json::from_slice(&std::fs::read(dir().join(format!("{name}.json"))).unwrap())
            .unwrap();
    let stream = std::fs::read(dir().join(format!("{name}.cesr"))).unwrap();
    Fixture {
        expect: json["expect"].as_str().unwrap().to_string(),
        issuer: json["issuer"].as_str().unwrap().to_string(),
        schema: json["schema"].as_str().unwrap().to_string(),
        credential: json["credential"].as_str().unwrap().to_string(),
        limit: json["limit"].as_u64(),
        messages: parser::parse_all(&stream).unwrap_or_else(|e| panic!("{name}: parse: {e}")),
    }
}

fn read(f: &Fixture) -> Result<registry::Designations, RegistryError> {
    let log = IssuerLog::replay(&f.messages, &f.issuer)
        .expect("keripy's KEL verifies")
        .as_of(f.limit);
    registry::designations(&f.messages, &log, &f.schema)
}

fn check(name: &str) {
    let f = load(name);
    let result = read(&f);
    match f.expect.as_str() {
        "issued" | "revoked" => {
            let found = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                found.rejected.is_empty(),
                "{name}: rejected {:?}",
                found.rejected
            );
            assert_eq!(found.credentials.len(), 1, "{name}: one credential");
            let c = &found.credentials[0];
            assert_eq!(c.said, f.credential, "{name}: credential");
            assert_eq!(c.version, 2);
            let want = if f.expect == "issued" {
                Status::Issued
            } else {
                Status::Revoked
            };
            assert_eq!(c.status, want, "{name}: status");
        }
        "error:missing-anchored-event" => assert!(
            matches!(result, Err(RegistryError::MissingAnchoredEvent { .. })),
            "{name}: {result:?}"
        ),
        "error:undisclosed-update" => assert!(
            matches!(result, Err(RegistryError::UndisclosedUpdate { .. })),
            "{name}: {result:?}"
        ),
        "error:unanchored-event" => assert!(
            matches!(result, Err(RegistryError::UnanchoredEvent { .. })),
            "{name}: {result:?}"
        ),
        other => panic!("{name}: unknown expectation {other}"),
    }
}

#[test]
fn an_issued_credential_stands() {
    check("v2-issued");
}

#[test]
fn a_revoked_credential_is_revoked() {
    check("v2-revoked");
}

#[test]
fn as_of_the_issuance_a_later_revocation_has_not_happened() {
    check("v2-revoked-as-of-issuance");
}

/// keripy reads this as issued: it checks what is presented, not that
/// everything anchored is presented.
#[test]
fn a_withheld_revocation_fails_the_read() {
    check("v2-revocation-withheld");
}

#[test]
fn the_latest_non_vacuous_update_decides() {
    check("v2-reissued");
    check("v2-vacuous-head");
}

/// keripy refuses this (two disclosures share a BLID in its detached list);
/// in the stream each disclosure is attached to its own update.
#[test]
fn a_public_mode_reissue_is_read_by_attachment() {
    check("v2-reissued-empty-uuid");
}

#[test]
fn an_update_without_its_disclosure_fails_the_read() {
    check("v2-head-undisclosed");
}

#[test]
fn an_unanchored_update_fails_the_read() {
    check("v2-update-unanchored");
}

/// Native CESR bodies throughout (P8): the KEL, the registry events and the
/// ACDC, whose SAID is over its most compact form, natively.
#[test]
fn native_registries_read_as_their_json_twins() {
    check("v2-issued-native");
    check("v2-revoked-native");
    let f = load("v2-revoked-native");
    assert!(
        f.messages
            .iter()
            .all(|m| m.serder.kind() == affinidi_keri_core::version::SerializationKind::Cesr)
    );
}

#[test]
fn every_fixture_is_covered() {
    let covered = [
        "v2-issued",
        "v2-issued-native",
        "v2-revoked-native",
        "v2-revoked",
        "v2-revoked-as-of-issuance",
        "v2-revocation-withheld",
        "v2-reissued",
        "v2-vacuous-head",
        "v2-reissued-empty-uuid",
        "v2-head-undisclosed",
        "v2-update-unanchored",
    ];
    for entry in std::fs::read_dir(dir()).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if let Some(stem) = name.strip_suffix(".json") {
            assert!(covered.contains(&stem), "fixture {stem} has no test");
        }
    }
}

/// The 1.x path, on a real `did:webs` artifact keripy produced: a signed
/// designated-aliases ACDC in a 1.x TEL.
#[test]
fn a_v1_designation_in_a_real_did_webs_stream_stands() {
    let stream = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/did-webs-ENro7uf0.keri.cesr"),
    )
    .unwrap();
    let messages = parser::parse_all(&stream).unwrap();
    let aid = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
    let log = IssuerLog::replay(&messages, aid).unwrap();
    let found = registry::designations(
        &messages,
        &log,
        "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5",
    )
    .unwrap();
    assert!(found.rejected.is_empty(), "{:?}", found.rejected);
    assert_eq!(found.credentials.len(), 1);
    let c = &found.credentials[0];
    assert_eq!(c.version, 1);
    assert_eq!(c.status, Status::Issued);

    // As of the inception, before the registry was anchored, nothing stands.
    let log = IssuerLog::replay(&messages, aid).unwrap().as_of(Some(0));
    let found = registry::designations(
        &messages,
        &log,
        "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5",
    )
    .unwrap();
    assert!(found.credentials.is_empty());
}

/// Replace the last occurrence of `from` with `to` (same length) in a
/// fixture's stream.
fn tampered(name: &str, from: &str, to: &str) -> Fixture {
    assert_eq!(from.len(), to.len());
    let mut f = load(name);
    let mut stream = std::fs::read(dir().join(format!("{name}.cesr"))).unwrap();
    let at = stream
        .windows(from.len())
        .rposition(|w| w == from.as_bytes())
        .unwrap_or_else(|| panic!("{from} not in {name}"));
    stream[at..at + from.len()].copy_from_slice(to.as_bytes());
    f.messages = parser::parse_all(&stream).unwrap();
    f
}

/// A credential is unsigned in 2.x: its compact SAID is what ties its content
/// to the registry update that names it, so changed content binds nothing.
#[test]
fn a_changed_alias_is_rejected() {
    let f = tampered("v2-issued", "example.com", "examplf.com");
    let found = read(&f).unwrap();
    assert!(found.credentials.is_empty());
    assert_eq!(found.rejected.len(), 1, "{:?}", found.rejected);
    assert!(
        found.rejected[0].1.contains("compact form"),
        "{:?}",
        found.rejected
    );
}

/// A disclosure that does not reproduce its BLID proves nothing: turning the
/// head's `revoked` into `issued` must not make the credential stand.
#[test]
fn a_rewritten_disclosure_fails_its_blid() {
    let f = tampered("v2-revoked", "Yrevoked", "0Missued");
    let result = read(&f);
    assert!(
        matches!(&result, Err(RegistryError::Chain { reason, .. }) if reason.contains("BLID")),
        "{result:?}"
    );
}
