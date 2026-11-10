//! The v2 registries and designations we write for keripy to verify
//! (`tests/fixtures/ours-v2-registries/`, checked by
//! `verify_ours_registries.py`).
//!
//! keripy can't run in CI, so this holds the other half: the committed files
//! are exactly what the writer produces today (a change to the output must be
//! regenerated and re-verified by keripy), and this library's own registry
//! reader (`affinidi_keri_core::registry`) reaches the status each file
//! records.

mod conformance;

use affinidi_keri_core::parser::parse_all;
use affinidi_keri_core::registry::{self, IssuerLog, Status};
use conformance::registry_scenarios;
use serde_json::Value;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ours-v2-registries"
);

#[test]
fn the_committed_fixtures_are_what_the_writer_writes() {
    let scenarios = registry_scenarios::all();
    for s in &scenarios {
        let stream = std::fs::read(format!("{DIR}/{}.cesr", s.name)).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run the emit_registry_conformance example)",
                s.name
            )
        });
        assert!(
            stream == s.stream,
            "{}: the stream differs from what the writer writes; regenerate and re-verify with keripy",
            s.name
        );
        let json = std::fs::read_to_string(format!("{DIR}/{}.json", s.name)).unwrap();
        assert_eq!(
            json,
            registry_scenarios::json_for(s),
            "{}: expectations differ",
            s.name
        );
    }
    let on_disk = std::fs::read_dir(DIR)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".cesr"))
        .count();
    assert_eq!(
        on_disk,
        scenarios.len(),
        "a fixture has no scenario, or a scenario no fixture"
    );
}

#[test]
fn our_reader_reaches_the_status_each_fixture_records() {
    for s in registry_scenarios::all() {
        let messages = parse_all(&s.stream).unwrap_or_else(|e| panic!("{}: {e}", s.name));
        let issuer = s.json["kel"]["prefix"].as_str().unwrap();
        let log =
            IssuerLog::replay(&messages, issuer).unwrap_or_else(|e| panic!("{}: {e}", s.name));
        for c in s.json["credentials"].as_array().unwrap() {
            let schema = c["schema"].as_str().unwrap();
            let found = registry::designations(&messages, &log, schema)
                .unwrap_or_else(|e| panic!("{}: {e}", s.name));
            assert!(
                found.rejected.is_empty(),
                "{}: rejected {:?}",
                s.name,
                found.rejected
            );
            let credential = found
                .credentials
                .iter()
                .find(|x| Value::String(x.said.clone()) == c["credential"])
                .unwrap_or_else(|| panic!("{}: {} not found", s.name, c["credential"]));
            let status = match credential.status {
                Status::Issued => "issued",
                Status::Revoked => "revoked",
                _ => "other",
            };
            assert_eq!(status, c["expect"], "{}: {schema}", s.name);
            assert_eq!(
                credential.registry,
                c["registry"].as_str().unwrap(),
                "{}",
                s.name
            );
            assert_eq!(credential.version, 2, "{}", s.name);
        }
    }
}
