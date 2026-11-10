//! The registry writer builds what keripy builds.
//!
//! keripy's `v2-reissued` fixture (`tests/fixtures/keripy-v2-registries/`) is a
//! registry incepted, a designated-aliases ACDC bound to it, and three updates
//! (issued, revoked, issued), each salted with its own UUID. Given keripy's
//! inputs (the issuer, the registry nonce, the timestamps, and the UUIDs keripy
//! disclosed), this crate's writer must produce the same SAIDs and BLIDs for
//! every message. The attribute block is the one place the bytes differ:
//! keripy leaves its `d` empty and this writer fills it, which leaves the
//! credential's SAID unchanged.

use std::path::PathBuf;

use affinidi_keri_core::parser::{self, Attachment};
use affinidi_keri_core::registry::write::{
    BlindingUuid, RegistryNonce, RegistryState, TransactionState,
};
use affinidi_keri_core::sad::SadValue;
use serde_json::json;

const ISSUER: &str = "EAQR5amK-y719-fDud1YLciOYogoOSokavPrUY8tn2Fi";
const ALIASES_V2: &str = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";

fn stamp(i: u64) -> String {
    format!("2026-01-0{i}T00:00:00.000000+00:00")
}

#[test]
fn the_writer_reproduces_keripys_reissued_registry() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keripy-v2-registries/v2-reissued.cesr");
    let messages = parser::parse_all(&std::fs::read(path).unwrap()).unwrap();
    let acdc: Vec<_> = messages
        .iter()
        .filter(|m| {
            m.serder
                .version
                .as_ref()
                .is_some_and(|v| v.protocol == "ACDC")
        })
        .collect();
    let ilk = |i: usize| acdc[i].serder.sad()["t"].as_str().unwrap().to_string();
    assert_eq!(
        (0..acdc.len()).map(ilk).collect::<Vec<_>>(),
        ["rip", "acm", "bup", "bup", "bup"]
    );
    let said = |i: usize| acdc[i].serder.sad()["d"].as_str().unwrap().to_string();
    let disclosure = |i: usize| {
        acdc[i]
            .attachments
            .iter()
            .find_map(|a| match a {
                Attachment::BlindedStates(s) => s.first().cloned(),
                _ => None,
            })
            .unwrap()
    };
    let uuid = |i: usize| {
        // A one-character code over 32 bytes: the code stands in for one lead
        // byte, so decode with the code zeroed and drop that byte.
        let qb64 = disclosure(i).uuid;
        let raw = affinidi_cesr::codec::b64_decode(&format!("A{}", &qb64[1..])).unwrap();
        BlindingUuid(raw[1..].try_into().unwrap())
    };

    let (state, rip) =
        RegistryState::incept(ISSUER, &RegistryNonce(*b"registry-uuid-01"), &stamp(1)).unwrap();
    assert_eq!(rip.said, said(0), "rip");
    assert_eq!(rip.raw, acdc[0].serder.raw(), "rip bytes");

    let attributes = SadValue::from_json_value(&json!({
        "dt": stamp(1),
        "ids": [format!("did:webs:example.com:{ISSUER}")],
    }));
    let credential = state.designation(ALIASES_V2, &attributes).unwrap();
    assert_eq!(credential.said, said(1), "acm");

    let mut state = state;
    for (i, ts) in [
        (2, TransactionState::Issued),
        (3, TransactionState::Revoked),
        (4, TransactionState::Issued),
    ] {
        let (next, bup) = state
            .update(&credential.said, ts, &uuid(i), &stamp(i as u64))
            .unwrap();
        assert_eq!(
            bup.disclosure.as_ref().unwrap(),
            &disclosure(i),
            "disclosure at {i}"
        );
        assert_eq!(
            String::from_utf8_lossy(&bup.raw),
            String::from_utf8_lossy(acdc[i].serder.raw()),
            "bup bytes at {i}"
        );
        assert_eq!(bup.said, said(i), "bup at {i}");
        state = next;
    }
}
