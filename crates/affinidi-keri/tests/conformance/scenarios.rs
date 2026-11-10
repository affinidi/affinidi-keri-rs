//! Reverse-conformance scenarios: key event logs written by this library's
//! controller, for keripy to verify (`tests/fixtures/ours-v2/verify_ours.py`).
//!
//! Shared by `examples/emit_conformance.rs`, which writes them to disk, and
//! `tests/ours_v2_conformance.rs`, which rebuilds them in memory and checks
//! they still match the committed files byte for byte.
//!
//! Every key comes from a fixed salt and Ed25519 signatures are deterministic,
//! so the output never changes unless the code that writes it does.

#![allow(dead_code)]

use affinidi_keri::ProtocolVersion;
use affinidi_keri::controller::{
    ControllerState, Inception, KeySigner, NextKey, PendingEvent, Rotation, incept,
};
use affinidi_keri::hab::SignedEvent;
use affinidi_keri_core::composer::compose_event;
use affinidi_keri_core::sad;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::threshold::{Threshold, ThresholdValue};
use affinidi_keri_crypto::{Salter, Signer};
use serde_json::{Value, json};

const SALT: [u8; 16] = *b"vti-ours-v2-fixt";

/// One scenario's output.
pub struct Scenario {
    pub name: &'static str,
    pub note: &'static str,
    /// `accept`: keripy must reach `state`. `refuse-rotation`: the stream
    /// carries a rotation a verifier must refuse, and `state` is where it stops.
    pub expect: &'static str,
    /// The published stream.
    pub stream: Vec<u8>,
    /// The state keripy must reach.
    pub state: Value,
}

fn key(path: &str) -> Signer {
    Salter::new("0A", SALT.to_vec())
        .unwrap()
        .signer("A", path, "low", true)
        .unwrap()
}

fn keys(prefix: &str, n: usize) -> Vec<Signer> {
    (0..n).map(|i| key(&format!("{prefix}.{i}"))).collect()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

fn next(signers: &[&Signer]) -> Vec<NextKey> {
    signers.iter().map(|s| NextKey::PublicKey(pk(s))).collect()
}

fn recovery_nt() -> Threshold {
    Threshold::from_json_value(&json!([["1/2", "1"]])).unwrap()
}

fn sign(mut pending: PendingEvent, signers: &[&Signer]) -> (SignedEvent, ControllerState) {
    for s in signers {
        pending.sign_with(*s as &dyn KeySigner).unwrap();
    }
    pending.finish().unwrap()
}

/// A threshold as keripy reports it (`Tholder.sith`): hex for a simple
/// threshold, the clause itself for a single-clause weighted one.
fn sith(t: &ThresholdValue) -> Value {
    let v = t.0.to_json_value();
    match &v {
        Value::Array(clauses) if clauses.len() == 1 && clauses[0].is_array() => clauses[0].clone(),
        _ => v,
    }
}

/// The state keripy must reach, in the shape of the keripy fixtures' `keripy`
/// block.
fn state(st: &ControllerState, ilk: &str) -> Value {
    json!({
        "prefix": st.prefix,
        "sn": st.sn,
        "said": st.last_said,
        "ilk": ilk,
        "version": format!("{}.0", st.version.major()),
        "keys": st.keys,
        "kt": sith(&st.threshold),
        "n": st.next_digests,
        "nt": sith(&st.next_threshold),
        "establishment": { "sn": st.establishment_sn, "said": st.establishment_said },
    })
}

fn stream(events: &[SignedEvent]) -> Vec<u8> {
    events.iter().flat_map(|e| e.composed.clone()).collect()
}

/// icp, ixn anchoring a digest seal, rot, ixn; one Ed25519 key.
fn basic() -> Scenario {
    let s = keys("basic", 3);
    let (icp, st) = sign(
        incept(&Inception::new(
            vec![pk(&s[0])],
            Threshold::Simple(1),
            next(&[&s[1]]),
            Threshold::Simple(1),
        ))
        .unwrap(),
        &[&s[0]],
    );
    let (ixn1, st) = sign(st.interact(&[sad!({ "d": icp.said })]).unwrap(), &[&s[0]]);
    let (rot, st) = sign(
        st.rotate(
            &[pk(&s[1])],
            &Rotation::new(Threshold::Simple(1), next(&[&s[2]]), Threshold::Simple(1)),
        )
        .unwrap(),
        &[&s[1]],
    );
    let (ixn2, st) = sign(st.interact(&[]).unwrap(), &[&s[1]]);
    Scenario {
        name: "v2-basic",
        note: "icp, ixn (one digest seal), rot, ixn; single Ed25519 key; KERI 2.0, JSON bodies",
        expect: "accept",
        stream: stream(&[icp, ixn1, rot, ixn2]),
        state: state(&st, "ixn"),
    }
}

/// The VTI level-3 shape: n [H(R'), H(K)], nt [["1/2","1"]].
fn recovery() -> Vec<Scenario> {
    let [r0, r1, k, r2, k2]: [Signer; 5] = keys("recovery", 5).try_into().ok().unwrap();
    let (icp, st) = sign(
        incept(&Inception::new(
            vec![pk(&r0)],
            Threshold::Simple(1),
            next(&[&r1, &k]),
            recovery_nt(),
        ))
        .unwrap(),
        &[&r0],
    );
    let (ixn, st) = sign(st.interact(&[]).unwrap(), &[&r0]);
    let rotation = Rotation::new(Threshold::Simple(1), next(&[&r2, &k2]), recovery_nt());
    let pending = st.rotate(&[pk(&r1), pk(&k)], &rotation).unwrap();

    let by = |signers: &[&Signer], name, note| {
        let (rot, after) = sign(pending.clone(), signers);
        Scenario {
            name,
            note,
            expect: "accept",
            stream: stream(&[icp.clone(), ixn.clone(), rot]),
            state: state(&after, "rot"),
        }
    };
    let by_k = by(
        &[&k],
        "v2-recovery-by-k",
        "rotation signed by the recovery key K alone meets the prior nt",
    );
    let by_both = by(
        &[&r1, &k],
        "v2-recovery-by-r-and-k",
        "rotation signed by R' and K",
    );

    // R' alone: our controller refuses to finish it, so compose it unchecked
    // for keripy to refuse too.
    let mut alone = pending.clone();
    alone.sign_with(&r1).unwrap();
    assert!(alone.clone().finish().is_err(), "R' alone must not finish");
    let raw = alone.signing_input().to_vec();
    let serder = Serder::from_raw(&raw).unwrap();
    let siger = r1.sign_indexed(&raw, 0, true).unwrap();
    let unchecked = compose_event(&serder, &[siger]).unwrap();
    let mut submitted = stream(&[icp, ixn]);
    submitted.extend_from_slice(&unchecked);
    let routine_alone = Scenario {
        name: "v2-recovery-routine-alone",
        note: "rotation signed by R' alone, composed without the controller's check: meets kt, not the prior nt; a verifier stops at sn 1",
        expect: "refuse-rotation",
        stream: submitted,
        state: state(&st, "ixn"),
    };
    vec![by_k, by_both, routine_alone]
}

/// kt 2 over three keys.
fn multisig() -> Scenario {
    let s = keys("multisig", 6);
    let (icp, st) = sign(
        incept(&Inception::new(
            s[..3].iter().map(pk).collect(),
            Threshold::Simple(2),
            next(&[&s[3], &s[4], &s[5]]),
            Threshold::Simple(2),
        ))
        .unwrap(),
        &[&s[0], &s[2]],
    );
    let (ixn, st) = sign(st.interact(&[]).unwrap(), &[&s[1], &s[2]]);
    Scenario {
        name: "v2-multisig-2of3",
        note: "kt 2 over three keys; icp signed by keys 0 and 2, ixn by 1 and 2",
        expect: "accept",
        stream: stream(&[icp, ixn]),
        state: state(&st, "ixn"),
    }
}

/// A version 1 log continued in version 2.
fn migrated() -> Scenario {
    let s = keys("migrated", 3);
    let (icp, st) = sign(
        incept(
            &Inception::new(
                vec![pk(&s[0])],
                Threshold::Simple(1),
                next(&[&s[1]]),
                Threshold::Simple(1),
            )
            .with_version(ProtocolVersion::V1),
        )
        .unwrap(),
        &[&s[0]],
    );
    let (ixn1, st) = sign(st.interact(&[]).unwrap(), &[&s[0]]);
    let st = st.upgrade(ProtocolVersion::V2).unwrap();
    let (rot, st) = sign(
        st.rotate(
            &[pk(&s[1])],
            &Rotation::new(Threshold::Simple(1), next(&[&s[2]]), Threshold::Simple(1)),
        )
        .unwrap(),
        &[&s[1]],
    );
    let (ixn2, st) = sign(st.interact(&[]).unwrap(), &[&s[1]]);
    Scenario {
        name: "migrated-v1-to-v2",
        note: "v1 icp and ixn, then v2 rot and ixn: a log may move up a version (P2)",
        expect: "accept",
        stream: stream(&[icp, ixn1, rot, ixn2]),
        state: state(&st, "ixn"),
    }
}

/// Ten keys at threshold ten: `kt` is `"a"`, not `"10"`.
fn hex_threshold() -> Scenario {
    let s = keys("hex", 20);
    let current: Vec<&Signer> = s[..10].iter().collect();
    let (icp, st) = sign(
        incept(&Inception::new(
            current.iter().map(|k| pk(k)).collect(),
            Threshold::Simple(10),
            next(&s[10..].iter().collect::<Vec<_>>()),
            Threshold::Simple(10),
        ))
        .unwrap(),
        &current,
    );
    let (ixn, st) = sign(st.interact(&[]).unwrap(), &current);
    Scenario {
        name: "v2-threshold-ten",
        note: "ten keys at kt and nt ten, written \"a\" as keripy reads a threshold (hex)",
        expect: "accept",
        stream: stream(&[icp, ixn]),
        state: state(&st, "ixn"),
    }
}

/// Every scenario, in a fixed order.
pub fn all() -> Vec<Scenario> {
    let mut out = vec![basic()];
    out.extend(recovery());
    out.push(multisig());
    out.push(migrated());
    out.push(hex_threshold());
    out
}

/// The `.json` written beside each stream.
pub fn json_for(s: &Scenario) -> String {
    let mut text = serde_json::to_string_pretty(&json!({
        "note": s.note,
        "expect": s.expect,
        "ours": s.state,
    }))
    .unwrap();
    text.push('\n');
    text
}
