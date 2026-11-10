//! A recovery takes what it supersedes with it (P7 of "did:webs on KERI v2",
//! OpenVTC/verifiable-trust-infrastructure docs/05-design-notes/did-webs-keri-v2.md).
//!
//! The identifier is the recovery custodian's shape: `k = [R0]`,
//! `n = [H(R1), H(K)]`, `nt = [["1/2", "1"]]`. R0 issues a designation (ixn 1)
//! and is then compromised: it revokes the designation (ixn 2). The recovery
//! key K rotates at sn 2, after ixn 1, superseding ixn 2. The published stream
//! carries everything; a reader must reach the rotation's key state, and read
//! the designation as issued: the revocation's only anchor was superseded.

use affinidi_keri::controller::{Inception, KeySigner, NextKey, Rotation, incept};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::parse_all;
use affinidi_keri_core::registry::write::{
    BlindingUuid, RegistryNonce, RegistryState, TransactionState,
};
use affinidi_keri_core::registry::{self, Anchor, IssuerLog, Status};
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Salter, Signer, Verfer};
use serde_json::json;

const ALIASES_V2: &str = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";
const DT: &str = "2026-01-01T00:00:00.000000+00:00";

fn key(seed: u8) -> Signer {
    Salter::new("0A", vec![seed; 16])
        .unwrap()
        .signer("A", "0", "low", true)
        .unwrap()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

fn recovery_nt() -> Threshold {
    Threshold::from_json_value(&json!([["1/2", "1"]])).unwrap()
}

#[test]
fn a_recovery_takes_the_revocation_it_supersedes_with_it() {
    let (r0, r1, k, r2, k2) = (key(1), key(2), key(3), key(4), key(5));
    let mut pending = incept(&Inception::new(
        vec![pk(&r0)],
        Threshold::Simple(1),
        vec![NextKey::PublicKey(pk(&r1)), NextKey::PublicKey(pk(&k))],
        recovery_nt(),
    ))
    .unwrap();
    pending.sign_with(&r0 as &dyn KeySigner).unwrap();
    let (icp, state) = pending.finish().unwrap();
    let aid = state.prefix.clone();
    let mut stream = icp.composed.clone();

    // ixn 1: R0 issues a designation in its own registry.
    let (registry, rip) = RegistryState::incept(&aid, &RegistryNonce([7; 16]), DT).unwrap();
    let attributes =
        SadValue::from_json_value(&json!({ "dt": DT, "ids": ["did:webs:example.com:x"] }));
    let credential = registry.designation(ALIASES_V2, &attributes).unwrap();
    let (registry, issued) = registry
        .update(
            &credential.said,
            TransactionState::Issued,
            &BlindingUuid([1; 32]),
            DT,
        )
        .unwrap();
    let mut pending = state.interact(&[rip.seal(), issued.seal()]).unwrap();
    pending.sign_with(&r0 as &dyn KeySigner).unwrap();
    let (ixn1, after_ixn1) = pending.finish().unwrap();
    let at1 = Anchor {
        sn: 1,
        said: ixn1.said.clone(),
    };
    stream.extend(&ixn1.composed);

    // ixn 2: the compromised R0 revokes it.
    let (_, revoked) = registry
        .update(
            &credential.said,
            TransactionState::Revoked,
            &BlindingUuid([2; 32]),
            DT,
        )
        .unwrap();
    let mut pending = after_ixn1.interact(&[revoked.seal()]).unwrap();
    pending.sign_with(&r0 as &dyn KeySigner).unwrap();
    let (ixn2, _) = pending.finish().unwrap();
    let at2 = Anchor {
        sn: 2,
        said: ixn2.said.clone(),
    };
    stream.extend(&ixn2.composed);

    // rot at sn 2, after ixn 1, signed by the recovery key K alone.
    let mut pending = after_ixn1
        .rotate(
            &[pk(&r1), pk(&k)],
            &Rotation::new(
                Threshold::Simple(1),
                vec![NextKey::PublicKey(pk(&r2)), NextKey::PublicKey(pk(&k2))],
                recovery_nt(),
            ),
        )
        .unwrap();
    pending.sign_with(&k as &dyn KeySigner).unwrap();
    let (rot, _) = pending.finish().unwrap();
    stream.extend(&rot.composed);

    // The registry messages, the revocation among them.
    stream.extend(rip.compose(&at1).unwrap());
    stream.extend(credential.compose().unwrap());
    stream.extend(issued.compose(&at1).unwrap());
    stream.extend(revoked.compose(&at2).unwrap());

    let messages = parse_all(&stream).unwrap();

    // The KEL: the rotation supersedes ixn 2.
    let mut kever: Option<Kever> = None;
    for m in messages
        .iter()
        .filter(|m| matches!(m.serder.ilk().as_deref(), Ok("icp" | "ixn" | "rot")))
    {
        match kever.as_mut() {
            None => {
                let verfers = vec![Verfer::from_qb64(&pk(&r0)).unwrap()];
                kever = Some(Kever::new(&m.serder, m.controller_sigs(), &verfers).unwrap());
            }
            Some(kv) => kv.update(&m.serder, m.controller_sigs()).unwrap(),
        }
    }
    let state = kever.unwrap().state().clone();
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.said, rot.said,
        "the rotation is the latest establishment"
    );
    assert_eq!(state.keys, vec![pk(&r1), pk(&k)]);

    // The designation stands: its revocation's only anchor was superseded.
    let log = IssuerLog::replay(&messages, &aid).unwrap();
    let found = registry::designations(&messages, &log, ALIASES_V2).unwrap();
    assert!(found.rejected.is_empty(), "{:?}", found.rejected);
    let [designation] = found.credentials.as_slice() else {
        panic!("one designation: {:?}", found.credentials);
    };
    assert_eq!(designation.said, credential.said);
    assert_eq!(designation.status, Status::Issued);

    // Without the recovery, the same stream reads as revoked.
    let unrecovered: Vec<_> = parse_all(&stream)
        .unwrap()
        .into_iter()
        .filter(|m| m.serder.said().ok().as_deref() != Some(rot.said.as_str()))
        .collect();
    let log = IssuerLog::replay(&unrecovered, &aid).unwrap();
    let found = registry::designations(&unrecovered, &log, ALIASES_V2).unwrap();
    assert_eq!(found.credentials[0].status, Status::Revoked);
}
