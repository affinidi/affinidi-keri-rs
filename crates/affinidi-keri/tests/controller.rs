//! Identifiers whose keys live outside the library, including a recovery key
//! held by someone else: every event is checked by `Kever`, the verifier every
//! reader of the log runs, not only by `PendingEvent::finish`.

use affinidi_cesr::Counter;
use affinidi_keri::controller::{
    ControllerState, Inception, KeySigner, NextKey, PendingEvent, Rotation, incept,
};
use affinidi_keri_core::composer::counter_code_for;
use affinidi_keri_core::counter_table::GroupKind;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{Attachment, parse_all};
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_core::{CoreError, SadValue};
use affinidi_keri_crypto::{Salter, Signer, Verfer};

/// Keys from distinct salts, standing in for keys held in different places.
fn key(seed: u8) -> Signer {
    Salter::new("0A", vec![seed; 16])
        .unwrap()
        .signer("A", "0", "low", true)
        .unwrap()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

/// `["1/2", "1"]`: the recovery key alone meets it, the routine key alone
/// does not.
fn recovery_nt() -> Threshold {
    Threshold::from_json_value(&serde_json::json!([["1/2", "1"]])).unwrap()
}

/// Feed a log through `Kever`, the way a resolver does.
fn verify(log: &[Vec<u8>]) -> Result<Kever, CoreError> {
    let mut kever: Option<Kever> = None;
    for event in log {
        let mut parsed = parse_all(event)?;
        let msg = parsed.remove(0);
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
                let keys: Vec<String> = msg.serder.sad()["k"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| k.as_str().unwrap().to_string())
                    .collect();
                let verfers: Vec<Verfer> =
                    keys.iter().map(|k| Verfer::from_qb64(k).unwrap()).collect();
                kever = Some(Kever::new(&msg.serder, &sigs, &verfers)?);
            }
            Some(k) => k.update(&msg.serder, &sigs)?,
        }
    }
    Ok(kever.expect("a log"))
}

/// Compose an event with whatever signatures it has, bypassing `finish`'s
/// threshold check, so the verifier's own refusal can be tested.
fn compose_unchecked(pending: &PendingEvent, signers: &[(usize, &Signer)]) -> Vec<u8> {
    let raw = pending.signing_input().to_vec();
    let serder = Serder::from_raw(&raw).unwrap();
    let code = counter_code_for(&serder, GroupKind::ControllerIdxSigs).unwrap();
    let mut out = raw.clone();
    out.extend_from_slice(
        Counter::new(code, signers.len())
            .unwrap()
            .qb64()
            .unwrap()
            .as_bytes(),
    );
    for (i, s) in signers {
        out.extend_from_slice(
            s.sign_indexed(&raw, *i, true)
                .unwrap()
                .qb64()
                .unwrap()
                .as_bytes(),
        );
    }
    out
}

struct Identity {
    log: Vec<Vec<u8>>,
    state: ControllerState,
}

/// Incept `k = [R0]`, `n = [H(R1), H(K)]`, `nt = ["1/2","1"]`. The custodian
/// hands over only `K`'s digest.
fn incept_with_recovery(r0: &Signer, r1: &Signer, k: &Signer) -> Identity {
    let k_digest = NextKey::PublicKey(pk(k)).digest().unwrap();
    let mut pending = incept(&Inception::new(
        vec![pk(r0)],
        Threshold::Simple(1),
        vec![NextKey::PublicKey(pk(r1)), NextKey::Digest(k_digest)],
        recovery_nt(),
    ))
    .unwrap();
    pending.sign_with(r0).unwrap();
    let (event, state) = pending.finish().unwrap();
    Identity {
        log: vec![event.composed],
        state,
    }
}

fn next_rotation(r2: &Signer, k2: &Signer) -> Rotation {
    Rotation::new(
        Threshold::Simple(1),
        vec![NextKey::PublicKey(pk(r2)), NextKey::PublicKey(pk(k2))],
        recovery_nt(),
    )
}

#[test]
fn an_inception_committing_a_recovery_key_by_digest_verifies() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let kever = verify(&id.log).expect("inception verifies");
    assert_eq!(kever.state().prefix, id.state.prefix);
    assert_eq!(id.state.next_digests.len(), 2);
}

#[test]
fn the_routine_successor_alone_cannot_rotate() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut pending = id
        .state
        .rotate(&[pk(&r1), pk(&k)], &next_rotation(&key(4), &key(5)))
        .unwrap();
    pending.sign_with(&r1).unwrap();
    assert!(!pending.is_complete(), "R′ weighs 1/2 under the prior nt");
    assert!(matches!(
        pending.clone().finish(),
        Err(affinidi_keri::KeriError::Core(CoreError::ThresholdNotMet))
    ));

    // And the verifier refuses it too, whoever composed it: R′ meets the
    // rotation's own kt "1", but not the nt the inception committed to.
    let mut log = id.log.clone();
    log.push(compose_unchecked(&pending, &[(0, &r1)]));
    assert!(matches!(verify(&log), Err(CoreError::ThresholdNotMet)));
}

#[test]
fn the_recovery_key_alone_can_rotate() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut pending = id
        .state
        .rotate(&[pk(&r1), pk(&k)], &next_rotation(&key(4), &key(5)))
        .unwrap();

    // The custodian signs elsewhere and returns a raw signature, after the
    // pending event has been stored and reloaded.
    let stored = serde_json::to_string(&pending).unwrap();
    let signature = KeySigner::sign(&k, pending.signing_input()).unwrap();
    pending = serde_json::from_str(&stored).unwrap();
    pending.add_signature(1, signature).unwrap();

    let (event, state) = pending.finish().expect("K meets the prior nt");
    let mut log = id.log;
    log.push(event.composed);
    let kever = verify(&log).expect("the recovery rotation verifies");
    assert_eq!(kever.state().keys, vec![pk(&r1), pk(&k)]);
    assert_eq!(state.establishment_sn, 1);
}

#[test]
fn the_routine_and_recovery_keys_together_can_rotate() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut pending = id
        .state
        .rotate(&[pk(&r1), pk(&k)], &next_rotation(&key(4), &key(5)))
        .unwrap();
    pending.sign_with(&r1).unwrap();
    pending.sign_with(&k).unwrap();
    let (event, _) = pending.finish().unwrap();
    let mut log = id.log;
    log.push(event.composed);
    verify(&log).expect("R′ and K together verify");
}

#[test]
fn after_a_rotation_the_routine_key_alone_signs_interactions() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut rot = id
        .state
        .rotate(&[pk(&r1), pk(&k)], &next_rotation(&key(4), &key(5)))
        .unwrap();
    rot.sign_with(&k).unwrap();
    let (rot, state) = rot.finish().unwrap();

    let seal = affinidi_keri_core::sad!({ "d": "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" });
    let mut ixn = state.interact(&[seal]).unwrap();
    ixn.sign_with(&r1).unwrap();
    let (ixn, state) = ixn.finish().unwrap();

    let log = [id.log[0].clone(), rot.composed, ixn.composed];
    let kever = verify(&log).expect("kt \"1\" lets R′ alone sign routine events");
    assert_eq!(kever.state().sn, 2);
    assert_eq!(state.sn, 2);
    assert_eq!(state.establishment_sn, 1);
}

#[test]
fn an_interaction_before_any_rotation_is_signed_by_the_current_key() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut ixn = id.state.interact(&[SadValue::object()]).unwrap();
    assert!(ixn.sign_with(&r1).is_err(), "R′ is not a current key");
    ixn.sign_with(&r0).unwrap();
    let (ixn, _) = ixn.finish().unwrap();
    verify(&[id.log[0].clone(), ixn.composed]).expect("verifies");
}

#[test]
fn a_rotation_must_reveal_exactly_the_committed_keys_in_order() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let rotation = next_rotation(&key(4), &key(5));
    assert!(id.state.rotate(&[pk(&k), pk(&r1)], &rotation).is_err());
    assert!(id.state.rotate(&[pk(&r1)], &rotation).is_err());
    assert!(id.state.rotate(&[pk(&r1), pk(&key(9))], &rotation).is_err());
}

#[test]
fn a_signature_that_does_not_verify_is_refused_when_added() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut pending = id
        .state
        .rotate(&[pk(&r1), pk(&k)], &next_rotation(&key(4), &key(5)))
        .unwrap();
    // R′'s signature offered as K's.
    let wrong = KeySigner::sign(&r1, pending.signing_input()).unwrap();
    assert!(pending.add_signature(1, wrong).is_err());
    assert!(pending.add_signature(7, vec![0; 64]).is_err());
    assert!(pending.signed_indices().is_empty());
}

#[test]
fn a_threshold_that_cannot_be_met_is_refused_at_inception() {
    let (r0, r1) = (key(1), key(2));
    let unmeetable = Threshold::from_json_value(&serde_json::json!([["1/2"]])).unwrap();
    assert!(
        incept(&Inception::new(
            vec![pk(&r0)],
            Threshold::Simple(1),
            vec![NextKey::PublicKey(pk(&r1))],
            unmeetable,
        ))
        .is_err()
    );
}

#[test]
fn a_rotation_committing_no_keys_abandons_the_identifier() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let id = incept_with_recovery(&r0, &r1, &k);
    let mut rot = id
        .state
        .rotate(
            &[pk(&r1), pk(&k)],
            &Rotation::new(Threshold::Simple(1), vec![], Threshold::Simple(0)),
        )
        .unwrap();
    rot.sign_with(&k).unwrap();
    let (rot, state) = rot.finish().unwrap();
    verify(&[id.log[0].clone(), rot.composed]).expect("abandonment verifies");
    assert!(state.rotate(&[], &next_rotation(&key(4), &key(5))).is_err());
}

/// A threshold counts places, not holders, so a key listed twice would let
/// one holder meet `kt "2"` alone. The builder refuses it in `k` and in `n`.
#[test]
fn a_key_listed_twice_is_refused() {
    let (r0, r1, k) = (key(1), key(2), key(3));
    let repeated_k = incept(&Inception::new(
        vec![pk(&r0), pk(&r0)],
        Threshold::Simple(2),
        vec![NextKey::PublicKey(pk(&r1))],
        Threshold::Simple(1),
    ));
    assert!(
        matches!(repeated_k, Err(affinidi_keri::KeriError::Config(m)) if m.contains("more than once"))
    );

    // The same successor named once by key and once by digest is still one key.
    let r1_digest = NextKey::PublicKey(pk(&r1)).digest().unwrap();
    let repeated_n = incept(&Inception::new(
        vec![pk(&r0)],
        Threshold::Simple(1),
        vec![NextKey::PublicKey(pk(&r1)), NextKey::Digest(r1_digest)],
        Threshold::Simple(2),
    ));
    assert!(
        matches!(repeated_n, Err(affinidi_keri::KeriError::Config(m)) if m.contains("more than once"))
    );

    // A rotation cannot put the routine successor in the recovery key's
    // place either: each key is matched to the digest committed at its
    // position, before any threshold is read.
    let id = incept_with_recovery(&r0, &r1, &k);
    let takeover = id
        .state
        .rotate(&[pk(&r1), pk(&r1)], &next_rotation(&key(4), &key(5)));
    assert!(matches!(takeover, Err(affinidi_keri::KeriError::Config(m)) if m.contains("key 1")));
}
