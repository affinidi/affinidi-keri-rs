//! An identifier resumed from persisted state must be indistinguishable from
//! one that was never interrupted.
//!
//! This is what makes a key event log usable across a process boundary. The
//! log alone is not enough to continue it: pre-rotated keys are committed to
//! by digest, so they cannot be recovered from the log, and a process that
//! lost them could never rotate again.

use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::hab::Hab;

const SALT: &[u8] = &[7u8; 16];

fn config() -> InceptionConfig {
    InceptionConfig::builder().salt(SALT.to_vec()).build()
}

/// Incept without a store, as a caller keeping the log elsewhere would.
fn incept() -> Hab {
    let (hab, _event) = Hab::incept_event("alice", &config()).expect("incept");
    hab
}

#[test]
fn a_resumed_identifier_produces_the_same_rotation() {
    // One identifier rotates straight through; the other is serialized,
    // dropped, and rebuilt from its state and salt first. Both must emit byte
    // for byte the same event — anything else means the resumed one signed
    // with different keys.
    let mut continuous = incept();
    let interrupted = incept();

    let state = interrupted.state();
    let json = serde_json::to_vec(&state).expect("state serializes");
    drop(interrupted);

    let restored: affinidi_keri::hab::HabState =
        serde_json::from_slice(&json).expect("state round-trips");
    let mut resumed = Hab::resume(&restored, SALT).expect("resume");

    let a = continuous
        .rotate_event(&RotationConfig::default())
        .expect("rotate");
    let b = resumed
        .rotate_event(&RotationConfig::default())
        .expect("rotate");

    assert_eq!(
        a.said, b.said,
        "a resumed identifier must produce the same event"
    );
    assert_eq!(a.composed, b.composed);
    assert_eq!(continuous.state(), resumed.state());
}

#[test]
fn resuming_survives_several_rotations() {
    // The generation counter advances by two per rotation and skips an index,
    // so the relationship between it and the key paths is not uniform. Resume
    // has to reproduce the paths exactly, at every point in the sequence.
    let mut continuous = incept();
    let mut interrupted = incept();

    for round in 0..4 {
        // Round-trip the interrupted one through its state before every step.
        let json = serde_json::to_vec(&interrupted.state()).expect("serializes");
        let state: affinidi_keri::hab::HabState =
            serde_json::from_slice(&json).expect("deserializes");
        interrupted = Hab::resume(&state, SALT).expect("resume");

        let a = continuous
            .rotate_event(&RotationConfig::default())
            .expect("rotate");
        let b = interrupted
            .rotate_event(&RotationConfig::default())
            .expect("rotate");

        assert_eq!(a.composed, b.composed, "diverged at rotation {round}");
    }

    assert_eq!(continuous.state(), interrupted.state());
}

#[test]
fn a_resumed_identifier_produces_the_same_interaction() {
    let mut continuous = incept();
    let mut resumed = Hab::resume(&incept().state(), SALT).expect("resume");

    let anchors = vec![serde_json::json!({"d": "EAnchor"})];
    let a = continuous.interact_event(&anchors).expect("interact");
    let b = resumed.interact_event(&anchors).expect("interact");

    assert_eq!(a.composed, b.composed);
}

#[test]
fn a_resumed_identifier_interacts_correctly_after_rotation() {
    // The discriminating case for the generation indices. Interactions are
    // signed by the *current* keys, and after a rotation those sit at a
    // generation the counter does not point at — `key_gen` is 4 while the
    // current keys are at generation 1, because `rotate` advances the counter
    // by two and skips an index.
    //
    // Resuming straight after inception cannot catch a wrong derivation, since
    // every plausible formula agrees there. It has to be after a rotation.
    let mut continuous = incept();
    let mut interrupted = incept();

    continuous
        .rotate_event(&RotationConfig::default())
        .expect("rotate");
    interrupted
        .rotate_event(&RotationConfig::default())
        .expect("rotate");

    let mut resumed = Hab::resume(&interrupted.state(), SALT).expect("resume");

    let anchors = vec![serde_json::json!({"d": "EAnchor"})];
    let a = continuous.interact_event(&anchors).expect("interact");
    let b = resumed.interact_event(&anchors).expect("interact");

    assert_eq!(
        a.composed, b.composed,
        "a resumed identifier must sign interactions with the same current keys",
    );
}

#[test]
fn the_wrong_salt_produces_different_keys() {
    // Resume cannot detect a wrong salt — the state carries no key material to
    // check against. What it must not do is silently produce the *same* event,
    // which would mean the salt was not being used.
    let mut right = Hab::resume(&incept().state(), SALT).expect("resume");
    let mut wrong = Hab::resume(&incept().state(), &[9u8; 16]).expect("resume");

    let a = right
        .rotate_event(&RotationConfig::default())
        .expect("rotate");
    let b = wrong
        .rotate_event(&RotationConfig::default())
        .expect("rotate");

    assert_ne!(
        a.composed, b.composed,
        "a different salt must derive different keys",
    );
}

#[test]
fn a_signed_event_carries_its_parts() {
    let (_hab, event) = Hab::incept_event("alice", &config()).expect("incept");

    assert!(!event.said.is_empty());
    assert!(event.composed.starts_with(&event.raw), "body comes first");
    assert!(
        event.composed.ends_with(&event.signatures),
        "signatures come last",
    );
    assert_eq!(
        event.composed.len(),
        event.raw.len() + 4 + event.signatures.len(),
        "body, a counter, then signatures",
    );
}

#[test]
fn incepting_without_a_store_matches_incepting_with_one() {
    use affinidi_keri_db::lmdb::LmdbStore;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = LmdbStore::open(dir.path()).expect("store");

    let (stored, stored_bytes) = Hab::incept("alice", &config(), &store).expect("incept");
    let (unstored, unstored_event) = Hab::incept_event("alice", &config()).expect("incept");

    assert_eq!(stored_bytes, unstored_event.composed);
    assert_eq!(stored.prefix(), unstored.prefix());
    assert_eq!(stored.state(), unstored.state());
}

#[test]
fn a_store_backed_identifier_can_be_resumed() {
    use affinidi_keri::habery::Habery;
    use affinidi_keri_db::lmdb::LmdbStore;

    let dir = tempfile::tempdir().expect("tempdir");

    // Incept, remember the prefix, then drop everything in memory — as a
    // process restart would.
    let prefix = {
        let store = LmdbStore::open(dir.path()).expect("store");
        let mut habery = Habery::new(Box::new(store));
        habery.incept("alice", &config()).expect("incept");
        habery
            .get("alice")
            .expect("registered")
            .prefix()
            .to_string()
    };

    // A fresh Habery over the same store knows nothing until it resumes.
    let store = LmdbStore::open(dir.path()).expect("store");
    let mut habery = Habery::new(Box::new(store));
    assert!(habery.get("alice").is_none(), "nothing is loaded eagerly");

    let resumed = habery.resume("alice", SALT).expect("resume");
    assert_eq!(resumed.prefix(), prefix);

    // And it can actually continue the log, which is the whole point.
    habery
        .rotate("alice", &RotationConfig::default())
        .expect("a resumed identifier must be able to rotate");
}

#[test]
fn resuming_an_unknown_identifier_is_an_error() {
    use affinidi_keri::habery::Habery;
    use affinidi_keri_db::lmdb::LmdbStore;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = LmdbStore::open(dir.path()).expect("store");
    let mut habery = Habery::new(Box::new(store));

    assert!(habery.resume("nobody", SALT).is_err());
}
