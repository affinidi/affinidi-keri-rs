//! End-to-end integration test for KERI witness support.
//!
//! Tests the full lifecycle: controller with 2 witnesses →
//! inception → rotation → interaction, all receipted and verified.

use std::collections::HashMap;

use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::direct;
use affinidi_keri::hab::Hab;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_db::KeriStore;
use affinidi_keri_db::lmdb::LmdbStore;

fn temp_store() -> LmdbStore {
    let dir = tempfile::tempdir().unwrap();
    LmdbStore::open(dir.path()).unwrap()
}

/// Helper: compose a full witnessed message by appending witness receipt
/// couples to the controller's event message.
fn compose_witnessed_message(ctrl_msg: &[u8], witnesses: &[&Hab]) -> Vec<u8> {
    let ctrl_serder = Serder::from_raw(ctrl_msg).unwrap();
    let witness_attachment =
        Hab::compose_witness_receipt_attachment(&ctrl_serder, witnesses).unwrap();

    let mut full_msg = ctrl_msg.to_vec();
    full_msg.extend_from_slice(&witness_attachment);
    full_msg
}

#[test]
fn test_witness_full_lifecycle() {
    // ─── Create 2 non-transferable witness Habs ───
    let w1_store = temp_store();
    let w2_store = temp_store();

    let w1_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0x10u8; 16])
        .build();
    let w2_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0x20u8; 16])
        .build();

    let (w1, _) = Hab::incept("witness1", &w1_config, &w1_store).unwrap();
    let (w2, _) = Hab::incept("witness2", &w2_config, &w2_store).unwrap();

    // Witness backer prefixes are their public keys (verfer qb64)
    let w1_prefix = w1.signers()[0].verfer().qb64().unwrap();
    let w2_prefix = w2.signers()[0].verfer().qb64().unwrap();

    assert!(!w1.transferable());
    assert!(!w2.transferable());
    assert_ne!(w1_prefix, w2_prefix);

    // ─── Create controller Hab with bt=2, backers=[wit1, wit2] ───
    let ctrl_store = temp_store();
    let ctrl_config = InceptionConfig::builder()
        .salt(vec![0x30u8; 16])
        .backer_threshold(2)
        .backers(vec![w1_prefix.clone(), w2_prefix.clone()])
        .build();

    let (mut ctrl, icp_msg) = Hab::incept("controller", &ctrl_config, &ctrl_store).unwrap();
    assert_eq!(ctrl.sn(), 0);

    // ─── Inception: witnesses receipt, verifier processes ───
    let icp_full = compose_witnessed_message(&icp_msg, &[&w1, &w2]);

    let verifier_store = temp_store();
    let mut kevers: HashMap<String, Kever> = HashMap::new();

    let r1 = direct::process_message(&icp_full, &verifier_store, &mut kevers).unwrap();
    assert_eq!(r1.ilk, "icp");
    assert_eq!(r1.sn, 0);
    assert!(kevers.contains_key(ctrl.prefix()));

    let kever = &kevers[ctrl.prefix()];
    assert_eq!(kever.state().backer_threshold, 2);
    assert_eq!(kever.state().backers.len(), 2);
    assert!(kever.state().backers.contains(&w1_prefix));
    assert!(kever.state().backers.contains(&w2_prefix));

    // ─── Rotation: witnesses receipt, verifier processes ───
    let rot_config = RotationConfig::default();
    let rot_msg = ctrl.rotate(&rot_config, &ctrl_store).unwrap();
    assert_eq!(ctrl.sn(), 1);

    let rot_full = compose_witnessed_message(&rot_msg, &[&w1, &w2]);
    let r2 = direct::process_message(&rot_full, &verifier_store, &mut kevers).unwrap();
    assert_eq!(r2.ilk, "rot");
    assert_eq!(r2.sn, 1);
    assert_eq!(kevers[ctrl.prefix()].sn(), 1);

    // ─── Interaction: witnesses receipt, verifier processes ───
    let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
    let ixn_msg = ctrl.interact(&[anchor], &ctrl_store).unwrap();
    assert_eq!(ctrl.sn(), 2);

    let ixn_full = compose_witnessed_message(&ixn_msg, &[&w1, &w2]);
    let r3 = direct::process_message(&ixn_full, &verifier_store, &mut kevers).unwrap();
    assert_eq!(r3.ilk, "ixn");
    assert_eq!(r3.sn, 2);
    assert_eq!(kevers[ctrl.prefix()].sn(), 2);

    // ─── Verify full KEL in verifier's store ───
    let kel = verifier_store.get_kel(ctrl.prefix()).unwrap();
    assert_eq!(kel.len(), 3);
    assert_eq!(kel[0].0, 0); // icp
    assert_eq!(kel[1].0, 1); // rot
    assert_eq!(kel[2].0, 2); // ixn

    // Verify each event is retrievable
    for (_, said) in &kel {
        let event_bytes = verifier_store.get_event(said).unwrap();
        assert!(event_bytes.is_some());
    }
}

#[test]
fn test_witness_receipt_message_stored() {
    // Create witness and controller
    let w_store = temp_store();
    let w_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0x10u8; 16])
        .build();
    let (witness, _) = Hab::incept("witness", &w_config, &w_store).unwrap();

    let ctrl_store = temp_store();
    let ctrl_config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
    let (_ctrl, ctrl_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();

    // Have witness generate and store a receipt message
    let ctrl_serder = Serder::from_raw(&ctrl_msg[..]).unwrap();
    let rct_msg = witness.receipt_message(&ctrl_serder, &w_store).unwrap();

    // Receipt should be stored in witness's store
    let ctrl_said = ctrl_serder.said().unwrap();
    let stored = w_store.get_receipts(&ctrl_said).unwrap();
    assert!(stored.is_some());

    // Parse the receipt message
    let rct_serder = Serder::from_raw(&rct_msg[..]).unwrap();
    assert_eq!(rct_serder.ilk().unwrap(), "rct");
}

#[test]
fn test_inception_without_witnesses_still_works() {
    // Ensure backward compatibility: events with bt=0 work without witnesses
    let ctrl_store = temp_store();
    let ctrl_config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
    let (mut ctrl, icp_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();

    let verifier_store = temp_store();
    let mut kevers: HashMap<String, Kever> = HashMap::new();

    // Should work without any witness receipts (backer_threshold=0)
    let r = direct::process_message(&icp_msg, &verifier_store, &mut kevers).unwrap();
    assert_eq!(r.ilk, "icp");
    assert_eq!(kevers[ctrl.prefix()].state().backer_threshold, 0);

    // Rotation also works without witnesses
    let rot_config = RotationConfig::default();
    let rot_msg = ctrl.rotate(&rot_config, &ctrl_store).unwrap();
    let r2 = direct::process_message(&rot_msg, &verifier_store, &mut kevers).unwrap();
    assert_eq!(r2.ilk, "rot");
    assert_eq!(r2.sn, 1);
}
