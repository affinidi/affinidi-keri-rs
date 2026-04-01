//! Direct mode protocol.
//!
//! Direct mode is the simplest KERI communication pattern: one identifier
//! sends events directly to another, which verifies signatures and updates
//! its view of the sender's key state.

use std::collections::HashMap;

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, Attachment, ParsedMessage};
use affinidi_keri_core::serder::Serder;
use affinidi_keri_crypto::{Siger, Verfer};
use affinidi_keri_db::KeriStore;

use crate::error::KeriError;

/// The result of processing an incoming message in direct mode.
#[derive(Debug)]
pub struct ProcessResult {
    /// The identifier prefix of the event.
    pub prefix: String,
    /// The sequence number of the event.
    pub sn: u64,
    /// The SAID of the event.
    pub said: String,
    /// The event type (ilk) tag.
    pub ilk: String,
}

/// Extract controller signatures from parsed attachments.
pub(crate) fn extract_controller_sigs(attachments: &[Attachment]) -> Vec<Siger> {
    let mut sigs = Vec::new();
    for att in attachments {
        if let Attachment::ControllerSigs(s) = att {
            sigs.extend_from_slice(s);
        }
    }
    sigs
}

/// Extract verification keys from a serialized event's `"k"` field.
pub(crate) fn verfers_from_serder(serder: &Serder) -> Result<Vec<Verfer>, KeriError> {
    let keys: Vec<String> = serder
        .sad()
        .get("k")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    keys.iter()
        .map(|k| Verfer::from_qb64(k).map_err(KeriError::Crypto))
        .collect::<Result<Vec<_>, _>>()
}

/// Process an incoming message stream in direct mode.
///
/// Parses raw bytes and delegates to [`process_parsed`].
pub fn process_message(
    data: &[u8],
    store: &dyn KeriStore,
    kevers: &mut HashMap<String, Kever>,
) -> Result<ProcessResult, KeriError> {
    let (parsed, _consumed) = parser::parse_next(data)?;
    process_parsed(parsed, store, kevers)
}

/// Process a pre-parsed message in direct mode.
///
/// Takes `ParsedMessage` by value so it can consume the SAD without cloning.
///
/// 1. Verifies controller signatures via `Kever`.
/// 2. Verifies witness receipt couples when a backer threshold is set.
/// 3. Stores the event, KEL entry, signatures, and receipts.
/// 4. Tracks verified key state in the `kevers` map.
///
/// Returns a `ProcessResult` describing the processed event.
pub fn process_parsed(
    mut parsed: ParsedMessage,
    store: &dyn KeriStore,
    kevers: &mut HashMap<String, Kever>,
) -> Result<ProcessResult, KeriError> {
    let prefix = parsed.serder.prefix()?;
    let sn = parsed.serder.sn()?;
    let said = parsed.serder.said()?;
    let ilk = parsed.serder.ilk()?;

    // Separate attachment types
    let controller_sigs = extract_controller_sigs(&parsed.attachments);
    let mut receipt_couples = Vec::new();
    let mut raw_sig_bytes = Vec::new();

    for att in &parsed.attachments {
        match att {
            Attachment::ControllerSigs(sigs) => {
                for sig in sigs {
                    let qb64 = sig.qb64().map_err(KeriError::Crypto)?;
                    raw_sig_bytes.extend_from_slice(qb64.as_bytes());
                }
            }
            Attachment::ReceiptCouples(couples) => {
                receipt_couples.extend_from_slice(couples);
            }
            Attachment::WitnessSigs(_) | Attachment::Raw(_) => {}
        }
    }

    match ilk.as_str() {
        "icp" | "dip" => {
            // Extract verfers before consuming the SAD
            let verfers = verfers_from_serder(&parsed.serder)?;

            // Take ownership of the SAD to avoid cloning during deserialization
            let sad = parsed.serder.take_sad();
            let kever =
                Kever::new_from_parts(parsed.serder.raw(), sad, &controller_sigs, &verfers)?;

            // Verify witness receipts if backer threshold > 0
            if kever.state().backer_threshold > 0 {
                kever.verify_witness_receipts(parsed.serder.raw(), &receipt_couples)?;
            }

            // Store event, KEL, first-seen, signatures in one transaction
            let sigs =
                if raw_sig_bytes.is_empty() { None } else { Some(raw_sig_bytes.as_slice()) };
            store.store_event(&said, parsed.serder.raw(), &prefix, sn, sigs)?;

            kevers.insert(prefix.clone(), kever);
        }
        "rot" | "ixn" | "drt" => {
            if let Some(kever) = kevers.get_mut(&prefix) {
                // Take ownership of the SAD and verify without cloning
                let sad = parsed.serder.take_sad();
                let new_state = kever.verify_update_owned(
                    parsed.serder.raw(),
                    sad,
                    &controller_sigs,
                )?;

                // Verify witness receipts against the proposed state
                if new_state.backer_threshold > 0 {
                    Kever::verify_witness_receipts_static(
                        parsed.serder.raw(),
                        &receipt_couples,
                        &new_state.backers,
                        new_state.backer_threshold,
                    )?;
                }

                // All checks passed — commit the update
                kever.apply_verified_update(new_state);

                let sigs =
                    if raw_sig_bytes.is_empty() { None } else { Some(raw_sig_bytes.as_slice()) };
                store.store_event(&said, parsed.serder.raw(), &prefix, sn, sigs)?;
            }
            // If no kever exists, in direct mode we skip
            // (a full implementation would escrow)
        }
        "rct" => {
            // Receipt message: store the receipt couples
            // The receipt references the receipted event's prefix/sn
            if !receipt_couples.is_empty() {
                // Serialize couples for storage
                let mut rct_bytes = Vec::new();
                for (pfx, sig) in &receipt_couples {
                    rct_bytes.extend_from_slice(pfx.as_bytes());
                    rct_bytes.extend_from_slice(sig);
                }
                store.put_receipts(&said, &rct_bytes)?;
            }
        }
        _ => {
            // Other message types — just store
            store.put_event(&said, parsed.serder.raw())?;
        }
    }

    Ok(ProcessResult {
        prefix,
        sn,
        said,
        ilk,
    })
}

/// Minimal key state entry tracked by the direct mode verifier.
///
/// Provides a lightweight snapshot of a Kever's state for external consumption.
#[derive(Debug, Clone)]
pub struct KeyStateEntry {
    /// The identifier prefix.
    pub prefix: String,
    /// The latest seen sequence number.
    pub sn: u64,
    /// The SAID of the latest processed event.
    pub said: String,
}

impl From<&Kever> for KeyStateEntry {
    fn from(kever: &Kever) -> Self {
        Self {
            prefix: kever.prefix().to_string(),
            sn: kever.sn(),
            said: kever.state().last_event_digest.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InceptionConfig, RotationConfig};
    use crate::hab::Hab;
    use affinidi_keri_db::lmdb::LmdbStore;

    fn temp_store() -> LmdbStore {
        let dir = tempfile::tempdir().unwrap();
        LmdbStore::open(dir.path()).unwrap()
    }

    #[test]
    fn test_direct_mode_process_inception() {
        let creator_store = temp_store();
        let config = InceptionConfig::builder()
            .salt(vec![0x01u8; 16])
            .build();
        let (hab, msg) = Hab::incept("alice", &config, &creator_store).unwrap();

        // Receiver processes the message
        let receiver_store = temp_store();
        let mut kevers = HashMap::new();

        let result = process_message(&msg, &receiver_store, &mut kevers).unwrap();
        assert_eq!(result.prefix, hab.prefix());
        assert_eq!(result.sn, 0);
        assert_eq!(result.ilk, "icp");

        // Verify kever was created
        assert!(kevers.contains_key(hab.prefix()));
        assert_eq!(kevers[hab.prefix()].sn(), 0);

        // Verify event was stored
        let stored = receiver_store.get_event(&result.said).unwrap();
        assert!(stored.is_some());

        // Verify KEL was stored
        let kel = receiver_store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 1);
    }

    #[test]
    fn test_direct_mode_process_rotation() {
        let creator_store = temp_store();
        let config = InceptionConfig::builder()
            .salt(vec![0x01u8; 16])
            .build();
        let (mut hab, icp_msg) = Hab::incept("alice", &config, &creator_store).unwrap();

        let rot_config = RotationConfig::default();
        let rot_msg = hab.rotate(&rot_config, &creator_store).unwrap();

        // Receiver processes both messages
        let receiver_store = temp_store();
        let mut kevers = HashMap::new();

        process_message(&icp_msg, &receiver_store, &mut kevers).unwrap();
        let result = process_message(&rot_msg, &receiver_store, &mut kevers).unwrap();

        assert_eq!(result.sn, 1);
        assert_eq!(result.ilk, "rot");
        assert_eq!(kevers[hab.prefix()].sn(), 1);

        // Verify KEL has two entries
        let kel = receiver_store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 2);
    }

    #[test]
    fn test_direct_mode_end_to_end_roundtrip() {
        let creator_store = temp_store();
        let config = InceptionConfig::builder()
            .salt(vec![0x42u8; 16])
            .build();
        let (mut hab, icp_msg) = Hab::incept("alice", &config, &creator_store).unwrap();

        // Rotate
        let rot_config = RotationConfig::default();
        let rot_msg = hab.rotate(&rot_config, &creator_store).unwrap();

        // Interact with anchor
        let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
        let ixn_msg = hab.interact(&[anchor], &creator_store).unwrap();

        // Receiver processes all three events
        let receiver_store = temp_store();
        let mut kevers = HashMap::new();

        let r1 = process_message(&icp_msg, &receiver_store, &mut kevers).unwrap();
        assert_eq!(r1.ilk, "icp");
        assert_eq!(r1.sn, 0);

        let r2 = process_message(&rot_msg, &receiver_store, &mut kevers).unwrap();
        assert_eq!(r2.ilk, "rot");
        assert_eq!(r2.sn, 1);

        let r3 = process_message(&ixn_msg, &receiver_store, &mut kevers).unwrap();
        assert_eq!(r3.ilk, "ixn");
        assert_eq!(r3.sn, 2);

        // Verify final state
        let kever = &kevers[hab.prefix()];
        assert_eq!(kever.sn(), 2);

        // Verify full KEL in receiver's store
        let kel = receiver_store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 3);
        assert_eq!(kel[0].0, 0);
        assert_eq!(kel[1].0, 1);
        assert_eq!(kel[2].0, 2);

        // Verify each event can be retrieved from the store
        for (_, said) in &kel {
            let event_bytes = receiver_store.get_event(said).unwrap();
            assert!(event_bytes.is_some());
        }
    }

    #[test]
    fn test_direct_mode_multiple_identifiers() {
        let store_a = temp_store();
        let store_b = temp_store();
        let config = InceptionConfig::default();

        let (hab_a, msg_a) = Hab::incept("alice", &config, &store_a).unwrap();
        let (hab_b, msg_b) = Hab::incept("bob", &config, &store_b).unwrap();

        // Verifier processes both inception events
        let verifier_store = temp_store();
        let mut kevers = HashMap::new();

        process_message(&msg_a, &verifier_store, &mut kevers).unwrap();
        process_message(&msg_b, &verifier_store, &mut kevers).unwrap();

        assert_eq!(kevers.len(), 2);
        assert!(kevers.contains_key(hab_a.prefix()));
        assert!(kevers.contains_key(hab_b.prefix()));
    }

    #[test]
    fn test_direct_mode_inception_with_witnesses() {
        // Create two non-transferable witnesses
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
        let (w1, _) = Hab::incept("wit1", &w1_config, &w1_store).unwrap();
        let (w2, _) = Hab::incept("wit2", &w2_config, &w2_store).unwrap();

        // Use the witness verfer qb64 as backer prefixes (non-transferable
        // witness prefix IS the public key)
        let w1_verfer = w1.signers()[0].verfer().qb64().unwrap();
        let w2_verfer = w2.signers()[0].verfer().qb64().unwrap();

        // Create controller with backer_threshold=2
        let ctrl_store = temp_store();
        let ctrl_config = InceptionConfig::builder()
            .salt(vec![0x30u8; 16])
            .backer_threshold(2)
            .backers(vec![w1_verfer, w2_verfer])
            .build();
        let (ctrl, ctrl_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();

        // Parse the event to get the serder
        let ctrl_serder =
            affinidi_keri_core::serder::Serder::from_raw(&ctrl_msg[..]).unwrap();

        // Witnesses receipt the inception
        let witness_attachment =
            Hab::compose_witness_receipt_attachment(&ctrl_serder, &[&w1, &w2]).unwrap();

        // Compose full message: event + controller sigs + witness receipts
        let mut full_msg = ctrl_msg.clone();
        full_msg.extend_from_slice(&witness_attachment);

        // Verifier processes
        let verifier_store = temp_store();
        let mut kevers = HashMap::new();
        let result = process_message(&full_msg, &verifier_store, &mut kevers).unwrap();

        assert_eq!(result.ilk, "icp");
        assert_eq!(result.prefix, ctrl.prefix());
        assert!(kevers.contains_key(ctrl.prefix()));
        assert_eq!(kevers[ctrl.prefix()].state().backer_threshold, 2);
    }

    #[test]
    fn test_direct_mode_inception_insufficient_witnesses_fails() {
        // Create two non-transferable witnesses
        let w1_store = temp_store();
        let w1_config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x10u8; 16])
            .build();
        let (w1, _) = Hab::incept("wit1", &w1_config, &w1_store).unwrap();

        let w2_store = temp_store();
        let w2_config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x20u8; 16])
            .build();
        let (w2, _) = Hab::incept("wit2", &w2_config, &w2_store).unwrap();

        let w1_verfer = w1.signers()[0].verfer().qb64().unwrap();
        let w2_verfer = w2.signers()[0].verfer().qb64().unwrap();

        // Controller requires 2 witnesses
        let ctrl_store = temp_store();
        let ctrl_config = InceptionConfig::builder()
            .salt(vec![0x30u8; 16])
            .backer_threshold(2)
            .backers(vec![w1_verfer, w2_verfer])
            .build();
        let (_ctrl, ctrl_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();

        // Only have 1 witness receipt
        let ctrl_serder =
            affinidi_keri_core::serder::Serder::from_raw(&ctrl_msg[..]).unwrap();
        let witness_attachment =
            Hab::compose_witness_receipt_attachment(&ctrl_serder, &[&w1]).unwrap();

        let mut full_msg = ctrl_msg.clone();
        full_msg.extend_from_slice(&witness_attachment);

        // Should fail — need 2 witnesses, only have 1
        let verifier_store = temp_store();
        let mut kevers = HashMap::new();
        let result = process_message(&full_msg, &verifier_store, &mut kevers);
        assert!(result.is_err());
    }

    #[test]
    fn test_direct_mode_rct_message_processing() {
        // Create controller
        let ctrl_store = temp_store();
        let ctrl_config = InceptionConfig::builder()
            .salt(vec![0x01u8; 16])
            .build();
        let (ctrl, ctrl_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();

        // Process inception first
        let verifier_store = temp_store();
        let mut kevers = HashMap::new();
        process_message(&ctrl_msg, &verifier_store, &mut kevers).unwrap();

        // Create a witness and have it send a receipt message
        let w_store = temp_store();
        let w_config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x50u8; 16])
            .build();
        let (witness, _) = Hab::incept("witness", &w_config, &w_store).unwrap();

        let ctrl_serder =
            affinidi_keri_core::serder::Serder::from_raw(&ctrl_msg[..]).unwrap();
        let rct_msg = witness.receipt_message(&ctrl_serder, &w_store).unwrap();

        // Process the receipt message
        let result = process_message(&rct_msg, &verifier_store, &mut kevers).unwrap();
        assert_eq!(result.ilk, "rct");

        // Controller kever should still be there and unchanged
        assert!(kevers.contains_key(ctrl.prefix()));
        assert_eq!(kevers[ctrl.prefix()].sn(), 0);
    }
}
