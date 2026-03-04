//! Demo: KERI Witness Support — Receipt Generation, Verification & Processing
//!
//! Run with: cargo run -p affinidi-keri --example demo_witness
//!
//! Witnesses are designated receipt signers that provide two guarantees:
//!   1. **Duplicity detection** — a witness will only sign one version of an
//!      event at a given sequence number, so conflicting events can be caught.
//!   2. **Availability** — witnesses store and serve the events they receipt,
//!      making the controller's KEL available even when the controller is offline.
//!
//! This example walks through the full witnessed lifecycle:
//!   1. Create non-transferable witness identities
//!   2. Create a controller identity that designates those witnesses
//!   3. Witnesses receipt the inception event
//!   4. A verifier processes the witnessed inception (sigs + receipts)
//!   5. Controller rotates keys — witnesses receipt the rotation
//!   6. Controller creates an interaction event — witnesses receipt it
//!   7. Demonstrate that insufficient witnesses are rejected
//!   8. Display the full verified Key Event Log

use std::collections::HashMap;

use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::direct;
use affinidi_keri::hab::Hab;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, Attachment};
use affinidi_keri_core::serder::Serder;
use affinidi_keri_db::lmdb::LmdbStore;
use affinidi_keri_db::KeriStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║            KERI Witness Demo: Receipts & Verification      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 1: Create Non-Transferable Witness Identities
    // ─────────────────────────────────────────────────────────────────────
    // Witnesses use non-transferable identifiers so their public key IS
    // their prefix — no KEL lookup needed to verify their receipts.

    println!("── Step 1: Create Non-Transferable Witness Identities ──");
    println!();

    let wit1_dir = tempfile::tempdir()?;
    let wit1_store = LmdbStore::open(wit1_dir.path())?;
    let wit1_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0xA1u8; 16])
        .build();
    let (wit1, _wit1_msg) = Hab::incept("witness-alpha", &wit1_config, &wit1_store)?;
    let wit1_prefix = wit1.signers()[0].verfer().qb64()?;

    let wit2_dir = tempfile::tempdir()?;
    let wit2_store = LmdbStore::open(wit2_dir.path())?;
    let wit2_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0xB2u8; 16])
        .build();
    let (wit2, _wit2_msg) = Hab::incept("witness-beta", &wit2_config, &wit2_store)?;
    let wit2_prefix = wit2.signers()[0].verfer().qb64()?;

    let wit3_dir = tempfile::tempdir()?;
    let wit3_store = LmdbStore::open(wit3_dir.path())?;
    let wit3_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0xC3u8; 16])
        .build();
    let (wit3, _) = Hab::incept("witness-gamma", &wit3_config, &wit3_store)?;
    let wit3_prefix = wit3.signers()[0].verfer().qb64()?;

    println!("  Witness alpha:  {wit1_prefix}");
    println!("    transferable: false");
    println!("    verfer code:  {} (Ed25519 non-transferable)", wit1.signers()[0].verfer().code());
    println!();
    println!("  Witness beta:   {wit2_prefix}");
    println!("    transferable: false");
    println!("    verfer code:  {} (Ed25519 non-transferable)", wit2.signers()[0].verfer().code());
    println!();
    println!("  Witness gamma:  {wit3_prefix}");
    println!("    transferable: false");
    println!("    verfer code:  {} (Ed25519 non-transferable)", wit3.signers()[0].verfer().code());
    println!();
    println!("  Key insight: code \"B\" means the prefix IS the public key.");
    println!("  No KEL lookup needed — we can verify receipts directly.");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 2: Create Controller Identity with Designated Witnesses
    // ─────────────────────────────────────────────────────────────────────
    // The controller designates witnesses in the inception event via:
    //   bt (backer threshold) — how many receipts are required
    //   b  (backers)          — the list of witness prefixes

    println!("── Step 2: Create Controller with bt=2, backers=[alpha, beta, gamma] ──");
    println!();

    let ctrl_dir = tempfile::tempdir()?;
    let ctrl_store = LmdbStore::open(ctrl_dir.path())?;
    let ctrl_config = InceptionConfig::builder()
        .salt(vec![0x42u8; 16])
        .backer_threshold(2) // require 2-of-3 witness receipts
        .backers(vec![
            wit1_prefix.clone(),
            wit2_prefix.clone(),
            wit3_prefix.clone(),
        ])
        .build();

    let (mut ctrl, icp_msg) = Hab::incept("controller", &ctrl_config, &ctrl_store)?;

    // Show the inception event JSON — note the bt and b fields
    let icp_serder = Serder::from_raw(&icp_msg)?;
    let icp_json: serde_json::Value = serde_json::from_slice(icp_serder.raw())?;
    println!("  Controller AID: {}", ctrl.prefix());
    println!("  Inception event (showing witness fields):");
    println!("    bt: {}  (backer threshold — receipts needed)", icp_json["bt"]);
    println!("    b:  [");
    if let Some(arr) = icp_json["b"].as_array() {
        for (i, b) in arr.iter().enumerate() {
            let label = match i {
                0 => "alpha",
                1 => "beta",
                2 => "gamma",
                _ => "?",
            };
            println!("      {}  ({label})", b.as_str().unwrap_or(""));
        }
    }
    println!("    ]");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 3: Witnesses Receipt the Inception Event
    // ─────────────────────────────────────────────────────────────────────
    // Each witness signs the raw event bytes with its non-transferable key,
    // producing a Cigar (non-indexed signature). The receipt attachment uses
    // the -D counter code for "non-transferable receipt couples":
    //   -D<count> + (prefix_qb64 + cigar_qb64) per witness

    println!("── Step 3: Witnesses Receipt the Inception Event ──");
    println!();

    // Each witness generates a receipt
    let rct1 = wit1.receipt(&icp_serder)?;
    let rct2 = wit2.receipt(&icp_serder)?;
    let rct3 = wit3.receipt(&icp_serder)?;

    println!("  Witness alpha receipt: {} bytes", rct1.len());
    println!("    counter: -D (non-transferable receipt couples)");
    println!("    format:  -DAB + prefix(44) + cigar(88) = {} bytes", rct1.len());
    println!();
    println!("  Witness beta receipt:  {} bytes", rct2.len());
    println!("  Witness gamma receipt: {} bytes", rct3.len());
    println!();

    // Also show the full receipt message (rct event body + attachment)
    let rct1_full = wit1.receipt_message(&icp_serder, &wit1_store)?;
    let rct1_parsed = Serder::from_raw(&rct1_full)?;
    let rct1_json: serde_json::Value = serde_json::from_slice(rct1_parsed.raw())?;
    println!("  Full receipt message from alpha (rct event body):");
    println!("{}", serde_json::to_string_pretty(&rct1_json)?);
    println!();
    println!("  The receipt body references the inception by prefix+sn,");
    println!("  and the -D attachment carries the witness signature.");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 4: Verifier Processes Witnessed Inception
    // ─────────────────────────────────────────────────────────────────────
    // The verifier receives: event body + controller sigs (-B) + witness
    // receipt couples (-D). It verifies controller sigs via Kever, then
    // checks that enough designated witnesses have receipted the event.

    println!("── Step 4: Verifier Processes Witnessed Inception ──");
    println!();

    // Compose the full witnessed message: event + ctrl sigs + witness receipts
    let witness_att = Hab::compose_witness_receipt_attachment(&icp_serder, &[&wit1, &wit2, &wit3])?;
    let mut icp_witnessed = icp_msg.clone();
    icp_witnessed.extend_from_slice(&witness_att);

    // Show what the parser extracts
    let (parsed, _) = parser::parse_next(&icp_witnessed)?;
    println!("  Message size: {} bytes total", icp_witnessed.len());
    println!("    Event body:  {} bytes (JSON)", parsed.serder.size());
    println!("    Attachments: {}", parsed.attachments.len());
    for (i, att) in parsed.attachments.iter().enumerate() {
        match att {
            Attachment::ControllerSigs(sigs) => {
                println!("    [{i}] -B ControllerSigs: {} indexed signature(s)", sigs.len());
            }
            Attachment::ReceiptCouples(couples) => {
                println!(
                    "    [{i}] -D ReceiptCouples: {} witness receipt(s)",
                    couples.len()
                );
                for (j, (pfx, sig)) in couples.iter().enumerate() {
                    let label = if *pfx == wit1_prefix {
                        "alpha"
                    } else if *pfx == wit2_prefix {
                        "beta"
                    } else if *pfx == wit3_prefix {
                        "gamma"
                    } else {
                        "?"
                    };
                    println!(
                        "      [{j}] prefix={}...  sig={} bytes  ({label})",
                        &pfx[..20],
                        sig.len()
                    );
                }
            }
            Attachment::WitnessSigs(sigs) => {
                println!("    [{i}] -C WitnessSigs: {} signature(s)", sigs.len());
            }
            Attachment::Raw(raw) => {
                println!("    [{i}] Raw: {} bytes", raw.len());
            }
        }
    }
    println!();

    // Process through direct mode — verifies controller sigs AND witness receipts
    let verifier_dir = tempfile::tempdir()?;
    let verifier_store = LmdbStore::open(verifier_dir.path())?;
    let mut kevers: HashMap<String, Kever> = HashMap::new();

    let r1 = direct::process_message(&icp_witnessed, &verifier_store, &mut kevers)?;
    let kever = &kevers[ctrl.prefix()];

    println!("  Verification result:");
    println!("    ilk:              {}", r1.ilk);
    println!("    prefix:           {}", r1.prefix);
    println!("    sn:               {}", r1.sn);
    println!("    controller sigs:  VERIFIED (threshold met)");
    println!("    witness receipts: VERIFIED (2-of-3 threshold met, 3 provided)");
    println!("    backer_threshold: {}", kever.state().backer_threshold);
    println!("    backers:          {} designated witnesses", kever.state().backers.len());
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 5: Controller Rotates — Witnesses Receipt the Rotation
    // ─────────────────────────────────────────────────────────────────────

    println!("── Step 5: Key Rotation with Witness Receipts ──");
    println!();

    let rot_config = RotationConfig::default();
    let rot_msg = ctrl.rotate(&rot_config, &ctrl_store)?;

    let rot_serder = Serder::from_raw(&rot_msg)?;
    let rot_witness_att = Hab::compose_witness_receipt_attachment(&rot_serder, &[&wit1, &wit2])?;
    let mut rot_witnessed = rot_msg.clone();
    rot_witnessed.extend_from_slice(&rot_witness_att);

    let r2 = direct::process_message(&rot_witnessed, &verifier_store, &mut kevers)?;

    let rot_json: serde_json::Value = serde_json::from_slice(rot_serder.raw())?;
    println!("  Rotation event (sn={}):", r2.sn);
    println!("    new signing key: {}", rot_json["k"][0].as_str().unwrap_or(""));
    println!("    prior SAID:      {}", rot_json["p"].as_str().unwrap_or(""));
    println!("    witnesses:       alpha + beta receipted (2-of-3)");
    println!("    verification:    PASSED");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 6: Interaction Event — Witnesses Receipt It
    // ─────────────────────────────────────────────────────────────────────

    println!("── Step 6: Interaction Event with Witness Receipts ──");
    println!();

    let anchor = serde_json::json!({
        "d": "EAnchored_data_digest_placeholder_______"
    });
    let ixn_msg = ctrl.interact(&[anchor], &ctrl_store)?;

    let ixn_serder = Serder::from_raw(&ixn_msg)?;
    let ixn_witness_att =
        Hab::compose_witness_receipt_attachment(&ixn_serder, &[&wit2, &wit3])?;
    let mut ixn_witnessed = ixn_msg.clone();
    ixn_witnessed.extend_from_slice(&ixn_witness_att);

    let r3 = direct::process_message(&ixn_witnessed, &verifier_store, &mut kevers)?;

    println!("  Interaction event (sn={}):", r3.sn);
    println!("    witnesses: beta + gamma receipted (2-of-3)");
    println!("    note: any 2 of the 3 designated witnesses suffice");
    println!("    verification: PASSED");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 7: Demonstrate Insufficient Witnesses → Rejection
    // ─────────────────────────────────────────────────────────────────────

    println!("── Step 7: Insufficient Witnesses are Rejected ──");
    println!();

    // Create another interaction but only provide 1 witness receipt
    let anchor2 = serde_json::json!({"d": "ESecondAnchor___________________________"});
    let ixn2_msg = ctrl.interact(&[anchor2], &ctrl_store)?;
    let ixn2_serder = Serder::from_raw(&ixn2_msg)?;

    // Only 1 witness out of required 2
    let ixn2_partial_att =
        Hab::compose_witness_receipt_attachment(&ixn2_serder, &[&wit1])?;
    let mut ixn2_partial = ixn2_msg.clone();
    ixn2_partial.extend_from_slice(&ixn2_partial_att);

    // This should fail because we need 2 receipts but only have 1
    let bad_store = LmdbStore::open(tempfile::tempdir()?.path())?;
    let mut bad_kevers: HashMap<String, Kever> = HashMap::new();

    // First re-process inception so the kever exists
    let icp_full_for_bad = {
        let att = Hab::compose_witness_receipt_attachment(
            &Serder::from_raw(&icp_msg)?,
            &[&wit1, &wit2, &wit3],
        )?;
        let mut m = icp_msg.clone();
        m.extend_from_slice(&att);
        m
    };
    direct::process_message(&icp_full_for_bad, &bad_store, &mut bad_kevers)?;
    // Re-process the rotation and first interaction so sn is current
    let rot_full_for_bad = {
        let att = Hab::compose_witness_receipt_attachment(
            &Serder::from_raw(&rot_msg)?,
            &[&wit1, &wit2],
        )?;
        let mut m = rot_msg.clone();
        m.extend_from_slice(&att);
        m
    };
    direct::process_message(&rot_full_for_bad, &bad_store, &mut bad_kevers)?;
    let ixn_full_for_bad = {
        let att = Hab::compose_witness_receipt_attachment(
            &Serder::from_raw(&ixn_msg)?,
            &[&wit2, &wit3],
        )?;
        let mut m = ixn_msg.clone();
        m.extend_from_slice(&att);
        m
    };
    direct::process_message(&ixn_full_for_bad, &bad_store, &mut bad_kevers)?;

    // Now try the under-witnessed event
    match direct::process_message(&ixn2_partial, &bad_store, &mut bad_kevers) {
        Err(e) => {
            println!("  Submitted interaction with only 1-of-3 witness receipts...");
            println!("  Result: REJECTED");
            println!("  Error:  {e}");
            println!();
            println!("  This is correct! The backer threshold requires 2 receipts.");
            println!("  The verifier refuses to accept under-witnessed events.");
        }
        Ok(_) => {
            println!("  ERROR: should have been rejected!");
        }
    }
    println!();

    // Now provide enough receipts — should succeed
    let ixn2_full_att =
        Hab::compose_witness_receipt_attachment(&ixn2_serder, &[&wit1, &wit3])?;
    let mut ixn2_full = ixn2_msg.clone();
    ixn2_full.extend_from_slice(&ixn2_full_att);

    match direct::process_message(&ixn2_full, &bad_store, &mut bad_kevers) {
        Ok(r) => {
            println!("  Re-submitted with 2-of-3 witness receipts (alpha + gamma)...");
            println!("  Result: ACCEPTED (sn={})", r.sn);
        }
        Err(e) => {
            println!("  ERROR: should have succeeded: {e}");
        }
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 8: Display the Full Verified Key Event Log
    // ─────────────────────────────────────────────────────────────────────

    println!("── Step 8: Verified Key Event Log ──");
    println!();

    let kel = verifier_store.get_kel(ctrl.prefix())?;
    println!("  Controller: {}", ctrl.prefix());
    println!("  KEL entries: {}", kel.len());
    println!("  Backer threshold: 2-of-3 witnesses");
    println!();

    for (sn, event_said) in &kel {
        if let Some(event_data) = verifier_store.get_event(event_said)? {
            let serder = Serder::from_raw(&event_data)?;
            let ilk = serder.ilk()?;
            let sad: serde_json::Value = serde_json::from_slice(serder.raw())?;

            println!(
                "  ┌─ SN={sn}  ilk={ilk}  said={}...",
                &event_said[..28]
            );

            match ilk.as_str() {
                "icp" => {
                    println!(
                        "  │  signing key:  {}",
                        sad["k"][0].as_str().unwrap_or("")
                    );
                    println!("  │  bt={}, witnesses={}", sad["bt"], {
                        sad["b"].as_array().map_or(0, |a| a.len())
                    });
                }
                "rot" => {
                    println!(
                        "  │  new key:      {}",
                        sad["k"][0].as_str().unwrap_or("")
                    );
                    println!(
                        "  │  prior:        {}...",
                        &sad["p"].as_str().unwrap_or("")[..28]
                    );
                }
                "ixn" => {
                    let n_anchors = sad["a"].as_array().map_or(0, |a| a.len());
                    println!("  │  anchors: {n_anchors} seal(s)");
                    println!(
                        "  │  prior:   {}...",
                        &sad["p"].as_str().unwrap_or("")[..28]
                    );
                }
                _ => {}
            }
            println!("  └─");
            println!();
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Summary
    // ─────────────────────────────────────────────────────────────────────

    println!("── Summary ──");
    println!();
    println!("  What witnesses provide:");
    println!("    - Duplicity detection: witnesses only sign one event per sn");
    println!("    - Availability: witnesses serve the KEL when controller is offline");
    println!("    - Threshold flexibility: 2-of-3 allows one witness to be down");
    println!();
    println!("  CESR counter codes used:");
    println!("    -B  Controller indexed signatures (Siger)");
    println!("    -D  Non-transferable receipt couples (prefix qb64 + Cigar qb64)");
    println!();
    println!("  Message format:  [JSON event body][-B sigs][-D receipt couples]");
    println!();
    println!("  Witness prefix code \"B\" = non-transferable Ed25519 public key");
    println!("  The prefix IS the key — no KEL lookup needed to verify receipts.");
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                   Witness Demo Complete                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}
