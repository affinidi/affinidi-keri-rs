//! Demo: did:keri + ACDC credential issuance and verification.
//!
//! Run with: cargo run -p affinidi-keri --example demo_credential
//!
//! This example demonstrates the full lifecycle:
//! 1. Create a KERI identifier → did:keri:<prefix>
//! 2. Derive a DID Document from the current key state
//! 3. Issue an ACDC credential (Authentic Chained Data Container)
//! 4. Anchor the credential SAID in the issuer's Key Event Log
//! 5. Verify everything: SAID integrity, KEL anchor, signature chain

use std::collections::HashMap;

use affinidi_keri::direct;
use affinidi_keri::{Hab, InceptionConfig};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_db::KeriStore;
use affinidi_keri_db::lmdb::LmdbStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       KERI Credential Demo: did:keri + ACDC Issuance       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 1: Create Witnesses and the Issuer Identity
    // ─────────────────────────────────────────────────────────────────────

    // Create two non-transferable witnesses for duplicity detection
    let wit1_dir = tempfile::tempdir()?;
    let wit1_store = LmdbStore::open(wit1_dir.path())?;
    let wit1_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0xA1u8; 16])
        .build();
    let (wit1, _) = Hab::incept("witness1", &wit1_config, &wit1_store)?;

    let wit2_dir = tempfile::tempdir()?;
    let wit2_store = LmdbStore::open(wit2_dir.path())?;
    let wit2_config = InceptionConfig::builder()
        .transferable(false)
        .salt(vec![0xA2u8; 16])
        .build();
    let (wit2, _) = Hab::incept("witness2", &wit2_config, &wit2_store)?;

    // Witness backer prefixes are their public keys
    let wit1_prefix = wit1.signers()[0].verfer().qb64()?;
    let wit2_prefix = wit2.signers()[0].verfer().qb64()?;

    // Create the issuer identity with 2 designated witnesses
    let issuer_dir = tempfile::tempdir()?;
    let issuer_store = LmdbStore::open(issuer_dir.path())?;

    let config = InceptionConfig::builder()
        .salt(vec![42u8; 16]) // deterministic salt for reproducible demo
        .backer_threshold(2)
        .backers(vec![wit1_prefix.clone(), wit2_prefix.clone()])
        .build();

    let (mut issuer, inception_msg) = Hab::incept("issuer", &config, &issuer_store)?;

    // Witnesses receipt the inception event
    let icp_serder = Serder::from_raw(&inception_msg)?;
    let witness_att = Hab::compose_witness_receipt_attachment(&icp_serder, &[&wit1, &wit2])?;
    let mut inception_witnessed = inception_msg.clone();
    inception_witnessed.extend_from_slice(&witness_att);

    println!("── Step 1: Issuer Identity Created (with 2 witnesses) ──");
    println!("  Name:       {}", issuer.name());
    println!("  AID Prefix: {}", issuer.prefix());
    println!("  Seq Number: {}", issuer.sn());
    println!("  Event SAID: {}", issuer.last_said());
    println!("  Witness 1:  {}...", &wit1_prefix[..24]);
    println!("  Witness 2:  {}...", &wit2_prefix[..24]);
    println!("  Threshold:  2");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 2: Derive the did:keri Identifier & DID Document
    // ─────────────────────────────────────────────────────────────────────
    let did = format!("did:keri:{}", issuer.prefix());
    let verfer = issuer.signers()[0].verfer();
    let verfer_qb64 = verfer.qb64()?;

    let did_document = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [{
            "id": format!("{did}#key-0"),
            "type": "Ed25519VerificationKey2020",
            "controller": &did,
            "publicKeyMultibase": format!("z{verfer_qb64}")
        }],
        "authentication": [format!("{did}#key-0")],
        "assertionMethod": [format!("{did}#key-0")]
    });

    println!("── Step 2: did:keri Identifier ──");
    println!("  DID: {did}");
    println!();
    println!("  DID Document:");
    println!("{}", serde_json::to_string_pretty(&did_document)?);
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 3: Create a Holder Identity (the credential subject)
    // ─────────────────────────────────────────────────────────────────────
    let holder_dir = tempfile::tempdir()?;
    let holder_store = LmdbStore::open(holder_dir.path())?;

    let holder_config = InceptionConfig::builder().salt(vec![7u8; 16]).build();

    let (holder, _holder_icp_msg) = Hab::incept("holder", &holder_config, &holder_store)?;
    let holder_did = format!("did:keri:{}", holder.prefix());

    println!("── Step 3: Holder Identity Created ──");
    println!("  Holder DID: {holder_did}");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 4: Issue an ACDC Credential
    // ─────────────────────────────────────────────────────────────────────
    // ACDC = Authentic Chained Data Container (KERI-native verifiable credential)

    // First, build the attributes block with its own SAID
    let mut attributes = serde_json::json!({
        "d": "",
        "i": holder.prefix(),
        "dt": "2026-03-04T12:00:00Z",
        "LEI": "254900OPPU84GM83MG36",
        "personLegalName": "Alice Smith",
        "officialRole": "Chief Executive Officer"
    });
    said::compute_said(&mut attributes, "d", "E", SerializationKind::Json)?;

    // Build the credential envelope
    let mut credential = serde_json::json!({
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": issuer.prefix(),
        "s": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "a": attributes
    });

    // Fix version string size (same technique as event SAID computation)
    let placeholder = "#".repeat(44);
    credential["d"] = serde_json::Value::String(placeholder);
    let temp_raw = serde_json::to_vec(&credential)?;
    credential["v"] = serde_json::Value::String(format!("ACDC10JSON{:06x}_", temp_raw.len()));
    credential["d"] = serde_json::Value::String(String::new());

    // Compute the credential's SAID
    let credential_said = said::compute_said(&mut credential, "d", "E", SerializationKind::Json)?;

    println!("── Step 4: ACDC Credential Issued ──");
    println!("  Credential SAID: {credential_said}");
    println!("  Issuer:          {did}");
    println!("  Subject:         {holder_did}");
    println!();
    println!("  Credential:");
    println!("{}", serde_json::to_string_pretty(&credential)?);
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 5: Anchor the Credential in the Issuer's KEL
    // ─────────────────────────────────────────────────────────────────────
    // An interaction event (ixn) anchors the credential's SAID as a seal
    let seal = serde_json::json!({
        "i": &credential_said,
        "s": "0",
        "d": &credential_said
    });

    let ixn_msg = issuer.interact(&[seal], &issuer_store)?;

    // Witnesses receipt the interaction event
    let ixn_serder = Serder::from_raw(&ixn_msg)?;
    let ixn_witness_att = Hab::compose_witness_receipt_attachment(&ixn_serder, &[&wit1, &wit2])?;
    let mut ixn_witnessed = ixn_msg.clone();
    ixn_witnessed.extend_from_slice(&ixn_witness_att);

    println!("── Step 5: Credential Anchored in KEL ──");
    println!("  Interaction SN:   {}", issuer.sn());
    println!("  Interaction SAID: {}", issuer.last_said());
    println!("  Seal anchors credential SAID in the issuer's Key Event Log");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 6: Verification (as a third-party verifier)
    // ─────────────────────────────────────────────────────────────────────
    println!("── Step 6: Verification ──");
    println!();

    let mut all_pass = true;

    // 6a. Verify credential SAID integrity
    print!("  [1/4] Credential SAID integrity ... ");
    match said::verify_said(&credential, "d", "E", SerializationKind::Json) {
        Ok(()) => println!("PASS"),
        Err(e) => {
            println!("FAIL: {e}");
            all_pass = false;
        }
    }

    // 6b. Verify attribute block SAID integrity
    print!("  [2/4] Attribute block SAID integrity ... ");
    match said::verify_said(
        credential.get("a").unwrap(),
        "d",
        "E",
        SerializationKind::Json,
    ) {
        Ok(()) => println!("PASS"),
        Err(e) => {
            println!("FAIL: {e}");
            all_pass = false;
        }
    }

    // 6c. Verify the credential is anchored in the issuer's KEL
    print!("  [3/4] Credential anchor in issuer KEL ... ");
    let kel = issuer_store.get_kel(issuer.prefix())?;
    let mut anchor_found = false;
    for (_sn, event_said) in &kel {
        if let Some(event_data) = issuer_store.get_event(event_said)? {
            let serder = Serder::from_raw(&event_data)?;
            if serder.ilk()? == "ixn"
                && let Some(anchors) = serder.sad().get("a").and_then(|v| v.as_array())
            {
                for anchor in anchors {
                    if anchor.get("i").and_then(|v| v.as_str()) == Some(&credential_said) {
                        anchor_found = true;
                    }
                }
            }
        }
    }
    if anchor_found {
        println!("PASS (found in KEL with {} events)", kel.len());
    } else {
        println!("FAIL: anchor not found");
        all_pass = false;
    }

    // 6d. Verify KEL event chain via direct mode (signature verification)
    print!("  [4/4] KEL event chain (direct mode) ... ");
    let verifier_dir = tempfile::tempdir()?;
    let verifier_store = LmdbStore::open(verifier_dir.path())?;
    let mut kevers: HashMap<String, Kever> = HashMap::new();

    let r1 = direct::process_message(&inception_witnessed, &verifier_store, &mut kevers)?;
    let r2 = direct::process_message(&ixn_witnessed, &verifier_store, &mut kevers)?;

    if r1.ilk == "icp" && r1.sn == 0 && r2.ilk == "ixn" && r2.sn == 1 {
        println!("PASS (icp@0 → ixn@1)");
    } else {
        println!("FAIL");
        all_pass = false;
    }

    println!();
    if all_pass {
        println!("  ✅ All verifications passed!");
    } else {
        println!("  ❌ Some verifications failed.");
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Step 7: Display the complete Key Event Log
    // ─────────────────────────────────────────────────────────────────────
    println!("── Step 7: Issuer's Complete Key Event Log ──");
    println!();
    for (sn, event_said) in &kel {
        if let Some(event_data) = issuer_store.get_event(event_said)? {
            let serder = Serder::from_raw(&event_data)?;
            let ilk = serder.ilk()?;
            println!("  SN={sn}  ilk={ilk}  said={}...", &event_said[..24]);
            let json: serde_json::Value = serde_json::from_slice(serder.raw())?;
            println!("{}", serde_json::to_string_pretty(&json)?);
            println!();
        }
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                     Demo Complete                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}
