//! Demo: KERI Judge — Duplicity Detection via the First-Seen Policy
//!
//! Run with: cargo run -p affinidi-keri --example demo_judge
//!
//! A Judge enforces the first-seen rule: for each (prefix, sn) it remembers
//! the first valid event it processed. If a second, different-but-valid event
//! arrives at the same (prefix, sn), the Judge flags the prefix as duplicitous.
//!
//! This demo shows:
//!   Part 1 — Without a Judge: two verifiers each accept a different event
//!            at sn=1 and neither detects the conflict.
//!   Part 2 — With a Judge: the Judge catches the conflicting event and
//!            records duplicity evidence in the DEL.

use std::collections::HashMap;

use affinidi_keri::config::InceptionConfig;
use affinidi_keri::direct;
use affinidi_keri::hab::Hab;
use affinidi_keri::judge::{Judge, JudgeResult};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_db::lmdb::LmdbStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       KERI Judge Demo: Duplicity Detection via First-Seen  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Setup: Create two Hab instances with the SAME salt
    // ─────────────────────────────────────────────────────────────────────
    // Identical salt → identical keys → identical inception event → same prefix.
    // This simulates a controller running on two devices (or a malicious clone).

    println!("── Setup: Create Two Habs with Identical Keys ──");
    println!();

    let salt = [0xDEu8; 16];

    let hab1_dir = tempfile::tempdir()?;
    let hab1_store = LmdbStore::open(hab1_dir.path())?;
    let config = InceptionConfig::builder()
        .salt(salt.to_vec())
        .build();
    let (mut hab1, icp_msg) = Hab::incept("device-1", &config, &hab1_store)?;

    let hab2_dir = tempfile::tempdir()?;
    let hab2_store = LmdbStore::open(hab2_dir.path())?;
    let (mut hab2, _) = Hab::incept("device-2", &config, &hab2_store)?;

    assert_eq!(hab1.prefix(), hab2.prefix(), "prefixes must match");

    println!("  Controller prefix: {}", hab1.prefix());
    println!("  Both devices derived from salt: {:02x?}", &salt[..4]);
    println!("  Same prefix, same keys — they look identical to verifiers.");
    println!();

    // Each device creates a DIFFERENT interaction event at sn=1
    let anchor_a = serde_json::json!({"d": "EAnchorA_document_hash_AAAAAAAAAAAAA"});
    let anchor_b = serde_json::json!({"d": "EAnchorB_document_hash_BBBBBBBBBBBBB"});

    let ixn_a = hab1.interact(&[anchor_a], &hab1_store)?;
    let ixn_b = hab2.interact(&[anchor_b], &hab2_store)?;

    let ixn_a_serder = Serder::from_raw(&ixn_a)?;
    let ixn_b_serder = Serder::from_raw(&ixn_b)?;

    println!("  Device 1 → ixn at sn=1  SAID: {}...", &ixn_a_serder.said()?[..20]);
    println!("    anchor: EAnchorA_document_hash_AAAAAAAAAAAAA");
    println!("  Device 2 → ixn at sn=1  SAID: {}...", &ixn_b_serder.said()?[..20]);
    println!("    anchor: EAnchorB_document_hash_BBBBBBBBBBBBB");
    println!();
    println!("  Same prefix, same sn, different content = DUPLICITY");
    println!();

    // ═════════════════════════════════════════════════════════════════════
    // Part 1: Without a Judge — Silent Inconsistency
    // ═════════════════════════════════════════════════════════════════════

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Part 1: Without a Judge — Two Verifiers, No Detection    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Verifier 1 sees icp + ixn_a
    let v1_dir = tempfile::tempdir()?;
    let v1_store = LmdbStore::open(v1_dir.path())?;
    let mut v1_kevers: HashMap<String, Kever> = HashMap::new();

    let r1_icp = direct::process_message(&icp_msg, &v1_store, &mut v1_kevers)?;
    let r1_ixn = direct::process_message(&ixn_a, &v1_store, &mut v1_kevers)?;

    println!("  Verifier 1:");
    println!("    Processed icp (sn=0): ACCEPTED  said={}...", &r1_icp.said[..20]);
    println!("    Processed ixn (sn=1): ACCEPTED  said={}...", &r1_ixn.said[..20]);
    println!("    Status: happy, no errors detected");
    println!();

    // Verifier 2 sees icp + ixn_b
    let v2_dir = tempfile::tempdir()?;
    let v2_store = LmdbStore::open(v2_dir.path())?;
    let mut v2_kevers: HashMap<String, Kever> = HashMap::new();

    let r2_icp = direct::process_message(&icp_msg, &v2_store, &mut v2_kevers)?;
    let r2_ixn = direct::process_message(&ixn_b, &v2_store, &mut v2_kevers)?;

    println!("  Verifier 2:");
    println!("    Processed icp (sn=0): ACCEPTED  said={}...", &r2_icp.said[..20]);
    println!("    Processed ixn (sn=1): ACCEPTED  said={}...", &r2_ixn.said[..20]);
    println!("    Status: happy, no errors detected");
    println!();

    println!("  Problem: Both verifiers accepted sn=1 with DIFFERENT SAIDs!");
    println!("    Verifier 1 sn=1 SAID: {}...", &r1_ixn.said[..20]);
    println!("    Verifier 2 sn=1 SAID: {}...", &r2_ixn.said[..20]);
    println!("    Neither verifier knows about the conflict.");
    println!("    This is why we need a Judge.");
    println!();

    // ═════════════════════════════════════════════════════════════════════
    // Part 2: With a Judge — Duplicity Detected!
    // ═════════════════════════════════════════════════════════════════════

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Part 2: With a Judge — Duplicity Detected!               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let judge_dir = tempfile::tempdir()?;
    let judge_store = LmdbStore::open(judge_dir.path())?;
    let mut judge = Judge::new(Box::new(judge_store));

    let prefix = hab1.prefix().to_string();

    // Step 1: Judge processes inception
    println!("  Step 1: Judge processes inception event");
    match judge.process(&icp_msg)? {
        JudgeResult::Accepted(r) => {
            println!("    Result: ACCEPTED (sn={}, ilk={})", r.sn, r.ilk);
        }
        other => println!("    Unexpected: {other:?}"),
    }
    println!("    Verdict: {:?}", judge.verdict(&prefix));
    println!();

    // Step 2: Judge processes ixn_a (first-seen at sn=1)
    println!("  Step 2: Judge processes interaction from Device 1");
    match judge.process(&ixn_a)? {
        JudgeResult::Accepted(r) => {
            println!("    Result: ACCEPTED (sn={}, ilk={})", r.sn, r.ilk);
            println!("    SAID:   {}...", &r.said[..20]);
            println!("    This is now the first-seen event at sn=1.");
        }
        other => println!("    Unexpected: {other:?}"),
    }
    println!("    Verdict: {:?}", judge.verdict(&prefix));
    println!();

    // Step 3: Judge processes ixn_b (CONFLICT at sn=1!)
    println!("  Step 3: Judge processes interaction from Device 2");
    match judge.process(&ixn_b)? {
        JudgeResult::DuplicityDetected(evidence) => {
            println!("    Result: DUPLICITY DETECTED!");
            println!();
            println!("    Evidence:");
            println!("      prefix:           {}", evidence.prefix);
            println!("      sn:               {}", evidence.sn);
            println!(
                "      first-seen SAID:  {}...",
                &evidence.first_seen_said[..20]
            );
            println!(
                "      conflicting SAID: {}...",
                &evidence.duplicitous_said[..20]
            );
            println!(
                "      first-seen event: {} bytes",
                evidence.first_seen_event.len()
            );
            println!(
                "      conflicting event: {} bytes",
                evidence.duplicitous_event.len()
            );
        }
        other => println!("    Unexpected: {other:?}"),
    }
    println!();

    // Step 4: Show final state
    println!("  Step 4: Final Judge State");
    println!("    Verdict:      {:?}", judge.verdict(&prefix));
    println!("    Is duplicitous: {}", judge.is_duplicitous(&prefix));
    println!("    DEL entries:  {}", judge.del().len());
    println!();

    let evidence_list = judge.evidence_for(&prefix);
    for (i, ev) in evidence_list.iter().enumerate() {
        println!("    DEL[{i}]:");
        println!("      sn={}, first_said={}..., dup_said={}...",
            ev.sn,
            &ev.first_seen_said[..20],
            &ev.duplicitous_said[..20],
        );
    }
    println!();

    // Step 5: Show idempotent replay
    println!("  Step 5: Replaying the same inception event");
    match judge.process(&icp_msg)? {
        JudgeResult::DuplicateAccepted => {
            println!("    Result: DuplicateAccepted (idempotent replay, no action needed)");
        }
        other => println!("    Unexpected: {other:?}"),
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // Summary
    // ─────────────────────────────────────────────────────────────────────

    println!("── Summary ──");
    println!();
    println!("  Without a Judge:");
    println!("    - Each verifier only sees its own stream of events");
    println!("    - Two verifiers can accept conflicting events at the same sn");
    println!("    - Neither detects the inconsistency");
    println!();
    println!("  With a Judge:");
    println!("    - The Judge remembers the first valid event at each (prefix, sn)");
    println!("    - A second, different event at the same (prefix, sn) triggers duplicity");
    println!("    - The Judge records evidence in the Duplicitous Event Log (DEL)");
    println!("    - The prefix verdict transitions: Unknown -> Trusted -> Duplicitous");
    println!("    - Once duplicitous, the prefix is permanently flagged");
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    Judge Demo Complete                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}
