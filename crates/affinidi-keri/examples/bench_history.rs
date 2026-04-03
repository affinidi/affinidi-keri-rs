/// Benchmark: 10-year monthly key rotation history for KERI
///
/// Creates a KERI identifier with inception + 120 key rotations (one per month
/// for 10 years), then measures generation and resolution performance.
///
/// Run with: cargo run -p affinidi-keri --example bench_history --release
/// With witnesses: cargo run -p affinidi-keri --example bench_history --release -- --witnesses 3 --threshold 2
use std::collections::HashMap;
use std::time::Instant;

use affinidi_keri::{Hab, InceptionConfig, Judge, JudgeResult, RotationConfig};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_db::lmdb::{LmdbStore, LmdbStoreConfig};

const ROTATION_COUNT: usize = 120;

fn parse_args() -> (usize, usize) {
    let args: Vec<String> = std::env::args().collect();
    let mut witnesses: usize = 0;
    let mut threshold: Option<usize> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--witnesses" => {
                i += 1;
                witnesses = args[i].parse().expect("--witnesses requires a number");
            }
            "--threshold" => {
                i += 1;
                threshold = Some(args[i].parse().expect("--threshold requires a number"));
            }
            _ => {}
        }
        i += 1;
    }

    let threshold = threshold.unwrap_or(witnesses);
    (witnesses, threshold)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (witness_count, witness_threshold) = parse_args();

    println!("KERI 10-Year Key Rotation Benchmark");
    println!("====================================");
    println!("Events: 1 inception + {ROTATION_COUNT} rotations");
    if witness_count > 0 {
        println!("Witnesses: {witness_count} (threshold: {witness_threshold})");
    }
    println!();

    // --- Setup phase (not timed) ---
    let bench_config = LmdbStoreConfig {
        no_sync: true,
        ..Default::default()
    };

    // Create witness Habs if requested
    let mut witness_dirs = Vec::new();
    let mut witness_stores = Vec::new();
    let mut witness_habs = Vec::new();

    for i in 0..witness_count {
        let dir = tempfile::tempdir()?;
        let store = LmdbStore::open_with_config(dir.path(), &bench_config)?;
        let salt = vec![0x50u8 + i as u8; 16];
        let w_config = InceptionConfig::builder()
            .transferable(false)
            .salt(salt)
            .build();
        let (w_hab, _) = Hab::incept(&format!("witness-{i}"), &w_config, &store)?;
        witness_dirs.push(dir);
        witness_stores.push(store);
        witness_habs.push(w_hab);
    }

    // Extract witness prefixes for the controller's inception config
    let witness_prefixes: Vec<String> = witness_habs
        .iter()
        .map(|w| w.signers()[0].verfer().qb64())
        .collect::<Result<Vec<_>, _>>()?;

    // --- Generation phase ---
    let gen_dir = tempfile::tempdir()?;
    let gen_store = LmdbStore::open(gen_dir.path())?;

    let mut config_builder = InceptionConfig::builder().salt(vec![0x42u8; 16]);
    if witness_count > 0 {
        config_builder = config_builder
            .backer_threshold(witness_threshold)
            .backers(witness_prefixes);
    }
    let config = config_builder.build();

    let witness_refs: Vec<&Hab> = witness_habs.iter().collect();

    let gen_start = Instant::now();

    let (mut hab, mut icp_msg) = Hab::incept("bench", &config, &gen_store)?;

    if witness_count > 0 {
        let serder = Serder::from_raw(&icp_msg)?;
        let attachment = Hab::compose_witness_receipt_attachment(&serder, &witness_refs)?;
        icp_msg.extend_from_slice(&attachment);
    }

    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(ROTATION_COUNT + 1);
    messages.push(icp_msg);

    let rot_config = RotationConfig::default();
    for _ in 0..ROTATION_COUNT {
        let mut rot_msg = hab.rotate(&rot_config, &gen_store)?;
        if witness_count > 0 {
            let serder = Serder::from_raw(&rot_msg)?;
            let attachment = Hab::compose_witness_receipt_attachment(&serder, &witness_refs)?;
            rot_msg.extend_from_slice(&attachment);
        }
        messages.push(rot_msg);
    }

    let gen_elapsed = gen_start.elapsed();

    let total_kel_bytes: usize = messages.iter().map(|m| m.len()).sum();
    let total_events = messages.len();

    println!("Generation");
    println!("----------");
    println!("  Time:       {gen_elapsed:.2?}");
    println!(
        "  Throughput: {:.1} events/sec",
        total_events as f64 / gen_elapsed.as_secs_f64()
    );
    println!(
        "  KEL size:   {} bytes ({:.1} KB)",
        total_kel_bytes,
        total_kel_bytes as f64 / 1024.0
    );
    println!("  Events:     {total_events}");
    println!();

    // --- Resolution phase (direct mode) ---
    let res_dir = tempfile::tempdir()?;
    let res_store = LmdbStore::open_with_config(res_dir.path(), &bench_config)?;
    let mut kevers: HashMap<String, Kever> = HashMap::new();

    let res_start = Instant::now();

    for msg in &messages {
        affinidi_keri::direct::process_message(msg, &res_store, &mut kevers)?;
    }

    let res_elapsed = res_start.elapsed();

    println!("Resolution (direct mode)");
    println!("------------------------");
    println!("  Time:       {res_elapsed:.2?}");
    println!(
        "  Throughput: {:.1} events/sec",
        total_events as f64 / res_elapsed.as_secs_f64()
    );
    println!();

    // --- Resolution phase (Judge) ---
    let judge_dir = tempfile::tempdir()?;
    let judge_store = LmdbStore::open_with_config(judge_dir.path(), &bench_config)?;

    let mut judge = Judge::new(Box::new(judge_store));

    let judge_start = Instant::now();

    for msg in &messages {
        match judge.process(msg)? {
            JudgeResult::Accepted(_) => {}
            other => panic!("unexpected judge result: {other:?}"),
        }
    }

    let judge_elapsed = judge_start.elapsed();

    println!("Resolution (Judge with duplicity detection)");
    println!("--------------------------------------------");
    println!("  Time:       {judge_elapsed:.2?}");
    println!(
        "  Throughput: {:.1} events/sec",
        total_events as f64 / judge_elapsed.as_secs_f64()
    );
    println!();

    println!("Done.");
    Ok(())
}
