use std::collections::HashMap;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use affinidi_keri::{Hab, InceptionConfig, Judge, JudgeResult, RotationConfig};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_db::lmdb::{LmdbStore, LmdbStoreConfig};

const ROTATION_COUNT: usize = 120;

/// Generate a full KEL (1 inception + `ROTATION_COUNT` rotations) and return
/// the collected messages along with the tempdir (to keep LMDB alive).
fn generate_kel() -> (Vec<Vec<u8>>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = LmdbStore::open(dir.path()).unwrap();

    let config = InceptionConfig::builder().salt(vec![0x42u8; 16]).build();

    let (mut hab, icp_msg) = Hab::incept("bench", &config, &store).unwrap();
    let mut messages = Vec::with_capacity(ROTATION_COUNT + 1);
    messages.push(icp_msg);

    let rot_config = RotationConfig::default();
    for _ in 0..ROTATION_COUNT {
        let rot_msg = hab.rotate(&rot_config, &store).unwrap();
        messages.push(rot_msg);
    }

    (messages, dir)
}

fn kel_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("kel_creation");

    group.bench_function("inception", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = LmdbStore::open(dir.path()).unwrap();
                (dir, store)
            },
            |(_dir, store)| {
                let config = InceptionConfig::builder().salt(vec![0x42u8; 16]).build();
                Hab::incept("bench", &config, &store).unwrap()
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("rotation", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = LmdbStore::open(dir.path()).unwrap();
                let config = InceptionConfig::builder().salt(vec![0x42u8; 16]).build();
                let (hab, _) = Hab::incept("bench", &config, &store).unwrap();
                (dir, store, hab)
            },
            |(_dir, store, mut hab)| hab.rotate(&RotationConfig::default(), &store).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn kel_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("kel_resolution");

    let bench_config = LmdbStoreConfig {
        no_sync: true,
        ..Default::default()
    };

    group.bench_function("single_event", |b| {
        let setup_dir = tempfile::tempdir().unwrap();
        let setup_store = LmdbStore::open(setup_dir.path()).unwrap();
        let config = InceptionConfig::builder().salt(vec![0x42u8; 16]).build();
        let (_, icp_msg) = Hab::incept("bench", &config, &setup_store).unwrap();

        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = LmdbStore::open_with_config(dir.path(), &bench_config).unwrap();
                let kevers: HashMap<String, Kever> = HashMap::new();
                (dir, store, kevers, icp_msg.clone())
            },
            |(_dir, store, mut kevers, msg)| {
                affinidi_keri::direct::process_message(&msg, &store, &mut kevers).unwrap()
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("full_history_120_rotations", |b| {
        let (messages, _gen_dir) = generate_kel();

        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = LmdbStore::open_with_config(dir.path(), &bench_config).unwrap();
                let kevers: HashMap<String, Kever> = HashMap::new();
                (dir, store, kevers, messages.clone())
            },
            |(_dir, store, mut kevers, msgs)| {
                for msg in &msgs {
                    affinidi_keri::direct::process_message(msg, &store, &mut kevers).unwrap();
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn kel_resolution_with_judge(c: &mut Criterion) {
    let mut group = c.benchmark_group("kel_resolution_with_judge");

    let bench_config = LmdbStoreConfig {
        no_sync: true,
        ..Default::default()
    };

    group.bench_function("full_history_120_rotations", |b| {
        let (messages, _gen_dir) = generate_kel();

        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = LmdbStore::open_with_config(dir.path(), &bench_config).unwrap();
                let judge = Judge::new(Box::new(store));
                (dir, judge, messages.clone())
            },
            |(_dir, mut judge, msgs)| {
                for msg in &msgs {
                    match judge.process(msg).unwrap() {
                        JudgeResult::Accepted(_) => {}
                        other => panic!("unexpected: {other:?}"),
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    kel_creation,
    kel_resolution,
    kel_resolution_with_judge
);
criterion_main!(benches);
