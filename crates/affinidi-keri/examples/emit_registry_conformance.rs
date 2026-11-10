//! Write the registry reverse-conformance fixtures: an issuer's KEL written by
//! this library's controller, and v2 registries and designations written by
//! `affinidi_keri_core::registry::write`, for keripy to verify.
//!
//! ```sh
//! cargo run -p affinidi-keri --example emit_registry_conformance -- crates/affinidi-keri/tests/fixtures/ours-v2-registries
//! ```
//!
//! Then, with keripy installed, run `verify_ours_registries.py` in that
//! directory (see its README). `tests/ours_v2_registries.rs` checks the
//! committed files still match what this writes.

#[path = "../tests/conformance/registry_scenarios.rs"]
mod registry_scenarios;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/affinidi-keri/tests/fixtures/ours-v2-registries".into());
    std::fs::create_dir_all(&dir).expect("output directory");
    for s in registry_scenarios::all() {
        std::fs::write(format!("{dir}/{}.cesr", s.name), &s.stream).expect("write stream");
        std::fs::write(
            format!("{dir}/{}.json", s.name),
            registry_scenarios::json_for(&s),
        )
        .expect("write expectations");
        println!("{:32} {:6} bytes", s.name, s.stream.len());
    }
}
