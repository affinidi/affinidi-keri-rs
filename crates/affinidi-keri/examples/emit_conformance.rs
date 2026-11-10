//! Write the reverse-conformance fixtures: key event logs built by this
//! library's controller, for keripy to verify.
//!
//! ```sh
//! cargo run -p affinidi-keri --example emit_conformance -- crates/affinidi-keri/tests/fixtures/ours-v2
//! ```
//!
//! Then, with keripy installed, run `verify_ours.py` in that directory (see its
//! README). `tests/ours_v2_conformance.rs` checks the committed files still
//! match what this writes.

#[path = "../tests/conformance/scenarios.rs"]
mod scenarios;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/affinidi-keri/tests/fixtures/ours-v2".into());
    std::fs::create_dir_all(&dir).expect("output directory");
    for s in scenarios::all() {
        std::fs::write(format!("{dir}/{}.cesr", s.name), &s.stream).expect("write stream");
        std::fs::write(format!("{dir}/{}.json", s.name), scenarios::json_for(&s))
            .expect("write state");
        println!("{:32} {:6} bytes  {}", s.name, s.stream.len(), s.expect);
    }
}
