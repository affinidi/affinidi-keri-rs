# Our KERI v2 output, verified by keripy

The reverse of `affinidi-keri-core/tests/fixtures/keripy-v2/`. There, keripy
writes the logs and this library must read them. Here, this library's
controller (`affinidi_keri::controller`) writes the logs and keripy must accept
them.

- `<name>.cesr`: the stream our controller writes.
- `<name>.json`:
  - `ours`: the state the log reaches, in the shape of the keripy fixtures'
    `keripy` block;
  - `expect`: `accept`, or `refuse-rotation` for a stream carrying a rotation a
    verifier must refuse (composed without the controller's own check, which
    refuses to finish it);
  - `note`: what the scenario is.

| Scenario | What it covers |
|---|---|
| `v2-basic` | `icp`, `ixn` with a digest seal, `rot`, `ixn` |
| `v2-recovery-by-k` | `n [H(R′), H(K)]`, `nt ["1/2","1"]`, rotated by K alone |
| `v2-recovery-by-r-and-k` | the same, rotated by R′ and K |
| `v2-recovery-routine-alone` | the same, rotated by R′ alone: refused |
| `v2-multisig-2of3` | `kt "2"` over three keys |
| `migrated-v1-to-v2` | a v1 log continued in v2 (`ControllerState::upgrade`) |
| `v2-threshold-ten` | ten keys at threshold ten, written `"a"` (hex) |

## Both halves

1. **keripy accepts them.** `verify_ours.py` feeds each stream to a fresh keripy
   `Kevery` and checks keripy reaches exactly `ours`. keripy can't run in CI,
   so run it whenever the output changes:

       DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours.py .

2. **They are what the controller writes today.**
   `tests/ours_v2_conformance.rs` rebuilds every scenario
   (`tests/conformance/scenarios.rs`), fails if a committed file differs, and
   checks our own `Kever` reaches the same state.

Regenerate after a deliberate change to the output, then re-run step 1:

    cargo run -p affinidi-keri --example emit_conformance -- crates/affinidi-keri/tests/fixtures/ours-v2

Output is byte-identical between runs: keys derive from a fixed salt and
Ed25519 signatures are deterministic.
