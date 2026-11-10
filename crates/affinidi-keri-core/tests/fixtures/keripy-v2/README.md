# keripy KERI v2 conformance fixtures

Built by `gen.py` with keripy (version and commit in `KERIPY_VERSION`). Each
scenario is constructed with keripy's event builders, processed by keripy's
`Kevery`, published the way keripy replays a log (`clonePreIter`, what a
`did:webs` `keri.cesr` generator emits), and re-read by a fresh keripy database.
A fixture is only written if keripy accepts its own published stream and reaches
the same key state.

- `<name>.cesr`: the published stream.
- `<name>.submitted.cesr` (only where `expect` is not `accept`): the messages
  as submitted, with a genus-version counter at each version change. keripy
  publishes only what it accepted, so a refused event appears only here.
  keripy reads this stream to the same state as it reached directly.
- `<name>.json`:
  - `keripy`: the key state keripy reached;
  - `expect`: what a verifier conforming to VTI's positions must do (`accept`,
    `refuse-rotation`, `refuse-event-1`);
  - `note`: what the scenario is.

Where `expect` differs from what keripy did, that is a recorded divergence
(see `docs/05-design-notes/did-webs-keri-v2.md` in OpenVTC/verifiable-trust-infrastructure).

Regenerate (keripy 2.x installed, libsodium on the library path):

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I gen.py .

Output is byte-identical between runs: keys derive from a fixed salt, Ed25519
signatures are deterministic, and the first-seen clock is pinned. A diff after
moving to a newer keripy commit is a behaviour change to review.

## What keripy does that a reader must know

- **The parser defaults to v2.** A v1 stream with no genus counter only parses
  as v1 when the parser is told so (`Parser(version=Vrsn_1_0)`).
- **A migrated log is republished under one v2 genus.** `migrated-v1-to-v2.cesr`
  opens with the v2 genus counter, and its v1 events carry v2 attachment groups.
  Attachments follow the stream's genus; each body carries its own version.
- **A rotation may reorder, reveal part of, or add to its committed keys.** In
  `v2-reordered-rotation.cesr` the new keys are `[B, A, X]` after
  `n = [H(A), H(B)]`: keripy signs B and A with `2A` (both lists, ondex 1 and
  0) and the uncommitted X current-only (`B`). The prior `nt` is met by the
  committed positions the signatures expose, not by the key list's shape.
- **A rotation supersedes interaction events after the last establishment
  event, and nothing else** (keripy's rules A0–A2). In
  `v2-superseding-recovery.cesr` the recovery key K rotates at sn 2 after
  ixn 1; keripy publishes the superseded ixn 2 too, before the rotation, so a
  reader must reconcile them. `v2-rotation-cannot-supersede-rotation` and
  `v2-stale-recovery` are refused. A superseding delegated rotation (rule B)
  is not supported yet.
- **A 2.x endorsement writes its sequence number as a `Number`.** In
  `v2-endorsed-replies.cesr` the `-X` group names the establishment event at
  sn 1 as `MAAB` (the smallest `Number` code), where 1.x writes a 24-character
  `Seqner` (`0A…`).
- **`messagize` defaults to v2 attachments**, even on a v1 event. `gen.py` builds
  v1 events with v1 attachments, as a v1 producer does.
- **A version decrease is accepted.** keripy accepts a v1 `ixn` after a v2 `icp`
  (`downgrade-v2-to-v1`); VTI's position is to refuse it.
- **The default body serialisation is native CESR** (`Kind = 'CESR'`).
  `v2-basic-native` is the native form of `v2-basic`.
