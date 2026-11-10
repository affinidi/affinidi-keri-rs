# Our v2 registries, verified by keripy

Each `<name>.cesr` is an issuer's published stream, written by this library:

- the issuer's KEL by `affinidi_keri::controller`;
- its v2 registries (`rip`), designations (`acm`) and blindable updates
  (`bup`) by `affinidi_keri_core::registry::write`.

`<name>.json` records the KEL state the stream ends in, and for each
credential its schema, registry, SAID, expected status (`expect`), and the
registry messages with the KEL events that anchor them.

## Both directions

- **keripy verifies what we write**: `verify_ours_registries.py` (needs keripy;
  version in `../../../../affinidi-keri-core/tests/fixtures/keripy-v2/KERIPY_VERSION`):
  1. keripy reads the KEL from the stream, starting in genus 1, and reaches the
     recorded state;
  2. every `rip` and `bup` keripy's own `messagize` builds from our message and
     its anchor is in the stream byte for byte;
  3. keripy's `SerderACDC` verifies every SAID, its `Blinder` reproduces every
     BLID, and `vetBinds` reaches each credential's expected status.

  ```sh
  DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours_registries.py .
  ```

  keripy's parser does not route ACDC registry messages from a stream (it
  refuses an ACDC message with an ilk), so step 3 builds keripy's objects from
  the bodies the `.json` records, and step 2 ties those bodies to the stream.
- **We match what keripy writes**: `affinidi-keri-core`'s
  `tests/registry_writer_matches_keripy.rs` rebuilds keripy's `v2-reissued`
  fixture from keripy's inputs and gets the same `rip` bytes, the same
  credential SAID, and byte-identical updates and disclosures.
- **In CI**, without keripy: `tests/ours_v2_registries.rs` checks these files
  are exactly what the writer produces, and that this library's registry reader
  reaches each recorded status.

Regenerate after a change to the writer, then re-run `verify_ours_registries.py`:

```sh
cargo run -p affinidi-keri --example emit_registry_conformance -- crates/affinidi-keri/tests/fixtures/ours-v2-registries
```

## The published stream

keripy defines no published-stream form for v2 registries. This is the one we
write, and propose for a `did:webs` `keri.cesr`:

1. **The KEL**, every event as the controller composes it. A 2.x event is the
   genus-version counter (`-_AAACAA`), the body and an attachment group (`-C`)
   of controller signatures (`-K`). A 1.x event is the body and its `-A` group,
   with no genus counter.
2. **Each registry**, after the KEL:
   1. the inception: `-_AAACAA`, the `rip` body, and `-C` holding one seal
      source couple (`-S`: the anchoring KEL event's sequence number as a
      `Number`, and its SAID);
   2. the designation bound to it: `-_AAACAA` and the `acm` body, with no
      attachments (a 2.x ACDC is not signed; its issuance is the anchored
      update);
   3. every update, in `n` order: `-_AAACAA`, the `bup` body, and `-C` holding
      its seal source couple and its disclosed state (`-a`: BLID, UUID,
      credential SAID, state label).

Rules this writer keeps:

- **Every message names its genus**, so a reader never has to infer it (P1).
- **Every update carries its disclosure**, not only the latest: a reader must
  be able to find the latest non-vacuous one.
- **A fresh 256-bit UUID per update.** With public mode's empty UUID, a
  re-issue's BLID collides with the first issuance's, and keripy refuses it.
- **Every registry event the KEL anchors is in the stream**; a reader refuses
  a stream that leaves one out.
- **One designation per registry.** A 2.x registry's state binds one
  credential, so each designation has its own registry.
- **The attribute block carries its own SAID.** keripy's `acdcmap` leaves it
  empty; keripy accepts it filled, and the credential's SAID is the same.
- **The KEL anchors each registry event with a `{s, d}` seal**: its registry
  sequence number in hex and its SAID, as keripy anchors one.

## Scenarios

| Scenario | What it is | Expect |
|---|---|---|
| `v2-registry-issued` | `rip`, `acm`, `bup(issued)`, each registry event anchored in its own `ixn` | issued |
| `v2-registry-revoked` | issued, then revoked | revoked |
| `v2-registry-reissued` | issued, revoked, issued again, a fresh UUID each | issued |
| `v2-two-designations` | designated aliases and a key agreement designation, each in its own registry; both inceptions in one `ixn`, both issuances in the next | issued, issued |
| `migrated-v1-kel-v2-registry` | a v1 `icp` and `ixn`, then v2 `ixn` events anchoring a v2 registry and its issuance | issued |
