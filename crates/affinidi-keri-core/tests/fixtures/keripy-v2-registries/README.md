# keripy KERI/ACDC v2 registry fixtures

Built by `gen.py` with keripy (version and commit in `KERIPY_VERSION`). Each
scenario is one issuer's published stream:

1. its KEL as keripy replays it (`clonePreIter`), opening with the v2 genus
   counter;
2. a v2 registry inception (`rip`) with an attachment group holding the seal
   source couple (`-S`) of the KEL event that anchors it;
3. a v2 designated-aliases ACDC (`acm`, schema
   `EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA`), body only: a 2.x ACDC
   is not signed, and its issuance is the anchored update that binds it;
4. blindable updates (`bup`), each with its seal source couple and its
   disclosed blinded state (`-a`, `BlindedStateQuadruples`).

keripy defines no published-stream format for v2 registries: it verifies
registry state from objects (`keri.acdc.regeventing.vet` and `vetBinds`). This is
the form keripy's own `messagize` produces for those messages. keripy re-reads
each stream's KEL to the same state, and `vetBinds` rules on the objects that
went into each stream.

- `<name>.cesr`: the stream.
- `<name>.json`: the issuer, schema, registry and credential;
  - `limit`: the KEL sequence number to read as of (`versionId`), if any;
  - `expect`: what a reader following VTI's positions must conclude;
  - `keripy`: what `vetBinds` concluded.

Regenerate (keripy 2.x installed, libsodium on the library path):

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I gen.py .

Output is byte-identical between runs.

## Where `expect` and keripy differ

- **`v2-revocation-withheld`**: the KEL anchors the revoking update, but the
  stream leaves it out. keripy rules on what it is given (issued). The reader
  here refuses: every registry event the issuer's KEL anchors must be in the
  stream.
- **`v2-reissued-empty-uuid`**: issued, revoked, issued again in public mode
  (empty UUID). Updates 1 and 3 disclose the same state, so they have the same
  BLID. keripy's `vetBinds` matches disclosures to updates by BLID from a
  detached list, finds two matches and refuses (`UnverifiedBlindError`). In the
  stream each disclosure is attached to its own update, so a reader that binds
  by attachment reads it unambiguously. A writer should use a fresh UUID per
  update (`v2-reissued`), which keripy also accepts.
- **`v2-revoked-as-of-issuance`**: keripy has no KEL-position cutoff
  (`vetBinds`' cutoff is a timestamp). Its verdict is computed over the updates
  anchored by the limit.

## What keripy does that a reader must know

- **The ACDC SAID is computed over the most compact form.** Each expanded
  section is replaced by its own SAID (nested blocks with a `d` first), and the
  version string is sized for the compact form (`SerderACDC._compute`).
  keripy's `acdcmap` leaves the expanded attribute block's own `d` empty, so a
  reader must compute the section SAID, not read it.
- **A BLID is the Blake3-256 SAID of the four disclosed fields concatenated as
  qb64**, with the BLID dummied (`#` × 44). States are CESR labels: `0Missued`,
  `Yrevoked`; the empty primitive `1AAP` is a placeholder.
- **A v1 KEL anchoring a v2 registry is not generated here.** keripy's
  `Hab(version=Vrsn_1_0)` writes a v1 `icp` but then v2 `ixn` events, and
  replaying that log with a v1 genus emits v2 attachments with no genus switch,
  which keripy itself cannot re-read past sn 0.
- **keripy's v1 registry builders (`keri.vdr.eventing`) default to v2**
  (`version=Version`), so a v1 TEL has to be asked for. The 1.x path is checked
  here against a real `did:webs` artifact instead
  (`../did-webs-ENro7uf0.keri.cesr`).
