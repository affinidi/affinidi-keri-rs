# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.3] - 2026-04-09

### Security

- **[HIGH]** Reject non-ASCII bytes in KERI version string parsing (`Version::parse_str`). The KERI spec requires version strings to be pure ASCII, but the parser only validated UTF-8. Crafted multi-byte UTF-8 sequences crossing fixed byte-offset slice boundaries caused a panic, enabling unauthenticated remote denial of service.
- **[HIGH]** Reject non-ASCII bytes in CESR attachment parsing (`parser.rs`). The CESR parser converted attacker-controlled bytes to `&str` via UTF-8 validation, then used fixed byte-offset slicing. Multi-byte UTF-8 characters at slice boundaries caused panics. Added ASCII guards in `parse_attachments`, `parse_indexed_sigs`, `parse_receipt_couples`, and `skip_counted_primitives`.

## [0.1.2] - 2026-04-03

### Security

- **[CRITICAL]** Add prefix derivation validation in `Kever::new` and `Kever::new_from_parts`. Self-addressing prefixes must match the event SAID (`i == d`), and basic prefixes must match the first public key. Previously, an attacker could set `"i"` to a victim's prefix while `"d"` is the attacker's own SAID — SAID verification would pass but the prefix was unchecked.
- **[HIGH]** Reject duplicate inceptions in direct mode. Replaying an inception event for an already-established prefix is now rejected, preventing KEL overwrites.
- **[HIGH]** Judge refuses further events once a prefix is flagged as duplicitous. Previously, events continued to be processed, growing the DEL without verification purpose.
- **[HIGH]** Add DEL size limits in Judge: 100 entries per prefix, 10,000 total. Prevents unbounded memory growth from sustained duplicity attacks.

### Added

- Benchmarks for KEL processing (`kel_benchmarks`) and history replay (`bench_history` example).
- `Kever::new_from_parts` and `Kever::verify_update_owned` for zero-clone event verification.
- `Kever::verify_witness_receipts_static` for verifying receipts without a mutable kever reference.
- `Serder::take_sad` for owned SAD consumption.
- `KeriStore::store_event` to consolidate event, KEL, first-seen, and signature writes into a single transaction.
- Regression tests for spoofed prefix attack, basic prefix mismatch, duplicate inception rejection, and post-duplicity event rejection.

### Fixed

- `rot`/`ixn`/`drt` events for unknown prefixes were persisted to the store without verification. Store writes now only happen after successful verification.

### Changed

- `process_parsed` takes `ParsedMessage` by value instead of by reference, enabling owned SAD consumption without cloning.
- Consolidated individual `put_event`/`append_kel`/`put_first_seen`/`put_signatures` calls in `direct.rs` into single `store_event` calls.

### Removed

- `affinidi-cesr` crate removed from the workspace (functionality consolidated elsewhere).

## [0.1.1] - 2026-04-02

### Security

- **[CRITICAL]** Add SAID verification to all Kever event processing paths (`new`, `new_from_parts`, `update`, `verify_update`, `verify_update_owned`). Previously, event contents could be tampered with after SAID computation without detection.
- **[CRITICAL]** Use constant-time comparison (`subtle::ConstantTimeEq`) for digest verification in `Diger::verify()` and prefix verification in `Prefixer::verify_basic()`/`verify_self_addressing()`. Previously used `==` which leaks timing information.
- **[CRITICAL]** Fix integer overflow in weighted threshold calculation (`threshold.rs`). Attacker-crafted weights with large denominators could overflow `u64` arithmetic, bypassing signature thresholds. Now uses checked arithmetic.
- **[CRITICAL]** Add next-key commitment verification in `KeyState::apply_rotation()`. Rotation keys are now hashed and verified against the prior establishment event's next-key digests, enforcing KERI's pre-rotation security guarantee.
- **[HIGH]** Fix state-before-persist ordering in direct mode. `apply_verified_update()` now runs after `store_event()`, preventing in-memory/storage divergence on DB write failure.
- **[HIGH]** Validate backer threshold against backer count in `from_inception()` and `apply_rotation()`. Prevents setting an unsatisfiable witness threshold.
- **[HIGH]** Remove `Clone` from `Signer` and `ZeroVec`. Cloning a `Signer` previously created an unzeroized copy of private key material in memory.
- **[HIGH]** `KeyEvent::sn()` now returns `Result` instead of silently masking parse failures as sequence number 0 via `unwrap_or(0)`.
- **[HIGH]** Remove non-atomic default `store_event`/`store_event_with_hab` from `KeriStore` trait. Implementations must now provide their own atomic transaction logic.
- **[HIGH]** Add escrow size limits (10K total entries, 16 per key, 4096 witness receipts per entry) to prevent memory exhaustion.
- **[HIGH]** Reject zero signing thresholds at parse time (`kt: "0"`) and as defense-in-depth in `is_satisfied()`. Previously, a zero threshold was always satisfied regardless of signatures.
- **[HIGH]** Add parser allocation bounds: hard cap of 4096 primitives per attachment group plus data-length sanity checks before `Vec::with_capacity(count)`. Prevents OOM from malicious CESR counter values.
- **[MEDIUM]** Sanitize crypto error messages in `Verfer` and `Signer` to avoid leaking internal library details.
- **[MEDIUM]** Document missing delegation seal verification (TODO) and volatile judge duplicity state (TODO).

### Changed

- `affinidi-cesr` dependency now loaded from crates.io (`0.1.0`) instead of a local path.
- Added `subtle = "2"` as a workspace dependency for constant-time operations.

## [0.1.0] - 2026-03-04

### Added

- Initial workspace setup with four crates: `affinidi-keri`, `affinidi-keri-core`, `affinidi-keri-crypto`, `affinidi-keri-db`.
- KERI event lifecycle: inception (`icp`/`dip`), rotation (`rot`/`drt`), interaction (`ixn`), and receipt (`rct`) processing.
- `Kever` for key state tracking and controller signature verification.
- `Serder` for KERI event serialization/deserialization with SAID verification.
- `Hab` (Habitat) for managing local KERI identifiers.
- `Habery` for multi-habitat management.
- Direct mode message processing (`direct.rs`) with witness receipt verification.
- KERI Judge with duplicity detection for identifying conflicting key event logs.
- LMDB-backed persistent storage implementing the `KeriStore` trait.
- Cryptographic primitives: `Signer`, `Verfer`, `Diger`, `Prefixer`, `Salter`, `Siger`, `Cigar`.
- CESR codec with Matter, Indexer, and Counter support.
- Event composition with configurable serialization (JSON, CBOR, MessagePack).
- Weighted and fractional threshold support for multi-sig.
- Escrow management for out-of-order and partially witnessed events.
- SAID (Self-Addressing Identifier) computation and verification.
- Parser for KERI message streams with attachment group handling.
- Example demos: credential workflow, witness interaction, and judge duplicity detection.
- Witness integration tests.
- README with architecture overview and demo instructions.
