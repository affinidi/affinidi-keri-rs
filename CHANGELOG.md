# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Benchmarks for KEL processing (`kel_benchmarks`) and history replay (`bench_history` example).
- `Kever::new_from_parts` and `Kever::verify_update_owned` for zero-clone event verification.
- `Kever::verify_witness_receipts_static` for verifying receipts without a mutable kever reference.
- `Serder::take_sad` for owned SAD consumption.
- `KeriStore::store_event` to consolidate event, KEL, first-seen, and signature writes into a single transaction.

### Fixed

- `rot`/`ixn`/`drt` events for unknown prefixes were persisted to the store without verification. Store writes now only happen after successful verification.

### Changed

- `process_parsed` takes `ParsedMessage` by value instead of by reference, enabling owned SAD consumption without cloning.
- Consolidated individual `put_event`/`append_kel`/`put_first_seen`/`put_signatures` calls in `direct.rs` into single `store_event` calls.

### Removed

- `affinidi-cesr` crate removed from the workspace (functionality consolidated elsewhere).

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
