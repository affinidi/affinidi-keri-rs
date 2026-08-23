# affinidi-keri-core

Core [KERI](https://keri.one/) protocol types and verification, part of
[affinidi-keri-rs](https://github.com/affinidi/affinidi-keri-rs).

- `Serder` — versioned, self-addressing event serialization (JSON, CBOR, MGPK)
  that retains the received bytes so signatures and SAIDs are always verified
  over the exact stream.
- `event` / `ilk` / `seal` — inception, rotation, interaction, delegated
  inception and rotation, and receipts.
- `kever` / `key_state` — key event log verification: SAID integrity, prior
  event digest chaining, sequence ordering, pre-rotation commitments, signing
  and witness thresholds.
- `threshold` — simple and weighted (fractional) thresholds.
- `parser` — CESR stream parsing into events plus their attachment groups.
- `escrow` — buffering for out-of-order events.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-keri-rs/blob/main/LICENSE)
