# affinidi-keri-db

LMDB-backed storage for [KERI](https://keri.one/), part of
[affinidi-keri-rs](https://github.com/affinidi/affinidi-keri-rs).

Persists key events, key event logs, signatures, witness receipts, key state
and escrow behind a `Store` trait, with an LMDB implementation via
[`heed`](https://crates.io/crates/heed).

Verification-only consumers (for example a `did:webs` resolver) do not need
this crate — `affinidi-keri-core` and `affinidi-keri-crypto` are enough.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-keri-rs/blob/main/LICENSE)
