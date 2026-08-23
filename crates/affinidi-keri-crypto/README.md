# affinidi-keri-crypto

Cryptographic primitives for [KERI](https://keri.one/) (Key Event Receipt
Infrastructure), part of [affinidi-keri-rs](https://github.com/affinidi/affinidi-keri-rs).

- `Signer` / `Verfer` — Ed25519, secp256k1 (ECDSA) and NIST P-256 signing and
  verification, keyed by CESR derivation code.
- `Siger` / `Cigar` — indexed and non-indexed signatures.
- `Diger` — Blake3, Blake2b/2s, SHA2 and SHA3 digests in 256- and 512-bit
  variants, CESR-coded.
- `Prefixer` — self-certifying and self-addressing identifier prefixes.
- `Salter` — Argon2id key derivation from a salt.

CESR encoding is provided by [`affinidi-cesr`](https://crates.io/crates/affinidi-cesr).

## License

[Apache-2.0](https://github.com/affinidi/affinidi-keri-rs/blob/main/LICENSE)
