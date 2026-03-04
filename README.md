# Affinidi KERI-RS

A Rust implementation of the [KERI](https://keri.one/) (Key Event Receipt
Infrastructure) protocol for decentralized identity management. Supports
identity creation, key rotation, event verification, and witness-backed
integrity in direct mode communication.

> **IMPORTANT:**
> affinidi-keri-rs crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users agree
> to assume all risks associated with its deployment and use
> including implementing security and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising
> from the use or modification of the project.

## Architecture

The workspace contains five crates that build on each other in layers:

```
┌─────────────────────────────────────────────────────┐
│                  affinidi-keri                       │
│       High-level identity management & direct mode  │
└────────┬────────────────────┬───────────────────────┘
         │                    │
┌────────▼─────────┐  ┌──────▼──────────┐
│  affinidi-keri-db│  │affinidi-keri-core│
│  Storage (LMDB)  │  │ Protocol logic   │
└────────┬─────────┘  └──────┬──────────┘
         │                    │
         └────────┬───────────┘
                  │
       ┌──────────▼───────────┐
       │ affinidi-keri-crypto  │
       │ Cryptographic prims   │
       └──────────┬───────────┘
                  │
          ┌───────▼────────┐
          │  affinidi-cesr  │
          │ CESR encoding   │
          └────────────────┘
```

## Components

| Crate | Description |
| ----- | ----------- |
| [affinidi-cesr](crates/affinidi-cesr/) | CESR (Composable Event Streaming Representation) encoding and decoding — matter primitives, counters, indexers, and code tables |
| [affinidi-keri-crypto](crates/affinidi-keri-crypto/) | Cryptographic primitives — signing (Ed25519, secp256k1, P-256), digests (Blake2/3, SHA2/3), key derivation (Argon2), and verification |
| [affinidi-keri-core](crates/affinidi-keri-core/) | Core KERI protocol — event structures (inception, rotation, interaction, delegation, receipts), KEL verification, serialization, and parsing |
| [affinidi-keri-db](crates/affinidi-keri-db/) | Storage layer — LMDB-backed persistence for events, key event logs, signatures, witness receipts, key state, and escrow |
| [affinidi-keri](crates/affinidi-keri/) | High-level identity management — Hab (single identifier), Habery (multi-identifier registry), direct mode message processing, and configuration |

## Quick Start

### Requirements

- Rust 1.90.0+ (2024 Edition)

### Build

```bash
git clone https://github.com/affinidi/affinidi-keri-rs.git
cd affinidi-keri-rs

# Build all crates
cargo build

# Build release version
cargo build --release
```

### Run Tests

```bash
# Run all tests
cargo test

# Run a specific integration test
cargo test --package affinidi-keri witness_full_lifecycle

# Run tests with output
cargo test -- --nocapture
```

## Demo Examples

The integration tests in [`crates/affinidi-keri/tests/witness_integration.rs`](crates/affinidi-keri/tests/witness_integration.rs)
demonstrate the full KERI lifecycle and serve as runnable examples.

### Witness Full Lifecycle

This test walks through the complete KERI workflow with two witnesses:

```bash
cargo test --package affinidi-keri test_witness_full_lifecycle -- --nocapture
```

**What it demonstrates:**

1. **Create witnesses** — Two non-transferable witness identifiers are created
   with deterministic key derivation:

   ```rust
   let w1_config = InceptionConfig::builder()
       .transferable(false)
       .salt(vec![0x10u8; 16])
       .build();
   let (w1, _) = Hab::incept("witness1", &w1_config, &w1_store).unwrap();
   ```

2. **Create controller with witnesses** — A transferable controller identifier
   is created with a backer threshold of 2 and both witnesses as backers:

   ```rust
   let ctrl_config = InceptionConfig::builder()
       .salt(vec![0x30u8; 16])
       .backer_threshold(2)
       .backers(vec![w1_prefix, w2_prefix])
       .build();
   let (mut ctrl, icp_msg) = Hab::incept("controller", &ctrl_config, &ctrl_store).unwrap();
   ```

3. **Inception with witness receipts** — The inception event is receipted by
   both witnesses and verified by a third-party verifier:

   ```rust
   let icp_full = compose_witnessed_message(&icp_msg, &[&w1, &w2]);
   let result = direct::process_message(&icp_full, &verifier_store, &mut kevers).unwrap();
   ```

4. **Key rotation** — The controller rotates its signing keys, with witnesses
   receipting the rotation event:

   ```rust
   let rot_msg = ctrl.rotate(&RotationConfig::default(), &ctrl_store).unwrap();
   ```

5. **Interaction (data anchoring)** — External data is anchored to the
   identifier via an interaction event:

   ```rust
   let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
   let ixn_msg = ctrl.interact(&[anchor], &ctrl_store).unwrap();
   ```

6. **KEL verification** — The full Key Event Log is retrieved and verified in
   the verifier's store.

### Witness Receipt Storage

```bash
cargo test --package affinidi-keri test_witness_receipt_message_stored -- --nocapture
```

Demonstrates a witness generating and storing a receipt message for a
controller's inception event, verifying the receipt is persisted and
parseable.

### Inception Without Witnesses

```bash
cargo test --package affinidi-keri test_inception_without_witnesses_still_works -- --nocapture
```

Demonstrates creating and verifying identifiers without any witness
infrastructure (backer threshold of 0), including inception and rotation.

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting Technical Issues

If you have a technical issue with the Affinidi KERI-RS codebase, you can also
create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-keri-rs/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-keri-rs/issues/new).
   Be sure to include a **title and clear description**, as much relevant
   information as possible, and a **code sample** or an **executable test case**
   demonstrating the expected behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-keri-rs/blob/main/CONTRIBUTING.md)
guidelines.
