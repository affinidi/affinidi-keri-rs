//! Reverse-conformance scenarios for registries: an issuer's KEL written by
//! this library's controller, and v2 registries and designations written by
//! `affinidi_keri_core::registry::write`, for keripy to verify
//! (`tests/fixtures/ours-v2-registries/verify_ours_registries.py`).
//!
//! Shared by `examples/emit_registry_conformance.rs`, which writes them to
//! disk, and `tests/ours_v2_registries.rs`, which rebuilds them in memory and
//! checks they still match the committed files byte for byte.
//!
//! Keys come from a fixed salt, timestamps are fixed, and every UUID is
//! derived from a fixed label, so the output never changes unless the code that
//! writes it does.

#![allow(dead_code)]

use affinidi_keri::ProtocolVersion;
use affinidi_keri::controller::{ControllerState, Inception, KeySigner, NextKey, incept};
use affinidi_keri::hab::SignedEvent;
use affinidi_keri_core::registry::Anchor;
use affinidi_keri_core::registry::write::{
    BlindingUuid, Designation, RegistryEvent, RegistryNonce, RegistryState, TransactionState,
};
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Diger, Salter, Signer};
use serde_json::{Value, json};

const SALT: [u8; 16] = *b"vti-ours-v2-regs";
/// The v2 designated-aliases schema (kswg-did-method-webs-specification#216).
pub const ALIASES_V2: &str = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";
/// The v2 key agreement designation schema (affinidi-did-webs).
pub const KEY_AGREEMENT_V2: &str = "EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ";

/// One scenario's output.
pub struct Scenario {
    pub name: &'static str,
    /// The published stream.
    pub stream: Vec<u8>,
    /// What keripy must agree with: the KEL state, and for each credential its
    /// registry messages, their anchors and its expected status.
    pub json: Value,
}

fn stamp(day: u32) -> String {
    format!("2026-02-{day:02}T00:00:00.000000+00:00")
}

/// A fixed, distinct UUID per label.
fn uuid(label: &str) -> BlindingUuid {
    let digest = Diger::from_data("E", label.as_bytes()).unwrap();
    BlindingUuid(digest.raw().try_into().unwrap())
}

fn key(path: &str) -> Signer {
    Salter::new("0A", SALT.to_vec())
        .unwrap()
        .signer("A", path, "low", true)
        .unwrap()
}

/// An issuer whose KEL this scenario writes, one interaction event per anchor.
struct Issuer {
    signer: Signer,
    state: ControllerState,
    events: Vec<SignedEvent>,
}

impl Issuer {
    fn new(name: &str, version: ProtocolVersion) -> Self {
        let signer = key(&format!("{name}.0"));
        let next = key(&format!("{name}.1"));
        let inception = Inception::new(
            vec![signer.public_key().unwrap()],
            Threshold::Simple(1),
            vec![NextKey::PublicKey(next.public_key().unwrap())],
            Threshold::Simple(1),
        )
        .with_version(version);
        let mut pending = incept(&inception).unwrap();
        pending.sign_with(&signer as &dyn KeySigner).unwrap();
        let (icp, state) = pending.finish().unwrap();
        Self {
            signer,
            state,
            events: vec![icp],
        }
    }

    fn prefix(&self) -> String {
        self.state.prefix.clone()
    }

    /// Anchor `seals` in one interaction event; where it landed.
    fn anchor(&mut self, seals: &[SadValue]) -> Anchor {
        let mut pending = self.state.interact(seals).unwrap();
        pending.sign_with(&self.signer as &dyn KeySigner).unwrap();
        let (ixn, state) = pending.finish().unwrap();
        self.state = state;
        self.events.push(ixn);
        Anchor {
            sn: self.state.sn,
            said: self.state.last_said.clone(),
        }
    }

    fn upgrade(&mut self) {
        self.state = self.state.upgrade(ProtocolVersion::V2).unwrap();
    }

    fn kel(&self) -> Vec<u8> {
        self.events
            .iter()
            .flat_map(|e| e.composed.clone())
            .collect()
    }

    fn kel_json(&self) -> Value {
        json!({ "prefix": self.prefix(), "sn": self.state.sn, "said": self.state.last_said })
    }
}

/// One registry with one designation, and the updates written so far.
struct Registry {
    schema: &'static str,
    state: RegistryState,
    rip: (RegistryEvent, Option<Anchor>),
    credential: Designation,
    updates: Vec<(RegistryEvent, Anchor)>,
    expect: &'static str,
}

impl Registry {
    fn new(issuer: &Issuer, nonce: &[u8; 16], schema: &'static str, attributes: Value) -> Self {
        Self::with_rules(issuer, nonce, schema, attributes, None)
    }

    fn with_rules(
        issuer: &Issuer,
        nonce: &[u8; 16],
        schema: &'static str,
        attributes: Value,
        rules: Option<Value>,
    ) -> Self {
        let (state, rip) =
            RegistryState::incept(&issuer.prefix(), &RegistryNonce(*nonce), &stamp(1)).unwrap();
        let attributes = SadValue::from_json_value(&attributes);
        let credential = match rules {
            None => state.designation(schema, &attributes),
            Some(r) => {
                state.designation_with_rules(schema, &attributes, &SadValue::from_json_value(&r))
            }
        }
        .unwrap();
        Self {
            schema,
            state,
            rip: (rip, None),
            credential,
            updates: Vec::new(),
            expect: "not-issued",
        }
    }

    /// The next update, not yet anchored.
    fn update(&mut self, ts: TransactionState, label: &str) -> RegistryEvent {
        let n = self.state.n + 1;
        let (next, bup) = self
            .state
            .update(
                &self.credential.said,
                ts,
                &uuid(label),
                &stamp(n as u32 + 1),
            )
            .unwrap();
        self.state = next;
        self.expect = match ts {
            TransactionState::Issued => "issued",
            TransactionState::Revoked => "revoked",
            _ => unreachable!(),
        };
        bup
    }

    fn stream(&self) -> Vec<u8> {
        let mut out = self.rip.0.compose(self.rip.1.as_ref().unwrap()).unwrap();
        out.extend(self.credential.compose().unwrap());
        for (bup, anchor) in &self.updates {
            out.extend(bup.compose(anchor).unwrap());
        }
        out
    }

    fn json(&self) -> Value {
        let anchor = |a: &Anchor| json!({ "sn": a.sn, "said": a.said });
        json!({
            "schema": self.schema,
            "registry": self.state.registry,
            "credential": self.credential.said,
            "expect": self.expect,
            "rip": {
                "raw": String::from_utf8(self.rip.0.raw.clone()).unwrap(),
                "anchor": anchor(self.rip.1.as_ref().unwrap()),
            },
            "acm": { "raw": String::from_utf8(self.credential.raw.clone()).unwrap() },
            "updates": self.updates.iter().map(|(bup, a)| {
                let d = bup.disclosure.as_ref().unwrap();
                json!({
                    "raw": String::from_utf8(bup.raw.clone()).unwrap(),
                    "anchor": anchor(a),
                    "disclosure": {
                        "blid": d.blid, "uuid": d.uuid, "acdc": d.acdc,
                        "state": if d.state == "0Missued" { "issued" } else { "revoked" },
                    },
                })
            }).collect::<Vec<_>>(),
        })
    }
}

fn aliases(issuer: &Issuer) -> Value {
    json!({ "dt": stamp(1), "ids": [format!("did:webs:example.com:{}", issuer.prefix())] })
}

/// Incept a registry and anchor its inception alone.
fn incepted(
    issuer: &mut Issuer,
    nonce: &[u8; 16],
    schema: &'static str,
    attributes: Value,
) -> Registry {
    let mut reg = Registry::new(issuer, nonce, schema, attributes);
    let anchor = issuer.anchor(&[reg.rip.0.seal()]);
    reg.rip.1 = Some(anchor);
    reg
}

/// Apply `states` in order, each update anchored in its own interaction event.
fn updated(issuer: &mut Issuer, reg: &mut Registry, name: &str, states: &[TransactionState]) {
    for (i, ts) in states.iter().enumerate() {
        let bup = reg.update(*ts, &format!("{name}.{i}"));
        let anchor = issuer.anchor(&[bup.seal()]);
        reg.updates.push((bup, anchor));
    }
}

fn scenario(name: &'static str, note: &str, issuer: &Issuer, registries: &[&Registry]) -> Scenario {
    let mut stream = issuer.kel();
    for r in registries {
        stream.extend(r.stream());
    }
    Scenario {
        name,
        stream,
        json: json!({
            "note": note,
            "kel": issuer.kel_json(),
            "credentials": registries.iter().map(|r| r.json()).collect::<Vec<_>>(),
        }),
    }
}

fn single(name: &'static str, note: &str, states: &[TransactionState]) -> Scenario {
    let mut issuer = Issuer::new(name, ProtocolVersion::V2);
    let attrs = aliases(&issuer);
    let mut reg = incepted(&mut issuer, b"vti-registry-001", ALIASES_V2, attrs);
    updated(&mut issuer, &mut reg, name, states);
    scenario(name, note, &issuer, &[&reg])
}

/// Two designations, each in its own registry: a v2 registry's state binds
/// one credential. Both inceptions are anchored in one interaction event, and
/// both issuances in the next.
fn two_designations() -> Scenario {
    let name = "v2-two-designations";
    let mut issuer = Issuer::new(name, ProtocolVersion::V2);
    let attrs = aliases(&issuer);
    let mut a = Registry::new(&issuer, b"vti-registry-001", ALIASES_V2, attrs);
    let mut k = Registry::new(
        &issuer,
        b"vti-registry-002",
        KEY_AGREEMENT_V2,
        json!({ "dt": stamp(1), "keys": ["CPz5wadpRpL4rGHeRSLHIc-2jMndx_mYBhuPhcr7WFRg"] }),
    );
    let both = issuer.anchor(&[a.rip.0.seal(), k.rip.0.seal()]);
    a.rip.1 = Some(both.clone());
    k.rip.1 = Some(both);
    let ua = a.update(TransactionState::Issued, "two.aliases");
    let uk = k.update(TransactionState::Issued, "two.ka");
    let anchor = issuer.anchor(&[ua.seal(), uk.seal()]);
    a.updates.push((ua, anchor.clone()));
    k.updates.push((uk, anchor));
    scenario(
        name,
        "designated aliases and a key agreement designation, each in its own registry; both inceptions anchored in one ixn, both issuances in the next",
        &issuer,
        &[&a, &k],
    )
}

/// A designation with the rules section its schema requires (`r`), as
/// `did:webs` writes one: the credential's SAID covers both sections compact.
fn with_rules() -> Scenario {
    let name = "v2-designation-with-rules";
    let mut issuer = Issuer::new(name, ProtocolVersion::V2);
    let attrs = aliases(&issuer);
    let rules = json!({
        "aliasDesignation": {
            "l": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID."
        },
        "usageDisclaimer": {
            "l": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID."
        },
        "issuanceDisclaimer": {
            "l": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified."
        },
        "termsOfUse": {
            "l": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller."
        }
    });
    let mut reg =
        Registry::with_rules(&issuer, b"vti-registry-001", ALIASES_V2, attrs, Some(rules));
    let anchor = issuer.anchor(&[reg.rip.0.seal()]);
    reg.rip.1 = Some(anchor);
    updated(&mut issuer, &mut reg, name, &[TransactionState::Issued]);
    scenario(
        name,
        "a designation with the rules section (r) its schema requires; its SAID covers the attribute block and rules compact",
        &issuer,
        &[&reg],
    )
}

/// A KEL that began in KERI v1 and continues in v2, issuing from a v2
/// registry once it is v2.
fn migrated() -> Scenario {
    let name = "migrated-v1-kel-v2-registry";
    let mut issuer = Issuer::new(name, ProtocolVersion::V1);
    issuer.anchor(&[]);
    issuer.upgrade();
    let attrs = aliases(&issuer);
    let mut reg = incepted(&mut issuer, b"vti-registry-001", ALIASES_V2, attrs);
    updated(&mut issuer, &mut reg, name, &[TransactionState::Issued]);
    scenario(
        name,
        "a v1 icp and ixn, then v2 ixn events anchoring a v2 registry and its issuance (P2: a v1 KEL may continue in v2 and anchor a v2 registry)",
        &issuer,
        &[&reg],
    )
}

/// Every scenario, in a fixed order.
pub fn all() -> Vec<Scenario> {
    use TransactionState::{Issued, Revoked};
    vec![
        single(
            "v2-registry-issued",
            "rip, acm, bup(issued); each registry event anchored in its own ixn",
            &[Issued],
        ),
        single(
            "v2-registry-revoked",
            "issued, then revoked",
            &[Issued, Revoked],
        ),
        single(
            "v2-registry-reissued",
            "issued, revoked, issued again, each update salted with a fresh UUID",
            &[Issued, Revoked, Issued],
        ),
        two_designations(),
        with_rules(),
        migrated(),
    ]
}

/// The `.json` written beside each stream.
pub fn json_for(s: &Scenario) -> String {
    let mut text = serde_json::to_string_pretty(&s.json).unwrap();
    text.push('\n');
    text
}
