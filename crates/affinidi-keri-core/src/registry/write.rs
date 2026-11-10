//! Writing ACDC 2.x registries and the designations bound to them.
//!
//! The counterpart of the reader in [`crate::registry`]: a registry inception
//! (`rip`), a designation credential (`acm`) bound to it, and blindable
//! updates (`bup`), each with its state disclosed (`-a`). Nothing here holds a
//! key. An ACDC 2.x credential is not signed; it is issued when an update its
//! issuer's KEL anchors discloses `issued` for it. So every registry event
//! this module builds comes with the seal ([`RegistryEvent::seal`]) that the
//! issuer anchors in an interaction event, which the caller builds and signs
//! with its own controller, and only then is the event composed for
//! publication ([`RegistryEvent::compose`]), naming the anchoring event.
//!
//! Messages are built as keripy builds them (`keri/acdc/messaging.py`,
//! `regcept`, `blindate`, `acdcmap`, b70986f), with two differences:
//!
//! - **A fresh UUID per update.** Every disclosure is salted with a 256-bit
//!   UUID the caller supplies ([`BlindingUuid`]). The ACDC specification's
//!   public mode, an empty UUID, gives a re-issue the same BLID as the first
//!   issuance, which keripy then refuses.
//! - **The attribute block carries its own SAID.** keripy's `acdcmap` leaves
//!   the expanded block's `d` empty; keripy accepts it filled, and the
//!   credential's SAID is the same either way, because it is computed over the
//!   compact form.
//!
//! A [`RegistryState`] is the non-secret state to continue a registry from.
//! [`RegistryState::update`] returns the next state rather than changing this
//! one, so a caller keeps the old state until the update is anchored.

use affinidi_cesr::codec::encode_qb64;
use affinidi_keri_crypto::Diger;
use serde::{Deserialize, Serialize};

use super::Anchor;
use crate::composer::{frame, number, push_group};
use crate::counter_table::{CounterTable, GroupKind};
use crate::error::CoreError;
use crate::parser::BlindedState;
use crate::sad::{SadMap, SadValue};
use crate::serder::Serder;
use crate::version::{SerializationKind, Version};

/// The digest code of every SAID this module writes: Blake3-256.
const SAID_CODE: &str = "E";
/// The length of a Blake3-256 SAID in qb64.
const SAID_LEN: usize = 44;

/// The 128-bit nonce of a registry inception (`rip`'s `u`, keripy's
/// `Noncer`, code `0A`). It makes two registries of one issuer distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryNonce(pub [u8; 16]);

impl RegistryNonce {
    fn qb64(&self) -> Result<String, CoreError> {
        cesr("0A", &self.0, 24)
    }
}

/// The 256-bit UUID salting one update's disclosed state (code `a`).
///
/// Use a fresh one for every update: two updates disclosing the same state
/// under the same UUID have the same BLID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindingUuid(pub [u8; 32]);

impl BlindingUuid {
    fn qb64(&self) -> Result<String, CoreError> {
        cesr("a", &self.0, 44)
    }
}

/// The state an update discloses for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TransactionState {
    /// The credential is issued.
    Issued,
    /// The credential is revoked.
    Revoked,
}

impl TransactionState {
    /// The state as a CESR label, as keripy writes it: `0Missued` (Tag6),
    /// `Yrevoked` (Tag7).
    fn label(self) -> &'static str {
        match self {
            Self::Issued => "0Missued",
            Self::Revoked => "Yrevoked",
        }
    }
}

/// A registry event: a `rip` or a `bup`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RegistryEvent {
    /// The event's SAID.
    pub said: String,
    /// Its sequence number in the registry (0 for the inception).
    pub n: u64,
    /// The serialized body.
    pub raw: Vec<u8>,
    /// The disclosed state of an update; `None` for an inception.
    pub disclosure: Option<BlindedState>,
}

impl RegistryEvent {
    /// The seal the issuer anchors in an interaction event: `{s, d}`, the
    /// registry sequence number in hex and the event's SAID, as keripy anchors
    /// a registry event.
    pub fn seal(&self) -> SadValue {
        let mut seal = SadValue::object();
        seal.insert("s", SadValue::String(format!("{:x}", self.n)));
        seal.insert("d", SadValue::String(self.said.clone()));
        seal
    }

    /// The event as published: the 2.x genus-version counter, the body, and
    /// an attachment group holding the seal source couple of the KEL event
    /// that anchors it and, for an update, its disclosed state.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the body does not parse or a group cannot be
    /// encoded.
    pub fn compose(&self, anchor: &Anchor) -> Result<Vec<u8>, CoreError> {
        let serder = Serder::from_raw(&self.raw)?;
        let table = CounterTable::V2;
        let mut groups = Vec::new();
        push_group(
            &mut groups,
            table,
            GroupKind::SealSourceCouples,
            &[number(anchor.sn)?, anchor.said.clone()],
        )?;
        if let Some(d) = &self.disclosure {
            push_group(
                &mut groups,
                table,
                GroupKind::BlindedStateQuadruples,
                &[
                    d.blid.clone(),
                    d.uuid.clone(),
                    d.acdc.clone(),
                    d.state.clone(),
                ],
            )?;
        }
        frame(&serder, &groups)
    }
}

/// A designation: an ACDC 2.x credential (`acm`) the issuer binds to its
/// registry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Designation {
    /// The credential's SAID, over its compact form.
    pub said: String,
    /// The serialized credential, its attribute block expanded.
    pub raw: Vec<u8>,
}

impl Designation {
    /// The credential as published: the 2.x genus-version counter and the
    /// body. It carries no attachments: its issuance is the anchored update
    /// that discloses it.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the body does not parse.
    pub fn compose(&self) -> Result<Vec<u8>, CoreError> {
        frame(&Serder::from_raw(&self.raw)?, &[])
    }
}

/// The non-secret state to continue a registry from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistryState {
    /// The issuer's AID.
    pub issuer: String,
    /// The registry's SAID (its inception's).
    pub registry: String,
    /// The SAID of the registry's latest event, which the next update names
    /// as prior.
    pub head: String,
    /// The latest event's sequence number.
    pub n: u64,
}

impl RegistryState {
    /// Incept a registry for `issuer`.
    ///
    /// `dt` is the inception's RFC 3339 timestamp, as keripy writes it
    /// (`2026-01-01T00:00:00.000000+00:00`).
    ///
    /// # Errors
    /// Returns [`CoreError`] if the event cannot be serialized.
    pub fn incept(
        issuer: &str,
        nonce: &RegistryNonce,
        dt: &str,
    ) -> Result<(Self, RegistryEvent), CoreError> {
        let mut sad = SadMap::new();
        sad.insert("v".into(), SadValue::String(acdc_version(0)));
        sad.insert("t".into(), SadValue::String("rip".into()));
        sad.insert("d".into(), SadValue::String(String::new()));
        sad.insert("u".into(), SadValue::String(nonce.qb64()?));
        sad.insert("i".into(), SadValue::String(issuer.into()));
        sad.insert("n".into(), SadValue::String("0".into()));
        sad.insert("dt".into(), SadValue::String(dt.into()));
        let (said, raw) = saidify(SadValue::Object(sad))?;
        let state = Self {
            issuer: issuer.into(),
            registry: said.clone(),
            head: said.clone(),
            n: 0,
        };
        Ok((
            state,
            RegistryEvent {
                said,
                n: 0,
                raw,
                disclosure: None,
            },
        ))
    }

    /// Continue `registry` from the published stream: the state after its
    /// latest update the issuer's KEL anchors.
    ///
    /// Read and checked as [`designations`](super::designations) reads a
    /// registry: the inception is the log's issuer's and anchored, the updates
    /// form a chain, and every registry event the KEL anchors is in the
    /// stream. So a caller needs no store of its own, and cannot continue from
    /// a state that the stream it publishes contradicts.
    ///
    /// # Errors
    /// Returns [`RegistryError`](super::RegistryError) if the registry is
    /// missing, not the issuer's, unanchored or broken, or if the KEL anchors
    /// a registry event the stream leaves out.
    pub fn resume(
        stream: &[crate::parser::ParsedMessage],
        log: &super::IssuerLog,
        registry: &str,
    ) -> Result<Self, super::RegistryError> {
        super::check_anchored_events_present(stream, log)?;
        super::v2::head(stream, log, registry)
    }

    /// A designation credential of `schema`, bound to this registry, with the
    /// attribute block `attributes` (an object; its `d` is computed).
    ///
    /// Building it issues nothing: [`RegistryState::update`] with
    /// [`TransactionState::Issued`] does, once anchored.
    ///
    /// # Errors
    /// Returns [`CoreError`] if `attributes` is not an object or the
    /// credential cannot be serialized.
    pub fn designation(
        &self,
        schema: &str,
        attributes: &SadValue,
    ) -> Result<Designation, CoreError> {
        designation(&self.issuer, &self.registry, schema, attributes)
    }

    /// As [`designation`](Self::designation), with a rules section `r` (an
    /// object; its `d` is computed), which a schema that requires `r` needs.
    ///
    /// # Errors
    /// Returns [`CoreError`] if `attributes` or `rules` is not an object or
    /// the credential cannot be serialized.
    pub fn designation_with_rules(
        &self,
        schema: &str,
        attributes: &SadValue,
        rules: &SadValue,
    ) -> Result<Designation, CoreError> {
        designation_with_rules(
            &self.issuer,
            &self.registry,
            schema,
            attributes,
            Some(rules),
        )
    }

    /// An update disclosing `state` for `credential`, salted with `uuid`.
    ///
    /// Returns the state after the update, and the update. Keep this state
    /// until the update is anchored.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the update cannot be serialized.
    pub fn update(
        &self,
        credential: &str,
        state: TransactionState,
        uuid: &BlindingUuid,
        dt: &str,
    ) -> Result<(Self, RegistryEvent), CoreError> {
        let disclosure = disclose(uuid, credential, state)?;
        let n = self.n + 1;
        let mut sad = SadMap::new();
        sad.insert("v".into(), SadValue::String(acdc_version(0)));
        sad.insert("t".into(), SadValue::String("bup".into()));
        sad.insert("d".into(), SadValue::String(String::new()));
        sad.insert("rd".into(), SadValue::String(self.registry.clone()));
        sad.insert("n".into(), SadValue::String(format!("{n:x}")));
        sad.insert("p".into(), SadValue::String(self.head.clone()));
        sad.insert("dt".into(), SadValue::String(dt.into()));
        sad.insert("b".into(), SadValue::String(disclosure.blid.clone()));
        let (said, raw) = saidify(SadValue::Object(sad))?;
        let next = Self {
            head: said.clone(),
            n,
            ..self.clone()
        };
        Ok((
            next,
            RegistryEvent {
                said,
                n,
                raw,
                disclosure: Some(disclosure),
            },
        ))
    }
}

/// A designation credential (`acm`) of `schema`, issued by `issuer` and
/// bound to `registry`.
///
/// # Errors
/// Returns [`CoreError`] if `attributes` is not an object or the credential
/// cannot be serialized.
pub fn designation(
    issuer: &str,
    registry: &str,
    schema: &str,
    attributes: &SadValue,
) -> Result<Designation, CoreError> {
    designation_with_rules(issuer, registry, schema, attributes, None)
}

/// A designation credential (`acm`) of `schema`, issued by `issuer`, bound to
/// `registry`, with the attribute block `attributes` and, if given, the rules
/// section `rules`.
///
/// Each section is published expanded with its own SAID first (`d`), and the
/// credential's SAID is computed over the compact form, each section replaced
/// by its SAID (keripy `SerderACDC._compute`).
///
/// # Errors
/// Returns [`CoreError`] if `attributes` or `rules` is not an object or the
/// credential cannot be serialized.
pub fn designation_with_rules(
    issuer: &str,
    registry: &str,
    schema: &str,
    attributes: &SadValue,
    rules: Option<&SadValue>,
) -> Result<Designation, CoreError> {
    let block = section(attributes, "attribute block")?;
    let rules = rules.map(|r| section(r, "rules section")).transpose()?;
    let said_of = |s: &SadValue| {
        s.get("d")
            .and_then(SadValue::as_str)
            .unwrap_or_default()
            .to_string()
    };

    let build = |a: SadValue, r: Option<SadValue>| {
        let mut sad = SadMap::new();
        sad.insert("v".into(), SadValue::String(acdc_version(0)));
        sad.insert("t".into(), SadValue::String("acm".into()));
        sad.insert("d".into(), SadValue::String("#".repeat(SAID_LEN)));
        sad.insert("i".into(), SadValue::String(issuer.into()));
        sad.insert("rd".into(), SadValue::String(registry.into()));
        sad.insert("s".into(), SadValue::String(schema.into()));
        sad.insert("a".into(), a);
        if let Some(r) = r {
            sad.insert("r".into(), r);
        }
        SadValue::Object(sad)
    };

    // The SAID is over the most compact form: each section replaced by its
    // SAID, and the version string sized for that form.
    let (said, _) = saidify(build(
        SadValue::String(said_of(&block)),
        rules.as_ref().map(|r| SadValue::String(said_of(r))),
    ))?;

    // Published expanded, with the version string sized for what is published.
    let mut expanded = build(block, rules);
    size_version(&mut expanded)?;
    expanded.insert("d", SadValue::String(said.clone()));
    let raw = serde_json::to_vec(&expanded)?;
    Ok(Designation { said, raw })
}

/// A section (`a` or `r`) with its SAID computed: `d` first, as keripy orders
/// it, then the fields as given.
fn section(given: &SadValue, what: &str) -> Result<SadValue, CoreError> {
    let Some(given) = given.as_object() else {
        return Err(CoreError::Validation(format!(
            "a designation's {what} must be an object"
        )));
    };
    let mut block = SadMap::new();
    block.insert("d".into(), SadValue::String(String::new()));
    for (k, v) in given {
        if k != "d" {
            block.insert(k.clone(), v.clone());
        }
    }
    fill_section(SadValue::Object(block))
}

/// The disclosed state of an update: BLID, UUID, credential and state. The
/// BLID is the SAID of the other three concatenated, behind a dummy BLID.
fn disclose(
    uuid: &BlindingUuid,
    credential: &str,
    state: TransactionState,
) -> Result<BlindedState, CoreError> {
    let uuid = uuid.qb64()?;
    let label = state.label();
    let text = format!("{}{uuid}{credential}{label}", "#".repeat(SAID_LEN));
    let blid = Diger::from_data(SAID_CODE, text.as_bytes())
        .and_then(|d| d.qb64())
        .map_err(CoreError::Crypto)?;
    Ok(BlindedState {
        blid,
        uuid,
        acdc: credential.into(),
        state: label.into(),
    })
}

/// A section expanded with its own SAID: each nested block that has a `d`
/// filled first, then this block's `d` computed over its compact form (each
/// nested block replaced by its SAID), as keripy computes a section's SAID.
fn fill_section(section: SadValue) -> Result<SadValue, CoreError> {
    let SadValue::Object(map) = section else {
        return Ok(section);
    };
    let mut expanded = SadMap::new();
    let mut compact = SadMap::new();
    for (k, v) in map {
        if v.is_object() && v.get("d").is_some() {
            let filled = fill_section(v)?;
            let said = filled.get("d").cloned().unwrap_or_default();
            compact.insert(k.clone(), said);
            expanded.insert(k, filled);
        } else {
            compact.insert(k.clone(), v.clone());
            expanded.insert(k, v);
        }
    }
    let mut compact = SadValue::Object(compact);
    let said = crate::said::compute_said(&mut compact, "d", SAID_CODE, SerializationKind::Json)?;
    let mut expanded = SadValue::Object(expanded);
    expanded.insert("d", SadValue::String(said));
    Ok(expanded)
}

/// An ACDC 2.x JSON version string of `size`.
fn acdc_version(size: usize) -> String {
    Version::new("ACDC", 2, 0, SerializationKind::Json, size).to_version_string()
}

/// Size the version string for the message as it stands, with a dummy `d`.
fn size_version(sad: &mut SadValue) -> Result<(), CoreError> {
    sad.insert("d", SadValue::String("#".repeat(SAID_LEN)));
    let size = serde_json::to_vec(&*sad)?.len();
    sad.insert("v", SadValue::String(acdc_version(size)));
    Ok(())
}

/// Size the version string, compute the SAID into `d`, and serialize.
fn saidify(mut sad: SadValue) -> Result<(String, Vec<u8>), CoreError> {
    size_version(&mut sad)?;
    let said = crate::said::compute_said(&mut sad, "d", SAID_CODE, SerializationKind::Json)?;
    let raw = serde_json::to_vec(&sad)?;
    Ok((said, raw))
}

/// A fixed-size CESR primitive of `code` over `raw`.
fn cesr(code: &str, raw: &[u8], fs: usize) -> Result<String, CoreError> {
    encode_qb64(code, raw, fs)
        .map_err(|e| CoreError::ParseError(format!("cannot encode {code}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_encoded_as_keripy_writes_them() {
        assert_eq!(number(0).unwrap(), "MAAA");
        assert_eq!(number(1).unwrap(), "MAAB");
        assert_eq!(number(2).unwrap(), "MAAC");
        assert_eq!(number(0x1_0000).unwrap().len(), 8);
        assert!(number(0x1_0000).unwrap().starts_with("0H"));
    }

    #[test]
    fn a_registry_nonce_is_salt_128() {
        // keripy fixture `v2-reissued`: Salter(raw=b"registry-uuid-01").qb64
        let nonce = RegistryNonce(*b"registry-uuid-01");
        assert_eq!(nonce.qb64().unwrap(), "0AByZWdpc3RyeS11dWlkLTAx");
    }

    #[test]
    fn two_updates_with_fresh_uuids_have_distinct_blids() {
        let a = disclose(
            &BlindingUuid([1; 32]),
            "E".repeat(44).as_str(),
            TransactionState::Issued,
        )
        .unwrap();
        let b = disclose(
            &BlindingUuid([2; 32]),
            "E".repeat(44).as_str(),
            TransactionState::Issued,
        )
        .unwrap();
        assert_ne!(a.blid, b.blid);
    }
}
