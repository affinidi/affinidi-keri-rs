//! Identifiers whose keys this library never holds.
//!
//! [`Hab`](crate::hab::Hab) derives every key — current and pre-rotated — from
//! one salt, which suits a wallet that keeps its own secrets. A custodian that
//! holds keys elsewhere (an HSM, an enclave, a key service) or shares control
//! with someone else cannot work that way: a recovery key held by a second
//! party must be committed to without the controller ever seeing its secret,
//! and a rotation that needs that party's signature may be signed hours later
//! on another machine.
//!
//! So this module separates *building* an event from *signing* it:
//!
//! 1. [`incept`], [`ControllerState::rotate`] and [`ControllerState::interact`]
//!    build the event from public material alone — current keys, and next
//!    keys as [`NextKey`] digests or public keys — and return a
//!    [`PendingEvent`].
//! 2. Signatures are added as they arrive: [`PendingEvent::sign_with`] for a
//!    [`KeySigner`] in this process, [`PendingEvent::add_signature`] for a raw
//!    signature produced anywhere else. Each is verified when it is added. A
//!    `PendingEvent` serializes, so it can wait for a remote signer.
//! 3. [`PendingEvent::finish`] refuses unless the event would be accepted —
//!    its own `kt`, and for a rotation the prior event's `nt` — and returns the
//!    signed event with the [`ControllerState`] it produces.
//!
//! Nothing here is secret, so a `ControllerState` and a `PendingEvent` can be
//! stored anywhere the key event log could be.
//!
//! # A recovery key the controller cannot use alone
//!
//! Commit the routine successor `R′` and a custodian's recovery key `K` with a
//! weighted next threshold that `K` meets and `R′` does not:
//!
//! ```text
//! k  = [R]              kt = "1"
//! n  = [H(R′), H(K)]    nt = [["1/2", "1"]]
//! ```
//!
//! A rotation must reveal every committed key, in order (`k = [R′, K]`), and
//! meet the prior `nt` over them: signed by `K`, or by `R′` and `K`, never by
//! `R′` alone. With `kt = "1"` the rotated identifier's routine events are then
//! signed by `R′` alone, and the rotation commits a fresh `K′`.

use std::collections::BTreeMap;

use affinidi_cesr::Counter;
use affinidi_keri_core::composer::counter_code_for;
use affinidi_keri_core::counter_table::GroupKind;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::threshold::{Threshold, ThresholdValue};
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_core::{CoreError, SadValue};
use affinidi_keri_crypto::{Diger, Siger, Signer, Verfer};
use serde::{Deserialize, Serialize};

use crate::error::KeriError;
use crate::hab::{SignedEvent, fix_version_string};

/// A signing key held outside this library.
///
/// Implement it over whatever holds the secret; this library only ever asks
/// for a signature over an event's serialized bytes.
pub trait KeySigner {
    /// The public key, qb64, exactly as it appears in an event's `k`.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the key cannot be encoded.
    fn public_key(&self) -> Result<String, KeriError>;

    /// A raw signature over `message` (64 bytes for every supported
    /// algorithm).
    ///
    /// # Errors
    /// Returns [`KeriError`] if the key cannot sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeriError>;
}

impl KeySigner for Signer {
    fn public_key(&self) -> Result<String, KeriError> {
        Ok(self.verfer().qb64()?)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeriError> {
        Ok(Signer::sign(self, message)?.raw().to_vec())
    }
}

/// A key committed to as a successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NextKey {
    /// A next-key digest, qb64, as it appears in `n`: the Blake3-256 digest
    /// (`E`) of the key's qb64 form. A custodian can hand over only this, and
    /// keep even its public key private until it rotates.
    Digest(String),
    /// A public key, qb64; this library computes its digest.
    PublicKey(String),
}

impl NextKey {
    /// The digest this key is committed by, as it appears in `n`.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the digest or key does not decode.
    pub fn digest(&self) -> Result<String, KeriError> {
        match self {
            Self::Digest(d) => {
                Diger::from_qb64(d)?;
                Ok(d.clone())
            }
            Self::PublicKey(key) => {
                Verfer::from_qb64(key)?;
                Ok(Diger::from_data("E", key.as_bytes())?.qb64()?)
            }
        }
    }
}

/// The parameters of an inception event.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Inception {
    /// The current signing keys, qb64.
    pub keys: Vec<String>,
    /// The signing threshold over `keys`.
    pub threshold: Threshold,
    /// The committed successors.
    pub next: Vec<NextKey>,
    /// The threshold a rotation must meet over the revealed successors.
    pub next_threshold: Threshold,
    /// Witness prefixes.
    pub backers: Vec<String>,
    /// Witness threshold.
    pub backer_threshold: usize,
    /// Configuration traits, such as `EO` (establishment only).
    pub config_traits: Vec<String>,
}

impl Inception {
    /// An inception with no witnesses and no configuration traits.
    pub fn new(
        keys: Vec<String>,
        threshold: Threshold,
        next: Vec<NextKey>,
        next_threshold: Threshold,
    ) -> Self {
        Self {
            keys,
            threshold,
            next,
            next_threshold,
            backers: Vec::new(),
            backer_threshold: 0,
            config_traits: Vec::new(),
        }
    }

    /// Set the witnesses and their threshold.
    pub fn with_backers(mut self, backers: Vec<String>, threshold: usize) -> Self {
        self.backers = backers;
        self.backer_threshold = threshold;
        self
    }

    /// Set the configuration traits.
    pub fn with_config_traits(mut self, traits: Vec<String>) -> Self {
        self.config_traits = traits;
        self
    }
}

/// The parameters of a rotation event.
///
/// The keys a rotation installs are the ones the prior establishment event
/// committed to, all of them and in order: they come from the state, not from
/// here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rotation {
    /// The signing threshold over the installed keys.
    pub threshold: Threshold,
    /// The successors this rotation commits to. Empty, with `next_threshold`
    /// `"0"`, abandons the identifier.
    pub next: Vec<NextKey>,
    /// The threshold the next rotation must meet.
    pub next_threshold: Threshold,
    /// Witnesses to add.
    pub backers_add: Vec<String>,
    /// Witnesses to remove.
    pub backers_remove: Vec<String>,
    /// The new witness threshold; `None` keeps the current one.
    pub backer_threshold: Option<usize>,
}

impl Rotation {
    /// A rotation that leaves the witnesses as they are.
    pub fn new(threshold: Threshold, next: Vec<NextKey>, next_threshold: Threshold) -> Self {
        Self {
            threshold,
            next,
            next_threshold,
            backers_add: Vec::new(),
            backers_remove: Vec::new(),
            backer_threshold: None,
        }
    }

    /// Change the witnesses.
    pub fn with_backers(
        mut self,
        add: Vec<String>,
        remove: Vec<String>,
        threshold: Option<usize>,
    ) -> Self {
        self.backers_add = add;
        self.backers_remove = remove;
        self.backer_threshold = threshold;
        self
    }
}

/// Everything needed to build the next event for an identifier. Nothing in it
/// is secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ControllerState {
    /// The identifier prefix, qb64.
    pub prefix: String,
    /// Sequence number of the latest event.
    pub sn: u64,
    /// SAID of the latest event.
    pub last_said: String,
    /// Sequence number of the latest establishment event.
    pub establishment_sn: u64,
    /// SAID of the latest establishment event.
    pub establishment_said: String,
    /// The current signing keys, qb64.
    pub keys: Vec<String>,
    /// The current signing threshold.
    pub threshold: ThresholdValue,
    /// The committed next-key digests, qb64.
    pub next_digests: Vec<String>,
    /// The threshold the next rotation must meet.
    pub next_threshold: ThresholdValue,
    /// Witness prefixes.
    pub backers: Vec<String>,
    /// Witness threshold.
    pub backer_threshold: usize,
}

/// What a pending event's signatures must satisfy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Requirement {
    /// The keys the signatures are indexed into.
    keys: Vec<String>,
    /// The thresholds those signatures must meet: the event's signing
    /// threshold, and for a rotation also the prior next threshold.
    thresholds: Vec<ThresholdValue>,
}

/// An event built and awaiting signatures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PendingEvent {
    /// SAID of the event.
    pub said: String,
    /// The event's ilk: `icp`, `rot` or `ixn`.
    pub ilk: String,
    /// The serialized event — the bytes every signature is over.
    raw: String,
    requirement: Requirement,
    /// Verified signatures, qb64, by key index.
    signatures: BTreeMap<usize, String>,
    /// The state once this event is accepted.
    next_state: ControllerState,
}

impl PendingEvent {
    /// The bytes to sign.
    pub fn signing_input(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    /// The keys signatures are indexed into, in order.
    pub fn keys(&self) -> &[String] {
        &self.requirement.keys
    }

    /// The indices that have a verified signature.
    pub fn signed_indices(&self) -> Vec<usize> {
        self.signatures.keys().copied().collect()
    }

    /// Whether the signatures added so far meet every threshold.
    pub fn is_complete(&self) -> bool {
        let indices = self.signed_indices();
        self.requirement
            .thresholds
            .iter()
            .all(|t| t.0.is_satisfied(&indices, self.requirement.keys.len()))
    }

    /// Sign with a key held in this process.
    ///
    /// # Errors
    /// Returns [`KeriError::Config`] if the signer's key is not one the event
    /// is signed by, or [`KeriError`] if it cannot sign or its signature does
    /// not verify.
    pub fn sign_with(&mut self, signer: &dyn KeySigner) -> Result<(), KeriError> {
        let key = signer.public_key()?;
        let index = self
            .requirement
            .keys
            .iter()
            .position(|k| *k == key)
            .ok_or_else(|| {
                KeriError::Config(format!("{key} is not a key this {} is signed by", self.ilk))
            })?;
        let signature = signer.sign(self.signing_input())?;
        self.add_signature(index, signature)
    }

    /// Add a raw signature produced elsewhere, by the key at `index`.
    ///
    /// # Errors
    /// Returns [`KeriError::Config`] if `index` names no key, or
    /// [`KeriError`] if the signature does not verify against that key.
    pub fn add_signature(&mut self, index: usize, signature: Vec<u8>) -> Result<(), KeriError> {
        let key = self.requirement.keys.get(index).ok_or_else(|| {
            KeriError::Config(format!(
                "signature index {index} is out of range for {} key(s)",
                self.requirement.keys.len()
            ))
        })?;
        let verfer = Verfer::from_qb64(key)?;
        if !verfer.verify(self.signing_input(), &signature)? {
            return Err(KeriError::Core(CoreError::Validation(format!(
                "signature by key {index} does not verify over this {}",
                self.ilk
            ))));
        }
        let siger = Siger::new_with_verfer(indexed_code(key)?, index, None, signature, verfer)?;
        self.signatures.insert(index, siger.qb64()?);
        Ok(())
    }

    /// The signed event, and the state it produces.
    ///
    /// # Errors
    /// Returns [`CoreError::ThresholdNotMet`] (as [`KeriError::Core`]) if the
    /// signatures do not meet every threshold the event must.
    pub fn finish(self) -> Result<(SignedEvent, ControllerState), KeriError> {
        if !self.is_complete() {
            return Err(KeriError::Core(CoreError::ThresholdNotMet));
        }
        let sig_bytes: Vec<u8> = self
            .signatures
            .values()
            .flat_map(|s| s.as_bytes().to_vec())
            .collect();
        let raw = self.raw.into_bytes();
        let serder = Serder::from_raw(&raw)?;
        let code = counter_code_for(&serder, GroupKind::ControllerIdxSigs)?;
        let counter = Counter::new(code, self.signatures.len())?.qb64()?;
        let mut composed = raw.clone();
        composed.extend_from_slice(counter.as_bytes());
        composed.extend_from_slice(&sig_bytes);
        Ok((
            SignedEvent {
                said: self.said,
                raw,
                signatures: sig_bytes,
                composed,
            },
            self.next_state,
        ))
    }
}

/// The "current only" indexed signature code for a key's algorithm.
fn indexed_code(key: &str) -> Result<&'static str, KeriError> {
    let code = if key.starts_with("1AAA") || key.starts_with("1AAB") {
        "C"
    } else if key.starts_with("1AAI") || key.starts_with("1AAJ") {
        "E"
    } else if key.starts_with('D') || key.starts_with('B') {
        "A"
    } else {
        return Err(KeriError::Config(format!("{key} is not a signing key")));
    };
    Ok(code)
}

fn digests(next: &[NextKey]) -> Result<Vec<String>, KeriError> {
    next.iter().map(NextKey::digest).collect()
}

fn check_thresholds(
    keys: &[String],
    threshold: &Threshold,
    next: &[String],
    next_threshold: &Threshold,
) -> Result<(), KeriError> {
    for key in keys {
        let verfer = Verfer::from_qb64(key)?;
        if !verfer.transferable() {
            return Err(KeriError::Config(format!(
                "{key} is a non-transferable key; a controlled identifier rotates"
            )));
        }
    }
    // A threshold counts positions, not holders: a key listed twice is one
    // holder filling two places, so `kt "2"` over `[K, K]` is met by K alone.
    // The same goes for `n`, where a repeated digest commits one successor to
    // two places of the next rotation.
    refuse_repeats(keys, "k")?;
    refuse_repeats(next, "n")?;
    threshold.check_satisfiable(keys.len(), "kt")?;
    match (next_threshold.is_zero(), next.is_empty()) {
        (true, true) => Ok(()),
        (true, false) => Err(KeriError::Config(format!(
            "nt is 0 but n commits to {} next key(s)",
            next.len()
        ))),
        (false, _) => Ok(next_threshold.check_satisfiable(next.len(), "nt")?),
    }
}

fn refuse_repeats(items: &[String], field: &str) -> Result<(), KeriError> {
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    match items.iter().find(|item| !seen.insert(item.as_str())) {
        Some(item) => Err(KeriError::Config(format!(
            "{field} lists {item} more than once; each place must be a distinct key"
        ))),
        None => Ok(()),
    }
}

/// Serialize a SAD with its SAID filled in.
fn saidify(mut sad: SadValue) -> Result<(String, String), KeriError> {
    fix_version_string(&mut sad)?;
    let said = said::compute_said(&mut sad, "d", "E", SerializationKind::Json)?;
    let serder = Serder::new(SerializationKind::Json, sad)?;
    let raw = String::from_utf8(serder.raw().to_vec())
        .map_err(|e| KeriError::Config(format!("event is not UTF-8: {e}")))?;
    Ok((said, raw))
}

fn threshold_sad(t: &Threshold) -> SadValue {
    SadValue::from_json_value(&t.to_json_value())
}

/// Build an inception event.
///
/// # Errors
/// Returns [`KeriError`] if a key or digest does not decode, a key is not
/// transferable, or a threshold cannot be met.
pub fn incept(inception: &Inception) -> Result<PendingEvent, KeriError> {
    let next = digests(&inception.next)?;
    check_thresholds(
        &inception.keys,
        &inception.threshold,
        &next,
        &inception.next_threshold,
    )?;
    if inception.backer_threshold > inception.backers.len() {
        return Err(KeriError::Config(format!(
            "witness threshold {} exceeds {} witness(es)",
            inception.backer_threshold,
            inception.backers.len()
        )));
    }
    let sad = affinidi_keri_core::sad!({
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "",
        "i": "",
        "s": "0",
        "kt": threshold_sad(&inception.threshold),
        "k": inception.keys,
        "nt": threshold_sad(&inception.next_threshold),
        "n": next,
        "bt": inception.backer_threshold.to_string(),
        "b": inception.backers,
        "c": inception.config_traits,
        "a": []
    });
    let (said, raw) = saidify(sad)?;
    Ok(PendingEvent {
        said: said.clone(),
        ilk: "icp".into(),
        raw,
        requirement: Requirement {
            keys: inception.keys.clone(),
            thresholds: vec![inception.threshold.clone().into()],
        },
        signatures: BTreeMap::new(),
        next_state: ControllerState {
            prefix: said.clone(),
            sn: 0,
            last_said: said.clone(),
            establishment_sn: 0,
            establishment_said: said,
            keys: inception.keys.clone(),
            threshold: inception.threshold.clone().into(),
            next_digests: next,
            next_threshold: inception.next_threshold.clone().into(),
            backers: inception.backers.clone(),
            backer_threshold: inception.backer_threshold,
        },
    })
}

impl ControllerState {
    /// Build a rotation that installs `keys`, the successors the latest
    /// establishment event committed to, all of them and in that order.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the identifier is abandoned, `keys` are not
    /// exactly the committed successors, or a threshold cannot be met.
    pub fn rotate(&self, keys: &[String], rotation: &Rotation) -> Result<PendingEvent, KeriError> {
        if self.next_digests.is_empty() {
            return Err(KeriError::Config(format!(
                "identifier {} is abandoned: it committed to no next keys",
                self.prefix
            )));
        }
        if keys.len() != self.next_digests.len() {
            return Err(KeriError::Config(format!(
                "a rotation reveals all {} committed key(s), in order; got {}",
                self.next_digests.len(),
                keys.len()
            )));
        }
        for (i, (key, digest)) in keys.iter().zip(&self.next_digests).enumerate() {
            if NextKey::PublicKey(key.clone()).digest()? != *digest {
                return Err(KeriError::Config(format!(
                    "key {i} ({key}) is not the successor committed at that position"
                )));
            }
        }
        let next = digests(&rotation.next)?;
        check_thresholds(keys, &rotation.threshold, &next, &rotation.next_threshold)?;

        let mut backers = self.backers.clone();
        backers.retain(|b| !rotation.backers_remove.contains(b));
        for b in &rotation.backers_add {
            if !backers.contains(b) {
                backers.push(b.clone());
            }
        }
        let backer_threshold = rotation.backer_threshold.unwrap_or(self.backer_threshold);
        if backer_threshold > backers.len() {
            return Err(KeriError::Config(format!(
                "witness threshold {backer_threshold} exceeds {} witness(es)",
                backers.len()
            )));
        }

        let sn = self.sn + 1;
        let sad = affinidi_keri_core::sad!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": self.prefix,
            "s": format!("{sn:x}"),
            "p": self.last_said,
            "kt": threshold_sad(&rotation.threshold),
            "k": keys,
            "nt": threshold_sad(&rotation.next_threshold),
            "n": next,
            "bt": backer_threshold.to_string(),
            "br": rotation.backers_remove,
            "ba": rotation.backers_add,
            "c": [],
            "a": []
        });
        let (said, raw) = saidify(sad)?;
        Ok(PendingEvent {
            said: said.clone(),
            ilk: "rot".into(),
            raw,
            requirement: Requirement {
                keys: keys.to_vec(),
                // Its own kt, and the nt the prior event committed to: without
                // the second a rotation could lower its own bar.
                thresholds: vec![
                    rotation.threshold.clone().into(),
                    self.next_threshold.clone(),
                ],
            },
            signatures: BTreeMap::new(),
            next_state: ControllerState {
                prefix: self.prefix.clone(),
                sn,
                last_said: said.clone(),
                establishment_sn: sn,
                establishment_said: said,
                keys: keys.to_vec(),
                threshold: rotation.threshold.clone().into(),
                next_digests: next,
                next_threshold: rotation.next_threshold.clone().into(),
                backers,
                backer_threshold,
            },
        })
    }

    /// Build an interaction event anchoring `anchors`, signed by the current
    /// keys under the current threshold.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the event cannot be serialized.
    pub fn interact(&self, anchors: &[SadValue]) -> Result<PendingEvent, KeriError> {
        let sn = self.sn + 1;
        let sad = affinidi_keri_core::sad!({
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "",
            "i": self.prefix,
            "s": format!("{sn:x}"),
            "p": self.last_said,
            "a": anchors
        });
        let (said, raw) = saidify(sad)?;
        let mut next_state = self.clone();
        next_state.sn = sn;
        next_state.last_said = said.clone();
        Ok(PendingEvent {
            said,
            ilk: "ixn".into(),
            raw,
            requirement: Requirement {
                keys: self.keys.clone(),
                thresholds: vec![self.threshold.clone()],
            },
            signatures: BTreeMap::new(),
            next_state,
        })
    }
}
