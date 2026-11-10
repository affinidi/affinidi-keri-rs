//! Credential registries: which ACDCs an issuer has issued, and whether they
//! still stand.
//!
//! An ACDC an AID issues to itself and anchors in its own KEL (a
//! *designation*: `did:webs` aliases, key agreement keys, services) stands
//! until its issuer revokes it. Whether it stands is read from the
//! credential's registry, whose events the issuer's KEL anchors. This module
//! answers, for one issuer and one schema: which credentials of that schema
//! verify, and is each issued or revoked, optionally as of a KEL event
//! (`versionId`).
//!
//! Both registry versions are read:
//!
//! - **ACDC 1.x**: the credential names its registry with `ri`; the registry
//!   is a 1.x TEL (`vcp`, `iss`, `rev`/`brv`) whose events the KEL anchors by
//!   `{i, s, d}` seals; the credential carries the issuer's signature.
//! - **ACDC 2.x**: the credential names its registry with `rd`; the registry
//!   is a `rip` and a chain of blindable updates (`bup`), each anchored in the
//!   KEL. A credential is not signed: it is issued when the registry's latest
//!   non-vacuous update discloses `issued` for it. Every update from the
//!   latest back to the latest non-vacuous one must carry its disclosed state
//!   (`-a`, `BlindedStateQuadruples`). Non-blindable `upd` updates are not
//!   read (keripy refuses them).
//!
//! The rules follow keripy (`keri/acdc/regeventing.py`, `vet` and `vetBinds`,
//! b70986f), with one addition: **every registry event the issuer's KEL
//! anchors must be in the stream.** keripy checks that what is presented is
//! anchored, not that everything anchored is presented, so a stream that
//! leaves out a revocation would read as issued. Here a KEL seal that names a
//! registry event missing from the stream fails the whole read. A seal is
//! attributed to a registry by its shape: a 2.x transaction event seal
//! (`{s, d}`), or a 1.x seal (`{i, s, d}`) whose `i` is a registry or a
//! credential the stream shows. A bare digest seal (`{d}`) names nothing it
//! can be attributed to, so it is not checked.

pub mod write;

use affinidi_keri_crypto::{Diger, Verfer};

use crate::error::CoreError;
use crate::fields::check_acdc_fields;
use crate::kever::Kever;
use crate::key_state::KeyState;
use crate::parser::{Attachment, BlindedState, ParsedMessage, TransIdxSigGroup};
use crate::sad::SadValue;

/// Where in the issuer's KEL something is anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The anchoring key event's sequence number.
    pub sn: u64,
    /// The anchoring key event's SAID.
    pub said: String,
}

/// One accepted event of the issuer's KEL.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LoggedEvent {
    /// Sequence number.
    pub sn: u64,
    /// SAID.
    pub said: String,
    /// The event's seals (its `a` field).
    pub seals: Vec<SadValue>,
    /// The key state an establishment event installs; `None` for an
    /// interaction event.
    pub establishment: Option<KeyState>,
}

impl LoggedEvent {
    /// An event from a KEL the caller has already verified.
    pub fn new(
        sn: u64,
        said: String,
        seals: Vec<SadValue>,
        establishment: Option<KeyState>,
    ) -> Self {
        Self {
            sn,
            said,
            seals,
            establishment,
        }
    }
}

/// The issuer's verified KEL, as far as a read may see it.
#[derive(Debug, Clone)]
pub struct IssuerLog {
    prefix: String,
    events: Vec<LoggedEvent>,
    /// Interaction events a rotation superseded (P7): what only they anchor
    /// has not happened.
    superseded: Vec<LoggedEvent>,
    limit: Option<u64>,
}

/// Where a registry event stands relative to the KEL a read may see.
enum Anchoring {
    /// Anchored at or before the limit.
    Within(Anchor),
    /// Anchored, but only after the limit, or only in events a rotation
    /// superseded: it has not happened (yet).
    Later,
    /// Never anchored.
    Absent,
}

impl IssuerLog {
    /// An issuer log from events the caller has already verified, in KEL
    /// order.
    pub fn new(prefix: impl Into<String>, events: Vec<LoggedEvent>) -> Self {
        Self {
            prefix: prefix.into(),
            events,
            superseded: Vec::new(),
            limit: None,
        }
    }

    /// Record interaction events a rotation superseded. What only they anchor
    /// is read as not having happened, rather than as unanchored: a recovery
    /// takes the events it supersedes with it, and with them, say, a
    /// revocation a compromised key anchored (P7).
    pub fn with_superseded(mut self, superseded: Vec<LoggedEvent>) -> Self {
        self.superseded = superseded;
        self
    }

    /// Verify the issuer's KEL from a parsed stream and record it.
    ///
    /// Reads the stream's `icp`, `rot` and `ixn` events for `prefix`, in
    /// order, through [`Kever`]. A rotation that supersedes interaction events
    /// drops them from the log, with what they anchored. A delegated identifier is not supported here;
    /// a caller that verifies delegation itself builds the log with
    /// [`IssuerLog::new`].
    ///
    /// # Errors
    /// Returns [`CoreError`] if the KEL does not verify, or is delegated.
    pub fn replay(stream: &[ParsedMessage], prefix: &str) -> Result<Self, CoreError> {
        let mut kever: Option<Kever> = None;
        let mut events = Vec::new();
        let mut superseded = Vec::new();
        for msg in stream {
            if !is_keri(msg) || msg.serder.prefix().ok().as_deref() != Some(prefix) {
                continue;
            }
            let ilk = msg.serder.ilk()?;
            match (ilk.as_str(), kever.as_mut()) {
                ("icp", None) => {
                    let verfers = msg.serder.sad()["k"]
                        .as_array()
                        .ok_or_else(|| CoreError::MissingField("k".into()))?
                        .iter()
                        .map(|k| {
                            Verfer::from_qb64(k.as_str().unwrap_or_default())
                                .map_err(CoreError::Crypto)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    kever = Some(Kever::new(&msg.serder, msg.controller_sigs(), &verfers)?);
                }
                ("rot" | "ixn", Some(k)) => k.update(&msg.serder, msg.controller_sigs())?,
                ("dip" | "drt", _) => {
                    return Err(CoreError::Unsupported(
                        "IssuerLog::replay does not verify delegation; build the log with IssuerLog::new"
                            .into(),
                    ));
                }
                _ => continue,
            }
            let k = kever.as_ref().expect("set above");
            // A superseding rotation takes the log back to its own sequence
            // number: the interaction events it superseded, and whatever they
            // anchored, are no longer the issuer's (P7).
            let (kept, gone): (Vec<LoggedEvent>, Vec<LoggedEvent>) = events
                .into_iter()
                .partition(|e: &LoggedEvent| e.sn < k.sn());
            events = kept;
            superseded.extend(gone);
            events.push(LoggedEvent {
                sn: k.sn(),
                said: msg.serder.said()?,
                seals: msg
                    .serder
                    .sad()
                    .get("a")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or_default(),
                establishment: (ilk != "ixn").then(|| k.state().clone()),
            });
        }
        if events.is_empty() {
            return Err(CoreError::Validation(format!(
                "the stream holds no KEL for {prefix}"
            )));
        }
        Ok(Self::new(prefix, events).with_superseded(superseded))
    }

    /// Read as of the KEL event with sequence number `limit` (`versionId`):
    /// anything anchored after it has not happened yet.
    pub fn as_of(mut self, limit: Option<u64>) -> Self {
        self.limit = limit;
        self
    }

    /// The issuer's prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn visible(&self) -> impl Iterator<Item = &LoggedEvent> {
        self.events
            .iter()
            .filter(move |e| self.limit.is_none_or(|l| e.sn <= l))
    }

    /// Where the first seal matching `matches` is anchored.
    fn anchoring(&self, matches: impl Fn(&SadValue) -> bool) -> Anchoring {
        match self.events.iter().find(|e| e.seals.iter().any(&matches)) {
            Some(e) if self.limit.is_none_or(|l| e.sn <= l) => Anchoring::Within(Anchor {
                sn: e.sn,
                said: e.said.clone(),
            }),
            Some(_) => Anchoring::Later,
            None if self.superseded.iter().any(|e| e.seals.iter().any(&matches)) => {
                Anchoring::Later
            }
            None => Anchoring::Absent,
        }
    }

    /// The key state an establishment event installed, if the log holds it.
    fn key_state_at(&self, said: &str) -> Option<&KeyState> {
        self.events
            .iter()
            .find(|e| e.said == said)
            .and_then(|e| e.establishment.as_ref())
    }
}

/// Whether a credential stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// Issued and not revoked.
    Issued,
    /// Revoked by its issuer.
    Revoked,
}

/// A credential that verifies, with its registry status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Credential {
    /// The credential's SAID.
    pub said: String,
    /// The ACDC protocol major version (1 or 2).
    pub version: u8,
    /// The registry's SAID (`ri` in 1.x, `rd` in 2.x).
    pub registry: String,
    /// Where the issuer's KEL anchors the registry event that decides the
    /// status: the issuance or revocation (1.x), or the latest non-vacuous
    /// update (2.x).
    pub anchor: Anchor,
    /// The SAID of that registry event.
    pub event: String,
    /// Issued or revoked.
    pub status: Status,
    /// The credential itself.
    pub sad: SadValue,
}

/// What a read found.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Designations {
    /// Credentials of the schema that verify, issued or revoked.
    pub credentials: Vec<Credential>,
    /// Credentials of the schema that do not verify, and why. They
    /// contribute nothing.
    pub rejected: Vec<(String, String)>,
}

/// A fault in the stream or a registry that makes the read meaningless.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The KEL does not verify, or a message does not parse.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// The issuer's KEL anchors a registry event the stream does not carry.
    #[error(
        "the issuer's KEL anchors registry event {digest} at sn {sn}, but the stream does not carry it"
    )]
    MissingAnchoredEvent {
        /// The anchored event's SAID.
        digest: String,
        /// The anchoring KEL event's sequence number.
        sn: u64,
    },
    /// A registry event in the stream is not anchored in the issuer's KEL.
    #[error("registry event {said} is not anchored in the issuer's KEL")]
    UnanchoredEvent {
        /// The event's SAID.
        said: String,
    },
    /// A 2.x update between the latest and the latest non-vacuous one carries
    /// no disclosure of its state.
    #[error("registry update {said} carries no disclosure of its state")]
    UndisclosedUpdate {
        /// The update's SAID.
        said: String,
    },
    /// Two distinct anchored events at one position in a registry.
    #[error("registry {registry} has more than one anchored event at n {n}")]
    Duplicity {
        /// The registry's SAID.
        registry: String,
        /// The contested sequence number.
        n: u64,
    },
    /// A registry's events do not form a chain.
    #[error("registry {registry} is broken: {reason}")]
    Chain {
        /// The registry's SAID.
        registry: String,
        /// What is wrong.
        reason: String,
    },
    /// A disclosed state outside the vocabulary (`issued`, `revoked`).
    #[error(
        "registry update {said} discloses state {state:?}, which is neither issued nor revoked"
    )]
    UnknownState {
        /// The update's SAID.
        said: String,
        /// The disclosed state.
        state: String,
    },
}

/// The credentials of `schema` that the log's issuer issued, each with its
/// status, as of the log's limit.
///
/// # Errors
/// Returns [`RegistryError`] for a fault that makes the read meaningless: a
/// registry event the KEL anchors but the stream leaves out, an unanchored,
/// duplicitous or broken registry, an undisclosed update, or a state outside
/// the vocabulary. A credential that merely does not verify is listed in
/// [`Designations::rejected`] instead.
pub fn designations(
    stream: &[ParsedMessage],
    log: &IssuerLog,
    schema: &str,
) -> Result<Designations, RegistryError> {
    check_anchored_events_present(stream, log)?;

    let mut out = Designations::default();
    for msg in stream.iter().filter(|m| is_credential(m)) {
        let sad = msg.serder.sad();
        if sad.get("i").and_then(|v| v.as_str()) != Some(log.prefix()) {
            continue;
        }
        if schema_said(sad).as_deref() != Some(schema) {
            continue;
        }
        let said = sad
            .get("d")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let found = match protocol_major(msg) {
            Some(1) => v1::credential(stream, log, msg)?,
            Some(2) => v2::credential(stream, log, msg)?,
            other => Err(format!("ACDC protocol version {other:?} is not supported")),
        };
        match found {
            Ok(Some(credential)) => out.credentials.push(credential),
            Ok(None) => {} // not issued, as of the limit
            Err(reason) => out.rejected.push((said, reason)),
        }
    }
    Ok(out)
}

/// A per-credential outcome: `Ok(None)` when it was not (yet) issued,
/// `Err` with a reason when it does not verify.
type Outcome = Result<Option<Credential>, String>;

fn is_keri(msg: &ParsedMessage) -> bool {
    msg.serder
        .version
        .as_ref()
        .is_some_and(|v| v.protocol == "KERI")
}

fn is_acdc(msg: &ParsedMessage) -> bool {
    msg.serder
        .version
        .as_ref()
        .is_some_and(|v| v.protocol == "ACDC")
}

fn protocol_major(msg: &ParsedMessage) -> Option<u8> {
    msg.serder.version.as_ref().map(|v| v.major)
}

/// A credential message: a bare ACDC (no `t`) or a 2.x `acm`.
fn is_credential(msg: &ParsedMessage) -> bool {
    is_acdc(msg)
        && match msg.serder.sad().get("t").and_then(|t| t.as_str()) {
            None => true,
            Some(t) => t == "acm",
        }
}

fn ilk_of(msg: &ParsedMessage) -> Option<&str> {
    msg.serder.sad().get("t").and_then(|t| t.as_str())
}

fn said_of(msg: &ParsedMessage) -> Option<&str> {
    msg.serder.sad().get("d").and_then(|t| t.as_str())
}

/// The credential's schema SAID: `s` itself, or an embedded schema's `$id`.
fn schema_said(sad: &SadValue) -> Option<String> {
    match sad.get("s")? {
        SadValue::String(s) => Some(s.clone()),
        s @ SadValue::Object(_) => s.get("$id").and_then(|v| v.as_str()).map(str::to_string),
        _ => None,
    }
}

/// Every registry event the issuer's KEL anchors (as far as the read sees)
/// must be in the stream.
fn check_anchored_events_present(
    stream: &[ParsedMessage],
    log: &IssuerLog,
) -> Result<(), RegistryError> {
    let present = |d: &str| stream.iter().any(|m| said_of(m) == Some(d));
    // 1.x registries and credentials the stream shows: a seal naming one of
    // them as `i` anchors one of its registry events.
    let v1_subjects: Vec<&str> = stream
        .iter()
        .filter(|m| is_keri(m) && matches!(ilk_of(m), Some("vcp" | "iss" | "bis")))
        .flat_map(|m| {
            let sad = m.serder.sad();
            [said_of(m), sad.get("i").and_then(|v| v.as_str())]
        })
        .flatten()
        .collect();

    for event in log.visible() {
        for seal in &event.seals {
            let Some(obj) = seal.as_object() else {
                continue;
            };
            let Some(d) = obj.get("d").and_then(|v| v.as_str()) else {
                continue;
            };
            let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
            let attributable = match keys.as_slice() {
                ["s", "d"] => true, // a 2.x transaction event seal
                ["i", "s", "d"] => obj
                    .get("i")
                    .and_then(|v| v.as_str())
                    .is_some_and(|i| v1_subjects.contains(&i)),
                _ => false,
            };
            if attributable && !present(d) {
                return Err(RegistryError::MissingAnchoredEvent {
                    digest: d.to_string(),
                    sn: event.sn,
                });
            }
        }
    }
    Ok(())
}

/// The digest code of a qb64 SAID, for recomputing it.
fn digest_code(said: &str) -> Result<&'static str, String> {
    match said.chars().next() {
        Some('E') => Ok("E"),
        _ => Err(format!("{said} is not a Blake3-256 SAID")),
    }
}

/// The SAID `label` would have over `sad` as given.
fn recompute(sad: &SadValue, label: &str, code: &str) -> Result<String, String> {
    let mut copy = sad.clone();
    crate::said::compute_said(
        &mut copy,
        label,
        code,
        crate::version::SerializationKind::Json,
    )
    .map_err(|e| format!("cannot compute the SAID: {e}"))
}

fn verify_plain_said(msg: &ParsedMessage) -> Result<String, String> {
    let said = said_of(msg).ok_or("the message has no SAID")?;
    let computed = recompute(msg.serder.sad(), "d", digest_code(said)?)?;
    if computed != said {
        return Err(format!(
            "the message's SAID is {said}, but its content gives {computed}"
        ));
    }
    Ok(said.to_string())
}

mod v1 {
    //! ACDC 1.x: signed credentials in 1.x TELs (`vcp`, `iss`, `rev`/`brv`).

    use super::*;

    pub(super) fn credential(
        stream: &[ParsedMessage],
        log: &IssuerLog,
        msg: &ParsedMessage,
    ) -> Result<Outcome, RegistryError> {
        let sad = msg.serder.sad();
        if let Err(e) = check_acdc_fields(sad, 1, None) {
            return Ok(Err(e.to_string()));
        }
        let said = match verify_plain_said(msg) {
            Ok(s) => s,
            Err(e) => return Ok(Err(e)),
        };
        if let Err(e) = verify_signed_by(log, msg) {
            return Ok(Err(e));
        }
        let Some(registry) = sad.get("ri").and_then(|v| v.as_str()) else {
            return Ok(Err("the credential names no registry (`ri`)".into()));
        };

        // The registry was incepted by this issuer, and the KEL anchors it.
        let Some(vcp) = stream
            .iter()
            .find(|m| is_keri(m) && ilk_of(m) == Some("vcp") && said_of(m) == Some(registry))
        else {
            return Ok(Err(format!(
                "registry {registry} has no inception event in the stream"
            )));
        };
        if vcp.serder.sad().get("ii").and_then(|v| v.as_str()) != Some(log.prefix()) {
            return Ok(Err(format!(
                "registry {registry} was not incepted by {}",
                log.prefix()
            )));
        }
        match anchored_v1(log, registry, 0, registry) {
            Anchoring::Within(_) => {}
            Anchoring::Later => return Ok(Ok(None)),
            Anchoring::Absent => {
                return Err(RegistryError::UnanchoredEvent {
                    said: registry.into(),
                });
            }
        }

        // It was issued in that registry, and the KEL anchors the issuance.
        let Some(iss) = stream.iter().find(|m| {
            is_keri(m)
                && ilk_of(m) == Some("iss")
                && m.serder.sad().get("i").and_then(|v| v.as_str()) == Some(&said)
        }) else {
            return Ok(Err(format!("no issuance event for credential {said}")));
        };
        if iss.serder.sad().get("ri").and_then(|v| v.as_str()) != Some(registry) {
            return Ok(Err(format!(
                "credential {said} was issued in another registry than it names"
            )));
        }
        let iss_said = said_of(iss).unwrap_or_default().to_string();
        let issued = match anchored_v1(log, &said, 0, &iss_said) {
            Anchoring::Within(a) => a,
            Anchoring::Later => return Ok(Ok(None)),
            Anchoring::Absent => return Err(RegistryError::UnanchoredEvent { said: iss_said }),
        };

        // Revoked once the KEL anchors a revocation.
        for rev in stream.iter().filter(|m| {
            is_keri(m)
                && matches!(ilk_of(m), Some("rev" | "brv"))
                && m.serder.sad().get("i").and_then(|v| v.as_str()) == Some(&said)
        }) {
            let rev_said = said_of(rev).unwrap_or_default().to_string();
            let sn = rev
                .serder
                .sad()
                .get("s")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(1);
            match anchored_v1(log, &said, sn, &rev_said) {
                Anchoring::Within(anchor) => {
                    return Ok(Ok(Some(Credential {
                        said,
                        version: 1,
                        registry: registry.into(),
                        anchor,
                        event: rev_said,
                        status: Status::Revoked,
                        sad: sad.clone(),
                    })));
                }
                Anchoring::Later => {}
                Anchoring::Absent => return Err(RegistryError::UnanchoredEvent { said: rev_said }),
            }
        }

        Ok(Ok(Some(Credential {
            said,
            version: 1,
            registry: registry.into(),
            anchor: issued,
            event: iss_said,
            status: Status::Issued,
            sad: sad.clone(),
        })))
    }

    /// A 1.x TEL event is anchored by a `{i, s, d}` seal.
    fn anchored_v1(log: &IssuerLog, i: &str, sn: u64, d: &str) -> Anchoring {
        let s = format!("{sn:x}");
        log.anchoring(|seal| {
            seal.get("i").and_then(|v| v.as_str()) == Some(i)
                && seal.get("s").and_then(|v| v.as_str()) == Some(s.as_str())
                && seal.get("d").and_then(|v| v.as_str()) == Some(d)
        })
    }

    /// The credential carries the issuer's signatures, under the key state of
    /// the establishment event they name and its threshold.
    fn verify_signed_by(log: &IssuerLog, msg: &ParsedMessage) -> Result<(), String> {
        let group: &TransIdxSigGroup = msg
            .attachments
            .iter()
            .find_map(|a| match a {
                Attachment::TransIdxSigGroups(groups) => {
                    groups.iter().find(|g| g.prefix == log.prefix())
                }
                _ => None,
            })
            .ok_or_else(|| {
                format!(
                    "the credential carries no signature group from {}",
                    log.prefix()
                )
            })?;
        let state = log.key_state_at(&group.said).ok_or_else(|| {
            format!(
                "the signature group names establishment event {}, which the KEL does not hold",
                group.said
            )
        })?;
        // keripy finds the establishment event by its sequence number and then
        // compares the SAID; a group naming the wrong one verifies nowhere.
        let sn = crate::parser::number_value(&group.sn).map_err(|e| e.to_string())?;
        if sn != state.sn {
            return Err(format!(
                "the signature group names establishment event {} at sn {sn}, but it is at sn {}",
                group.said, state.sn
            ));
        }
        let mut indices = Vec::new();
        for sig in &group.sigs {
            let key = state
                .keys
                .get(sig.index())
                .ok_or_else(|| format!("signature index {} is out of range", sig.index()))?;
            let verfer = Verfer::from_qb64(key).map_err(|e| e.to_string())?;
            if verfer
                .verify(msg.serder.raw(), sig.raw())
                .map_err(|e| e.to_string())?
                && !indices.contains(&sig.index())
            {
                indices.push(sig.index());
            }
        }
        if !state.threshold.is_satisfied(&indices, state.keys.len()) {
            return Err("the credential's signatures do not meet the signing threshold".into());
        }
        Ok(())
    }
}

mod v2 {
    //! ACDC 2.x: unsigned credentials bound to `rip` + `bup` registries.

    use super::*;

    pub(super) fn credential(
        stream: &[ParsedMessage],
        log: &IssuerLog,
        msg: &ParsedMessage,
    ) -> Result<Outcome, RegistryError> {
        let sad = msg.serder.sad();
        let ilk = ilk_of(msg);
        if let Err(e) = check_acdc_fields(sad, 2, ilk) {
            return Ok(Err(e.to_string()));
        }
        let said = match verify_compact_said(sad) {
            Ok(s) => s,
            Err(e) => return Ok(Err(e)),
        };
        let Some(registry) = sad.get("rd").and_then(|v| v.as_str()) else {
            return Ok(Err("the credential names no registry (`rd`)".into()));
        };

        let Some(rip) = stream
            .iter()
            .find(|m| is_acdc(m) && ilk_of(m) == Some("rip") && said_of(m) == Some(registry))
        else {
            return Ok(Err(format!(
                "registry {registry} has no inception event in the stream"
            )));
        };
        if let Err(e) = registry_event(rip, "rip") {
            return Ok(Err(e));
        }
        let rsad = rip.serder.sad();
        if rsad.get("i").and_then(|v| v.as_str()) != Some(log.prefix()) {
            return Ok(Err(format!(
                "registry {registry} was not incepted by {}",
                log.prefix()
            )));
        }
        if rsad.get("n").and_then(|v| v.as_str()) != Some("0") {
            return Err(RegistryError::Chain {
                registry: registry.into(),
                reason: "its inception is not at n 0".into(),
            });
        }
        match anchored_v2(log, registry) {
            Anchoring::Within(_) => {}
            Anchoring::Later => return Ok(Ok(None)),
            Anchoring::Absent => {
                return Err(RegistryError::UnanchoredEvent {
                    said: registry.into(),
                });
            }
        }

        let chain = chain(stream, log, registry)?;

        // From the latest update back, the first non-vacuous one decides.
        for (update, anchor) in chain.iter().rev() {
            let b = update
                .serder
                .sad()
                .get("b")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let update_said = said_of(update).unwrap_or_default().to_string();
            let disclosed: Vec<&BlindedState> = update
                .attachments
                .iter()
                .filter_map(|a| match a {
                    Attachment::BlindedStates(states) => Some(states.iter()),
                    _ => None,
                })
                .flatten()
                .filter(|s| s.blid == b)
                .collect();
            let [state] = disclosed.as_slice() else {
                return Err(RegistryError::UndisclosedUpdate { said: update_said });
            };
            verify_blid(state).map_err(|reason| RegistryError::Chain {
                registry: registry.into(),
                reason: format!("update {update_said}: {reason}"),
            })?;
            let (td, ts) = (empty_or(&state.acdc), label_text(&state.state));
            if td.is_none() && ts.as_deref() == Some("") {
                continue; // vacuous: a placeholder
            }
            let status = match ts.as_deref() {
                Some("issued") => Status::Issued,
                Some("revoked") => Status::Revoked,
                _ => {
                    return Err(RegistryError::UnknownState {
                        said: update_said,
                        state: state.state.clone(),
                    });
                }
            };
            if td.as_deref() != Some(said.as_str()) {
                return Ok(Err(format!(
                    "registry {registry}'s latest state binds {}, not this credential",
                    td.unwrap_or_default()
                )));
            }
            return Ok(Ok(Some(Credential {
                said,
                version: 2,
                registry: registry.into(),
                anchor: anchor.clone(),
                event: update_said,
                status,
                sad: sad.clone(),
            })));
        }
        Ok(Ok(None)) // no non-vacuous update yet: not issued
    }

    /// The state to continue `registry` from: its inception verified and
    /// anchored, then every update the read may see, in order.
    pub(super) fn head(
        stream: &[ParsedMessage],
        log: &IssuerLog,
        registry: &str,
    ) -> Result<write::RegistryState, RegistryError> {
        let broken = |reason: String| RegistryError::Chain {
            registry: registry.into(),
            reason,
        };
        let rip = stream
            .iter()
            .find(|m| is_acdc(m) && ilk_of(m) == Some("rip") && said_of(m) == Some(registry))
            .ok_or_else(|| broken("it has no inception event in the stream".into()))?;
        registry_event(rip, "rip").map_err(broken)?;
        let rsad = rip.serder.sad();
        if rsad.get("i").and_then(|v| v.as_str()) != Some(log.prefix()) {
            return Err(broken(format!("it was not incepted by {}", log.prefix())));
        }
        if rsad.get("n").and_then(|v| v.as_str()) != Some("0") {
            return Err(broken("its inception is not at n 0".into()));
        }
        match anchored_v2(log, registry) {
            Anchoring::Within(_) => {}
            Anchoring::Later => {
                return Err(broken("it is not incepted yet, as of the limit".into()));
            }
            Anchoring::Absent => {
                return Err(RegistryError::UnanchoredEvent {
                    said: registry.into(),
                });
            }
        }
        let chain = chain(stream, log, registry)?;
        let (head, n) = chain.last().map_or((registry.to_string(), 0), |(m, _)| {
            (
                said_of(m).unwrap_or_default().to_string(),
                chain.len() as u64,
            )
        });
        Ok(write::RegistryState {
            issuer: log.prefix().into(),
            registry: registry.into(),
            head,
            n,
        })
    }

    /// A 2.x registry event's fields and SAID.
    fn registry_event(msg: &ParsedMessage, ilk: &str) -> Result<(), String> {
        check_acdc_fields(msg.serder.sad(), 2, Some(ilk)).map_err(|e| e.to_string())?;
        verify_plain_said(msg)?;
        Ok(())
    }

    /// A 2.x registry event is anchored by any seal carrying its SAID as `d`,
    /// or by its SAID alone (keripy `sealDigests`).
    fn anchored_v2(log: &IssuerLog, said: &str) -> Anchoring {
        log.anchoring(|seal| match seal {
            SadValue::String(s) => s == said,
            other => other.get("d").and_then(|v| v.as_str()) == Some(said),
        })
    }

    /// The registry's updates the read may see, in order, each with its
    /// anchor: `n` from 1 up, each naming the previous as `p`, one per `n`.
    fn chain<'a>(
        stream: &'a [ParsedMessage],
        log: &IssuerLog,
        registry: &str,
    ) -> Result<Vec<(&'a ParsedMessage, Anchor)>, RegistryError> {
        let broken = |reason: String| RegistryError::Chain {
            registry: registry.into(),
            reason,
        };
        let mut visible = Vec::new();
        for m in stream.iter().filter(|m| {
            is_acdc(m)
                && ilk_of(m) == Some("bup")
                && m.serder.sad().get("rd").and_then(|v| v.as_str()) == Some(registry)
        }) {
            registry_event(m, "bup").map_err(broken)?;
            let said = said_of(m).unwrap_or_default().to_string();
            let n = m
                .serder
                .sad()
                .get("n")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or_else(|| broken(format!("update {said} has no hex sequence number")))?;
            if n == 0 {
                return Err(broken(format!(
                    "update {said} is at n 0, which is the inception's"
                )));
            }
            match anchored_v2(log, &said) {
                Anchoring::Within(a) => visible.push((n, m, a)),
                Anchoring::Later => {}
                Anchoring::Absent => return Err(RegistryError::UnanchoredEvent { said }),
            }
        }
        visible.sort_by_key(|(n, ..)| *n);

        let mut out: Vec<(&ParsedMessage, Anchor)> = Vec::new();
        let mut prior = registry.to_string();
        for (expect, group) in (1u64..).zip(visible.chunk_by(|a, b| a.0 == b.0)) {
            let n = group[0].0;
            if n != expect {
                return Err(broken(format!("no update at n {expect}, but one at n {n}")));
            }
            let mut saids: Vec<&str> = group.iter().filter_map(|(_, m, _)| said_of(m)).collect();
            saids.dedup();
            if saids.len() > 1 {
                return Err(RegistryError::Duplicity {
                    registry: registry.into(),
                    n,
                });
            }
            let (_, m, a) = &group[0];
            if m.serder.sad().get("p").and_then(|v| v.as_str()) != Some(prior.as_str()) {
                return Err(broken(format!(
                    "the update at n {n} does not name the one before it"
                )));
            }
            prior = said_of(m).unwrap_or_default().to_string();
            out.push((m, a.clone()));
        }
        Ok(out)
    }

    /// A disclosed state proves something only if it reproduces its BLID:
    /// the SAID of its four fields concatenated, the BLID dummied.
    fn verify_blid(state: &BlindedState) -> Result<(), String> {
        let code = digest_code(&state.blid)?;
        let text = format!(
            "{}{}{}{}",
            "#".repeat(state.blid.len()),
            state.uuid,
            state.acdc,
            state.state
        );
        let computed = Diger::from_data(code, text.as_bytes())
            .and_then(|d| d.qb64())
            .map_err(|e| e.to_string())?;
        if computed != state.blid {
            return Err(format!(
                "its disclosed state does not reproduce its BLID {}",
                state.blid
            ));
        }
        Ok(())
    }

    fn empty_or(qb64: &str) -> Option<String> {
        (qb64 != "1AAP").then(|| qb64.to_string())
    }

    /// The text of a CESR label: empty, or a fixed-size tag.
    fn label_text(qb64: &str) -> Option<String> {
        let (hs, xs) = match qb64 {
            "1AAP" => return Some(String::new()),
            q if q.starts_with("0J") || q.starts_with("0L") => (2, 1),
            q if q.starts_with("0K") || q.starts_with("0M") => (2, 0),
            q if q.starts_with('X') || q.starts_with('Y') => (1, 0),
            q if q.starts_with("1AAF") || q.starts_with("1AAN") => (4, 0),
            _ => return None,
        };
        qb64.get(hs + xs..).map(str::to_string)
    }

    /// An ACDC 2.x SAID is computed over its most compact form: each
    /// expanded section replaced by its own SAID, and the version string
    /// sized for that form (keripy `SerderACDC._compute`).
    fn verify_compact_said(sad: &SadValue) -> Result<String, String> {
        let said = sad
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or("the credential has no SAID")?;
        let code = digest_code(said)?;
        let mut compact = sad.clone();
        for label in ["s", "a", "e", "r"] {
            let Some(section) = compact.get(label) else {
                continue;
            };
            if !section.is_object() {
                continue;
            }
            let section_said = if label == "s" {
                recompute(section, "$id", code)?
            } else {
                compact_section(section, code)?
            };
            compact.insert(label, SadValue::String(section_said));
        }
        if compact.get("A").is_some_and(|a| !a.is_string()) {
            return Err("an expanded aggregate section (`A`) is not supported".into());
        }

        // Size the version string for the compact form, then compute.
        compact.insert("d", SadValue::String("#".repeat(said.len())));
        let size = serde_json::to_vec(&compact)
            .map_err(|e| e.to_string())?
            .len();
        let vs = compact
            .get("v")
            .and_then(|v| v.as_str())
            .ok_or("the credential has no version")?;
        let mut version = crate::version::Version::parse_str(vs).map_err(|e| e.to_string())?;
        version.size = size;
        compact.insert("v", SadValue::String(version.to_version_string()));
        let computed = recompute(&compact, "d", code)?;
        if computed != said {
            return Err(format!(
                "the credential's SAID is {said}, but its compact form gives {computed}"
            ));
        }
        Ok(said.to_string())
    }

    /// A section's SAID over its most compact form: each nested block that
    /// has a `d` replaced by its own SAID, innermost first.
    fn compact_section(section: &SadValue, code: &str) -> Result<String, String> {
        let mut copy = section.clone();
        if let Some(obj) = copy.as_object_mut() {
            for value in obj.values_mut() {
                if value.is_object() && value.get("d").is_some() {
                    *value = SadValue::String(compact_section(value, code)?);
                }
            }
        }
        recompute(&copy, "d", code)
    }
}
