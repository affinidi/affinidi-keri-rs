//! Hab: single identifier management.
//!
//! A Hab (habitat) wraps the key material and event state for one KERI
//! identifier, providing high-level operations for inception, rotation,
//! interaction, and receipt generation.

use affinidi_cesr::Counter;
use affinidi_keri_core::composer::counter_code_for;
use affinidi_keri_core::counter_table::GroupKind;
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_crypto::{Cigar, Diger, Salter, Signer};
use affinidi_keri_db::KeriStore;
use serde::{Deserialize, Serialize};

use crate::config::{InceptionConfig, RotationConfig};
use crate::error::KeriError;

/// A single KERI identifier manager.
///
/// Holds the signing keys, next keys, and event state for one AID.
pub struct Hab {
    /// Human-readable name for this identifier.
    name: String,
    /// The identifier prefix (qb64).
    prefix: String,
    /// Current signing keys.
    signers: Vec<Signer>,
    /// Pre-rotated next signing keys.
    next_signers: Vec<Signer>,
    /// The Salter used for deterministic key derivation.
    salter: Salter,
    /// Whether this identifier is transferable.
    transferable: bool,
    /// The signing algorithm code.
    code: String,
    /// The SAID of the latest event.
    last_said: String,
    /// The current sequence number.
    sn: u64,
    /// Counter tracking how many key generations have been derived.
    key_gen: usize,
    /// Derivation path index of the current signing keys.
    ///
    /// Recorded rather than computed from `key_gen`, because the relationship
    /// is not uniform: after inception the current keys are at `key_gen - 2`,
    /// and after any rotation at `key_gen - 3`, since `rotate` advances the
    /// counter by two and leaves one index unused. Only the *next* keys are
    /// always at `key_gen - 1`. Deriving these from the counter is how a
    /// resumed identifier would silently sign with the wrong keys.
    signer_gen: usize,
    /// Derivation path index of the pre-rotated next keys.
    next_gen: usize,
    /// Current backer (witness) threshold.
    backer_threshold: usize,
    /// Current backer (witness) prefixes.
    backers: Vec<String>,
}

/// Fix the version string in a SAD so the embedded size matches the actual
/// serialized size before SAID computation.
///
/// The SAID field (`d`) will be 44 chars in the final form (Blake3-256 qb64).
/// We temporarily set `d` (and `i` for self-addressing inception) to 44-char
/// placeholders, serialize to compute the correct size, update `v`, then
/// restore the original values so `compute_said` can run normally.
fn fix_version_string(sad: &mut serde_json::Value) -> Result<(), KeriError> {
    let placeholder = "#".repeat(44); // Blake3-256 qb64 length
    let is_self_addressing = sad.get("d") == sad.get("i");

    // Save originals
    let orig_d = sad["d"].clone();
    let orig_i = sad["i"].clone();

    // Set placeholders to compute correct size
    sad["d"] = serde_json::Value::String(placeholder.clone());
    if is_self_addressing {
        sad["i"] = serde_json::Value::String(placeholder);
    }

    let temp_raw = serde_json::to_vec(sad)
        .map_err(|e| KeriError::Core(affinidi_keri_core::CoreError::Json(e)))?;
    sad["v"] = serde_json::Value::String(format!("KERI10JSON{:06x}_", temp_raw.len()));

    // Restore originals for compute_said
    sad["d"] = orig_d;
    sad["i"] = orig_i;

    Ok(())
}

/// Everything needed to resume signing for an identifier, **except the salt**.
///
/// `Hab` derives its keys deterministically from a [`Salter`], so the only
/// secret worth protecting is the salt — every key, current and pre-rotated,
/// is reproducible from it plus the generation indices recorded here. Keeping
/// the salt out of this type is deliberate: it can then be persisted anywhere
/// the key event log itself could go, while the salt lives wherever the
/// application keeps secrets.
///
/// Without this, an identifier could not be resumed at all. The key event log
/// alone is not enough to sign the next event: the pre-rotated keys are
/// committed to by digest, so they cannot be recovered from the log, and a
/// process that lost them could never rotate again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HabState {
    /// Human-readable name.
    pub name: String,
    /// The identifier prefix (qb64).
    pub prefix: String,
    /// Signing algorithm code.
    pub code: String,
    /// Whether the identifier is transferable.
    pub transferable: bool,
    /// Derivation path index of the current signing keys.
    pub signer_gen: usize,
    /// How many current signing keys there are.
    pub signer_count: usize,
    /// Derivation path index of the pre-rotated next keys.
    pub next_gen: usize,
    /// How many pre-rotated next keys there are.
    pub next_count: usize,
    /// The internal generation counter, preserved verbatim so a resumed
    /// identifier keeps deriving the same paths a continuous one would.
    pub key_gen: usize,
    /// SAID of the latest event.
    pub last_said: String,
    /// Current sequence number.
    pub sn: u64,
    /// Witness threshold.
    pub backer_threshold: usize,
    /// Witness prefixes.
    pub backers: Vec<String>,
}

/// A signed event, before anything has been persisted.
///
/// Returned by the `*_event` constructors for callers that store the key event
/// log somewhere other than a [`KeriStore`] — a `did:webs` `keri.cesr`
/// artifact, for instance.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedEvent {
    /// SAID of the event.
    pub said: String,
    /// The serialized event body, without attachments.
    pub raw: Vec<u8>,
    /// The attached indexed signatures, qb64.
    pub signatures: Vec<u8>,
    /// Body and attachments together, as they belong in a CESR stream.
    pub composed: Vec<u8>,
}

impl Hab {
    /// Create a new identifier via inception.
    ///
    /// Generates signing keys and next keys, builds the inception event,
    /// computes its SAID, signs it, stores everything in the database,
    /// and returns the Hab along with the composed message bytes.
    pub fn incept(
        name: &str,
        config: &InceptionConfig,
        store: &dyn KeriStore,
    ) -> Result<(Self, Vec<u8>), KeriError> {
        let (hab, event) = Self::incept_inner(name, config, Some(store))?;
        Ok((hab, event.composed))
    }

    /// Incept without a store, returning the signed event for the caller to
    /// keep wherever the key event log lives.
    ///
    /// Pair with [`Hab::state`] and a safe home for the salt: those two are
    /// everything needed to [`resume`](Hab::resume) later.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the event cannot be built or signed.
    pub fn incept_event(
        name: &str,
        config: &InceptionConfig,
    ) -> Result<(Self, SignedEvent), KeriError> {
        Self::incept_inner(name, config, None)
    }

    fn incept_inner(
        name: &str,
        config: &InceptionConfig,
        store: Option<&dyn KeriStore>,
    ) -> Result<(Self, SignedEvent), KeriError> {
        // Build salter from config or generate random
        let salter = if let Some(ref salt) = config.salt {
            Salter::new("0A", salt.clone())?
        } else {
            Salter::new_random()?
        };

        // Derive current signing keys
        let mut signers = Vec::with_capacity(config.count);
        for i in 0..config.count {
            let path = format!("0.{i}");
            let signer = salter.signer(&config.code, &path, "low", config.transferable)?;
            signers.push(signer);
        }

        // Derive next signing keys
        let mut next_signers = Vec::with_capacity(config.next_count);
        for i in 0..config.next_count {
            let path = format!("1.{i}");
            let signer = salter.signer(&config.code, &path, "low", config.transferable)?;
            next_signers.push(signer);
        }

        // Collect current key qb64 strings
        let keys: Vec<String> = signers
            .iter()
            .map(|s| s.verfer().qb64())
            .collect::<Result<Vec<_>, _>>()?;

        // Compute next key digests (Blake3-256)
        let next_key_digests: Vec<String> = next_signers
            .iter()
            .map(|s| {
                // Commit to the qb64 form of the next key, matching keripy.
                let diger = Diger::from_data("E", s.verfer().qb64()?.as_bytes())?;
                diger.qb64().map_err(KeriError::Crypto)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Build inception SAD with proper field ordering
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": config.threshold.to_string(),
            "k": keys,
            "nt": config.next_threshold.to_string(),
            "n": next_key_digests,
            "bt": config.backer_threshold.to_string(),
            "b": config.backers,
            "c": config.config_traits,
            "a": []
        });

        // Fix version string size before computing SAID
        fix_version_string(&mut sad)?;

        // Compute SAID (fills d and i for self-addressing)
        let computed_said = said::compute_said(&mut sad, "d", "E", SerializationKind::Json)?;

        // Create Serder from the SAD
        let serder = Serder::new(SerializationKind::Json, sad)?;

        // Sign the event with all current signers (indexed signatures)
        let mut sig_bytes = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let siger = signer.sign_indexed(serder.raw(), i, true)?;
            let qb64 = siger.qb64()?;
            sig_bytes.extend_from_slice(qb64.as_bytes());
        }

        // Build counter for controller indexed signatures. The code comes
        // from the event's own protocol version so that composing and parsing
        // cannot drift apart.
        let code = counter_code_for(&serder, GroupKind::ControllerIdxSigs)?;
        let counter = Counter::new(code, signers.len())?;
        let counter_qb64 = counter.qb64()?;

        // Compose the full message: event + counter + signatures
        let mut composed = Vec::new();
        composed.extend_from_slice(serder.raw());
        composed.extend_from_slice(counter_qb64.as_bytes());
        composed.extend_from_slice(&sig_bytes);

        let prefix = computed_said.clone();

        // Store event, KEL, first-seen, signatures, and hab metadata in one transaction
        // The full resumable state, so a store-backed identifier can be picked
        // up again later. It deliberately excludes the salt: that belongs
        // wherever the application keeps secrets, not next to the key event
        // log. Previously only {name, prefix, transferable, code} was written,
        // which is not enough to sign anything.
        let hab_data = serde_json::json!({
            "name": name,
            "prefix": prefix,
            "code": config.code,
            "transferable": config.transferable,
            "signer_gen": 0,
            "signer_count": config.count,
            "next_gen": 1,
            "next_count": config.next_count,
            "key_gen": 2,
            "last_said": computed_said,
            "sn": 0,
            "backer_threshold": config.backer_threshold,
            "backers": config.backers,
        });
        let hab_bytes =
            serde_json::to_vec(&hab_data).map_err(|e| KeriError::Config(e.to_string()))?;
        if let Some(store) = store {
            store.store_event_with_hab(
                &computed_said,
                serder.raw(),
                &prefix,
                0,
                Some(&sig_bytes),
                name,
                &hab_bytes,
            )?;
        }

        let hab = Hab {
            name: name.to_string(),
            prefix,
            signers,
            next_signers,
            salter,
            transferable: config.transferable,
            code: config.code.clone(),
            last_said: computed_said.clone(),
            sn: 0,
            key_gen: 2, // gen 0 = current, gen 1 = next
            signer_gen: 0,
            next_gen: 1,
            backer_threshold: config.backer_threshold,
            backers: config.backers.clone(),
        };

        Ok((
            hab,
            SignedEvent {
                said: computed_said,
                raw: serder.raw().to_vec(),
                signatures: sig_bytes,
                composed,
            },
        ))
    }

    /// Rotate the identifier's keys.
    ///
    /// Generates new signing keys and next keys, builds the rotation event,
    /// signs it with the CURRENT signers, updates internal state, stores
    /// everything, and returns the composed message.
    pub fn rotate(
        &mut self,
        config: &RotationConfig,
        store: &dyn KeriStore,
    ) -> Result<Vec<u8>, KeriError> {
        self.rotate_inner(config, Some(store)).map(|e| e.composed)
    }

    /// Rotate without a store, returning the signed event.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the identifier is not transferable, or the
    /// event cannot be built or signed.
    pub fn rotate_event(&mut self, config: &RotationConfig) -> Result<SignedEvent, KeriError> {
        self.rotate_inner(config, None)
    }

    fn rotate_inner(
        &mut self,
        config: &RotationConfig,
        store: Option<&dyn KeriStore>,
    ) -> Result<SignedEvent, KeriError> {
        if !self.transferable {
            return Err(KeriError::Config(
                "cannot rotate a non-transferable identifier".to_string(),
            ));
        }

        let new_sn = self.sn + 1;
        let current_gen = self.key_gen;

        // New signing keys come from the pre-rotated next keys
        // (the current next_signers become the new signers)
        let new_signers = std::mem::take(&mut self.next_signers);

        // Generate new next keys
        let next_gen = current_gen + 1;
        let mut new_next_signers = Vec::with_capacity(config.next_count);
        for i in 0..config.next_count {
            let path = format!("{next_gen}.{i}");
            let signer = self
                .salter
                .signer(&self.code, &path, "low", self.transferable)?;
            new_next_signers.push(signer);
        }

        // Collect new key qb64 strings
        let keys: Vec<String> = new_signers
            .iter()
            .map(|s| s.verfer().qb64())
            .collect::<Result<Vec<_>, _>>()?;

        // Compute new next key digests
        let next_key_digests: Vec<String> = new_next_signers
            .iter()
            .map(|s| {
                // Commit to the qb64 form of the next key, matching keripy.
                let diger = Diger::from_data("E", s.verfer().qb64()?.as_bytes())?;
                diger.qb64().map_err(KeriError::Crypto)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Build rotation SAD
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": self.prefix,
            "s": format!("{new_sn:x}"),
            "p": self.last_said,
            "kt": config.threshold.to_string(),
            "k": keys,
            "nt": config.next_threshold.to_string(),
            "n": next_key_digests,
            "bt": self.backer_threshold.to_string(),
            "br": config.backers_remove,
            "ba": config.backers_add,
            "c": [],
            "a": []
        });

        // Fix version string size before computing SAID
        fix_version_string(&mut sad)?;

        // Compute SAID
        let computed_said = said::compute_said(&mut sad, "d", "E", SerializationKind::Json)?;

        // Create Serder
        let serder = Serder::new(SerializationKind::Json, sad)?;

        // Sign with the NEW signers — the ones this rotation installs, which
        // the previous event committed to by digest. A rotation signed by the
        // outgoing keys is not what KERI defines and is not what keripy
        // accepts: possession of the pre-rotated keys is the whole proof of
        // authority to rotate.
        let mut sig_bytes = Vec::new();
        for (i, signer) in new_signers.iter().enumerate() {
            let siger = signer.sign_indexed(serder.raw(), i, true)?;
            let qb64 = siger.qb64()?;
            sig_bytes.extend_from_slice(qb64.as_bytes());
        }

        // Build counter
        let code = counter_code_for(&serder, GroupKind::ControllerIdxSigs)?;
        let counter = Counter::new(code, new_signers.len())?;
        let counter_qb64 = counter.qb64()?;

        // Compose message
        let mut composed = Vec::new();
        composed.extend_from_slice(serder.raw());
        composed.extend_from_slice(counter_qb64.as_bytes());
        composed.extend_from_slice(&sig_bytes);

        // Store event, KEL, first-seen, signatures in one transaction
        if let Some(store) = store {
            store.store_event(
                &computed_said,
                serder.raw(),
                &self.prefix,
                new_sn,
                Some(&sig_bytes),
            )?;
        }

        // Update internal state
        self.signers = new_signers;
        self.next_signers = new_next_signers;
        self.last_said = computed_said.clone();
        self.sn = new_sn;
        self.key_gen = next_gen + 1;
        // The keys just installed are the ones that were pre-rotated, so they
        // sit at the generation the previous state called `next_gen`.
        self.signer_gen = self.next_gen;
        self.next_gen = next_gen;

        // Update backers: remove then add
        self.backers.retain(|b| !config.backers_remove.contains(b));
        for b in &config.backers_add {
            if !self.backers.contains(b) {
                self.backers.push(b.clone());
            }
        }

        Ok(SignedEvent {
            said: computed_said,
            raw: serder.raw().to_vec(),
            signatures: sig_bytes,
            composed,
        })
    }

    /// The state needed to resume this identifier later, minus the salt.
    ///
    /// Persist this alongside the key event log; keep the salt wherever the
    /// application keeps secrets. [`Hab::resume`] puts the two back together.
    pub fn state(&self) -> HabState {
        HabState {
            name: self.name.clone(),
            prefix: self.prefix.clone(),
            code: self.code.clone(),
            transferable: self.transferable,
            signer_gen: self.signer_gen,
            signer_count: self.signers.len(),
            next_gen: self.next_gen,
            next_count: self.next_signers.len(),
            key_gen: self.key_gen,
            last_said: self.last_said.clone(),
            sn: self.sn,
            backer_threshold: self.backer_threshold,
            backers: self.backers.clone(),
        }
    }

    /// Rebuild an identifier from persisted state and its salt.
    ///
    /// Both signing key sets are re-derived from the salt at the generations
    /// the state records, so a resumed `Hab` signs exactly what an unbroken one
    /// would. Nothing is read from a store — the caller decides where the state
    /// and the salt were kept.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the salt or the derived keys are unusable.
    pub fn resume(state: &HabState, salt: &[u8]) -> Result<Self, KeriError> {
        let salter = Salter::new("0A", salt.to_vec())?;

        let derive = |generation: usize, count: usize| -> Result<Vec<Signer>, KeriError> {
            (0..count)
                .map(|i| {
                    salter
                        .signer(
                            &state.code,
                            &format!("{generation}.{i}"),
                            "low",
                            state.transferable,
                        )
                        .map_err(KeriError::from)
                })
                .collect()
        };

        let signers = derive(state.signer_gen, state.signer_count)?;
        let next_signers = derive(state.next_gen, state.next_count)?;

        Ok(Self {
            name: state.name.clone(),
            prefix: state.prefix.clone(),
            signers,
            next_signers,
            salter,
            transferable: state.transferable,
            code: state.code.clone(),
            last_said: state.last_said.clone(),
            sn: state.sn,
            key_gen: state.key_gen,
            signer_gen: state.signer_gen,
            next_gen: state.next_gen,
            backer_threshold: state.backer_threshold,
            backers: state.backers.clone(),
        })
    }

    /// Create an interaction event with the given anchors.
    ///
    /// Interaction events do not change keys -- they only anchor data
    /// (seals) into the KEL.
    pub fn interact(
        &mut self,
        anchors: &[serde_json::Value],
        store: &dyn KeriStore,
    ) -> Result<Vec<u8>, KeriError> {
        self.interact_inner(anchors, Some(store))
            .map(|e| e.composed)
    }

    /// Create an interaction event without a store.
    ///
    /// # Errors
    /// Returns [`KeriError`] if the event cannot be built or signed.
    pub fn interact_event(
        &mut self,
        anchors: &[serde_json::Value],
    ) -> Result<SignedEvent, KeriError> {
        self.interact_inner(anchors, None)
    }

    fn interact_inner(
        &mut self,
        anchors: &[serde_json::Value],
        store: Option<&dyn KeriStore>,
    ) -> Result<SignedEvent, KeriError> {
        let new_sn = self.sn + 1;

        // Build interaction SAD
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "",
            "i": self.prefix,
            "s": format!("{new_sn:x}"),
            "p": self.last_said,
            "a": anchors
        });

        // Fix version string size before computing SAID
        fix_version_string(&mut sad)?;

        // Compute SAID
        let computed_said = said::compute_said(&mut sad, "d", "E", SerializationKind::Json)?;

        // Create Serder
        let serder = Serder::new(SerializationKind::Json, sad)?;

        // Sign with current signers
        let mut sig_bytes = Vec::new();
        for (i, signer) in self.signers.iter().enumerate() {
            let siger = signer.sign_indexed(serder.raw(), i, true)?;
            let qb64 = siger.qb64()?;
            sig_bytes.extend_from_slice(qb64.as_bytes());
        }

        // Build counter
        let code = counter_code_for(&serder, GroupKind::ControllerIdxSigs)?;
        let counter = Counter::new(code, self.signers.len())?;
        let counter_qb64 = counter.qb64()?;

        // Compose message
        let mut composed = Vec::new();
        composed.extend_from_slice(serder.raw());
        composed.extend_from_slice(counter_qb64.as_bytes());
        composed.extend_from_slice(&sig_bytes);

        // Store event, KEL, first-seen, signatures in one transaction
        if let Some(store) = store {
            store.store_event(
                &computed_said,
                serder.raw(),
                &self.prefix,
                new_sn,
                Some(&sig_bytes),
            )?;
        }

        // Update state
        self.last_said = computed_said.clone();
        self.sn = new_sn;

        Ok(SignedEvent {
            said: computed_said,
            raw: serder.raw().to_vec(),
            signatures: sig_bytes,
            composed,
        })
    }

    /// Generate a receipt attachment for another event.
    ///
    /// - **Non-transferable** identifiers: produces a `-D` counter with a receipt
    ///   couple (prefix qb64 + Cigar qb64) suitable for witness receipts.
    /// - **Transferable** identifiers: produces a `-B` counter with indexed
    ///   signatures.
    pub fn receipt(&self, other_serder: &Serder) -> Result<Vec<u8>, KeriError> {
        let mut receipt_msg = Vec::new();

        if !self.transferable {
            // Non-transferable: produce receipt couple (prefix + cigar)
            let cigar = self.signers[0].sign(other_serder.raw())?;
            let prefix_qb64 = self.signers[0].verfer().qb64()?;
            let cigar_qb64 = cigar.qb64()?;

            let code = counter_code_for(other_serder, GroupKind::NonTransReceiptCouples)?;
            let counter = Counter::new(code, 1)?;
            let counter_qb64 = counter.qb64()?;

            receipt_msg.extend_from_slice(counter_qb64.as_bytes());
            receipt_msg.extend_from_slice(prefix_qb64.as_bytes());
            receipt_msg.extend_from_slice(cigar_qb64.as_bytes());
        } else {
            // Transferable: produce indexed signatures
            let mut sig_bytes = Vec::new();
            for (i, signer) in self.signers.iter().enumerate() {
                let siger = signer.sign_indexed(other_serder.raw(), i, true)?;
                let qb64 = siger.qb64()?;
                sig_bytes.extend_from_slice(qb64.as_bytes());
            }

            let code = counter_code_for(other_serder, GroupKind::ControllerIdxSigs)?;
            let counter = Counter::new(code, self.signers.len())?;
            let counter_qb64 = counter.qb64()?;

            receipt_msg.extend_from_slice(counter_qb64.as_bytes());
            receipt_msg.extend_from_slice(&sig_bytes);
        }

        Ok(receipt_msg)
    }

    /// Build a full `rct` receipt message for another event.
    ///
    /// Constructs a receipt event body (with SAID), appends the receipt
    /// attachment from `receipt()`, and stores the receipt via the store.
    pub fn receipt_message(
        &self,
        other_serder: &Serder,
        store: &dyn KeriStore,
    ) -> Result<Vec<u8>, KeriError> {
        let other_prefix = other_serder.prefix()?;
        let other_sn = other_serder.sn()?;
        let other_said = other_serder.said()?;

        // Build receipt event SAD
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rct",
            "d": "",
            "i": other_prefix,
            "s": format!("{other_sn:x}")
        });

        fix_version_string(&mut sad)?;
        let _receipt_said = said::compute_said(&mut sad, "d", "E", SerializationKind::Json)?;
        let serder = Serder::new(SerializationKind::Json, sad)?;

        // Generate the receipt attachment
        let attachment = self.receipt(other_serder)?;

        // Compose: receipt event body + attachment
        let mut composed = Vec::new();
        composed.extend_from_slice(serder.raw());
        composed.extend_from_slice(&attachment);

        // Store the receipt
        store.put_receipts(&other_said, &attachment)?;

        Ok(composed)
    }

    /// Collect receipt couples from an array of non-transferable witness Habs.
    ///
    /// Each witness signs the event and produces a `(prefix_qb64, sig_raw)` couple.
    /// Returns the collected couples suitable for `verify_witness_receipts`.
    ///
    /// # Errors
    /// Returns an error if any witness Hab is transferable.
    pub fn collect_witness_receipts(
        event_serder: &Serder,
        witness_habs: &[&Hab],
    ) -> Result<Vec<(String, Vec<u8>)>, KeriError> {
        let mut couples = Vec::with_capacity(witness_habs.len());

        for witness in witness_habs {
            if witness.transferable {
                return Err(KeriError::Config(format!(
                    "witness '{}' must be non-transferable",
                    witness.name
                )));
            }

            let cigar = witness.signers[0].sign(event_serder.raw())?;
            let prefix_qb64 = witness.signers[0].verfer().qb64()?;
            couples.push((prefix_qb64, cigar.raw().to_vec()));
        }

        Ok(couples)
    }

    /// Get the receipt couples as a `-D` attachment block from multiple witnesses.
    ///
    /// Returns the composed CESR bytes: a non-transferable receipt couple
    /// counter followed by (prefix + cigar) couples.
    pub fn compose_witness_receipt_attachment(
        event_serder: &Serder,
        witness_habs: &[&Hab],
    ) -> Result<Vec<u8>, KeriError> {
        let couples = Self::collect_witness_receipts(event_serder, witness_habs)?;

        let code = counter_code_for(event_serder, GroupKind::NonTransReceiptCouples)?;
        let counter = Counter::new(code, couples.len())?;
        let counter_qb64 = counter.qb64()?;

        let mut output = Vec::new();
        output.extend_from_slice(counter_qb64.as_bytes());

        for (prefix_qb64, sig_raw) in &couples {
            output.extend_from_slice(prefix_qb64.as_bytes());
            let cigar = Cigar::new("0B", sig_raw.clone())?;
            let cigar_qb64 = cigar.qb64()?;
            output.extend_from_slice(cigar_qb64.as_bytes());
        }

        Ok(output)
    }

    /// The human-readable name of this identifier.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The identifier prefix (qb64).
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The current sequence number.
    pub fn sn(&self) -> u64 {
        self.sn
    }

    /// The SAID of the latest event.
    pub fn last_said(&self) -> &str {
        &self.last_said
    }

    /// Whether this identifier is transferable.
    pub fn transferable(&self) -> bool {
        self.transferable
    }

    /// Access the current signers.
    pub fn signers(&self) -> &[Signer] {
        &self.signers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_keri_core::parser;
    use affinidi_keri_db::lmdb::LmdbStore;

    fn temp_store() -> LmdbStore {
        let dir = tempfile::tempdir().unwrap();
        LmdbStore::open(dir.path()).unwrap()
    }

    #[test]
    fn test_hab_incept_default() {
        let store = temp_store();
        let config = InceptionConfig::default();
        let (hab, msg) = Hab::incept("alice", &config, &store).unwrap();

        assert_eq!(hab.name(), "alice");
        assert!(!hab.prefix().is_empty());
        // Prefix should be a 44-char self-addressing identifier (Blake3-256 digest)
        assert_eq!(hab.prefix().len(), 44);
        assert!(hab.prefix().starts_with('E'));
        assert_eq!(hab.sn(), 0);
        assert!(hab.transferable());
        assert!(!msg.is_empty());

        // Verify the event was stored
        let stored = store.get_event(hab.last_said()).unwrap();
        assert!(stored.is_some());

        // Verify the KEL was stored
        let kel = store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 1);
        assert_eq!(kel[0].0, 0);
    }

    #[test]
    fn test_hab_incept_with_salt() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x42u8; 16]).build();
        let (hab1, _) = Hab::incept("test1", &config, &store).unwrap();

        // Same salt should produce same prefix (deterministic)
        let store2 = temp_store();
        let (hab2, _) = Hab::incept("test2", &config, &store2).unwrap();
        assert_eq!(hab1.prefix(), hab2.prefix());
    }

    #[test]
    fn test_hab_incept_prefix_derived_correctly() {
        let store = temp_store();
        let config = InceptionConfig::default();
        let (hab, msg) = Hab::incept("test", &config, &store).unwrap();

        // Parse back the event from the message to verify structure
        let serder = Serder::from_raw(&msg[..]).unwrap();
        assert_eq!(serder.ilk().unwrap(), "icp");
        assert_eq!(serder.prefix().unwrap(), hab.prefix());
        assert_eq!(serder.sn().unwrap(), 0);

        // Verify SAID
        serder.verify_said("E").unwrap();
    }

    #[test]
    fn test_hab_rotate() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
        let (mut hab, _) = Hab::incept("alice", &config, &store).unwrap();

        let old_prefix = hab.prefix().to_string();
        let old_said = hab.last_said().to_string();

        let rot_config = RotationConfig::default();
        let rot_msg = hab.rotate(&rot_config, &store).unwrap();

        // Prefix should not change
        assert_eq!(hab.prefix(), old_prefix);
        // Sequence number should increment
        assert_eq!(hab.sn(), 1);
        // SAID should change
        assert_ne!(hab.last_said(), old_said);
        assert!(!rot_msg.is_empty());

        // Parse and verify the rotation event
        let serder = Serder::from_raw(&rot_msg[..]).unwrap();
        assert_eq!(serder.ilk().unwrap(), "rot");
        assert_eq!(serder.prefix().unwrap(), old_prefix);
        assert_eq!(serder.sn().unwrap(), 1);

        // Verify KEL has two entries
        let kel = store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 2);
    }

    #[test]
    fn test_hab_interact() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
        let (mut hab, _) = Hab::incept("alice", &config, &store).unwrap();

        let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
        let ixn_msg = hab.interact(&[anchor], &store).unwrap();

        assert_eq!(hab.sn(), 1);
        assert!(!ixn_msg.is_empty());

        // Parse and verify
        let serder = Serder::from_raw(&ixn_msg[..]).unwrap();
        assert_eq!(serder.ilk().unwrap(), "ixn");
        assert_eq!(serder.sn().unwrap(), 1);

        // Verify KEL has two entries
        let kel = store.get_kel(hab.prefix()).unwrap();
        assert_eq!(kel.len(), 2);
    }

    #[test]
    fn test_hab_rotate_non_transferable_fails() {
        let store = temp_store();
        let config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x01u8; 16])
            .build();
        let (mut hab, _) = Hab::incept("alice", &config, &store).unwrap();

        let rot_config = RotationConfig::default();
        let result = hab.rotate(&rot_config, &store);
        assert!(result.is_err());
    }

    #[test]
    fn test_hab_receipt() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
        let (hab, msg) = Hab::incept("alice", &config, &store).unwrap();

        // Parse the inception event to get a Serder
        let serder = Serder::from_raw(&msg[..]).unwrap();

        // Generate receipt
        let receipt = hab.receipt(&serder).unwrap();
        assert!(!receipt.is_empty());
    }

    #[test]
    fn test_hab_rotate_key_change() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
        let (mut hab, icp_msg) = Hab::incept("alice", &config, &store).unwrap();

        // Get the inception key
        let icp_serder = Serder::from_raw(&icp_msg[..]).unwrap();
        let icp_keys: Vec<String> = icp_serder.sad()["k"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        // Rotate
        let rot_config = RotationConfig::default();
        let rot_msg = hab.rotate(&rot_config, &store).unwrap();

        // Get the rotation key
        let rot_serder = Serder::from_raw(&rot_msg[..]).unwrap();
        let rot_keys: Vec<String> = rot_serder.sad()["k"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        // Keys should be different after rotation
        assert_ne!(icp_keys, rot_keys);
    }

    #[test]
    fn test_hab_receipt_non_transferable_uses_d_counter() {
        let store = temp_store();
        let config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x02u8; 16])
            .build();
        let (hab, msg) = Hab::incept("witness", &config, &store).unwrap();
        let serder = Serder::from_raw(&msg[..]).unwrap();

        let receipt = hab.receipt(&serder).unwrap();
        let receipt_str = std::str::from_utf8(&receipt).unwrap();

        // Non-transferable receipt should use -D counter
        // KERI 1.x non-transferable receipt couples.
        assert!(receipt_str.starts_with("-C"), "got {receipt_str}");

        // Should contain: counter(4) + prefix(44) + cigar(88) = 136
        assert_eq!(receipt.len(), 4 + 44 + 88);
    }

    #[test]
    fn test_hab_receipt_transferable_uses_b_counter() {
        let store = temp_store();
        let config = InceptionConfig::builder().salt(vec![0x01u8; 16]).build();
        let (hab, msg) = Hab::incept("alice", &config, &store).unwrap();
        let serder = Serder::from_raw(&msg[..]).unwrap();

        let receipt = hab.receipt(&serder).unwrap();
        let receipt_str = std::str::from_utf8(&receipt).unwrap();

        // Transferable receipt should use -B counter
        // KERI 1.x controller indexed sigs.
        assert!(receipt_str.starts_with("-A"), "got {receipt_str}");
    }

    #[test]
    fn test_hab_receipt_message_roundtrip() {
        let store = temp_store();
        let config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x03u8; 16])
            .build();
        let (hab, msg) = Hab::incept("witness", &config, &store).unwrap();
        let event_serder = Serder::from_raw(&msg[..]).unwrap();

        let rct_msg = hab.receipt_message(&event_serder, &store).unwrap();

        // Parse the receipt message back
        let (parsed, _consumed) = parser::parse_next(&rct_msg).unwrap();
        assert_eq!(parsed.serder.ilk().unwrap(), "rct");
        assert!(!parsed.attachments.is_empty());
    }

    #[test]
    fn test_collect_witness_receipts() {
        let store1 = temp_store();
        let store2 = temp_store();
        let w1_config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x10u8; 16])
            .build();
        let w2_config = InceptionConfig::builder()
            .transferable(false)
            .salt(vec![0x20u8; 16])
            .build();

        let (w1, _) = Hab::incept("wit1", &w1_config, &store1).unwrap();
        let (w2, _) = Hab::incept("wit2", &w2_config, &store2).unwrap();

        // Create a controller event to receipt
        let ctrl_store = temp_store();
        let ctrl_config = InceptionConfig::builder().salt(vec![0x30u8; 16]).build();
        let (_ctrl, ctrl_msg) = Hab::incept("ctrl", &ctrl_config, &ctrl_store).unwrap();
        let ctrl_serder = Serder::from_raw(&ctrl_msg[..]).unwrap();

        let couples = Hab::collect_witness_receipts(&ctrl_serder, &[&w1, &w2]).unwrap();
        assert_eq!(couples.len(), 2);

        // Each couple should have a 44-char prefix and 64-byte sig
        for (prefix, sig) in &couples {
            assert_eq!(prefix.len(), 44);
            assert_eq!(sig.len(), 64);
        }
    }

    #[test]
    fn test_hab_multi_key() {
        let store = temp_store();
        let config = InceptionConfig::builder()
            .count(3)
            .threshold(2)
            .next_count(3)
            .next_threshold(2)
            .salt(vec![0x07u8; 16])
            .build();
        let (hab, msg) = Hab::incept("multi", &config, &store).unwrap();

        assert_eq!(hab.signers().len(), 3);

        // Parse and verify event has 3 keys
        let serder = Serder::from_raw(&msg[..]).unwrap();
        let keys = serder.sad()["k"].as_array().unwrap();
        assert_eq!(keys.len(), 3);

        let kt = serder.sad()["kt"].as_str().unwrap();
        assert_eq!(kt, "2");
    }
}
