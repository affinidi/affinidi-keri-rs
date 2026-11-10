//! Kever: Key Event Verifier.
//!
//! A Kever tracks the verified state of a single KERI identifier
//! by processing its key event log (KEL). It validates signatures,
//! sequence numbers, and prior event digests.

use affinidi_keri_crypto::{Diger, Siger, Verfer};

use crate::delegation::{self, DelegationProof, DelegatorAnchors};
use crate::error::CoreError;
use crate::event::{
    DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
    RotationEvent,
};
use crate::key_state::KeyState;
use crate::said;
use crate::serder::Serder;
use crate::version::SerializationKind;

/// Key Event Verifier for a single KERI identifier.
///
/// Kever maintains the current key state and validates incoming
/// events against the existing state.
#[derive(Debug, Clone)]
pub struct Kever {
    /// The current verified key state.
    state: KeyState,
    /// The state the last establishment event installed, from which a
    /// superseding rotation recovers.
    est: KeyState,
    /// The interaction events after it, in order: each one's SAID and
    /// protocol version.
    since: Vec<(String, u8)>,
    /// Whether the kever has been fully initialized with an inception event.
    pub incepted: bool,
}

impl Kever {
    /// Create a new Kever from an inception event.
    ///
    /// Validates that:
    /// - The event is an inception event (ilk == "icp")
    /// - The provided keys match the verfers
    /// - The signatures satisfy the signing threshold
    /// - For self-addressing AIDs (i == d), the prefix matches the SAID
    ///
    /// # Errors
    /// Returns `CoreError` if the inception event is invalid.
    pub fn new(serder: &Serder, sigs: &[Siger], verfers: &[Verfer]) -> Result<Self, CoreError> {
        let ilk = serder.ilk()?;
        if ilk == "dip" {
            return Err(CoreError::UnexpectedIlk(
                "'dip' is a delegated inception; use Kever::new_delegated, which verifies \
                 the delegator's anchoring seal"
                    .into(),
            ));
        }
        if ilk != "icp" {
            return Err(CoreError::UnexpectedIlk(format!(
                "expected 'icp', got '{ilk}'"
            )));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        check_shape(serder.sad(), "icp")?;
        // Parse the inception event from the SAD
        let icp: InceptionEvent = serder.sad().deserialize_into().map_err(CoreError::Json)?;

        // Validate keys match provided verfers
        if icp.keys.len() != verfers.len() {
            return Err(CoreError::Validation(format!(
                "key count mismatch: event has {} keys, {} verfers provided",
                icp.keys.len(),
                verfers.len()
            )));
        }

        for (i, (key_qb64, verfer)) in icp.keys.iter().zip(verfers.iter()).enumerate() {
            let verfer_qb64 = verfer.qb64().map_err(CoreError::Crypto)?;
            if *key_qb64 != verfer_qb64 {
                return Err(CoreError::Validation(format!(
                    "key[{i}] mismatch: event key '{key_qb64}' != verfer '{verfer_qb64}'"
                )));
            }
        }

        // Verify signatures against the serialized event body
        Self::verify_sigs_static(serder.raw(), sigs, verfers, &icp.keys_threshold.0)?;

        // Validate prefix derivation (self-addressing: i == d, basic: i == keys[0])
        Self::validate_prefix_derivation(&icp)?;

        // Derive initial key state
        let state = KeyState::from_inception(&icp)?;

        Ok(Self {
            est: state.clone(),
            since: Vec::new(),
            state,
            incepted: true,
        })
    }

    /// Create a new Kever from a **delegated** inception event (`dip`).
    ///
    /// Everything `new` checks is checked here too, plus the part that makes
    /// delegation mean anything: the delegator named in `di` must have a
    /// verified event, at the location given by `proof`, anchoring a seal for
    /// this exact event. `proof` comes from the seal source couple attached to
    /// the event in the CESR stream — see
    /// [`DelegationProof::from_seal_source_couple`].
    ///
    /// Without that check a `dip` proves nothing: the `di` field is just a
    /// string the delegated identifier wrote about itself.
    ///
    /// # Errors
    /// Returns `CoreError` if the event is invalid, its signatures do not meet
    /// the threshold, or the delegation is not anchored by the delegator.
    pub fn new_delegated(
        serder: &Serder,
        sigs: &[Siger],
        verfers: &[Verfer],
        proof: &DelegationProof,
        source: &dyn DelegatorAnchors,
    ) -> Result<Self, CoreError> {
        let ilk = serder.ilk()?;
        if ilk != "dip" {
            return Err(CoreError::UnexpectedIlk(format!(
                "expected 'dip', got '{ilk}'"
            )));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        check_shape(serder.sad(), "dip")?;
        let dip: DelegatedInceptionEvent =
            serder.sad().deserialize_into().map_err(CoreError::Json)?;

        if dip.keys.len() != verfers.len() {
            return Err(CoreError::Validation(format!(
                "key count mismatch: event has {} keys, {} verfers provided",
                dip.keys.len(),
                verfers.len()
            )));
        }

        for (i, (key_qb64, verfer)) in dip.keys.iter().zip(verfers.iter()).enumerate() {
            let verfer_qb64 = verfer.qb64().map_err(CoreError::Crypto)?;
            if *key_qb64 != verfer_qb64 {
                return Err(CoreError::Validation(format!(
                    "key[{i}] mismatch: event key '{key_qb64}' != verfer '{verfer_qb64}'"
                )));
            }
        }

        Self::verify_sigs_static(serder.raw(), sigs, verfers, &dip.keys_threshold.0)?;

        // A delegated identifier is always self-addressing: its prefix is the
        // SAID of the very event the delegator anchors, which is what binds
        // the two together.
        if dip.prefix != dip.said {
            return Err(CoreError::InvalidPrefix(
                "delegated inception prefix does not match event SAID (i != d)".into(),
            ));
        }

        delegation::verify_delegation(&dip.prefix, 0, &dip.said, &dip.delegator, proof, source)?;

        let state = KeyState::from_delegated_inception(&dip)?;

        Ok(Self {
            est: state.clone(),
            since: Vec::new(),
            state,
            incepted: true,
        })
    }

    /// Create a new Kever from pre-parsed parts, taking ownership of the SAD.
    ///
    /// Same validation as [`new`], but avoids cloning the SAD. Use when the
    /// caller has already consumed it from a `Serder` via
    /// [`Serder::take_sad`].
    pub fn new_from_parts(
        raw: &[u8],
        sad: crate::sad::SadValue,
        sigs: &[Siger],
        verfers: &[Verfer],
    ) -> Result<Self, CoreError> {
        let ilk = sad
            .get("t")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::MissingField("t".into()))?;
        if ilk != "icp" {
            return Err(CoreError::UnexpectedIlk(format!(
                "expected 'icp', got '{ilk}'"
            )));
        }

        // Verify SAID integrity before trusting any event fields
        said::verify_said(&sad, "d", "E", SerializationKind::Json)?;

        check_shape(&sad, "icp")?;
        let icp: InceptionEvent = sad.deserialize_into().map_err(CoreError::Json)?;

        if icp.keys.len() != verfers.len() {
            return Err(CoreError::Validation(format!(
                "key count mismatch: event has {} keys, {} verfers provided",
                icp.keys.len(),
                verfers.len()
            )));
        }

        for (i, (key_qb64, verfer)) in icp.keys.iter().zip(verfers.iter()).enumerate() {
            let verfer_qb64 = verfer.qb64().map_err(CoreError::Crypto)?;
            if *key_qb64 != verfer_qb64 {
                return Err(CoreError::Validation(format!(
                    "key[{i}] mismatch: event key '{key_qb64}' != verfer '{verfer_qb64}'"
                )));
            }
        }

        Self::verify_sigs_static(raw, sigs, verfers, &icp.keys_threshold.0)?;

        // Validate prefix derivation (self-addressing: i == d, basic: i == keys[0])
        Self::validate_prefix_derivation(&icp)?;

        let state = KeyState::from_inception(&icp)?;

        Ok(Self {
            est: state.clone(),
            since: Vec::new(),
            state,
            incepted: true,
        })
    }

    /// Process the next event in the KEL.
    ///
    /// Handles rotation and interaction events, and a rotation that
    /// supersedes interaction events (see [`Kever::verify_update`]).
    /// Validates that:
    /// - The sequence number is exactly current_sn + 1, or, for a superseding
    ///   rotation, after the last establishment event
    /// - The prior SAID matches the digest of the event before it
    /// - Signatures satisfy the current signing threshold
    ///
    /// # Errors
    /// Returns `CoreError` if the event is invalid or out of order.
    pub fn update(&mut self, serder: &Serder, sigs: &[Siger]) -> Result<(), CoreError> {
        let new_state = self.verify_update(serder, sigs)?;
        self.apply_verified_update(new_state);
        Ok(())
    }

    /// Verify the next event without mutating the Kever, returning the proposed
    /// new `KeyState` on success.
    ///
    /// This avoids cloning the entire Kever for rollback support: the caller
    /// can inspect the proposed state (e.g. to verify witness receipts) before
    /// committing with [`apply_verified_update`].
    pub fn verify_update(&self, serder: &Serder, sigs: &[Siger]) -> Result<KeyState, CoreError> {
        if !self.incepted {
            return Err(CoreError::Validation(
                "kever not initialized with inception event".into(),
            ));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        let ilk = serder.ilk()?;
        let sn = serder.sn()?;

        if ilk == "rot" && sn <= self.state.sn {
            return self.recovery_base(sn)?.verify_update(serder, sigs);
        }
        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        let new_state = match ilk.as_str() {
            "rot" => {
                self.reject_plain_rotation_when_delegated()?;
                check_shape(serder.sad(), "rot")?;
                let rot: RotationEvent =
                    serder.sad().deserialize_into().map_err(CoreError::Json)?;
                // Signed by the keys it installs — see `update`.
                self.verify_rotation_sigs(serder.raw(), sigs, &rot.keys, &rot.keys_threshold.0)?;
                self.state.apply_rotation(&rot)?
            }
            "ixn" => {
                let verfers = self.build_verfers()?;
                Self::verify_sigs_static(serder.raw(), sigs, &verfers, &self.state.threshold)?;
                check_shape(serder.sad(), "ixn")?;
                let ixn: InteractionEvent =
                    serder.sad().deserialize_into().map_err(CoreError::Json)?;
                self.state.apply_interaction(&ixn)?
            }
            "drt" => {
                return Err(CoreError::UnexpectedIlk(
                    "'drt' is a delegated rotation; use Kever::verify_update_delegated, \
                     which verifies the delegator's anchoring seal"
                        .into(),
                ));
            }
            _ => {
                return Err(CoreError::UnexpectedIlk(format!(
                    "expected 'rot' or 'ixn' for update, got '{ilk}'"
                )));
            }
        };

        Ok(new_state)
    }

    /// Like [`verify_update`], but takes an owned SAD to avoid cloning.
    ///
    /// Use when the caller has consumed the SAD from a `Serder` via
    /// [`Serder::take_sad`].
    pub fn verify_update_owned(
        &self,
        raw: &[u8],
        sad: crate::sad::SadValue,
        sigs: &[Siger],
    ) -> Result<KeyState, CoreError> {
        if !self.incepted {
            return Err(CoreError::Validation(
                "kever not initialized with inception event".into(),
            ));
        }

        // Verify SAID integrity before trusting any event fields
        said::verify_said(&sad, "d", "E", SerializationKind::Json)?;

        let ilk = sad
            .get("t")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::MissingField("t".into()))?;

        let sn_str = sad
            .get("s")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::MissingField("s".into()))?;
        let sn = u64::from_str_radix(sn_str, 16)
            .map_err(|_| CoreError::Validation(format!("invalid sn: {sn_str}")))?;

        if ilk == "rot" && sn <= self.state.sn {
            return self.recovery_base(sn)?.verify_update_owned(raw, sad, sigs);
        }
        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        let new_state = match ilk.as_str() {
            "rot" => {
                self.reject_plain_rotation_when_delegated()?;
                check_shape(&sad, "rot")?;
                let rot: RotationEvent = sad.deserialize_into().map_err(CoreError::Json)?;
                // Signed by the keys it installs — see `update`.
                self.verify_rotation_sigs(raw, sigs, &rot.keys, &rot.keys_threshold.0)?;
                self.state.apply_rotation(&rot)?
            }
            "ixn" => {
                let verfers = self.build_verfers()?;
                Self::verify_sigs_static(raw, sigs, &verfers, &self.state.threshold)?;
                check_shape(&sad, "ixn")?;
                let ixn: InteractionEvent = sad.deserialize_into().map_err(CoreError::Json)?;
                self.state.apply_interaction(&ixn)?
            }
            "drt" => {
                return Err(CoreError::UnexpectedIlk(
                    "'drt' is a delegated rotation; use Kever::verify_update_delegated, \
                     which verifies the delegator's anchoring seal"
                        .into(),
                ));
            }
            _ => {
                return Err(CoreError::UnexpectedIlk(format!(
                    "expected 'rot' or 'ixn' for update, got '{ilk}'"
                )));
            }
        };

        Ok(new_state)
    }

    /// Verify a **delegated** rotation (`drt`) against the current state.
    ///
    /// Checks everything `verify_update` checks for a rotation — sequence
    /// ordering, prior-event digest, signatures against the current key set,
    /// the pre-rotation commitment — and additionally that the delegator named
    /// in `di` anchored this exact event, and is the same delegator the
    /// identifier was incepted under.
    ///
    /// Returns the proposed state; commit it with
    /// [`apply_verified_update`](Self::apply_verified_update).
    ///
    /// # Errors
    /// Returns `CoreError` if the rotation is invalid or the delegation is not
    /// anchored by the delegator.
    pub fn verify_update_delegated(
        &self,
        serder: &Serder,
        sigs: &[Siger],
        proof: &DelegationProof,
        source: &dyn DelegatorAnchors,
    ) -> Result<KeyState, CoreError> {
        if !self.incepted {
            return Err(CoreError::Validation(
                "kever not initialized with inception event".into(),
            ));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        let ilk = serder.ilk()?;
        if ilk != "drt" {
            return Err(CoreError::UnexpectedIlk(format!(
                "expected 'drt', got '{ilk}'"
            )));
        }

        let sn = serder.sn()?;
        if sn <= self.state.sn {
            return Err(CoreError::Unsupported(format!(
                "a delegated rotation at sn {sn} would supersede the event there: \
                 superseding delegated rotations (KERI recovery rule B) are not supported"
            )));
        }
        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        let drt: DelegatedRotationEvent =
            serder.sad().deserialize_into().map_err(CoreError::Json)?;

        // Like a plain rotation, signed by the keys it installs.
        self.verify_rotation_sigs(serder.raw(), sigs, &drt.keys, &drt.keys_threshold.0)?;

        delegation::verify_delegation(&drt.prefix, sn, &drt.said, &drt.delegator, proof, source)?;

        self.state.apply_delegated_rotation(&drt)
    }

    /// Apply a previously verified update (from [`verify_update`]).
    ///
    /// After a superseding rotation the state's sequence number goes back:
    /// the superseded interaction events are no longer part of the log.
    pub fn apply_verified_update(&mut self, new_state: KeyState) {
        if new_state.said == new_state.last_event_digest {
            // An establishment event: recovery starts from here.
            self.est = new_state.clone();
            self.since.clear();
        } else {
            self.since.push((
                new_state.last_event_digest.clone(),
                new_state.protocol_major,
            ));
        }
        self.state = new_state;
    }

    /// The state to verify a superseding rotation at `sn` against: the log as
    /// it stood at `sn - 1`.
    ///
    /// KERI's recovery rules for a non-delegated rotation (keripy
    /// `Kever.update` and its superseding rules A0–A2, b70986f): a rotation
    /// may supersede interaction events after the last establishment event,
    /// and nothing else. So `sn` must be after the last establishment event
    /// and at or before the latest event, which is then an interaction event.
    /// Interaction events change no keys, so the state at `sn - 1` is the last
    /// establishment event's, at that event's sequence number and SAID; the
    /// rotation is then verified exactly as the next event of that log — its
    /// prior, its signatures against the pre-rotation commitment — and on
    /// acceptance the events it supersedes are gone. This is how a recovery
    /// key holder takes back an identifier whose routine key signed events it
    /// should not have.
    fn recovery_base(&self, sn: u64) -> Result<Kever, CoreError> {
        if sn <= self.est.sn {
            return Err(CoreError::Validation(format!(
                "stale rotation at sn {sn}: the last establishment event is at sn {}, and a \
                 rotation supersedes only interaction events after it",
                self.est.sn
            )));
        }
        // est.sn < sn <= state.sn, so every event in (est.sn, state.sn] is an
        // interaction event, recorded in `since`.
        let kept = usize::try_from(sn - 1 - self.est.sn)
            .map_err(|_| CoreError::Validation("sequence number out of range".into()))?;
        let mut base = self.est.clone();
        base.sn = sn - 1;
        if let Some((said, major)) = kept.checked_sub(1).and_then(|i| self.since.get(i)) {
            base.last_event_digest = said.clone();
            base.protocol_major = *major;
        }
        Ok(Kever {
            state: base,
            est: self.est.clone(),
            since: self.since[..kept].to_vec(),
            incepted: true,
        })
    }

    /// Verify signatures over a message using the current key set.
    ///
    /// Each signature's index maps to a key in the current key list.
    /// Enough signatures must satisfy the current signing threshold.
    ///
    /// # Errors
    /// Returns `CoreError::ThresholdNotMet` if insufficient valid signatures.
    pub fn verify_sigs(&self, message: &[u8], sigs: &[Siger]) -> Result<bool, CoreError> {
        let verfers = self.build_verfers()?;
        Self::verify_sigs_static(message, sigs, &verfers, &self.state.threshold)?;
        Ok(true)
    }

    /// Return the current key state.
    pub fn state(&self) -> &KeyState {
        &self.state
    }

    /// Return the identifier prefix.
    pub fn prefix(&self) -> &str {
        &self.state.prefix
    }

    /// Return the current sequence number.
    pub fn sn(&self) -> u64 {
        self.state.sn
    }

    /// Verify witness receipts against this kever's current backer list and threshold.
    ///
    /// Each receipt couple is `(witness_prefix_qb64, sig_raw_bytes)`.
    /// Non-transferable witness prefixes (code `B`) ARE the public key,
    /// so no KEL lookup is needed.
    pub fn verify_witness_receipts(
        &self,
        message: &[u8],
        receipt_couples: &[(String, Vec<u8>)],
    ) -> Result<(), CoreError> {
        Self::verify_witness_receipts_static(
            message,
            receipt_couples,
            &self.state.backers,
            self.state.backer_threshold,
        )
    }

    /// Static helper to verify witness receipt couples against a given backer set.
    pub fn verify_witness_receipts_static(
        message: &[u8],
        receipt_couples: &[(String, Vec<u8>)],
        backers: &[String],
        backer_threshold: usize,
    ) -> Result<(), CoreError> {
        if backer_threshold == 0 {
            return Ok(());
        }

        let mut valid_prefixes = Vec::new();

        for (prefix_qb64, sig_raw) in receipt_couples {
            // Only count witnesses that are in the designated backer list
            if !backers.contains(prefix_qb64) {
                continue;
            }

            // Deduplicate by prefix
            if valid_prefixes.contains(prefix_qb64) {
                continue;
            }

            // Build verfer from the prefix (non-transferable prefix IS the public key)
            let verfer = Verfer::from_qb64(prefix_qb64).map_err(CoreError::Crypto)?;
            let valid = verfer.verify(message, sig_raw).map_err(CoreError::Crypto)?;

            if valid {
                valid_prefixes.push(prefix_qb64.clone());
            }
        }

        if valid_prefixes.len() < backer_threshold {
            return Err(CoreError::Validation(format!(
                "witness receipt threshold not met: need {}, got {}",
                backer_threshold,
                valid_prefixes.len()
            )));
        }

        Ok(())
    }

    /// Build Verfer instances from a list of qb64 keys.
    fn verfers_from_keys(keys: &[String]) -> Result<Vec<Verfer>, CoreError> {
        let mut verfers = Vec::with_capacity(keys.len());
        for key_qb64 in keys {
            verfers.push(Verfer::from_qb64(key_qb64).map_err(CoreError::Crypto)?);
        }
        Ok(verfers)
    }

    /// Reject a plain rotation on a delegated identifier.
    ///
    /// A delegated identifier rotates with `drt`, which carries the
    /// delegator's authorisation. Accepting a bare `rot` would let it rotate
    /// out from under its delegator.
    fn reject_plain_rotation_when_delegated(&self) -> Result<(), CoreError> {
        if self.state.delegated {
            return Err(CoreError::UnexpectedIlk(
                "identifier is delegated and must rotate with 'drt', not 'rot'".into(),
            ));
        }
        Ok(())
    }

    /// Build Verfer instances from the current key state's key list.
    fn build_verfers(&self) -> Result<Vec<Verfer>, CoreError> {
        let mut verfers = Vec::with_capacity(self.state.keys.len());
        for key_qb64 in &self.state.keys {
            let verfer = Verfer::from_qb64(key_qb64).map_err(CoreError::Crypto)?;
            verfers.push(verfer);
        }
        Ok(verfers)
    }

    /// Validate that the inception event's prefix is correctly derived.
    ///
    /// Per the KERI spec, there are two valid derivation methods:
    /// - **Self-addressing**: prefix code is a digest code (`E`, `F`, etc.)
    ///   and the prefix MUST equal the event SAID (`i == d`).
    /// - **Basic**: prefix code is a public-key code (`B`, `D`, `1AAB`, etc.)
    ///   and the prefix MUST equal the first public key in the event.
    fn validate_prefix_derivation(icp: &InceptionEvent) -> Result<(), CoreError> {
        // Self-addressing AID: prefix is a digest
        if Diger::from_qb64(&icp.prefix).is_ok() {
            if icp.prefix != icp.said {
                return Err(CoreError::InvalidPrefix(
                    "self-addressing prefix does not match event SAID (i != d)".into(),
                ));
            }
            return Ok(());
        }

        // Basic AID: prefix is a public key
        if Verfer::from_qb64(&icp.prefix).is_ok() {
            if icp.keys.is_empty() || icp.prefix != icp.keys[0] {
                return Err(CoreError::InvalidPrefix(
                    "basic prefix does not match first public key".into(),
                ));
            }
            return Ok(());
        }

        Err(CoreError::InvalidPrefix(
            "prefix is neither a valid digest code nor a valid key code".into(),
        ))
    }

    /// Verify a rotation's signatures.
    ///
    /// A rotation is signed by the keys it installs, and must meet two
    /// thresholds: its own `kt` over those keys, by each signature's `index`;
    /// and the `nt` the prior establishment event committed to, over the
    /// committed positions the signatures expose. A signature exposes the
    /// prior next-key digest at its `ondex` when the key at its `index`
    /// digests to it (keripy `Kever.exposeds`); a current-only signature
    /// exposes none. Checking `kt` alone would let a rotation lower its own
    /// bar: holding one of three keys pre-committed under `nt: "2"`, a
    /// rotation declaring `kt: "1"` would pass.
    ///
    /// The new keys need not be the committed ones, nor in their order: a
    /// rotation may reorder them, reveal only some (the rest stay in
    /// reserve), or add keys never committed to.
    fn verify_rotation_sigs(
        &self,
        raw: &[u8],
        sigs: &[Siger],
        keys: &[String],
        kt: &crate::threshold::Threshold,
    ) -> Result<(), CoreError> {
        if self.state.is_abandoned() {
            return Err(CoreError::Validation(format!(
                "identifier {} is abandoned: its last establishment event committed to no \
                 next keys, so it cannot rotate",
                self.state.prefix
            )));
        }
        let verfers = Self::verfers_from_keys(keys)?;
        Self::verify_sigs_static(raw, sigs, &verfers, kt)?;

        let prior = &self.state.next_keys;
        let mut exposed: Vec<usize> = Vec::new();
        for sig in sigs {
            let (Some(ondex), Some(key), Some(verfer)) =
                (sig.ondex(), keys.get(sig.index()), verfers.get(sig.index()))
            else {
                continue;
            };
            let Some(digest) = prior.get(ondex) else {
                continue;
            };
            if exposed.contains(&ondex)
                || !verfer.verify(raw, sig.raw()).map_err(CoreError::Crypto)?
            {
                continue;
            }
            // The digest's own code says how to digest the key (crypto
            // agility, as keripy); the commitment is over the key's qb64.
            let diger = Diger::from_qb64(digest).map_err(|e| {
                CoreError::Validation(format!("invalid prior next-key digest at {ondex}: {e}"))
            })?;
            if diger
                .verify(key.as_bytes())
                .map_err(|e| CoreError::Validation(format!("next-key digest at {ondex}: {e}")))?
            {
                exposed.push(ondex);
            }
        }
        if !self
            .state
            .next_threshold
            .is_satisfied(&exposed, prior.len())
        {
            return Err(CoreError::ThresholdNotMet);
        }
        Ok(())
    }

    /// Static helper to verify indexed signatures against a key set and threshold.
    fn verify_sigs_static(
        message: &[u8],
        sigs: &[Siger],
        verfers: &[Verfer],
        threshold: &crate::threshold::Threshold,
    ) -> Result<(), CoreError> {
        let mut satisfied_indices = Vec::new();

        for sig in sigs {
            let idx = sig.index();
            if idx >= verfers.len() {
                // Skip signatures with out-of-range indices
                continue;
            }

            let verfer = &verfers[idx];
            let valid = verfer
                .verify(message, sig.raw())
                .map_err(CoreError::Crypto)?;

            if valid && !satisfied_indices.contains(&idx) {
                satisfied_indices.push(idx);
            }
        }

        if !threshold.is_satisfied(&satisfied_indices, verfers.len()) {
            return Err(CoreError::ThresholdNotMet);
        }

        Ok(())
    }
}

/// Check an event's top-level fields against keripy's list for its type and
/// protocol version, before any field of it is trusted.
///
/// `drt` is not checked: keripy's `drt` has no `di` (and in version 1 no `c`),
/// while this crate's `DelegatedRotationEvent` requires both — a divergence
/// to resolve with delegated rotation's own conformance work.
fn check_shape(sad: &crate::sad::SadValue, ilk: &str) -> Result<(), CoreError> {
    let major = crate::fields::protocol_major(sad)?;
    crate::fields::check_keri_fields(sad, major, ilk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::said;
    use crate::version::SerializationKind;
    use affinidi_keri_crypto::{Diger, Signer};

    /// Helper: create a signer from a seed byte.
    fn make_signer(seed_byte: u8) -> Signer {
        let seed = [seed_byte; 32];
        Signer::new("A", seed.to_vec()).unwrap()
    }

    /// Fix the version string size so SAID computation is stable across
    /// Serder construction. Without this, Serder::new re-serializes with
    /// a corrected `v` field, changing the raw bytes and invalidating the SAID.
    fn fix_version_string(sad: &mut crate::sad::SadValue) {
        let placeholder = "#".repeat(44); // Blake3-256 qb64 length
        let is_self_addressing = sad.get("d") == sad.get("i");
        let orig_d = sad["d"].clone();
        let orig_i = sad["i"].clone();
        sad["d"] = crate::sad::SadValue::String(placeholder.clone());
        if is_self_addressing {
            sad["i"] = crate::sad::SadValue::String(placeholder);
        }
        let temp_raw = serde_json::to_vec(sad).unwrap();
        sad["v"] = crate::sad::SadValue::String(format!("KERI10JSON{:06x}_", temp_raw.len()));
        sad["d"] = orig_d;
        sad["i"] = orig_i;
    }

    /// Compute the next-key digest for a signer (Blake3-256 of raw public key).
    fn next_key_digest(signer: &Signer) -> String {
        Diger::from_data("E", signer.verfer().qb64().unwrap().as_bytes())
            .unwrap()
            .qb64()
            .unwrap()
    }

    /// Helper: build an inception event SAD, compute its SAID, and return the Serder.
    /// `next_signers` are the keys committed to for the first rotation.
    fn build_inception_serder(signers: &[&Signer], next_signers: &[&Signer]) -> Serder {
        let keys: Vec<String> = signers.iter().map(|s| s.verfer().qb64().unwrap()).collect();

        let next_keys: Vec<String> = next_signers.iter().map(|s| next_key_digest(s)).collect();

        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": keys.len().min(1).to_string(),
            "k": keys,
            "nt": next_keys.len().min(1).to_string(),
            "n": next_keys,
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    /// Helper: build a rotation event Serder.
    /// `signers` are the new current signing keys.
    /// `next_signers` are the keys committed to for the next rotation.
    fn build_rotation_serder(
        prefix: &str,
        sn: u64,
        prior_said: &str,
        signers: &[&Signer],
        next_signers: &[&Signer],
    ) -> Serder {
        let keys: Vec<String> = signers.iter().map(|s| s.verfer().qb64().unwrap()).collect();

        let next_keys: Vec<String> = next_signers.iter().map(|s| next_key_digest(s)).collect();

        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": prefix,
            "s": format!("{sn:x}"),
            "p": prior_said,
            "kt": keys.len().min(1).to_string(),
            "k": keys,
            "nt": next_keys.len().min(1).to_string(),
            "n": next_keys,
            "bt": "0",
            "br": [],
            "ba": [],
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    /// Helper: build an interaction event Serder.
    fn build_interaction_serder(prefix: &str, sn: u64, prior_said: &str) -> Serder {
        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "",
            "i": prefix,
            "s": format!("{sn:x}"),
            "p": prior_said,
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    #[test]
    fn test_kever_inception() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);
        let serder = build_inception_serder(&[&signer], &[&next_signer]);

        let sig = signer.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        let kever = Kever::new(&serder, &[sig], &[verfer]).unwrap();
        assert!(kever.incepted);
        assert_eq!(kever.sn(), 0);
        assert_eq!(kever.prefix(), serder.prefix().unwrap());
    }

    #[test]
    fn test_kever_inception_bad_ilk() {
        let signer = make_signer(42);
        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": "PREFIX",
            "s": "0"
        });
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        assert!(Kever::new(&serder, &[sig], &[verfer]).is_err());
    }

    #[test]
    fn test_kever_inception_bad_sig() {
        let signer = make_signer(42);
        let wrong_signer = make_signer(99);
        let next_signer = make_signer(43);
        let serder = build_inception_serder(&[&signer], &[&next_signer]);

        // Sign with the wrong key
        let sig = wrong_signer.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        assert!(Kever::new(&serder, &[sig], &[verfer]).is_err());
    }

    #[test]
    fn test_kever_inception_and_signature_verification() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);
        let serder = build_inception_serder(&[&signer], &[&next_signer]);
        let sig = signer.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        let kever = Kever::new(&serder, &[sig], &[verfer]).unwrap();

        // Verify a message
        let message = b"test message to verify";
        let msg_sig = signer.sign_indexed(message, 0, false).unwrap();
        assert!(kever.verify_sigs(message, &[msg_sig]).unwrap());
    }

    #[test]
    fn test_kever_rotation() {
        let signer1 = make_signer(42);
        let signer2 = make_signer(99);
        let signer3 = make_signer(77);

        // Inception with signer1, committing to signer2 as the next key
        let icp_serder = build_inception_serder(&[&signer1], &[&signer2]);
        let icp_sig = signer1.sign_indexed(icp_serder.raw(), 0, false).unwrap();
        let verfer1 = signer1.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer1]).unwrap();
        assert_eq!(kever.sn(), 0);
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Rotation to signer2, committing to signer3 for next rotation
        let rot_serder = build_rotation_serder(&prefix, 1, &prior_said, &[&signer2], &[&signer3]);

        // Sign the rotation with the keys it INSTALLS (signer2), which the
        // inception committed to by digest — not with the outgoing key.
        let rot_sig = signer2.sign_indexed(rot_serder.raw(), 0, false).unwrap();
        kever.update(&rot_serder, &[rot_sig]).unwrap();

        assert_eq!(kever.sn(), 1);
        // After rotation, keys should be signer2's key
        let expected_key = signer2.verfer().qb64().unwrap();
        assert_eq!(kever.state().keys, vec![expected_key]);
    }

    #[test]
    fn test_kever_interaction() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);

        // Inception
        let icp_serder = build_inception_serder(&[&signer], &[&next_signer]);
        let icp_sig = signer.sign_indexed(icp_serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer]).unwrap();
        assert_eq!(kever.sn(), 0);
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Interaction
        let ixn_serder = build_interaction_serder(&prefix, 1, &prior_said);
        let ixn_sig = signer.sign_indexed(ixn_serder.raw(), 0, false).unwrap();
        kever.update(&ixn_serder, &[ixn_sig]).unwrap();

        assert_eq!(kever.sn(), 1);
        // Keys should be unchanged after interaction
        let expected_key = signer.verfer().qb64().unwrap();
        assert_eq!(kever.state().keys, vec![expected_key]);
    }

    #[test]
    fn test_kever_out_of_order() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);

        let icp_serder = build_inception_serder(&[&signer], &[&next_signer]);
        let icp_sig = signer.sign_indexed(icp_serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer]).unwrap();
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Try interaction with sn=2 (should be 1)
        let ixn_serder = build_interaction_serder(&prefix, 2, &prior_said);
        let ixn_sig = signer.sign_indexed(ixn_serder.raw(), 0, false).unwrap();
        assert!(kever.update(&ixn_serder, &[ixn_sig]).is_err());
    }

    /// Helper: create a non-transferable signer (witness).
    fn make_witness(seed_byte: u8) -> Signer {
        let seed = [seed_byte; 32];
        Signer::new_with_transferable("A", seed.to_vec(), false).unwrap()
    }

    #[test]
    fn test_witness_receipt_valid() {
        let witness = make_witness(50);
        let prefix = witness.verfer().qb64().unwrap();
        let message = b"test event data";
        let cigar = witness.sign(message).unwrap();

        let couples = vec![(prefix.clone(), cigar.raw().to_vec())];
        let backers = vec![prefix];

        Kever::verify_witness_receipts_static(message, &couples, &backers, 1).unwrap();
    }

    #[test]
    fn test_witness_receipt_invalid_sig() {
        let witness = make_witness(50);
        let prefix = witness.verfer().qb64().unwrap();
        let message = b"test event data";

        // Sign a different message
        let cigar = witness.sign(b"wrong message").unwrap();
        let couples = vec![(prefix.clone(), cigar.raw().to_vec())];
        let backers = vec![prefix];

        assert!(Kever::verify_witness_receipts_static(message, &couples, &backers, 1).is_err());
    }

    #[test]
    fn test_witness_receipt_threshold_2_with_1_fails() {
        let w1 = make_witness(50);
        let w2 = make_witness(60);
        let p1 = w1.verfer().qb64().unwrap();
        let p2 = w2.verfer().qb64().unwrap();
        let message = b"test event data";
        let c1 = w1.sign(message).unwrap();

        let couples = vec![(p1.clone(), c1.raw().to_vec())];
        let backers = vec![p1, p2];

        assert!(Kever::verify_witness_receipts_static(message, &couples, &backers, 2).is_err());
    }

    #[test]
    fn test_witness_receipt_threshold_2_with_2_passes() {
        let w1 = make_witness(50);
        let w2 = make_witness(60);
        let p1 = w1.verfer().qb64().unwrap();
        let p2 = w2.verfer().qb64().unwrap();
        let message = b"test event data";
        let c1 = w1.sign(message).unwrap();
        let c2 = w2.sign(message).unwrap();

        let couples = vec![
            (p1.clone(), c1.raw().to_vec()),
            (p2.clone(), c2.raw().to_vec()),
        ];
        let backers = vec![p1, p2];

        Kever::verify_witness_receipts_static(message, &couples, &backers, 2).unwrap();
    }

    #[test]
    fn test_witness_receipt_threshold_0_always_passes() {
        let message = b"test event data";
        Kever::verify_witness_receipts_static(message, &[], &[], 0).unwrap();
    }

    #[test]
    fn test_witness_receipt_non_designated_ignored() {
        let w1 = make_witness(50);
        let non_designated = make_witness(70);
        let p1 = w1.verfer().qb64().unwrap();
        let p_nd = non_designated.verfer().qb64().unwrap();
        let message = b"test event data";
        let c_nd = non_designated.sign(message).unwrap();

        // Only the non-designated witness signed, but it's not in backers list
        let couples = vec![(p_nd, c_nd.raw().to_vec())];
        let backers = vec![p1];

        assert!(Kever::verify_witness_receipts_static(message, &couples, &backers, 1).is_err());
    }

    #[test]
    fn test_witness_receipt_duplicate_counted_once() {
        let w1 = make_witness(50);
        let p1 = w1.verfer().qb64().unwrap();
        let message = b"test event data";
        let c1 = w1.sign(message).unwrap();
        let c1b = w1.sign(message).unwrap();

        // Same witness signs twice — should only count once
        let couples = vec![
            (p1.clone(), c1.raw().to_vec()),
            (p1.clone(), c1b.raw().to_vec()),
        ];
        let backers = vec![p1];

        // Threshold 1 should pass (1 unique valid witness)
        Kever::verify_witness_receipts_static(message, &couples, &backers, 1).unwrap();

        // But threshold 2 should fail (only 1 unique witness)
        let w2 = make_witness(60);
        let p2 = w2.verfer().qb64().unwrap();
        let backers2 = vec![couples[0].0.clone(), p2];
        assert!(Kever::verify_witness_receipts_static(message, &couples, &backers2, 2).is_err());
    }

    #[test]
    fn test_kever_multi_key_threshold() {
        let signer1 = make_signer(10);
        let signer2 = make_signer(20);
        let signer3 = make_signer(30);

        // Build inception with 3 keys, threshold 2
        let keys: Vec<String> = [&signer1, &signer2, &signer3]
            .iter()
            .map(|s| s.verfer().qb64().unwrap())
            .collect();

        let next_keys: Vec<String> = [&signer1, &signer2, &signer3]
            .iter()
            .map(|s| next_key_digest(s))
            .collect();

        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "2",
            "k": keys,
            "nt": "2",
            "n": next_keys,
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();

        let verfers: Vec<Verfer> = [&signer1, &signer2, &signer3]
            .iter()
            .map(|s| s.verfer().clone())
            .collect();

        // Sign with only 1 signature (threshold is 2) - should fail
        let sig1 = signer1.sign_indexed(serder.raw(), 0, false).unwrap();
        assert!(Kever::new(&serder, std::slice::from_ref(&sig1), &verfers).is_err());

        // Sign with 2 signatures - should succeed
        let sig2 = signer2.sign_indexed(serder.raw(), 1, false).unwrap();
        let kever = Kever::new(&serder, &[sig1, sig2], &verfers).unwrap();
        assert!(kever.incepted);
    }

    /// Regression test: crafting a non-self-addressing inception with a spoofed
    /// prefix must be rejected. This is the exact attack vector where an attacker
    /// sets `"i"` to a victim's prefix while `"d"` is the attacker's own SAID.
    #[test]
    fn test_reject_spoofed_prefix_attack() {
        let attacker = make_signer(66);
        let attacker_next = make_signer(67);

        let keys: Vec<String> = vec![attacker.verfer().qb64().unwrap()];
        let next_keys: Vec<String> = vec![next_key_digest(&attacker_next)];

        // Victim's prefix (in a real attack this would be observed from the network)
        let victim_prefix = "EBWnTcz-EszJ6AiQ0RLBP_UdBFbDeCfP1t7O4APHxE7E";

        // Build the inception event with i = victim's prefix, d = "" (different from i).
        // compute_said will see i != d and only replace d, leaving i as the victim's prefix.
        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": victim_prefix,
            "s": "0",
            "kt": "1",
            "k": keys,
            "nt": "1",
            "n": next_keys,
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        // Verify: i != d (this is the attack — non-self-addressing with spoofed prefix)
        assert_ne!(sad["i"].as_str().unwrap(), sad["d"].as_str().unwrap());

        // SAID verification passes (the vulnerability: d is valid, i is unchecked)
        said::verify_said(&sad, "d", "E", SerializationKind::Json).unwrap();

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = attacker.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = attacker.verfer().clone();

        // The fix: Kever::new must reject this because the self-addressing
        // prefix does not match the SAID
        let result = Kever::new(&serder, &[sig], &[verfer]);
        assert!(result.is_err(), "spoofed prefix inception must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("self-addressing prefix does not match event SAID"),
            "unexpected error: {err}"
        );
    }

    /// Verify that a basic (non-self-addressing) prefix must match the first key.
    #[test]
    fn test_reject_basic_prefix_mismatch() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);

        let keys: Vec<String> = vec![signer.verfer().qb64().unwrap()];
        let next_keys: Vec<String> = vec![next_key_digest(&next_signer)];

        // Use a different key as prefix (not the signer's key)
        let wrong_signer = make_signer(99);
        let wrong_prefix = wrong_signer.verfer().qb64().unwrap();

        let mut sad = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": wrong_prefix,
            "s": "0",
            "kt": "1",
            "k": keys,
            "nt": "1",
            "n": next_keys,
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, false).unwrap();
        let verfer = signer.verfer().clone();

        let result = Kever::new(&serder, &[sig], &[verfer]);
        assert!(result.is_err(), "mismatched basic prefix must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("basic prefix does not match first public key"),
            "unexpected error: {err}"
        );
    }

    /// An establishment event with explicit thresholds. `ilk` is `icp` or
    /// `rot`; `prefix`, `sn` and `prior` are ignored for `icp`.
    #[allow(clippy::too_many_arguments)] // a test fixture, read at each call
    fn establishment(
        ilk: &str,
        prefix: &str,
        sn: u64,
        prior: &str,
        kt: crate::sad::SadValue,
        signers: &[&Signer],
        nt: crate::sad::SadValue,
        next_signers: &[&Signer],
    ) -> Serder {
        let keys: Vec<String> = signers.iter().map(|s| s.verfer().qb64().unwrap()).collect();
        let next_keys: Vec<String> = next_signers.iter().map(|s| next_key_digest(s)).collect();
        let mut sad = if ilk == "icp" {
            crate::sad!({
                "v": "KERI10JSON000000_", "t": "icp", "d": "", "i": "", "s": "0",
                "kt": kt, "k": keys, "nt": nt, "n": next_keys,
                "bt": "0", "b": [], "c": [], "a": []
            })
        } else {
            crate::sad!({
                "v": "KERI10JSON000000_", "t": "rot", "d": "", "i": prefix,
                "s": format!("{sn:x}"), "p": prior,
                "kt": kt, "k": keys, "nt": nt, "n": next_keys,
                "bt": "0", "br": [], "ba": [], "a": []
            })
        };
        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    fn sign_all(serder: &Serder, signers: &[&Signer]) -> Vec<Siger> {
        signers
            .iter()
            .enumerate()
            .map(|(i, s)| s.sign_indexed(serder.raw(), i, false).unwrap())
            .collect()
    }

    fn incept(
        kt: &str,
        signers: &[&Signer],
        nt: &str,
        next: &[&Signer],
    ) -> Result<Kever, CoreError> {
        let icp = establishment("icp", "", 0, "", kt.into(), signers, nt.into(), next);
        let verfers: Vec<Verfer> = signers.iter().map(|s| s.verfer().clone()).collect();
        Kever::new(&icp, &sign_all(&icp, signers), &verfers)
    }

    #[test]
    fn a_rotation_to_no_next_keys_abandons_the_identifier() {
        let (k0, k1, k2) = (make_signer(1), make_signer(2), make_signer(3));
        let mut kever = incept("1", &[&k0], "1", &[&k1]).unwrap();
        assert!(!kever.state().is_abandoned());
        let prefix = kever.prefix().to_string();

        let rot = establishment(
            "rot",
            &prefix,
            1,
            &kever.state().last_event_digest.clone(),
            "1".into(),
            &[&k1],
            "0".into(),
            &[],
        );
        kever.update(&rot, &sign_all(&rot, &[&k1])).unwrap();
        assert!(kever.state().is_abandoned());
        assert_eq!(
            kever.state().next_threshold,
            crate::threshold::Threshold::Simple(0)
        );

        // No interaction may follow, though the current key signs it.
        let ixn = build_interaction_serder(&prefix, 2, &kever.state().last_event_digest.clone());
        let err = kever
            .verify_update(&ixn, &sign_all(&ixn, &[&k1]))
            .unwrap_err();
        assert!(err.to_string().contains("abandoned"), "{err}");

        // Nor a rotation, whatever keys it names.
        let rot = establishment(
            "rot",
            &prefix,
            2,
            &kever.state().last_event_digest.clone(),
            "1".into(),
            &[&k2],
            "0".into(),
            &[],
        );
        let err = kever
            .verify_update(&rot, &sign_all(&rot, &[&k2]))
            .unwrap_err();
        assert!(err.to_string().contains("abandoned"), "{err}");
    }

    #[test]
    fn an_inception_with_no_next_keys_is_abandoned_from_the_start() {
        let k0 = make_signer(1);
        let kever = incept("1", &[&k0], "0", &[]).unwrap();
        assert!(kever.state().is_abandoned());
    }

    #[test]
    fn a_rotation_by_a_key_never_committed_to_does_not_meet_the_prior_threshold() {
        let k0 = make_signer(1);
        let n0 = make_signer(10);
        let stranger = make_signer(99);
        let kever = incept("1", &[&k0], "1", &[&n0]).unwrap();
        let prefix = kever.prefix().to_string();
        let prior = kever.state().last_event_digest.clone();
        let rot = establishment(
            "rot",
            &prefix,
            1,
            &prior,
            "1".into(),
            &[&stranger],
            "1".into(),
            &[&k0],
        );
        // Its own `kt` is met; the stranger exposes no committed digest.
        let sigs = vec![stranger.sign_indexed(rot.raw(), 0, false).unwrap()];
        assert!(matches!(
            kever.verify_update(&rot, &sigs),
            Err(CoreError::ThresholdNotMet)
        ));
    }

    #[test]
    fn a_rotation_may_reveal_part_of_its_commitment_and_add_keys() {
        // n = [H(A), H(B), H(C)] under nt 2. The rotation reveals C and A, in
        // that order, keeps B in reserve, and adds X: the signatures of C and
        // A expose positions 2 and 0, which meet the prior nt.
        let k0 = make_signer(1);
        let (a, b, c, x) = (
            make_signer(10),
            make_signer(11),
            make_signer(12),
            make_signer(13),
        );
        let mut kever = incept("1", &[&k0], "2", &[&a, &b, &c]).unwrap();
        let prefix = kever.prefix().to_string();
        let prior = kever.state().last_event_digest.clone();
        let rot = establishment(
            "rot",
            &prefix,
            1,
            &prior,
            "2".into(),
            &[&c, &a, &x],
            "1".into(),
            &[&k0],
        );
        let both = |s: &Signer, index: usize, ondex: usize| {
            let raw = s.sign_indexed(rot.raw(), index, false).unwrap();
            Siger::new_with_verfer(
                if index == ondex { "A" } else { "2A" },
                index,
                Some(ondex),
                raw.raw().to_vec(),
                s.verfer().clone(),
            )
            .unwrap()
        };
        // One signature meets neither kt 2 nor nt 2.
        let only_c = vec![both(&c, 0, 2)];
        assert!(kever.verify_update(&rot, &only_c).is_err());
        // C and the uncommitted X meet kt, but expose one position.
        let c_and_x = vec![both(&c, 0, 2), x.sign_indexed(rot.raw(), 2, true).unwrap()];
        assert!(matches!(
            kever.verify_update(&rot, &c_and_x),
            Err(CoreError::ThresholdNotMet)
        ));
        // A signature claiming the wrong committed position exposes nothing.
        let wrong = vec![both(&c, 0, 0), both(&a, 1, 2)];
        assert!(matches!(
            kever.verify_update(&rot, &wrong),
            Err(CoreError::ThresholdNotMet)
        ));
        // C and A, each naming its committed position.
        let right = vec![both(&c, 0, 2), both(&a, 1, 0)];
        kever.update(&rot, &right).unwrap();
        assert_eq!(kever.state().keys.len(), 3);
    }

    #[test]
    fn a_rotation_must_meet_the_prior_next_threshold() {
        let k0 = make_signer(1);
        let (n0, n1, n2) = (make_signer(10), make_signer(11), make_signer(12));
        let mut kever = incept("1", &[&k0], "2", &[&n0, &n1, &n2]).unwrap();
        let prefix = kever.prefix().to_string();
        let prior = kever.state().last_event_digest.clone();

        // The rotation lowers its own `kt` to 1 and carries one signature:
        // its own threshold is met, the pre-committed 2-of-3 is not.
        let rot = establishment(
            "rot",
            &prefix,
            1,
            &prior,
            "1".into(),
            &[&n0, &n1, &n2],
            "1".into(),
            &[&k0],
        );
        let one = vec![n0.sign_indexed(rot.raw(), 0, false).unwrap()];
        assert!(matches!(
            kever.verify_update(&rot, &one),
            Err(CoreError::ThresholdNotMet)
        ));
        let (raw, sad) = (rot.raw().to_vec(), rot.sad().clone());
        assert!(matches!(
            kever.verify_update_owned(&raw, sad, &one),
            Err(CoreError::ThresholdNotMet)
        ));

        // Two of the three meet both.
        let two = vec![
            n0.sign_indexed(rot.raw(), 0, false).unwrap(),
            n2.sign_indexed(rot.raw(), 2, false).unwrap(),
        ];
        kever.update(&rot, &two).unwrap();
        assert_eq!(kever.sn(), 1);
    }

    #[test]
    fn thresholds_must_fit_their_key_lists() {
        let (k0, k1) = (make_signer(1), make_signer(2));
        let cases: [(&str, &str, &[&Signer], &str); 4] = [
            ("1", "0", &[&k1], "nt 0 beside next-key digests"),
            ("1", "1", &[], "a non-zero nt with no next keys"),
            ("2", "1", &[&k1], "kt above the key count"),
            ("1", "2", &[&k1], "nt above the next-key count"),
        ];
        for (kt, nt, next, why) in cases {
            let icp = establishment("icp", "", 0, "", kt.into(), &[&k0], nt.into(), next);
            let state = KeyState::from_inception(&icp.sad().deserialize_into().unwrap());
            assert!(state.is_err(), "{why} was accepted");
        }

        // A zero signing threshold is refused, both by the signature check
        // and by key state.
        assert!(incept("0", &[&k0], "1", &[&k1]).is_err());
        let icp = establishment("icp", "", 0, "", "0".into(), &[&k0], "1".into(), &[&k1]);
        assert!(KeyState::from_inception(&icp.sad().deserialize_into().unwrap()).is_err());

        // A weighted threshold that every key together cannot meet.
        let icp = establishment(
            "icp",
            "",
            0,
            "",
            crate::sad!([["1/3", "1/3"]]),
            &[&k0, &k1],
            "1".into(),
            &[&k1],
        );
        assert!(KeyState::from_inception(&icp.sad().deserialize_into().unwrap()).is_err());
    }
}
