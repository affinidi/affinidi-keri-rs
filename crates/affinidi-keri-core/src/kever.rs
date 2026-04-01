//! Kever: Key Event Verifier.
//!
//! A Kever tracks the verified state of a single KERI identifier
//! by processing its key event log (KEL). It validates signatures,
//! sequence numbers, and prior event digests.

use affinidi_keri_crypto::{Siger, Verfer};

use crate::error::CoreError;
use crate::event::{InceptionEvent, InteractionEvent, RotationEvent};
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
        if ilk != "icp" {
            return Err(CoreError::UnexpectedIlk(format!(
                "expected 'icp', got '{ilk}'"
            )));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        // Parse the inception event from the SAD
        let icp: InceptionEvent =
            serde_json::from_value(serder.sad().clone()).map_err(CoreError::Json)?;

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
        Self::verify_sigs_static(
            serder.raw(),
            sigs,
            verfers,
            &icp.keys_threshold.0,
        )?;

        // Derive initial key state
        let state = KeyState::from_inception(&icp)?;

        Ok(Self {
            state,
            incepted: true,
        })
    }

    /// Create a new Kever from pre-parsed parts, taking ownership of the SAD.
    ///
    /// Same validation as [`new`], but avoids cloning the JSON `Value` for
    /// `serde_json::from_value`. Use when the caller has already consumed the
    /// SAD from a `Serder` via [`Serder::take_sad`].
    pub fn new_from_parts(
        raw: &[u8],
        sad: serde_json::Value,
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

        let icp: InceptionEvent =
            serde_json::from_value(sad).map_err(CoreError::Json)?;

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

        let state = KeyState::from_inception(&icp)?;

        Ok(Self {
            state,
            incepted: true,
        })
    }

    /// Process the next event in the KEL.
    ///
    /// Handles rotation and interaction events. Validates that:
    /// - The sequence number is exactly current_sn + 1
    /// - The prior SAID matches the last event digest
    /// - Signatures satisfy the current signing threshold
    ///
    /// # Errors
    /// Returns `CoreError` if the event is invalid or out of order.
    pub fn update(&mut self, serder: &Serder, sigs: &[Siger]) -> Result<(), CoreError> {
        if !self.incepted {
            return Err(CoreError::Validation(
                "kever not initialized with inception event".into(),
            ));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        let ilk = serder.ilk()?;
        let sn = serder.sn()?;

        // Sequence number must be exactly current + 1
        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        // Build verfers from current keys for signature verification
        let verfers = self.build_verfers()?;

        // Verify signatures against current keys
        Self::verify_sigs_static(
            serder.raw(),
            sigs,
            &verfers,
            &self.state.threshold,
        )?;

        match ilk.as_str() {
            "rot" => {
                let rot: RotationEvent =
                    serde_json::from_value(serder.sad().clone()).map_err(CoreError::Json)?;
                self.state = self.state.apply_rotation(&rot)?;
            }
            "ixn" => {
                let ixn: InteractionEvent =
                    serde_json::from_value(serder.sad().clone()).map_err(CoreError::Json)?;
                self.state = self.state.apply_interaction(&ixn)?;
            }
            _ => {
                return Err(CoreError::UnexpectedIlk(format!(
                    "expected 'rot' or 'ixn' for update, got '{ilk}'"
                )));
            }
        }

        Ok(())
    }

    /// Verify the next event without mutating the Kever, returning the proposed
    /// new `KeyState` on success.
    ///
    /// This avoids cloning the entire Kever for rollback support: the caller
    /// can inspect the proposed state (e.g. to verify witness receipts) before
    /// committing with [`apply_verified_update`].
    pub fn verify_update(
        &self,
        serder: &Serder,
        sigs: &[Siger],
    ) -> Result<KeyState, CoreError> {
        if !self.incepted {
            return Err(CoreError::Validation(
                "kever not initialized with inception event".into(),
            ));
        }

        // Verify SAID integrity before trusting any event fields
        serder.verify_said("E")?;

        let ilk = serder.ilk()?;
        let sn = serder.sn()?;

        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        let verfers = self.build_verfers()?;
        Self::verify_sigs_static(serder.raw(), sigs, &verfers, &self.state.threshold)?;

        let new_state = match ilk.as_str() {
            "rot" => {
                let rot: RotationEvent =
                    serde_json::from_value(serder.sad().clone()).map_err(CoreError::Json)?;
                self.state.apply_rotation(&rot)?
            }
            "ixn" => {
                let ixn: InteractionEvent =
                    serde_json::from_value(serder.sad().clone()).map_err(CoreError::Json)?;
                self.state.apply_interaction(&ixn)?
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
        sad: serde_json::Value,
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

        if sn != self.state.sn + 1 {
            return Err(CoreError::OutOfOrder {
                expected: self.state.sn + 1,
                got: sn,
            });
        }

        let verfers = self.build_verfers()?;
        Self::verify_sigs_static(raw, sigs, &verfers, &self.state.threshold)?;

        let new_state = match ilk.as_str() {
            "rot" => {
                let rot: RotationEvent =
                    serde_json::from_value(sad).map_err(CoreError::Json)?;
                self.state.apply_rotation(&rot)?
            }
            "ixn" => {
                let ixn: InteractionEvent =
                    serde_json::from_value(sad).map_err(CoreError::Json)?;
                self.state.apply_interaction(&ixn)?
            }
            _ => {
                return Err(CoreError::UnexpectedIlk(format!(
                    "expected 'rot' or 'ixn' for update, got '{ilk}'"
                )));
            }
        };

        Ok(new_state)
    }

    /// Apply a previously verified update (from [`verify_update`]).
    pub fn apply_verified_update(&mut self, new_state: KeyState) {
        self.state = new_state;
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

    /// Build Verfer instances from the current key state's key list.
    fn build_verfers(&self) -> Result<Vec<Verfer>, CoreError> {
        let mut verfers = Vec::with_capacity(self.state.keys.len());
        for key_qb64 in &self.state.keys {
            let verfer = Verfer::from_qb64(key_qb64).map_err(CoreError::Crypto)?;
            verfers.push(verfer);
        }
        Ok(verfers)
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
    fn fix_version_string(sad: &mut serde_json::Value) {
        let placeholder = "#".repeat(44); // Blake3-256 qb64 length
        let is_self_addressing = sad.get("d") == sad.get("i");
        let orig_d = sad["d"].clone();
        let orig_i = sad["i"].clone();
        sad["d"] = serde_json::Value::String(placeholder.clone());
        if is_self_addressing {
            sad["i"] = serde_json::Value::String(placeholder);
        }
        let temp_raw = serde_json::to_vec(sad).unwrap();
        sad["v"] = serde_json::Value::String(format!("KERI10JSON{:06x}_", temp_raw.len()));
        sad["d"] = orig_d;
        sad["i"] = orig_i;
    }

    /// Compute the next-key digest for a signer (Blake3-256 of raw public key).
    fn next_key_digest(signer: &Signer) -> String {
        Diger::from_data("E", signer.verfer().raw())
            .unwrap()
            .qb64()
            .unwrap()
    }

    /// Helper: build an inception event SAD, compute its SAID, and return the Serder.
    /// `next_signers` are the keys committed to for the first rotation.
    fn build_inception_serder(signers: &[&Signer], next_signers: &[&Signer]) -> Serder {
        let keys: Vec<String> = signers
            .iter()
            .map(|s| s.verfer().qb64().unwrap())
            .collect();

        let next_keys: Vec<String> = next_signers
            .iter()
            .map(|s| next_key_digest(s))
            .collect();

        let mut sad = serde_json::json!({
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
        let keys: Vec<String> = signers
            .iter()
            .map(|s| s.verfer().qb64().unwrap())
            .collect();

        let next_keys: Vec<String> = next_signers
            .iter()
            .map(|s| next_key_digest(s))
            .collect();

        let mut sad = serde_json::json!({
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
            "c": [],
            "a": []
        });

        fix_version_string(&mut sad);
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    /// Helper: build an interaction event Serder.
    fn build_interaction_serder(prefix: &str, sn: u64, prior_said: &str) -> Serder {
        let mut sad = serde_json::json!({
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

        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let verfer = signer.verfer().clone();

        let kever = Kever::new(&serder, &[sig], &[verfer]).unwrap();
        assert!(kever.incepted);
        assert_eq!(kever.sn(), 0);
        assert_eq!(kever.prefix(), serder.prefix().unwrap());
    }

    #[test]
    fn test_kever_inception_bad_ilk() {
        let signer = make_signer(42);
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": "PREFIX",
            "s": "0"
        });
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
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
        let sig = wrong_signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let verfer = signer.verfer().clone();

        assert!(Kever::new(&serder, &[sig], &[verfer]).is_err());
    }

    #[test]
    fn test_kever_inception_and_signature_verification() {
        let signer = make_signer(42);
        let next_signer = make_signer(43);
        let serder = build_inception_serder(&[&signer], &[&next_signer]);
        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let verfer = signer.verfer().clone();

        let kever = Kever::new(&serder, &[sig], &[verfer]).unwrap();

        // Verify a message
        let message = b"test message to verify";
        let msg_sig = signer.sign_indexed(message, 0, true).unwrap();
        assert!(kever.verify_sigs(message, &[msg_sig]).unwrap());
    }

    #[test]
    fn test_kever_rotation() {
        let signer1 = make_signer(42);
        let signer2 = make_signer(99);
        let signer3 = make_signer(77);

        // Inception with signer1, committing to signer2 as the next key
        let icp_serder = build_inception_serder(&[&signer1], &[&signer2]);
        let icp_sig = signer1.sign_indexed(icp_serder.raw(), 0, true).unwrap();
        let verfer1 = signer1.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer1]).unwrap();
        assert_eq!(kever.sn(), 0);
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Rotation to signer2, committing to signer3 for next rotation
        let rot_serder =
            build_rotation_serder(&prefix, 1, &prior_said, &[&signer2], &[&signer3]);

        // Sign rotation with CURRENT keys (signer1)
        let rot_sig = signer1.sign_indexed(rot_serder.raw(), 0, true).unwrap();
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
        let icp_sig = signer.sign_indexed(icp_serder.raw(), 0, true).unwrap();
        let verfer = signer.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer]).unwrap();
        assert_eq!(kever.sn(), 0);
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Interaction
        let ixn_serder = build_interaction_serder(&prefix, 1, &prior_said);
        let ixn_sig = signer.sign_indexed(ixn_serder.raw(), 0, true).unwrap();
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
        let icp_sig = signer.sign_indexed(icp_serder.raw(), 0, true).unwrap();
        let verfer = signer.verfer().clone();

        let mut kever = Kever::new(&icp_serder, &[icp_sig], &[verfer]).unwrap();
        let prefix = kever.prefix().to_string();
        let prior_said = kever.state().last_event_digest.clone();

        // Try interaction with sn=2 (should be 1)
        let ixn_serder = build_interaction_serder(&prefix, 2, &prior_said);
        let ixn_sig = signer.sign_indexed(ixn_serder.raw(), 0, true).unwrap();
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

        let mut sad = serde_json::json!({
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
        let sig1 = signer1.sign_indexed(serder.raw(), 0, true).unwrap();
        assert!(Kever::new(&serder, &[sig1.clone()], &verfers).is_err());

        // Sign with 2 signatures - should succeed
        let sig2 = signer2.sign_indexed(serder.raw(), 1, true).unwrap();
        let kever = Kever::new(&serder, &[sig1, sig2], &verfers).unwrap();
        assert!(kever.incepted);
    }
}
