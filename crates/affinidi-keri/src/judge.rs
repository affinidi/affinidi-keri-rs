//! KERI Judge with duplicity detection.
//!
//! A Judge enforces the **first-seen policy**: for each `(prefix, sn)` pair it
//! remembers the SAID of the first valid event it processed.  If a second,
//! different-but-valid event arrives at the same `(prefix, sn)`, the Judge
//! flags the prefix as **duplicitous** and records the evidence in the
//! Duplicitous Event Log (DEL).

use std::collections::{HashMap, HashSet};

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, ParsedMessage};
use affinidi_keri_db::KeriStore;

use crate::direct::{self, ProcessResult};
use crate::error::KeriError;

/// The trust verdict for a prefix as determined by the Judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The prefix has a consistent, verified KEL.
    Trusted,
    /// The prefix has been caught producing conflicting events.
    Duplicitous,
    /// The Judge has not yet seen any events for this prefix.
    Unknown,
}

/// Evidence of duplicity: two different valid events at the same `(prefix, sn)`.
#[derive(Debug, Clone)]
pub struct DuplicityEvidence {
    /// The identifier prefix that committed duplicity.
    pub prefix: String,
    /// The sequence number at which the conflict occurred.
    pub sn: u64,
    /// The SAID of the first-seen event.
    pub first_seen_said: String,
    /// The SAID of the conflicting event.
    pub duplicitous_said: String,
    /// The raw serialized event body of the first-seen event.
    pub first_seen_event: Vec<u8>,
    /// The raw serialized event body of the conflicting event.
    pub duplicitous_event: Vec<u8>,
}

/// The result of submitting a message to the Judge.
#[derive(Debug)]
pub enum JudgeResult {
    /// The event was accepted (first-seen at this `(prefix, sn)`).
    Accepted(ProcessResult),
    /// The event is an idempotent replay of an already-accepted event.
    DuplicateAccepted,
    /// The event is valid but conflicts with the first-seen event — duplicity!
    DuplicityDetected(DuplicityEvidence),
}

/// A KERI Judge that enforces the first-seen policy and detects duplicity.
///
/// The `duplicitous` set and `del` vector are maintained together: any prefix
/// in `duplicitous` has at least one entry in `del`, and vice versa. All
/// mutations go through [`record_duplicity`](Self::record_duplicity).
pub struct Judge {
    store: Box<dyn KeriStore>,
    kevers: HashMap<String, Kever>,
    duplicitous: HashSet<String>,
    del: Vec<DuplicityEvidence>,
}

impl Judge {
    /// Create a new Judge backed by the given store.
    pub fn new(store: Box<dyn KeriStore>) -> Self {
        Self {
            store,
            kevers: HashMap::new(),
            duplicitous: HashSet::new(),
            del: Vec::new(),
        }
    }

    /// Process an incoming message, enforcing the first-seen policy.
    ///
    /// 1. Pre-parse to extract prefix, sn, said, ilk.
    /// 2. For `rct` messages: pass through to `direct::process_parsed`.
    /// 3. Check `store.get_first_seen(prefix, sn)`:
    ///    - `None` → delegate to `direct::process_parsed`, return `Accepted`.
    ///    - `Some(same_said)` → idempotent replay, return `DuplicateAccepted`.
    ///    - `Some(different_said)` → verify the new event independently;
    ///      if valid, record duplicity evidence and return `DuplicityDetected`.
    pub fn process(&mut self, data: &[u8]) -> Result<JudgeResult, KeriError> {
        // Parse once — reused for both inspection and processing.
        let (parsed, _consumed) = parser::parse_next(data)?;

        let prefix = parsed.serder.prefix()?;
        let sn = parsed.serder.sn()?;
        let said = parsed.serder.said()?;
        let ilk = parsed.serder.ilk()?;

        // Receipts don't affect key state — just pass through.
        if ilk == "rct" {
            let result =
                direct::process_parsed(parsed, self.store.as_ref(), &mut self.kevers)?;
            return Ok(JudgeResult::Accepted(result));
        }

        // Check the first-seen log BEFORE calling process_parsed,
        // because LMDB put is an upsert that would silently overwrite.
        let first_seen = self.store.get_first_seen(&prefix, sn)?;

        match first_seen {
            None => {
                // No prior event at this (prefix, sn) — accept normally.
                let result =
                    direct::process_parsed(parsed, self.store.as_ref(), &mut self.kevers)?;
                Ok(JudgeResult::Accepted(result))
            }
            Some(ref existing_said) if existing_said == &said => {
                // Same SAID — idempotent replay, nothing to do.
                Ok(JudgeResult::DuplicateAccepted)
            }
            Some(ref existing_said) => {
                // Different SAID at the same (prefix, sn) — potential duplicity.
                // Verify the new event independently to confirm it's valid
                // (not just a corrupt/forged message).
                // verify_for_duplicity uses the old Kever::new / verify_sigs path
                // (cold path — clone cost is irrelevant for duplicity detection).
                self.verify_for_duplicity(&parsed, existing_said)
            }
        }
    }

    /// Verify a conflicting event independently to confirm genuine duplicity.
    fn verify_for_duplicity(
        &mut self,
        parsed: &ParsedMessage,
        existing_said: &str,
    ) -> Result<JudgeResult, KeriError> {
        let serder = &parsed.serder;
        let prefix = serder.prefix()?;
        let sn = serder.sn()?;
        let said = serder.said()?;
        let ilk = serder.ilk()?;

        let controller_sigs = direct::extract_controller_sigs(&parsed.attachments);

        // Trial-verify the new event without committing to the store.
        match ilk.as_str() {
            "icp" | "dip" => {
                let verfers = direct::verfers_from_serder(serder)?;

                // Kever::new verifies signatures — if it succeeds the event is valid.
                Kever::new(serder, &controller_sigs, &verfers)?;
            }
            "rot" | "ixn" | "drt" => {
                // Verify signatures against the current key state.
                // This works for ixn (keys unchanged) and for rot when
                // the signing keys are the same as the current kever's.
                if let Some(kever) = self.kevers.get(&prefix) {
                    kever.verify_sigs(serder.raw(), &controller_sigs)?;
                } else {
                    return Err(KeriError::NotFound(format!(
                        "no kever for prefix {prefix}"
                    )));
                }
            }
            _ => {
                return Err(KeriError::Config(format!(
                    "unexpected ilk for duplicity check: {ilk}"
                )));
            }
        }

        // The new event is cryptographically valid — this is genuine duplicity.
        let first_seen_event = self
            .store
            .get_event(existing_said)?
            .ok_or_else(|| {
                KeriError::NotFound(format!(
                    "first-seen event {existing_said} missing from store"
                ))
            })?;

        let evidence = DuplicityEvidence {
            prefix: prefix.clone(),
            sn,
            first_seen_said: existing_said.to_string(),
            duplicitous_said: said,
            first_seen_event,
            duplicitous_event: serder.raw().to_vec(),
        };

        Ok(JudgeResult::DuplicityDetected(self.record_duplicity(evidence)))
    }

    /// Record duplicity evidence and flag the prefix.
    ///
    /// Maintains the invariant that `self.duplicitous` contains exactly the
    /// set of prefixes that appear in `self.del`.
    fn record_duplicity(&mut self, evidence: DuplicityEvidence) -> DuplicityEvidence {
        self.duplicitous.insert(evidence.prefix.clone());
        self.del.push(evidence.clone());
        evidence
    }

    /// Return the trust verdict for a prefix.
    pub fn verdict(&self, prefix: &str) -> Verdict {
        if self.duplicitous.contains(prefix) {
            Verdict::Duplicitous
        } else if self.kevers.contains_key(prefix) {
            Verdict::Trusted
        } else {
            Verdict::Unknown
        }
    }

    /// Check whether a prefix has been flagged as duplicitous.
    pub fn is_duplicitous(&self, prefix: &str) -> bool {
        self.duplicitous.contains(prefix)
    }

    /// Return all duplicity evidence for a given prefix.
    pub fn evidence_for(&self, prefix: &str) -> Vec<&DuplicityEvidence> {
        self.del.iter().filter(|e| e.prefix == prefix).collect()
    }

    /// Return the full Duplicitous Event Log.
    pub fn del(&self) -> &[DuplicityEvidence] {
        &self.del
    }

    /// Return the Judge's kever map.
    pub fn kevers(&self) -> &HashMap<String, Kever> {
        &self.kevers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InceptionConfig;
    use crate::hab::Hab;
    use affinidi_keri_db::lmdb::LmdbStore;

    fn temp_store() -> Box<LmdbStore> {
        let dir = tempfile::tempdir().unwrap();
        Box::new(LmdbStore::open(dir.path()).unwrap())
    }

    /// Helper: create a Hab with the given salt in its own store, returning
    /// the Hab, inception message, and the store (kept alive).
    fn make_hab(
        name: &str,
        salt: [u8; 16],
    ) -> (Hab, Vec<u8>, Box<LmdbStore>) {
        let store = temp_store();
        let config = InceptionConfig::builder()
            .salt(salt.to_vec())
            .build();
        let (hab, msg) = Hab::incept(name, &config, store.as_ref()).unwrap();
        (hab, msg, store)
    }

    #[test]
    fn test_judge_accepts_inception() {
        let (_, icp_msg, _hab_store) = make_hab("alice", [0x01; 16]);

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        match judge.process(&icp_msg).unwrap() {
            JudgeResult::Accepted(r) => {
                assert_eq!(r.ilk, "icp");
                assert_eq!(r.sn, 0);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn test_judge_accepts_interaction() {
        let (mut hab, icp_msg, hab_store) = make_hab("alice", [0x01; 16]);

        let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
        let ixn_msg = hab.interact(&[anchor], hab_store.as_ref()).unwrap();

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        // Process inception first
        judge.process(&icp_msg).unwrap();

        // Process interaction
        match judge.process(&ixn_msg).unwrap() {
            JudgeResult::Accepted(r) => {
                assert_eq!(r.ilk, "ixn");
                assert_eq!(r.sn, 1);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn test_judge_detects_duplicity() {
        // Two Habs with identical salt → same prefix and keys.
        let (mut hab1, icp_msg, hab1_store) = make_hab("hab1", [0xDE; 16]);
        let (mut hab2, _, hab2_store) = make_hab("hab2", [0xDE; 16]);

        // Sanity: same prefix
        assert_eq!(hab1.prefix(), hab2.prefix());

        // Each produces a different ixn at sn=1
        let anchor_a = serde_json::json!({"d": "EAnchorA_document_hash_AAAAAAAAAAAAA"});
        let anchor_b = serde_json::json!({"d": "EAnchorB_document_hash_BBBBBBBBBBBBB"});
        let ixn_a = hab1.interact(&[anchor_a], hab1_store.as_ref()).unwrap();
        let ixn_b = hab2.interact(&[anchor_b], hab2_store.as_ref()).unwrap();

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        // Judge accepts inception
        judge.process(&icp_msg).unwrap();

        // Judge accepts first ixn
        match judge.process(&ixn_a).unwrap() {
            JudgeResult::Accepted(r) => assert_eq!(r.sn, 1),
            other => panic!("expected Accepted, got {other:?}"),
        }

        // Judge detects duplicity on second ixn
        match judge.process(&ixn_b).unwrap() {
            JudgeResult::DuplicityDetected(ev) => {
                assert_eq!(ev.prefix, hab1.prefix());
                assert_eq!(ev.sn, 1);
                assert_ne!(ev.first_seen_said, ev.duplicitous_said);
            }
            other => panic!("expected DuplicityDetected, got {other:?}"),
        }
    }

    #[test]
    fn test_judge_idempotent_replay() {
        let (_, icp_msg, _hab_store) = make_hab("alice", [0x01; 16]);

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        // First time → accepted
        judge.process(&icp_msg).unwrap();

        // Second time → duplicate accepted
        match judge.process(&icp_msg).unwrap() {
            JudgeResult::DuplicateAccepted => {}
            other => panic!("expected DuplicateAccepted, got {other:?}"),
        }
    }

    #[test]
    fn test_judge_verdict_transitions() {
        let (mut hab1, icp_msg, hab1_store) = make_hab("hab1", [0xDE; 16]);
        let (mut hab2, _, hab2_store) = make_hab("hab2", [0xDE; 16]);
        let prefix = hab1.prefix().to_string();

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        // Before any events
        assert_eq!(judge.verdict(&prefix), Verdict::Unknown);

        // After inception
        judge.process(&icp_msg).unwrap();
        assert_eq!(judge.verdict(&prefix), Verdict::Trusted);

        // After duplicity
        let anchor_a = serde_json::json!({"d": "EAnchorA_document_hash_AAAAAAAAAAAAA"});
        let anchor_b = serde_json::json!({"d": "EAnchorB_document_hash_BBBBBBBBBBBBB"});
        let ixn_a = hab1.interact(&[anchor_a], hab1_store.as_ref()).unwrap();
        let ixn_b = hab2.interact(&[anchor_b], hab2_store.as_ref()).unwrap();

        judge.process(&ixn_a).unwrap();
        judge.process(&ixn_b).unwrap();
        assert_eq!(judge.verdict(&prefix), Verdict::Duplicitous);
    }

    #[test]
    fn test_judge_evidence_retrieval() {
        let (mut hab1, icp_msg, hab1_store) = make_hab("hab1", [0xDE; 16]);
        let (mut hab2, _, hab2_store) = make_hab("hab2", [0xDE; 16]);
        let prefix = hab1.prefix().to_string();

        let judge_store = temp_store();
        let mut judge = Judge::new(judge_store);

        judge.process(&icp_msg).unwrap();

        let anchor_a = serde_json::json!({"d": "EAnchorA_document_hash_AAAAAAAAAAAAA"});
        let anchor_b = serde_json::json!({"d": "EAnchorB_document_hash_BBBBBBBBBBBBB"});
        let ixn_a = hab1.interact(&[anchor_a], hab1_store.as_ref()).unwrap();
        let ixn_b = hab2.interact(&[anchor_b], hab2_store.as_ref()).unwrap();

        judge.process(&ixn_a).unwrap();
        judge.process(&ixn_b).unwrap();

        // evidence_for returns the right entries
        let evidence = judge.evidence_for(&prefix);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].sn, 1);
        assert!(!evidence[0].first_seen_event.is_empty());
        assert!(!evidence[0].duplicitous_event.is_empty());

        // DEL has the same entry
        assert_eq!(judge.del().len(), 1);

        // An unrelated prefix has no evidence
        assert!(judge.evidence_for("ENonExistent________________________________").is_empty());
    }
}
