//! Escrow management for out-of-order and partially-signed events.
//!
//! Events that cannot be immediately verified (e.g., missing prior events,
//! insufficient signatures) are held in escrow until they can be processed.

use std::collections::HashMap;

use crate::serder::Serder;

/// An event that has been verified for controller signatures but is
/// waiting for enough witness receipts to meet the backer threshold.
#[derive(Debug)]
pub struct PartiallyWitnessedEntry {
    /// The serialized event.
    pub serder: Serder,
    /// Controller signatures (raw CESR bytes).
    pub signatures: Vec<u8>,
    /// Collected witness receipt couples: (prefix_qb64, sig_raw).
    pub receipts: Vec<(String, Vec<u8>)>,
    /// Required backer threshold.
    pub backer_threshold: usize,
    /// Timestamp when the event was escrowed.
    pub escrowed_at: chrono::DateTime<chrono::Utc>,
}

/// An escrowed event waiting to be processed.
#[derive(Debug)]
pub struct EscrowedEvent {
    /// The serialized event.
    pub serder: Serder,
    /// Collected signature attachments (raw CESR bytes).
    pub signatures: Vec<u8>,
    /// Timestamp when the event was escrowed.
    pub escrowed_at: chrono::DateTime<chrono::Utc>,
}

/// Maximum total entries across all escrow categories to prevent resource exhaustion.
const MAX_ESCROW_ENTRIES: usize = 10_000;

/// Maximum number of entries per (prefix, sn) key in out-of-order and
/// partially-signed escrows to prevent per-key resource exhaustion.
const MAX_ENTRIES_PER_KEY: usize = 16;

/// Maximum number of witness receipts that can be accumulated for a
/// single partially-witnessed event.
const MAX_ATTACHMENT_COUNT: usize = 4096;

/// Escrow manager for pending events.
#[derive(Debug)]
pub struct Escrow {
    /// Out-of-order events keyed by (prefix, sequence number).
    pub out_of_order: HashMap<(String, u64), Vec<EscrowedEvent>>,
    /// Partially-signed events keyed by (prefix, sequence number).
    pub partially_signed: HashMap<(String, u64), Vec<EscrowedEvent>>,
    /// Events verified for controller signatures but awaiting enough
    /// witness receipts to meet the backer threshold.
    pub partially_witnessed: HashMap<(String, u64), PartiallyWitnessedEntry>,
}

impl Escrow {
    /// Create a new empty escrow manager.
    pub fn new() -> Self {
        Self {
            out_of_order: HashMap::new(),
            partially_signed: HashMap::new(),
            partially_witnessed: HashMap::new(),
        }
    }

    /// Total number of entries across all escrow categories.
    pub fn total_count(&self) -> usize {
        self.out_of_order_count()
            + self.partially_signed_count()
            + self.partially_witnessed_count()
    }

    /// Add an out-of-order event to escrow.
    ///
    /// Events are stored keyed by (prefix, sn) so they can be retrieved
    /// when the preceding events arrive. Silently drops the event if
    /// escrow limits are exceeded.
    pub fn escrow_out_of_order(
        &mut self,
        prefix: &str,
        sn: u64,
        serder: Serder,
        signatures: Vec<u8>,
    ) {
        if self.total_count() >= MAX_ESCROW_ENTRIES {
            return;
        }
        let key = (prefix.to_string(), sn);
        let entries = self.out_of_order.entry(key).or_default();
        if entries.len() >= MAX_ENTRIES_PER_KEY {
            return;
        }
        entries.push(EscrowedEvent {
            serder,
            signatures,
            escrowed_at: chrono::Utc::now(),
        });
    }

    /// Add a partially-signed event to escrow.
    ///
    /// Events are stored until enough signatures accumulate to meet
    /// the signing threshold. Silently drops the event if
    /// escrow limits are exceeded.
    pub fn escrow_partially_signed(
        &mut self,
        prefix: &str,
        sn: u64,
        serder: Serder,
        signatures: Vec<u8>,
    ) {
        if self.total_count() >= MAX_ESCROW_ENTRIES {
            return;
        }
        let key = (prefix.to_string(), sn);
        let entries = self.partially_signed.entry(key).or_default();
        if entries.len() >= MAX_ENTRIES_PER_KEY {
            return;
        }
        entries.push(EscrowedEvent {
            serder,
            signatures,
            escrowed_at: chrono::Utc::now(),
        });
    }

    /// Retrieve out-of-order events that are now in sequence.
    ///
    /// Returns events where `sn == current_sn + 1` for the given prefix,
    /// removing them from escrow.
    pub fn process_escrow(&mut self, prefix: &str, current_sn: u64) -> Vec<EscrowedEvent> {
        let key = (prefix.to_string(), current_sn + 1);
        self.out_of_order.remove(&key).unwrap_or_default()
    }

    /// Escrow an event that needs more witness receipts.
    pub fn escrow_partially_witnessed(
        &mut self,
        prefix: &str,
        sn: u64,
        serder: Serder,
        signatures: Vec<u8>,
        backer_threshold: usize,
    ) {
        let key = (prefix.to_string(), sn);
        let entry = PartiallyWitnessedEntry {
            serder,
            signatures,
            receipts: Vec::new(),
            backer_threshold,
            escrowed_at: chrono::Utc::now(),
        };
        self.partially_witnessed.insert(key, entry);
    }

    /// Add a witness receipt couple to an escrowed partially-witnessed event.
    ///
    /// Returns `true` if the entry was found and the receipt was added.
    /// Returns `false` if the entry was not found or the receipt limit
    /// has been reached.
    pub fn add_witness_receipt(
        &mut self,
        prefix: &str,
        sn: u64,
        witness_prefix: String,
        sig_raw: Vec<u8>,
    ) -> bool {
        let key = (prefix.to_string(), sn);
        if let Some(entry) = self.partially_witnessed.get_mut(&key) {
            if entry.receipts.len() >= MAX_ATTACHMENT_COUNT {
                return false;
            }
            entry.receipts.push((witness_prefix, sig_raw));
            true
        } else {
            false
        }
    }

    /// Check if a partially-witnessed event has enough receipts and remove it
    /// from escrow if so.
    ///
    /// Returns `Some(entry)` if the threshold is met, `None` otherwise.
    pub fn check_and_promote_witnessed(
        &mut self,
        prefix: &str,
        sn: u64,
    ) -> Option<PartiallyWitnessedEntry> {
        let key = (prefix.to_string(), sn);
        if let Some(entry) = self.partially_witnessed.get(&key) {
            // Count unique valid witness prefixes
            let mut unique = Vec::new();
            for (wp, _) in &entry.receipts {
                if !unique.contains(wp) {
                    unique.push(wp.clone());
                }
            }
            if unique.len() >= entry.backer_threshold {
                return self.partially_witnessed.remove(&key);
            }
        }
        None
    }

    /// Return the number of partially-witnessed events currently escrowed.
    pub fn partially_witnessed_count(&self) -> usize {
        self.partially_witnessed.len()
    }

    /// Remove stale escrowed events older than the given duration.
    ///
    /// This prevents the escrow from growing unboundedly when events
    /// never become processable.
    pub fn prune(&mut self, max_age: chrono::Duration) {
        let cutoff = chrono::Utc::now() - max_age;

        Self::prune_map(&mut self.out_of_order, cutoff);
        Self::prune_map(&mut self.partially_signed, cutoff);
        self.partially_witnessed
            .retain(|_, entry| entry.escrowed_at >= cutoff);
    }

    /// Remove entries older than `cutoff` from a map.
    fn prune_map(
        map: &mut HashMap<(String, u64), Vec<EscrowedEvent>>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) {
        for events in map.values_mut() {
            events.retain(|e| e.escrowed_at >= cutoff);
        }
        map.retain(|_, events| !events.is_empty());
    }

    /// Return the number of out-of-order events currently escrowed.
    pub fn out_of_order_count(&self) -> usize {
        self.out_of_order.values().map(|v| v.len()).sum()
    }

    /// Return the number of partially-signed events currently escrowed.
    pub fn partially_signed_count(&self) -> usize {
        self.partially_signed.values().map(|v| v.len()).sum()
    }
}

impl Default for Escrow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::SerializationKind;

    fn make_test_serder(ilk: &str, prefix: &str, sn: u64) -> Serder {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": ilk,
            "d": "",
            "i": prefix,
            "s": format!("{sn:x}"),
        });
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    #[test]
    fn test_escrow_out_of_order() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("ixn", "PREFIX", 3);

        escrow.escrow_out_of_order("PREFIX", 3, serder, vec![0xAB]);
        assert_eq!(escrow.out_of_order_count(), 1);

        // Process at sn=2 should retrieve the event at sn=3
        let events = escrow.process_escrow("PREFIX", 2);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signatures, vec![0xAB]);

        // Should be removed after processing
        assert_eq!(escrow.out_of_order_count(), 0);
    }

    #[test]
    fn test_escrow_out_of_order_wrong_sn() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("ixn", "PREFIX", 5);

        escrow.escrow_out_of_order("PREFIX", 5, serder, vec![]);

        // Process at sn=2 looks for sn=3, not sn=5
        let events = escrow.process_escrow("PREFIX", 2);
        assert!(events.is_empty());
        assert_eq!(escrow.out_of_order_count(), 1);
    }

    #[test]
    fn test_escrow_partially_signed() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("icp", "PREFIX", 0);

        escrow.escrow_partially_signed("PREFIX", 0, serder, vec![0x01, 0x02]);
        assert_eq!(escrow.partially_signed_count(), 1);
    }

    #[test]
    fn test_escrow_multiple_events_same_key() {
        let mut escrow = Escrow::new();

        let serder1 = make_test_serder("ixn", "PREFIX", 2);
        let serder2 = make_test_serder("ixn", "PREFIX", 2);

        escrow.escrow_out_of_order("PREFIX", 2, serder1, vec![0x01]);
        escrow.escrow_out_of_order("PREFIX", 2, serder2, vec![0x02]);
        assert_eq!(escrow.out_of_order_count(), 2);

        let events = escrow.process_escrow("PREFIX", 1);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_escrow_prune() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("ixn", "PREFIX", 5);

        // Create an event that was escrowed "in the past"
        let old_event = EscrowedEvent {
            serder,
            signatures: vec![],
            escrowed_at: chrono::Utc::now() - chrono::Duration::hours(2),
        };
        escrow
            .out_of_order
            .entry(("PREFIX".into(), 5))
            .or_default()
            .push(old_event);
        assert_eq!(escrow.out_of_order_count(), 1);

        // Prune events older than 1 hour
        escrow.prune(chrono::Duration::hours(1));
        assert_eq!(escrow.out_of_order_count(), 0);
    }

    #[test]
    fn test_escrow_prune_keeps_recent() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("ixn", "PREFIX", 5);

        escrow.escrow_out_of_order("PREFIX", 5, serder, vec![]);
        assert_eq!(escrow.out_of_order_count(), 1);

        // Prune events older than 1 hour - recent event should remain
        escrow.prune(chrono::Duration::hours(1));
        assert_eq!(escrow.out_of_order_count(), 1);
    }

    #[test]
    fn test_escrow_default() {
        let escrow = Escrow::default();
        assert_eq!(escrow.out_of_order_count(), 0);
        assert_eq!(escrow.partially_signed_count(), 0);
        assert_eq!(escrow.partially_witnessed_count(), 0);
    }

    #[test]
    fn test_partially_witnessed_escrow_and_promote() {
        let mut escrow = Escrow::new();
        let serder = make_test_serder("icp", "PREFIX", 0);

        escrow.escrow_partially_witnessed("PREFIX", 0, serder, vec![0x01], 2);
        assert_eq!(escrow.partially_witnessed_count(), 1);

        // Not enough receipts yet
        assert!(escrow.check_and_promote_witnessed("PREFIX", 0).is_none());

        // Add first receipt
        assert!(escrow.add_witness_receipt("PREFIX", 0, "BWit1".into(), vec![0xAA]));
        assert!(escrow.check_and_promote_witnessed("PREFIX", 0).is_none());

        // Add second receipt
        assert!(escrow.add_witness_receipt("PREFIX", 0, "BWit2".into(), vec![0xBB]));
        let entry = escrow.check_and_promote_witnessed("PREFIX", 0);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.receipts.len(), 2);
        assert_eq!(escrow.partially_witnessed_count(), 0);
    }

    #[test]
    fn test_partially_witnessed_add_to_missing() {
        let mut escrow = Escrow::new();
        // Adding a receipt for a non-existent entry returns false
        assert!(!escrow.add_witness_receipt("MISSING", 0, "BWit".into(), vec![0xAA]));
    }
}
