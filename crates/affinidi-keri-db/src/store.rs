//! Abstract storage trait for KERI data.

use crate::error::DbError;

/// Abstract storage interface for KERI event logs, state, and associated data.
///
/// Implementations provide persistence for:
/// - Key Event Logs (KEL): ordered sequence of events per identifier
/// - Key state: current derived state for each identifier
/// - Signatures: controller and witness signatures for events
/// - Receipts: non-transferable and transferable receipts
/// - Escrow: out-of-order and partially-signed events
/// - Identifier metadata: hab configuration and management data
pub trait KeriStore: Send + Sync {
    // --- Event storage ---

    /// Store a serialized event by its SAID.
    fn put_event(&self, said: &str, event: &[u8]) -> Result<(), DbError>;

    /// Get a serialized event by its SAID.
    fn get_event(&self, said: &str) -> Result<Option<Vec<u8>>, DbError>;

    /// Append a SAID to the Key Event Log for a prefix.
    fn append_kel(&self, prefix: &str, sn: u64, said: &str) -> Result<(), DbError>;

    /// Get the SAID at a given sequence number in the KEL.
    fn get_kel_said(&self, prefix: &str, sn: u64) -> Result<Option<String>, DbError>;

    /// Get all SAIDs in the KEL for a prefix, ordered by sequence number.
    fn get_kel(&self, prefix: &str) -> Result<Vec<(u64, String)>, DbError>;

    // --- First seen log ---

    /// Record the first-seen ordering for an event.
    fn put_first_seen(&self, prefix: &str, sn: u64, said: &str) -> Result<(), DbError>;

    /// Get the first-seen SAID at a sequence number.
    fn get_first_seen(&self, prefix: &str, sn: u64) -> Result<Option<String>, DbError>;

    // --- Timestamp ---

    /// Store a datetime stamp for an event SAID.
    fn put_datetime(&self, said: &str, dt: &str) -> Result<(), DbError>;

    /// Get the datetime stamp for an event SAID.
    fn get_datetime(&self, said: &str) -> Result<Option<String>, DbError>;

    // --- Signatures ---

    /// Store controller signatures for an event SAID.
    fn put_signatures(&self, said: &str, sigs: &[u8]) -> Result<(), DbError>;

    /// Get controller signatures for an event SAID.
    fn get_signatures(&self, said: &str) -> Result<Option<Vec<u8>>, DbError>;

    /// Store witness signatures for an event SAID.
    fn put_witness_sigs(&self, said: &str, sigs: &[u8]) -> Result<(), DbError>;

    /// Get witness signatures for an event SAID.
    fn get_witness_sigs(&self, said: &str) -> Result<Option<Vec<u8>>, DbError>;

    // --- Receipts ---

    /// Store receipt couples (prefix + signature) for an event SAID.
    fn put_receipts(&self, said: &str, rcts: &[u8]) -> Result<(), DbError>;

    /// Get receipt couples for an event SAID.
    fn get_receipts(&self, said: &str) -> Result<Option<Vec<u8>>, DbError>;

    // --- Key state ---

    /// Store the current key state for a prefix (serialized JSON).
    fn put_state(&self, prefix: &str, state: &[u8]) -> Result<(), DbError>;

    /// Get the current key state for a prefix.
    fn get_state(&self, prefix: &str) -> Result<Option<Vec<u8>>, DbError>;

    // --- Escrow ---

    /// Store an out-of-order escrowed event.
    fn put_escrow_ooo(&self, prefix: &str, sn: u64, event: &[u8]) -> Result<(), DbError>;

    /// Get out-of-order escrowed events for a prefix/sn.
    fn get_escrow_ooo(&self, prefix: &str, sn: u64) -> Result<Option<Vec<u8>>, DbError>;

    /// Remove an out-of-order escrowed event.
    fn del_escrow_ooo(&self, prefix: &str, sn: u64) -> Result<(), DbError>;

    /// Store a partially-signed escrowed event.
    fn put_escrow_ps(&self, prefix: &str, sn: u64, event: &[u8]) -> Result<(), DbError>;

    /// Get partially-signed escrowed events.
    fn get_escrow_ps(&self, prefix: &str, sn: u64) -> Result<Option<Vec<u8>>, DbError>;

    /// Remove a partially-signed escrowed event.
    fn del_escrow_ps(&self, prefix: &str, sn: u64) -> Result<(), DbError>;

    // --- Hab management ---

    /// Store hab (identifier) configuration data.
    fn put_hab(&self, name: &str, data: &[u8]) -> Result<(), DbError>;

    /// Get hab configuration data.
    fn get_hab(&self, name: &str) -> Result<Option<Vec<u8>>, DbError>;

    /// List all hab names.
    fn list_habs(&self) -> Result<Vec<String>, DbError>;

    /// Delete hab configuration data.
    fn del_hab(&self, name: &str) -> Result<(), DbError>;

    // --- Maintenance ---

    /// Get the latest sequence number for a prefix.
    fn latest_sn(&self, prefix: &str) -> Result<Option<u64>, DbError>;

    // --- Batch operations ---

    /// Store an event with its KEL entry, first-seen record, and optional signatures
    /// in a single atomic operation.
    ///
    /// # Safety
    /// Implementations **must** perform all writes within a single transaction.
    /// Partial writes (e.g. event stored but KEL entry missing) leave the
    /// database in an inconsistent state that can cause panics on reload.
    fn store_event(
        &self,
        said: &str,
        event: &[u8],
        prefix: &str,
        sn: u64,
        sigs: Option<&[u8]>,
    ) -> Result<(), DbError>;

    /// Store an event (as in [`store_event`](Self::store_event)) plus hab metadata
    /// in a single atomic operation.
    ///
    /// See [`store_event`](Self::store_event) for atomicity requirements.
    fn store_event_with_hab(
        &self,
        said: &str,
        event: &[u8],
        prefix: &str,
        sn: u64,
        sigs: Option<&[u8]>,
        hab_name: &str,
        hab_data: &[u8],
    ) -> Result<(), DbError>;
}
