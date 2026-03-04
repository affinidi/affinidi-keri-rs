//! LMDB-backed implementation of the KeriStore trait.

use std::fs;
use std::path::{Path, PathBuf};

use heed::types::*;
use heed::{Database, Env, EnvOpenOptions};

use crate::error::DbError;
use crate::keys;
use crate::store::KeriStore;

/// Maximum LMDB map size (1 GiB).
const MAX_MAP_SIZE: usize = 1024 * 1024 * 1024;

/// Maximum number of named databases.
const MAX_DBS: u32 = 20;

/// LMDB-backed storage for KERI data.
///
/// Uses separate named databases (sub-databases) for different data types,
/// all within a single LMDB environment for atomic cross-database transactions.
pub struct LmdbStore {
    #[allow(dead_code)]
    path: PathBuf,
    env: Env,
    /// Serialized events keyed by SAID
    evts: Database<Str, Bytes>,
    /// KEL: keyed by prefix.sn -> SAID
    kels: Database<Str, Str>,
    /// First-seen log: keyed by prefix.sn -> SAID
    fels: Database<Str, Str>,
    /// Datetime stamps: keyed by SAID -> ISO datetime string
    dtss: Database<Str, Str>,
    /// Controller signatures: keyed by SAID -> raw CESR bytes
    sigs: Database<Str, Bytes>,
    /// Witness signatures: keyed by SAID -> raw CESR bytes
    wigs: Database<Str, Bytes>,
    /// Receipts: keyed by SAID -> raw CESR bytes
    rcts: Database<Str, Bytes>,
    /// Key state: keyed by prefix -> serialized state
    states: Database<Str, Bytes>,
    /// Out-of-order escrow: keyed by prefix.sn -> event bytes
    ooes: Database<Str, Bytes>,
    /// Partially-signed escrow: keyed by prefix.sn -> event bytes
    pses: Database<Str, Bytes>,
    /// Hab data: keyed by name -> serialized config
    habs: Database<Str, Bytes>,
}

impl LmdbStore {
    /// Open or create an LMDB store at the given path.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        fs::create_dir_all(path)
            .map_err(|e| DbError::Database(format!("failed to create db dir: {e}")))?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(MAX_MAP_SIZE)
                .max_dbs(MAX_DBS)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;

        let evts = env.create_database(&mut wtxn, Some("evts"))?;
        let kels = env.create_database(&mut wtxn, Some("kels"))?;
        let fels = env.create_database(&mut wtxn, Some("fels"))?;
        let dtss = env.create_database(&mut wtxn, Some("dtss"))?;
        let sigs = env.create_database(&mut wtxn, Some("sigs"))?;
        let wigs = env.create_database(&mut wtxn, Some("wigs"))?;
        let rcts = env.create_database(&mut wtxn, Some("rcts"))?;
        let states = env.create_database(&mut wtxn, Some("states"))?;
        let ooes = env.create_database(&mut wtxn, Some("ooes"))?;
        let pses = env.create_database(&mut wtxn, Some("pses"))?;
        let habs = env.create_database(&mut wtxn, Some("habs"))?;

        wtxn.commit()?;

        Ok(Self {
            path: path.to_path_buf(),
            env,
            evts,
            kels,
            fels,
            dtss,
            sigs,
            wigs,
            rcts,
            states,
            ooes,
            pses,
            habs,
        })
    }

    /// Open a temporary store for testing.
    #[cfg(test)]
    pub fn open_temp() -> Result<Self, DbError> {
        let dir = tempfile::tempdir()
            .map_err(|e| DbError::Database(format!("failed to create temp dir: {e}")))?;
        Self::open(dir.path())
    }
}

impl KeriStore for LmdbStore {
    fn put_event(&self, said: &str, event: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.evts.put(&mut wtxn, said, event)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_event(&self, said: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.evts.get(&rtxn, said)?.map(|b| b.to_vec()))
    }

    fn append_kel(&self, prefix: &str, sn: u64, said: &str) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.kels.put(&mut wtxn, &key, said)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_kel_said(&self, prefix: &str, sn: u64) -> Result<Option<String>, DbError> {
        let key = keys::sn_key(prefix, sn);
        let rtxn = self.env.read_txn()?;
        Ok(self.kels.get(&rtxn, &key)?.map(|s| s.to_string()))
    }

    fn get_kel(&self, prefix: &str) -> Result<Vec<(u64, String)>, DbError> {
        let rtxn = self.env.read_txn()?;
        let prefix_dot = format!("{prefix}.");
        let mut results = Vec::new();

        let iter = self.kels.iter(&rtxn)?;
        for item in iter {
            let (key, said) = item?;
            if key.starts_with(&prefix_dot)
                && let Some(sn) = keys::split_sn(key)
            {
                results.push((sn, said.to_string()));
            }
        }
        results.sort_by_key(|(sn, _)| *sn);
        Ok(results)
    }

    fn put_first_seen(&self, prefix: &str, sn: u64, said: &str) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.fels.put(&mut wtxn, &key, said)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_first_seen(&self, prefix: &str, sn: u64) -> Result<Option<String>, DbError> {
        let key = keys::sn_key(prefix, sn);
        let rtxn = self.env.read_txn()?;
        Ok(self.fels.get(&rtxn, &key)?.map(|s| s.to_string()))
    }

    fn put_datetime(&self, said: &str, dt: &str) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.dtss.put(&mut wtxn, said, dt)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_datetime(&self, said: &str) -> Result<Option<String>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.dtss.get(&rtxn, said)?.map(|s| s.to_string()))
    }

    fn put_signatures(&self, said: &str, sigs: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.sigs.put(&mut wtxn, said, sigs)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_signatures(&self, said: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.sigs.get(&rtxn, said)?.map(|b| b.to_vec()))
    }

    fn put_witness_sigs(&self, said: &str, sigs: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.wigs.put(&mut wtxn, said, sigs)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_witness_sigs(&self, said: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.wigs.get(&rtxn, said)?.map(|b| b.to_vec()))
    }

    fn put_receipts(&self, said: &str, rcts: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.rcts.put(&mut wtxn, said, rcts)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_receipts(&self, said: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.rcts.get(&rtxn, said)?.map(|b| b.to_vec()))
    }

    fn put_state(&self, prefix: &str, state: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.states.put(&mut wtxn, prefix, state)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_state(&self, prefix: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.states.get(&rtxn, prefix)?.map(|b| b.to_vec()))
    }

    fn put_escrow_ooo(&self, prefix: &str, sn: u64, event: &[u8]) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.ooes.put(&mut wtxn, &key, event)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_escrow_ooo(&self, prefix: &str, sn: u64) -> Result<Option<Vec<u8>>, DbError> {
        let key = keys::sn_key(prefix, sn);
        let rtxn = self.env.read_txn()?;
        Ok(self.ooes.get(&rtxn, &key)?.map(|b| b.to_vec()))
    }

    fn del_escrow_ooo(&self, prefix: &str, sn: u64) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.ooes.delete(&mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(())
    }

    fn put_escrow_ps(&self, prefix: &str, sn: u64, event: &[u8]) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.pses.put(&mut wtxn, &key, event)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_escrow_ps(&self, prefix: &str, sn: u64) -> Result<Option<Vec<u8>>, DbError> {
        let key = keys::sn_key(prefix, sn);
        let rtxn = self.env.read_txn()?;
        Ok(self.pses.get(&rtxn, &key)?.map(|b| b.to_vec()))
    }

    fn del_escrow_ps(&self, prefix: &str, sn: u64) -> Result<(), DbError> {
        let key = keys::sn_key(prefix, sn);
        let mut wtxn = self.env.write_txn()?;
        self.pses.delete(&mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(())
    }

    fn put_hab(&self, name: &str, data: &[u8]) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.habs.put(&mut wtxn, name, data)?;
        wtxn.commit()?;
        Ok(())
    }

    fn get_hab(&self, name: &str) -> Result<Option<Vec<u8>>, DbError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.habs.get(&rtxn, name)?.map(|b| b.to_vec()))
    }

    fn list_habs(&self) -> Result<Vec<String>, DbError> {
        let rtxn = self.env.read_txn()?;
        let mut names = Vec::new();
        let iter = self.habs.iter(&rtxn)?;
        for item in iter {
            let (key, _) = item?;
            names.push(key.to_string());
        }
        Ok(names)
    }

    fn del_hab(&self, name: &str) -> Result<(), DbError> {
        let mut wtxn = self.env.write_txn()?;
        self.habs.delete(&mut wtxn, name)?;
        wtxn.commit()?;
        Ok(())
    }

    fn latest_sn(&self, prefix: &str) -> Result<Option<u64>, DbError> {
        let kel = self.get_kel(prefix)?;
        Ok(kel.last().map(|(sn, _)| *sn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> LmdbStore {
        let dir = tempfile::tempdir().unwrap();
        LmdbStore::open(dir.path()).unwrap()
    }

    #[test]
    fn test_event_roundtrip() {
        let store = temp_store();
        let said = "Eabcdef123456";
        let event = b"test event data";

        store.put_event(said, event).unwrap();
        let retrieved = store.get_event(said).unwrap().unwrap();
        assert_eq!(retrieved, event);
    }

    #[test]
    fn test_event_not_found() {
        let store = temp_store();
        assert!(store.get_event("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_kel_operations() {
        let store = temp_store();
        let prefix = "DPRE";

        store.append_kel(prefix, 0, "Esaid0").unwrap();
        store.append_kel(prefix, 1, "Esaid1").unwrap();
        store.append_kel(prefix, 2, "Esaid2").unwrap();

        assert_eq!(store.get_kel_said(prefix, 0).unwrap(), Some("Esaid0".to_string()));
        assert_eq!(store.get_kel_said(prefix, 1).unwrap(), Some("Esaid1".to_string()));
        assert_eq!(store.get_kel_said(prefix, 2).unwrap(), Some("Esaid2".to_string()));
        assert!(store.get_kel_said(prefix, 3).unwrap().is_none());

        let kel = store.get_kel(prefix).unwrap();
        assert_eq!(kel.len(), 3);
        assert_eq!(kel[0], (0, "Esaid0".to_string()));
        assert_eq!(kel[2], (2, "Esaid2".to_string()));
    }

    #[test]
    fn test_signatures_roundtrip() {
        let store = temp_store();
        let said = "Esaid";
        let sigs = b"signature data bytes";

        store.put_signatures(said, sigs).unwrap();
        let retrieved = store.get_signatures(said).unwrap().unwrap();
        assert_eq!(retrieved, sigs);
    }

    #[test]
    fn test_state_roundtrip() {
        let store = temp_store();
        let prefix = "DPRE";
        let state = b"{\"prefix\":\"DPRE\",\"sn\":0}";

        store.put_state(prefix, state).unwrap();
        let retrieved = store.get_state(prefix).unwrap().unwrap();
        assert_eq!(retrieved, state);
    }

    #[test]
    fn test_escrow_ooo() {
        let store = temp_store();
        let prefix = "DPRE";

        store.put_escrow_ooo(prefix, 5, b"ooo event").unwrap();
        assert_eq!(
            store.get_escrow_ooo(prefix, 5).unwrap().unwrap(),
            b"ooo event"
        );

        store.del_escrow_ooo(prefix, 5).unwrap();
        assert!(store.get_escrow_ooo(prefix, 5).unwrap().is_none());
    }

    #[test]
    fn test_hab_operations() {
        let store = temp_store();

        store.put_hab("alice", b"alice config").unwrap();
        store.put_hab("bob", b"bob config").unwrap();

        assert_eq!(
            store.get_hab("alice").unwrap().unwrap(),
            b"alice config"
        );

        let names = store.list_habs().unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"alice".to_string()));
        assert!(names.contains(&"bob".to_string()));

        store.del_hab("alice").unwrap();
        assert!(store.get_hab("alice").unwrap().is_none());
    }

    #[test]
    fn test_latest_sn() {
        let store = temp_store();
        let prefix = "DPRE";

        assert!(store.latest_sn(prefix).unwrap().is_none());

        store.append_kel(prefix, 0, "Esaid0").unwrap();
        assert_eq!(store.latest_sn(prefix).unwrap(), Some(0));

        store.append_kel(prefix, 1, "Esaid1").unwrap();
        assert_eq!(store.latest_sn(prefix).unwrap(), Some(1));
    }

    #[test]
    fn test_datetime_roundtrip() {
        let store = temp_store();
        store.put_datetime("Esaid", "2024-01-01T00:00:00Z").unwrap();
        assert_eq!(
            store.get_datetime("Esaid").unwrap().unwrap(),
            "2024-01-01T00:00:00Z"
        );
    }
}
