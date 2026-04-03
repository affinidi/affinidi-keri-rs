//! Habery: multi-identifier manager.
//!
//! The Habery is a registry of Hab instances, providing a single entry
//! point for managing multiple KERI identifiers backed by a shared store.

use std::collections::HashMap;

use affinidi_keri_db::KeriStore;

use crate::config::{InceptionConfig, RotationConfig};
use crate::error::KeriError;
use crate::hab::Hab;

/// Multi-identifier manager backed by a shared store.
pub struct Habery {
    store: Box<dyn KeriStore>,
    habs: HashMap<String, Hab>,
}

impl Habery {
    /// Create a new Habery with the given store.
    pub fn new(store: Box<dyn KeriStore>) -> Self {
        Self {
            store,
            habs: HashMap::new(),
        }
    }

    /// Create a new identifier via inception and register it.
    ///
    /// Returns the composed inception message bytes.
    pub fn incept(&mut self, name: &str, config: &InceptionConfig) -> Result<Vec<u8>, KeriError> {
        if self.habs.contains_key(name) {
            return Err(KeriError::AlreadyExists(name.to_string()));
        }

        let (hab, msg) = Hab::incept(name, config, self.store.as_ref())?;
        self.habs.insert(name.to_string(), hab);
        Ok(msg)
    }

    /// Get a reference to a Hab by name.
    pub fn get(&self, name: &str) -> Option<&Hab> {
        self.habs.get(name)
    }

    /// Get a mutable reference to a Hab by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Hab> {
        self.habs.get_mut(name)
    }

    /// Rotate the keys of the named identifier.
    ///
    /// Returns the composed rotation message bytes.
    pub fn rotate(&mut self, name: &str, config: &RotationConfig) -> Result<Vec<u8>, KeriError> {
        let hab = self
            .habs
            .get_mut(name)
            .ok_or_else(|| KeriError::NotFound(name.to_string()))?;
        hab.rotate(config, self.store.as_ref())
    }

    /// Create an interaction event for the named identifier.
    ///
    /// Returns the composed interaction message bytes.
    pub fn interact(
        &mut self,
        name: &str,
        anchors: &[serde_json::Value],
    ) -> Result<Vec<u8>, KeriError> {
        let hab = self
            .habs
            .get_mut(name)
            .ok_or_else(|| KeriError::NotFound(name.to_string()))?;
        hab.interact(anchors, self.store.as_ref())
    }

    /// List all registered Hab names.
    pub fn list(&self) -> Vec<&str> {
        self.habs.keys().map(|s| s.as_str()).collect()
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &dyn KeriStore {
        self.store.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_keri_db::lmdb::LmdbStore;

    fn temp_habery() -> Habery {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbStore::open(dir.path()).unwrap();
        Habery::new(Box::new(store))
    }

    #[test]
    fn test_habery_incept() {
        let mut habery = temp_habery();
        let config = InceptionConfig::default();
        let msg = habery.incept("alice", &config).unwrap();
        assert!(!msg.is_empty());

        let hab = habery.get("alice").unwrap();
        assert_eq!(hab.name(), "alice");
        assert_eq!(hab.sn(), 0);
    }

    #[test]
    fn test_habery_multi_identifier() {
        let mut habery = temp_habery();
        let config = InceptionConfig::default();

        habery.incept("alice", &config).unwrap();
        habery.incept("bob", &config).unwrap();
        habery.incept("carol", &config).unwrap();

        let names = habery.list();
        assert_eq!(names.len(), 3);
        assert!(habery.get("alice").is_some());
        assert!(habery.get("bob").is_some());
        assert!(habery.get("carol").is_some());

        // Prefixes should all be different (random salts)
        let alice_prefix = habery.get("alice").unwrap().prefix().to_string();
        let bob_prefix = habery.get("bob").unwrap().prefix().to_string();
        let carol_prefix = habery.get("carol").unwrap().prefix().to_string();
        assert_ne!(alice_prefix, bob_prefix);
        assert_ne!(bob_prefix, carol_prefix);
    }

    #[test]
    fn test_habery_duplicate_name() {
        let mut habery = temp_habery();
        let config = InceptionConfig::default();

        habery.incept("alice", &config).unwrap();
        let result = habery.incept("alice", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_habery_rotate() {
        let mut habery = temp_habery();
        let icp_config = InceptionConfig::default();
        habery.incept("alice", &icp_config).unwrap();

        let rot_config = RotationConfig::default();
        let rot_msg = habery.rotate("alice", &rot_config).unwrap();
        assert!(!rot_msg.is_empty());

        let hab = habery.get("alice").unwrap();
        assert_eq!(hab.sn(), 1);
    }

    #[test]
    fn test_habery_interact() {
        let mut habery = temp_habery();
        let icp_config = InceptionConfig::default();
        habery.incept("alice", &icp_config).unwrap();

        let anchor = serde_json::json!({"d": "ETestDigest_____________________________"});
        let ixn_msg = habery.interact("alice", &[anchor]).unwrap();
        assert!(!ixn_msg.is_empty());

        let hab = habery.get("alice").unwrap();
        assert_eq!(hab.sn(), 1);
    }

    #[test]
    fn test_habery_not_found() {
        let mut habery = temp_habery();
        let rot_config = RotationConfig::default();

        let result = habery.rotate("nonexistent", &rot_config);
        assert!(result.is_err());

        let result = habery.interact("nonexistent", &[]);
        assert!(result.is_err());
    }
}
