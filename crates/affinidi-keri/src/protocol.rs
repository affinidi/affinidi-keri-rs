//! The KERI protocol version an identifier's events are written in.
//!
//! A key event log may move up a version (a v1 log continued in v2) but never
//! down: the verifier refuses a decrease, so a builder that produced one would
//! only produce an event nobody accepts.

use affinidi_keri_core::version::{SerializationKind, Version};
use serde::{Deserialize, Serialize};

use crate::error::KeriError;

/// A KERI protocol version this library writes.
///
/// Events are written with JSON bodies in either version. A version 2 event
/// is framed the way keripy publishes one: a genus-version counter, the body,
/// then its signatures inside an attachment group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// KERI 1.0, the version every log written before 0.6 is in.
    #[serde(rename = "1.0")]
    V1,
    /// KERI 2.0 (genus 2.0), keripy's default.
    #[serde(rename = "2.0")]
    V2,
}

impl ProtocolVersion {
    /// The version of a log whose persisted state names none: everything
    /// written before 0.6 was version 1.
    pub(crate) fn legacy() -> Self {
        Self::V1
    }

    /// The major version number.
    pub fn major(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// A JSON version string of this version with a zero size: the right
    /// length to size an event before its real size is known.
    pub(crate) fn placeholder(self) -> String {
        match self {
            Self::V1 => Version::default_v1(SerializationKind::Json, 0),
            Self::V2 => Version::default_v2(SerializationKind::Json, 0),
        }
        .to_version_string()
    }

    /// Refuse to move a log from `current` to `self` if that goes down a
    /// version.
    pub(crate) fn check_from(self, current: Self) -> Result<(), KeriError> {
        if self < current {
            return Err(KeriError::Config(format!(
                "a key event log in KERI {}.0 cannot continue in {}.0: a log never goes down a version",
                current.major(),
                self.major()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_have_each_versions_length() {
        assert_eq!(ProtocolVersion::V1.placeholder(), "KERI10JSON000000_");
        assert_eq!(ProtocolVersion::V2.placeholder().len(), 19);
        assert!(ProtocolVersion::V2.placeholder().starts_with("KERICAA"));
    }

    #[test]
    fn a_log_moves_up_but_not_down() {
        assert!(ProtocolVersion::V2.check_from(ProtocolVersion::V1).is_ok());
        assert!(ProtocolVersion::V2.check_from(ProtocolVersion::V2).is_ok());
        assert!(ProtocolVersion::V1.check_from(ProtocolVersion::V2).is_err());
    }

    #[test]
    fn serializes_as_the_version_number() {
        assert_eq!(
            serde_json::to_string(&ProtocolVersion::V2).unwrap(),
            "\"2.0\""
        );
        let v: ProtocolVersion = serde_json::from_str("\"1.0\"").unwrap();
        assert_eq!(v, ProtocolVersion::V1);
    }
}
