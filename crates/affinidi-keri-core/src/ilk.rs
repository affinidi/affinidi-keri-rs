//! KERI event type identifiers (ilks).
//!
//! Each KERI message has a type tag (the "ilk") that identifies what kind
//! of event or message it represents. Ilks are serialized as 3-character
//! lowercase strings.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

/// The event type identifier for a KERI message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ilk {
    /// Inception event.
    Icp,
    /// Rotation event.
    Rot,
    /// Interaction event.
    Ixn,
    /// Delegated inception event.
    Dip,
    /// Delegated rotation event.
    Drt,
    /// Receipt (non-transferable).
    Rct,
    /// Query message.
    Qry,
    /// Reply message.
    Rpy,
    /// Exchange message.
    Exn,
}

impl Ilk {
    /// Return the 3-character ilk tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Rot => "rot",
            Self::Ixn => "ixn",
            Self::Dip => "dip",
            Self::Drt => "drt",
            Self::Rct => "rct",
            Self::Qry => "qry",
            Self::Rpy => "rpy",
            Self::Exn => "exn",
        }
    }

    /// Parse from a 3-character tag string.
    pub fn from_tag(tag: &str) -> Result<Self, CoreError> {
        match tag {
            "icp" => Ok(Self::Icp),
            "rot" => Ok(Self::Rot),
            "ixn" => Ok(Self::Ixn),
            "dip" => Ok(Self::Dip),
            "drt" => Ok(Self::Drt),
            "rct" => Ok(Self::Rct),
            "qry" => Ok(Self::Qry),
            "rpy" => Ok(Self::Rpy),
            "exn" => Ok(Self::Exn),
            _ => Err(CoreError::UnexpectedIlk(tag.to_string())),
        }
    }

    /// Returns `true` if this is an establishment event (icp, rot, dip, drt).
    pub fn is_establishment(&self) -> bool {
        matches!(self, Self::Icp | Self::Rot | Self::Dip | Self::Drt)
    }

    /// All known ilk variants.
    pub fn all() -> &'static [Ilk] {
        &[
            Self::Icp,
            Self::Rot,
            Self::Ixn,
            Self::Dip,
            Self::Drt,
            Self::Rct,
            Self::Qry,
            Self::Rpy,
            Self::Exn,
        ]
    }
}

impl fmt::Display for Ilk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag())
    }
}

impl Serialize for Ilk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.tag())
    }
}

impl<'de> Deserialize<'de> for Ilk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_tag(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_roundtrip() {
        for ilk in Ilk::all() {
            let tag = ilk.tag();
            let parsed = Ilk::from_tag(tag).unwrap();
            assert_eq!(*ilk, parsed);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Ilk::Icp), "icp");
        assert_eq!(format!("{}", Ilk::Rot), "rot");
        assert_eq!(format!("{}", Ilk::Ixn), "ixn");
        assert_eq!(format!("{}", Ilk::Dip), "dip");
        assert_eq!(format!("{}", Ilk::Drt), "drt");
        assert_eq!(format!("{}", Ilk::Rct), "rct");
        assert_eq!(format!("{}", Ilk::Qry), "qry");
        assert_eq!(format!("{}", Ilk::Rpy), "rpy");
        assert_eq!(format!("{}", Ilk::Exn), "exn");
    }

    #[test]
    fn test_is_establishment() {
        assert!(Ilk::Icp.is_establishment());
        assert!(Ilk::Rot.is_establishment());
        assert!(Ilk::Dip.is_establishment());
        assert!(Ilk::Drt.is_establishment());
        assert!(!Ilk::Ixn.is_establishment());
        assert!(!Ilk::Rct.is_establishment());
        assert!(!Ilk::Qry.is_establishment());
        assert!(!Ilk::Rpy.is_establishment());
        assert!(!Ilk::Exn.is_establishment());
    }

    #[test]
    fn test_from_tag_error() {
        assert!(Ilk::from_tag("xyz").is_err());
        assert!(Ilk::from_tag("").is_err());
    }

    #[test]
    fn test_serde_serialize() {
        let json = serde_json::to_string(&Ilk::Icp).unwrap();
        assert_eq!(json, "\"icp\"");
    }

    #[test]
    fn test_serde_deserialize() {
        let ilk: Ilk = serde_json::from_str("\"rot\"").unwrap();
        assert_eq!(ilk, Ilk::Rot);
    }

    #[test]
    fn test_serde_roundtrip() {
        for ilk in Ilk::all() {
            let json = serde_json::to_string(ilk).unwrap();
            let parsed: Ilk = serde_json::from_str(&json).unwrap();
            assert_eq!(*ilk, parsed);
        }
    }

    #[test]
    fn test_serde_deserialize_invalid() {
        let result: Result<Ilk, _> = serde_json::from_str("\"xxx\"");
        assert!(result.is_err());
    }
}
