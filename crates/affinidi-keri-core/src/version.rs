//! KERI protocol version handling.
//!
//! KERI version strings follow the format `PPPPvvSSSSnnnnnnn_` where:
//! - `PPPP` is the 4-character protocol identifier (e.g., "KERI", "ACDC")
//! - `vv` is major.minor version as hex digits (e.g., "10" = v1.0)
//! - `SSSS` is the 4-character serialization kind ("JSON", "CBOR", "MGPK")
//! - `nnnnnn` is a 6-digit hex-encoded message size
//! - `_` is the terminator
//!
//! Total length: 4 + 2 + 4 + 6 + 1 = 17 characters.

use crate::error::CoreError;

/// Full size of a KERI version string in bytes.
pub const KERI_VER_FULLSIZE: usize = 17;

/// Serialization format for KERI messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationKind {
    /// JSON serialization.
    Json,
    /// CBOR serialization.
    Cbor,
    /// MessagePack serialization.
    MsgPack,
}

impl SerializationKind {
    /// Return the 4-character tag used in the version string.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Cbor => "CBOR",
            Self::MsgPack => "MGPK",
        }
    }

    /// Parse from a 4-character tag.
    pub fn from_tag(tag: &str) -> Result<Self, CoreError> {
        match tag {
            "JSON" => Ok(Self::Json),
            "CBOR" => Ok(Self::Cbor),
            "MGPK" => Ok(Self::MsgPack),
            _ => Err(CoreError::InvalidVersion(format!(
                "unknown serialization kind: {tag}"
            ))),
        }
    }
}

/// A parsed KERI version string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Protocol identifier (e.g., "KERI").
    pub protocol: String,
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
    /// Serialization format.
    pub kind: SerializationKind,
    /// Message size in bytes.
    pub size: usize,
}

impl Version {
    /// Create a new Version.
    pub fn new(
        protocol: &str,
        major: u8,
        minor: u8,
        kind: SerializationKind,
        size: usize,
    ) -> Self {
        Self {
            protocol: protocol.to_string(),
            major,
            minor,
            kind,
            size,
        }
    }

    /// Shorthand for KERI v1.0 with a given serialization kind and size.
    pub fn default_v1(kind: SerializationKind, size: usize) -> Self {
        Self::new("KERI", 1, 0, kind, size)
    }

    /// Parse a version string from raw bytes.
    ///
    /// Expects at least 17 bytes in the format `PPPPvvSSSSnnnnnnn_`.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidVersion` if the data cannot be parsed.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < KERI_VER_FULLSIZE {
            return Err(CoreError::InvalidVersion(format!(
                "version string too short: {} bytes (need {})",
                data.len(),
                KERI_VER_FULLSIZE,
            )));
        }

        let vs = std::str::from_utf8(&data[..KERI_VER_FULLSIZE]).map_err(|_| {
            CoreError::InvalidVersion("version string is not valid UTF-8".into())
        })?;

        Self::parse_str(vs)
    }

    /// Parse a version string from a `&str`.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidVersion` if the string cannot be parsed.
    pub fn parse_str(vs: &str) -> Result<Self, CoreError> {
        if vs.len() < KERI_VER_FULLSIZE {
            return Err(CoreError::InvalidVersion(format!(
                "version string too short: {} chars (need {})",
                vs.len(),
                KERI_VER_FULLSIZE,
            )));
        }

        // Protocol: chars 0..4
        let protocol = &vs[0..4];

        // Version: chars 4..6 (major hex digit + minor hex digit)
        let major_ch = vs.as_bytes()[4];
        let minor_ch = vs.as_bytes()[5];
        let major = hex_digit(major_ch).ok_or_else(|| {
            CoreError::InvalidVersion(format!("invalid major version digit: {}", major_ch as char))
        })?;
        let minor = hex_digit(minor_ch).ok_or_else(|| {
            CoreError::InvalidVersion(format!("invalid minor version digit: {}", minor_ch as char))
        })?;

        // Serialization kind: chars 6..10
        let kind_tag = &vs[6..10];
        let kind = SerializationKind::from_tag(kind_tag)?;

        // Size: chars 10..16 (6 hex digits)
        let size_str = &vs[10..16];
        let size = usize::from_str_radix(size_str, 16).map_err(|_| {
            CoreError::InvalidVersion(format!("invalid hex size: {size_str}"))
        })?;

        // Terminator: char 16 must be '_'
        if vs.as_bytes()[16] != b'_' {
            return Err(CoreError::InvalidVersion(format!(
                "expected '_' terminator at position 16, got '{}'",
                vs.as_bytes()[16] as char,
            )));
        }

        Ok(Self {
            protocol: protocol.to_string(),
            major,
            minor,
            kind,
            size,
        })
    }

    /// Format this version as a version string.
    ///
    /// Produces a 17-character string in the format `PPPPvvSSSSnnnnnnn_`.
    pub fn to_version_string(&self) -> String {
        format!(
            "{}{:x}{:x}{}{:06x}_",
            self.protocol,
            self.major,
            self.minor,
            self.kind.tag(),
            self.size,
        )
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_version_string())
    }
}

/// Parse a single hex digit character to its numeric value.
fn hex_digit(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keri10json() {
        let vs = "KERI10JSON0000fd_";
        let v = Version::parse_str(vs).unwrap();
        assert_eq!(v.protocol, "KERI");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.kind, SerializationKind::Json);
        assert_eq!(v.size, 253);
    }

    #[test]
    fn test_parse_from_bytes() {
        let data = b"KERI10JSON0000fd_extra data follows";
        let v = Version::parse(data).unwrap();
        assert_eq!(v.protocol, "KERI");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.kind, SerializationKind::Json);
        assert_eq!(v.size, 253);
    }

    #[test]
    fn test_version_string_roundtrip() {
        let v = Version::new("KERI", 1, 0, SerializationKind::Json, 253);
        let vs = v.to_version_string();
        assert_eq!(vs, "KERI10JSON0000fd_");
        let v2 = Version::parse_str(&vs).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_version_string_cbor() {
        let v = Version::new("KERI", 1, 0, SerializationKind::Cbor, 0x100);
        let vs = v.to_version_string();
        assert_eq!(vs, "KERI10CBOR000100_");
        let v2 = Version::parse_str(&vs).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_version_string_msgpack() {
        let v = Version::new("KERI", 1, 0, SerializationKind::MsgPack, 42);
        let vs = v.to_version_string();
        assert_eq!(vs, "KERI10MGPK00002a_");
        let v2 = Version::parse_str(&vs).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_default_v1() {
        let v = Version::default_v1(SerializationKind::Json, 0);
        assert_eq!(v.protocol, "KERI");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.kind, SerializationKind::Json);
    }

    #[test]
    fn test_acdc_protocol() {
        let vs = "ACDC10JSON000100_";
        let v = Version::parse_str(vs).unwrap();
        assert_eq!(v.protocol, "ACDC");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.size, 256);
    }

    #[test]
    fn test_fullsize_constant() {
        assert_eq!(KERI_VER_FULLSIZE, 17);
    }

    #[test]
    fn test_parse_too_short() {
        assert!(Version::parse_str("KERI10JSON").is_err());
    }

    #[test]
    fn test_parse_bad_terminator() {
        assert!(Version::parse_str("KERI10JSON0000fdX").is_err());
    }

    #[test]
    fn test_serialization_kind_tags() {
        assert_eq!(SerializationKind::Json.tag(), "JSON");
        assert_eq!(SerializationKind::Cbor.tag(), "CBOR");
        assert_eq!(SerializationKind::MsgPack.tag(), "MGPK");
    }

    #[test]
    fn test_serialization_kind_from_tag() {
        assert_eq!(SerializationKind::from_tag("JSON").unwrap(), SerializationKind::Json);
        assert_eq!(SerializationKind::from_tag("CBOR").unwrap(), SerializationKind::Cbor);
        assert_eq!(SerializationKind::from_tag("MGPK").unwrap(), SerializationKind::MsgPack);
        assert!(SerializationKind::from_tag("XXXX").is_err());
    }

    #[test]
    fn test_display() {
        let v = Version::default_v1(SerializationKind::Json, 100);
        assert_eq!(format!("{v}"), "KERI10JSON000064_");
    }
}
