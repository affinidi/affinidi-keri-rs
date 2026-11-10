//! KERI protocol version handling.
//!
//! Two version string forms exist, and a message carries whichever its
//! protocol version uses (keripy `kering.py`, `VEREX1` / `VEREX2`):
//!
//! **Version 1**, 17 characters, `PPPPvvKKKKssssss_`:
//! - `PPPP` protocol (`KERI`, `ACDC`)
//! - `vv` major and minor, one hex digit each
//! - `KKKK` serialization kind (`JSON`, `CBOR`, `MGPK`)
//! - `ssssss` message size, six hex digits
//! - `_` terminator
//!
//! **Version 2**, 19 characters, `PPPPMmmGggKKKKssss.`:
//! - `PPPP` protocol
//! - `Mmm` protocol major (one Base64 digit) and minor (two Base64 digits)
//! - `Ggg` CESR genus major and minor, the same way
//! - `KKKK` serialization kind, which may also be `CESR`
//! - `ssss` message size, four Base64 digits
//! - `.` terminator
//!
//! A v1 string must name major version 1 or lower and must not be `CESR`; a v2
//! string must name protocol and genus major version 2. keripy enforces the
//! same (`rematch`).

use crate::error::CoreError;

/// Full size of a version 1 version string in bytes.
pub const KERI_VER_FULLSIZE: usize = 17;

/// Full size of a version 2 version string in bytes.
pub const KERI_VER2_FULLSIZE: usize = 19;

/// The URL-safe Base64 alphabet CESR uses for its digits.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Serialization format for KERI messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SerializationKind {
    /// JSON serialization.
    Json,
    /// CBOR serialization.
    Cbor,
    /// MessagePack serialization.
    MsgPack,
    /// Native CESR serialization (version 2 only): the body is a CESR group
    /// of primitives, not a field map.
    Cesr,
}

impl SerializationKind {
    /// Return the 4-character tag used in the version string.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Cbor => "CBOR",
            Self::MsgPack => "MGPK",
            Self::Cesr => "CESR",
        }
    }

    /// Parse from a 4-character tag.
    pub fn from_tag(tag: &str) -> Result<Self, CoreError> {
        match tag {
            "JSON" => Ok(Self::Json),
            "CBOR" => Ok(Self::Cbor),
            "MGPK" => Ok(Self::MsgPack),
            "CESR" => Ok(Self::Cesr),
            _ => Err(CoreError::InvalidVersion(format!(
                "unknown serialization kind: {tag}"
            ))),
        }
    }
}

/// A parsed KERI version string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The CESR genus version a version 2 string names, as (major, minor).
    /// `None` for a version 1 string, which names none.
    pub genus: Option<(u8, u8)>,
}

impl Version {
    /// Create a new Version.
    ///
    /// A major version of 2 or above gets the genus version 2.0, which is what
    /// a version 2 string must name; use [`with_genus`](Self::with_genus) to
    /// name another.
    pub fn new(protocol: &str, major: u8, minor: u8, kind: SerializationKind, size: usize) -> Self {
        Self {
            protocol: protocol.to_string(),
            major,
            minor,
            kind,
            size,
            genus: (major >= 2).then_some((2, 0)),
        }
    }

    /// Shorthand for KERI v1.0 with a given serialization kind and size.
    pub fn default_v1(kind: SerializationKind, size: usize) -> Self {
        Self::new("KERI", 1, 0, kind, size)
    }

    /// Shorthand for KERI v2.0, genus 2.0, with a given serialization kind
    /// and size.
    pub fn default_v2(kind: SerializationKind, size: usize) -> Self {
        Self::new("KERI", 2, 0, kind, size)
    }

    /// The same version naming a different CESR genus version.
    pub fn with_genus(mut self, major: u8, minor: u8) -> Self {
        self.genus = Some((major, minor));
        self
    }

    /// The length of this version's version string: 17 for version 1, 19
    /// for version 2.
    pub fn full_size(&self) -> usize {
        if self.major >= 2 {
            KERI_VER2_FULLSIZE
        } else {
            KERI_VER_FULLSIZE
        }
    }

    /// Parse a version string from the start of raw bytes, in either form.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidVersion` if the data cannot be parsed.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        // The two forms are told apart by their terminators: `_` at 16 for
        // version 1, `.` at 18 for version 2. Exactly one can hold, because a
        // version 1 string has a hex digit where a version 2 string has its
        // terminator's predecessor, and vice versa.
        let v1 = data.len() >= KERI_VER_FULLSIZE && data[KERI_VER_FULLSIZE - 1] == b'_';
        let v2 = data.len() >= KERI_VER2_FULLSIZE && data[KERI_VER2_FULLSIZE - 1] == b'.';
        let len = match (v1, v2) {
            (true, false) => KERI_VER_FULLSIZE,
            (false, true) => KERI_VER2_FULLSIZE,
            (true, true) => {
                return Err(CoreError::InvalidVersion(
                    "version string has both a version 1 and a version 2 terminator".into(),
                ));
            }
            (false, false) => {
                return Err(CoreError::InvalidVersion(format!(
                    "no version string: need a `_` at byte {} or a `.` at byte {} \
                     ({} bytes available)",
                    KERI_VER_FULLSIZE - 1,
                    KERI_VER2_FULLSIZE - 1,
                    data.len()
                )));
            }
        };
        if !data[..len].is_ascii() {
            return Err(CoreError::InvalidVersion(
                "version string contains non-ASCII bytes".into(),
            ));
        }
        let vs = std::str::from_utf8(&data[..len])
            .map_err(|_| CoreError::InvalidVersion("version string is not valid UTF-8".into()))?;
        Self::parse_str(vs)
    }

    /// Parse a version string from a `&str`, in either form.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidVersion` if the string cannot be parsed.
    pub fn parse_str(vs: &str) -> Result<Self, CoreError> {
        let bytes = vs.as_bytes();
        if bytes.len() >= KERI_VER2_FULLSIZE
            && bytes[KERI_VER2_FULLSIZE - 1] == b'.'
            && bytes[..KERI_VER2_FULLSIZE].is_ascii()
        {
            return Self::parse_v2(&vs[..KERI_VER2_FULLSIZE]);
        }
        Self::parse_v1(vs)
    }

    fn parse_v1(vs: &str) -> Result<Self, CoreError> {
        if vs.len() < KERI_VER_FULLSIZE {
            return Err(CoreError::InvalidVersion(format!(
                "version string too short: {} chars (need {})",
                vs.len(),
                KERI_VER_FULLSIZE,
            )));
        }

        // KERI spec requires version strings to be pure ASCII.
        // Reject non-ASCII to prevent panics from byte-indexing multi-byte UTF-8.
        if !vs.as_bytes()[..KERI_VER_FULLSIZE].is_ascii() {
            return Err(CoreError::InvalidVersion(
                "version string contains non-ASCII bytes".into(),
            ));
        }

        let protocol = parse_protocol(&vs[0..4])?;

        // Version: chars 4..6 (major hex digit + minor hex digit)
        let major_ch = vs.as_bytes()[4];
        let minor_ch = vs.as_bytes()[5];
        let major = hex_digit(major_ch).ok_or_else(|| {
            CoreError::InvalidVersion(format!("invalid major version digit: {}", major_ch as char))
        })?;
        let minor = hex_digit(minor_ch).ok_or_else(|| {
            CoreError::InvalidVersion(format!("invalid minor version digit: {}", minor_ch as char))
        })?;
        if major > 1 {
            return Err(CoreError::InvalidVersion(format!(
                "a version 1 string cannot name major version {major}"
            )));
        }

        // Serialization kind: chars 6..10
        let kind = SerializationKind::from_tag(&vs[6..10])?;
        if kind == SerializationKind::Cesr {
            return Err(CoreError::InvalidVersion(
                "native CESR serialization does not exist in version 1".into(),
            ));
        }

        // Size: chars 10..16 (6 hex digits)
        let size_str = &vs[10..16];
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| CoreError::InvalidVersion(format!("invalid hex size: {size_str}")))?;

        // Terminator: char 16 must be '_'
        if vs.as_bytes()[16] != b'_' {
            return Err(CoreError::InvalidVersion(format!(
                "expected '_' terminator at position 16, got '{}'",
                vs.as_bytes()[16] as char,
            )));
        }

        Ok(Self {
            protocol,
            major,
            minor,
            kind,
            size,
            genus: None,
        })
    }

    fn parse_v2(vs: &str) -> Result<Self, CoreError> {
        let protocol = parse_protocol(&vs[0..4])?;
        let major = b64_to_u8(&vs[4..5], "protocol major")?;
        let minor = b64_to_u8(&vs[5..7], "protocol minor")?;
        let genus_major = b64_to_u8(&vs[7..8], "genus major")?;
        let genus_minor = b64_to_u8(&vs[8..10], "genus minor")?;
        if major != 2 {
            return Err(CoreError::InvalidVersion(format!(
                "a version 2 string must name protocol major version 2, not {major}"
            )));
        }
        if genus_major != 2 {
            return Err(CoreError::InvalidVersion(format!(
                "a version 2 string must name genus major version 2, not {genus_major}"
            )));
        }
        let kind = SerializationKind::from_tag(&vs[10..14])?;
        let size = b64_to_usize(&vs[14..18])?;
        Ok(Self {
            protocol,
            major,
            minor,
            kind,
            size,
            genus: Some((genus_major, genus_minor)),
        })
    }

    /// Format this version as a version string: the 17-character form for
    /// major version 1 and below, the 19-character form for 2 and above.
    ///
    /// The size is truncated to its field's width; a message too large for
    /// it is refused when it is serialized (see `Serder::new`).
    pub fn to_version_string(&self) -> String {
        if self.major >= 2 {
            let (gmajor, gminor) = self.genus.unwrap_or((2, 0));
            format!(
                "{}{}{}{}{}{}{}.",
                self.protocol,
                int_to_b64(self.major.into(), 1),
                int_to_b64(self.minor.into(), 2),
                int_to_b64(gmajor.into(), 1),
                int_to_b64(gminor.into(), 2),
                self.kind.tag(),
                int_to_b64(self.size, 4),
            )
        } else {
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

    /// The largest message size this version's size field can hold.
    pub fn max_size(&self) -> usize {
        if self.major >= 2 {
            64usize.pow(4) - 1
        } else {
            16usize.pow(6) - 1
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_version_string())
    }
}

/// The protocol identifiers a version string may name (keripy `Protocols`).
fn parse_protocol(p: &str) -> Result<String, CoreError> {
    if p.len() == 4 && p.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(p.to_string())
    } else {
        Err(CoreError::InvalidVersion(format!(
            "invalid protocol: {p:?}"
        )))
    }
}

/// Parse a single hex digit character to its numeric value.
///
/// keripy's version 1 pattern admits lowercase hex only (`[0-9a-f]`); upper
/// case is accepted here as it always has been.
fn hex_digit(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

/// The value of one Base64 digit.
pub(crate) fn b64_digit(ch: u8) -> Option<usize> {
    B64.iter().position(|&c| c == ch)
}

/// The value of a run of Base64 digits, most significant first.
pub(crate) fn b64_to_usize(s: &str) -> Result<usize, CoreError> {
    s.bytes().try_fold(0usize, |acc, ch| {
        let d = b64_digit(ch).ok_or_else(|| {
            CoreError::InvalidVersion(format!("invalid Base64 digit {:?} in {s:?}", ch as char))
        })?;
        acc.checked_mul(64)
            .and_then(|a| a.checked_add(d))
            .ok_or_else(|| CoreError::InvalidVersion(format!("Base64 number {s:?} overflows")))
    })
}

fn b64_to_u8(s: &str, what: &str) -> Result<u8, CoreError> {
    let v = b64_to_usize(s)?;
    u8::try_from(v).map_err(|_| CoreError::InvalidVersion(format!("{what} {v} is out of range")))
}

/// `value` as `width` Base64 digits, most significant first. Higher digits
/// than `width` holds are dropped.
pub(crate) fn int_to_b64(mut value: usize, width: usize) -> String {
    let mut out = vec![b'A'; width];
    for slot in out.iter_mut().rev() {
        *slot = B64[value % 64];
        value /= 64;
    }
    String::from_utf8(out).expect("Base64 alphabet is ASCII")
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
    fn test_parse_non_ascii_returns_error() {
        // PoC from security report: multi-byte UTF-8 chars at offsets that
        // would cause &str byte-indexing to panic without the ASCII guard.
        // Bytes: KERI10 + ࠀ (3-byte) + 🦀 (4-byte) + padding
        let payload = b"KERI10\xe0\xa0\x80\xf0\x9f\xa6\x80____";
        let vs = std::str::from_utf8(payload).unwrap(); // valid UTF-8
        let result = Version::parse_str(vs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-ASCII"),);
    }

    #[test]
    fn test_parse_non_ascii_via_bytes() {
        // Same PoC via Version::parse (the &[u8] entry point)
        let payload = b"KERI10\xe0\xa0\x80\xf0\x9f\xa6\x80____";
        assert!(Version::parse(payload).is_err());
    }

    #[test]
    fn test_parse_multibyte_straddling_the_guard_boundary() {
        // The guard slices `vs[..17]`, and a `&str` slice panics when byte 17
        // is not a char boundary — so the check meant to reject non-ASCII
        // could crash before rejecting anything. `Version::parse` is the first
        // function called on every inbound message, before any signature is
        // checked, so this was reachable by an unauthenticated peer.
        //
        // The two tests above do NOT cover it: their payload is exactly 17
        // bytes, so byte 17 is the end of the string and every boundary
        // aligns. The character has to *span* byte 17.
        for (label, payload) in [
            // 2-byte char at bytes 16..18
            ("2-byte", "KERI10JSON000000\u{016D}"),
            // 3-byte char at bytes 15..18
            ("3-byte", "KERI10JSON00000\u{20AC}xx"),
            // 4-byte char at bytes 14..18
            ("4-byte", "KERI10JSON0000\u{1F600}xx"),
        ] {
            let result = Version::parse_str(payload);
            assert!(
                result.is_err(),
                "{label} payload straddling byte 17 must be rejected, not parsed",
            );
            assert!(
                result.unwrap_err().to_string().contains("non-ASCII"),
                "{label} payload should be rejected as non-ASCII",
            );
        }
    }

    #[test]
    fn test_parse_every_multibyte_offset_is_rejected() {
        // Walk a multi-byte character across every offset that can overlap the
        // guard boundary, so a future change to the guard cannot reintroduce
        // the panic at some offset the fixed payloads above happen to miss.
        for width in [2usize, 3, 4] {
            let ch = match width {
                2 => '\u{016D}',
                3 => '\u{20AC}',
                _ => '\u{1F600}',
            };
            for prefix in 0..=KERI_VER_FULLSIZE {
                let mut payload = "K".repeat(prefix);
                payload.push(ch);
                payload.push_str(&"_".repeat(KERI_VER_FULLSIZE));

                // Must return, never panic. Content is nonsense, so the only
                // acceptable outcome is an error.
                assert!(
                    Version::parse_str(&payload).is_err(),
                    "width {width} at offset {prefix} should be rejected",
                );
            }
        }
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
        assert_eq!(
            SerializationKind::from_tag("JSON").unwrap(),
            SerializationKind::Json
        );
        assert_eq!(
            SerializationKind::from_tag("CBOR").unwrap(),
            SerializationKind::Cbor
        );
        assert_eq!(
            SerializationKind::from_tag("MGPK").unwrap(),
            SerializationKind::MsgPack
        );
        assert_eq!(
            SerializationKind::from_tag("CESR").unwrap(),
            SerializationKind::Cesr
        );
        assert!(SerializationKind::from_tag("XXXX").is_err());
    }

    #[test]
    fn a_version_2_string_from_keripy_parses() {
        // From the keripy v2 fixtures: KERI 2.0, genus 2.0, JSON, 0x12d bytes.
        let v = Version::parse_str("KERICAACAAJSONAAEt.").unwrap();
        assert_eq!(v.protocol, "KERI");
        assert_eq!((v.major, v.minor), (2, 0));
        assert_eq!(v.genus, Some((2, 0)));
        assert_eq!(v.kind, SerializationKind::Json);
        assert_eq!(v.size, 4 * 64 + 45);
        assert_eq!(v.to_version_string(), "KERICAACAAJSONAAEt.");
    }

    #[test]
    fn version_2_round_trips_and_parses_from_bytes() {
        let v = Version::default_v2(SerializationKind::Json, 1234);
        let vs = v.to_version_string();
        assert_eq!(vs.len(), KERI_VER2_FULLSIZE);
        assert_eq!(Version::parse_str(&vs).unwrap(), v);
        let mut data = vs.into_bytes();
        data.extend_from_slice(br#"","t":"icp""#);
        assert_eq!(Version::parse(&data).unwrap(), v);
    }

    #[test]
    fn a_version_1_string_is_still_17_characters() {
        let v = Version::parse(br#"KERI10JSON0000fd_","t""#).unwrap();
        assert_eq!(v.genus, None);
        assert_eq!(v.full_size(), KERI_VER_FULLSIZE);
    }

    #[test]
    fn each_form_refuses_the_other_forms_versions() {
        // keripy `rematch`: a v1 string naming major 2, a v2 string naming
        // major 1, and native CESR in a v1 string are all refused.
        assert!(Version::parse_str("KERI20JSON0000fd_").is_err());
        assert!(Version::parse_str("KERIBAACAAJSONAAEt.").is_err());
        assert!(
            Version::parse_str("KERICAABAAJSONAAEt.").is_err(),
            "genus 1"
        );
        assert!(Version::parse_str("KERI10CESR0000fd_").is_err());
        assert_eq!(
            Version::parse_str("KERICAACAACESRAAEt.").unwrap().kind,
            SerializationKind::Cesr
        );
    }

    #[test]
    fn test_display() {
        let v = Version::default_v1(SerializationKind::Json, 100);
        assert_eq!(format!("{v}"), "KERI10JSON000064_");
    }
}
