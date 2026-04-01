//! Serder: serialization/deserialization of KERI messages.
//!
//! Serder handles converting between raw bytes, JSON/CBOR/MGPK
//! representations, and structured KERI event objects. It wraps a
//! serialized event body and provides parsed access to common fields.

use crate::error::CoreError;
use crate::said;
use crate::version::{SerializationKind, Version, KERI_VER_FULLSIZE};

/// A KERI message serializer/deserializer.
///
/// Serder wraps a raw message and provides access to its parsed fields,
/// serialization kind, version, and SAID.
#[derive(Debug, Clone)]
pub struct Serder {
    /// The raw serialized bytes of the message.
    raw: Vec<u8>,
    /// The parsed version information.
    pub version: Option<Version>,
    /// The serialization kind (JSON, CBOR, or MessagePack).
    kind: SerializationKind,
    /// The parsed JSON value (the SAD).
    sad: serde_json::Value,
}

impl Serder {
    /// Create a Serder by serializing a SAD (Self-Addressing Data) map.
    ///
    /// This method:
    /// 1. Computes the serialized form of the SAD.
    /// 2. Embeds the version string with the computed size.
    /// 3. Stores the raw bytes.
    ///
    /// The SAD should already have proper field ordering. A version string
    /// (`v` field) will be updated with the correct size.
    ///
    /// # Errors
    /// Returns `CoreError` if serialization fails.
    pub fn new(kind: SerializationKind, mut sad: serde_json::Value) -> Result<Self, CoreError> {
        // First pass: serialize to compute size
        let raw = serialize_value(&sad, kind)?;

        // Parse or create version string
        let version = if let Some(v_str) = sad.get("v").and_then(|v| v.as_str()) {
            // Try to parse existing version string to get protocol/major/minor
            if let Ok(mut ver) = Version::parse_str(v_str) {
                // Update size to match actual serialized size
                ver.size = raw.len();
                Some(ver)
            } else {
                // Create a default version with the actual size
                Some(Version::default_v1(kind, raw.len()))
            }
        } else {
            None
        };

        // If we have a version, update the v field with the correct size and re-serialize
        if let Some(ref ver) = version {
            let vs = ver.to_version_string();
            if let Some(obj) = sad.as_object_mut() {
                obj.insert("v".into(), serde_json::Value::String(vs));
            }

            // Re-serialize with the updated version string
            let raw = serialize_value(&sad, kind)?;

            // The size might have changed due to version string length change, iterate
            let mut final_ver = ver.clone();
            final_ver.size = raw.len();
            let final_vs = final_ver.to_version_string();

            if let Some(obj) = sad.as_object_mut() {
                obj.insert("v".into(), serde_json::Value::String(final_vs));
            }

            let raw = serialize_value(&sad, kind)?;

            return Ok(Self {
                raw,
                version: Some(final_ver),
                kind,
                sad,
            });
        }

        Ok(Self {
            raw,
            version,
            kind,
            sad,
        })
    }

    /// Create a Serder from raw bytes.
    ///
    /// Detects the serialization format from the first byte(s), parses the
    /// version string, and deserializes the body.
    ///
    /// # Errors
    /// Returns `CoreError` if the bytes cannot be parsed.
    pub fn from_raw(raw: &[u8]) -> Result<Self, CoreError> {
        if raw.is_empty() {
            return Err(CoreError::ParseError("empty input".into()));
        }

        // Sniff the format
        let kind = sniff_kind(raw)?;

        // For JSON/CBOR/MGPK, the version string is embedded in the `v` field,
        // not at the start of the raw bytes. We can try to extract the version
        // string from the raw bytes for non-JSON (CBOR/MGPK start with binary
        // markers), but for JSON we need to find the `v` field.
        //
        // Strategy: first try to find the version string at a known offset
        // in the raw bytes. For JSON, look for "KERI" or "ACDC" patterns.
        let version = extract_version_from_raw(raw, kind);

        // Determine how many bytes to consume
        let msg_len = if let Some(ref ver) = version {
            ver.size
        } else {
            raw.len()
        };

        if raw.len() < msg_len {
            return Err(CoreError::ParseError(format!(
                "raw data too short: {} bytes but version says {}",
                raw.len(),
                msg_len
            )));
        }

        let msg_bytes = &raw[..msg_len];

        // Deserialize to a JSON value
        let sad = deserialize_value(msg_bytes, kind)?;

        // If we didn't get the version from raw scanning, try from the parsed SAD
        let version = version.or_else(|| {
            sad.get("v")
                .and_then(|v| v.as_str())
                .and_then(|vs| Version::parse_str(vs).ok())
        });

        Ok(Self {
            raw: msg_bytes.to_vec(),
            version,
            kind,
            sad,
        })
    }

    /// Create a Serder from a JSON value (convenience wrapper).
    ///
    /// Serializes as JSON by default.
    ///
    /// # Errors
    /// Returns `CoreError` if the value is not a valid KERI message.
    pub fn from_json_value(sad: serde_json::Value) -> Result<Self, CoreError> {
        Self::new(SerializationKind::Json, sad)
    }

    /// The raw serialized bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The number of raw bytes.
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    /// The serialization kind.
    pub fn kind(&self) -> SerializationKind {
        self.kind
    }

    /// The parsed JSON SAD (Self-Addressing Data).
    pub fn sad(&self) -> &serde_json::Value {
        &self.sad
    }

    /// The SAID (self-addressing identifier / digest) of this message.
    pub fn said(&self) -> Result<String, CoreError> {
        self.sad
            .get("d")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::MissingField("d".into()))
    }

    /// The event type (ilk) tag.
    pub fn ilk(&self) -> Result<String, CoreError> {
        self.sad
            .get("t")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::MissingField("t".into()))
    }

    /// The identifier prefix.
    pub fn prefix(&self) -> Result<String, CoreError> {
        self.sad
            .get("i")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::MissingField("i".into()))
    }

    /// The sequence number (parsed from hex string).
    pub fn sn(&self) -> Result<u64, CoreError> {
        self.sad
            .get("s")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| CoreError::MissingField("s".into()))
    }

    /// Take ownership of the parsed SAD, replacing it with `Value::Null`.
    ///
    /// This allows downstream consumers to call `serde_json::from_value(sad)`
    /// without cloning. The `raw()`, `ilk()`, `prefix()`, `sn()`, and `said()`
    /// methods that read from `raw` will still work, but `sad()` will return
    /// `&Value::Null` after this call.
    pub fn take_sad(&mut self) -> serde_json::Value {
        std::mem::replace(&mut self.sad, serde_json::Value::Null)
    }

    /// Verify the SAID of this message.
    ///
    /// # Errors
    /// Returns `CoreError::SaidMismatch` if the digest does not match.
    pub fn verify_said(&self, code: &str) -> Result<(), CoreError> {
        said::verify_said(&self.sad, "d", code, self.kind)
    }
}

/// Try to extract a version string from raw bytes.
///
/// For JSON, the version string appears inside `{"v":"KERI10JSON..."}` so we
/// scan for a known protocol prefix. For CBOR/MGPK, the version string
/// may also be embedded but we use the same scanning approach.
fn extract_version_from_raw(data: &[u8], _kind: SerializationKind) -> Option<Version> {
    // Look for a known protocol prefix in the raw bytes
    let protocols = [b"KERI" as &[u8], b"ACDC", b"SAID"];
    for proto in &protocols {
        if let Some(pos) = data
            .windows(proto.len())
            .position(|w| w == *proto)
            && pos + KERI_VER_FULLSIZE <= data.len()
            && let Ok(ver) = Version::parse(&data[pos..])
        {
            return Some(ver);
        }
    }
    None
}

/// Detect serialization kind from the first byte of raw data.
fn sniff_kind(data: &[u8]) -> Result<SerializationKind, CoreError> {
    if data.is_empty() {
        return Err(CoreError::ParseError("empty data".into()));
    }

    match data[0] {
        b'{' => Ok(SerializationKind::Json),
        0xa0..=0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbf => Ok(SerializationKind::Cbor),
        0x80..=0x8f | 0xde | 0xdf => Ok(SerializationKind::MsgPack),
        _ => Err(CoreError::ParseError(format!(
            "cannot detect serialization kind from first byte: 0x{:02x}",
            data[0]
        ))),
    }
}

/// Serialize a serde_json::Value to bytes in the specified format.
fn serialize_value(
    value: &serde_json::Value,
    kind: SerializationKind,
) -> Result<Vec<u8>, CoreError> {
    match kind {
        SerializationKind::Json => serde_json::to_vec(value).map_err(CoreError::Json),
        SerializationKind::Cbor => {
            let mut buf = Vec::new();
            ciborium::into_writer(value, &mut buf)
                .map_err(|e| CoreError::Cbor(e.to_string()))?;
            Ok(buf)
        }
        SerializationKind::MsgPack => {
            rmp_serde::to_vec(value).map_err(|e| CoreError::MsgPack(e.to_string()))
        }
    }
}

/// Deserialize bytes to a serde_json::Value from the specified format.
fn deserialize_value(
    data: &[u8],
    kind: SerializationKind,
) -> Result<serde_json::Value, CoreError> {
    match kind {
        SerializationKind::Json => serde_json::from_slice(data).map_err(CoreError::Json),
        SerializationKind::Cbor => {
            ciborium::from_reader(data).map_err(|e| CoreError::Cbor(e.to_string()))
        }
        SerializationKind::MsgPack => {
            rmp_serde::from_slice(data).map_err(|e| CoreError::MsgPack(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serder_new_json() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0"
        });

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();

        // Should have raw bytes
        assert!(!serder.raw().is_empty());

        // Should have parsed version
        assert!(serder.version.is_some());
        let ver = serder.version.as_ref().unwrap();
        assert_eq!(ver.protocol, "KERI");
        assert_eq!(ver.kind, SerializationKind::Json);

        // Size in version should match raw size
        assert_eq!(ver.size, serder.raw().len());

        // Should be able to access fields
        assert_eq!(serder.ilk().unwrap(), "icp");
        assert_eq!(serder.sn().unwrap(), 0);
    }

    #[test]
    fn test_serder_from_raw_json() {
        // Create a valid one with correct size
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": []
        });

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let raw = serder.raw();

        // Now parse it back
        let serder2 = Serder::from_raw(raw).unwrap();
        assert_eq!(serder2.ilk().unwrap(), "icp");
        assert_eq!(serder2.kind(), SerializationKind::Json);
    }

    #[test]
    fn test_serder_from_json_value() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "SAID",
            "i": "PREFIX",
            "s": "1"
        });

        let serder = Serder::from_json_value(sad).unwrap();
        assert_eq!(serder.ilk().unwrap(), "rot");
        assert_eq!(serder.prefix().unwrap(), "PREFIX");
        assert_eq!(serder.sn().unwrap(), 1);
        assert_eq!(serder.said().unwrap(), "SAID");
    }

    #[test]
    fn test_serder_version_size_correct() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0"
        });

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let ver = serder.version.as_ref().unwrap();

        // The version size should match the actual raw byte count
        assert_eq!(ver.size, serder.raw().len());

        // Extract the version string from the v field in the SAD
        let v_str = serder.sad().get("v").unwrap().as_str().unwrap();
        let embedded_ver = Version::parse_str(v_str).unwrap();
        assert_eq!(embedded_ver.size, serder.raw().len());
        assert_eq!(embedded_ver.protocol, "KERI");
        assert_eq!(embedded_ver.kind, SerializationKind::Json);
    }

    #[test]
    fn test_serder_roundtrip() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "DIGEST",
            "i": "PREFIX",
            "s": "a",
            "p": "PRIOR",
            "a": []
        });

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let raw = serder.raw().to_vec();

        let serder2 = Serder::from_raw(&raw).unwrap();
        assert_eq!(serder2.ilk().unwrap(), "ixn");
        assert_eq!(serder2.prefix().unwrap(), "PREFIX");
        assert_eq!(serder2.sn().unwrap(), 10); // 0xa = 10
    }

    #[test]
    fn test_serder_empty_input() {
        assert!(Serder::from_raw(&[]).is_err());
    }

    #[test]
    fn test_serder_missing_fields() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "x": "no standard fields"
        });

        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        assert!(serder.ilk().is_err());
        assert!(serder.prefix().is_err());
        assert!(serder.sn().is_err());
        assert!(serder.said().is_err());
    }

    #[test]
    fn test_sniff_kind_json() {
        assert_eq!(sniff_kind(b"{\"v\":\"test\"}").unwrap(), SerializationKind::Json);
    }

    #[test]
    fn test_sniff_kind_cbor() {
        assert_eq!(sniff_kind(&[0xa2, 0x01]).unwrap(), SerializationKind::Cbor);
    }

    #[test]
    fn test_sniff_kind_msgpack() {
        assert_eq!(sniff_kind(&[0x82, 0xa1]).unwrap(), SerializationKind::MsgPack);
    }

    #[test]
    fn test_sniff_kind_unknown() {
        assert!(sniff_kind(&[0x00]).is_err());
    }
}
