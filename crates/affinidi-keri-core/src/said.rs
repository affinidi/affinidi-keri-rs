//! SAID (Self-Addressing Identifier) computation.
//!
//! A SAID is a content digest that is embedded in the content itself.
//! The algorithm:
//! 1. Start with the serialized data (SAD = Self-Addressing Data).
//! 2. Replace the SAID field (`d`) with a dummy string of `#` characters
//!    whose length equals the expected qb64 output of the digest algorithm.
//! 3. For inception events where `i` == `d` (self-addressing AID), also
//!    replace `i` with the same dummy.
//! 4. Serialize the modified SAD.
//! 5. Compute the digest of the serialized bytes.
//! 6. The qb64-encoded digest IS the SAID.
//! 7. Replace the dummy values in the original SAD with the computed SAID.

use affinidi_cesr::tables::matter_sizage;
use affinidi_keri_crypto::Diger;

use crate::error::CoreError;
use crate::version::SerializationKind;

/// Default digest algorithm code for SAID computation (Blake3-256).
pub const DEFAULT_DIGEST_CODE: &str = "E";

/// Compute the SAID for a JSON value.
///
/// The `label` identifies which field to use as the SAID field (typically `"d"`).
/// The `code` specifies the CESR digest algorithm code (e.g., `"E"` for Blake3-256).
///
/// This function mutates `sad` in place, replacing the SAID field (and the `i`
/// field for self-addressing inception events) with the computed digest.
///
/// # Errors
/// Returns `CoreError` if the value is not an object, the label field is missing,
/// or the digest computation fails.
pub fn compute_said(
    sad: &mut serde_json::Value,
    label: &str,
    code: &str,
    kind: SerializationKind,
) -> Result<String, CoreError> {
    let obj = sad
        .as_object_mut()
        .ok_or_else(|| CoreError::Validation("SAD must be a JSON object".into()))?;

    // Look up the full size (fs) for this digest code to know the dummy length
    let sizage = matter_sizage(code)
        .ok_or_else(|| CoreError::Validation(format!("unknown digest code: {code}")))?;
    let dummy_len = sizage.fs;
    if dummy_len == 0 {
        return Err(CoreError::Validation(format!(
            "digest code {code} has variable length, cannot compute SAID"
        )));
    }

    let dummy = "#".repeat(dummy_len);

    // Check if label field exists
    if !obj.contains_key(label) {
        return Err(CoreError::MissingField(label.into()));
    }

    // Check if this is a self-addressing inception (i == d before replacement)
    let is_self_addressing = if label == "d" {
        if let (Some(d_val), Some(i_val)) = (obj.get("d"), obj.get("i")) {
            d_val == i_val
        } else {
            false
        }
    } else {
        false
    };

    // Replace label field with dummy
    obj.insert(label.into(), serde_json::Value::String(dummy.clone()));

    // If self-addressing, also replace `i` with dummy
    if is_self_addressing {
        obj.insert("i".into(), serde_json::Value::String(dummy.clone()));
    }

    // Serialize with the dummies in place
    let serialized = serialize_sad(sad, kind)?;

    // Compute the digest
    let diger = Diger::from_data(code, &serialized)?;
    let said = diger.qb64().map_err(CoreError::Crypto)?;

    // Replace dummies with computed SAID
    let obj = sad
        .as_object_mut()
        .ok_or_else(|| CoreError::Validation("SAD must be a JSON object".into()))?;

    obj.insert(label.into(), serde_json::Value::String(said.clone()));
    if is_self_addressing {
        obj.insert("i".into(), serde_json::Value::String(said.clone()));
    }

    Ok(said)
}

/// Verify that the SAID field in a JSON value matches the computed digest.
///
/// # Errors
/// Returns `CoreError::SaidMismatch` if the digest does not match.
pub fn verify_said(
    sad: &serde_json::Value,
    label: &str,
    code: &str,
    kind: SerializationKind,
) -> Result<(), CoreError> {
    let obj = sad
        .as_object()
        .ok_or_else(|| CoreError::Validation("SAD must be a JSON object".into()))?;

    // Get the current SAID value
    let current_said = obj
        .get(label)
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::MissingField(label.into()))?
        .to_string();

    // Clone and recompute
    let mut sad_clone = sad.clone();
    let computed_said = compute_said(&mut sad_clone, label, code, kind)?;

    if computed_said != current_said {
        return Err(CoreError::SaidMismatch);
    }

    Ok(())
}

/// Serialize a SAD value according to the specified serialization kind.
fn serialize_sad(sad: &serde_json::Value, kind: SerializationKind) -> Result<Vec<u8>, CoreError> {
    match kind {
        SerializationKind::Json => serde_json::to_vec(sad).map_err(CoreError::Json),
        SerializationKind::Cbor => {
            let mut buf = Vec::new();
            ciborium::into_writer(sad, &mut buf).map_err(|e| CoreError::Cbor(e.to_string()))?;
            Ok(buf)
        }
        SerializationKind::MsgPack => {
            rmp_serde::to_vec(sad).map_err(|e| CoreError::MsgPack(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_said_basic() {
        let mut sad = serde_json::json!({
            "d": "",
            "msg": "hello world"
        });

        let said = compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        // SAID should be a 44-char qb64 string starting with 'E'
        assert_eq!(said.len(), 44);
        assert!(said.starts_with('E'));

        // The 'd' field should now contain the computed SAID
        assert_eq!(sad["d"].as_str().unwrap(), &said);
    }

    #[test]
    fn test_compute_said_self_addressing() {
        // When d == i, both should be replaced with the computed SAID
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0"
        });

        let said = compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        assert_eq!(sad["d"].as_str().unwrap(), &said);
        assert_eq!(sad["i"].as_str().unwrap(), &said);
    }

    #[test]
    fn test_compute_said_deterministic() {
        // Same input should produce the same SAID
        let make_sad = || {
            serde_json::json!({
                "d": "",
                "x": "test"
            })
        };

        let mut sad1 = make_sad();
        let mut sad2 = make_sad();

        let said1 = compute_said(&mut sad1, "d", "E", SerializationKind::Json).unwrap();
        let said2 = compute_said(&mut sad2, "d", "E", SerializationKind::Json).unwrap();

        assert_eq!(said1, said2);
    }

    #[test]
    fn test_verify_said_valid() {
        let mut sad = serde_json::json!({
            "d": "",
            "x": "verify me"
        });

        compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        // Verification should pass
        verify_said(&sad, "d", "E", SerializationKind::Json).unwrap();
    }

    #[test]
    fn test_verify_said_tampered() {
        let mut sad = serde_json::json!({
            "d": "",
            "x": "verify me"
        });

        compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();

        // Tamper with the data
        sad["x"] = serde_json::Value::String("tampered".into());

        // Verification should fail
        let result = verify_said(&sad, "d", "E", SerializationKind::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_said_missing_field() {
        let mut sad = serde_json::json!({
            "x": "no d field"
        });

        let result = compute_said(&mut sad, "d", "E", SerializationKind::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_said_not_object() {
        let mut sad = serde_json::json!("not an object");
        let result = compute_said(&mut sad, "d", "E", SerializationKind::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_said_different_algorithms() {
        let make_sad = || {
            serde_json::json!({
                "d": "",
                "x": "test"
            })
        };

        let mut sad_e = make_sad();
        let mut sad_i = make_sad();

        let said_e = compute_said(&mut sad_e, "d", "E", SerializationKind::Json).unwrap();
        let said_i = compute_said(&mut sad_i, "d", "I", SerializationKind::Json).unwrap();

        // Different algorithms should produce different SAIDs
        assert_ne!(said_e, said_i);
        // But same lengths (both 44 chars for 256-bit digests)
        assert_eq!(said_e.len(), 44);
        assert_eq!(said_i.len(), 44);
        // Different prefix codes
        assert!(said_e.starts_with('E'));
        assert!(said_i.starts_with('I'));
    }
}
