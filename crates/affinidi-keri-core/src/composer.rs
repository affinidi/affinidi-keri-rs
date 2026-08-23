//! Composer for building KERI messages.
//!
//! The Composer constructs serialized KERI events with CESR-encoded
//! signature attachments appended after the message body.

use affinidi_cesr::Counter;
use affinidi_keri_crypto::{Cigar, Siger};

use crate::counter_table::{CounterTable, GroupKind};
use crate::error::CoreError;
use crate::serder::Serder;

/// The counter table an event's own version string implies.
///
/// Composing and parsing must agree, so both derive the table the same way
/// rather than hard-coding counter codes. A `KERI10JSON…` event gets the 1.x
/// table, where controller signatures are `-A` — not `-B`, which is what the
/// 2.x table calls them.
pub fn table_for(serder: &Serder) -> CounterTable {
    serder
        .version
        .as_ref()
        .map_or(CounterTable::default(), |v| {
            CounterTable::from_major(v.major)
        })
}

/// The counter code for `kind` under the table implied by `serder`.
///
/// # Errors
/// Returns `CoreError` if the group has no code in that table.
pub fn counter_code_for(serder: &Serder, kind: GroupKind) -> Result<&'static str, CoreError> {
    let table = table_for(serder);
    kind.code(table)
        .ok_or_else(|| CoreError::ParseError(format!("{kind:?} has no counter code in {table:?}")))
}

/// Compose a signed event message.
///
/// Concatenates the serialized event body with the controller-indexed-signature
/// counter code for the event's protocol version, followed by each indexed
/// signature in qb64 encoding.
///
/// # Errors
/// Returns `CoreError` if the counter or signatures cannot be encoded.
pub fn compose_event(serder: &Serder, sigs: &[Siger]) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::with_capacity(serder.size() + 4 + sigs.len() * 88);

    // Message body
    output.extend_from_slice(serder.raw());

    if !sigs.is_empty() {
        let code = counter_code_for(serder, GroupKind::ControllerIdxSigs)?;
        let counter = Counter::new(code, sigs.len())
            .map_err(|e| CoreError::ParseError(format!("failed to create counter: {e}")))?;
        let counter_qb64 = counter
            .qb64()
            .map_err(|e| CoreError::ParseError(format!("failed to encode counter: {e}")))?;
        output.extend_from_slice(counter_qb64.as_bytes());

        // Each indexed signature
        for sig in sigs {
            let sig_qb64 = sig.qb64().map_err(CoreError::Crypto)?;
            output.extend_from_slice(sig_qb64.as_bytes());
        }
    }

    Ok(output)
}

/// Compose a non-transferable receipt message.
///
/// Concatenates the serialized event body with the non-transferable receipt
/// couple counter code for the event's protocol version, followed by the
/// prefix qb64 and cigar (non-indexed signature) qb64.
///
/// # Errors
/// Returns `CoreError` if the counter or primitives cannot be encoded.
pub fn compose_receipt(serder: &Serder, prefix: &str, cigar: &Cigar) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::with_capacity(serder.size() + 4 + prefix.len() + 88);

    // Message body
    output.extend_from_slice(serder.raw());

    let code = counter_code_for(serder, GroupKind::NonTransReceiptCouples)?;
    let counter = Counter::new(code, 1)
        .map_err(|e| CoreError::ParseError(format!("failed to create counter: {e}")))?;
    let counter_qb64 = counter
        .qb64()
        .map_err(|e| CoreError::ParseError(format!("failed to encode counter: {e}")))?;
    output.extend_from_slice(counter_qb64.as_bytes());

    // Prefix qb64
    output.extend_from_slice(prefix.as_bytes());

    // Cigar qb64
    let cigar_qb64 = cigar.qb64().map_err(CoreError::Crypto)?;
    output.extend_from_slice(cigar_qb64.as_bytes());

    Ok(output)
}

/// Compose a message with witness indexed signatures.
///
/// Similar to `compose_event` but uses the witness-indexed-signature counter
/// code for the event's protocol version.
///
/// # Errors
/// Returns `CoreError` if encoding fails.
pub fn compose_witness_sigs(serder: &Serder, sigs: &[Siger]) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::with_capacity(serder.size() + 4 + sigs.len() * 88);

    // Message body
    output.extend_from_slice(serder.raw());

    if !sigs.is_empty() {
        let code = counter_code_for(serder, GroupKind::WitnessIdxSigs)?;
        let counter = Counter::new(code, sigs.len())
            .map_err(|e| CoreError::ParseError(format!("failed to create counter: {e}")))?;
        let counter_qb64 = counter
            .qb64()
            .map_err(|e| CoreError::ParseError(format!("failed to encode counter: {e}")))?;
        output.extend_from_slice(counter_qb64.as_bytes());

        // Each indexed signature
        for sig in sigs {
            let sig_qb64 = sig.qb64().map_err(CoreError::Crypto)?;
            output.extend_from_slice(sig_qb64.as_bytes());
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::said;
    use crate::version::SerializationKind;
    use affinidi_keri_crypto::{Diger, Signer};

    fn make_test_serder() -> Serder {
        let signer = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let verfer_qb64 = signer.verfer().qb64().unwrap();
        let next_digest = Diger::from_data("E", verfer_qb64.as_bytes())
            .unwrap()
            .qb64()
            .unwrap();

        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": [verfer_qb64],
            "nt": "1",
            "n": [next_digest],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        Serder::new(SerializationKind::Json, sad).unwrap()
    }

    #[test]
    fn test_compose_event_single_sig() {
        let signer = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let serder = make_test_serder();

        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let composed = compose_event(&serder, &[sig]).unwrap();

        // Should start with the serialized message
        assert!(composed.starts_with(serder.raw()));

        // Should have counter code after message body
        let attachment_part = std::str::from_utf8(&composed[serder.size()..]).unwrap();
        // KERI 1.x controller indexed sigs: "-A" with count 1 = "-AAB".
        assert!(attachment_part.starts_with("-AAB"), "got {attachment_part}");

        // Total size: message + 4 (counter) + 88 (ed25519 indexed sig)
        assert_eq!(composed.len(), serder.size() + 4 + 88);
    }

    #[test]
    fn test_compose_event_multiple_sigs() {
        let signer1 = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let signer2 = Signer::new("A", [7u8; 32].to_vec()).unwrap();
        let serder = make_test_serder();

        let sig1 = signer1.sign_indexed(serder.raw(), 0, true).unwrap();
        let sig2 = signer2.sign_indexed(serder.raw(), 1, true).unwrap();
        let composed = compose_event(&serder, &[sig1, sig2]).unwrap();

        // Total size: message + 4 (counter) + 88 * 2 (two ed25519 indexed sigs)
        assert_eq!(composed.len(), serder.size() + 4 + 88 * 2);
    }

    #[test]
    fn test_compose_event_no_sigs() {
        let serder = make_test_serder();
        let composed = compose_event(&serder, &[]).unwrap();

        // Just the message body, no counter
        assert_eq!(composed.len(), serder.size());
    }

    #[test]
    fn test_compose_receipt() {
        let signer = Signer::new_with_transferable("A", [42u8; 32].to_vec(), false).unwrap();
        let serder = make_test_serder();

        let cigar = signer.sign(serder.raw()).unwrap();
        let prefix = signer.verfer().qb64().unwrap();

        let composed = compose_receipt(&serder, &prefix, &cigar).unwrap();

        // Should start with the message body
        assert!(composed.starts_with(serder.raw()));

        // Should have -D counter after message
        let att_str = std::str::from_utf8(&composed[serder.size()..]).unwrap();
        // KERI 1.x non-transferable receipt couples.
        assert!(att_str.starts_with("-C"), "got {att_str}");

        // Size: message + 4 (counter) + 44 (prefix qb64) + 88 (cigar qb64)
        assert_eq!(composed.len(), serder.size() + 4 + 44 + 88);
    }

    #[test]
    fn test_compose_witness_sigs() {
        let signer = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let serder = make_test_serder();

        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let composed = compose_witness_sigs(&serder, &[sig]).unwrap();

        let att_str = std::str::from_utf8(&composed[serder.size()..]).unwrap();
        // KERI 1.x witness indexed sigs.
        assert!(att_str.starts_with("-B"), "got {att_str}");
    }
}
