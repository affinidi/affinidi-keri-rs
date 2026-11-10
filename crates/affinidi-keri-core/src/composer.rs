//! Composer for building KERI messages.
//!
//! The Composer constructs serialized KERI events with CESR-encoded
//! signature attachments appended after the message body.

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

/// Append `items` as one counted group of `kind`, in `table`'s code and unit.
pub(crate) fn push_group(
    out: &mut Vec<u8>,
    table: CounterTable,
    kind: GroupKind,
    items: &[String],
) -> Result<(), CoreError> {
    let body: String = items.concat();
    let count = if table.counts_quadlets(kind) {
        if !body.len().is_multiple_of(4) {
            return Err(CoreError::ParseError(format!(
                "{kind:?} material of {} characters is not whole quadlets",
                body.len()
            )));
        }
        body.len() / 4
    } else {
        items.len()
    };
    out.extend_from_slice(kind.counter(table, count)?.as_bytes());
    out.extend_from_slice(body.as_bytes());
    Ok(())
}

/// Frame a message body and its attachment groups the way keripy publishes
/// one in its version's genus.
///
/// A version 1 event is the body followed by its groups, unchanged from what
/// this crate has always written. A version 2 event opens with the 2.x
/// genus-version counter, so the message declares its own genus wherever it
/// lands in a stream (a stream with none is read as 1.x, P1), and its groups
/// are wrapped in an attachment group, as keripy's `clonePreIter` writes them.
pub(crate) fn frame(serder: &Serder, groups: &[u8]) -> Result<Vec<u8>, CoreError> {
    let table = table_for(serder);
    let mut out = Vec::with_capacity(serder.size() + groups.len() + 16);
    match table {
        CounterTable::V1 => {
            out.extend_from_slice(serder.raw());
            out.extend_from_slice(groups);
        }
        _ => {
            out.extend_from_slice(table.genus_counter().as_bytes());
            out.extend_from_slice(serder.raw());
            if !groups.is_empty() {
                let text = std::str::from_utf8(groups)
                    .map_err(|_| CoreError::ParseError("attachments are not ASCII".into()))?;
                push_group(
                    &mut out,
                    table,
                    GroupKind::AttachedMaterialQuadlets,
                    &[text.to_string()],
                )?;
            }
        }
    }
    Ok(out)
}

/// Compose a signed event message.
///
/// The event's controller indexed signatures, in the counter table its own
/// version implies; a version 2 event is framed as [`frame`] describes.
///
/// # Errors
/// Returns `CoreError` if the counter or signatures cannot be encoded.
pub fn compose_event(serder: &Serder, sigs: &[Siger]) -> Result<Vec<u8>, CoreError> {
    let mut groups = Vec::new();
    if !sigs.is_empty() {
        let items = sigs
            .iter()
            .map(|s| s.qb64().map_err(CoreError::Crypto))
            .collect::<Result<Vec<_>, _>>()?;
        push_group(
            &mut groups,
            table_for(serder),
            GroupKind::ControllerIdxSigs,
            &items,
        )?;
    }
    frame(serder, &groups)
}

/// Compose a non-transferable receipt message.
///
/// The event followed by one non-transferable receipt couple (prefix and
/// cigar) in the counter table its own version implies.
///
/// # Errors
/// Returns `CoreError` if the counter or primitives cannot be encoded.
pub fn compose_receipt(serder: &Serder, prefix: &str, cigar: &Cigar) -> Result<Vec<u8>, CoreError> {
    let cigar_qb64 = cigar.qb64().map_err(CoreError::Crypto)?;
    let mut groups = Vec::new();
    push_group(
        &mut groups,
        table_for(serder),
        GroupKind::NonTransReceiptCouples,
        &[format!("{prefix}{cigar_qb64}")],
    )?;
    frame(serder, &groups)
}

/// Compose a message with witness indexed signatures.
///
/// Similar to `compose_event` but uses the witness-indexed-signature counter
/// code for the event's protocol version.
///
/// # Errors
/// Returns `CoreError` if encoding fails.
pub fn compose_witness_sigs(serder: &Serder, sigs: &[Siger]) -> Result<Vec<u8>, CoreError> {
    let mut groups = Vec::new();
    if !sigs.is_empty() {
        let items = sigs
            .iter()
            .map(|s| s.qb64().map_err(CoreError::Crypto))
            .collect::<Result<Vec<_>, _>>()?;
        push_group(
            &mut groups,
            table_for(serder),
            GroupKind::WitnessIdxSigs,
            &items,
        )?;
    }
    frame(serder, &groups)
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

        let mut sad = crate::sad!({
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
    fn a_version_2_event_is_framed_as_keripy_frames_it() {
        let signer = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let verfer_qb64 = signer.verfer().qb64().unwrap();
        let mut sad = crate::sad!({
            "v": "KERICAACAAJSONAAAA.",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": [verfer_qb64],
            "nt": "0",
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let composed = compose_event(&serder, &[sig]).unwrap();

        let text = std::str::from_utf8(&composed).unwrap();
        assert!(text.starts_with("-_AAACAA{"), "genus counter first: {text}");
        let tail = &text[8 + serder.size()..];
        // -C wrapping 23 quadlets: -KAW (1) and one 88-character signature (22).
        assert!(tail.starts_with("-CAX-KAW"), "{tail}");

        let (parsed, consumed) = crate::parser::parse_next(&composed).unwrap();
        assert_eq!(consumed, composed.len());
        assert_eq!(parsed.controller_sigs().len(), 1);
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
