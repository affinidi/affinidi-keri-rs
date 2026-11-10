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

/// Compose a message endorsed by a transferable identifier: the body and one
/// transferable indexed signature group (`-F` in 1.x, `-X` in 2.x), naming
/// the establishment event whose key state made the signatures.
///
/// This is how a `rpy` (an endpoint role or location) or a 1.x ACDC is signed
/// by an AID. The group holds `prefix`, the establishment event's sequence
/// number `sn` and SAID `establishment`, then `sigs` as a controller
/// signature group. The sequence number is written as each genus writes it:
/// a 1.x `Seqner` (`0A`, 16 bytes), or a 2.x `Number` in the smallest code
/// that holds it (keripy `messagize` with `tsgs`).
///
/// # Errors
/// Returns `CoreError` if `sigs` is empty or a primitive cannot be encoded.
pub fn compose_endorsed(
    serder: &Serder,
    prefix: &str,
    sn: u64,
    establishment: &str,
    sigs: &[Siger],
) -> Result<Vec<u8>, CoreError> {
    if sigs.is_empty() {
        return Err(CoreError::Validation(
            "an endorsement needs at least one signature".into(),
        ));
    }
    let table = table_for(serder);
    let items = sigs
        .iter()
        .map(|s| s.qb64().map_err(CoreError::Crypto))
        .collect::<Result<Vec<_>, _>>()?;
    let mut group = Vec::new();
    group.extend_from_slice(prefix.as_bytes());
    group.extend_from_slice(sequence_number(table, sn)?.as_bytes());
    group.extend_from_slice(establishment.as_bytes());
    push_group(&mut group, table, GroupKind::ControllerIdxSigs, &items)?;
    let group = String::from_utf8(group)
        .map_err(|_| CoreError::ParseError("an endorsement is not ASCII".into()))?;

    let mut groups = Vec::new();
    push_group(&mut groups, table, GroupKind::TransIdxSigGroups, &[group])?;
    frame(serder, &groups)
}

/// A sequence number as an attachment carries it in `table`'s genus.
pub(crate) fn sequence_number(table: CounterTable, sn: u64) -> Result<String, CoreError> {
    match table {
        CounterTable::V1 => {
            let mut raw = [0u8; 16];
            raw[8..].copy_from_slice(&sn.to_be_bytes());
            cesr("0A", &raw, 24)
        }
        _ => number(sn),
    }
}

/// A number as keripy's `Number` writes it: the smallest of Short (`M`, 2
/// bytes), Long (`0H`, 4), Tall (`R`, 5) and Big (`N`, 8) that holds it.
pub(crate) fn number(n: u64) -> Result<String, CoreError> {
    let bytes = n.to_be_bytes();
    if n <= 0xffff {
        cesr("M", &bytes[6..], 4)
    } else if n <= 0xffff_ffff {
        cesr("0H", &bytes[4..], 8)
    } else if n <= 0xff_ffff_ffff {
        cesr("R", &bytes[3..], 8)
    } else {
        cesr("N", &bytes, 12)
    }
}

fn cesr(code: &str, raw: &[u8], fs: usize) -> Result<String, CoreError> {
    affinidi_cesr::codec::encode_qb64(code, raw, fs)
        .map_err(|e| CoreError::ParseError(format!("cannot encode {code}: {e}")))
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

    #[test]
    fn sequence_numbers_read_back() {
        use crate::parser::number_value;
        for n in [
            0u64,
            1,
            0xff,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            for table in [CounterTable::V1, CounterTable::V2] {
                let qb64 = sequence_number(table, n).unwrap();
                assert_eq!(number_value(&qb64).unwrap(), n, "{qb64}");
            }
        }
        assert_eq!(number_value("MAAB").unwrap(), 1);
        assert!(number_value("EAAB").is_err());
        assert!(number_value("MAA").is_err());
    }

    #[test]
    fn a_version_1_endorsement_is_an_f_group_with_a_seqner() {
        let serder = make_test_serder();
        let signer = Signer::new("A", [42u8; 32].to_vec()).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let prefix = serder.prefix().unwrap();
        let said = serder.said().unwrap();
        let out = compose_endorsed(&serder, &prefix, 3, &said, std::slice::from_ref(&sig)).unwrap();
        let text = String::from_utf8(out).unwrap();
        let attachments = &text[serder.size()..];
        let expected = format!(
            "-FAB{prefix}0AAAAAAAAAAAAAAAAAAAAAAD{said}-AAB{}",
            sig.qb64().unwrap()
        );
        assert_eq!(attachments, expected);
        assert!(compose_endorsed(&serder, &prefix, 3, &said, &[]).is_err());
    }

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
