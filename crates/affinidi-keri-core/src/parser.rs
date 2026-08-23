//! Parser for KERI message streams.
//!
//! Handles parsing of concatenated KERI messages from raw byte streams,
//! extracting events and their attached signatures grouped by CESR
//! counter codes.

use affinidi_cesr::tables::{hardage, indexer_sizage};
use affinidi_cesr::{Counter, Indexer};
use affinidi_keri_crypto::Siger;

use crate::counter_table::{CounterTable, GroupKind};
use crate::error::CoreError;
use crate::serder::Serder;

/// Maximum number of primitives allowed per attachment group.
/// Prevents memory exhaustion from malicious counter values.
const MAX_ATTACHMENT_COUNT: usize = 4096;

/// Minimum size in bytes of a single CESR primitive (smallest qb64 code).
const MIN_PRIMITIVE_SIZE: usize = 4;

/// A receipt couple: (prefix qb64, signature raw bytes).
type ReceiptCouple = (String, Vec<u8>);

/// A transferable indexed signature group: a signature made by a transferable
/// identifier, carried with the point in that identifier's KEL that authorises
/// it.
///
/// This is how a `did:webs` designated-aliases ACDC is signed by the AID that
/// issued it, so it is what an `alsoKnownAs` list has to be verified against.
#[derive(Debug, Clone)]
pub struct TransIdxSigGroup {
    /// The signing identifier's prefix, qb64.
    pub prefix: String,
    /// The sequence number of the establishment event, qb64.
    pub sn: String,
    /// The SAID of the establishment event, qb64.
    pub said: String,
    /// The indexed signatures made under that key state.
    pub sigs: Vec<Siger>,
}

/// A parsed message consisting of a serialized event and its attachments.
#[derive(Debug)]
pub struct ParsedMessage {
    /// The serialized event.
    pub serder: Serder,
    /// Attached signature groups, receipts, etc.
    pub attachments: Vec<Attachment>,
}

/// An attachment group parsed from the CESR stream following a message body.
///
/// Counter codes are interpreted against the message's [`CounterTable`]; see
/// that type for why the same code means different things in KERI 1.x and 2.x.
#[derive(Debug)]
#[non_exhaustive]
pub enum Attachment {
    /// Controller indexed signatures.
    ControllerSigs(Vec<Siger>),
    /// Witness indexed signatures.
    WitnessSigs(Vec<Siger>),
    /// Non-transferable receipt couples: (witness prefix qb64, signature raw).
    ReceiptCouples(Vec<ReceiptCouple>),
    /// First seen replay couples, kept as qb64: (sequence number, datetime).
    FirstSeenReplayCouples(Vec<(String, String)>),
    /// Seal source couples, kept as qb64: (sequence number, event SAID).
    ///
    /// This is the delegator anchor attached to a delegated event.
    SealSourceCouples(Vec<(String, String)>),
    /// Transferable indexed signature groups.
    TransIdxSigGroups(Vec<TransIdxSigGroup>),
    /// A group whose counter code this parser does not interpret.
    ///
    /// Only produced by [`parse_all_lenient`]; strict parsing rejects the
    /// stream instead. `raw` holds *every remaining attachment byte*, not just
    /// this group: an uninterpreted counter's length cannot be derived, so
    /// nothing after it can be located either.
    Unknown {
        /// The counter code, e.g. `"-F"`.
        code: String,
        /// The counter's count field, whose unit depends on the group.
        count: usize,
        /// The remaining attachment bytes, starting after the counter.
        raw: Vec<u8>,
    },
}

impl ParsedMessage {
    /// The controller signatures attached to this message, if any.
    pub fn controller_sigs(&self) -> &[Siger] {
        self.attachments
            .iter()
            .find_map(|a| match a {
                Attachment::ControllerSigs(sigs) => Some(sigs.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// The witness signatures attached to this message, if any.
    pub fn witness_sigs(&self) -> &[Siger] {
        self.attachments
            .iter()
            .find_map(|a| match a {
                Attachment::WitnessSigs(sigs) => Some(sigs.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// The seal source couples attached to this message, if any.
    ///
    /// A delegated event carries its delegator anchor here.
    pub fn seal_source_couples(&self) -> &[(String, String)] {
        self.attachments
            .iter()
            .find_map(|a| match a {
                Attachment::SealSourceCouples(couples) => Some(couples.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// The transferable indexed signature groups attached to this message.
    pub fn trans_idx_sig_groups(&self) -> &[TransIdxSigGroup] {
        self.attachments
            .iter()
            .find_map(|a| match a {
                Attachment::TransIdxSigGroups(groups) => Some(groups.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Whether any attachment group could not be interpreted.
    ///
    /// Verification paths must refuse a message where this is true: an
    /// uninterpreted group may be carrying the signatures or receipts that
    /// were supposed to be checked.
    pub fn has_uninterpreted_attachments(&self) -> bool {
        self.attachments
            .iter()
            .any(|a| matches!(a, Attachment::Unknown { .. }))
    }
}

/// Parse the next message from a byte stream.
///
/// Returns the parsed message and the number of bytes consumed.
///
/// # Errors
/// Returns `CoreError::ParseError` if the stream cannot be parsed.
pub fn parse_next(stream: &[u8]) -> Result<(ParsedMessage, usize), CoreError> {
    parse_next_inner(stream, true)
}

/// Like [`parse_next`], but records an uninterpretable attachment group as
/// [`Attachment::Unknown`] instead of failing.
///
/// Use only for inspection. Anything that verifies signatures must use the
/// strict form, or at minimum reject a message where
/// [`ParsedMessage::has_uninterpreted_attachments`] is true.
///
/// # Errors
/// Returns `CoreError::ParseError` if the message body cannot be parsed.
pub fn parse_next_lenient(stream: &[u8]) -> Result<(ParsedMessage, usize), CoreError> {
    parse_next_inner(stream, false)
}

fn parse_next_inner(stream: &[u8], strict: bool) -> Result<(ParsedMessage, usize), CoreError> {
    if stream.is_empty() {
        return Err(CoreError::ParseError("empty stream".into()));
    }

    // Detect whether the stream starts with a message body (JSON/CBOR/MGPK)
    // or a CESR-native text stream.
    let first = stream[0];
    if first == b'{' || is_cbor_start(first) || is_msgpack_start(first) {
        parse_next_sad(stream, strict)
    } else {
        Err(CoreError::ParseError(format!(
            "unrecognized stream start byte: 0x{first:02x}"
        )))
    }
}

/// Parse all messages from a byte stream.
///
/// # Errors
/// Returns `CoreError::ParseError` if any message cannot be parsed.
pub fn parse_all(stream: &[u8]) -> Result<Vec<ParsedMessage>, CoreError> {
    parse_all_inner(stream, true)
}

/// Like [`parse_all`], but records uninterpretable attachment groups as
/// [`Attachment::Unknown`] instead of failing. See [`parse_next_lenient`].
///
/// # Errors
/// Returns `CoreError::ParseError` if a message body cannot be parsed.
pub fn parse_all_lenient(stream: &[u8]) -> Result<Vec<ParsedMessage>, CoreError> {
    parse_all_inner(stream, false)
}

fn parse_all_inner(stream: &[u8], strict: bool) -> Result<Vec<ParsedMessage>, CoreError> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset < stream.len() {
        // Skip any whitespace between messages
        while offset < stream.len() && stream[offset].is_ascii_whitespace() {
            offset += 1;
        }
        if offset >= stream.len() {
            break;
        }

        let (msg, consumed) = parse_next_inner(&stream[offset..], strict)?;
        if consumed == 0 {
            return Err(CoreError::ParseError(
                "parse_next consumed zero bytes".into(),
            ));
        }
        messages.push(msg);
        offset += consumed;
    }

    Ok(messages)
}

/// Parse a SAD-based message (JSON/CBOR/MGPK) followed by CESR attachments.
fn parse_next_sad(stream: &[u8], strict: bool) -> Result<(ParsedMessage, usize), CoreError> {
    let serder = Serder::from_raw(stream)?;
    let msg_size = serder.size();

    // The counter table is chosen by the protocol version in the message's own
    // version string, never guessed: reading a 1.x stream against the 2.x
    // table turns controller signatures into an uninterpreted group.
    let table = serder
        .version
        .as_ref()
        .map_or(CounterTable::default(), |v| {
            CounterTable::from_major(v.major)
        });

    // Parse attachments after the message body
    let rest = &stream[msg_size..];
    let (attachments, att_consumed) = parse_attachments(rest, table, strict)?;

    let total_consumed = msg_size + att_consumed;
    Ok((
        ParsedMessage {
            serder,
            attachments,
        },
        total_consumed,
    ))
}

/// Parse CESR attachment groups from the stream following a message body.
///
/// `table` decides what each counter code means; see [`CounterTable`].
///
/// In strict mode a counter code this parser does not model is an error. In
/// lenient mode it is recorded as [`Attachment::Unknown`] and parsing stops,
/// because a group of unknown shape has unknown length — nothing after it can
/// be located.
///
/// Returns the parsed attachments and the number of bytes consumed.
fn parse_attachments(
    data: &[u8],
    table: CounterTable,
    strict: bool,
) -> Result<(Vec<Attachment>, usize), CoreError> {
    let mut attachments = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Check if we're looking at a counter code (starts with '-')
        if data[offset] != b'-' {
            // Not an attachment group; stop parsing attachments
            break;
        }

        // Try to parse a counter from the text.
        // CESR is Base64-encoded, so all valid data must be ASCII.
        // Reject non-ASCII to prevent panics from byte-indexing multi-byte UTF-8.
        if !data[offset..].is_ascii() {
            return Err(CoreError::ParseError(
                "attachment data contains non-ASCII bytes".into(),
            ));
        }
        let rest = std::str::from_utf8(&data[offset..])
            .map_err(|_| CoreError::ParseError("attachment data is not valid UTF-8".into()))?;

        let counter = Counter::from_qb64(rest)
            .map_err(|e| CoreError::ParseError(format!("failed to parse counter: {e}")))?;

        let counter_size = counter.full_size();
        offset += counter_size;

        let code = counter.code().to_string();
        let count = counter.count();

        let Some(kind) = GroupKind::classify(&code, table) else {
            if strict {
                return Err(CoreError::ParseError(format!(
                    "unrecognised attachment counter code {code:?} for {table:?}; \
                     refusing to guess its length"
                )));
            }
            attachments.push(Attachment::Unknown {
                code,
                count,
                raw: data[offset..].to_vec(),
            });
            offset = data.len();
            break;
        };

        match kind {
            GroupKind::AttachedMaterialQuadlets => {
                // The count is in quadlets (4-character units) of nested
                // attachment material, not a number of primitives. Recurse
                // into exactly that span so a wrapper cannot swallow the
                // groups it contains.
                let byte_len = count.checked_mul(4).ok_or_else(|| {
                    CoreError::ParseError(format!("quadlet count {count} overflows"))
                })?;
                let end = offset.checked_add(byte_len).ok_or_else(|| {
                    CoreError::ParseError("attachment group extends past usize".into())
                })?;
                if end > data.len() {
                    return Err(CoreError::ParseError(format!(
                        "attachment group of {byte_len} bytes extends past the stream \
                         ({} bytes available)",
                        data.len() - offset
                    )));
                }
                let (inner, consumed) = parse_attachments(&data[offset..end], table, strict)?;
                if consumed != byte_len {
                    return Err(CoreError::ParseError(format!(
                        "attachment group declared {byte_len} bytes but its contents \
                         accounted for {consumed}"
                    )));
                }
                attachments.extend(inner);
                offset = end;
            }
            GroupKind::ControllerIdxSigs => {
                let (sigers, consumed) = parse_indexed_sigs(&data[offset..], count)?;
                attachments.push(Attachment::ControllerSigs(sigers));
                offset += consumed;
            }
            GroupKind::WitnessIdxSigs => {
                let (sigers, consumed) = parse_indexed_sigs(&data[offset..], count)?;
                attachments.push(Attachment::WitnessSigs(sigers));
                offset += consumed;
            }
            GroupKind::NonTransReceiptCouples => {
                let (couples, consumed) = parse_receipt_couples(&data[offset..], count)?;
                attachments.push(Attachment::ReceiptCouples(couples));
                offset += consumed;
            }
            GroupKind::FirstSeenReplayCouples => {
                let (couples, consumed) = parse_qb64_pairs(&data[offset..], count)?;
                attachments.push(Attachment::FirstSeenReplayCouples(couples));
                offset += consumed;
            }
            GroupKind::SealSourceCouples => {
                let (couples, consumed) = parse_qb64_pairs(&data[offset..], count)?;
                attachments.push(Attachment::SealSourceCouples(couples));
                offset += consumed;
            }
            GroupKind::TransIdxSigGroups => {
                let (groups, consumed) =
                    parse_trans_idx_sig_groups(&data[offset..], count, table, strict)?;
                attachments.push(Attachment::TransIdxSigGroups(groups));
                offset += consumed;
            }
            // Modelled in the code table but not yet parsed. Treated exactly
            // like an unrecognised code rather than skipped, because their
            // internal shape is what determines their length.
            GroupKind::TransReceiptQuadruples => {
                if strict {
                    return Err(CoreError::ParseError(format!(
                        "attachment group {code:?} ({kind:?}) is not yet supported; \
                         refusing to guess its length"
                    )));
                }
                attachments.push(Attachment::Unknown {
                    code,
                    count,
                    raw: data[offset..].to_vec(),
                });
                offset = data.len();
                break;
            }
        }
    }

    Ok((attachments, offset))
}

/// Parse `count` transferable indexed signature groups.
///
/// Each group is a (prefix, sequence number, event SAID) triple followed by a
/// nested controller-indexed-signature group.
fn parse_trans_idx_sig_groups(
    data: &[u8],
    count: usize,
    table: CounterTable,
    strict: bool,
) -> Result<(Vec<TransIdxSigGroup>, usize), CoreError> {
    if count > MAX_ATTACHMENT_COUNT {
        return Err(CoreError::ParseError(format!(
            "transferable sig group count {count} exceeds maximum of {MAX_ATTACHMENT_COUNT}"
        )));
    }
    if !data.is_ascii() {
        return Err(CoreError::ParseError(
            "transferable sig group data contains non-ASCII bytes".into(),
        ));
    }
    let text = std::str::from_utf8(data).map_err(|_| {
        CoreError::ParseError("transferable sig group data is not valid UTF-8".into())
    })?;

    let mut groups = Vec::with_capacity(count);
    let mut offset = 0;

    for i in 0..count {
        let (prefix, n) = parse_matter_qb64(&text[offset..], i, "transferable sig group prefix")?;
        offset += n;
        let (sn, n) = parse_matter_qb64(&text[offset..], i, "transferable sig group sn")?;
        offset += n;
        let (said, n) = parse_matter_qb64(&text[offset..], i, "transferable sig group said")?;
        offset += n;

        // The signatures follow as their own counted group.
        let (inner, consumed) = parse_attachments(&data[offset..], table, strict)?;
        offset += consumed;

        let mut sigs = Vec::new();
        for att in inner {
            match att {
                Attachment::ControllerSigs(s) => sigs.extend(s),
                other => {
                    return Err(CoreError::ParseError(format!(
                        "transferable sig group {i} contains {other:?} where indexed \
                         signatures were expected"
                    )));
                }
            }
        }
        if sigs.is_empty() {
            return Err(CoreError::ParseError(format!(
                "transferable sig group {i} carries no signatures"
            )));
        }

        groups.push(TransIdxSigGroup {
            prefix,
            sn,
            said,
            sigs,
        });
    }

    Ok((groups, offset))
}

/// Parse `count` pairs of fixed-size qb64 primitives, returning them as
/// strings. Used for the couple-shaped groups (first seen replay, seal
/// source) whose members are plain Matter primitives.
fn parse_qb64_pairs(
    data: &[u8],
    count: usize,
) -> Result<(Vec<(String, String)>, usize), CoreError> {
    if count > MAX_ATTACHMENT_COUNT {
        return Err(CoreError::ParseError(format!(
            "couple count {count} exceeds maximum of {MAX_ATTACHMENT_COUNT}"
        )));
    }
    if count * MIN_PRIMITIVE_SIZE * 2 > data.len() {
        return Err(CoreError::ParseError(format!(
            "couple count {count} requires at least {} bytes, but only {} available",
            count * MIN_PRIMITIVE_SIZE * 2,
            data.len()
        )));
    }
    if !data.is_ascii() {
        return Err(CoreError::ParseError(
            "couple data contains non-ASCII bytes".into(),
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| CoreError::ParseError("couple data is not valid UTF-8".into()))?;

    let mut couples = Vec::with_capacity(count);
    let mut offset = 0;

    for i in 0..count {
        let (first, first_size) = parse_matter_qb64(&text[offset..], i, "couple first member")?;
        offset += first_size;
        let (second, second_size) = parse_matter_qb64(&text[offset..], i, "couple second member")?;
        offset += second_size;
        couples.push((first, second));
    }

    Ok((couples, offset))
}

/// Parse `count` indexed signatures from the data.
fn parse_indexed_sigs(data: &[u8], count: usize) -> Result<(Vec<Siger>, usize), CoreError> {
    if count > MAX_ATTACHMENT_COUNT {
        return Err(CoreError::ParseError(format!(
            "indexed sig count {count} exceeds maximum of {MAX_ATTACHMENT_COUNT}"
        )));
    }
    if count * MIN_PRIMITIVE_SIZE > data.len() {
        return Err(CoreError::ParseError(format!(
            "indexed sig count {count} requires at least {} bytes, but only {} available",
            count * MIN_PRIMITIVE_SIZE,
            data.len()
        )));
    }

    // CESR is Base64-encoded, so all valid data must be ASCII.
    // Reject non-ASCII to prevent panics from byte-indexing multi-byte UTF-8.
    if !data.is_ascii() {
        return Err(CoreError::ParseError(
            "indexed sig data contains non-ASCII bytes".into(),
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| CoreError::ParseError("indexed sig data is not valid UTF-8".into()))?;

    let mut sigers = Vec::with_capacity(count);
    let mut offset = 0;

    for i in 0..count {
        if offset >= text.len() {
            return Err(CoreError::ParseError(format!(
                "unexpected end of data while parsing indexed sig {i}/{count}"
            )));
        }

        // Determine the full size of this indexed signature
        let first_char = text[offset..]
            .chars()
            .next()
            .ok_or_else(|| CoreError::ParseError(format!("empty data for indexed sig {i}")))?;
        let hs = hardage(first_char).ok_or_else(|| {
            CoreError::ParseError(format!(
                "unknown hardage for char '{first_char}' in indexed sig"
            ))
        })?;

        if offset + hs > text.len() {
            return Err(CoreError::ParseError("truncated indexer code".into()));
        }
        let code = &text[offset..offset + hs];
        let sizage = indexer_sizage(code)
            .ok_or_else(|| CoreError::ParseError(format!("unknown indexer code: {code}")))?;

        if offset + sizage.fs > text.len() {
            return Err(CoreError::ParseError(format!(
                "truncated indexed sig: need {}, have {}",
                sizage.fs,
                text.len() - offset
            )));
        }

        let qb64 = &text[offset..offset + sizage.fs];
        let indexer = Indexer::from_qb64(qb64)
            .map_err(|e| CoreError::ParseError(format!("failed to parse indexer: {e}")))?;

        let siger = Siger::new(
            indexer.code(),
            indexer.index(),
            indexer.ondex(),
            indexer.raw().to_vec(),
        )
        .map_err(CoreError::Crypto)?;

        sigers.push(siger);
        offset += sizage.fs;
    }

    Ok((sigers, offset))
}

/// Parse `count` receipt couples (prefix + non-indexed signature).
/// Each couple is a Matter primitive (prefix) + Matter primitive (signature).
fn parse_receipt_couples(
    data: &[u8],
    count: usize,
) -> Result<(Vec<ReceiptCouple>, usize), CoreError> {
    if count > MAX_ATTACHMENT_COUNT {
        return Err(CoreError::ParseError(format!(
            "receipt couple count {count} exceeds maximum of {MAX_ATTACHMENT_COUNT}"
        )));
    }
    // Each couple contains two primitives.
    if count * MIN_PRIMITIVE_SIZE * 2 > data.len() {
        return Err(CoreError::ParseError(format!(
            "receipt couple count {count} requires at least {} bytes, but only {} available",
            count * MIN_PRIMITIVE_SIZE * 2,
            data.len()
        )));
    }

    // CESR is Base64-encoded, so all valid data must be ASCII.
    // Reject non-ASCII to prevent panics from byte-indexing multi-byte UTF-8.
    if !data.is_ascii() {
        return Err(CoreError::ParseError(
            "receipt couple data contains non-ASCII bytes".into(),
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| CoreError::ParseError("receipt couple data is not valid UTF-8".into()))?;

    let mut couples = Vec::with_capacity(count);
    let mut offset = 0;

    for i in 0..count {
        // Parse prefix (Matter primitive)
        let (prefix_qb64, prefix_size) = parse_matter_qb64(&text[offset..], i, "prefix")?;
        offset += prefix_size;

        // Parse signature (Matter primitive)
        let (sig_qb64, sig_size) = parse_matter_qb64(&text[offset..], i, "signature")?;
        offset += sig_size;

        // Decode the signature raw bytes from the Matter
        let sig_matter = affinidi_cesr::Matter::from_qb64(&sig_qb64)
            .map_err(|e| CoreError::ParseError(format!("failed to parse sig matter: {e}")))?;

        couples.push((prefix_qb64, sig_matter.raw().to_vec()));
    }

    Ok((couples, offset))
}

/// Parse a single Matter primitive qb64 string from text data.
/// Returns the qb64 string and the number of characters consumed.
fn parse_matter_qb64(text: &str, index: usize, name: &str) -> Result<(String, usize), CoreError> {
    use affinidi_cesr::tables::matter_sizage;

    if text.is_empty() {
        return Err(CoreError::ParseError(format!(
            "empty data for {name} at couple {index}"
        )));
    }

    let first_char = text
        .chars()
        .next()
        .ok_or_else(|| CoreError::ParseError(format!("empty data for {name} at couple {index}")))?;

    let hs = hardage(first_char).ok_or_else(|| {
        CoreError::ParseError(format!("unknown hardage for char '{first_char}' in {name}"))
    })?;

    if text.len() < hs {
        return Err(CoreError::ParseError(format!(
            "truncated {name} code at couple {index}"
        )));
    }

    let code = &text[..hs];
    let sizage = matter_sizage(code)
        .ok_or_else(|| CoreError::ParseError(format!("unknown matter code: {code} for {name}")))?;

    let fs = if sizage.fs > 0 {
        sizage.fs
    } else {
        return Err(CoreError::ParseError(format!(
            "variable-length {name} not supported in receipt couples"
        )));
    };

    if text.len() < fs {
        return Err(CoreError::ParseError(format!(
            "truncated {name}: need {fs}, have {}",
            text.len()
        )));
    }

    Ok((text[..fs].to_string(), fs))
}

/// Check if a byte is a CBOR map start.
fn is_cbor_start(b: u8) -> bool {
    matches!(b, 0xa0..=0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbf)
}

/// Check if a byte is a MessagePack map start.
fn is_msgpack_start(b: u8) -> bool {
    matches!(b, 0x80..=0x8f | 0xde | 0xdf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer;
    use crate::said;
    use crate::version::SerializationKind;
    use affinidi_keri_crypto::{Diger, Signer};

    #[test]
    fn test_parse_next_json_no_attachments() {
        let sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": ["DKey"],
            "nt": "1",
            "n": ["EDigest"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let raw = serder.raw().to_vec();

        let (parsed, consumed) = parse_next(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(parsed.serder.ilk().unwrap(), "icp");
        assert!(parsed.attachments.is_empty());
    }

    #[test]
    fn test_parse_all_empty() {
        let result = parse_all(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_compose_parse_roundtrip() {
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
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();

        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();
        let composed = composer::compose_event(&serder, &[sig]).unwrap();

        // Parse it back
        let (parsed, consumed) = parse_next(&composed).unwrap();
        assert_eq!(consumed, composed.len());
        assert_eq!(parsed.serder.ilk().unwrap(), "icp");
        assert_eq!(parsed.attachments.len(), 1);

        match &parsed.attachments[0] {
            Attachment::ControllerSigs(sigers) => {
                assert_eq!(sigers.len(), 1);
                assert_eq!(sigers[0].index(), 0);
            }
            other => panic!("expected ControllerSigs, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_all_multiple_messages() {
        let signer = Signer::new("A", [7u8; 32].to_vec()).unwrap();
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
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let sig = signer.sign_indexed(serder.raw(), 0, true).unwrap();

        let msg1 = composer::compose_event(&serder, std::slice::from_ref(&sig)).unwrap();
        let msg2 = composer::compose_event(&serder, std::slice::from_ref(&sig)).unwrap();

        let mut combined = msg1;
        combined.extend_from_slice(&msg2);

        let messages = parse_all(&combined).unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn test_parse_next_empty_stream() {
        assert!(parse_next(&[]).is_err());
    }

    #[test]
    fn test_parse_next_unknown_start() {
        assert!(parse_next(&[0x00]).is_err());
    }

    #[test]
    fn test_non_ascii_attachment_returns_error() {
        // Build a valid JSON event body, then append a counter + non-ASCII bytes.
        // This reproduces the PoC: a -D counter followed by multi-byte UTF-8.
        let mut sad = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": ["DKey"],
            "nt": "1",
            "n": ["EDigest"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        crate::said::compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
        let serder = Serder::new(SerializationKind::Json, sad).unwrap();
        let mut payload = serder.raw().to_vec();

        // Append a -D counter (count=1) then non-ASCII bytes that would panic
        // on byte-offset slicing without the ASCII guard.
        // -DAAB is counter code "-D" with count 1 in qb64.
        payload.extend_from_slice(b"-DAAB");
        // 'é' is 0xC3 0xA9 (2-byte UTF-8) — slicing at byte 2 inside it panics.
        payload.extend_from_slice(b"0\xc3\xa9AAAAAAAAAA");

        let result = parse_next(&payload);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("non-ASCII"),
            "expected non-ASCII error, got: {err}"
        );
    }

    #[test]
    fn test_non_ascii_indexed_sigs_returns_error() {
        // Directly test parse_indexed_sigs with non-ASCII data
        let data = b"A\xc3\xa9BBBBBBBBBBB";
        let result = parse_indexed_sigs(data, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-ASCII"));
    }

    #[test]
    fn test_non_ascii_qb64_pairs_returns_error() {
        // Directly test parse_qb64_pairs with non-ASCII data
        let data = b"0\xc3\xa9AAAAAAAAAA";
        let result = parse_qb64_pairs(data, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-ASCII"));
    }
}
