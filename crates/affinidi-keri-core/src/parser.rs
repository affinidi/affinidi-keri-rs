//! Parser for KERI message streams.
//!
//! Handles parsing of concatenated KERI messages from raw byte streams,
//! extracting events and their attached signatures grouped by CESR
//! counter codes.

use affinidi_cesr::tables::{counter_sizage, hardage, indexer_sizage};
use affinidi_cesr::{Counter, Indexer};
use affinidi_keri_crypto::Siger;

use crate::error::CoreError;
use crate::serder::Serder;

/// A receipt couple: (prefix qb64, signature raw bytes).
type ReceiptCouple = (String, Vec<u8>);

/// A parsed message consisting of a serialized event and its attachments.
#[derive(Debug)]
pub struct ParsedMessage {
    /// The serialized event.
    pub serder: Serder,
    /// Attached signature groups, receipts, etc.
    pub attachments: Vec<Attachment>,
}

/// An attachment group parsed from the CESR stream following a message body.
#[derive(Debug)]
pub enum Attachment {
    /// Controller indexed signatures (counter code `-B`).
    ControllerSigs(Vec<Siger>),
    /// Witness indexed signatures (counter code `-C`).
    WitnessSigs(Vec<Siger>),
    /// Receipt couples (prefix qb64, signature raw bytes) (counter code `-D`).
    ReceiptCouples(Vec<(String, Vec<u8>)>),
    /// Raw unparsed attachment bytes for unrecognized counter codes.
    Raw(Vec<u8>),
}

/// Parse the next message from a byte stream.
///
/// Returns the parsed message and the number of bytes consumed.
///
/// # Errors
/// Returns `CoreError::ParseError` if the stream cannot be parsed.
pub fn parse_next(stream: &[u8]) -> Result<(ParsedMessage, usize), CoreError> {
    if stream.is_empty() {
        return Err(CoreError::ParseError("empty stream".into()));
    }

    // Detect whether the stream starts with a message body (JSON/CBOR/MGPK)
    // or a CESR-native text stream.
    let first = stream[0];
    if first == b'{' || is_cbor_start(first) || is_msgpack_start(first) {
        parse_next_sad(stream)
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

        let (msg, consumed) = parse_next(&stream[offset..])?;
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
fn parse_next_sad(stream: &[u8]) -> Result<(ParsedMessage, usize), CoreError> {
    let serder = Serder::from_raw(stream)?;
    let msg_size = serder.size();

    // Parse attachments after the message body
    let rest = &stream[msg_size..];
    let (attachments, att_consumed) = parse_attachments(rest)?;

    let total_consumed = msg_size + att_consumed;
    Ok((ParsedMessage { serder, attachments }, total_consumed))
}

/// Parse CESR attachment groups from the stream following a message body.
///
/// Returns the parsed attachments and the number of bytes consumed.
fn parse_attachments(data: &[u8]) -> Result<(Vec<Attachment>, usize), CoreError> {
    let mut attachments = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Check if we're looking at a counter code (starts with '-')
        if data[offset] != b'-' {
            // Not an attachment group; stop parsing attachments
            break;
        }

        // Try to parse a counter from the text
        let rest = std::str::from_utf8(&data[offset..]).map_err(|_| {
            CoreError::ParseError("attachment data is not valid UTF-8".into())
        })?;

        let counter = Counter::from_qb64(rest).map_err(|e| {
            CoreError::ParseError(format!("failed to parse counter: {e}"))
        })?;

        let counter_size = counter.full_size();
        offset += counter_size;

        let code = counter.code().to_string();
        let count = counter.count();

        match code.as_str() {
            "-B" | "-0B" => {
                // Controller indexed signatures
                let (sigers, consumed) = parse_indexed_sigs(&data[offset..], count)?;
                attachments.push(Attachment::ControllerSigs(sigers));
                offset += consumed;
            }
            "-C" | "-0C" => {
                // Witness indexed signatures
                let (sigers, consumed) = parse_indexed_sigs(&data[offset..], count)?;
                attachments.push(Attachment::WitnessSigs(sigers));
                offset += consumed;
            }
            "-D" | "-0D" => {
                // Non-transferable receipt couples (prefix + cigar)
                let (couples, consumed) = parse_receipt_couples(&data[offset..], count)?;
                attachments.push(Attachment::ReceiptCouples(couples));
                offset += consumed;
            }
            _ => {
                // Unknown counter code: try to skip the counted primitives
                // For safety, we store the remaining bytes we can identify as raw
                let (raw, consumed) = skip_counted_primitives(&data[offset..], count)?;
                attachments.push(Attachment::Raw(raw));
                offset += consumed;
            }
        }
    }

    Ok((attachments, offset))
}

/// Parse `count` indexed signatures from the data.
fn parse_indexed_sigs(data: &[u8], count: usize) -> Result<(Vec<Siger>, usize), CoreError> {
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
        let first_char = text[offset..].chars().next().ok_or_else(|| {
            CoreError::ParseError(format!("empty data for indexed sig {i}"))
        })?;
        let hs = hardage(first_char).ok_or_else(|| {
            CoreError::ParseError(format!(
                "unknown hardage for char '{first_char}' in indexed sig"
            ))
        })?;

        if offset + hs > text.len() {
            return Err(CoreError::ParseError("truncated indexer code".into()));
        }
        let code = &text[offset..offset + hs];
        let sizage = indexer_sizage(code).ok_or_else(|| {
            CoreError::ParseError(format!("unknown indexer code: {code}"))
        })?;

        if offset + sizage.fs > text.len() {
            return Err(CoreError::ParseError(format!(
                "truncated indexed sig: need {}, have {}",
                sizage.fs,
                text.len() - offset
            )));
        }

        let qb64 = &text[offset..offset + sizage.fs];
        let indexer = Indexer::from_qb64(qb64).map_err(|e| {
            CoreError::ParseError(format!("failed to parse indexer: {e}"))
        })?;

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
        let sig_matter = affinidi_cesr::Matter::from_qb64(&sig_qb64).map_err(|e| {
            CoreError::ParseError(format!("failed to parse sig matter: {e}"))
        })?;

        couples.push((prefix_qb64, sig_matter.raw().to_vec()));
    }

    Ok((couples, offset))
}

/// Parse a single Matter primitive qb64 string from text data.
/// Returns the qb64 string and the number of characters consumed.
fn parse_matter_qb64(
    text: &str,
    index: usize,
    name: &str,
) -> Result<(String, usize), CoreError> {
    use affinidi_cesr::tables::matter_sizage;

    if text.is_empty() {
        return Err(CoreError::ParseError(format!(
            "empty data for {name} at couple {index}"
        )));
    }

    let first_char = text.chars().next().ok_or_else(|| {
        CoreError::ParseError(format!("empty data for {name} at couple {index}"))
    })?;

    let hs = hardage(first_char).ok_or_else(|| {
        CoreError::ParseError(format!(
            "unknown hardage for char '{first_char}' in {name}"
        ))
    })?;

    if text.len() < hs {
        return Err(CoreError::ParseError(format!(
            "truncated {name} code at couple {index}"
        )));
    }

    let code = &text[..hs];
    let sizage = matter_sizage(code).ok_or_else(|| {
        CoreError::ParseError(format!("unknown matter code: {code} for {name}"))
    })?;

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

/// Skip `count` primitives for unrecognized counter codes.
/// Returns the raw bytes and count of characters consumed.
fn skip_counted_primitives(data: &[u8], count: usize) -> Result<(Vec<u8>, usize), CoreError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| CoreError::ParseError("data is not valid UTF-8".into()))?;

    let mut offset = 0;

    for _i in 0..count {
        if offset >= text.len() {
            break;
        }

        let first_char = text[offset..].chars().next().unwrap_or('\0');
        let hs = hardage(first_char).unwrap_or(1);

        if offset + hs > text.len() {
            break;
        }

        let code = &text[offset..offset + hs];

        // Try indexer, then matter sizage
        if let Some(sizage) = indexer_sizage(code) {
            if offset + sizage.fs > text.len() {
                break;
            }
            offset += sizage.fs;
        } else if let Some(sizage) = affinidi_cesr::tables::matter_sizage(code) {
            if sizage.fs > 0 {
                if offset + sizage.fs > text.len() {
                    break;
                }
                offset += sizage.fs;
            } else {
                break;
            }
        } else if let Some(sizage) = counter_sizage(code) {
            if offset + sizage.fs > text.len() {
                break;
            }
            offset += sizage.fs;
        } else {
            break;
        }
    }

    Ok((data[..offset].to_vec(), offset))
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

        let msg1 = composer::compose_event(&serder, &[sig.clone()]).unwrap();
        let msg2 = composer::compose_event(&serder, &[sig]).unwrap();

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
}
