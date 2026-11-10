//! Parser for KERI message streams.
//!
//! Handles parsing of concatenated KERI messages from raw byte streams,
//! extracting events and their attached signatures grouped by CESR
//! counter codes.

use affinidi_cesr::Indexer;
use affinidi_cesr::tables::{hardage, indexer_sizage};
use affinidi_keri_crypto::Siger;

use crate::counter_table::{CounterTable, GroupKind, read_counter};
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
/// The stream is read as a stream of its own: it is in CESR genus 1.x unless
/// it opens with a genus-version counter (`-_AAA…`), which this consumes
/// (did:webs on KERI v2, P1). To keep the genus across calls, use
/// [`parse_next_in`].
///
/// Returns the parsed message and the number of bytes consumed.
///
/// # Errors
/// Returns `CoreError::ParseError` if the stream cannot be parsed.
pub fn parse_next(stream: &[u8]) -> Result<(ParsedMessage, usize), CoreError> {
    let mut genus = CounterTable::V1;
    parse_next_inner(stream, &mut genus, true)
}

/// Parse the next message in a stream whose genus so far is `genus`.
///
/// A genus-version counter before the message switches `genus`, and the
/// message's attachments are read in the result, so pass the same `genus`
/// back for the next message.
///
/// # Errors
/// Returns `CoreError` if the stream cannot be parsed.
pub fn parse_next_in(
    stream: &[u8],
    genus: &mut CounterTable,
) -> Result<(ParsedMessage, usize), CoreError> {
    parse_next_inner(stream, genus, true)
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
    let mut genus = CounterTable::V1;
    parse_next_inner(stream, &mut genus, false)
}

fn parse_next_inner(
    stream: &[u8],
    genus: &mut CounterTable,
    strict: bool,
) -> Result<(ParsedMessage, usize), CoreError> {
    let mut offset = 0;
    // Genus-version counters before the message switch the stream's genus.
    while stream[offset..].starts_with(b"-_") {
        let counter = read_counter(&stream[offset..])?;
        let (major, _minor) = counter.genus_version().ok_or_else(|| {
            CoreError::ParseError(format!(
                "{:?} is not a genus-version counter this parser knows",
                counter.code
            ))
        })?;
        *genus = CounterTable::for_genus(major)?;
        offset += counter.size;
    }
    let rest = &stream[offset..];
    let Some(&first) = rest.first() else {
        return Err(CoreError::ParseError("empty stream".into()));
    };

    // A message body is a JSON, CBOR or MessagePack map, or (in a 2.x
    // stream) a CESR-native group.
    if first == b'{' || is_cbor_start(first) || is_msgpack_start(first) {
        let (msg, consumed) = parse_next_sad(rest, *genus, strict)?;
        Ok((msg, offset + consumed))
    } else if first == b'-' {
        let counter = read_counter(rest)?;
        let base = counter.code.trim_start_matches('-');
        Err(match (*genus, base) {
            // keripy CounterCodex_2_0: FixBodyGroup, MapBodyGroup.
            (CounterTable::V2, "F" | "G") => CoreError::native_cesr_unsupported(),
            (CounterTable::V2, "B" | "H") | (CounterTable::V1, "U" | "W") => {
                CoreError::Unsupported(format!(
                    "enclosed message group {:?} in a {genus:?} stream",
                    counter.code
                ))
            }
            _ => CoreError::ParseError(format!(
                "a {genus:?} stream has counter {:?} where a message was expected",
                counter.code
            )),
        })
    } else {
        Err(CoreError::ParseError(format!(
            "unrecognized stream start byte: 0x{first:02x}"
        )))
    }
}

/// Parse all messages from a byte stream.
///
/// The stream starts in CESR genus 1.x; a genus-version counter anywhere
/// between messages switches it (P1, P2).
///
/// # Errors
/// Returns `CoreError::ParseError` if any message cannot be parsed. A frame
/// that cannot be read fails the whole stream: nothing is skipped (P3).
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
    let mut genus = CounterTable::V1;

    while offset < stream.len() {
        // Skip any whitespace between messages
        while offset < stream.len() && stream[offset].is_ascii_whitespace() {
            offset += 1;
        }
        if offset >= stream.len() {
            break;
        }
        // A genus-version counter at the very end announces nothing.
        if stream[offset..].starts_with(b"-_") {
            let counter = read_counter(&stream[offset..])?;
            if offset + counter.size == stream.len() {
                break;
            }
        }

        let (msg, consumed) = parse_next_inner(&stream[offset..], &mut genus, strict)?;
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

/// Parse a SAD-based message (JSON/CBOR/MGPK) followed by CESR attachments,
/// read in the stream's genus.
fn parse_next_sad(
    stream: &[u8],
    genus: CounterTable,
    strict: bool,
) -> Result<(ParsedMessage, usize), CoreError> {
    let serder = Serder::from_raw(stream)?;
    let msg_size = serder.size();

    // Attachments follow the stream's genus, and the body carries its own
    // version: keripy republishes v1 events in a 2.x stream with 2.x
    // attachments (P2). The reverse — a version 2 message in a 1.x stream —
    // has no attachment table that could be right for it, so it is refused.
    if let Some(v) = serder.version.as_ref()
        && v.major >= 2
        && genus == CounterTable::V1
    {
        return Err(CoreError::ParseError(format!(
            "a version {}.{} message in a CESR 1.x stream: a 2.x stream opens with \
             the genus-version counter {}",
            v.major,
            v.minor,
            CounterTable::V2.genus_counter()
        )));
    }

    let rest = &stream[msg_size..];
    let (attachments, att_consumed) = parse_attachments(rest, genus, strict)?;

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
/// `table` decides what each counter code means and what its count counts;
/// see [`CounterTable`].
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

    // A genus-version counter ends this message's attachments: it opens the
    // next run of the stream.
    while offset < data.len() && data[offset] == b'-' && !data[offset..].starts_with(b"-_") {
        // CESR text is Base64, so all of it is ASCII. Checked up front so no
        // later slice can land inside a multi-byte character.
        if !data[offset..].is_ascii() {
            return Err(CoreError::ParseError(
                "attachment data contains non-ASCII bytes".into(),
            ));
        }
        let (group, consumed) = parse_group(&data[offset..], table, strict)?;
        offset += consumed;
        match group {
            Group::One(a) => {
                let stop = matches!(a, Attachment::Unknown { .. });
                attachments.push(a);
                if stop {
                    offset = data.len();
                    break;
                }
            }
            Group::Many(inner) => {
                let stop = inner
                    .iter()
                    .any(|a| matches!(a, Attachment::Unknown { .. }));
                attachments.extend(inner);
                if stop {
                    offset = data.len();
                    break;
                }
            }
        }
    }

    Ok((attachments, offset))
}

/// One counted group: a single attachment, or the contents of a nested
/// attachment group.
enum Group {
    One(Attachment),
    Many(Vec<Attachment>),
}

/// Parse the counted group at the head of `data`, returning it and the bytes
/// it occupies.
fn parse_group(
    data: &[u8],
    table: CounterTable,
    strict: bool,
) -> Result<(Group, usize), CoreError> {
    let counter = read_counter(data)?;
    let mut offset = counter.size;
    let code = counter.code.clone();
    let count = counter.count;

    let Some(kind) = GroupKind::classify(&code, table) else {
        if strict {
            return Err(CoreError::ParseError(format!(
                "unrecognised attachment counter code {code:?} for {table:?}; \
                 refusing to guess its length"
            )));
        }
        return Ok((
            Group::One(Attachment::Unknown {
                code,
                count,
                raw: data[offset..].to_vec(),
            }),
            data.len(),
        ));
    };

    let body = &data[offset..];
    let group = match kind {
        GroupKind::AttachedMaterialQuadlets => {
            // The count is in quadlets of nested attachment material. Recurse
            // into exactly that span so a wrapper cannot swallow the groups
            // that follow it, nor stop short of its own.
            let span = quadlet_span(body, count)?;
            let (inner, consumed) = parse_attachments(&body[..span], table, strict)?;
            if consumed != span {
                return Err(CoreError::ParseError(format!(
                    "attachment group declared {span} bytes but its contents \
                     accounted for {consumed}"
                )));
            }
            offset += span;
            return Ok((Group::Many(inner), offset));
        }
        GroupKind::ControllerIdxSigs => {
            let (sigs, n) = take(body, table, kind, count, parse_indexed_sig)?;
            offset += n;
            Attachment::ControllerSigs(sigs)
        }
        GroupKind::WitnessIdxSigs => {
            let (sigs, n) = take(body, table, kind, count, parse_indexed_sig)?;
            offset += n;
            Attachment::WitnessSigs(sigs)
        }
        GroupKind::NonTransReceiptCouples => {
            let (couples, n) = take(body, table, kind, count, parse_receipt_couple)?;
            offset += n;
            Attachment::ReceiptCouples(couples)
        }
        GroupKind::FirstSeenReplayCouples => {
            let (couples, n) = take(body, table, kind, count, parse_qb64_pair)?;
            offset += n;
            Attachment::FirstSeenReplayCouples(couples)
        }
        GroupKind::SealSourceCouples => {
            let (couples, n) = take(body, table, kind, count, parse_qb64_pair)?;
            offset += n;
            Attachment::SealSourceCouples(couples)
        }
        GroupKind::TransIdxSigGroups => {
            let (groups, n) = take(body, table, kind, count, |d| {
                parse_trans_idx_sig_group(d, table)
            })?;
            offset += n;
            Attachment::TransIdxSigGroups(groups)
        }
        // Modelled in the code table but not parsed. Treated exactly like an
        // unrecognised code rather than skipped, because its internal shape
        // is what determines its length.
        _ => {
            if strict {
                return Err(CoreError::ParseError(format!(
                    "attachment group {code:?} ({kind:?}) is not yet supported; \
                     refusing to guess its length"
                )));
            }
            return Ok((
                Group::One(Attachment::Unknown {
                    code,
                    count,
                    raw: body.to_vec(),
                }),
                data.len(),
            ));
        }
    };
    Ok((Group::One(group), offset))
}

/// The byte length of `count` quadlets, checked against what is available.
fn quadlet_span(data: &[u8], count: usize) -> Result<usize, CoreError> {
    let span = count
        .checked_mul(4)
        .ok_or_else(|| CoreError::ParseError(format!("quadlet count {count} overflows")))?;
    if span > data.len() {
        return Err(CoreError::ParseError(format!(
            "attachment group of {span} bytes extends past the stream ({} bytes available)",
            data.len()
        )));
    }
    Ok(span)
}

/// Read the items of a group with `item`: `count` of them where the table
/// counts items, or exactly `count` quadlets' worth where it counts quadlets.
fn take<T>(
    data: &[u8],
    table: CounterTable,
    kind: GroupKind,
    count: usize,
    item: impl Fn(&[u8]) -> Result<(T, usize), CoreError>,
) -> Result<(Vec<T>, usize), CoreError> {
    let mut items = Vec::new();
    let mut offset = 0;
    if table.counts_quadlets(kind) {
        let span = quadlet_span(data, count)?;
        while offset < span {
            if items.len() >= MAX_ATTACHMENT_COUNT {
                return Err(CoreError::ParseError(format!(
                    "{kind:?} holds more than {MAX_ATTACHMENT_COUNT} items"
                )));
            }
            let (it, n) = item(&data[offset..span])?;
            items.push(it);
            offset += n;
        }
        if offset != span {
            return Err(CoreError::ParseError(format!(
                "{kind:?} declared {span} bytes but its items accounted for {offset}"
            )));
        }
    } else {
        if count > MAX_ATTACHMENT_COUNT {
            return Err(CoreError::ParseError(format!(
                "{kind:?} count {count} exceeds maximum of {MAX_ATTACHMENT_COUNT}"
            )));
        }
        if count * MIN_PRIMITIVE_SIZE > data.len() {
            return Err(CoreError::ParseError(format!(
                "{kind:?} count {count} requires at least {} bytes, but only {} available",
                count * MIN_PRIMITIVE_SIZE,
                data.len()
            )));
        }
        for _ in 0..count {
            let (it, n) = item(&data[offset..])?;
            items.push(it);
            offset += n;
        }
    }
    Ok((items, offset))
}

/// Parse one transferable indexed signature group: a (prefix, sequence
/// number, event SAID) triple followed by exactly one nested
/// controller-indexed-signature group.
fn parse_trans_idx_sig_group(
    data: &[u8],
    table: CounterTable,
) -> Result<(TransIdxSigGroup, usize), CoreError> {
    let text = ascii(data, "transferable sig group")?;
    let mut offset = 0;
    let (prefix, n) = parse_matter_qb64(&text[offset..], 0, "transferable sig group prefix")?;
    offset += n;
    let (sn, n) = parse_matter_qb64(&text[offset..], 0, "transferable sig group sn")?;
    offset += n;
    let (said, n) = parse_matter_qb64(&text[offset..], 0, "transferable sig group said")?;
    offset += n;

    let counter = read_counter(&data[offset..])?;
    if GroupKind::classify(&counter.code, table) != Some(GroupKind::ControllerIdxSigs) {
        return Err(CoreError::ParseError(format!(
            "transferable sig group has {:?} where indexed signatures were expected",
            counter.code
        )));
    }
    offset += counter.size;
    let (sigs, n) = take(
        &data[offset..],
        table,
        GroupKind::ControllerIdxSigs,
        counter.count,
        parse_indexed_sig,
    )?;
    offset += n;
    if sigs.is_empty() {
        return Err(CoreError::ParseError(
            "transferable sig group carries no signatures".into(),
        ));
    }
    Ok((
        TransIdxSigGroup {
            prefix,
            sn,
            said,
            sigs,
        },
        offset,
    ))
}

fn ascii<'a>(data: &'a [u8], what: &str) -> Result<&'a str, CoreError> {
    // CESR is Base64-encoded, so all valid data must be ASCII. Reject
    // non-ASCII to prevent panics from byte-indexing multi-byte UTF-8.
    if !data.is_ascii() {
        return Err(CoreError::ParseError(format!(
            "{what} data contains non-ASCII bytes"
        )));
    }
    std::str::from_utf8(data)
        .map_err(|_| CoreError::ParseError(format!("{what} data is not valid UTF-8")))
}

/// Parse a pair of fixed-size qb64 primitives, as strings: the couple-shaped
/// groups (first seen replay, seal source) whose members are plain Matter
/// primitives.
fn parse_qb64_pair(data: &[u8]) -> Result<((String, String), usize), CoreError> {
    let text = ascii(data, "couple")?;
    let (first, a) = parse_matter_qb64(text, 0, "couple first member")?;
    let (second, b) = parse_matter_qb64(&text[a..], 0, "couple second member")?;
    Ok(((first, second), a + b))
}

/// Parse `count` pairs of fixed-size qb64 primitives (1.x item counts).
#[cfg(test)]
fn parse_qb64_pairs(
    data: &[u8],
    count: usize,
) -> Result<(Vec<(String, String)>, usize), CoreError> {
    take(
        data,
        CounterTable::V1,
        GroupKind::SealSourceCouples,
        count,
        parse_qb64_pair,
    )
}

/// Parse one indexed signature.
fn parse_indexed_sig(data: &[u8]) -> Result<(Siger, usize), CoreError> {
    let text = ascii(data, "indexed sig")?;
    let first_char = text
        .chars()
        .next()
        .ok_or_else(|| CoreError::ParseError("empty data for indexed sig".into()))?;
    let hs = hardage(first_char).ok_or_else(|| {
        CoreError::ParseError(format!(
            "unknown hardage for char '{first_char}' in indexed sig"
        ))
    })?;
    if hs > text.len() {
        return Err(CoreError::ParseError("truncated indexer code".into()));
    }
    let code = &text[..hs];
    let sizage = indexer_sizage(code)
        .ok_or_else(|| CoreError::ParseError(format!("unknown indexer code: {code}")))?;
    if sizage.fs > text.len() {
        return Err(CoreError::ParseError(format!(
            "truncated indexed sig: need {}, have {}",
            sizage.fs,
            text.len()
        )));
    }
    let indexer = Indexer::from_qb64(&text[..sizage.fs])
        .map_err(|e| CoreError::ParseError(format!("failed to parse indexer: {e}")))?;
    let siger = Siger::new(
        indexer.code(),
        indexer.index(),
        indexer.ondex(),
        indexer.raw().to_vec(),
    )
    .map_err(CoreError::Crypto)?;
    Ok((siger, sizage.fs))
}

/// Parse `count` indexed signatures (1.x item counts).
#[cfg(test)]
fn parse_indexed_sigs(data: &[u8], count: usize) -> Result<(Vec<Siger>, usize), CoreError> {
    take(
        data,
        CounterTable::V1,
        GroupKind::ControllerIdxSigs,
        count,
        parse_indexed_sig,
    )
}

/// Parse one receipt couple (prefix + non-indexed signature).
fn parse_receipt_couple(data: &[u8]) -> Result<(ReceiptCouple, usize), CoreError> {
    let text = ascii(data, "receipt couple")?;
    let (prefix_qb64, a) = parse_matter_qb64(text, 0, "prefix")?;
    let (sig_qb64, b) = parse_matter_qb64(&text[a..], 0, "signature")?;
    let sig_matter = affinidi_cesr::Matter::from_qb64(&sig_qb64)
        .map_err(|e| CoreError::ParseError(format!("failed to parse sig matter: {e}")))?;
    Ok(((prefix_qb64, sig_matter.raw().to_vec()), a + b))
}

/// Full sizes of fixed-size Matter codes `affinidi-cesr` 0.1.3 does not know
/// but KERI attachments carry: keripy's Number codes (`coring.py`, `NumDex`),
/// which a 2.x first-seen replay couple uses for its ordinal (`MAAA`).
fn extra_matter_size(code: &str) -> Option<usize> {
    Some(match code {
        "M" => 4,  // Short
        "0H" => 8, // Long
        "R" => 8,  // Tall
        "N" => 12, // Big
        "S" => 16, // Large
        "T" => 20, // Great
        "U" => 24, // Vast
        _ => return None,
    })
}

/// Parse a single Matter primitive qb64 string from text data.
/// Returns the qb64 string and the number of characters consumed.
fn parse_matter_qb64(text: &str, index: usize, name: &str) -> Result<(String, usize), CoreError> {
    use affinidi_cesr::tables::matter_sizage;

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
    let fs = match matter_sizage(code) {
        Some(sizage) if sizage.fs > 0 => sizage.fs,
        Some(_) => {
            return Err(CoreError::ParseError(format!(
                "variable-length {name} not supported in attachment couples"
            )));
        }
        None => extra_matter_size(code).ok_or_else(|| {
            CoreError::ParseError(format!("unknown matter code: {code} for {name}"))
        })?,
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
        let sad = crate::sad!({
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
        let mut sad = crate::sad!({
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
