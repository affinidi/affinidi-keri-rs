//! Native CESR message bodies: KERI and ACDC 2.x messages of kind `CESR`.
//!
//! A native body is not a field map in JSON, CBOR or MessagePack: it is a
//! CESR group (`-F` fixed fields, `-G` a field map) of primitives, one per
//! field, read in the order the message type's field list gives. This module
//! reads one into the same SAD keripy's `Serder._loads` produces, and writes a
//! SAD back the way keripy's `Serder._dumps` does, so that a SAID is checked
//! over exactly the bytes keripy digests (keripy `serdering.py` and the
//! primitives in `coring.py`, `mapping.py` and `structing.py`, b70986f).
//!
//! Writing exists for that check. A native body is accepted only if writing
//! the SAD read from it gives back the same bytes, as keripy requires ("Invalid
//! round trip"): every primitive has one encoding, so what was signed and what
//! the SAID names cannot differ.
//!
//! Not read: the aggregate section `A` in its expanded form (keripy `Aggor`),
//! which this crate does not support in any serialization.

use std::fmt::Write as _;

use affinidi_cesr::codec::{b64_decode, b64_encode};

use crate::counter_table::read_counter;
use crate::error::CoreError;
use crate::sad::{SadMap, SadValue};
use crate::version::{SerializationKind, Version};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn err(msg: impl Into<String>) -> CoreError {
    CoreError::ParseError(format!("native CESR body: {}", msg.into()))
}

// ---------------------------------------------------------------------------
// Matter: the primitive codec (keripy `Matter._infil` / `_exfil`).
// ---------------------------------------------------------------------------

/// The sizes of a primitive code: hard, soft, extra (prepad), full (`None` for
/// variable size) and lead. keripy `Matter.Sizes`.
#[derive(Debug, Clone, Copy)]
struct Sizes {
    hs: usize,
    ss: usize,
    xs: usize,
    fs: Option<usize>,
    ls: usize,
}

const fn fixed(hs: usize, ss: usize, xs: usize, fs: usize, ls: usize) -> Sizes {
    Sizes {
        hs,
        ss,
        xs,
        fs: Some(fs),
        ls,
    }
}

/// keripy's `Matter.Sizes`, b70986f.
fn sizes(code: &str) -> Option<Sizes> {
    Some(match code {
        "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I" | "J" | "O" | "Q" | "a" => {
            fixed(1, 0, 0, 44, 0)
        }
        "K" | "L" => fixed(1, 0, 0, 76, 0),
        "M" => fixed(1, 0, 0, 4, 0),
        "N" => fixed(1, 0, 0, 12, 0),
        "P" => fixed(1, 0, 0, 124, 0),
        "R" => fixed(1, 0, 0, 8, 0),
        "S" => fixed(1, 0, 0, 16, 0),
        "T" => fixed(1, 0, 0, 20, 0),
        "U" => fixed(1, 0, 0, 24, 0),
        "V" => fixed(1, 0, 0, 4, 1),
        "W" => fixed(1, 0, 0, 4, 0),
        "X" => fixed(1, 3, 0, 4, 0),
        "Y" => fixed(1, 7, 0, 8, 0),
        "Z" => fixed(1, 11, 0, 12, 0),
        "b" => fixed(1, 3, 0, 8, 0),
        "0A" => fixed(2, 0, 0, 24, 0),
        "0B" | "0C" | "0D" | "0E" | "0F" | "0G" | "0I" => fixed(2, 0, 0, 88, 0),
        "0H" => fixed(2, 0, 0, 8, 0),
        "0J" => fixed(2, 2, 1, 4, 0),
        "0K" => fixed(2, 2, 0, 4, 0),
        "0L" => fixed(2, 6, 1, 8, 0),
        "0M" => fixed(2, 6, 0, 8, 0),
        "0N" => fixed(2, 10, 1, 12, 0),
        "0O" => fixed(2, 10, 0, 12, 0),
        "1AAA" | "1AAB" | "1AAI" | "1AAJ" => fixed(4, 0, 0, 48, 0),
        "1AAC" | "1AAD" => fixed(4, 0, 0, 80, 0),
        "1AAE" => fixed(4, 0, 0, 156, 0),
        "1AAF" => fixed(4, 4, 0, 8, 0),
        "1AAG" => fixed(4, 0, 0, 36, 0),
        "1AAH" => fixed(4, 0, 0, 100, 0),
        "1AAK" | "1AAL" | "1AAM" | "1AAO" | "1AAP" => fixed(4, 0, 0, 4, 0),
        "1AAN" => fixed(4, 8, 0, 12, 0),
        "1__-" => fixed(4, 2, 0, 12, 0),
        "1___" => fixed(4, 0, 0, 8, 0),
        "2__-" => fixed(4, 2, 1, 12, 1),
        "2___" => fixed(4, 0, 0, 8, 1),
        "3__-" => fixed(4, 2, 0, 12, 2),
        "3___" => fixed(4, 0, 0, 8, 2),
        _ => {
            let b = code.as_bytes();
            let family = |c: u8| matches!(c, b'A'..=b'F' | b'H');
            match b {
                [lead @ b'4'..=b'6', f] if family(*f) => Sizes {
                    hs: 2,
                    ss: 2,
                    xs: 0,
                    fs: None,
                    ls: usize::from(lead - b'4'),
                },
                [lead @ b'7'..=b'9', b'A', b'A', f] if family(*f) => Sizes {
                    hs: 4,
                    ss: 4,
                    xs: 0,
                    fs: None,
                    ls: usize::from(lead - b'7'),
                },
                _ => return None,
            }
        }
    })
}

/// The hard size a code's first character selects (keripy `Matter.Hards`).
fn hard_size(first: u8) -> Option<usize> {
    match first {
        b'A'..=b'Z' | b'a'..=b'z' => Some(1),
        b'0' | b'4' | b'5' | b'6' => Some(2),
        b'1' | b'2' | b'3' | b'7' | b'8' | b'9' => Some(4),
        _ => None,
    }
}

fn b64_value(c: u8) -> Option<usize> {
    B64.iter().position(|&x| x == c)
}

fn b64_to_int(text: &[u8]) -> Result<usize, CoreError> {
    text.iter().try_fold(0usize, |acc, &c| {
        let v = b64_value(c).ok_or_else(|| err(format!("{:?} is not Base64", c as char)))?;
        acc.checked_mul(64)
            .map(|a| a + v)
            .ok_or_else(|| err("size overflow"))
    })
}

fn int_to_b64(mut n: usize, len: usize) -> String {
    let mut out = vec![b'A'; len];
    for slot in out.iter_mut().rev() {
        *slot = B64[n % 64];
        n /= 64;
    }
    String::from_utf8(out).expect("Base64 is ASCII")
}

fn is_b64(text: &[u8]) -> bool {
    text.iter().all(|c| B64.contains(c))
}

/// A primitive read from a stream.
#[derive(Debug, Clone)]
struct Mtr {
    code: String,
    soft: String,
    raw: Vec<u8>,
    qb64: String,
}

/// Read the primitive at the head of `buf`, as keripy's `Matter._exfil`.
fn read_matter(buf: &[u8]) -> Result<(Mtr, usize), CoreError> {
    let first = *buf.first().ok_or_else(|| err("a primitive was expected"))?;
    if first == b'-' {
        return Err(err("a counter where a primitive was expected"));
    }
    let hs = hard_size(first)
        .ok_or_else(|| err(format!("no primitive code starts with {:?}", first as char)))?;
    let hard = buf.get(..hs).ok_or_else(|| err("truncated primitive"))?;
    let hard = std::str::from_utf8(hard).map_err(|_| err("primitive is not ASCII"))?;
    let s = sizes(hard).ok_or_else(|| err(format!("unknown primitive code {hard:?}")))?;
    let cs = s.hs + s.ss;
    let soft = buf
        .get(s.hs..cs)
        .ok_or_else(|| err("truncated primitive"))?;
    if !is_b64(soft) {
        return Err(err("primitive soft part is not Base64"));
    }
    let (xtra, soft) = soft.split_at(s.xs);
    if xtra.iter().any(|&c| c != b'_') {
        return Err(err(format!("invalid prepad on {hard:?}")));
    }
    let fs = match s.fs {
        Some(fs) => fs,
        None => b64_to_int(soft)?
            .checked_mul(4)
            .and_then(|n| n.checked_add(cs))
            .ok_or_else(|| err("size overflow"))?,
    };
    let full = buf.get(..fs).ok_or_else(|| err("truncated primitive"))?;
    if !is_b64(&full[cs..]) {
        return Err(err(format!("{hard:?} material is not Base64")));
    }
    let ps = cs % 4;
    let mut base = "A".repeat(ps);
    base.push_str(std::str::from_utf8(&full[cs..]).map_err(|_| err("not ASCII"))?);
    let paw = b64_decode(&base).map_err(|e| err(format!("{hard:?}: {e}")))?;
    let lead = ps + s.ls;
    if paw.len() < lead || paw[..lead].iter().any(|&b| b != 0) {
        return Err(err(format!("{hard:?} has nonzero pad bits")));
    }
    let raw = paw[lead..].to_vec();
    if raw.len() + s.ls != (fs - cs) * 3 / 4 {
        return Err(err(format!("{hard:?} is improperly qualified")));
    }
    Ok((
        Mtr {
            code: hard.to_string(),
            soft: String::from_utf8(soft.to_vec()).expect("checked Base64"),
            raw,
            qb64: String::from_utf8(full.to_vec()).expect("checked Base64"),
        },
        fs,
    ))
}

/// Encode a primitive, as keripy's `Matter(raw=, code=, soft=)` then `.qb64`.
///
/// A variable-size `code` names its family (`4A`, `4B`, …); the lead size and
/// the small or big form are chosen from the raw size, as keripy does.
fn encode_matter(code: &str, soft: &str, raw: &[u8]) -> Result<String, CoreError> {
    let s = sizes(code).ok_or_else(|| err(format!("unknown primitive code {code:?}")))?;
    match s.fs {
        None => {
            let family = code.as_bytes()[code.len() - 1] as char;
            let ls = (3 - raw.len() % 3) % 3;
            let size = (raw.len() + ls) / 3;
            let (code, ss) = if size < 64 * 64 {
                (format!("{}{family}", b"456"[ls] as char), 2)
            } else if size < 64usize.pow(4) {
                (format!("{}AA{family}", b"789"[ls] as char), 4)
            } else {
                return Err(err("primitive too large"));
            };
            let mut padded = vec![0u8; ls];
            padded.extend_from_slice(raw);
            Ok(format!(
                "{code}{}{}",
                int_to_b64(size, ss),
                b64_encode(&padded)
            ))
        }
        Some(fs) => {
            if soft.len() != s.ss - s.xs || !is_b64(soft.as_bytes()) {
                return Err(err(format!("invalid soft part {soft:?} for {code:?}")));
            }
            let cs = s.hs + s.ss;
            let ps = (3 - (raw.len() + s.ls) % 3) % 3;
            if ps != cs % 4 {
                return Err(err(format!("raw size {} does not fit {code:?}", raw.len())));
            }
            let mut padded = vec![0u8; ps + s.ls];
            padded.extend_from_slice(raw);
            let out = format!(
                "{code}{}{soft}{}",
                "_".repeat(s.xs),
                &b64_encode(&padded)[ps..]
            );
            if out.len() != fs {
                return Err(err(format!("raw size {} does not fit {code:?}", raw.len())));
            }
            Ok(out)
        }
    }
}

/// Whether `text` is, in full, one primitive keripy reads (`Matter(qb64=)`).
fn is_whole_primitive(text: &str) -> Option<Mtr> {
    match read_matter(text.as_bytes()) {
        Ok((m, n)) if n == text.len() => Some(m),
        _ => None,
    }
}

// Code classes (keripy `coring.py` codices).
const DIG: &[&str] = &["E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"];
const PRE: &[&str] = &[
    "B", "D", "E", "F", "G", "H", "I", "0D", "0E", "0F", "0G", "1AAA", "1AAB", "1AAC", "1AAD",
    "1AAE", "1AAI", "1AAJ",
];
const NONCE: &[&str] = &[
    "1AAP", "0A", "a", "E", "F", "G", "H", "I", "0D", "0E", "0F", "0G",
];
const NUM: &[&str] = &["M", "0H", "R", "N", "S", "T", "0A", "U"];
const TAG: &[&str] = &[
    "0J", "0K", "X", "1AAF", "0L", "0M", "Y", "1AAN", "0N", "0O", "Z",
];
const TRAITS: &[&str] = &["EO", "DND", "RB", "NB", "NRB", "DID"];
const EMPTY: &str = "1AAP";
const ESCAPE: &str = "1AAO";
const NULL: &str = "1AAK";
const NO: &str = "1AAL";
const YES: &str = "1AAM";

fn is_bext(code: &str) -> bool {
    sizes(code).is_some_and(|s| s.fs.is_none()) && code.ends_with('A')
}
fn is_texter(code: &str) -> bool {
    sizes(code).is_some_and(|s| s.fs.is_none()) && code.ends_with('B')
}
fn is_decimal(code: &str) -> bool {
    sizes(code).is_some_and(|s| s.fs.is_none()) && code.ends_with('H')
}
fn is_label(code: &str) -> bool {
    code == EMPTY
        || TAG.contains(&code)
        || is_bext(code)
        || is_texter(code)
        || code == "V"
        || code == "W"
}
fn is_escaped(code: &str) -> bool {
    is_label(code) || [ESCAPE, NULL, NO, YES].contains(&code) || is_decimal(code)
}

/// A primitive of one of `class`, as qb64.
fn read_class<'a>(buf: &'a [u8], class: &[&str], what: &str) -> Result<(Mtr, &'a [u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    if !class.contains(&m.code.as_str()) {
        return Err(err(format!("{:?} is not a valid {what} code", m.code)));
    }
    Ok((m, &buf[n..]))
}

fn verbatim_class(qb64: &str, class: &[&str], what: &str) -> Result<String, CoreError> {
    match is_whole_primitive(qb64) {
        Some(m) if class.contains(&m.code.as_str()) => Ok(qb64.to_string()),
        _ => Err(err(format!("{qb64:?} is not a valid {what}"))),
    }
}

// ---------------------------------------------------------------------------
// Typed primitives.
// ---------------------------------------------------------------------------

/// keripy `Number.numh`: lowercase hex, no leading zeros.
fn numh(raw: &[u8]) -> String {
    let mut out = String::new();
    for b in raw {
        let _ = write!(out, "{b:02x}");
    }
    let trimmed = out.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

/// keripy `Number(numh=)`: the smallest of its codes that holds the value.
fn encode_number(hex: &str) -> Result<String, CoreError> {
    let digits = hex.trim_start_matches('0');
    if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(format!("{hex:?} is not a hex number")));
    }
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    let bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).expect("hex checked"))
        .collect();
    let (code, size) = [
        ("M", 2),
        ("R", 5),
        ("N", 8),
        ("S", 11),
        ("T", 14),
        ("U", 17),
    ]
    .into_iter()
    .find(|(_, size)| bytes.len() <= *size)
    .ok_or_else(|| err(format!("{hex:?} is too large for a Number")))?;
    let mut raw = vec![0u8; size - bytes.len()];
    raw.extend(bytes);
    encode_matter(code, "", &raw)
}

fn read_number(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, rest) = read_class(buf, NUM, "Number")?;
    Ok((numh(&m.raw), rest))
}

/// The raw bytes of a whole CESR number primitive (keripy `NumDex`: a 1.x
/// `Seqner` is `0A`, a 2.x `Number` any of its codes).
pub(crate) fn number_raw(qb64: &str) -> Result<Vec<u8>, CoreError> {
    match is_whole_primitive(qb64) {
        Some(m) if NUM.contains(&m.code.as_str()) => Ok(m.raw),
        _ => Err(err(format!("{qb64:?} is not a CESR number"))),
    }
}

/// keripy `Bexter._rawify`.
fn bext_rawify(bext: &str, escapive: bool) -> Result<Vec<u8>, CoreError> {
    if !is_b64(bext.as_bytes()) {
        return Err(err(format!("{bext:?} is not Base64")));
    }
    let mut bext = bext.to_string();
    let mut ws = (4 - bext.len() % 4) % 4;
    if escapive && ((bext.starts_with('A') && ws <= 1) || bext.starts_with('-')) {
        bext.insert(0, '-');
        ws = (4 - bext.len() % 4) % 4;
    }
    let base = format!("{}{bext}", "A".repeat(ws));
    let ls = (3 - bext.len() % 4) % 3;
    let decoded = b64_decode(&base).map_err(|e| err(e.to_string()))?;
    Ok(decoded[ls..].to_vec())
}

/// keripy `Bexter._derawify`.
fn bext_derawify(raw: &[u8], code: &str, escapive: bool) -> Result<String, CoreError> {
    let ls = sizes(code).map(|s| s.ls).unwrap_or_default();
    let mut lead = vec![0u8; ls];
    lead.extend_from_slice(raw);
    let bext = b64_encode(&lead);
    let ws = if ls == 0 {
        usize::from(bext.starts_with('A'))
    } else {
        (ls + 1) % 4
    };
    let mut bext = bext.get(ws..).unwrap_or_default().to_string();
    if escapive && bext.starts_with('-') {
        bext.remove(0);
    }
    Ok(bext)
}

/// keripy `Labeler(text=).qb64`.
fn encode_text(text: &str) -> Result<String, CoreError> {
    let bytes = text.as_bytes();
    if is_b64(bytes) {
        if bytes.is_empty() {
            return encode_matter(EMPTY, "", &[]);
        }
        if bytes.len() <= TAG.len() {
            return encode_matter(TAG[bytes.len() - 1], text, &[]);
        }
        return encode_matter("4A", "", &bext_rawify(text, true)?);
    }
    match bytes.len() {
        1 => encode_matter("V", "", bytes),
        2 => encode_matter("W", "", bytes),
        _ => encode_matter("4B", "", bytes),
    }
}

/// keripy `Labeler.text`.
fn label_text(m: &Mtr) -> Result<String, CoreError> {
    if !is_label(&m.code) {
        return Err(err(format!("{:?} is not a label code", m.code)));
    }
    if TAG.contains(&m.code.as_str()) {
        return Ok(m.soft.clone());
    }
    if is_bext(&m.code) {
        return bext_derawify(&m.raw, &m.code, true);
    }
    String::from_utf8(m.raw.clone()).map_err(|_| err("label is not UTF-8"))
}

/// keripy `Reatt`: an attribute-like label.
fn is_attribute_label(label: &str) -> bool {
    let mut chars = label.bytes();
    matches!(chars.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn read_label(buf: &[u8], strict: bool) -> Result<(String, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    let text = label_text(&m)?;
    if strict && !is_attribute_label(&text) {
        return Err(err(format!("invalid field label {text:?}")));
    }
    Ok((text, &buf[n..]))
}

/// keripy `Dater`.
fn read_dater(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    if m.code != "1AAG" {
        return Err(err(format!("{:?} is not a date-time code", m.code)));
    }
    let dts: String = m.qb64[4..]
        .chars()
        .map(|c| match c {
            'c' => ':',
            'd' => '.',
            'p' => '+',
            other => other,
        })
        .collect();
    Ok((dts, &buf[n..]))
}

fn encode_dater(dts: &str) -> Result<String, CoreError> {
    let text: String = dts
        .chars()
        .map(|c| match c {
            ':' => 'c',
            '.' => 'd',
            '+' => 'p',
            other => other,
        })
        .collect();
    let qb64 = format!("1AAG{text}");
    match is_whole_primitive(&qb64) {
        Some(m) if m.code == "1AAG" => Ok(qb64),
        _ => Err(err(format!("{dts:?} is not a CESR date-time"))),
    }
}

/// keripy `Pather.path`.
fn read_pather(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    let path = if is_bext(&m.code) {
        let path = bext_derawify(&m.raw, &m.code, false)?;
        let path = path.strip_prefix("--").unwrap_or(&path);
        path.split('-').collect::<Vec<_>>().join("/")
    } else if is_texter(&m.code) {
        String::from_utf8(m.raw).map_err(|_| err("path is not UTF-8"))?
    } else {
        return Err(err(format!("{:?} is not a path code", m.code)));
    };
    Ok((path, &buf[n..]))
}

/// keripy `Pather(path=, relative=True, pathive=False)`.
fn encode_pather(path: &str) -> Result<String, CoreError> {
    let parts: Vec<&str> = if path.contains('/') {
        path.split('/').collect()
    } else {
        path.split('-').collect()
    };
    let bextable = parts
        .iter()
        .all(|p| p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'));
    if bextable {
        let mut joined = parts.join("-");
        if joined.contains("--") {
            return Err(err(format!("path {path:?} has empty parts")));
        }
        let ws = (4 - joined.len() % 4) % 4;
        if joined.starts_with('A') && ws <= 1 {
            joined.insert_str(0, "--");
        }
        encode_matter("4A", "", &bext_rawify(&joined, false)?)
    } else {
        let joined = parts.join("/");
        if joined.contains("//") {
            return Err(err(format!("path {path:?} has empty parts")));
        }
        encode_matter("4B", "", joined.as_bytes())
    }
}

/// keripy `Verser.versage`: (protocol, major, minor, genus).
type Versage = (String, u8, u8, Option<(u8, u8)>);

fn read_verser(buf: &[u8]) -> Result<(Versage, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    if m.code != "Y" && m.code != "0O" {
        return Err(err(format!("{:?} is not a version code", m.code)));
    }
    let tag = m.soft.as_bytes();
    let ver = |b: &[u8]| -> Result<(u8, u8), CoreError> {
        let major = u8::try_from(b64_to_int(&b[..1])?).map_err(|_| err("version"))?;
        let minor =
            u8::try_from(b64_to_int(&b[1..3])?).map_err(|_| err("a minor version above 255"))?;
        Ok((major, minor))
    };
    let protocol = String::from_utf8(tag[..4].to_vec()).expect("checked Base64");
    let (major, minor) = ver(&tag[4..7])?;
    let genus = if tag.len() == 10 {
        Some(ver(&tag[7..10])?)
    } else {
        None
    };
    Ok(((protocol, major, minor, genus), &buf[n..]))
}

fn encode_verser(v: &Version) -> Result<String, CoreError> {
    let ver = |major: u8, minor: u8| {
        format!(
            "{}{}",
            int_to_b64(major.into(), 1),
            int_to_b64(minor.into(), 2)
        )
    };
    let mut tag = format!("{}{}", v.protocol, ver(v.major, v.minor));
    if let Some((gm, gn)) = v.genus {
        tag.push_str(&ver(gm, gn));
    }
    match tag.len() {
        7 => encode_matter("Y", &tag, &[]),
        10 => encode_matter("0O", &tag, &[]),
        _ => Err(err(format!(
            "protocol {:?} is not four characters",
            v.protocol
        ))),
    }
}

fn read_tag(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    if !TAG.contains(&m.code.as_str()) {
        return Err(err(format!("{:?} is not a tag code", m.code)));
    }
    Ok((m.soft, &buf[n..]))
}

fn encode_tag(tag: &str) -> Result<String, CoreError> {
    if tag.is_empty() || tag.len() > TAG.len() {
        return Err(err(format!("{tag:?} cannot be a tag")));
    }
    encode_matter(TAG[tag.len() - 1], tag, &[])
}

/// A KERI `u`: a nonce as qb64, the empty one as `1AAP`.
fn read_nonce(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, rest) = read_class(buf, NONCE, "nonce")?;
    Ok((m.qb64, rest))
}

/// An ACDC nonce field (`u`, `rd`, `td`): keripy `Noncer.nonce`, empty for
/// the empty nonce.
fn read_acdc_nonce(buf: &[u8]) -> Result<(String, &[u8]), CoreError> {
    let (m, rest) = read_class(buf, NONCE, "nonce")?;
    Ok((
        if m.code == EMPTY {
            String::new()
        } else {
            m.qb64
        },
        rest,
    ))
}

fn encode_acdc_nonce(nonce: &str) -> Result<String, CoreError> {
    if nonce.is_empty() {
        encode_matter(EMPTY, "", &[])
    } else {
        verbatim_class(nonce, NONCE, "nonce")
    }
}

// ---------------------------------------------------------------------------
// Thresholds (keripy `Tholder`).
// ---------------------------------------------------------------------------

/// A non-negative rational weight, reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Weight {
    num: u128,
    den: u128,
}

fn gcd(a: u128, b: u128) -> u128 {
    if b == 0 { a } else { gcd(b, a % b) }
}

impl Weight {
    /// keripy `Tholder.weight`: an integer or a ratio, from 0 to 1.
    fn parse(w: &str) -> Result<Self, CoreError> {
        let bad = || err(format!("invalid weight {w:?}"));
        let (n, d) = match w.split_once('/') {
            Some((n, d)) => (n, d),
            None => (w, "1"),
        };
        if n.is_empty() || d.is_empty() || !n.bytes().chain(d.bytes()).all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        let num: u128 = n.parse().map_err(|_| bad())?;
        let den: u128 = d.parse().map_err(|_| bad())?;
        if den == 0 {
            return Err(bad());
        }
        // keripy: 0 <= w <= 1.
        if num > den {
            return Err(bad());
        }
        let g = gcd(num, den).max(1);
        Ok(Self {
            num: num / g,
            den: den / g,
        })
    }

    /// keripy's rendering: `n<sep>d` for a proper fraction, else `0` or `1`.
    fn render(self, sep: char) -> String {
        if self.num > 0 && self.num < self.den {
            format!("{}{sep}{}", self.num, self.den)
        } else {
            format!("{}", self.num / self.den)
        }
    }

    fn at_least_one(sum: &[Self]) -> bool {
        // Σ n/d >= 1, over a common denominator.
        let den = sum.iter().fold(1u128, |l, w| {
            let g = gcd(l, w.den);
            l / g * w.den
        });
        let num: u128 = sum.iter().map(|w| w.num * (den / w.den)).sum();
        num >= den
    }
}

/// A weighted clause element: a weight, or a weight over a nested clause.
enum Element {
    Weight(Weight),
    Nested(Weight, Vec<Weight>),
}

fn check_clauses(clauses: &[Vec<Element>]) -> Result<(), CoreError> {
    for clause in clauses {
        let mut top = Vec::new();
        for e in clause {
            match e {
                Element::Weight(w) => top.push(*w),
                Element::Nested(w, nested) => {
                    if !Weight::at_least_one(nested) {
                        return Err(err("a nested threshold clause sums to less than 1"));
                    }
                    top.push(*w);
                }
            }
        }
        if !Weight::at_least_one(&top) {
            return Err(err("a threshold clause sums to less than 1"));
        }
    }
    Ok(())
}

/// keripy `Tholder(limen=).sith`.
fn read_tholder(buf: &[u8]) -> Result<(SadValue, &[u8]), CoreError> {
    let (m, n) = read_matter(buf)?;
    let rest = &buf[n..];
    if NUM.contains(&m.code.as_str()) {
        return Ok((SadValue::String(numh(&m.raw)), rest));
    }
    if !is_bext(&m.code) {
        return Err(err(format!("{:?} is not a threshold code", m.code)));
    }
    let bext = bext_derawify(&m.raw, &m.code, true)?.replace('s', "/");
    let mut clauses = Vec::new();
    for c in bext.split('a') {
        let mut clause = Vec::new();
        for e in c.split('c') {
            match e.split_once('k') {
                Some((k, v)) => clause.push(Element::Nested(
                    Weight::parse(k)?,
                    v.split('v').map(Weight::parse).collect::<Result<_, _>>()?,
                )),
                None => clause.push(Element::Weight(Weight::parse(e)?)),
            }
        }
        clauses.push(clause);
    }
    check_clauses(&clauses)?;
    let mut sith: Vec<SadValue> = clauses
        .iter()
        .map(|clause| {
            SadValue::Array(
                clause
                    .iter()
                    .map(|e| match e {
                        Element::Weight(w) => SadValue::String(w.render('/')),
                        Element::Nested(w, nested) => {
                            let mut map = SadMap::new();
                            map.insert(
                                w.render('/'),
                                SadValue::Array(
                                    nested
                                        .iter()
                                        .map(|x| SadValue::String(x.render('/')))
                                        .collect(),
                                ),
                            );
                            SadValue::Object(map)
                        }
                    })
                    .collect(),
            )
        })
        .collect();
    let sith = if sith.len() == 1 {
        sith.pop().expect("one clause")
    } else {
        SadValue::Array(sith)
    };
    Ok((sith, rest))
}

/// keripy `Tholder(sith=).limen`.
fn encode_tholder(sith: &SadValue) -> Result<String, CoreError> {
    let clauses = match sith {
        SadValue::String(s) => return encode_number(s),
        SadValue::Array(items) => {
            let nested = items.iter().map(SadValue::is_array).collect::<Vec<_>>();
            if nested.iter().all(|n| *n) {
                items.iter().collect::<Vec<_>>()
            } else if nested.iter().any(|n| *n) {
                return Err(err("a threshold mixes clauses and weights"));
            } else {
                vec![sith]
            }
        }
        _ => return Err(err("a threshold is a hex number or a list of weights")),
    };
    let mut parsed = Vec::new();
    for clause in &clauses {
        let mut elements = Vec::new();
        for e in clause.as_array().into_iter().flatten() {
            match e {
                SadValue::String(w) => elements.push(Element::Weight(Weight::parse(w)?)),
                SadValue::Object(map) if map.len() == 1 => {
                    let (k, v) = map.iter().next().expect("one member");
                    let nested = v
                        .as_array()
                        .ok_or_else(|| err("a nested threshold clause is a list"))?
                        .iter()
                        .map(|w| {
                            w.as_str()
                                .ok_or_else(|| err("weights are strings"))
                                .and_then(Weight::parse)
                        })
                        .collect::<Result<_, _>>()?;
                    elements.push(Element::Nested(Weight::parse(k)?, nested));
                }
                _ => return Err(err("invalid threshold element")),
            }
        }
        parsed.push(elements);
    }
    check_clauses(&parsed)?;
    let bext = parsed
        .iter()
        .map(|clause| {
            clause
                .iter()
                .map(|e| match e {
                    Element::Weight(w) => w.render('s'),
                    Element::Nested(w, nested) => format!(
                        "{}k{}",
                        w.render('s'),
                        nested
                            .iter()
                            .map(|x| x.render('s'))
                            .collect::<Vec<_>>()
                            .join("v")
                    ),
                })
                .collect::<Vec<_>>()
                .join("c")
        })
        .collect::<Vec<_>>()
        .join("a");
    encode_matter("4A", "", &bext_rawify(&bext, true)?)
}

// ---------------------------------------------------------------------------
// Groups: lists, field maps (keripy `Mapper`) and seals (keripy `Sealer`).
// ---------------------------------------------------------------------------

/// The counter code of a 2.x group, by its one-letter selector.
fn enclose(selector: char, body: &str) -> Result<String, CoreError> {
    let count = body.len() / 4;
    if !body.len().is_multiple_of(4) {
        return Err(err("a group's content is not quadlet aligned"));
    }
    if count < 64 * 64 {
        Ok(format!("-{selector}{}{body}", int_to_b64(count, 2)))
    } else if count < 64usize.pow(5) {
        Ok(format!("--{selector}{}{body}", int_to_b64(count, 5)))
    } else {
        Err(err("a group too large to count"))
    }
}

/// Read a group counter of `selector` (small or big) and split off its content.
fn read_group<'a>(
    buf: &'a [u8],
    selectors: &[char],
) -> Result<(char, &'a [u8], &'a [u8]), CoreError> {
    let counter = read_counter(buf).map_err(|e| err(e.to_string()))?;
    let selector = counter.code.trim_start_matches('-');
    let selector = match selector.chars().collect::<Vec<_>>().as_slice() {
        [c] if selectors.contains(c) => *c,
        _ => {
            return Err(err(format!(
                "expected a {selectors:?} group, found {:?}",
                counter.code
            )));
        }
    };
    let len = counter
        .count
        .checked_mul(4)
        .ok_or_else(|| err("group size overflow"))?;
    let content = buf
        .get(counter.size..counter.size + len)
        .ok_or_else(|| err("truncated group"))?;
    Ok((selector, content, &buf[counter.size + len..]))
}

const GENERIC_MAP: char = 'I';
const GENERIC_LIST: char = 'J';

/// How deeply field maps and lists may nest: serde_json's limit, so a native
/// body is held to what a JSON one is. A stream is untrusted input, and each
/// level costs a stack frame.
const MAX_DEPTH: usize = 128;

/// keripy `Mapper._deserialize`.
fn read_value(buf: &[u8], strict: bool, depth: usize) -> Result<(SadValue, &[u8]), CoreError> {
    if buf.first() == Some(&b'-') {
        if depth >= MAX_DEPTH {
            return Err(err(format!(
                "field maps and lists nest deeper than {MAX_DEPTH}"
            )));
        }
        let (selector, mut content, rest) = read_group(buf, &[GENERIC_MAP, GENERIC_LIST])?;
        if selector == GENERIC_LIST {
            let mut items = Vec::new();
            while !content.is_empty() {
                let (v, r) = read_value(content, strict, depth + 1)?;
                items.push(v);
                content = r;
            }
            return Ok((SadValue::Array(items), rest));
        }
        return Ok((
            SadValue::Object(read_map_content(content, strict, depth + 1)?),
            rest,
        ));
    }
    let (m, n) = read_matter(buf)?;
    let rest = &buf[n..];
    let value = match m.code.as_str() {
        ESCAPE => {
            let (inner, n2) = read_matter(rest)?;
            return Ok((SadValue::String(inner.qb64), &rest[n2..]));
        }
        NULL => SadValue::Null,
        YES => SadValue::Bool(true),
        NO => SadValue::Bool(false),
        c if is_decimal(c) => decimal_value(&bext_derawify(&m.raw, c, false)?.replace('p', "."))?,
        c if is_label(c) => SadValue::String(label_text(&m)?),
        _ => SadValue::String(m.qb64),
    };
    Ok((value, rest))
}

fn read_map_content(mut content: &[u8], strict: bool, depth: usize) -> Result<SadMap, CoreError> {
    let mut map = SadMap::new();
    while !content.is_empty() {
        let (label, rest) = read_label(content, strict)?;
        let (value, rest) = read_value(rest, strict, depth)?;
        map.insert(label, value);
        content = rest;
    }
    Ok(map)
}

/// keripy `Mapper(qb64b=)`: a whole field map group.
fn read_map(buf: &[u8], strict: bool) -> Result<(SadValue, &[u8]), CoreError> {
    let (_, content, rest) = read_group(buf, &[GENERIC_MAP])?;
    Ok((
        SadValue::Object(read_map_content(content, strict, 1)?),
        rest,
    ))
}

/// keripy `Decimer.decimal`: an int if it reads as one, else a float.
fn decimal_value(dns: &str) -> Result<SadValue, CoreError> {
    if let Ok(i) = dns.parse::<i64>() {
        return Ok(SadValue::Number(i.into()));
    }
    if let Ok(u) = dns.parse::<u64>() {
        return Ok(SadValue::Number(u.into()));
    }
    dns.parse::<f64>()
        .ok()
        .and_then(serde_json::Number::from_f64)
        .map(SadValue::Number)
        .ok_or_else(|| err(format!("{dns:?} is not a decimal this crate can hold")))
}

/// keripy `Decimer(decimal=)`, for the values Python formats the same way.
fn encode_decimal(n: &serde_json::Number) -> Result<String, CoreError> {
    let dns = if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        let f = n.as_f64().ok_or_else(|| err("not a number"))?;
        let abs = f.abs();
        // Python's repr switches to an exponent outside [1e-4, 1e16).
        if !(f == 0.0 || (1e-4..1e16).contains(&abs)) {
            return Err(err(format!("{f} has no native CESR decimal form here")));
        }
        let s = f.to_string();
        if s.contains('.') { s } else { format!("{s}.0") }
    };
    let text = dns.replace('.', "p");
    // keripy `Decimer._rawify`.
    let ts = text.len() % 4;
    let ws = (4 - ts) % 4;
    let ls = (3 - ts) % 3;
    let decoded =
        b64_decode(&format!("{}{text}", "A".repeat(ws))).map_err(|e| err(e.to_string()))?;
    encode_matter("4H", "", &decoded[ls..])
}

/// keripy `Mapper._serialize`.
fn write_value(value: &SadValue, out: &mut String) -> Result<(), CoreError> {
    match value {
        SadValue::Null => out.push_str(&encode_matter(NULL, "", &[])?),
        SadValue::Bool(true) => out.push_str(&encode_matter(YES, "", &[])?),
        SadValue::Bool(false) => out.push_str(&encode_matter(NO, "", &[])?),
        SadValue::Number(n) => out.push_str(&encode_decimal(n)?),
        SadValue::String(s) => match is_whole_primitive(s) {
            Some(m) => {
                if is_escaped(&m.code) {
                    out.push_str(&encode_matter(ESCAPE, "", &[])?);
                }
                out.push_str(s);
            }
            None => out.push_str(&encode_text(s)?),
        },
        SadValue::Object(map) => out.push_str(&write_map(map, &[])?),
        SadValue::Array(items) => {
            let mut body = String::new();
            for item in items {
                write_value(item, &mut body)?;
            }
            out.push_str(&enclose(GENERIC_LIST, &body)?);
        }
    }
    Ok(())
}

/// keripy `Mapper._exhale`. Values of the `verbatim` labels (a SAID filled
/// with `#`) are written as their text, unencoded.
fn write_map(map: &SadMap, verbatim: &[&str]) -> Result<String, CoreError> {
    let mut body = String::new();
    for (label, value) in map {
        body.push_str(&encode_text(label)?);
        match value {
            SadValue::String(s) if verbatim.contains(&label.as_str()) => body.push_str(s),
            other => write_value(other, &mut body)?,
        }
    }
    enclose(GENERIC_MAP, &body)
}

/// A seal type: its counter selector and fields (keripy `SealClanDom`,
/// `Serder.ClanCodes`).
const SEALS: &[(char, &[&str])] = &[
    ('Q', &["d"]),
    ('R', &["rd"]),
    ('S', &["s", "d"]),
    ('T', &["i", "s", "d"]),
    ('U', &["i"]),
    ('V', &["bi", "d"]),
    ('W', &["t", "d"]),
];

fn read_seal_field<'a>(
    buf: &'a [u8],
    selector: char,
    field: &str,
) -> Result<(String, &'a [u8]), CoreError> {
    match (selector, field) {
        (_, "s") => read_number(buf),
        ('W', "t") => {
            read_verser(buf)?;
            let (m, n) = read_matter(buf)?;
            Ok((m.qb64, &buf[n..]))
        }
        ('W', "d") => read_class(buf, NONCE, "nonce").map(|(m, r)| (m.qb64, r)),
        (_, "i" | "bi") => read_class(buf, PRE, "prefix").map(|(m, r)| (m.qb64, r)),
        _ => read_class(buf, DIG, "digest").map(|(m, r)| (m.qb64, r)),
    }
}

fn write_seal_field(selector: char, field: &str, value: &SadValue) -> Result<String, CoreError> {
    let text = value
        .as_str()
        .ok_or_else(|| err(format!("seal field {field:?} is not a string")))?;
    match (selector, field) {
        (_, "s") => encode_number(text),
        ('W', "t") => {
            let (_, rest) = read_verser(text.as_bytes())?;
            if !rest.is_empty() {
                return Err(err("invalid seal version"));
            }
            Ok(text.to_string())
        }
        ('W', "d") => verbatim_class(text, NONCE, "nonce"),
        (_, "i" | "bi") => verbatim_class(text, PRE, "prefix"),
        _ => verbatim_class(text, DIG, "digest"),
    }
}

/// A list of seals: a generic list of seal groups.
fn read_seals(content: &[u8]) -> Result<Vec<SadValue>, CoreError> {
    let selectors: Vec<char> = SEALS.iter().map(|(c, _)| *c).collect();
    let mut seals = Vec::new();
    let mut frame = content;
    while !frame.is_empty() {
        let (selector, mut group, rest) = read_group(frame, &selectors)?;
        let fields = SEALS
            .iter()
            .find(|(c, _)| *c == selector)
            .map(|(_, f)| *f)
            .expect("selector checked");
        while !group.is_empty() {
            let mut seal = SadMap::new();
            for field in fields {
                let (value, r) = read_seal_field(group, selector, field)?;
                seal.insert((*field).to_string(), SadValue::String(value));
                group = r;
            }
            seals.push(SadValue::Object(seal));
        }
        frame = rest;
    }
    Ok(seals)
}

fn write_seals(seals: &[SadValue]) -> Result<String, CoreError> {
    let mut frame = String::new();
    let mut current: Option<char> = None;
    let mut group = String::new();
    for seal in seals {
        let obj = seal
            .as_object()
            .ok_or_else(|| err("a seal is a field map"))?;
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        let (selector, fields) = SEALS
            .iter()
            .find(|(_, f)| *f == keys.as_slice())
            .ok_or_else(|| err(format!("no native seal has the fields {keys:?}")))?;
        if current != Some(*selector) {
            if let Some(c) = current {
                frame.push_str(&enclose(c, &group)?);
                group.clear();
            }
            current = Some(*selector);
        }
        for field in *fields {
            group.push_str(&write_seal_field(*selector, field, &obj[*field])?);
        }
    }
    if let Some(c) = current {
        frame.push_str(&enclose(c, &group)?);
    }
    enclose(GENERIC_LIST, &frame)
}

// ---------------------------------------------------------------------------
// Message bodies.
// ---------------------------------------------------------------------------

const FIX_BODY: char = 'F';
const MAP_BODY: char = 'G';

/// The KERI 2.0 message types keripy reads natively, with their fields.
fn keri_fields(ilk: &str) -> Option<&'static [&'static str]> {
    crate::fields::keri_fields(2, ilk)
}

/// The ACDC 2.0 fixed-field message types, with their fields (keripy
/// `Serder.Fields`).
fn acdc_fixed_fields(ilk: &str) -> Option<&'static [&'static str]> {
    Some(match ilk {
        "act" => &["v", "t", "d", "u", "i", "rd", "s", "a", "e", "r"],
        "acg" => &["v", "t", "d", "u", "i", "rd", "s", "A", "e", "r"],
        "sch" => &["v", "t", "d", "s"],
        "att" => &["v", "t", "d", "a"],
        "agg" => &["v", "t", "d", "A"],
        "edg" => &["v", "t", "d", "e"],
        "rul" => &["v", "t", "d", "r"],
        "rip" => &["v", "t", "d", "u", "i", "n", "dt"],
        "bup" => &["v", "t", "d", "rd", "n", "p", "dt", "b"],
        "upd" => &["v", "t", "d", "rd", "n", "p", "dt", "td", "ts"],
        _ => return None,
    })
}

/// The size of the native body at the head of `buf`, if it starts with a
/// body group: its counter and content.
pub(crate) fn body_size(buf: &[u8]) -> Result<usize, CoreError> {
    let counter = read_counter(buf)?;
    let selector = counter.code.trim_start_matches('-');
    if selector != "F" && selector != "G" {
        return Err(err(format!(
            "{:?} is not a message body group",
            counter.code
        )));
    }
    Ok(counter.size + counter.count * 4)
}

/// Read the native body at the head of `buf`, as keripy's `Serder._loads`.
///
/// Returns the SAD, the version it names, and the body's size. The body is
/// accepted only if writing the SAD gives back the same bytes.
pub(crate) fn load(buf: &[u8]) -> Result<(SadValue, Version, usize), CoreError> {
    let size = body_size(buf)?;
    let raw = buf.get(..size).ok_or_else(|| {
        err(format!(
            "the body needs {size} bytes, the stream has {}",
            buf.len()
        ))
    })?;
    if !raw.is_ascii() {
        return Err(err("a native body is CESR text, which is ASCII"));
    }
    let (selector, content, _) = read_group(raw, &[FIX_BODY, MAP_BODY])?;
    let fixed = selector == FIX_BODY;
    let mut rest = content;
    if !fixed {
        let (label, r) = read_label(rest, true)?;
        if label != "v" {
            return Err(err("a field map body starts with its version"));
        }
        rest = r;
    }
    let ((protocol, major, minor, genus), r) = read_verser(rest)?;
    rest = r;
    if major < 2 || genus.is_some_and(|(g, _)| g < 2) {
        return Err(err("native CESR serialization exists only in version 2"));
    }
    let mut version = Version::new(&protocol, major, minor, SerializationKind::Cesr, size);
    version.genus = Some(genus.unwrap_or((major, minor)));
    let vs = SadValue::String(version.to_version_string());

    let mut sad = SadMap::new();
    match protocol.as_str() {
        "KERI" => {
            if !fixed {
                return Err(err("a KERI message body has fixed fields"));
            }
            let (ilk, r) = read_tag(rest)?;
            rest = r;
            let fields = keri_fields(&ilk)
                .filter(|_| ilk.len() == 3)
                .ok_or_else(|| err(format!("unexpected KERI message type {ilk:?}")))?;
            for &label in fields {
                let value = match label {
                    "v" => vs.clone(),
                    "t" => SadValue::String(ilk.clone()),
                    _ => {
                        let (value, r) = read_keri_field(rest, label, &ilk)?;
                        rest = r;
                        value
                    }
                };
                sad.insert(label.to_string(), value);
            }
        }
        "ACDC" => {
            let (ilk, fields): (Option<String>, &[&str]) = if fixed {
                let (ilk, r) = read_tag(rest)?;
                rest = r;
                let fields = acdc_fixed_fields(&ilk)
                    .ok_or_else(|| err(format!("unexpected fixed-field ACDC type {ilk:?}")))?;
                (Some(ilk), fields)
            } else {
                sad.insert("v".into(), vs.clone());
                // An optional message type, then labelled fields.
                let ilk = match read_label(rest, true) {
                    Ok((label, r)) if label == "t" => {
                        let (ilk, r) = read_tag(r)?;
                        rest = r;
                        sad.insert("t".into(), SadValue::String(ilk.clone()));
                        Some(ilk)
                    }
                    _ => None,
                };
                if !matches!(ilk.as_deref(), None | Some("acm" | "ace")) {
                    return Err(err(format!("unexpected field-map ACDC type {ilk:?}")));
                }
                (ilk, &[])
            };
            let mut labels = fields.iter();
            loop {
                let label = if fixed {
                    match labels.next() {
                        Some(l) => (*l).to_string(),
                        None => break,
                    }
                } else {
                    if rest.is_empty() {
                        break;
                    }
                    let (label, r) = read_label(rest, true)?;
                    rest = r;
                    label
                };
                let value = match label.as_str() {
                    "v" if fixed => vs.clone(),
                    "t" if fixed => SadValue::String(ilk.clone().unwrap_or_default()),
                    _ => {
                        let (value, r) = read_acdc_field(rest, &label)?;
                        rest = r;
                        value
                    }
                };
                if sad.insert(label.clone(), value).is_some() {
                    return Err(err(format!("field {label:?} appears twice")));
                }
            }
        }
        other => return Err(err(format!("unsupported protocol {other:?}"))),
    }
    if !rest.is_empty() {
        return Err(err("the body has bytes after its last field"));
    }
    let sad = SadValue::Object(sad);

    // keripy's round trip: the SAD must write back to these bytes.
    if dump(&sad, &[])?.as_bytes() != raw {
        return Err(err("the body is not in its canonical encoding"));
    }
    Ok((sad, version, size))
}

fn read_keri_field<'a>(
    buf: &'a [u8],
    label: &str,
    ilk: &str,
) -> Result<(SadValue, &'a [u8]), CoreError> {
    let s = SadValue::String;
    Ok(match label {
        "d" | "p" | "x" => {
            let (m, r) = read_class(buf, DIG, "digest")?;
            (s(m.qb64), r)
        }
        "u" => {
            let (n, r) = read_nonce(buf)?;
            (s(n), r)
        }
        "i" | "di" | "ri" => {
            let (m, r) = read_class(buf, PRE, "prefix")?;
            (s(m.qb64), r)
        }
        "s" | "bt" => {
            let (n, r) = read_number(buf)?;
            (s(n), r)
        }
        "kt" | "nt" => read_tholder(buf)?,
        "k" | "n" | "b" | "ba" | "br" => {
            let (_, mut content, rest) = read_group(buf, &[GENERIC_LIST])?;
            let mut items = Vec::new();
            while !content.is_empty() {
                let (m, n) = read_matter(content)?;
                items.push(s(m.qb64));
                content = &content[n..];
            }
            (SadValue::Array(items), rest)
        }
        "dt" => {
            let (d, r) = read_dater(buf)?;
            (s(d), r)
        }
        "r" | "rr" => {
            let (p, r) = read_pather(buf)?;
            (s(p), r)
        }
        "c" => {
            let (_, mut content, rest) = read_group(buf, &[GENERIC_LIST])?;
            let mut traits = Vec::new();
            while !content.is_empty() {
                let (t, r) = read_tag(content)?;
                if !TRAITS.contains(&t.as_str()) {
                    return Err(err(format!("unknown configuration trait {t:?}")));
                }
                traits.push(s(t));
                content = r;
            }
            (SadValue::Array(traits), rest)
        }
        "a" => {
            let counter = read_counter(buf).map_err(|e| err(e.to_string()))?;
            match counter.code.trim_start_matches('-') {
                "I" => read_map(buf, true)?,
                "J" => {
                    if !matches!(ilk, "icp" | "ixn" | "rot" | "dip" | "drt") {
                        return Err(err(format!("a '{ilk}' carries no seal list")));
                    }
                    let (_, content, rest) = read_group(buf, &[GENERIC_LIST])?;
                    (SadValue::Array(read_seals(content)?), rest)
                }
                other => return Err(err(format!("`a` is a map or a list, not {other:?}"))),
            }
        }
        "q" => read_map(buf, true)?,
        other => return Err(err(format!("unsupported KERI field {other:?}"))),
    })
}

fn read_acdc_field<'a>(buf: &'a [u8], label: &str) -> Result<(SadValue, &'a [u8]), CoreError> {
    let s = SadValue::String;
    let section = |buf: &'a [u8], strict: bool| -> Result<(SadValue, &'a [u8]), CoreError> {
        if buf.first() == Some(&b'-') {
            read_map(buf, strict)
        } else {
            let (m, r) = read_class(buf, DIG, "digest")?;
            Ok((s(m.qb64), r))
        }
    };
    Ok(match label {
        "d" | "p" | "b" => {
            let (m, r) = read_class(buf, DIG, "digest")?;
            (s(m.qb64), r)
        }
        "u" | "rd" | "td" => {
            let (n, r) = read_acdc_nonce(buf)?;
            (s(n), r)
        }
        "i" => {
            let (m, r) = read_class(buf, PRE, "prefix")?;
            (s(m.qb64), r)
        }
        "n" => {
            let (n, r) = read_number(buf)?;
            (s(n), r)
        }
        "dt" => {
            let (d, r) = read_dater(buf)?;
            (s(d), r)
        }
        "ts" => {
            let (m, n) = read_matter(buf)?;
            (s(label_text(&m)?), &buf[n..])
        }
        "s" => section(buf, false)?,
        "a" | "e" | "r" => section(buf, true)?,
        "A" => {
            if buf.first() == Some(&b'-') {
                return Err(CoreError::Unsupported(
                    "an expanded aggregate section (`A`) is not supported".into(),
                ));
            }
            let (m, r) = read_class(buf, DIG, "digest")?;
            (s(m.qb64), r)
        }
        other => return Err(err(format!("unsupported ACDC field {other:?}"))),
    })
}

/// Write `sad` natively, as keripy's `Serder._dumps` (a message, which has a
/// version string) or `Mapper._exhale` (any other field map).
///
/// Values of the `verbatim` labels are written as their text: this is how a
/// SAID is computed, over its field filled with `#`. A message's SAID and
/// prefix fields are always written as their text, as keripy does.
pub(crate) fn dump(sad: &SadValue, verbatim: &[&str]) -> Result<String, CoreError> {
    let obj = sad
        .as_object()
        .ok_or_else(|| err("only a field map has a native form"))?;
    let version = obj
        .get("v")
        .and_then(SadValue::as_str)
        .and_then(|vs| Version::parse_str(vs).ok());
    let Some(version) = version else {
        return write_map(obj, verbatim);
    };
    if version.kind != SerializationKind::Cesr {
        return Err(err("the message's version string does not name CESR"));
    }
    let ilk = obj.get("t").and_then(SadValue::as_str);
    let mut body = String::new();
    match version.protocol.as_str() {
        "KERI" => {
            let ilk = ilk.ok_or_else(|| err("a KERI message has a type"))?;
            if keri_fields(ilk).is_none() {
                return Err(err(format!("unexpected KERI message type {ilk:?}")));
            }
            for (label, value) in obj {
                body.push_str(&write_keri_field(label, value, ilk, &version)?);
            }
            enclose(FIX_BODY, &body)
        }
        "ACDC" => {
            let map_body = matches!(ilk, None | Some("acm" | "ace"));
            if !map_body && ilk.and_then(acdc_fixed_fields).is_none() {
                return Err(err(format!("unexpected ACDC message type {ilk:?}")));
            }
            for (label, value) in obj {
                if map_body {
                    body.push_str(&encode_text(label)?);
                }
                body.push_str(&write_acdc_field(label, value, &version)?);
            }
            enclose(if map_body { MAP_BODY } else { FIX_BODY }, &body)
        }
        other => Err(err(format!("unsupported protocol {other:?}"))),
    }
}

fn text_of<'a>(label: &str, value: &'a SadValue) -> Result<&'a str, CoreError> {
    value
        .as_str()
        .ok_or_else(|| err(format!("field {label:?} is not a string")))
}

fn write_keri_field(
    label: &str,
    value: &SadValue,
    ilk: &str,
    version: &Version,
) -> Result<String, CoreError> {
    Ok(match label {
        "v" => encode_verser(version)?,
        "t" => encode_tag(text_of(label, value)?)?,
        "d" | "i" | "p" | "u" | "di" | "ri" | "x" => text_of(label, value)?.to_string(),
        "s" | "bt" => encode_number(text_of(label, value)?)?,
        "kt" | "nt" => encode_tholder(value)?,
        "k" | "n" | "b" | "ba" | "br" => {
            let items = value
                .as_array()
                .ok_or_else(|| err(format!("field {label:?} is a list")))?;
            let mut body = String::new();
            for item in items {
                body.push_str(text_of(label, item)?);
            }
            enclose(GENERIC_LIST, &body)?
        }
        "dt" => encode_dater(text_of(label, value)?)?,
        "r" | "rr" => encode_pather(text_of(label, value)?)?,
        "c" => {
            let items = value
                .as_array()
                .ok_or_else(|| err("field \"c\" is a list"))?;
            let mut body = String::new();
            for item in items {
                body.push_str(&encode_tag(text_of(label, item)?)?);
            }
            enclose(GENERIC_LIST, &body)?
        }
        "a" => match value {
            SadValue::Object(map) => write_map(map, &[])?,
            SadValue::Array(seals) => {
                if !matches!(ilk, "icp" | "ixn" | "rot" | "dip" | "drt") {
                    return Err(err(format!("a '{ilk}' carries no seal list")));
                }
                write_seals(seals)?
            }
            _ => return Err(err("`a` is a map or a list")),
        },
        "q" => match value {
            SadValue::Object(map) => write_map(map, &[])?,
            _ => return Err(err("`q` is a map")),
        },
        other => return Err(err(format!("unsupported KERI field {other:?}"))),
    })
}

fn write_acdc_field(label: &str, value: &SadValue, version: &Version) -> Result<String, CoreError> {
    // A section is a block, or the SAID of one (never empty).
    let section = || -> Result<String, CoreError> {
        match value {
            SadValue::Object(map) => write_map(map, &[]),
            SadValue::String(s) if !s.is_empty() => verbatim_class(s, DIG, "digest"),
            _ => Err(err(format!("section {label:?} is a block or a SAID"))),
        }
    };
    Ok(match label {
        "v" => encode_verser(version)?,
        "t" => encode_tag(text_of(label, value)?)?,
        "d" | "i" | "p" | "b" => text_of(label, value)?.to_string(),
        "u" | "rd" | "td" => encode_acdc_nonce(text_of(label, value)?)?,
        "n" => encode_number(text_of(label, value)?)?,
        "dt" => encode_dater(text_of(label, value)?)?,
        "ts" => encode_text(text_of(label, value)?)?,
        "s" | "a" | "e" | "r" => section()?,
        "A" => match value {
            SadValue::String(s) if !s.is_empty() => verbatim_class(s, DIG, "digest")?,
            _ => {
                return Err(CoreError::Unsupported(
                    "an expanded aggregate section (`A`) is not supported".into(),
                ));
            }
        },
        other => return Err(err(format!("unsupported ACDC field {other:?}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip_as_keripy_encodes_them() {
        // Values from keripy b70986f.
        assert_eq!(encode_number("0").unwrap(), "MAAA");
        assert_eq!(encode_number("1").unwrap(), "MAAB");
        assert_eq!(encode_number("10000").unwrap(), "RAAAAQAA");
        assert_eq!(encode_tag("icp").unwrap(), "Xicp");
        assert_eq!(encode_text("v").unwrap(), "0J_v");
        assert_eq!(encode_text("").unwrap(), "1AAP");
        let v = Version::new("KERI", 2, 0, SerializationKind::Cesr, 0);
        assert_eq!(encode_verser(&v).unwrap(), "0OKERICAACAA");
        assert_eq!(
            encode_dater("2026-01-01T00:00:00.000000+00:00").unwrap(),
            "1AAG2026-01-01T00c00c00d000000p00c00"
        );
        let route = encode_pather("/end/role/add").unwrap();
        assert_eq!(read_pather(route.as_bytes()).unwrap().0, "/end/role/add");
    }

    #[test]
    fn a_weighted_threshold_reads_back_collapsed() {
        let sith = SadValue::from_json_value(&serde_json::json!([["1/2", "1"]]));
        let limen = encode_tholder(&sith).unwrap();
        let (read, rest) = read_tholder(limen.as_bytes()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(read.to_json_value(), serde_json::json!(["1/2", "1"]));
        assert_eq!(encode_tholder(&read).unwrap(), limen);
    }

    #[test]
    fn a_weight_above_one_is_refused() {
        // keripy `Tholder.weight`: 0 <= w <= 1.
        for w in ["3/2", "2", "1/0", "1.5", "-1/2", ""] {
            assert!(Weight::parse(w).is_err(), "{w}");
        }
        assert_eq!(Weight::parse("2/4").unwrap().render('/'), "1/2");
        assert_eq!(Weight::parse("2/2").unwrap().render('/'), "1");
        assert_eq!(Weight::parse("0").unwrap().render('/'), "0");
    }

    #[test]
    fn a_seal_of_no_native_type_is_not_written() {
        // keripy's native writer drops such a seal from the body; this one
        // refuses, so a SAID is never computed over less than the SAD holds.
        let seals = vec![SadValue::from_json_value(&serde_json::json!({ "x": "E" }))];
        assert!(write_seals(&seals).is_err());
    }

    #[test]
    fn a_non_canonical_number_is_refused_by_the_round_trip() {
        // `0H` is a Number code keripy reads but never writes.
        let long = encode_matter("0H", "", &[0, 0, 0, 1]).unwrap();
        let (n, _) = read_number(long.as_bytes()).unwrap();
        assert_eq!(n, "1");
        assert_ne!(encode_number(&n).unwrap(), long);
    }

    #[test]
    fn nesting_past_the_limit_is_refused_not_a_stack_overflow() {
        // A field map holding `{"a": [[[ … ]]]}`, nested far past MAX_DEPTH.
        let mut inner = String::new();
        for _ in 0..10_000 {
            inner = enclose(GENERIC_LIST, &inner).unwrap();
        }
        let body = format!("{}{inner}", encode_text("a").unwrap());
        let map = enclose(GENERIC_MAP, &body).unwrap();
        let e = read_map(map.as_bytes(), true).unwrap_err();
        assert!(e.to_string().contains("nest deeper"), "{e}");

        // Within the limit it reads.
        let mut inner = String::new();
        for _ in 0..(MAX_DEPTH - 2) {
            inner = enclose(GENERIC_LIST, &inner).unwrap();
        }
        let body = format!("{}{inner}", encode_text("a").unwrap());
        let map = enclose(GENERIC_MAP, &body).unwrap();
        read_map(map.as_bytes(), true).unwrap();
    }
}
