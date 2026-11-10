//! CESR counter code tables, one per genus version.
//!
//! A counter code does not mean the same thing in every CESR genus version.
//! The tables below are keripy's (`keri/core/counting.py`, `CounterCodex_1_0`
//! and `CounterCodex_2_0`, at b70986f), limited to the groups this crate
//! models:
//!
//! | group | 1.x | 2.x |
//! |---|---|---|
//! | attachment group (nested, quadlets) | `-V` | `-C` |
//! | controller indexed sigs | `-A` | `-K` |
//! | witness indexed sigs | `-B` | `-L` |
//! | non-transferable receipt couples | `-C` | `-M` |
//! | transferable receipt quadruples (legacy) | `-D` | — |
//! | first seen replay couples | `-E` | `-O` |
//! | transferable indexed sig groups | `-F` | `-X` |
//! | seal source couples | `-G` | `-S` |
//!
//! Two other differences matter as much as the codes:
//!
//! - **What a count counts.** In 1.x a count is a number of items, except for
//!   the attachment group, whose count is in quadlets (4-character units). In
//!   2.x *every* count is in quadlets: `-KAW` is 22 quadlets, one 88-character
//!   signature.
//! - **Which table applies.** The stream's genus decides, never a message's
//!   own version: keripy republishes v1 events under a v2 genus with 2.x
//!   attachments. A stream with no genus-version counter is 1.x (did:webs on
//!   KERI v2, positions P1 and P2).
//!
//! Counter sizes come from keripy's `Counter.Hards`: `-` and a letter is a
//! 2-character code with a 2-digit count; `--` and a letter a 3-character
//! code with a 5-digit count (a "big" group); `-_` a 5-character code with a
//! 3-digit count (the genus-version counter, `-_AAA`). The `-0` big form is an
//! older 1.x spelling, still read in 1.x streams.

use crate::error::CoreError;
use crate::version::{b64_to_usize, int_to_b64};

/// Which CESR counter code table a stream uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CounterTable {
    /// CESR genus 1.x: what `KERI10JSON…` events and every deployed
    /// `did:webs` `keri.cesr` carry, and what a stream with no genus-version
    /// counter is.
    #[default]
    V1,
    /// CESR genus 2.x.
    V2,
}

impl CounterTable {
    /// Select the table from a protocol or genus major version.
    pub fn from_major(major: u8) -> Self {
        if major >= 2 { Self::V2 } else { Self::V1 }
    }

    /// The table a genus major version names, refusing one this crate does
    /// not know rather than reading it as the nearest.
    ///
    /// # Errors
    /// Returns [`CoreError::Unsupported`] for a major version other than 1 or 2.
    pub fn for_genus(major: u8) -> Result<Self, CoreError> {
        match major {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            other => Err(CoreError::Unsupported(format!(
                "CESR genus version {other}"
            ))),
        }
    }

    /// The genus-version counter that switches a stream to this table:
    /// `-_AAABAA` for 1.0, `-_AAACAA` for 2.0.
    pub fn genus_counter(self) -> &'static str {
        match self {
            Self::V1 => "-_AAABAA",
            Self::V2 => "-_AAACAA",
        }
    }

    /// Whether a group's count is in quadlets rather than items.
    pub fn counts_quadlets(self, kind: GroupKind) -> bool {
        match self {
            Self::V1 => kind == GroupKind::AttachedMaterialQuadlets,
            Self::V2 => true,
        }
    }
}

/// What a counter code means, independent of which table produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupKind {
    /// A group whose count is in quadlets (4-character units) of nested
    /// attachment material: 1.x `-V`, 2.x `-C`.
    AttachedMaterialQuadlets,
    /// Controller indexed signatures.
    ControllerIdxSigs,
    /// Witness indexed signatures.
    WitnessIdxSigs,
    /// Non-transferable receipt couples: (witness prefix, signature).
    NonTransReceiptCouples,
    /// Transferable receipt quadruples (1.x `-D`, no longer in keripy's 1.x
    /// table; recognised so it is refused by name).
    TransReceiptQuadruples,
    /// First seen replay couples: (sequence number, datetime).
    FirstSeenReplayCouples,
    /// Transferable indexed signature groups.
    TransIdxSigGroups,
    /// Seal source couples: (sequence number, event SAID). This is the
    /// delegator anchor carried with a delegated event.
    SealSourceCouples,
    /// Blinded state quadruples (2.x `-a`): (BLID, UUID, transaction ACDC
    /// SAID, transaction state), the disclosed state of a blindable registry
    /// update.
    BlindedStateQuadruples,
}

impl GroupKind {
    /// Resolve a counter code against a table.
    ///
    /// Big forms (`--X`, and `-0X` in 1.x) resolve to the same group as `-X`.
    /// Returns `None` for codes this implementation does not model. Callers
    /// must treat `None` as "cannot be interpreted", never as "empty".
    pub fn classify(code: &str, table: CounterTable) -> Option<Self> {
        let base = match (code.strip_prefix("--"), code.strip_prefix("-0")) {
            (Some(rest), _) => rest,
            (None, Some(rest)) if table == CounterTable::V1 => rest,
            _ => code.strip_prefix('-')?,
        };

        match (table, base) {
            (CounterTable::V1, "A") => Some(Self::ControllerIdxSigs),
            (CounterTable::V1, "B") => Some(Self::WitnessIdxSigs),
            (CounterTable::V1, "C") => Some(Self::NonTransReceiptCouples),
            (CounterTable::V1, "D") => Some(Self::TransReceiptQuadruples),
            (CounterTable::V1, "E") => Some(Self::FirstSeenReplayCouples),
            (CounterTable::V1, "F") => Some(Self::TransIdxSigGroups),
            (CounterTable::V1, "G") => Some(Self::SealSourceCouples),
            (CounterTable::V1, "V") => Some(Self::AttachedMaterialQuadlets),

            (CounterTable::V2, "C") => Some(Self::AttachedMaterialQuadlets),
            (CounterTable::V2, "K") => Some(Self::ControllerIdxSigs),
            (CounterTable::V2, "L") => Some(Self::WitnessIdxSigs),
            (CounterTable::V2, "M") => Some(Self::NonTransReceiptCouples),
            (CounterTable::V2, "O") => Some(Self::FirstSeenReplayCouples),
            (CounterTable::V2, "S") => Some(Self::SealSourceCouples),
            (CounterTable::V2, "X") => Some(Self::TransIdxSigGroups),
            (CounterTable::V2, "a") => Some(Self::BlindedStateQuadruples),

            _ => None,
        }
    }

    /// The (small) counter code for this group in the given table.
    ///
    /// Returns `None` when the table has no code for the group.
    pub fn code(self, table: CounterTable) -> Option<&'static str> {
        let code = match (table, self) {
            (CounterTable::V1, Self::ControllerIdxSigs) => "-A",
            (CounterTable::V1, Self::WitnessIdxSigs) => "-B",
            (CounterTable::V1, Self::NonTransReceiptCouples) => "-C",
            (CounterTable::V1, Self::TransReceiptQuadruples) => "-D",
            (CounterTable::V1, Self::FirstSeenReplayCouples) => "-E",
            (CounterTable::V1, Self::TransIdxSigGroups) => "-F",
            (CounterTable::V1, Self::SealSourceCouples) => "-G",
            (CounterTable::V1, Self::AttachedMaterialQuadlets) => "-V",

            (CounterTable::V2, Self::AttachedMaterialQuadlets) => "-C",
            (CounterTable::V2, Self::ControllerIdxSigs) => "-K",
            (CounterTable::V2, Self::WitnessIdxSigs) => "-L",
            (CounterTable::V2, Self::NonTransReceiptCouples) => "-M",
            (CounterTable::V2, Self::FirstSeenReplayCouples) => "-O",
            (CounterTable::V2, Self::SealSourceCouples) => "-S",
            (CounterTable::V2, Self::TransIdxSigGroups) => "-X",
            (CounterTable::V2, Self::BlindedStateQuadruples) => "-a",
            (CounterTable::V2, Self::TransReceiptQuadruples) => return None,
            (CounterTable::V1, Self::BlindedStateQuadruples) => return None,
        };
        Some(code)
    }

    /// Encode a counter for this group: the small form when the count fits
    /// two Base64 digits, otherwise the big (`--`) form.
    ///
    /// `count` is in the group's unit for the table — items, or quadlets
    /// where [`CounterTable::counts_quadlets`] says so.
    ///
    /// # Errors
    /// Returns `CoreError` if the table has no code for the group, or the
    /// count does not fit even the big form.
    pub fn counter(self, table: CounterTable, count: usize) -> Result<String, CoreError> {
        let code = self.code(table).ok_or_else(|| {
            CoreError::Unsupported(format!("{self:?} has no counter code in {table:?}"))
        })?;
        if count < 64 * 64 {
            Ok(format!("{code}{}", int_to_b64(count, 2)))
        } else if count < 64usize.pow(5) {
            Ok(format!("-{code}{}", int_to_b64(count, 5)))
        } else {
            Err(CoreError::ParseError(format!(
                "count {count} does not fit a {code} counter"
            )))
        }
    }
}

/// A counter read from the head of a CESR text stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCounter {
    /// The full code, e.g. `-K`, `--K`, `-0V` or `-_AAA`.
    pub code: String,
    /// The count field's value. Its unit depends on the group and table.
    pub count: usize,
    /// The counter's length in characters.
    pub size: usize,
}

impl RawCounter {
    /// Whether this is the KERI/ACDC genus-version counter (`-_AAA`).
    pub fn is_genus_version(&self) -> bool {
        self.code == "-_AAA"
    }

    /// For a genus-version counter, the (major, minor) version it names: the
    /// count's three digits are one for the major and two for the minor.
    pub fn genus_version(&self) -> Option<(u8, u8)> {
        if !self.is_genus_version() {
            return None;
        }
        let major = u8::try_from(self.count / (64 * 64)).ok()?;
        let minor = u8::try_from(self.count % (64 * 64)).ok()?;
        Some((major, minor))
    }
}

/// Read the counter at the head of `text`.
///
/// # Errors
/// Returns `CoreError::ParseError` if `text` does not start with a counter
/// whose size can be determined.
pub fn read_counter(text: &[u8]) -> Result<RawCounter, CoreError> {
    if text.first() != Some(&b'-') {
        return Err(CoreError::ParseError("a counter starts with '-'".into()));
    }
    let second = *text
        .get(1)
        .ok_or_else(|| CoreError::ParseError("truncated counter".into()))?;
    let (hs, ss) = match second {
        b'-' | b'0' => (3, 5),
        b'_' => (5, 3),
        b'A'..=b'Z' | b'a'..=b'z' => (2, 2),
        other => {
            return Err(CoreError::ParseError(format!(
                "no counter code starts with '-{}'",
                other as char
            )));
        }
    };
    let fs = hs + ss;
    if text.len() < fs {
        return Err(CoreError::ParseError(format!(
            "truncated counter: need {fs} characters, have {}",
            text.len()
        )));
    }
    let head = std::str::from_utf8(&text[..fs])
        .map_err(|_| CoreError::ParseError("counter is not ASCII".into()))?;
    if !head.is_ascii() {
        return Err(CoreError::ParseError("counter is not ASCII".into()));
    }
    let count = b64_to_usize(&head[hs..])
        .map_err(|e| CoreError::ParseError(format!("counter {head:?}: {e}")))?;
    Ok(RawCounter {
        code: head[..hs].to_string(),
        count,
        size: fs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_and_v2_disagree_on_the_same_code() {
        assert_eq!(
            GroupKind::classify("-C", CounterTable::V1),
            Some(GroupKind::NonTransReceiptCouples)
        );
        assert_eq!(
            GroupKind::classify("-C", CounterTable::V2),
            Some(GroupKind::AttachedMaterialQuadlets)
        );
        assert_eq!(
            GroupKind::classify("-A", CounterTable::V1),
            Some(GroupKind::ControllerIdxSigs)
        );
        // `-A` is keripy's 2.x generic group, which this crate does not model.
        assert_eq!(GroupKind::classify("-A", CounterTable::V2), None);
    }

    #[test]
    fn big_count_variants_classify_the_same() {
        for (table, bases) in [
            (CounterTable::V1, ["A", "B", "C", "E", "F", "G", "V"]),
            (CounterTable::V2, ["C", "K", "L", "M", "O", "S", "X"]),
        ] {
            for base in bases {
                assert_eq!(
                    GroupKind::classify(&format!("-{base}"), table),
                    GroupKind::classify(&format!("--{base}"), table),
                    "table {table:?} code {base}"
                );
            }
        }
        // The `-0` spelling is 1.x only.
        assert_eq!(
            GroupKind::classify("-0V", CounterTable::V1),
            Some(GroupKind::AttachedMaterialQuadlets)
        );
        assert_eq!(GroupKind::classify("-0K", CounterTable::V2), None);
    }

    #[test]
    fn codes_round_trip_through_classify() {
        for table in [CounterTable::V1, CounterTable::V2] {
            for kind in [
                GroupKind::AttachedMaterialQuadlets,
                GroupKind::ControllerIdxSigs,
                GroupKind::WitnessIdxSigs,
                GroupKind::NonTransReceiptCouples,
                GroupKind::FirstSeenReplayCouples,
                GroupKind::TransIdxSigGroups,
                GroupKind::SealSourceCouples,
            ] {
                let code = kind.code(table).expect("code exists");
                assert_eq!(GroupKind::classify(code, table), Some(kind));
            }
        }
    }

    #[test]
    fn unknown_codes_are_none() {
        assert_eq!(GroupKind::classify("-Z", CounterTable::V1), None);
        assert_eq!(GroupKind::classify("A", CounterTable::V1), None);
        assert_eq!(GroupKind::classify("-V", CounterTable::V2), None);
    }

    #[test]
    fn reads_keripy_counters() {
        // From the keripy v2 fixtures.
        let c = read_counter(b"-CAi-KAW").unwrap();
        assert_eq!((c.code.as_str(), c.count, c.size), ("-C", 34, 4));
        let g = read_counter(b"-_AAACAA{").unwrap();
        assert!(g.is_genus_version());
        assert_eq!(g.genus_version(), Some((2, 0)));
        assert_eq!(
            read_counter(b"-_AAABAA").unwrap().genus_version(),
            Some((1, 0))
        );
        let big = read_counter(b"--KAAABA").unwrap();
        assert_eq!((big.code.as_str(), big.count, big.size), ("--K", 64, 8));
    }

    #[test]
    fn encodes_small_and_big_counters() {
        assert_eq!(
            GroupKind::ControllerIdxSigs
                .counter(CounterTable::V2, 22)
                .unwrap(),
            "-KAW"
        );
        assert_eq!(
            GroupKind::ControllerIdxSigs
                .counter(CounterTable::V1, 1)
                .unwrap(),
            "-AAB"
        );
        let big = GroupKind::AttachedMaterialQuadlets
            .counter(CounterTable::V2, 5000)
            .unwrap();
        assert_eq!(big, "--CAABOI");
        assert_eq!(read_counter(big.as_bytes()).unwrap().count, 5000);
    }

    #[test]
    fn genus_tables() {
        assert_eq!(CounterTable::for_genus(1).unwrap(), CounterTable::V1);
        assert_eq!(CounterTable::for_genus(2).unwrap(), CounterTable::V2);
        assert!(CounterTable::for_genus(3).is_err());
        assert_eq!(CounterTable::from_major(3), CounterTable::V2);
        assert!(CounterTable::V2.counts_quadlets(GroupKind::ControllerIdxSigs));
        assert!(!CounterTable::V1.counts_quadlets(GroupKind::ControllerIdxSigs));
    }
}
