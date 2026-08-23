//! CESR counter code tables.
//!
//! A counter code such as `-A` does not mean the same thing in every version
//! of CESR. KERI 1.x and KERI 2.x assign the same two-character codes to
//! *different* attachment groups:
//!
//! | code | KERI 1.x                    | KERI 2.x                    |
//! |------|-----------------------------|-----------------------------|
//! | `-A` | controller indexed sigs     | attached material (quadlets)|
//! | `-B` | witness indexed sigs        | controller indexed sigs     |
//! | `-C` | non-transferable receipt couples | witness indexed sigs   |
//! | `-D` | transferable receipt quadruples  | non-transferable receipt couples |
//! | `-E` | first seen replay couples   | transferable receipt quadruples |
//! | `-F` | transferable indexed sig groups | first seen replay couples |
//! | `-G` | seal source couples         | seal source couples         |
//! | `-V` | attached material (quadlets)| —                           |
//!
//! The *sizes* are identical in both (a two-character code plus a
//! two-character count, or the `-0X` big variant), which is why
//! `affinidi_cesr::tables::counter_sizage` needs no version — only the
//! meaning differs. Reading a stream against the wrong table silently turns
//! signatures into an uninterpreted blob, so the table is always selected
//! explicitly, from the protocol version in the message's own version string.

/// Which CESR counter code table a stream uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CounterTable {
    /// KERI/CESR 1.x — what `KERI10JSON…` events carry, and what keripy and
    /// the `did:webs` `keri.cesr` artifact use.
    #[default]
    V1,
    /// KERI/CESR 2.x.
    V2,
}

impl CounterTable {
    /// Select the table from a protocol major version.
    pub fn from_major(major: u8) -> Self {
        if major >= 2 { Self::V2 } else { Self::V1 }
    }
}

/// What a counter code means, independent of which table produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupKind {
    /// A group whose count is in quadlets (4-character units) of nested
    /// attachment material, rather than a count of primitives.
    AttachedMaterialQuadlets,
    /// Controller indexed signatures.
    ControllerIdxSigs,
    /// Witness indexed signatures.
    WitnessIdxSigs,
    /// Non-transferable receipt couples: (witness prefix, signature).
    NonTransReceiptCouples,
    /// Transferable receipt quadruples.
    TransReceiptQuadruples,
    /// First seen replay couples: (sequence number, datetime).
    FirstSeenReplayCouples,
    /// Transferable indexed signature groups.
    TransIdxSigGroups,
    /// Seal source couples: (sequence number, event SAID). This is the
    /// delegator anchor carried with a delegated event.
    SealSourceCouples,
}

impl GroupKind {
    /// Resolve a counter code against a table.
    ///
    /// Returns `None` for codes this implementation does not model. Callers
    /// must treat `None` as "cannot be interpreted", never as "empty".
    pub fn classify(code: &str, table: CounterTable) -> Option<Self> {
        // The `-0X` forms are the big-count variants of the same group.
        let base = match code.strip_prefix("-0") {
            Some(rest) => rest,
            None => code.strip_prefix('-')?,
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

            (CounterTable::V2, "A") => Some(Self::AttachedMaterialQuadlets),
            (CounterTable::V2, "B") => Some(Self::ControllerIdxSigs),
            (CounterTable::V2, "C") => Some(Self::WitnessIdxSigs),
            (CounterTable::V2, "D") => Some(Self::NonTransReceiptCouples),
            (CounterTable::V2, "E") => Some(Self::TransReceiptQuadruples),
            (CounterTable::V2, "F") => Some(Self::FirstSeenReplayCouples),
            (CounterTable::V2, "G") => Some(Self::SealSourceCouples),

            _ => None,
        }
    }

    /// The counter code for this group in the given table.
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

            (CounterTable::V2, Self::AttachedMaterialQuadlets) => "-A",
            (CounterTable::V2, Self::ControllerIdxSigs) => "-B",
            (CounterTable::V2, Self::WitnessIdxSigs) => "-C",
            (CounterTable::V2, Self::NonTransReceiptCouples) => "-D",
            (CounterTable::V2, Self::TransReceiptQuadruples) => "-E",
            (CounterTable::V2, Self::FirstSeenReplayCouples) => "-F",
            (CounterTable::V2, Self::SealSourceCouples) => "-G",
            (CounterTable::V2, Self::TransIdxSigGroups) => return None,
        };
        Some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_and_v2_disagree_on_the_same_code() {
        assert_eq!(
            GroupKind::classify("-A", CounterTable::V1),
            Some(GroupKind::ControllerIdxSigs)
        );
        assert_eq!(
            GroupKind::classify("-A", CounterTable::V2),
            Some(GroupKind::AttachedMaterialQuadlets)
        );
        assert_eq!(
            GroupKind::classify("-B", CounterTable::V1),
            Some(GroupKind::WitnessIdxSigs)
        );
        assert_eq!(
            GroupKind::classify("-B", CounterTable::V2),
            Some(GroupKind::ControllerIdxSigs)
        );
    }

    #[test]
    fn big_count_variants_classify_the_same() {
        for table in [CounterTable::V1, CounterTable::V2] {
            for base in ["A", "B", "C", "D", "E", "F", "G"] {
                assert_eq!(
                    GroupKind::classify(&format!("-{base}"), table),
                    GroupKind::classify(&format!("-0{base}"), table),
                    "table {table:?} code {base}"
                );
            }
        }
    }

    #[test]
    fn v1_quadlet_group_is_dash_v() {
        assert_eq!(
            GroupKind::classify("-V", CounterTable::V1),
            Some(GroupKind::AttachedMaterialQuadlets)
        );
        // `-V` has no meaning in the 2.x table.
        assert_eq!(GroupKind::classify("-V", CounterTable::V2), None);
    }

    #[test]
    fn codes_round_trip_through_classify() {
        for table in [CounterTable::V1, CounterTable::V2] {
            for kind in [
                GroupKind::AttachedMaterialQuadlets,
                GroupKind::ControllerIdxSigs,
                GroupKind::WitnessIdxSigs,
                GroupKind::NonTransReceiptCouples,
                GroupKind::TransReceiptQuadruples,
                GroupKind::FirstSeenReplayCouples,
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
    }

    #[test]
    fn table_from_major() {
        assert_eq!(CounterTable::from_major(1), CounterTable::V1);
        assert_eq!(CounterTable::from_major(2), CounterTable::V2);
        assert_eq!(CounterTable::from_major(3), CounterTable::V2);
    }
}
