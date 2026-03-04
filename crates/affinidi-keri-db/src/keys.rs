//! Key encoding utilities for database lookups.
//!
//! KERI database keys combine the identifier prefix with a sequence number
//! or digest to form unique lookup keys.

/// Separator used between prefix and suffix in database keys.
const SEP: &str = ".";

/// Encode a key from prefix and sequence number.
///
/// Format: `{prefix}.{sn:032x}` (zero-padded 32-char hex sequence number).
pub fn sn_key(prefix: &str, sn: u64) -> String {
    format!("{prefix}{SEP}{sn:032x}")
}

/// Encode a key from prefix and digest.
///
/// Format: `{prefix}.{digest}`.
pub fn dg_key(prefix: &str, digest: &str) -> String {
    format!("{prefix}{SEP}{digest}")
}

/// Encode a key from prefix, sequence number, and digest.
///
/// Format: `{prefix}.{sn:032x}.{digest}`.
pub fn sn_dg_key(prefix: &str, sn: u64, digest: &str) -> String {
    format!("{prefix}{SEP}{sn:032x}{SEP}{digest}")
}

/// Extract the prefix from a compound key.
pub fn split_prefix(key: &str) -> Option<&str> {
    key.split(SEP).next()
}

/// Extract the sequence number from a sn_key.
pub fn split_sn(key: &str) -> Option<u64> {
    let parts: Vec<&str> = key.split(SEP).collect();
    if parts.len() >= 2 {
        u64::from_str_radix(parts[1], 16).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sn_key() {
        let key = sn_key("DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH", 0);
        assert!(key.starts_with("DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH."));
        assert!(key.ends_with("00000000000000000000000000000000"));
    }

    #[test]
    fn test_sn_key_nonzero() {
        let key = sn_key("DPRE", 255);
        assert_eq!(key, "DPRE.000000000000000000000000000000ff");
    }

    #[test]
    fn test_dg_key() {
        let key = dg_key("DPRE", "Eabcdef");
        assert_eq!(key, "DPRE.Eabcdef");
    }

    #[test]
    fn test_split_prefix() {
        assert_eq!(split_prefix("DPRE.00000000"), Some("DPRE"));
    }

    #[test]
    fn test_split_sn() {
        let key = sn_key("DPRE", 42);
        assert_eq!(split_sn(&key), Some(42));
    }
}
