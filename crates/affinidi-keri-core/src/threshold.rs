//! Signing threshold types for KERI events.
//!
//! KERI supports two kinds of signing thresholds:
//!
//! - **Simple**: a numeric M-of-N threshold, e.g. `"2"` means at least 2 signatures required.
//! - **Weighted**: fractional weights per key grouped into clauses. Each clause must be
//!   independently satisfied (the weighted sum of satisfied keys >= 1) for the overall
//!   threshold to be met.
//!
//! In KERI event fields, simple thresholds are encoded as string numbers (`"1"`, `"2"`),
//! and weighted thresholds are encoded as nested arrays of fraction strings
//! (`[["1/2", "1/2", "1/2"], ["1", "1"]]`).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

/// A fractional weight used in weighted thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weight {
    /// Numerator.
    pub num: u32,
    /// Denominator.
    pub den: u32,
}

impl Weight {
    /// Create a new weight.
    pub fn new(num: u32, den: u32) -> Result<Self, CoreError> {
        if den == 0 {
            return Err(CoreError::Validation(
                "weight denominator cannot be zero".into(),
            ));
        }
        Ok(Self { num, den })
    }

    /// Parse a weight from a fractional string like `"1/2"` or `"1"`.
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        if let Some((num_s, den_s)) = s.split_once('/') {
            let num: u32 = num_s
                .parse()
                .map_err(|_| CoreError::Validation(format!("invalid weight numerator: {num_s}")))?;
            let den: u32 = den_s.parse().map_err(|_| {
                CoreError::Validation(format!("invalid weight denominator: {den_s}"))
            })?;
            Self::new(num, den)
        } else {
            // Whole number, e.g. "1" means 1/1
            let num: u32 = s
                .parse()
                .map_err(|_| CoreError::Validation(format!("invalid weight: {s}")))?;
            Self::new(num, 1)
        }
    }

    /// Convert to a floating-point value.
    pub fn as_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }

    /// Format as a fraction string.
    pub fn to_fraction_string(&self) -> String {
        if self.den == 1 {
            format!("{}", self.num)
        } else {
            format!("{}/{}", self.num, self.den)
        }
    }
}

/// Signing threshold specification.
///
/// KERI supports both simple numeric thresholds and weighted multi-sig
/// thresholds with fractional weights.
#[derive(Debug, Clone, PartialEq)]
pub enum Threshold {
    /// A simple M-of-N threshold where `usize` is the required count.
    Simple(usize),
    /// A weighted threshold expressed as groups of fractional weights.
    /// Each inner Vec represents a clause; satisfaction requires the
    /// weighted sum of satisfied keys to be >= 1.0 within each clause.
    Weighted(Vec<Vec<Weight>>),
}

impl Threshold {
    /// Parse a threshold from its KERI field representation.
    ///
    /// A simple threshold is a JSON string like `"1"` or `"2"`.
    /// A weighted threshold is a nested JSON array of fractional strings,
    /// e.g. `[["1/2", "1/2", "1/2"]]`.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, CoreError> {
        match value {
            serde_json::Value::String(s) => {
                let n: usize = s
                    .parse()
                    .map_err(|_| CoreError::Validation(format!("invalid threshold string: {s}")))?;
                Ok(Threshold::Simple(n))
            }
            serde_json::Value::Number(n) => {
                let n = n.as_u64().ok_or_else(|| {
                    CoreError::Validation(format!("invalid threshold number: {n}"))
                })?;
                Ok(Threshold::Simple(n as usize))
            }
            serde_json::Value::Array(clauses) => {
                let mut weighted = Vec::new();
                for clause in clauses {
                    let arr = clause.as_array().ok_or_else(|| {
                        CoreError::Validation(
                            "weighted threshold clause must be an array".into(),
                        )
                    })?;
                    let mut weights = Vec::new();
                    for w in arr {
                        let s = w.as_str().ok_or_else(|| {
                            CoreError::Validation(
                                "weighted threshold weight must be a string".into(),
                            )
                        })?;
                        weights.push(Weight::parse(s)?);
                    }
                    weighted.push(weights);
                }
                Ok(Threshold::Weighted(weighted))
            }
            _ => Err(CoreError::Validation(format!(
                "invalid threshold value: {value}"
            ))),
        }
    }

    /// Convert this threshold to its JSON representation.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Threshold::Simple(n) => serde_json::Value::String(n.to_string()),
            Threshold::Weighted(clauses) => {
                let arr: Vec<serde_json::Value> = clauses
                    .iter()
                    .map(|clause| {
                        let weights: Vec<serde_json::Value> = clause
                            .iter()
                            .map(|w| serde_json::Value::String(w.to_fraction_string()))
                            .collect();
                        serde_json::Value::Array(weights)
                    })
                    .collect();
                serde_json::Value::Array(arr)
            }
        }
    }

    /// Return `true` if the threshold is satisfied given the indices of keys
    /// that have valid signatures.
    ///
    /// For simple thresholds: satisfied if `indices.len() >= threshold`.
    ///
    /// For weighted thresholds: each clause must be independently satisfied.
    /// A clause is satisfied when the sum of weights at the given indices >= 1.0.
    /// The `total_keys` parameter is the total number of keys in the key set.
    pub fn is_satisfied(&self, indices: &[usize], total_keys: usize) -> bool {
        match self {
            Threshold::Simple(k) => indices.len() >= *k,
            Threshold::Weighted(clauses) => {
                // Build a flat list of all weights across clauses, indexed by key position.
                // Each clause must be independently satisfied.
                let mut key_idx = 0;
                for clause in clauses {
                    // Use proper fraction addition: a/b + c/d = (a*d + c*b)/(b*d)
                    let mut total_num: u64 = 0;
                    let mut total_den: u64 = 1;

                    for weight in clause {
                        if key_idx < total_keys && indices.contains(&key_idx) {
                            // Add this weight: total_num/total_den += weight.num/weight.den
                            total_num =
                                total_num * weight.den as u64 + weight.num as u64 * total_den;
                            total_den *= weight.den as u64;
                        }
                        key_idx += 1;
                    }

                    // Check if total >= 1 (i.e., total_num >= total_den)
                    if total_num < total_den {
                        return false;
                    }
                }

                true
            }
        }
    }
}

/// Threshold value for serde: can be either a string (simple) or an array (weighted).
///
/// This type is used directly in event structures for the `kt` and `nt` fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdValue(pub Threshold);

impl Serialize for ThresholdValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Threshold::Simple(n) => serializer.serialize_str(&n.to_string()),
            Threshold::Weighted(clauses) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(clauses.len()))?;
                for clause in clauses {
                    let weights: Vec<String> =
                        clause.iter().map(|w| w.to_fraction_string()).collect();
                    seq.serialize_element(&weights)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ThresholdValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let threshold =
            Threshold::from_json_value(&value).map_err(serde::de::Error::custom)?;
        Ok(ThresholdValue(threshold))
    }
}

impl From<Threshold> for ThresholdValue {
    fn from(t: Threshold) -> Self {
        ThresholdValue(t)
    }
}

impl From<usize> for ThresholdValue {
    fn from(n: usize) -> Self {
        ThresholdValue(Threshold::Simple(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_threshold_parse() {
        let v = serde_json::json!("2");
        let t = Threshold::from_json_value(&v).unwrap();
        assert_eq!(t, Threshold::Simple(2));
    }

    #[test]
    fn test_simple_threshold_number() {
        let v = serde_json::json!(3);
        let t = Threshold::from_json_value(&v).unwrap();
        assert_eq!(t, Threshold::Simple(3));
    }

    #[test]
    fn test_weighted_threshold_parse() {
        let v = serde_json::json!([["1/2", "1/2", "1/2"]]);
        let t = Threshold::from_json_value(&v).unwrap();
        match t {
            Threshold::Weighted(clauses) => {
                assert_eq!(clauses.len(), 1);
                assert_eq!(clauses[0].len(), 3);
                assert_eq!(clauses[0][0], Weight { num: 1, den: 2 });
            }
            _ => panic!("expected weighted threshold"),
        }
    }

    #[test]
    fn test_simple_satisfaction() {
        let t = Threshold::Simple(2);
        assert!(!t.is_satisfied(&[0], 3));
        assert!(t.is_satisfied(&[0, 1], 3));
        assert!(t.is_satisfied(&[0, 1, 2], 3));
    }

    #[test]
    fn test_weighted_satisfaction() {
        // One clause with three keys at 1/2 each. Need sum >= 1.
        let t = Threshold::Weighted(vec![vec![
            Weight::new(1, 2).unwrap(),
            Weight::new(1, 2).unwrap(),
            Weight::new(1, 2).unwrap(),
        ]]);

        // One key (1/2 < 1) -> not satisfied
        assert!(!t.is_satisfied(&[0], 3));
        // Two keys (1/2 + 1/2 = 1) -> satisfied
        assert!(t.is_satisfied(&[0, 1], 3));
        // Three keys (3/2 >= 1) -> satisfied
        assert!(t.is_satisfied(&[0, 1, 2], 3));
    }

    #[test]
    fn test_weighted_multi_clause() {
        // Two clauses:
        // Clause 0: keys 0,1 with weight 1/2 each
        // Clause 1: keys 2,3 with weight 1/1 each
        let t = Threshold::Weighted(vec![
            vec![Weight::new(1, 2).unwrap(), Weight::new(1, 2).unwrap()],
            vec![Weight::new(1, 1).unwrap(), Weight::new(1, 1).unwrap()],
        ]);

        // Need both clauses satisfied
        // indices 0,1 satisfy clause 0, but clause 1 needs key 2 or 3
        assert!(!t.is_satisfied(&[0, 1], 4));
        // indices 0,1,2 satisfy both
        assert!(t.is_satisfied(&[0, 1, 2], 4));
        // indices 2 only satisfies clause 1 (since key 2 has weight 1/1 >= 1), not clause 0
        assert!(!t.is_satisfied(&[2], 4));
    }

    #[test]
    fn test_threshold_value_serde_simple() {
        let tv = ThresholdValue(Threshold::Simple(2));
        let json = serde_json::to_string(&tv).unwrap();
        assert_eq!(json, "\"2\"");
        let parsed: ThresholdValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tv);
    }

    #[test]
    fn test_threshold_value_serde_weighted() {
        let tv = ThresholdValue(Threshold::Weighted(vec![vec![
            Weight::new(1, 2).unwrap(),
            Weight::new(1, 2).unwrap(),
        ]]));
        let json = serde_json::to_string(&tv).unwrap();
        assert_eq!(json, r#"[["1/2","1/2"]]"#);
        let parsed: ThresholdValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tv);
    }

    #[test]
    fn test_weight_from_str_fraction() {
        let w = Weight::parse("3/4").unwrap();
        assert_eq!(w.num, 3);
        assert_eq!(w.den, 4);
    }

    #[test]
    fn test_weight_from_str_whole() {
        let w = Weight::parse("1").unwrap();
        assert_eq!(w.num, 1);
        assert_eq!(w.den, 1);
    }

    #[test]
    fn test_weight_zero_denominator() {
        assert!(Weight::new(1, 0).is_err());
    }

    #[test]
    fn test_to_json_value_simple() {
        let t = Threshold::Simple(1);
        let v = t.to_json_value();
        assert_eq!(v, serde_json::json!("1"));
    }

    #[test]
    fn test_to_json_value_weighted() {
        let t = Threshold::Weighted(vec![vec![
            Weight::new(1, 2).unwrap(),
            Weight::new(1, 3).unwrap(),
        ]]);
        let v = t.to_json_value();
        assert_eq!(v, serde_json::json!([["1/2", "1/3"]]));
    }
}
