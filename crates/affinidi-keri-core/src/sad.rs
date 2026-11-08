//! Order-preserving JSON for KERI messages.
//!
//! A KERI or ACDC message's field order is part of the message: every SAID and
//! every signature covers the exact bytes, and keripy refuses an event whose
//! fields are out of order. `serde_json::Value` cannot be relied on to keep
//! that order. Its `Map` is a `BTreeMap` unless some crate in the build turns
//! on serde_json's `preserve_order` feature, and cargo unifies features across
//! the whole build — so a library that needs order would have to change how
//! `serde_json` behaves for every crate its consumer compiles.
//!
//! [`SadValue`] keeps order itself, whatever features `serde_json` was built
//! with: its objects are [`IndexMap`]s, parsing keeps the order the bytes had,
//! and serializing writes members in that order. Build messages with the
//! [`sad!`](crate::sad!) macro, which takes the same syntax as `json!`.
//!
//! The read API mirrors `serde_json::Value` (`get`, `as_str`, `as_array`, …)
//! so reading a field looks the same. Convert to a `serde_json::Value` with
//! [`SadValue::to_json_value`] only to hand data to code that wants one — the
//! result's member order is whatever `serde_json` gives it.

use std::fmt;

use indexmap::IndexMap;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The members of a [`SadValue::Object`], in order.
pub type SadMap = IndexMap<String, SadValue>;

/// A JSON value whose objects keep their member order.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SadValue {
    /// `null`.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<SadValue>),
    /// An object, members in order.
    Object(SadMap),
}

static NULL: SadValue = SadValue::Null;

impl SadValue {
    /// An empty object.
    pub fn object() -> Self {
        Self::Object(SadMap::new())
    }

    /// The value of member `key`, if this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&SadValue> {
        self.as_object().and_then(|o| o.get(key))
    }

    /// The value of member `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut SadValue> {
        self.as_object_mut().and_then(|o| o.get_mut(key))
    }

    /// Set member `key`. An existing member keeps its position; a new one is
    /// appended. Returns `None` if this is not an object.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<SadValue>) -> Option<()> {
        self.as_object_mut()
            .map(|o| o.insert(key.into(), value.into()))
            .map(|_| ())
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number as a `u64`, if it is one.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    /// The number as an `i64`, if it is one.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    /// The number as an `f64`, if it is one.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&Vec<SadValue>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The elements, mutably.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<SadValue>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The members, if this is an object.
    pub fn as_object(&self) -> Option<&SadMap> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The members, mutably.
    pub fn as_object_mut(&mut self) -> Option<&mut SadMap> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Whether this is a string.
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Whether this is an array.
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Whether this is an object.
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// Whether this is a number.
    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    /// Serialize any value, keeping the order it serializes its fields in: a
    /// derived struct's field order, and the iteration order of any map.
    ///
    /// # Errors
    /// Returns an error if `value` cannot be serialized as JSON.
    pub fn from_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(value)?;
        serde_json::from_slice(&bytes)
    }

    /// Read this value as a `T`.
    ///
    /// # Errors
    /// Returns an error if it does not have `T`'s shape.
    pub fn deserialize_into<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        serde_json::from_slice(&bytes)
    }

    /// This value as a `serde_json::Value`, for code that wants one. Member
    /// order in the result is whatever `serde_json` was built to keep.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::Number(n) => serde_json::Value::Number(n.clone()),
            Self::String(s) => serde_json::Value::String(s.clone()),
            Self::Array(a) => serde_json::Value::Array(a.iter().map(Self::to_json_value).collect()),
            Self::Object(o) => serde_json::Value::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), v.to_json_value()))
                    .collect(),
            ),
        }
    }

    /// A `serde_json::Value`, in the member order it iterates in. That order
    /// is alphabetical unless some crate in the build turned on
    /// `preserve_order`, so never build a message from one: use
    /// [`sad!`](crate::sad!) or [`SadValue::from_serialize`] on a struct.
    pub fn from_json_value(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Bool(*b),
            serde_json::Value::Number(n) => Self::Number(n.clone()),
            serde_json::Value::String(s) => Self::String(s.clone()),
            serde_json::Value::Array(a) => {
                Self::Array(a.iter().map(Self::from_json_value).collect())
            }
            serde_json::Value::Object(o) => Self::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), Self::from_json_value(v)))
                    .collect(),
            ),
        }
    }
}

impl std::ops::Index<&str> for SadValue {
    type Output = SadValue;
    fn index(&self, key: &str) -> &SadValue {
        self.get(key).unwrap_or(&NULL)
    }
}

/// Like `serde_json::Value`: a missing member is appended as `null`, and
/// `null` becomes an empty object first.
///
/// # Panics
/// If the value is neither an object nor `null`.
impl std::ops::IndexMut<&str> for SadValue {
    fn index_mut(&mut self, key: &str) -> &mut SadValue {
        if self.is_null() {
            *self = Self::object();
        }
        match self {
            Self::Object(o) => o.entry(key.to_string()).or_insert(Self::Null),
            _ => panic!("cannot index a non-object SadValue with {key:?}"),
        }
    }
}

impl std::ops::Index<usize> for SadValue {
    type Output = SadValue;
    fn index(&self, i: usize) -> &SadValue {
        self.as_array().and_then(|a| a.get(i)).unwrap_or(&NULL)
    }
}

impl fmt::Display for SadValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl PartialEq<str> for SadValue {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}

impl PartialEq<&str> for SadValue {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

impl PartialEq<String> for SadValue {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == Some(other.as_str())
    }
}

impl From<&str> for SadValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<String> for SadValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&String> for SadValue {
    fn from(s: &String) -> Self {
        Self::String(s.clone())
    }
}

impl From<bool> for SadValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

macro_rules! from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for SadValue {
            fn from(n: $t) -> Self {
                Self::Number(n.into())
            }
        }
    )*};
}
from_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl<T: Into<SadValue>> From<Vec<T>> for SadValue {
    fn from(v: Vec<T>) -> Self {
        Self::Array(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<SadValue> + Clone> From<&[T]> for SadValue {
    fn from(v: &[T]) -> Self {
        Self::Array(v.iter().cloned().map(Into::into).collect())
    }
}

impl<T: Into<SadValue>> From<Option<T>> for SadValue {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

impl From<SadMap> for SadValue {
    fn from(o: SadMap) -> Self {
        Self::Object(o)
    }
}

impl FromIterator<SadValue> for SadValue {
    fn from_iter<I: IntoIterator<Item = SadValue>>(iter: I) -> Self {
        Self::Array(iter.into_iter().collect())
    }
}

/// A value the [`sad!`](crate::sad!) macro can interpolate.
///
/// Deliberately not implemented for `serde_json::Value`, whose member order
/// depends on how `serde_json` was built: convert one explicitly with
/// [`SadValue::from_json_value`] where order cannot matter.
pub trait ToSad {
    /// This value as a [`SadValue`].
    fn to_sad(&self) -> SadValue;
}

impl ToSad for SadValue {
    fn to_sad(&self) -> SadValue {
        self.clone()
    }
}

impl ToSad for SadMap {
    fn to_sad(&self) -> SadValue {
        SadValue::Object(self.clone())
    }
}

impl ToSad for str {
    fn to_sad(&self) -> SadValue {
        SadValue::String(self.to_string())
    }
}

impl ToSad for String {
    fn to_sad(&self) -> SadValue {
        SadValue::String(self.clone())
    }
}

impl ToSad for bool {
    fn to_sad(&self) -> SadValue {
        SadValue::Bool(*self)
    }
}

macro_rules! to_sad_int {
    ($($t:ty),*) => {$(
        impl ToSad for $t {
            fn to_sad(&self) -> SadValue {
                SadValue::Number((*self).into())
            }
        }
    )*};
}
to_sad_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl<T: ToSad> ToSad for [T] {
    fn to_sad(&self) -> SadValue {
        SadValue::Array(self.iter().map(ToSad::to_sad).collect())
    }
}

impl<T: ToSad> ToSad for Vec<T> {
    fn to_sad(&self) -> SadValue {
        self.as_slice().to_sad()
    }
}

impl<T: ToSad> ToSad for Option<T> {
    fn to_sad(&self) -> SadValue {
        self.as_ref().map_or(SadValue::Null, ToSad::to_sad)
    }
}

impl<T: ToSad + ?Sized> ToSad for &T {
    fn to_sad(&self) -> SadValue {
        (**self).to_sad()
    }
}

impl Serialize for SadValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Number(n) => n.serialize(serializer),
            Self::String(s) => serializer.serialize_str(s),
            Self::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Self::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for SadValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SadVisitor)
    }
}

struct SadVisitor;

impl<'de> Visitor<'de> for SadVisitor {
    type Value = SadValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<SadValue, E> {
        Ok(SadValue::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<SadValue, E> {
        Ok(SadValue::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<SadValue, E> {
        Ok(SadValue::Number(v.into()))
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<SadValue, E> {
        i64::try_from(v)
            .map(|v| SadValue::Number(v.into()))
            .or_else(|_| u64::try_from(v).map(|v| SadValue::Number(v.into())))
            .map_err(|_| E::custom("integer out of range"))
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<SadValue, E> {
        u64::try_from(v)
            .map(|v| SadValue::Number(v.into()))
            .map_err(|_| E::custom("integer out of range"))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<SadValue, E> {
        serde_json::Number::from_f64(v)
            .map(SadValue::Number)
            .ok_or_else(|| E::custom("a JSON number cannot be NaN or infinite"))
    }

    fn visit_str<E>(self, v: &str) -> Result<SadValue, E> {
        Ok(SadValue::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<SadValue, E> {
        Ok(SadValue::String(v))
    }

    fn visit_unit<E>(self) -> Result<SadValue, E> {
        Ok(SadValue::Null)
    }

    fn visit_none<E>(self) -> Result<SadValue, E> {
        Ok(SadValue::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<SadValue, D::Error> {
        Deserialize::deserialize(d)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SadValue, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(SadValue::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SadValue, A::Error> {
        let mut out = SadMap::with_capacity(map.size_hint().unwrap_or(0).min(4096));
        while let Some((k, v)) = map.next_entry::<String, SadValue>()? {
            if out.insert(k, v).is_some() {
                return Err(de::Error::custom("duplicate member in a KERI message"));
            }
        }
        Ok(SadValue::Object(out))
    }
}

/// Build a [`SadValue`] with `json!` syntax, keeping member order.
///
/// ```
/// use affinidi_keri_core::sad;
/// let v = sad!({"v": "KERI10JSON000000_", "t": "icp", "a": [{"i": "x", "s": "0"}]});
/// assert_eq!(v.to_string(), r#"{"v":"KERI10JSON000000_","t":"icp","a":[{"i":"x","s":"0"}]}"#);
/// ```
///
/// An interpolated expression is borrowed and converted with [`ToSad`], as
/// `json!` borrows it; pass a struct through [`SadValue::from_serialize`]
/// first.
#[macro_export]
macro_rules! sad {
    ($($tt:tt)+) => {
        $crate::sad_internal!($($tt)+)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! sad_internal {
    // ----- arrays: munch elements into [$($elems,)*] -----
    (@array [$($elems:expr,)*]) => {
        ::std::vec![$($elems,)*]
    };
    (@array [$($elems:expr),*]) => {
        ::std::vec![$($elems),*]
    };
    (@array [$($elems:expr,)*] null $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!(null)] $($rest)*)
    };
    (@array [$($elems:expr,)*] true $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!(true)] $($rest)*)
    };
    (@array [$($elems:expr,)*] false $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!(false)] $($rest)*)
    };
    (@array [$($elems:expr,)*] [$($array:tt)*] $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!([$($array)*])] $($rest)*)
    };
    (@array [$($elems:expr,)*] {$($map:tt)*} $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!({$($map)*})] $($rest)*)
    };
    (@array [$($elems:expr,)*] $next:expr, $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!($next),] $($rest)*)
    };
    (@array [$($elems:expr,)*] $last:expr) => {
        $crate::sad_internal!(@array [$($elems,)* $crate::sad_internal!($last)])
    };
    (@array [$($elems:expr),*] , $($rest:tt)*) => {
        $crate::sad_internal!(@array [$($elems,)*] $($rest)*)
    };

    // ----- objects -----
    (@object $object:ident () () ()) => {};
    // Insert the current entry followed by a trailing comma.
    (@object $object:ident [$($key:tt)+] ($value:expr) , $($rest:tt)*) => {
        let _ = $object.insert(($($key)+).into(), $value);
        $crate::sad_internal!(@object $object () ($($rest)*) ($($rest)*));
    };
    // Insert the last entry without a trailing comma.
    (@object $object:ident [$($key:tt)+] ($value:expr)) => {
        let _ = $object.insert(($($key)+).into(), $value);
    };
    (@object $object:ident ($($key:tt)+) (: null $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!(null)) $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: true $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!(true)) $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: false $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!(false)) $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: [$($array:tt)*] $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!([$($array)*])) $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: {$($map:tt)*} $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!({$($map)*})) $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: $value:expr , $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!($value)) , $($rest)*);
    };
    (@object $object:ident ($($key:tt)+) (: $value:expr) $copy:tt) => {
        $crate::sad_internal!(@object $object [$($key)+] ($crate::sad_internal!($value)));
    };
    // Munch a key: a parenthesised expression, or tokens up to the colon.
    (@object $object:ident () (($key:expr) : $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object ($key) (: $($rest)*) (: $($rest)*));
    };
    (@object $object:ident ($($key:tt)*) ($tt:tt $($rest:tt)*) $copy:tt) => {
        $crate::sad_internal!(@object $object ($($key)* $tt) ($($rest)*) ($($rest)*));
    };

    // ----- values -----
    (null) => { $crate::sad::SadValue::Null };
    (true) => { $crate::sad::SadValue::Bool(true) };
    (false) => { $crate::sad::SadValue::Bool(false) };
    ([]) => { $crate::sad::SadValue::Array(::std::vec![]) };
    ([ $($tt:tt)+ ]) => {
        $crate::sad::SadValue::Array($crate::sad_internal!(@array [] $($tt)+))
    };
    ({}) => { $crate::sad::SadValue::Object($crate::sad::SadMap::new()) };
    ({ $($tt:tt)+ }) => {
        $crate::sad::SadValue::Object({
            let mut object = $crate::sad::SadMap::new();
            $crate::sad_internal!(@object object () ($($tt)+) ($($tt)+));
            object
        })
    };
    ($other:expr) => {
        $crate::sad::ToSad::to_sad(&$other)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_macro_keeps_member_order() {
        let k = "key";
        let v = crate::sad!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "kt": "1",
            "k": [k, "b"],
            "a": [{"i": "x", "s": "0", "d": "y"}],
            "n": null,
            "f": false,
            "x": 3u64,
        });
        assert_eq!(
            v.to_string(),
            r#"{"v":"KERI10JSON000000_","t":"icp","d":"","kt":"1","k":["key","b"],"a":[{"i":"x","s":"0","d":"y"}],"n":null,"f":false,"x":3}"#
        );
    }

    #[test]
    fn parsing_keeps_member_order() {
        let raw = r#"{"z":1,"a":{"y":true,"b":[{"q":null,"c":"s"}]}}"#;
        let v: SadValue = serde_json::from_str(raw).unwrap();
        assert_eq!(v.to_string(), raw);
    }

    #[test]
    fn a_duplicate_member_is_refused() {
        assert!(serde_json::from_str::<SadValue>(r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn a_struct_keeps_its_field_order() {
        #[derive(Serialize)]
        struct S {
            zed: u8,
            alpha: &'static str,
        }
        let v = SadValue::from_serialize(&S { zed: 1, alpha: "a" }).unwrap();
        assert_eq!(v.to_string(), r#"{"zed":1,"alpha":"a"}"#);
    }

    #[test]
    fn cbor_round_trip_keeps_order() {
        let v = crate::sad!({"z": "1", "a": ["x"], "m": {"q": 2u64, "b": 1u64}});
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        let back: SadValue = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.to_string(), v.to_string());
    }
}
