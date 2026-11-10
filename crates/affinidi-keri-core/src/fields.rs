//! The top-level fields of each KERI message type, per protocol version.
//!
//! keripy refuses a KERI message whose top-level field list is not exactly
//! its version's list, in order (`serdering.py`, `SerderKERI._verify`:
//! "Invalid top level field list"). The lists are keripy's `Serder.Fields`
//! (`keri/core/serdering.py`, b70986f).
//!
//! What changes in version 2: `rot` and `drt` gain `c`; `qry`, `rpy`, `pro`
//! and `bar` gain `i`; `exn` gains `ri` and `x` and drops `rp` and `e`; `xip`
//! is new; the `vcp`/`vrt`/`iss`/`rev`/`bis`/`brv` registry events are gone
//! from the KERI protocol (version 2 registries are ACDC messages).
//!
//! Neither version's `drt` has a `di` field: the delegator is the one the
//! identifier was incepted under.

use crate::error::CoreError;
use crate::sad::SadValue;

const V1: &[(&str, &[&str])] = &[
    (
        "icp",
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
        ],
    ),
    (
        "rot",
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a",
        ],
    ),
    ("ixn", &["v", "t", "d", "i", "s", "p", "a"]),
    (
        "dip",
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di",
        ],
    ),
    (
        "drt",
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a",
        ],
    ),
    ("rct", &["v", "t", "d", "i", "s"]),
    ("qry", &["v", "t", "d", "dt", "r", "rr", "q"]),
    ("rpy", &["v", "t", "d", "dt", "r", "a"]),
    ("pro", &["v", "t", "d", "dt", "r", "rr", "q"]),
    ("bar", &["v", "t", "d", "dt", "r", "a"]),
    (
        "exn",
        &["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"],
    ),
    ("vcp", &["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]),
    ("vrt", &["v", "t", "d", "i", "p", "s", "bt", "br", "ba"]),
    ("iss", &["v", "t", "d", "i", "s", "ri", "dt"]),
    ("rev", &["v", "t", "d", "i", "s", "ri", "p", "dt"]),
    ("bis", &["v", "t", "d", "i", "ii", "s", "ra", "dt"]),
    ("brv", &["v", "t", "d", "i", "s", "p", "ra", "dt"]),
];

const V2: &[(&str, &[&str])] = &[
    (
        "icp",
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
        ],
    ),
    (
        "rot",
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a",
        ],
    ),
    ("ixn", &["v", "t", "d", "i", "s", "p", "a"]),
    (
        "dip",
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di",
        ],
    ),
    (
        "drt",
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a",
        ],
    ),
    ("rct", &["v", "t", "d", "i", "s"]),
    ("qry", &["v", "t", "d", "i", "dt", "r", "rr", "q"]),
    ("rpy", &["v", "t", "d", "i", "dt", "r", "a"]),
    ("pro", &["v", "t", "d", "i", "dt", "r", "rr", "q"]),
    ("bar", &["v", "t", "d", "i", "dt", "r", "a"]),
    ("xip", &["v", "t", "d", "u", "i", "ri", "dt", "r", "q", "a"]),
    (
        "exn",
        &["v", "t", "d", "i", "ri", "x", "p", "dt", "r", "q", "a"],
    ),
];

/// The top-level fields of a KERI message of type `ilk` in protocol major
/// version `major`, in order. `None` if keripy defines no such message.
pub fn keri_fields(major: u8, ilk: &str) -> Option<&'static [&'static str]> {
    let table = match major {
        1 => V1,
        2 => V2,
        _ => return None,
    };
    table.iter().find(|(t, _)| *t == ilk).map(|(_, f)| *f)
}

/// Check that a KERI message's top-level fields are exactly its version's
/// list for its type, in order, as keripy requires.
///
/// # Errors
/// Returns [`CoreError::Validation`] if they are not, or
/// [`CoreError::Unsupported`] if the version defines no such message type.
pub fn check_keri_fields(sad: &SadValue, major: u8, ilk: &str) -> Result<(), CoreError> {
    let expected = keri_fields(major, ilk).ok_or_else(|| {
        CoreError::Unsupported(format!("KERI {major}.x defines no '{ilk}' message"))
    })?;
    let obj = sad
        .as_object()
        .ok_or_else(|| CoreError::Validation("a KERI message is a field map".into()))?;
    let got: Vec<&str> = obj.keys().map(String::as_str).collect();
    if got != expected {
        return Err(CoreError::Validation(format!(
            "a KERI {major}.x '{ilk}' has the fields {expected:?}, in that order; \
             this one has {got:?}"
        )));
    }
    Ok(())
}

/// The top-level fields of an ACDC protocol message: every field it may
/// carry, in order (`alls`), and which of them it may leave out (`opts`).
///
/// keripy's `Serder.Fields` for the ACDC protocol (`serdering.py`, b70986f).
/// `ilk` `None` is a bare ACDC, which carries no `t`. The attribute section
/// `a` and the aggregate section `A` are alternatives: a message carries at
/// most one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcdcFields {
    /// Every field the message may carry, in order.
    pub alls: &'static [&'static str],
    /// The fields it may leave out.
    pub opts: &'static [&'static str],
}

const ACDC: &[(u8, Option<&str>, AcdcFields)] = &[
    (
        1,
        None,
        AcdcFields {
            alls: &["v", "d", "u", "i", "ri", "s", "a", "A", "e", "r"],
            opts: &["u", "ri", "a", "A", "e", "r"],
        },
    ),
    (
        2,
        None,
        AcdcFields {
            alls: &["v", "d", "u", "i", "rd", "s", "a", "A", "e", "r"],
            opts: &["u", "rd", "a", "A", "e", "r"],
        },
    ),
    (
        2,
        Some("acm"),
        AcdcFields {
            alls: &["v", "t", "d", "u", "i", "rd", "s", "a", "A", "e", "r"],
            opts: &["t", "u", "rd", "a", "A", "e", "r"],
        },
    ),
    (
        2,
        Some("rip"),
        AcdcFields {
            alls: &["v", "t", "d", "u", "i", "n", "dt"],
            opts: &[],
        },
    ),
    (
        2,
        Some("bup"),
        AcdcFields {
            alls: &["v", "t", "d", "rd", "n", "p", "dt", "b"],
            opts: &[],
        },
    ),
];

/// The fields of an ACDC protocol message of type `ilk` (`None` for a bare
/// ACDC) in protocol major version `major`. `None` if this crate does not
/// model that message.
pub fn acdc_fields(major: u8, ilk: Option<&str>) -> Option<AcdcFields> {
    ACDC.iter()
        .find(|(m, i, _)| *m == major && *i == ilk)
        .map(|(_, _, f)| *f)
}

/// Check an ACDC protocol message's top-level fields: each is one of its
/// type's fields, in that type's order; every field that is not optional is
/// present; and it carries at most one of `a` and `A`.
///
/// # Errors
/// Returns [`CoreError::Validation`] if they are not, or
/// [`CoreError::Unsupported`] if this crate does not model the message type.
pub fn check_acdc_fields(sad: &SadValue, major: u8, ilk: Option<&str>) -> Result<(), CoreError> {
    let name = ilk.unwrap_or("bare ACDC");
    let fields = acdc_fields(major, ilk).ok_or_else(|| {
        CoreError::Unsupported(format!(
            "ACDC {major}.x '{name}' messages are not supported"
        ))
    })?;
    let obj = sad
        .as_object()
        .ok_or_else(|| CoreError::Validation("an ACDC message is a field map".into()))?;
    let got: Vec<&str> = obj.keys().map(String::as_str).collect();
    let mut cursor = fields.alls.iter();
    for label in &got {
        if !cursor.by_ref().any(|f| f == label) {
            return Err(CoreError::Validation(format!(
                "an ACDC {major}.x '{name}' has the fields {:?}, in that order; \
                 this one has {got:?}",
                fields.alls
            )));
        }
    }
    for required in fields.alls.iter().filter(|f| !fields.opts.contains(f)) {
        if !got.contains(required) {
            return Err(CoreError::Validation(format!(
                "an ACDC {major}.x '{name}' must carry '{required}'"
            )));
        }
    }
    if got.contains(&"a") && got.contains(&"A") {
        return Err(CoreError::Validation(format!(
            "an ACDC {major}.x '{name}' carries both an attribute and an aggregate section"
        )));
    }
    Ok(())
}

/// The protocol major version a message's `v` field names.
///
/// # Errors
/// Returns `CoreError` if the field is missing or is not a version string.
pub fn protocol_major(sad: &SadValue) -> Result<u8, CoreError> {
    let vs = sad
        .get("v")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::MissingField("v".into()))?;
    Ok(crate::version::Version::parse_str(vs)?.major)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// keripy's own definitions, copied verbatim from
    /// `keri/core/serdering.py` at b70986f (`Serder.Fields`, KERI protocol),
    /// so a change to either side shows up here.
    const KERIPY: &[(u8, &str, &str)] = &[
        (
            1,
            "icp",
            "v='', t='',d='', i='', s='0',
                        kt='0',k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[]",
        ),
        (
            1,
            "rot",
            "v='', t='',d='', i='', s='0',
                            p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], a=[]",
        ),
        (
            1,
            "ixn",
            "v='', t='',d='', i='', s='0',
                        p='', a=[]",
        ),
        (
            1,
            "dip",
            "v='', t='',d='', i='', s='0',
                        kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[], di=''",
        ),
        (
            1,
            "drt",
            "v='', t='',d='', i='', s='0',
                        p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], a=[]",
        ),
        (1, "rct", "v='', t='',d='', i='', s='0'"),
        (
            1,
            "qry",
            "v='', t='',d='', dt='', r='',
                        rr='',q={}",
        ),
        (
            1,
            "rpy",
            "v='', t='',d='', dt='', r='',
                        a=[]",
        ),
        (
            1,
            "pro",
            "v='', t='',d='', dt='', r='',
                        rr='',q={}",
        ),
        (
            1,
            "bar",
            "v='', t='',d='', dt='', r='',
                        a=[]",
        ),
        (
            1,
            "exn",
            "v='', t='', d='', i=\"\", rp=\"\",
                        p=\"\", dt='', r='',q={}, a=[], e={}",
        ),
        (
            1,
            "vcp",
            "v='', t='',d='', i='', ii='',
                        s='0', c=[], bt='0', b=[], n=''",
        ),
        (
            1,
            "vrt",
            "v='', t='',d='', i='', p='',
                        s='0', bt='0', br=[], ba=[]",
        ),
        (
            1,
            "iss",
            "v='', t='',d='', i='', s='0',
                        ri='', dt=''",
        ),
        (
            1,
            "rev",
            "v='', t='',d='', i='', s='0',
                        ri='', p='', dt=''",
        ),
        (
            1,
            "bis",
            "v='', t='',d='', i='', ii='',
                        s='0', ra={}, dt=''",
        ),
        (
            1,
            "brv",
            "v='', t='',d='', i='', s='0',
                         p='', ra={}, dt=''",
        ),
        (
            2,
            "icp",
            "v='', t='',d='', i='', s='0',
                         kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                         a=[]",
        ),
        (
            2,
            "rot",
            "v='', t='',d='', i='', s='0',
                        p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], c=[], a=[]",
        ),
        (
            2,
            "ixn",
            "v='', t='',d='', i='', s='0',
                        p='', a=[]",
        ),
        (
            2,
            "dip",
            "v='', t='',d='', i='', s='0',
                        kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[], di=''",
        ),
        (
            2,
            "drt",
            "v='', t='',d='', i='', s='0',
                         p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], c=[], a=[]",
        ),
        (2, "rct", "v='', t='',d='', i='', s='0'"),
        (
            2,
            "qry",
            "v='', t='',d='', i='', dt='',
                        r='', rr='', q={}",
        ),
        (
            2,
            "rpy",
            "v='', t='',d='', i='', dt='',
                        r='',a={}",
        ),
        (
            2,
            "pro",
            "v='', t='',d='', i='', dt='',
                        r='', rr='', q={}",
        ),
        (
            2,
            "bar",
            "v='', t='',d='', i='', dt='',
                        r='',a={}",
        ),
        (
            2,
            "xip",
            "v='', t='', d='', u='', i=\"\", ri=\"\",
                                             dt='', r='', q={}, a={}",
        ),
        (
            2,
            "exn",
            "v='', t='', d='', i=\"\", ri=\"\",
                        x=\"\", p=\"\", dt='', r='', q={}, a={}",
        ),
    ];

    /// The labels of a keripy `dict(...)` argument list.
    fn labels(dict_args: &str) -> Vec<String> {
        dict_args
            .split(',')
            .filter_map(|part| part.split_once('='))
            .map(|(k, _)| k.trim().to_string())
            .collect()
    }

    #[test]
    fn field_lists_are_keripys() {
        for (major, ilk, keripy) in KERIPY {
            let ours: Vec<String> = keri_fields(*major, ilk)
                .unwrap_or_else(|| panic!("no {major}.x {ilk}"))
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert_eq!(ours, labels(keripy), "{major}.x {ilk}");
        }
        for (major, table) in [(1u8, V1), (2, V2)] {
            assert_eq!(
                table.len(),
                KERIPY.iter().filter(|(m, ..)| *m == major).count(),
                "{major}.x has a message type keripy does not, or lacks one it has"
            );
        }
    }

    /// keripy's ACDC protocol definitions, copied verbatim from
    /// `keri/core/serdering.py` at b70986f (`Serder.Fields`, ACDC protocol).
    const KERIPY_ACDC: &[(u8, Option<&str>, &str, &str)] = &[
        (
            1,
            None,
            "v='', d='', u='', i='',
                        ri='', s='', a='', A='', e='', r=''",
            "u='', ri='', a='', A='', e='', r=''",
        ),
        (
            2,
            None,
            "v='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''",
            "u='', rd='', a='', A='', e='', r=''",
        ),
        (
            2,
            Some("acm"),
            "v='', t='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''",
            "t='', u='', rd='', a='', A='', e='', r=''",
        ),
        (
            2,
            Some("rip"),
            "v='', t='', d='', u='', i='',
                                              n='', dt=''",
            "",
        ),
        (
            2,
            Some("bup"),
            "v='', t='', d='', rd='', n='',
                                              p='', dt='', b=''",
            "",
        ),
    ];

    #[test]
    fn acdc_field_lists_are_keripys() {
        for (major, ilk, alls, opts) in KERIPY_ACDC {
            let ours = acdc_fields(*major, *ilk).unwrap_or_else(|| panic!("no {major}.x {ilk:?}"));
            let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            assert_eq!(strs(ours.alls), labels(alls), "{major}.x {ilk:?} alls");
            assert_eq!(strs(ours.opts), labels(opts), "{major}.x {ilk:?} opts");
        }
        assert_eq!(ACDC.len(), KERIPY_ACDC.len());
    }

    #[test]
    fn acdc_fields_follow_order_presence_and_the_a_or_aggregate_rule() {
        let bup = crate::sad!({"v": "", "t": "bup", "d": "", "rd": "", "n": "1", "p": "", "dt": "", "b": ""});
        check_acdc_fields(&bup, 2, Some("bup")).unwrap();
        let no_b =
            crate::sad!({"v": "", "t": "bup", "d": "", "rd": "", "n": "1", "p": "", "dt": ""});
        assert!(check_acdc_fields(&no_b, 2, Some("bup")).is_err());
        let acm = crate::sad!({"v": "", "t": "acm", "d": "", "i": "", "rd": "", "s": "", "a": {}});
        check_acdc_fields(&acm, 2, Some("acm")).unwrap();
        let swapped =
            crate::sad!({"v": "", "t": "acm", "d": "", "rd": "", "i": "", "s": "", "a": {}});
        assert!(check_acdc_fields(&swapped, 2, Some("acm")).is_err());
        let both = crate::sad!({"v": "", "t": "acm", "d": "", "i": "", "s": "", "a": {}, "A": []});
        assert!(check_acdc_fields(&both, 2, Some("acm")).is_err());
        let v1 = crate::sad!({"v": "", "d": "", "i": "", "ri": "", "s": "", "a": {}});
        check_acdc_fields(&v1, 1, None).unwrap();
        assert!(
            check_acdc_fields(&v1, 2, None).is_err(),
            "ri is a 1.x field"
        );
    }

    #[test]
    fn version_2_drops_the_kel_registry_events() {
        for ilk in ["vcp", "vrt", "iss", "rev", "bis", "brv"] {
            assert!(keri_fields(1, ilk).is_some());
            assert!(keri_fields(2, ilk).is_none(), "{ilk}");
        }
    }

    #[test]
    fn a_field_out_of_order_or_extra_is_refused() {
        let ok = crate::sad!({"v": "KERI10JSON000000_", "t": "ixn", "d": "", "i": "", "s": "1", "p": "", "a": []});
        check_keri_fields(&ok, 1, "ixn").unwrap();
        let swapped = crate::sad!({"v": "KERI10JSON000000_", "t": "ixn", "d": "", "i": "", "p": "", "s": "1", "a": []});
        assert!(check_keri_fields(&swapped, 1, "ixn").is_err());
        let v1_rot_with_c = crate::sad!({
            "v": "", "t": "rot", "d": "", "i": "", "s": "1", "p": "", "kt": "1", "k": [],
            "nt": "1", "n": [], "bt": "0", "br": [], "ba": [], "c": [], "a": []
        });
        assert!(check_keri_fields(&v1_rot_with_c, 1, "rot").is_err());
        check_keri_fields(&v1_rot_with_c, 2, "rot").unwrap();
    }
}
