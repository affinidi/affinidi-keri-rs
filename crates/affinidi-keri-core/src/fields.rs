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
