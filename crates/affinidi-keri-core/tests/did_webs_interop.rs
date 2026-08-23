//! Conformance test against a real `did:webs` `keri.cesr` artifact.
//!
//! Every other test in this workspace round-trips bytes this library produced
//! itself, which cannot catch a counter code we and only we agree on. This one
//! reads a stream produced by keripy, so it fails if our reading of CESR
//! diverges from the ecosystem's.
//!
//! See `tests/fixtures/ATTRIBUTION.md` for provenance.

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, Attachment};
use affinidi_keri_crypto::Verfer;

const ARTIFACT: &[u8] = include_bytes!("fixtures/did-webs-ENro7uf0.keri.cesr");
const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

#[test]
fn parses_a_real_did_webs_stream() {
    let messages = parser::parse_all(ARTIFACT).expect("real keri.cesr must parse");

    // icp, ixn, ixn (the KEL), vcp, iss (the credential registry TEL), then
    // the designated-aliases ACDC itself, which carries no `t` field.
    let ilks: Vec<String> = messages
        .iter()
        .map(|m| m.serder.ilk().unwrap_or_else(|_| "<acdc>".to_string()))
        .collect();
    assert_eq!(
        ilks,
        ["icp", "ixn", "ixn", "vcp", "iss", "<acdc>"],
        "message sequence",
    );

    // Nothing in a real artifact may land in the uninterpreted bucket: a group
    // we cannot read is a group whose signatures we are not checking.
    for (i, msg) in messages.iter().enumerate() {
        assert!(
            !msg.has_uninterpreted_attachments(),
            "message {i} ({}) has an attachment group we could not interpret: {:?}",
            ilks[i],
            msg.attachments,
        );
    }
}

#[test]
fn reads_the_designated_aliases_attestation() {
    let messages = parser::parse_all(ARTIFACT).expect("parse");

    // The last message is the designated-aliases ACDC. `did:webs` builds the
    // DID document's `alsoKnownAs` from it, so being able to read it — and the
    // transferable indexed signature group that authenticates it — is what
    // makes that field verifiable rather than merely copied.
    let acdc = messages.last().expect("stream is not empty");
    assert_eq!(
        acdc.serder.sad()["i"].as_str(),
        Some(AID),
        "the attestation is issued by the AID being resolved",
    );

    let groups = acdc.trans_idx_sig_groups();
    assert_eq!(groups.len(), 1, "one signing group, got {groups:?}");
    assert_eq!(groups[0].prefix, AID, "signed by the issuing AID");
    assert_eq!(groups[0].sigs.len(), 1, "one indexed signature");

    let aliases = acdc.serder.sad()["a"]["ids"]
        .as_array()
        .expect("attestation carries an ids list");
    assert!(
        aliases.iter().any(|a| a
            .as_str()
            .is_some_and(|s| s.starts_with("did:webs:") && s.ends_with(AID))),
        "designated aliases should include a did:webs form, got {aliases:?}",
    );
}

#[test]
fn reads_controller_signatures_not_an_opaque_blob() {
    let messages = parser::parse_all(ARTIFACT).expect("parse");

    // The KEL events are wrapped in a `-V` quadlet group holding a `-A`
    // controller signature group. Under the 2.x table `-A` is the wrapper and
    // `-B` the signatures, so reading this stream with the wrong table yields
    // zero controller signatures — which is exactly the failure this asserts
    // against.
    for (i, msg) in messages.iter().take(3).enumerate() {
        assert_eq!(
            msg.controller_sigs().len(),
            1,
            "KEL message {i} should carry exactly one controller signature",
        );
    }

    // The inception event also carries a first-seen replay couple.
    assert!(
        messages[0]
            .attachments
            .iter()
            .any(|a| matches!(a, Attachment::FirstSeenReplayCouples(c) if c.len() == 1)),
        "inception should carry one first seen replay couple, got {:?}",
        messages[0].attachments,
    );
}

#[test]
fn verifies_the_kel_end_to_end() {
    let messages = parser::parse_all(ARTIFACT).expect("parse");

    let icp = &messages[0];
    assert_eq!(icp.serder.prefix().expect("prefix"), AID);

    // Verification keys come from the inception event's own `k` field.
    let keys = icp.serder.sad()["k"]
        .as_array()
        .expect("inception carries a key list");
    let verfers: Vec<Verfer> = keys
        .iter()
        .map(|k| Verfer::from_qb64(k.as_str().expect("key is a string")).expect("valid verfer"))
        .collect();

    let mut kever = Kever::new(&icp.serder, icp.controller_sigs(), &verfers)
        .expect("inception must verify against its own signatures");
    assert_eq!(kever.sn(), 0);
    assert_eq!(kever.prefix(), AID);

    // Apply the two interaction events. Each is signature-checked against the
    // current key state, and its `p` field against the previous event digest.
    for (i, msg) in messages[1..3].iter().enumerate() {
        kever
            .update(&msg.serder, msg.controller_sigs())
            .unwrap_or_else(|e| panic!("event {} must verify: {e}", i + 1));
    }

    assert_eq!(kever.sn(), 2, "KEL should advance to sequence number 2");
    assert_eq!(
        kever.state().keys,
        vec!["DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr"],
        "current signing key after replaying the KEL",
    );
    assert_eq!(
        kever.state().next_keys,
        vec!["ELa775aLyane1vdiJEuexP8zrueiIoG995pZPGJiBzGX"],
        "pre-rotation commitment after replaying the KEL",
    );
}

#[test]
fn tampering_with_an_event_is_rejected() {
    // Flip a byte inside the inception event body. The SAID no longer matches,
    // so it must be refused before any field of it is trusted.
    let mut tampered = ARTIFACT.to_vec();
    let pos = tampered
        .windows(3)
        .position(|w| w == b"\"s\"")
        .expect("inception has an `s` field");
    tampered[pos + 5] = b'9';

    let messages = parser::parse_all(&tampered).expect("still parses as a stream");
    let icp = &messages[0];
    let keys = icp.serder.sad()["k"].as_array().expect("key list");
    let verfers: Vec<Verfer> = keys
        .iter()
        .map(|k| Verfer::from_qb64(k.as_str().expect("string")).expect("verfer"))
        .collect();

    assert!(
        Kever::new(&icp.serder, icp.controller_sigs(), &verfers).is_err(),
        "a tampered inception event must not produce a key state",
    );
}

#[test]
fn an_acdc_followed_by_a_key_event_still_parses() {
    // The version string is the first field of a message, but the scanner used
    // to search the whole remaining buffer for a protocol tag — and tried
    // `KERI` before `ACDC` regardless of position. So an ACDC parsed in a
    // stream containing any later KERI event picked up *that* event's declared
    // size and was sliced to the wrong length.
    //
    // The published artifact hides this because its ACDC happens to be last.
    // Streams of this shape are ordinary: a credential followed by further key
    // events, which is every vLEI chain.
    let mut sad = serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "rev",
        "d": "ERevocation000000000000000000000000000000000",
        "i": "EIEXitNCXQ_Y7HC6I7oiY7fPrRJyJzwvn_YIjvSHPzav",
        "s": "1",
        "ri": "EHfE7gojVcX5Ldu8zzBr9WZhVz2ZP7XoYDaVEtqcyDRP",
        "dt": "2024-01-01T00:00:00.000000+00:00",
    });
    let len = serde_json::to_vec(&sad).expect("serializes").len();
    sad["v"] = serde_json::json!(format!("KERI10JSON{len:06x}_"));

    let mut stream = ARTIFACT.to_vec();
    stream.extend_from_slice(&serde_json::to_vec(&sad).expect("serializes"));

    let messages = parser::parse_all(&stream).expect("an ACDC followed by a key event must parse");

    assert_eq!(
        messages.len(),
        7,
        "six original messages plus the appended one"
    );
    assert_eq!(
        messages[5].serder.size(),
        1522,
        "the ACDC keeps its own declared size, not the following event's",
    );
    assert_eq!(
        messages[6].serder.ilk().expect("ilk"),
        "rev",
        "the appended event parses as itself",
    );
}
