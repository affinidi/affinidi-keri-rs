//! `Hab` writes version 1 unless told otherwise, can write version 2, and
//! moves a log up a version but never down.

use affinidi_keri::ProtocolVersion;
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::hab::{Hab, HabState};
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{Attachment, parse_all};
use affinidi_keri_core::sad;
use affinidi_keri_crypto::Verfer;

const SALT: &[u8] = &[9u8; 16];

fn config(version: ProtocolVersion) -> InceptionConfig {
    InceptionConfig::builder()
        .salt(SALT.to_vec())
        .version(version)
        .build()
}

/// Feed composed events through `Kever`, the verifier every reader runs.
fn verify(log: &[Vec<u8>]) -> Kever {
    let mut kever: Option<Kever> = None;
    for event in log {
        let msg = parse_all(event).expect("parses").remove(0);
        let sigs = msg
            .attachments
            .into_iter()
            .find_map(|a| match a {
                Attachment::ControllerSigs(s) => Some(s),
                _ => None,
            })
            .expect("controller signatures");
        match kever.as_mut() {
            None => {
                let verfers: Vec<Verfer> = msg.serder.sad()["k"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| Verfer::from_qb64(k.as_str().unwrap()).unwrap())
                    .collect();
                kever = Some(Kever::new(&msg.serder, &sigs, &verfers).expect("icp"));
            }
            Some(k) => k.update(&msg.serder, &sigs).expect("event"),
        }
    }
    kever.expect("a log")
}

#[test]
fn hab_defaults_to_version_1() {
    let (hab, icp) = Hab::incept_event("a", &InceptionConfig::default()).unwrap();
    assert_eq!(hab.version(), ProtocolVersion::V1);
    assert!(icp.composed.starts_with(br#"{"v":"KERI10JSON"#));
}

#[test]
fn a_version_2_log_verifies() {
    let (mut hab, icp) = Hab::incept_event("a", &config(ProtocolVersion::V2)).unwrap();
    assert!(icp.composed.starts_with(b"-_AAACAA{\"v\":\"KERICAACAA"));
    let ixn = hab.interact_event(&[sad!({ "d": icp.said })]).unwrap();
    let rot = hab.rotate_event(&RotationConfig::default()).unwrap();
    let kever = verify(&[icp.composed, ixn.composed, rot.composed]);
    assert_eq!(kever.sn(), 2);
    assert_eq!(kever.state().protocol_major, 2);
}

#[test]
fn a_version_1_log_continues_in_version_2() {
    let (mut hab, icp) = Hab::incept_event("a", &config(ProtocolVersion::V1)).unwrap();
    let ixn = hab.interact_event(&[]).unwrap();
    hab.upgrade(ProtocolVersion::V2).unwrap();
    let rot = hab.rotate_event(&RotationConfig::default()).unwrap();
    assert!(rot.composed.starts_with(b"-_AAACAA"));
    let kever = verify(&[icp.composed, ixn.composed, rot.composed]);
    assert_eq!(kever.sn(), 2);
    assert_eq!(kever.state().protocol_major, 2);
}

#[test]
fn a_log_never_goes_down_a_version() {
    let (mut hab, _) = Hab::incept_event("a", &config(ProtocolVersion::V2)).unwrap();
    assert!(hab.upgrade(ProtocolVersion::V1).is_err());
    assert_eq!(hab.version(), ProtocolVersion::V2);
}

#[test]
fn a_state_persisted_before_versions_existed_is_version_1() {
    let (hab, _) = Hab::incept_event("a", &config(ProtocolVersion::V1)).unwrap();
    let mut json = serde_json::to_value(hab.state()).unwrap();
    json.as_object_mut().unwrap().remove("version");
    let state: HabState = serde_json::from_value(json).unwrap();
    assert_eq!(state.version, ProtocolVersion::V1);

    let (hab2, _) = Hab::incept_event("b", &config(ProtocolVersion::V2)).unwrap();
    let round: HabState =
        serde_json::from_value(serde_json::to_value(hab2.state()).unwrap()).unwrap();
    assert_eq!(round.version, ProtocolVersion::V2);
}
