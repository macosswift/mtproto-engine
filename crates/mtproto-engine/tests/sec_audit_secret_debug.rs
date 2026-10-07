//! Events carry a fresh auth key to the host. A host or test that logs events with `{:?}` must not print
//! the key, and a Rust host that drops the event must not leave the key behind in freed memory.

use mtproto_engine::EngineEvent;

#[test]
fn a_created_key_is_never_printed_by_debug() {
    let event = EngineEvent::AuthKeyCreated {
        key: vec![0xab; 256].into(),
        salt: 7,
        time_difference: 1.5,
        expires_at: Some(86_400),
        dc_id: 2,
    };
    let printed = format!("{event:?} {event:#?}");
    assert!(!printed.contains("171"), "the key bytes are printed: {printed}");
    assert!(!printed.to_lowercase().contains("abab"), "the key bytes are printed: {printed}");
    assert!(printed.contains("256"), "the length is still shown: {printed}");
    let copy = event.clone();
    assert_eq!(copy, event);
}
