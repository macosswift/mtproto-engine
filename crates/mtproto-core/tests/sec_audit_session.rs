use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::message::{MessageError, encode_plain_message};
use mtproto_core::session::{
    Now, QueryId, QueryOptions, ServerSalt, Session, SessionConfig, SessionError, SessionEvent,
};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_result, update};

const START: f64 = 1_727_000_000.0;

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(seed)))
}

struct Rig {
    session: Session,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
    first_transmit: Vec<u8>,
}

impl Rig {
    fn new() -> Self {
        let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
        let mut rng = XorShiftRandom::new(3);
        let now = Now { mono: 100.0, unix: START };
        let mut session = Session::new(SessionConfig::default(), key(7), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), now);
        let mut server = ServerPeer::new(key(7), START);
        server.salt = 101;
        let transmit = session.poll_transmit(now, &mut rng).expect("first packet");
        server.decode(&transmit.data);
        session.drain_events();
        Self { session, server, rng, now, first_transmit: transmit.data }
    }

    fn feed(&mut self, packet: &[u8]) -> Result<(), SessionError> {
        self.session.handle_packet(packet, self.now, &mut self.rng)
    }

    fn assert_untouched(&mut self, what: &str) {
        let events = self.session.drain_events();
        assert!(events.is_empty(), "{what}: {events:?}");
        assert_eq!(self.session.time_difference(), 0.0, "{what} moved the clock");
        assert!(self.session.has_unanswered_queries(), "{what} completed a query");
    }
}

#[test]
fn a_forged_plain_packet_is_refused_by_an_established_session() {
    let mut rig = Rig::new();
    let mut body = Vec::new();
    body.extend_from_slice(&0xf35c6d01u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 12]);
    let short = encode_plain_message(msg_id_now(), &body);
    assert!(matches!(rig.feed(&short), Err(SessionError::Decrypt(MessageError::TooShort(_)))));
    rig.assert_untouched("a short plain packet");
    body.extend_from_slice(&[0u8; 64]);
    let plain = encode_plain_message(msg_id_now(), &body);
    assert!(matches!(rig.feed(&plain), Err(SessionError::Decrypt(MessageError::AuthKeyMismatch { .. }))));
    rig.assert_untouched("a plain packet");
}

#[test]
fn the_client_packet_reflected_back_is_refused() {
    let mut rig = Rig::new();
    let reflected = rig.first_transmit.clone();
    assert!(matches!(rig.feed(&reflected), Err(SessionError::Decrypt(MessageError::MsgKeyMismatch))));
    rig.assert_untouched("a reflected packet");
}

#[test]
fn a_packet_under_another_key_or_session_changes_nothing() {
    let mut rig = Rig::new();
    let mut stranger = ServerPeer::new(key(9), START + 5000.0);
    stranger.session_id = rig.server.session_id;
    let foreign_key = stranger.encode(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]);
    assert!(matches!(rig.feed(&foreign_key), Err(SessionError::Decrypt(MessageError::AuthKeyMismatch { .. }))));
    rig.assert_untouched("a packet under another key");

    let mut other_session = ServerPeer::new(key(7), START + 5000.0);
    other_session.session_id = rig.server.session_id.wrapping_add(1);
    let foreign_session = other_session.encode(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]);
    assert_eq!(rig.feed(&foreign_session), Err(SessionError::ForeignSession));
    rig.assert_untouched("a packet of another session");
}

#[test]
fn truncated_or_extended_genuine_packets_never_complete_a_query() {
    let mut rig = Rig::new();
    let query = {
        let mut probe = ServerPeer::new(key(7), START);
        probe.decode(&rig.first_transmit).messages.iter().find(|m| m.constructor() == 0x1122_3344).unwrap().msg_id
    };
    let genuine = rig.server.encode(vec![Outgoing::Content(rpc_result(query, &[1, 2, 3, 4]))]);
    for cut in [1usize, 4, 15, 16, 32, 48] {
        let truncated = &genuine[..genuine.len() - cut];
        assert!(rig.feed(truncated).is_err(), "cut {cut}");
        rig.assert_untouched("a truncated packet");
    }
    let mut extended = genuine.clone();
    extended.extend_from_slice(&[0u8; 16]);
    assert!(rig.feed(&extended).is_err());
    rig.assert_untouched("an extended packet");
    rig.feed(&genuine).unwrap();
    assert!(rig.session.drain_events().iter().any(|event| matches!(event, SessionEvent::Result { .. })));
}

fn msg_id_now() -> i64 {
    mtproto_core::msg_id::msg_id_for_time(START) | 1
}
