use super::*;
use crate::crypto::XorShiftRandom;
use crate::test_support::server_peer::*;

const START: f64 = 1_727_000_000.0;

struct Rig {
    session: Session,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(11)))
}

impl Rig {
    fn new() -> Self {
        let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
        let mut rng = XorShiftRandom::new(9);
        let now = Now { mono: 100.0, unix: START };
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let mut server = ServerPeer::new(key(), START);
        server.salt = 101;
        let mut rig = Self { session, server, rng, now };
        rig.flush();
        rig
    }

    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.server_time += seconds;
    }

    fn flush(&mut self) -> Option<DecodedPacket> {
        self.advance(0.002);
        let transmit = self.session.poll_transmit(self.now, &mut self.rng)?;
        Some(self.server.decode(&transmit.data))
    }

    fn feed(&mut self, packet: &[u8]) -> Result<(), SessionError> {
        self.session.handle_packet(packet, self.now, &mut self.rng)
    }

    /// Fresh server messages until the duplicate window has evicted everything before them, as a
    /// busy session gets within the 300 s time window.
    fn push_window_past(&mut self, packets: usize) {
        for _ in 0..packets {
            let packet = self.server.encode(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]);
            self.feed(&packet).unwrap();
        }
        self.session.drain_events();
    }

    fn recorded_pong(&mut self) -> Vec<u8> {
        let packet = self.flush().expect("ping");
        let ping = packet
            .messages
            .iter()
            .find(|message| message.constructor() == ids::PING_DELAY_DISCONNECT)
            .expect("ping")
            .clone();
        let recorded = self.server.encode(vec![Outgoing::Service(pong(ping.msg_id, ping_id_of(&ping).unwrap()))]);
        self.feed(&recorded).unwrap();
        recorded
    }
}

#[test]
fn a_replayed_pong_does_not_refresh_ping_liveness() {
    let mut rig = Rig::new();
    rig.advance(70.0);
    let recorded = rig.recorded_pong();
    rig.push_window_past(2100);
    rig.advance(30.0);
    let before = rig.session.last_pong_at;
    rig.feed(&recorded).unwrap();
    assert_eq!(rig.session.last_pong_at, before, "an old pong replayed from the wire is no sign of life");
}

#[test]
fn a_replayed_pong_cannot_declare_unknown_queries_stuck() {
    let mut rig = Rig::new();
    rig.session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), rig.now);
    rig.flush().expect("query");
    rig.advance(240.0);
    let recorded = rig.recorded_pong();
    rig.advance(1.0);
    rig.session.connection_closed();
    rig.session.connection_opened(rig.now);
    assert!(rig.session.has_unknown_queries());
    rig.push_window_past(2100);
    rig.advance(61.0);
    assert_eq!(rig.feed(&recorded), Ok(()), "an old pong replayed from the wire proves nothing about this connection");
}

#[test]
fn a_fresh_pong_still_declares_unknown_queries_stuck() {
    let mut rig = Rig::new();
    rig.session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), rig.now);
    rig.flush().expect("query");
    rig.advance(241.0);
    rig.session.connection_closed();
    rig.session.connection_opened(rig.now);
    assert!(rig.session.has_unknown_queries());
    rig.advance(61.0);
    let packet = rig.flush().expect("ping");
    let ping = packet
        .messages
        .iter()
        .find(|message| message.constructor() == ids::PING_DELAY_DISCONNECT)
        .expect("ping")
        .clone();
    let fresh = rig.server.encode(vec![Outgoing::Service(pong(ping.msg_id, ping_id_of(&ping).unwrap()))]);
    assert_eq!(rig.feed(&fresh), Err(SessionError::UnknownQueriesStuck));
}

#[test]
fn replaying_an_evicted_large_answer_does_not_count_as_dropped_answers() {
    let mut rig = Rig::new();
    rig.session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), rig.now);
    let packet = rig.flush().expect("query");
    let query = packet.messages.iter().find(|message| message.constructor() == 0x1122_3344).expect("query").msg_id;
    let recorded = rig.server.encode(vec![Outgoing::Content(rpc_result(query, &vec![7u8; 64 * 1024]))]);
    rig.feed(&recorded).unwrap();
    assert!(rig.session.drain_events().iter().any(|event| matches!(event, SessionEvent::Result { .. })));
    rig.push_window_past(2100);
    rig.advance(1.0);
    for _ in 0..200 {
        rig.feed(&recorded).unwrap();
    }
    let events = rig.session.drain_events();
    assert!(
        !events.iter().any(|event| matches!(event, SessionEvent::DroppedAnswerTooLarge { .. })),
        "an old answer replayed from the wire made the session ask for a connection reset"
    );
}
