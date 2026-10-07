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
        rig.advance(0.002);
        let transmit = rig.session.poll_transmit(rig.now, &mut rig.rng).expect("first packet");
        rig.server.decode(&transmit.data);
        rig
    }

    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.server_time += seconds;
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
}

fn count_lost(events: &[SessionEvent]) -> usize {
    events.iter().filter(|event| matches!(event, SessionEvent::UpdatesLost)).count()
}

#[test]
fn replaying_one_evicted_update_packet_cannot_storm_updates_lost() {
    let mut rig = Rig::new();
    let recorded = rig.server.encode(vec![Outgoing::Content(update(0x0202_0202, &[0; 4]))]);
    rig.feed(&recorded).unwrap();
    let delivered = rig.session.drain_events();
    assert_eq!(delivered.iter().filter(|event| matches!(event, SessionEvent::Update { .. })).count(), 1);
    rig.push_window_past(2100);
    rig.advance(1.0);
    let mut lost = 0;
    for _ in 0..50 {
        rig.feed(&recorded).unwrap();
        lost += count_lost(&rig.session.drain_events());
    }
    assert!(lost <= 1, "one recorded packet replayed 50 times asked the host for {lost} difference fetches");
}

#[test]
fn a_loss_newer_than_the_last_fetch_is_still_reported() {
    let mut rig = Rig::new();
    let first = rig.server.encode(vec![Outgoing::Content(update(0x0202_0202, &[0; 4]))]);
    rig.feed(&first).unwrap();
    rig.push_window_past(2100);
    rig.feed(&first).unwrap();
    assert_eq!(count_lost(&rig.session.drain_events()), 1);

    rig.advance(5.0);
    let late_id = rig.server.next_msg_id(false);
    let late = rig.server.seal(late_id, 1, &update(0x0303_0303, &[0; 4]));
    rig.push_window_past(2100);
    rig.feed(&late).unwrap();
    assert_eq!(count_lost(&rig.session.drain_events()), 1, "a message sent after the last fetch was asked for");
}

#[test]
fn a_local_session_reset_forgets_the_covered_floor() {
    let mut rig = Rig::new();
    let first = rig.server.encode(vec![Outgoing::Content(update(0x0202_0202, &[0; 4]))]);
    rig.feed(&first).unwrap();
    rig.push_window_past(2100);
    rig.feed(&first).unwrap();
    assert_eq!(count_lost(&rig.session.drain_events()), 1);
    rig.session.reset(&mut rig.rng);
    assert_eq!(rig.session.updates_lost_covered, 0);
}
