use super::*;
use crate::crypto::XorShiftRandom;
use crate::test_support::server_peer::*;

const START: f64 = 1_727_000_000.0;

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(11)))
}

#[test]
fn a_rejected_container_does_not_hold_the_salt_request_for_a_minute() {
    let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
    let mut rng = XorShiftRandom::new(9);
    let mut now = Now { mono: 100.0, unix: START };
    let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let mut server = ServerPeer::new(key(), START + 3600.0);
    server.salt = 101;
    session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), now);
    now.mono += 0.002;
    now.unix += 0.002;
    let transmit = session.poll_transmit(now, &mut rng).expect("first packet");
    let packet = server.decode(&transmit.data);
    assert!(packet.find(ids::GET_FUTURE_SALTS).is_some(), "the first packet asks for future salts");
    assert!(packet.messages.len() > 1, "and goes in a container");
    let container = packet.header.msg_id;

    let notice = server.encode(vec![Outgoing::Service(bad_msg_notification(container, packet.header.seq_no, 16))]);
    session.handle_packet(&notice, now, &mut rng).unwrap();
    session.drain_events();

    let mut asked_at = None;
    for step in 0..100 {
        now.mono += 0.1;
        now.unix += 0.1;
        let _ = session.handle_timeout(now);
        if let Some(transmit) = session.poll_transmit(now, &mut rng)
            && server.decode(&transmit.data).find(ids::GET_FUTURE_SALTS).is_some()
        {
            asked_at = Some(step);
            break;
        }
    }
    assert!(asked_at.is_some(), "the salt the resync expired is asked for again at once, not after 60 s");
}
