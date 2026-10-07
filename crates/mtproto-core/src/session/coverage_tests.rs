//! Paths the rest of the suite left unexercised, found with coverage measurement and fuzzing: the
//! bounds that keep a hostile or chatty server from growing the session, and small state queries.
use super::*;
use crate::crypto::SequenceRandom;

fn query_ids(packet: &DecodedPacket) -> Vec<u32> {
    packet.messages.iter().filter_map(|message| query_tag(&message.body)).collect()
}

#[test]
fn a_server_session_notice_is_acted_on_once_per_unique_id_among_the_last_sixteen() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let resets = |h: &mut Harness| {
        h.events().into_iter().filter(|event| matches!(event, SessionEvent::ServerSessionReset { .. })).count()
    };
    h.deliver(vec![Outgoing::Service(new_session_created(first, 1000, 101))]).unwrap();
    assert_eq!(resets(&mut h), 1);
    h.deliver(vec![Outgoing::Service(new_session_created(first, 1000, 101))]).unwrap();
    assert_eq!(resets(&mut h), 0, "the same server session announced again changes nothing");
    for unique in 1001..1017 {
        h.deliver(vec![Outgoing::Service(new_session_created(first, unique, 101))]).unwrap();
    }
    assert_eq!(resets(&mut h), 16);
    h.deliver(vec![Outgoing::Service(new_session_created(first, 1016, 101))]).unwrap();
    assert_eq!(resets(&mut h), 0, "a recent one is still remembered");
    h.deliver(vec![Outgoing::Service(new_session_created(first, 1000, 101))]).unwrap();
    assert_eq!(resets(&mut h), 1, "only the last sixteen are kept, so the oldest counts again");
    assert!(h.session.recent_unique_ids.len() <= 16);
}

#[test]
fn http_tracks_at_most_the_newest_requests_for_loss() {
    let mut h = Harness::new();
    h.session.set_http(true);
    assert!(h.session.is_http());
    let mut first = None;
    let mut last = None;
    for tag in 0..(MAX_TRACKED_HTTP_PACKETS as u32 + 8) {
        h.session.send(QueryId(u64::from(tag) + 1), query_body(tag), QueryOptions::default(), h.now);
        h.advance(0.002);
        let transmit = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true).unwrap();
        first.get_or_insert(transmit.packet_seq);
        last = Some(transmit.packet_seq);
    }
    assert!(h.session.http_packets.len() <= MAX_TRACKED_HTTP_PACKETS);
    h.session.http_packet_lost(first.unwrap(), h.now);
    h.advance(0.002);
    assert!(
        h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true).is_none(),
        "a request no longer tracked resends nothing (its query waits for a state request)"
    );
    h.session.http_packet_lost(last.unwrap(), h.now);
    h.advance(0.002);
    let again = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true).unwrap();
    assert_eq!(query_ids(&h.server.decode(&again.data)), vec![MAX_TRACKED_HTTP_PACKETS as u32 + 7]);
}

#[test]
fn quick_ack_tokens_are_remembered_for_the_newest_packets_only() {
    let mut h = Harness::new();
    let mut tokens = Vec::new();
    for tag in 0..(MAX_RECENT_QUICK_ACKS as u32 + 4) {
        let options = QueryOptions { quick_ack: true, invoke_after: None };
        h.session.send(QueryId(u64::from(tag) + 1), query_body(tag), options, h.now);
        h.advance(0.002);
        let transmit = h.session.poll_transmit(h.now, &mut h.rng).unwrap();
        tokens.push(transmit.quick_ack_token.expect("a quick-ack query asks for one"));
    }
    assert!(h.session.quick_acks.len() <= MAX_RECENT_QUICK_ACKS);
    assert!(!h.session.handle_quick_ack(tokens[0], h.now), "the oldest token was forgotten");
    assert!(h.session.handle_quick_ack(*tokens.last().unwrap(), h.now));
    assert!(
        h.events().contains(&SessionEvent::Acknowledged { id: QueryId(MAX_RECENT_QUICK_ACKS as u64 + 4) }),
        "the newest query is acknowledged by its token"
    );
    assert!(!h.session.handle_quick_ack(*tokens.last().unwrap(), h.now), "a token counts once");
}

#[test]
fn without_ping_delay_disconnect_a_plain_ping_goes_out() {
    let config = SessionConfig { use_ping_delay_disconnect: false, ..SessionConfig::default() };
    let mut rng = XorShiftRandom::new(5);
    let now = Now { mono: 100.0, unix: START };
    let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
    let mut session = Session::new(config, key(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let transmit = session.poll_transmit(now, &mut rng).expect("a liveness ping");
    let mut server = ServerPeer::new(key(), START);
    let packet = server.decode(&transmit.data);
    assert!(packet.find(ids::PING).is_some(), "{:x?}", packet.constructors());
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_none());
}

#[test]
fn force_ack_sends_waiting_acknowledgements_at_once() {
    let mut h = Harness::new();
    h.flush_all();
    h.deliver(vec![Outgoing::Content(update(0x1234_5678, &[1, 2, 3, 4]))]).unwrap();
    h.advance(0.002);
    assert!(h.session.poll_transmit(h.now, &mut h.rng).is_none(), "an ack alone waits to ride along");
    h.session.force_ack(h.now);
    let packet = h.flush().expect("forced");
    assert!(packet.find(ids::MSGS_ACK).is_some());
    h.session.force_ack(h.now);
    assert!(h.flush().is_none(), "nothing left to acknowledge");
}

#[test]
fn a_msg_id_never_has_a_zero_low_word() {
    let mut rng = SequenceRandom::new(vec![0; 4096]);
    let now = Now { mono: 100.0, unix: START };
    let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
    let config = SessionConfig { use_ping_delay_disconnect: false, ..SessionConfig::default() };
    let mut session = Session::new(config, key(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    session.send(QueryId(1), query_body(1), QueryOptions::default(), now);
    let transmit = session.poll_transmit(now, &mut rng).unwrap();
    let mut server = ServerPeer::new(key(), START);
    let packet = server.decode(&transmit.data);
    for message in &packet.messages {
        assert_ne!(message.msg_id & 0xffff_ffff, 0, "{:#x}", message.msg_id);
        assert_eq!(message.msg_id & 3, 0);
    }
    assert_eq!(packet.messages.iter().map(|message| message.msg_id >> 32).min(), Some(START as i64));
}

#[test]
fn query_state_accessors_follow_the_queries() {
    let mut h = Harness::new();
    assert_eq!(h.session.query_count(), 0);
    assert!(!h.session.contains(QueryId(1)));
    assert!(h.session.describe_queries().is_empty());
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    assert_eq!(h.session.query_count(), 2);
    assert!(h.session.contains(QueryId(1)));
    assert!(h.session.describe_queries().contains("Pending"));
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    assert!(h.session.describe_queries().contains(&format!("msg {first:x}")));
    h.deliver(vec![Outgoing::Content(rpc_result(first, &[1, 1, 1, 1]))]).unwrap();
    assert!(!h.session.contains(QueryId(1)), "an answered query is gone");
    assert_eq!(h.session.query_count(), 1);
    assert!(h.session.is_bound(), "a permanent key needs no binding");
    h.session.hold_until_bound();
    assert!(!h.session.is_bound());
}

#[test]
fn a_bind_request_prints_the_key_id_not_the_key() {
    let request = BindRequest { perm_key: AuthKey::new([0xab; 256]), nonce: 7, expires_at: 99 };
    let printed = format!("{request:?}");
    assert!(printed.contains(&request.perm_key.id().to_string()), "{printed}");
    assert!(!printed.contains("171, 171") && !printed.contains("abab"), "{printed}");
    assert!(!printed.contains("nonce"), "the nonce stays out too: {printed}");
}

mod packing {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

        /// However many queries of whatever sizes wait, every one goes exactly once, and no packet
        /// carries more queries or (beyond a single query) more bytes than the container limits allow.
        #[test]
        fn containers_respect_their_limits(
            sizes in proptest::collection::vec(0usize..3000, 1..80),
            max_queries in 1usize..12,
            max_bytes in 64usize..6000,
            quick_ack in any::<bool>(),
        ) {
            let config = SessionConfig {
                max_container_queries: max_queries,
                max_container_bytes: max_bytes,
                ..SessionConfig::default()
            };
            let mut rng = XorShiftRandom::new(sizes.len() as u64 + 1);
            let now = Now { mono: 100.0, unix: START };
            let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
            let mut session = Session::new(config, key(), &salts, 0.0, now, &mut rng);
            session.connection_opened(now);
            for (index, size) in sizes.iter().enumerate() {
                let mut body = query_body(index as u32);
                body.resize(8 + size / 4 * 4, 0);
                session.send(QueryId(index as u64 + 1), body, QueryOptions { quick_ack, invoke_after: None }, now);
            }
            let mut server = ServerPeer::new(key(), START);
            server.salt = 101;
            let mut now = now;
            let mut seen = Vec::new();
            for _ in 0..(4 * sizes.len() + 40) {
                now.mono += 0.01;
                now.unix += 0.01;
                server.server_time += 0.01;
                let Some(transmit) = session.poll_transmit(now, &mut rng) else {
                    if seen.len() == sizes.len() {
                        break;
                    }
                    continue;
                };
                let packet = server.decode(&transmit.data);
                let pongs: Vec<Outgoing> = packet
                    .messages
                    .iter()
                    .filter_map(|message| ping_id_of(message).map(|ping| Outgoing::Service(pong(message.msg_id, ping))))
                    .collect();
                if !pongs.is_empty() {
                    let reply = server.encode(pongs);
                    session.handle_packet(&reply, now, &mut rng).expect("pong");
                }
                let queries: Vec<&ClientMessage> =
                    packet.messages.iter().filter(|message| query_tag(&message.body).is_some()).collect();
                prop_assert!(queries.len() <= max_queries, "{} queries in one packet", queries.len());
                let bytes: usize = queries.iter().map(|message| message.body.len()).sum();
                prop_assert!(queries.len() <= 1 || bytes <= max_bytes, "{bytes} bytes of queries in one container");
                prop_assert!(packet.messages.len() <= MAX_CONTAINER_MESSAGES_OUT);
                seen.extend(queries.iter().filter_map(|message| query_tag(&message.body)));
            }
            seen.sort_unstable();
            let expected: Vec<u32> = (0..sizes.len() as u32).collect();
            prop_assert_eq!(seen, expected, "every query exactly once");
            prop_assert!(session.poll_transmit(now, &mut rng).is_none(), "nothing left to send");
        }
    }
}
