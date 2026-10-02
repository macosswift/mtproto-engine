use super::*;
use crate::crypto::XorShiftRandom;
use crate::test_support::server_peer::*;

const START: f64 = 1_727_000_000.0;
const QUERY_CONSTRUCTOR: u32 = 0x1122_3344;

struct Harness {
    session: Session,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7)))
}

fn query_body(tag: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(QUERY_CONSTRUCTOR);
    writer.write_u32(tag);
    writer.into_inner()
}

fn query_tag(body: &[u8]) -> Option<u32> {
    let mut reader = Reader::new(body);
    let mut constructor = reader.read_u32().ok()?;
    if constructor == ids::INVOKE_AFTER_MSG {
        reader.read_i64().ok()?;
        constructor = reader.read_u32().ok()?;
    }
    (constructor == QUERY_CONSTRUCTOR).then(|| reader.read_u32().ok()).flatten()
}

impl Harness {
    fn new() -> Self {
        Self::with_salts(vec![
            ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 },
            ServerSalt { salt: 102, valid_since: START + 1800.0, valid_until: START + 3600.0 },
        ])
    }

    fn with_salts(salts: Vec<ServerSalt>) -> Self {
        let mut rng = XorShiftRandom::new(5);
        let now = Now { mono: 100.0, unix: START };
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let mut server = ServerPeer::new(key(), START);
        server.salt = 101;
        Self { session, server, rng, now }
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

    fn flush_all(&mut self) -> Vec<DecodedPacket> {
        let mut packets = Vec::new();
        while let Some(packet) = self.flush() {
            packets.push(packet);
            if packets.len() > 50 {
                panic!("flush loop");
            }
        }
        packets
    }

    fn deliver(&mut self, items: Vec<Outgoing>) -> Result<(), SessionError> {
        let packet = self.server.encode(items);
        self.session.handle_packet(&packet, self.now, &mut self.rng)
    }

    fn events(&mut self) -> Vec<SessionEvent> {
        self.session.drain_events()
    }

    fn results(&mut self) -> Vec<(QueryId, Vec<u8>)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                SessionEvent::Result { id, body, .. } => Some((id, body)),
                _ => None,
            })
            .collect()
    }

    fn answer_pings(&mut self, packet: &DecodedPacket) {
        let pongs: Vec<Outgoing> = packet
            .messages
            .iter()
            .filter(|message| message.constructor() == ids::PING_DELAY_DISCONNECT || message.constructor() == ids::PING)
            .map(|message| {
                Outgoing::Service(pong(message.msg_id, i64::from_le_bytes(message.body[4..12].try_into().unwrap())))
            })
            .collect();
        if !pongs.is_empty() {
            self.deliver(pongs).unwrap();
        }
    }

    fn sent_query(&mut self, packet: &DecodedPacket, tag: u32) -> i64 {
        packet
            .messages
            .iter()
            .find(|message| query_tag(&message.body) == Some(tag))
            .map(|message| message.msg_id)
            .unwrap_or_else(|| panic!("query {tag} not in packet {:x?}", packet.constructors()))
    }
}

#[test]
fn request_roundtrip_with_ping_and_acks() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().expect("packet");
    assert_eq!(packet.header.salt, 101);
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_some());
    let query_msg_id = h.sent_query(&packet, 1);
    assert_eq!(query_msg_id % 4, 0);
    let query = packet.messages.iter().find(|m| m.msg_id == query_msg_id).unwrap();
    assert!(query.is_content_related());
    let ping = packet.find(ids::PING_DELAY_DISCONNECT).unwrap();
    assert!(!ping.is_content_related());
    assert!(packet.messages.iter().all(|m| m.msg_id < packet.header.msg_id));

    h.deliver(vec![Outgoing::Content(rpc_result(query_msg_id, &[1, 2, 3, 4]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 2, 3, 4])]);
    assert!(!h.session.has_queries());

    assert!(h.flush().is_none(), "acks are delayed");
    h.advance(ACK_DELAY + 1.0);
    let packet = h.flush().expect("ack packet");
    let ack = packet.find(ids::MSGS_ACK).expect("ack");
    assert_eq!(read_vector_after_constructor(&ack.body).len(), 1);
}

#[test]
fn queries_are_packed_into_one_container_in_order() {
    let mut h = Harness::new();
    for tag in 1..=5 {
        h.session.send(QueryId(tag as u64), query_body(tag), QueryOptions::default(), h.now);
    }
    let packet = h.flush().unwrap();
    let tags: Vec<u32> = packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect();
    assert_eq!(tags, vec![1, 2, 3, 4, 5]);
    let ids: Vec<i64> = packet.queries().iter().map(|m| m.msg_id).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    let seqs: Vec<i32> = packet.queries().iter().map(|m| m.seq_no).collect();
    assert_eq!(seqs, vec![1, 3, 5, 7, 9]);
}

#[test]
fn container_limits_split_packets() {
    let mut h = Harness::new();
    for tag in 0..40u32 {
        let mut body = query_body(tag);
        body.extend(vec![0u8; 2048]);
        h.session.send(QueryId(tag as u64), body, QueryOptions::default(), h.now);
    }
    let packets = h.flush_all();
    assert!(packets.len() >= 3, "{}", packets.len());
    let total: usize = packets.iter().map(|p| p.queries().len()).sum();
    assert_eq!(total, 40);
    for packet in &packets {
        let size: usize = packet.queries().iter().map(|m| m.body.len()).sum();
        assert!(size <= DEFAULT_CONTAINER_BYTES + 2100);
    }
}

#[test]
fn single_large_query_is_sent_alone() {
    let mut h = Harness::new();
    h.session.set_online(false, h.now);
    let mut warmup = h.flush_all();
    warmup.clear();
    let mut body = query_body(9);
    body.extend(vec![1u8; 600 * 1024]);
    h.session.send(QueryId(9), body.clone(), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    assert_eq!(packet.messages.len(), 1);
    assert_eq!(packet.messages[0].body, body);
}

#[test]
fn bad_server_salt_updates_salt_and_resends() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first_id = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 555))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::SaltsUpdated { .. })));
    let packet = h.flush().unwrap();
    assert_eq!(packet.header.salt, 555);
    let second_id = h.sent_query(&packet, 1);
    assert!(second_id > first_id);
    assert!(packet.find(ids::GET_FUTURE_SALTS).is_some());
}

#[test]
fn bad_msg_16_resyncs_time_and_resends() {
    let mut h = Harness::new();
    h.server.server_time += 500.0;
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first_id = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(bad_msg_notification(first_id, 1, 16))]).unwrap();
    let events = h.events();
    assert!(events
        .iter()
        .any(|e| matches!(e, SessionEvent::TimeDifferenceUpdated { forced: true, difference } if (*difference - 500.0).abs() < 1.0)));
    let packet = h.flush().unwrap();
    let second_id = h.sent_query(&packet, 1);
    assert!(msg_id_time(second_id) > START + 499.0);
}

#[test]
fn bad_msg_17_resets_session() {
    let mut h = Harness::new();
    let old_session = h.session.session_id();
    h.server.server_time -= 300.0;
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first_id = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(bad_msg_notification(first_id, 1, 17))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::LocalSessionReset { .. })));
    assert_ne!(h.session.session_id(), old_session);
    let packet = h.flush().unwrap();
    let second_id = h.sent_query(&packet, 1);
    assert!(msg_id_time(second_id) < START - 299.0);
    assert_eq!(packet.header.session_id, h.session.session_id());
}

#[test]
fn bad_msg_17_drains_answers_in_flight_before_resetting() {
    let mut h = Harness::new();
    let old_session = h.session.session_id();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let first_packet = h.flush().unwrap();
    let first_id = h.sent_query(&first_packet, 1);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let second_packet = h.flush().unwrap();
    let second_id = h.sent_query(&second_packet, 2);
    h.server.server_time -= 600.0;
    h.deliver(vec![Outgoing::Service(bad_msg_notification(second_id, 1, 17))]).unwrap();
    assert!(!h.events().iter().any(|event| matches!(event, SessionEvent::LocalSessionReset { .. })), "draining");
    assert_eq!(h.session.session_id(), old_session);
    assert!(h.flush().is_none(), "nothing is sent on a session the server now rejects");
    h.deliver(vec![Outgoing::Content(rpc_result(first_id, &query_body(1)))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
    assert!(events.iter().any(|event| matches!(event, SessionEvent::LocalSessionReset { .. })));
    let packet = h.flush().unwrap();
    assert_ne!(h.session.session_id(), old_session);
    assert_eq!(packet.header.session_id, h.session.session_id());
    h.sent_query(&packet, 2);
    assert!(
        packet.messages.iter().all(|message| query_tag(&message.body) != Some(1)),
        "the answered query stays answered"
    );
}

#[test]
fn bad_msg_17_drain_gives_up_after_its_deadline() {
    let mut h = Harness::new();
    let old_session = h.session.session_id();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.flush().unwrap();
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let second_packet = h.flush().unwrap();
    let second_id = h.sent_query(&second_packet, 2);
    h.server.server_time -= 600.0;
    h.deliver(vec![Outgoing::Service(bad_msg_notification(second_id, 1, 17))]).unwrap();
    let deadline = h.session.poll_timeout(h.now).unwrap();
    assert!(deadline <= h.now.mono + RESET_DRAIN_MAX + 0.01);
    h.advance(RESET_DRAIN_MAX + 0.1);
    let packet = h.flush().unwrap();
    assert_ne!(h.session.session_id(), old_session);
    h.sent_query(&packet, 1);
    h.sent_query(&packet, 2);
}

#[test]
fn bad_msg_32_resets_session_and_keeps_processing_container() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    h.deliver(vec![
        Outgoing::Content(rpc_result(first, &[9, 9, 9, 9])),
        Outgoing::Service(bad_msg_notification(second, 3, 32)),
    ])
    .unwrap();
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Result { id: QueryId(1), .. })));
    assert!(events.iter().any(|e| matches!(e, SessionEvent::LocalSessionReset { .. })));
    let packet = h.flush().unwrap();
    assert_eq!(packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect::<Vec<_>>(), vec![2]);
    assert_eq!(packet.queries()[0].seq_no, 1);
}

#[test]
fn new_session_created_resends_older_queries_and_reports_reset() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let first_packet = h.flush().unwrap();
    let first = h.sent_query(&first_packet, 1);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let second_packet = h.flush().unwrap();
    let second = h.sent_query(&second_packet, 2);
    h.deliver(vec![Outgoing::Content(new_session_created(second, 42, 101))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::ServerSessionReset { unique_id: 42, .. })));
    let packet = h.flush().unwrap();
    let tags: Vec<u32> = packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect();
    assert_eq!(tags, vec![1]);
    assert!(h.sent_query(&packet, 1) > first);
    h.deliver(vec![Outgoing::Content(rpc_result(second, &[2, 0, 0, 0]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(2), vec![2, 0, 0, 0])]);
}

#[test]
fn reconnect_without_ack_retransmits_with_original_msg_ids() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let originals: Vec<(i64, i32)> = packet.queries().iter().map(|m| (m.msg_id, m.seq_no)).collect();
    h.session.connection_closed();
    assert!(h.session.has_unknown_queries());
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::MSGS_STATE_REQ).is_none(), "no state request round trip");
    assert!(packet.messages.iter().all(|m| m.container_id.is_some()));
    let retransmitted: Vec<(i64, i32)> = packet.queries().iter().map(|m| (m.msg_id, m.seq_no)).collect();
    assert_eq!(retransmitted, originals, "same msg_id and seqno, so the server deduplicates");
    assert!(!h.session.has_unknown_queries());
    h.deliver(vec![
        Outgoing::Content(rpc_result(originals[0].0, &[1, 1, 1, 1])),
        Outgoing::Content(rpc_result(originals[1].0, &[2, 2, 2, 2])),
    ])
    .unwrap();
    let mut results = h.results();
    results.sort_by_key(|(id, _)| id.0);
    assert_eq!(results, vec![(QueryId(1), vec![1, 1, 1, 1]), (QueryId(2), vec![2, 2, 2, 2])]);
    assert!(h.flush_all().iter().all(|packet| packet.queries().is_empty()));
}

#[test]
fn retransmissions_respect_container_limits_and_keep_order() {
    let mut h = Harness::new();
    let part = vec![0x55u8; DEFAULT_CONTAINER_BYTES / 2 + 4];
    let mut originals = Vec::new();
    for index in 0..6u32 {
        let mut body = query_body(index);
        body.extend_from_slice(&part);
        h.session.send(QueryId(u64::from(index)), body, QueryOptions::default(), h.now);
        let packet = h.flush().unwrap();
        originals.push(h.sent_query(&packet, index));
    }
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    h.session.send(QueryId(99), query_body(99), QueryOptions::default(), h.now);
    let packets = h.flush_all();
    let mut retransmitted = Vec::new();
    let mut fresh_seen_at = None;
    for (index, packet) in packets.iter().enumerate() {
        let queries = packet.queries();
        let bytes: usize = queries.iter().map(|m| m.body.len()).sum();
        assert!(queries.len() == 1 || bytes <= DEFAULT_CONTAINER_BYTES, "packet {index} carries {bytes} bytes");
        for message in queries {
            if query_tag(&message.body) == Some(99) {
                fresh_seen_at = Some(retransmitted.len());
            } else {
                retransmitted.push(message.msg_id);
            }
        }
    }
    assert_eq!(retransmitted, originals);
    assert_eq!(fresh_seen_at, Some(originals.len()), "new queries follow the retransmissions");
    assert!(packets.len() >= 3);
}

#[test]
fn large_answers_are_acknowledged_at_once_small_ones_are_batched() {
    let mut h = Harness::new();
    h.sync();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let small = h.sent_query(&packet, 1);
    let large = h.sent_query(&packet, 2);
    h.flush_all();
    h.deliver(vec![Outgoing::Content(rpc_result(small, &[1, 2, 3, 4]))]).unwrap();
    assert!(h.flush_all().iter().all(|packet| packet.find(ids::MSGS_ACK).is_none()), "small answers wait for company");
    h.deliver(vec![Outgoing::Content(rpc_result(large, &vec![7u8; IMMEDIATE_ACK_SIZE]))]).unwrap();
    let packets = h.flush_all();
    let ack = packets.iter().find_map(|packet| packet.find(ids::MSGS_ACK)).expect("large answer acknowledged at once");
    assert!(read_vector_after_constructor(&ack.body).len() >= 2, "pending small acks ride along");
}

fn busy_with_unanswered_ping(h: &mut Harness) -> f64 {
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.flush_all();
    let since = h.session.unanswered_ping_since().expect("a ping went out with the query");
    assert!(h.session.wants_outbound_backlog());
    since
}

#[test]
fn silent_connection_is_cut_by_the_probe_long_before_the_read_timeout() {
    let mut h = Harness::new();
    let since = busy_with_unanswered_ping(&mut h);
    h.session.note_outbound_backlog(Some(0), h.now);
    let timeout = h.session.probe_timeout();
    assert!((PROBE_TIMEOUT_MIN..=PROBE_TIMEOUT_MAX).contains(&timeout));
    assert!(timeout < h.session.read_disconnect_delay());
    let deadline = h.session.poll_timeout(h.now).unwrap();
    assert!(deadline <= h.now.mono + BACKLOG_SAMPLE_INTERVAL + 0.01, "backlog is sampled while the ping is unanswered");
    let mut elapsed = 0.0;
    let outcome = loop {
        h.advance(0.1);
        elapsed += 0.1;
        h.session.note_outbound_backlog(Some(0), h.now);
        match h.session.handle_timeout(h.now) {
            Ok(()) => assert!(elapsed < 10.0),
            Err(error) => break error,
        }
    };
    assert_eq!(outcome, SessionError::ProbeTimeout);
    assert!(h.now.mono - since <= timeout + 0.25, "cut {:.2} s after the ping", h.now.mono - since);
}

#[test]
fn draining_backlog_is_progress_and_never_trips_the_probe() {
    let mut h = Harness::new();
    busy_with_unanswered_ping(&mut h);
    let mut backlog = 4_000_000usize;
    for _ in 0..60 {
        h.session.note_outbound_backlog(Some(backlog), h.now);
        assert_eq!(h.session.handle_timeout(h.now), Ok(()));
        h.advance(0.1);
        backlog -= 50_000;
        h.session.note_bytes_received(h.now);
    }
    busy_with_unanswered_ping(&mut h);
    let mut stalled = Ok(());
    for _ in 0..80 {
        h.advance(0.1);
        h.session.note_outbound_backlog(Some(backlog), h.now);
        stalled = h.session.handle_timeout(h.now);
        if stalled.is_err() {
            break;
        }
    }
    assert_eq!(stalled, Err(SessionError::ProbeTimeout), "a backlog that stops draining is a dead path");
}

#[test]
fn writes_acknowledged_by_a_proxy_after_the_ping_drained_are_not_liveness() {
    let mut h = Harness::new();
    let since = busy_with_unanswered_ping(&mut h);
    h.session.note_outbound_backlog(Some(300), h.now);
    h.advance(0.05);
    h.session.note_outbound_backlog(Some(0), h.now);
    let mut outcome = Ok(());
    for step in 0..60 {
        h.advance(0.1);
        h.session.note_outbound_backlog(Some(if step % 2 == 0 { 120 } else { 0 }), h.now);
        outcome = h.session.handle_timeout(h.now);
        if outcome.is_err() {
            break;
        }
    }
    assert_eq!(outcome, Err(SessionError::ProbeTimeout));
    assert!(
        h.now.mono - since < h.session.probe_timeout() + 0.5,
        "new writes after the drain must not extend the probe"
    );
}

#[test]
fn jittery_slow_links_get_a_wider_probe_window() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_some());
    h.advance(2.4);
    h.answer_pings(&packet);
    let timeout = h.session.probe_timeout();
    assert!(timeout >= 2.4 * 1.5, "a 2.4 s round trip must not look dead after {timeout} s");
    assert!(timeout <= PROBE_TIMEOUT_MAX);
}

#[test]
fn a_connection_that_never_answered_does_not_grow_the_backoff() {
    let mut h = Harness::new();
    let base = h.session.probe_timeout();
    busy_with_unanswered_ping(&mut h);
    h.session.note_outbound_backlog(Some(0), h.now);
    h.advance(base + 0.5);
    h.session.note_outbound_backlog(Some(0), h.now);
    assert_eq!(h.session.handle_timeout(h.now), Err(SessionError::ProbeTimeout));
    assert_eq!(h.session.probe_timeout(), base, "a dead path is not a false alarm");
}

#[test]
fn without_backlog_information_only_the_classic_timeouts_apply() {
    let mut h = Harness::new();
    busy_with_unanswered_ping(&mut h);
    let mut seconds = 0.0;
    let outcome = loop {
        h.advance(0.25);
        seconds += 0.25;
        if let Err(error) = h.session.handle_timeout(h.now) {
            break error;
        }
        assert!(seconds < 200.0);
    };
    assert_ne!(outcome, SessionError::ProbeTimeout);
    assert!(seconds >= h.session.read_disconnect_delay() - 0.5);
}

#[test]
fn inbound_bytes_after_the_ping_cancel_the_probe() {
    let mut h = Harness::new();
    busy_with_unanswered_ping(&mut h);
    h.session.note_outbound_backlog(Some(0), h.now);
    h.advance(0.3);
    h.session.note_bytes_received(h.now);
    assert!(h.session.unanswered_ping_since().is_none());
    assert!(!h.session.wants_outbound_backlog());
    h.advance(PROBE_TIMEOUT_MAX);
    h.session.note_bytes_received(h.now);
    assert_eq!(h.session.handle_timeout(h.now), Ok(()));
}

#[test]
fn probe_backoff_grows_after_a_false_alarm_and_relaxes_after_fast_pongs() {
    let mut h = Harness::new();
    h.sync();
    h.advance(61.0);
    let base = h.session.probe_timeout();
    busy_with_unanswered_ping(&mut h);
    h.session.note_outbound_backlog(Some(0), h.now);
    assert_eq!(base, PROBE_TIMEOUT_INITIAL, "no RTT sample yet: conservative");
    h.advance(base + 0.5);
    h.session.note_outbound_backlog(Some(0), h.now);
    assert_eq!(h.session.handle_timeout(h.now), Err(SessionError::ProbeTimeout));
    assert!(h.session.probe_timeout() > base * 1.5);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let mut answered = 0;
    for _ in 0..20 {
        h.session.handle_timeout(h.now).unwrap();
        for packet in h.flush_all() {
            if packet.find(ids::PING_DELAY_DISCONNECT).is_some() || packet.find(ids::PING).is_some() {
                h.advance(0.05);
                h.answer_pings(&packet);
                answered += 1;
            }
        }
        h.advance(1.1);
    }
    assert!(answered >= 3);
    assert!(
        h.session.probe_timeout() <= PROBE_TIMEOUT_MIN + 0.5,
        "fast pongs shrink the timeout and the backoff: {}",
        h.session.probe_timeout()
    );
}

#[test]
fn repeated_reconnects_keep_retransmitting_the_same_message() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    for _ in 0..5 {
        h.session.connection_closed();
        h.advance(2.0);
        h.session.connection_opened(h.now);
        let packet = h.flush().unwrap();
        assert_eq!(h.sent_query(&packet, 1), original);
    }
    h.deliver(vec![Outgoing::Content(rpc_result(original, &[9, 9, 9, 9]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![9, 9, 9, 9])]);
}

#[test]
fn reconnect_after_retransmit_window_asks_state_and_resends_only_unreceived() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    h.session.connection_closed();
    assert!(h.session.has_unknown_queries());
    assert!(h.session.is_performing_service_tasks());
    h.advance(RETRANSMIT_WINDOW + 1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert!(packet.messages.iter().all(|m| query_tag(&m.body).is_none()), "no blind resend");
    let state_request = packet.find(ids::MSGS_STATE_REQ).expect("state request");
    let mut asked = read_vector_after_constructor(&state_request.body);
    asked.sort_unstable();
    assert_eq!(asked, vec![first, second]);
    let info: Vec<u8> =
        read_vector_after_constructor(&state_request.body).iter().map(|id| if *id == first { 4 } else { 2 }).collect();
    h.deliver(vec![Outgoing::Content(msgs_state_info(state_request.msg_id, &info))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Acknowledged { id: QueryId(1) })));
    assert!(!h.session.has_unknown_queries());
    let packet = h.flush().unwrap();
    let tags: Vec<u32> = packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect();
    assert_eq!(tags, vec![2]);
    assert!(h.sent_query(&packet, 2) > second);
    h.deliver(vec![Outgoing::Content(rpc_result(first, &[1, 1, 1, 1]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 1, 1, 1])]);
}

#[test]
fn retransmission_rejected_for_salt_is_retransmitted_again_with_the_same_msg_id() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert_eq!(h.sent_query(&packet, 1), original);
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 555))]).unwrap();
    let packet = h.flush().unwrap();
    assert_eq!(h.sent_query(&packet, 1), original, "a new msg_id could execute the query twice");
    assert_eq!(packet.header.salt, 555);
}

#[test]
fn fresh_query_rejected_for_salt_still_gets_a_new_msg_id() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 555))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(h.sent_query(&packet, 1) > original);
}

#[test]
fn retransmission_rejected_by_bad_msg_falls_back_to_state_request() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert_eq!(h.sent_query(&packet, 1), original);
    h.deliver(vec![Outgoing::Service(bad_msg_notification(packet.header.msg_id, packet.header.seq_no, 20))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(packet.queries().is_empty(), "the first transmission may have been executed");
    let request = packet.find(ids::MSGS_STATE_REQ).expect("state request");
    assert_eq!(read_vector_after_constructor(&request.body), vec![original]);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert!(packet.queries().is_empty(), "a refused retransmission is not retried blindly");
    let request = packet.find(ids::MSGS_STATE_REQ).expect("state request after reconnect");
    h.deliver(vec![Outgoing::Content(msgs_state_info(request.msg_id, &[2]))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(h.sent_query(&packet, 1) > original, "not received, so a new msg_id is safe");
}

#[test]
fn stale_not_received_info_does_not_duplicate_a_retransmitted_query() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert_eq!(h.sent_query(&packet, 1), original);
    h.deliver(vec![Outgoing::Service(msgs_all_info(&[original], &[2]))]).unwrap();
    assert!(h.flush_all().iter().all(|packet| packet.queries().is_empty()));
    h.deliver(vec![Outgoing::Content(rpc_result(original, &[3, 3, 3, 3]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![3, 3, 3, 3])]);
}

#[test]
fn rejected_connection_does_not_resend_a_retransmission_under_a_new_msg_id() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = h.sent_query(&packet, 1);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    h.flush().unwrap();
    h.session.connection_rejected(h.now);
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert_eq!(h.sent_query(&packet, 1), original);
}

#[test]
fn acknowledged_queries_survive_reconnect_without_state_request() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(msgs_ack(&[packet.header.msg_id]))]).unwrap();
    assert!(h.events().iter().any(|e| matches!(e, SessionEvent::Acknowledged { id: QueryId(1) })));
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    assert!(!h.session.has_unknown_queries());
    let packets = h.flush_all();
    for packet in &packets {
        assert!(packet.find(ids::MSGS_STATE_REQ).is_none());
        assert!(packet.messages.iter().all(|m| query_tag(&m.body).is_none()));
    }
    h.deliver(vec![Outgoing::Content(rpc_result(first, &[7, 7, 7, 7]))]).unwrap();
    assert_eq!(h.results().len(), 1);
}

#[test]
fn unanswered_state_request_is_retried() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.flush().unwrap();
    h.session.connection_closed();
    h.advance(RETRANSMIT_WINDOW + 1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    let first_request = packet.find(ids::MSGS_STATE_REQ).expect("state request").msg_id;
    let mut state_requests = vec![first_request];
    for _ in 0..30 {
        h.advance(1.0);
        h.session.handle_timeout(h.now).unwrap();
        while let Some(packet) = h.flush() {
            h.answer_pings(&packet);
            if let Some(request) = packet.find(ids::MSGS_STATE_REQ) {
                state_requests.push(request.msg_id);
            }
        }
    }
    assert_eq!(state_requests.len(), 2, "re-asked once after STATE_REQUEST_RETRY");
}

#[test]
fn quick_ack_marks_query_acknowledged() {
    let mut h = Harness::new();
    h.session.send(QueryId(7), query_body(7), QueryOptions { quick_ack: true, invoke_after: None }, h.now);
    h.advance(0.01);
    let transmit = h.session.poll_transmit(h.now, &mut h.rng).unwrap();
    let token = transmit.quick_ack_token.expect("quick ack requested");
    h.session.handle_quick_ack(token | 0x8000_0000);
    assert_eq!(h.events(), vec![SessionEvent::Acknowledged { id: QueryId(7) }]);
    h.session.handle_quick_ack(token);
    assert!(h.events().is_empty());
}

#[test]
fn msgs_ack_on_container_acknowledges_children_once() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    h.deliver(vec![Outgoing::Service(msgs_ack(&[packet.header.msg_id, packet.header.msg_id]))]).unwrap();
    let acks: Vec<SessionEvent> =
        h.events().into_iter().filter(|e| matches!(e, SessionEvent::Acknowledged { .. })).collect();
    assert_eq!(acks.len(), 2);
}

#[test]
fn gzip_rpc_errors_and_duplicates() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    let big = vec![5u8; 100_000];
    let packet = h.server.encode(vec![
        Outgoing::Content(rpc_result_gzipped(first, &big)),
        Outgoing::Content(rpc_error(second, 420, "FLOOD_WAIT_7")),
    ]);
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    let events = h.events();
    let results: Vec<&SessionEvent> = events.iter().filter(|e| matches!(e, SessionEvent::Result { .. })).collect();
    assert_eq!(results.len(), 1);
    match results[0] {
        SessionEvent::Result { id, body, .. } => {
            assert_eq!(*id, QueryId(1));
            assert_eq!(body, &big);
        }
        _ => unreachable!(),
    }
    assert!(events.iter().any(
        |e| matches!(e, SessionEvent::Error { id: QueryId(2), code: 420, message, .. } if message == "FLOOD_WAIT_7")
    ));
}

#[test]
fn updates_are_delivered_once_and_unknown_constructors_do_not_break_containers() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let update_msg_id = h.server.next_msg_id(false);
    let updates = update(0x74ae4240, &[1, 2, 3, 4]);
    let packet = h.server.encode(vec![
        Outgoing::Raw { body: updates.clone(), seq_no: 1, msg_id: Some(update_msg_id) },
        Outgoing::Content(update(0xdeadbeef, &[0; 8])),
        Outgoing::Content(rpc_result(first, &[3, 3, 3, 3])),
    ]);
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    let events = h.events();
    let update_events: Vec<&SessionEvent> =
        events.iter().filter(|e| matches!(e, SessionEvent::Update { .. })).collect();
    assert_eq!(update_events.len(), 2);
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Result { id: QueryId(1), .. })));
    let resent = h.server.seal(update_msg_id, 1, &updates);
    h.session.handle_packet(&resent, h.now, &mut h.rng).unwrap();
    assert!(h.events().iter().all(|e| !matches!(e, SessionEvent::Update { .. })));
}

#[test]
fn missing_salt_requests_future_salts_first() {
    let mut h = Harness::with_salts(vec![]);
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    assert_eq!(packet.constructors(), vec![ids::GET_FUTURE_SALTS]);
    assert!(h.flush().is_none());
    let request = packet.messages[0].msg_id;
    let now = h.server.server_time as i32;
    h.deliver(vec![
        Outgoing::Service(bad_server_salt(request, 0, 900)),
        Outgoing::Content(future_salts(request, now, &[(now - 10, now + 1800, 900), (now + 1800, now + 3600, 901)])),
    ])
    .unwrap();
    let packet = h.flush().unwrap();
    assert_eq!(packet.header.salt, 900);
    h.sent_query(&packet, 1);
    h.advance(1900.0);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    assert_eq!(packet.header.salt, 901);
}

#[test]
fn msg_detailed_info_requests_lost_answer() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let answer_id = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(first, answer_id, 1000))]).unwrap();
    assert!(h.events().iter().any(|e| matches!(e, SessionEvent::Acknowledged { id: QueryId(1) })));
    let packet = h.flush().unwrap();
    let resend = packet.find(ids::MSG_RESEND_REQ).expect("resend request");
    assert_eq!(read_vector_after_constructor(&resend.body), vec![answer_id]);
    let answer = h.server.seal(answer_id, 1, &rpc_result(first, &[4, 4, 4, 4]));
    h.session.handle_packet(&answer, h.now, &mut h.rng).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![4, 4, 4, 4])]);
}

#[test]
fn msg_new_detailed_info_for_received_message_is_only_acked() {
    let mut h = Harness::new();
    h.flush();
    let update_id = h.server.next_msg_id(false);
    let packet = h.server.seal(update_id, 1, &update(0x1234_5678, &[0; 4]));
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    h.events();
    h.deliver(vec![Outgoing::Service(msg_new_detailed_info(update_id, 100))]).unwrap();
    h.advance(ACK_DELAY + 1.0);
    let packets = h.flush_all();
    assert!(packets.iter().all(|p| p.find(ids::MSG_RESEND_REQ).is_none()));
    assert!(packets.iter().any(|p| p.find(ids::MSGS_ACK).is_some()));
}

#[test]
fn dependencies_wrap_invoke_after_msg() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions { quick_ack: false, invoke_after: Some(QueryId(1)) }, h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let dependent = packet.messages.iter().find(|m| query_tag(&m.body) == Some(2)).unwrap();
    let mut reader = Reader::new(&dependent.body);
    assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_AFTER_MSG);
    assert_eq!(reader.read_i64().unwrap(), first);

    h.deliver(vec![Outgoing::Content(rpc_result(first, &[0; 4]))]).unwrap();
    h.session.send(QueryId(3), query_body(3), QueryOptions { quick_ack: false, invoke_after: Some(QueryId(1)) }, h.now);
    let packet = h.flush().unwrap();
    let third = packet.messages.iter().find(|m| query_tag(&m.body) == Some(3)).unwrap();
    assert_eq!(u32::from_le_bytes(third.body[..4].try_into().unwrap()), QUERY_CONSTRUCTOR);
}

#[test]
fn cancellation() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    assert_eq!(h.session.cancel(QueryId(1)), CancelOutcome::Removed);
    let packets = h.flush_all();
    assert!(packets.iter().all(|p| p.messages.iter().all(|m| query_tag(&m.body).is_none())));

    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let second = h.sent_query(&packet, 2);
    assert_eq!(h.session.cancel(QueryId(2)), CancelOutcome::RemovedInFlight { msg_id: second });
    h.deliver(vec![Outgoing::Content(rpc_result(second, &[0; 4]))]).unwrap();
    assert!(h.results().is_empty());
    assert_eq!(h.session.cancel(QueryId(2)), CancelOutcome::NotFound);
}

#[test]
fn ping_and_read_timeouts() {
    let mut h = Harness::new();
    h.flush_all();
    let deadline = h.session.poll_timeout(h.now).unwrap();
    assert!(deadline > h.now.mono);
    h.advance(200.0);
    assert!(matches!(h.session.handle_timeout(h.now), Err(SessionError::PingTimeout) | Err(SessionError::ReadTimeout)));
}

#[test]
fn online_mode_pings_faster() {
    let mut h = Harness::new();
    h.session.set_online(true, h.now);
    h.flush_all();
    h.advance(3.0);
    let packet = h.flush().expect("ping due");
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_some());
}

#[test]
fn foreign_session_and_tampering_are_rejected() {
    let mut h = Harness::new();
    h.flush();
    let mut other = ServerPeer::new(key(), START);
    other.session_id = h.session.session_id() ^ 1;
    let packet = other.encode(vec![Outgoing::Content(update(1, &[0; 4]))]);
    assert_eq!(h.session.handle_packet(&packet, h.now, &mut h.rng), Err(SessionError::ForeignSession));
    let mut packet = h.server.encode(vec![Outgoing::Content(update(1, &[0; 4]))]);
    let last = packet.len() - 1;
    packet[last] ^= 1;
    assert!(matches!(h.session.handle_packet(&packet, h.now, &mut h.rng), Err(SessionError::Decrypt(_))));
}

#[test]
fn messages_outside_time_window_are_ignored_after_sync() {
    let mut h = Harness::new();
    h.flush();
    h.deliver(vec![Outgoing::Content(update(1, &[0; 4]))]).unwrap();
    h.events();
    let old_id = msg_id_for_time(START - 400.0) | 3;
    let packet = h.server.seal(old_id, 1, &update(2, &[0; 4]));
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    assert!(h.events().iter().all(|e| !matches!(e, SessionEvent::Update { .. })));
    assert!(!h.session.received.contains(old_id), "a dropped stale packet is not recorded as received");
    let future_id = msg_id_for_time(START + 400.0) | 3;
    h.session.handle_packet(&h.server.seal(future_id, 1, &update(3, &[0; 4])), h.now, &mut h.rng).unwrap();
    assert_eq!(updates_of(&h.events()), vec![3], "a newer server clock raises ours");
    let acked = h.acks_after_delay();
    assert!(!acked.contains(&old_id), "and it is not acknowledged");
    assert!(acked.contains(&future_id));
}

#[test]
fn server_state_request_is_answered() {
    let mut h = Harness::new();
    h.flush();
    let update_id = h.server.next_msg_id(false);
    let packet = h.server.seal(update_id, 1, &update(5, &[0; 4]));
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    let unknown_id = update_id + 400;
    h.deliver(vec![Outgoing::Content(msgs_state_req(&[update_id, unknown_id]))]).unwrap();
    let packet = h.flush().unwrap();
    let reply = packet.find(ids::MSGS_STATE_INFO).expect("state info reply");
    let mut reader = Reader::new(&reply.body[4..]);
    reader.read_i64().unwrap();
    assert_eq!(reader.read_bytes().unwrap(), &[4, 3]);
}

#[test]
fn progress_target_identifies_large_result() {
    let mut h = Harness::new();
    h.session.send(QueryId(77), query_body(77), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let msg_id = h.sent_query(&packet, 77);
    let big = vec![9u8; 4096];
    let response = h.server.encode(vec![Outgoing::Content(rpc_result(msg_id, &big))]);
    assert_eq!(h.session.progress_target(&response[..128]), Some(QueryId(77)));
    let container =
        h.server.encode(vec![Outgoing::Content(rpc_result(msg_id, &big)), Outgoing::Content(update(1, &[0; 4]))]);
    assert_eq!(h.session.progress_target(&container[..128]), Some(QueryId(77)));
    assert_eq!(h.session.progress_target(&response[..40]), None);
}

#[test]
fn reset_requeues_everything_in_original_order() {
    let mut h = Harness::new();
    for tag in 1..=3 {
        h.session.send(QueryId(tag), query_body(tag as u32), QueryOptions::default(), h.now);
    }
    h.flush().unwrap();
    h.session.send(QueryId(4), query_body(4), QueryOptions::default(), h.now);
    h.session.reset(&mut h.rng);
    let packet = h.flush().unwrap();
    let tags: Vec<u32> = packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect();
    assert_eq!(tags, vec![1, 2, 3, 4]);
}

#[test]
fn many_acks_flush_immediately() {
    let mut h = Harness::new();
    h.flush_all();
    for _ in 0..MAX_PENDING_ACKS {
        h.deliver(vec![Outgoing::Content(update(9, &[0; 4]))]).unwrap();
    }
    let packet = h.flush().expect("ack flush");
    let ack = packet.find(ids::MSGS_ACK).unwrap();
    assert_eq!(read_vector_after_constructor(&ack.body).len(), MAX_PENDING_ACKS);
}

#[test]
fn dropped_answers_are_accounted() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let msg_id = h.sent_query(&packet, 1);
    h.session.cancel(QueryId(1));
    for _ in 0..20 {
        h.deliver(vec![Outgoing::Content(rpc_result(msg_id, &vec![0u8; 131_072]))]).unwrap();
        h.advance(1.0);
    }
    assert!(
        !h.events().iter().any(|e| matches!(e, SessionEvent::DroppedAnswerTooLarge { .. })),
        "a trickle of cancelled parts is normal while scrolling"
    );
    for _ in 0..20 {
        h.deliver(vec![Outgoing::Content(rpc_result(msg_id, &vec![0u8; 512 * 1024]))]).unwrap();
    }
    assert!(h.events().iter().any(|e| matches!(e, SessionEvent::DroppedAnswerTooLarge { .. })));
}

fn ack_ids(packets: &[DecodedPacket]) -> Vec<i64> {
    packets
        .iter()
        .filter_map(|packet| packet.find(ids::MSGS_ACK))
        .flat_map(|ack| read_vector_after_constructor(&ack.body))
        .collect()
}

fn has_forced_time_update(events: &[SessionEvent]) -> bool {
    events.iter().any(|event| matches!(event, SessionEvent::TimeDifferenceUpdated { forced: true, .. }))
}

fn updates_of(events: &[SessionEvent]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            SessionEvent::Update { body, .. } => Some(u32::from_le_bytes(body[..4].try_into().unwrap())),
            _ => None,
        })
        .collect()
}

impl Harness {
    fn sync(&mut self) {
        self.flush();
        self.deliver(vec![Outgoing::Content(update(0x0bad_cafe, &[0; 4]))]).unwrap();
        self.events();
    }

    fn sent_one(&mut self, tag: u32) -> i64 {
        self.session.send(QueryId(tag as u64), query_body(tag), QueryOptions::default(), self.now);
        let packet = self.flush().expect("packet with query");
        self.sent_query(&packet, tag)
    }

    fn deliver_sealed(&mut self, msg_id: i64, seq_no: i32, body: &[u8]) -> Result<(), SessionError> {
        let packet = self.server.seal(msg_id, seq_no, body);
        self.session.handle_packet(&packet, self.now, &mut self.rng)
    }

    fn acks_after_delay(&mut self) -> Vec<i64> {
        self.advance(ACK_DELAY + 1.0);
        let packets = self.flush_all();
        ack_ids(&packets)
    }
}

#[test]
fn even_server_msg_id_is_ignored() {
    let mut h = Harness::new();
    h.flush();
    let even = h.server.next_msg_id(true) & !3;
    assert_eq!(h.deliver_sealed(even, 1, &update(0x1234_5678, &[0; 4])), Err(SessionError::EvenServerMsgId(even)));
    assert!(h.events().is_empty());
    assert!(h.acks_after_delay().is_empty());
}

#[test]
fn duplicate_container_reacks_every_content_child() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let result_id = h.server.next_msg_id(true);
    let update_id = h.server.next_msg_id(false);
    let outer = h.server.next_msg_id(false);
    let body =
        container(&[(result_id, 1, rpc_result(query, &[1, 0, 0, 0])), (update_id, 3, update(0x1111_2222, &[0; 4]))]);
    let packet = h.server.seal(outer, 0, &body);
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    let events = h.events();
    assert_eq!(updates_of(&events), vec![0x1111_2222]);
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
    let mut acked = h.acks_after_delay();
    acked.sort_unstable();
    assert_eq!(acked, vec![result_id, update_id]);
    h.session.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    assert!(updates_of(&h.events()).is_empty(), "duplicates are not reprocessed");
    let mut reacked = h.acks_after_delay();
    reacked.sort_unstable();
    assert_eq!(reacked, vec![result_id, update_id], "children of a duplicate container are acked again");
}

#[test]
fn too_old_messages_are_acked_and_replayed_safely() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let old_result = h.server.next_msg_id(true);
    let old_update = h.server.next_msg_id(false);
    let old_outer = h.server.next_msg_id(false);
    for _ in 0..2100 {
        h.deliver(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]).unwrap();
    }
    h.events();
    h.advance(ACK_DELAY + 1.0);
    h.flush_all();
    let outer = h.server.next_msg_id(false);
    let body =
        container(&[(old_result, 1, rpc_result(query, &[7, 0, 0, 0])), (old_update, 3, update(0x0202_0202, &[0; 4]))]);
    h.deliver_sealed(outer, 0, &body).unwrap();
    let events = h.events();
    assert!(
        events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })),
        "pending query completes"
    );
    assert!(updates_of(&events).is_empty(), "an unverifiable update is not delivered twice");
    assert!(events.contains(&SessionEvent::UpdatesLost), "the host is told to fetch the difference");
    let acked = h.acks_after_delay();
    assert!(acked.contains(&old_result) && acked.contains(&old_update), "acked so the server stops resending");

    h.deliver_sealed(old_outer, 1, &update(0x0303_0303, &[0; 4])).unwrap();
    let events = h.events();
    assert!(updates_of(&events).is_empty());
    assert!(events.contains(&SessionEvent::UpdatesLost));
    assert!(h.acks_after_delay().contains(&old_outer));
}

#[test]
fn future_msg_id_glitch_is_recovered_through_a_freshness_proof() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let query = h.sent_query(&packet, 1);
    let ping = packet.find(ids::PING_DELAY_DISCONNECT).unwrap().clone();
    let glitch = msg_id_for_time(h.server.server_time + 1000.0) | 3;
    h.deliver_sealed(glitch, 1, &update(1, &[0; 4])).unwrap();
    assert_eq!(updates_of(&h.events()), vec![1]);
    let normal = msg_id_for_time(h.server.server_time) | 3;
    h.deliver_sealed(normal, 1, &update(2, &[0; 4])).unwrap();
    assert!(updates_of(&h.events()).is_empty(), "looks 1000 s old after the glitch and has no proof");
    let proof = msg_id_for_time(h.server.server_time + 0.01) | 1;
    let body = container(&[
        (proof + 4, 0, pong(ping.msg_id, ping_id_of(&ping).unwrap())),
        (proof + 8, 1, rpc_result(query, &[3, 0, 0, 0])),
    ]);
    h.deliver_sealed(proof + 12, 0, &body).unwrap();
    let events = h.events();
    assert!(has_forced_time_update(&events));
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
    let later = msg_id_for_time(h.server.server_time + 0.02) | 3;
    h.deliver_sealed(later, 1, &update(3, &[0; 4])).unwrap();
    assert_eq!(updates_of(&h.events()), vec![3]);
}

#[test]
fn wall_clock_jumps_do_not_move_server_time() {
    let mut h = Harness::new();
    h.sync();
    h.now.unix += 3600.0;
    h.deliver(vec![Outgoing::Content(update(5, &[0; 4]))]).unwrap();
    let events = h.events();
    assert_eq!(updates_of(&events), vec![5]);
    assert!(events.iter().any(
        |event| matches!(event, SessionEvent::TimeDifferenceUpdated { forced: true, difference } if (*difference + 3600.0).abs() < 1.0)
    ));
    assert!((h.session.time_difference() + 3600.0).abs() < 1.0);
    let query = h.sent_one(1);
    assert!((msg_id_time(query) - h.server.server_time).abs() < 2.0);
    h.now.unix -= 7200.0;
    let query = h.sent_one(2);
    assert!((msg_id_time(query) - h.server.server_time).abs() < 2.0);
}

#[test]
fn server_pings_are_answered_with_pongs() {
    let mut h = Harness::new();
    h.sync();
    let ping_msg = h.server.next_msg_id(false);
    let delayed_ping_msg = h.server.next_msg_id(false);
    let outer = h.server.next_msg_id(false);
    let body =
        container(&[(ping_msg, 0, server_ping(77)), (delayed_ping_msg, 0, server_ping_delay_disconnect(78, 75))]);
    h.deliver_sealed(outer, 0, &body).unwrap();
    assert!(h.events().is_empty(), "server pings are not updates");
    let packet = h.flush().expect("pong reply");
    let pongs: Vec<(i64, i64)> = packet
        .messages
        .iter()
        .filter(|message| message.constructor() == ids::PONG)
        .map(|message| {
            let mut reader = Reader::new(&message.body[4..]);
            (reader.read_i64().unwrap(), reader.read_i64().unwrap())
        })
        .collect();
    assert_eq!(pongs, vec![(ping_msg, 77), (delayed_ping_msg, 78)]);
    assert!(packet.messages.iter().filter(|m| m.constructor() == ids::PONG).all(|m| !m.is_content_related()));
}

#[test]
fn pong_for_unknown_ping_is_ignored() {
    let mut h = Harness::new();
    h.sync();
    let fake = msg_id_for_time(START + 100.0);
    h.deliver(vec![Outgoing::Service(pong(fake, fake))]).unwrap();
    let events = h.events();
    assert!(!events.iter().any(|event| matches!(event, SessionEvent::Pong { .. })));
    assert!(!has_forced_time_update(&events));
}

#[test]
fn responses_older_than_their_request_reset_the_clock() {
    let mut h = Harness::new();
    h.sync();
    h.session.set_time_difference(100.0);
    let query = h.sent_one(1);
    assert!(msg_id_time(query) > h.server.server_time + 99.0);
    h.deliver(vec![Outgoing::Content(rpc_result(query, &[1, 0, 0, 0]))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(
        |event| matches!(event, SessionEvent::TimeDifferenceUpdated { forced: true, difference } if difference.abs() < 1.0)
    ));

    let mut h = Harness::new();
    h.sync();
    h.session.set_time_difference(100.0);
    h.advance(70.0);
    let packet = h.flush().expect("ping");
    let ping = packet.find(ids::PING_DELAY_DISCONNECT).unwrap().clone();
    h.deliver(vec![Outgoing::Service(pong(ping.msg_id, ping_id_of(&ping).unwrap()))]).unwrap();
    let events = h.events();
    assert!(has_forced_time_update(&events));
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Pong { .. })));
}

#[test]
fn notifications_about_messages_we_never_sent_are_ignored() {
    let mut h = Harness::new();
    h.sync();
    let stranger = msg_id_for_time(START - 50.0);
    h.deliver(vec![
        Outgoing::Service(bad_server_salt(stranger, 0, 999)),
        Outgoing::Service(bad_msg_notification(stranger + 4, 0, 16)),
        Outgoing::Service(bad_msg_notification(stranger + 8, 0, 17)),
        Outgoing::Service(bad_msg_notification(stranger + 12, 0, 32)),
    ])
    .unwrap();
    let events = h.events();
    assert!(!events.iter().any(|event| matches!(event, SessionEvent::SaltsUpdated { .. })));
    assert!(!has_forced_time_update(&events));
    assert!(!events.iter().any(|event| matches!(event, SessionEvent::LocalSessionReset { .. })));
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    assert_eq!(h.flush().unwrap().header.salt, 101);
}

#[test]
fn every_bad_msg_notification_code_recovers_the_message() {
    for code in [16, 17, 18, 19, 20, 32, 33, 34, 35, 48, 64, 0, 99, -1] {
        let mut h = Harness::new();
        let old_session = h.session.session_id();
        let first = h.sent_one(1);
        h.deliver(vec![Outgoing::Service(bad_msg_notification(first, 1, code))]).unwrap();
        let events = h.events();
        let reset = events.iter().any(|event| matches!(event, SessionEvent::LocalSessionReset { .. }));
        assert_eq!(reset, matches!(code, 17 | 32 | 33), "code {code}");
        assert_eq!(reset, h.session.session_id() != old_session, "code {code}");
        assert_eq!(has_forced_time_update(&events), matches!(code, 16 | 17), "code {code}");
        assert!(!events.iter().any(|event| matches!(event, SessionEvent::Error { .. })), "code {code}");
        if code == 48 {
            let packet = h.flush().unwrap();
            assert_eq!(packet.constructors(), vec![ids::GET_FUTURE_SALTS], "queries wait for a valid salt");
            let now = h.server.server_time as i32;
            h.deliver(vec![Outgoing::Content(future_salts(
                packet.messages[0].msg_id,
                now,
                &[(now - 10, now + 1800, 555)],
            ))])
            .unwrap();
        }
        let packet = h.flush().unwrap();
        let second = h.sent_query(&packet, 1);
        assert!(second > first, "code {code}: resent with a fresh msg_id");
        if code == 48 {
            assert_eq!(packet.header.salt, 555);
        }
    }
}

#[test]
fn container_rejection_resends_every_child() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let container_id = packet.header.msg_id;
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    h.deliver(vec![Outgoing::Service(bad_msg_notification(container_id, 0, 64))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(h.sent_query(&packet, 1) > first);
    assert!(h.sent_query(&packet, 2) > second);
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_some(), "the ping in the rejected container is restarted");
}

#[test]
fn repeated_bug_class_rejections_fail_the_query_instead_of_looping() {
    let mut h = Harness::new();
    let mut msg_id = h.sent_one(1);
    for attempt in 1..=MAX_PROTOCOL_STRIKES {
        h.deliver(vec![Outgoing::Service(bad_msg_notification(msg_id, 1, 34))]).unwrap();
        let events = h.events();
        let failed = events.iter().any(|event| {
            matches!(event, SessionEvent::Error { id: QueryId(1), code: 500, message, .. } if message == "PROTOCOL_ERROR_BAD_MSG_34")
        });
        assert_eq!(failed, attempt == MAX_PROTOCOL_STRIKES);
        if attempt < MAX_PROTOCOL_STRIKES {
            let packet = h.flush().unwrap();
            msg_id = h.sent_query(&packet, 1);
        }
    }
    assert!(!h.session.has_queries());
    assert!(h.flush_all().iter().all(|packet| packet.messages.iter().all(|m| query_tag(&m.body).is_none())));
}

#[test]
fn bad_server_salt_inside_a_container_keeps_siblings() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    h.deliver(vec![
        Outgoing::Content(rpc_result(first, &[1, 0, 0, 0])),
        Outgoing::Service(bad_server_salt(second, 3, 4242)),
    ])
    .unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 0, 0, 0])]);
    let packet = h.flush().unwrap();
    assert_eq!(packet.header.salt, 4242);
    assert!(h.sent_query(&packet, 2) > second);
}

#[test]
fn new_session_created_never_resends_queries_answered_in_the_same_packet() {
    for result_first in [false, true] {
        let mut h = Harness::new();
        let query = h.sent_one(1);
        let notification = Outgoing::Content(new_session_created(query + 4, 42, 101));
        let answer = Outgoing::Content(rpc_result(query, &[9, 0, 0, 0]));
        let items = if result_first { vec![answer, notification] } else { vec![notification, answer] };
        h.deliver(items).unwrap();
        let events = h.events();
        assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
        assert!(events.iter().any(|event| matches!(event, SessionEvent::ServerSessionReset { unique_id: 42, .. })));
        assert!(h.flush_all().iter().all(|packet| packet.messages.iter().all(|m| query_tag(&m.body).is_none())));
    }
}

#[test]
fn duplicate_new_session_notifications_are_ignored() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let query = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Content(new_session_created(packet.header.msg_id + 4, 42, 101))]).unwrap();
    assert_eq!(h.events().iter().filter(|event| matches!(event, SessionEvent::ServerSessionReset { .. })).count(), 1);
    let packet = h.flush().unwrap();
    let resent = h.sent_query(&packet, 1);
    assert!(resent > query);
    h.deliver(vec![Outgoing::Content(new_session_created(packet.header.msg_id + 4, 42, 101))]).unwrap();
    assert!(!h.events().iter().any(|event| matches!(event, SessionEvent::ServerSessionReset { .. })));
    assert!(h.flush_all().iter().all(|packet| packet.messages.iter().all(|m| query_tag(&m.body).is_none())));
}

#[test]
fn new_session_created_salt_is_adopted() {
    let mut h = Harness::new();
    h.flush();
    h.deliver(vec![Outgoing::Content(new_session_created(1, 7, 31337))]).unwrap();
    assert!(h.events().iter().any(|event| matches!(event, SessionEvent::SaltsUpdated { .. })));
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    assert_eq!(h.flush().unwrap().header.salt, 31337);
}

#[test]
fn msg_copy_is_unwrapped_and_deduplicated() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let inner = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_copy(inner, 1, &rpc_result(query, &[5, 0, 0, 0])))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![5, 0, 0, 0])]);
    assert!(h.acks_after_delay().contains(&inner));
    h.deliver(vec![Outgoing::Service(msg_copy(inner, 1, &update(0x4444_4444, &[0; 4])))]).unwrap();
    assert!(updates_of(&h.events()).is_empty(), "the copy of an already received message is not processed again");
    assert!(h.acks_after_delay().contains(&inner), "and its original is acknowledged again");
}

#[test]
fn nested_containers_and_gzip_are_unwrapped() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let a = h.server.next_msg_id(true);
    let b = h.server.next_msg_id(false);
    let c = h.server.next_msg_id(false);
    let inner = container(&[(a, 1, rpc_result(query, &[8, 0, 0, 0]))]);
    let packed_update = gzip_packed(&update(0x5555_5555, &[1; 8]));
    let outer = container(&[(b, 0, inner), (c, 1, packed_update)]);
    h.deliver(vec![Outgoing::Service(gzip_packed(&outer))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
    assert_eq!(updates_of(&events), vec![0x5555_5555]);
    let mut acked = h.acks_after_delay();
    acked.sort_unstable();
    assert!(acked.contains(&a) && acked.contains(&c));
}

#[test]
fn container_children_with_even_msg_ids_are_skipped() {
    let mut h = Harness::new();
    h.flush();
    let good = h.server.next_msg_id(false);
    let even = (good + 64) & !3;
    let outer = h.server.next_msg_id(false) + 128;
    let body = container(&[(even, 1, update(0x6666_6666, &[0; 4])), (good, 1, update(0x7777_7777, &[0; 4]))]);
    h.deliver_sealed(outer, 0, &body).unwrap();
    assert_eq!(updates_of(&h.events()), vec![0x7777_7777]);
}

#[test]
fn malformed_and_unknown_children_do_not_break_the_container() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let ids_: Vec<i64> = (0..6).map(|_| h.server.next_msg_id(false)).collect();
    let truncated_bad_msg = bad_msg_notification(query, 1, 16)[..12].to_vec();
    let mut broken_gzip = Writer::new();
    broken_gzip.write_u32(ids::GZIP_PACKED);
    broken_gzip.write_bytes(&[0x1f, 0x8b, 1, 2, 3, 4]);
    let body = container(&[
        (ids_[0], 1, truncated_bad_msg),
        (ids_[1], 1, update(0xfeed_f00d, &[0; 12])),
        (ids_[2], 1, Vec::new()),
        (ids_[3], 1, broken_gzip.into_inner()),
        (ids_[4], 1, rpc_result(query, &[6, 0, 0, 0])),
    ]);
    let outer = h.server.next_msg_id(false);
    assert!(h.deliver_sealed(outer, 0, &body).is_ok());
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
    assert_eq!(updates_of(&events), vec![0xfeed_f00d], "unknown constructors are handed to the host");
    assert!(!has_forced_time_update(&events));
    let acked = h.acks_after_delay();
    for id in &ids_[..5] {
        assert!(acked.contains(id), "every content child is acked, even malformed ones");
    }
}

#[test]
fn broken_container_structure_is_reported() {
    let mut h = Harness::new();
    h.flush();
    let mut body = container(&[(h.server.next_msg_id(false), 1, update(1, &[0; 4]))]);
    body[4..8].copy_from_slice(&3i32.to_le_bytes());
    let outer = h.server.next_msg_id(false);
    assert!(matches!(h.deliver_sealed(outer, 0, &body), Err(SessionError::Malformed(_))));
    let mut body = container(&[(h.server.next_msg_id(false), 1, update(1, &[0; 4]))]);
    let length_offset = 8 + 12;
    body[length_offset..length_offset + 4].copy_from_slice(&400i32.to_le_bytes());
    let outer = h.server.next_msg_id(false);
    assert!(matches!(h.deliver_sealed(outer, 0, &body), Err(SessionError::Malformed(_))));
}

#[test]
fn unpacking_is_bounded_per_packet_and_by_depth() {
    let mut h = Harness::new();
    h.session = Session::new(
        SessionConfig { max_unpacked_bytes: 64 * 1024, ..SessionConfig::default() },
        key(),
        &h.session.salts(),
        0.0,
        h.now,
        &mut h.rng,
    );
    h.session.connection_opened(h.now);
    h.flush();
    let children: Vec<(i64, i32, Vec<u8>)> = (0..3u32)
        .map(|index| (h.server.next_msg_id(false), 1, gzip_packed(&update(0x1000 + index, &vec![0u8; 30 * 1024]))))
        .collect();
    h.deliver(vec![Outgoing::Service(container(&children))]).unwrap();
    assert_eq!(updates_of(&h.events()), vec![0x1000, 0x1001], "the third child exceeds the packet budget");
    let mut nested = update(0x2000, &[0; 4]);
    for _ in 0..(MAX_NESTING_DEPTH + 4) {
        nested = gzip_packed(&nested);
    }
    h.deliver(vec![Outgoing::Content(nested)]).unwrap();
    assert!(updates_of(&h.events()).is_empty());
}

#[test]
fn server_state_requests_get_precise_statuses() {
    let mut h = Harness::new();
    h.flush();
    let first = h.server.next_msg_id(false);
    let missing = h.server.next_msg_id(false);
    let last = h.server.next_msg_id(false);
    h.deliver_sealed(first, 1, &update(1, &[0; 4])).unwrap();
    h.deliver_sealed(last, 1, &update(2, &[0; 4])).unwrap();
    let older = first - 400;
    let newer = last + 400;
    h.deliver(vec![Outgoing::Service(msgs_state_req(&[first, missing, newer, last]))]).unwrap();
    let packet = h.flush().unwrap();
    let reply = packet.find(ids::MSGS_STATE_INFO).expect("reply");
    let mut reader = Reader::new(&reply.body[12..]);
    assert_eq!(reader.read_bytes().unwrap(), &[4, 2, 3, 4]);
    assert!(!reply.is_content_related());
    let _ = older;
    let mut filled = Harness::new();
    filled.flush();
    let ancient = filled.server.next_msg_id(false);
    for _ in 0..1001 {
        filled.deliver(vec![Outgoing::Content(update(3, &[0; 4]))]).unwrap();
    }
    filled.deliver(vec![Outgoing::Service(msgs_state_req(&[ancient]))]).unwrap();
    filled.events();
    let packets = filled.flush_all();
    let reply = packets.iter().find_map(|packet| packet.find(ids::MSGS_STATE_INFO)).expect("reply");
    let mut reader = Reader::new(&reply.body[12..]);
    assert_eq!(reader.read_bytes().unwrap(), &[1]);
}

#[test]
fn server_resend_request_retransmits_the_original_message_in_a_container() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let original = packet.messages.iter().find(|m| query_tag(&m.body) == Some(1)).unwrap().clone();
    h.deliver(vec![Outgoing::Service(msg_resend_req(&[original.msg_id]))]).unwrap();
    let packet = h.flush().unwrap();
    let copy = packet.messages.iter().find(|m| query_tag(&m.body) == Some(1)).expect("retransmitted");
    assert_eq!(copy.msg_id, original.msg_id);
    assert_eq!(copy.seq_no, original.seq_no);
    assert_eq!(copy.body, original.body);
    assert_eq!(copy.container_id, Some(packet.header.msg_id), "a resent message always travels in a fresh container");
    assert!(packet.header.msg_id > original.msg_id);
    assert!(packet.find(ids::MSGS_STATE_INFO).is_none());
    h.deliver(vec![Outgoing::Content(rpc_result(original.msg_id, &[1, 1, 1, 1]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 1, 1, 1])]);

    let unknown = original.msg_id + 4000;
    let request_id = h.server.next_msg_id(false);
    h.deliver_sealed(request_id, 0, &msg_resend_req(&[unknown])).unwrap();
    let packet = h.flush().unwrap();
    let reply = packet.find(ids::MSGS_STATE_INFO).expect("state info for unknown ids");
    let mut reader = Reader::new(&reply.body[4..]);
    assert_eq!(reader.read_i64().unwrap(), request_id);
    assert_eq!(reader.read_bytes().unwrap(), &[1]);
}

#[test]
fn server_resend_answer_request_gets_state_info() {
    let mut h = Harness::new();
    h.flush();
    let request_id = h.server.next_msg_id(false);
    h.deliver_sealed(request_id, 0, &msg_resend_ans_req(&[11, 15])).unwrap();
    let packet = h.flush().unwrap();
    let reply = packet.find(ids::MSGS_STATE_INFO).expect("reply");
    let mut reader = Reader::new(&reply.body[4..]);
    assert_eq!(reader.read_i64().unwrap(), request_id);
    assert_eq!(reader.read_bytes().unwrap(), &[1, 1]);
}

#[test]
fn future_salts_must_answer_our_request() {
    let mut h = Harness::with_salts(vec![]);
    let packet = h.flush().unwrap();
    let request = packet.messages[0].msg_id;
    let now = h.server.server_time as i32;
    h.deliver(vec![Outgoing::Service(bad_server_salt(request, 0, 900))]).unwrap();
    h.deliver(vec![Outgoing::Content(future_salts(
        request + 400,
        now,
        &[(now - 10, now + 1800, 1), (now + 1800, now + 3600, 2)],
    ))])
    .unwrap();
    assert_eq!(h.session.salts().iter().map(|salt| salt.salt).collect::<Vec<_>>(), vec![900]);
    h.deliver(vec![Outgoing::Content(future_salts(
        request,
        now,
        &[(now - 10, now + 1800, 3), (now + 1800, now + 3600, 4), (now + 50, now + 40, 5)],
    ))])
    .unwrap();
    let salts: Vec<i64> = h.session.salts().iter().map(|salt| salt.salt).collect();
    assert_eq!(salts, vec![3, 4], "inverted ranges are dropped");
}

#[test]
fn drop_answer_replies_are_silent_and_acked() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    assert!(matches!(h.session.cancel(QueryId(1)), CancelOutcome::RemovedInFlight { .. }));
    h.session.drop_answer(query, h.now);
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::RPC_DROP_ANSWER).is_some());
    let mut dropped = Vec::new();
    dropped.extend_from_slice(&query.to_le_bytes());
    dropped.extend_from_slice(&1i32.to_le_bytes());
    dropped.extend_from_slice(&64i32.to_le_bytes());
    h.deliver(vec![
        Outgoing::Content(rpc_answer(query, ids::RPC_ANSWER_UNKNOWN, &[])),
        Outgoing::Content(rpc_answer(query, ids::RPC_ANSWER_DROPPED_RUNNING, &[])),
        Outgoing::Content(rpc_answer(query, ids::RPC_ANSWER_DROPPED, &dropped)),
    ])
    .unwrap();
    assert!(!h.events().iter().any(|event| matches!(
        event,
        SessionEvent::Result { .. } | SessionEvent::Error { .. } | SessionEvent::Update { .. }
    )));
    assert_eq!(h.acks_after_delay().len(), 3);
}

#[test]
fn rpc_errors_are_sanitized_like_tdlib() {
    for (code, message, expected_code, expected_message) in [
        (0, b"ZERO".to_vec(), 500, "ZERO".to_string()),
        (10000, b"HUGE".to_vec(), 500, "HUGE".to_string()),
        (-10000, b"TINY".to_vec(), 500, "TINY".to_string()),
        (303, b"PHONE_MIGRATE_4".to_vec(), 303, "PHONE_MIGRATE_4".to_string()),
        (400, vec![0xff, 0xfe, 0x41], 400, "INVALID_UTF8_ERROR_MESSAGE".to_string()),
        (-503, b"Timeout".to_vec(), -503, "Timeout".to_string()),
    ] {
        let mut h = Harness::new();
        let query = h.sent_one(1);
        h.deliver(vec![Outgoing::Content(rpc_error_raw(query, code, &message))]).unwrap();
        let events = h.events();
        assert!(
            events.iter().any(|event| matches!(event, SessionEvent::Error { code, message, .. } if *code == expected_code && *message == expected_message)),
            "{code}: {events:?}"
        );
    }
}

#[test]
fn unparsable_results_fail_the_query_once() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let mut broken = Writer::new();
    broken.write_u32(ids::GZIP_PACKED);
    broken.write_bytes(&[1, 2, 3, 4, 5]);
    h.deliver(vec![Outgoing::Content(rpc_result(query, broken.as_slice()))]).unwrap();
    let events = h.events();
    assert!(events.iter().any(
        |event| matches!(event, SessionEvent::Error { id: QueryId(1), code: 500, message, .. } if message.starts_with(RESPONSE_UNPACK_FAILED))
    ));
    assert!(!h.session.has_queries());
}

#[test]
fn detailed_info_without_answer_resends_the_query() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    h.deliver(vec![Outgoing::Service(msg_detailed_info_status(query, 0, 0, 0))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(h.sent_query(&packet, 1) > query);
    assert!(packet.find(ids::MSG_RESEND_REQ).is_none());
}

#[test]
fn answer_resend_requests_resolve_or_fall_back_to_resending_the_query() {
    let mut h = Harness::new();
    let query = h.sent_one(1);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, answer, 100))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::MSG_RESEND_REQ).is_some());
    assert!(h.session.is_performing_service_tasks());
    h.deliver_sealed(answer, 1, &rpc_result(query, &[4, 4, 4, 4])).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![4, 4, 4, 4])]);
    assert!(!h.session.is_performing_service_tasks(), "a satisfied resend request no longer shows 'updating'");

    let query = h.sent_one(2);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, answer, 100))]).unwrap();
    let packet = h.flush().unwrap();
    let request = packet.find(ids::MSG_RESEND_REQ).unwrap().msg_id;
    h.deliver(vec![Outgoing::Service(msgs_state_info(request, &[1]))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(h.sent_query(&packet, 2) > query, "an answer the server cannot resend means the query is resent");

    let query = h.sent_one(3);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, answer, 100))]).unwrap();
    let mut requests = 0;
    let mut resent = None;
    for _ in 0..80 {
        h.advance(1.0);
        h.session.handle_timeout(h.now).unwrap();
        while let Some(packet) = h.flush() {
            h.answer_pings(&packet);
            if packet.find(ids::MSG_RESEND_REQ).is_some() {
                requests += 1;
            }
            if let Some(message) = packet.messages.iter().find(|m| query_tag(&m.body) == Some(3)) {
                resent = Some(message.msg_id);
            }
        }
    }
    assert_eq!(requests, MAX_ANSWER_REQUESTS as usize);
    assert!(resent.is_some_and(|id| id > query), "unanswered resend requests fall back to resending the query");
    assert!(!h.session.is_performing_service_tasks() || h.session.has_unanswered_queries());
}

#[test]
fn state_info_with_mismatched_length_is_ignored() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.flush().unwrap();
    h.session.connection_closed();
    h.advance(RETRANSMIT_WINDOW + 1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    let request = packet.find(ids::MSGS_STATE_REQ).unwrap().msg_id;
    h.deliver(vec![Outgoing::Service(msgs_state_info(request, &[4, 4]))]).unwrap();
    assert!(h.session.has_unknown_queries());
    assert!(h.flush_all().iter().all(|packet| packet.messages.iter().all(|m| query_tag(&m.body).is_none())));
}

#[test]
fn unknown_queries_stuck_for_a_minute_close_the_connection_after_processing() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let second = h.sent_query(&packet, 2);
    h.session.connection_closed();
    h.advance(RETRANSMIT_WINDOW + 1.0);
    h.session.connection_opened(h.now);
    let mut outcome = Ok(());
    for _ in 0..70 {
        h.advance(1.0);
        h.session.handle_timeout(h.now).unwrap();
        while let Some(packet) = h.flush() {
            if let Some(ping) = packet.find(ids::PING_DELAY_DISCONNECT) {
                let reply = vec![
                    Outgoing::Service(pong(ping.msg_id, ping_id_of(ping).unwrap())),
                    Outgoing::Content(rpc_result(second, &[2, 0, 0, 0])),
                ];
                outcome = h.deliver(reply);
            }
        }
        if outcome.is_err() {
            break;
        }
    }
    assert_eq!(outcome, Err(SessionError::UnknownQueriesStuck));
    assert!(h.results().iter().any(|(id, _)| *id == QueryId(2)), "siblings of the pong are still processed");
}

#[test]
fn service_queues_are_bounded() {
    let mut h = Harness::new();
    h.sync();
    for index in 0..(MAX_QUEUED_ACKS as i64 * 2) {
        h.session.schedule_ack(index * 4 + 1, h.now);
    }
    assert_eq!(h.session.to_ack.len(), MAX_QUEUED_ACKS);
    for index in 0..(MAX_QUEUED_SERVICE_REPLIES * 3) as i64 {
        let id = h.server.next_msg_id(false);
        h.deliver_sealed(id, 0, &server_ping(index)).unwrap();
        h.deliver(vec![Outgoing::Service(msgs_state_req(&[index]))]).unwrap();
    }
    assert!(h.session.to_pong.len() <= MAX_QUEUED_SERVICE_REPLIES);
    assert!(h.session.to_state_info_reply.len() <= MAX_QUEUED_SERVICE_REPLIES);
}

#[test]
fn offline_session_with_a_pending_query_detects_a_dead_connection_fast() {
    let mut h = Harness::new();
    h.flush_all();
    h.advance(100.0);
    h.flush_all();
    let started = h.now.mono;
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.flush().unwrap();
    let mut failed_at = None;
    for _ in 0..200 {
        h.advance(0.25);
        h.flush_all();
        if let Err(error) = h.session.handle_timeout(h.now) {
            failed_at = Some((h.now.mono - started, error));
            break;
        }
    }
    let (elapsed, error) = failed_at.expect("dead connection detected");
    assert_eq!(error, SessionError::ReadTimeout);
    assert!((6.9..=8.0).contains(&elapsed), "detected after {elapsed} s");
    let deadline = h.session.poll_timeout(h.now);
    assert!(deadline.is_some());
}

#[test]
fn offline_idle_session_keeps_the_long_timeout() {
    let mut h = Harness::new();
    h.flush_all();
    let started = h.now.mono;
    let mut failed_at = None;
    for _ in 0..400 {
        h.advance(1.0);
        h.flush_all();
        if h.session.handle_timeout(h.now).is_err() {
            failed_at = Some(h.now.mono - started);
            break;
        }
    }
    let elapsed = failed_at.expect("eventually times out");
    assert!(elapsed >= 135.0, "idle offline sessions wait {elapsed} s");
}

#[test]
fn slow_link_trickling_bytes_never_times_out() {
    for online in [false, true] {
        let mut h = Harness::new();
        h.session.set_online(online, h.now);
        h.flush_all();
        h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
        h.flush().unwrap();
        for _ in 0..30 {
            for _ in 0..8 {
                h.advance(0.25);
                h.flush_all();
                assert!(h.session.handle_timeout(h.now).is_ok(), "online={online}");
            }
            h.session.note_bytes_received(h.now);
        }
    }
}

#[test]
fn reconnect_sends_a_ping_immediately() {
    let mut h = Harness::new();
    h.flush_all();
    h.advance(10.0);
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    let packet = h.flush().expect("ping right after reconnect");
    assert!(packet.find(ids::PING_DELAY_DISCONNECT).is_some());
}

#[test]
fn rejected_connection_requeues_only_unacknowledged_queries() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    h.deliver(vec![Outgoing::Service(msgs_ack(&[first]))]).unwrap();
    let second = h.sent_one(2);
    h.session.connection_rejected(h.now);
    assert!(!h.session.is_connected());
    h.session.connection_opened(h.now);
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::MSGS_STATE_REQ).is_none(), "nothing is unknown");
    let tags: Vec<u32> = packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect();
    assert_eq!(tags, vec![2]);
    assert!(h.sent_query(&packet, 2) > second);
    h.deliver(vec![Outgoing::Content(rpc_result(first, &[1, 0, 0, 0]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 0, 0, 0])]);
}

#[test]
fn destroy_responses_are_handled() {
    let mut h = Harness::new();
    h.sync();
    let mut session_ok = Writer::new();
    session_ok.write_u32(ids::DESTROY_SESSION_OK);
    session_ok.write_i64(5);
    let mut session_none = Writer::new();
    session_none.write_u32(ids::DESTROY_SESSION_NONE);
    session_none.write_i64(6);
    h.deliver(vec![
        Outgoing::Service(session_ok.into_inner()),
        Outgoing::Service(session_none.into_inner()),
        Outgoing::Service(update(ids::DESTROY_AUTH_KEY_OK, &[])),
    ])
    .unwrap();
    assert!(h.events().is_empty(), "unsolicited destroy results are ignored");
    h.session.request_destroy_auth_key();
    let packet = h.flush().unwrap();
    assert!(packet.find(ids::DESTROY_AUTH_KEY).is_some());
    for (constructor, outcome) in [
        (ids::DESTROY_AUTH_KEY_OK, DestroyAuthKeyOutcome::Ok),
        (ids::DESTROY_AUTH_KEY_NONE, DestroyAuthKeyOutcome::None),
        (ids::DESTROY_AUTH_KEY_FAIL, DestroyAuthKeyOutcome::Fail),
    ] {
        h.deliver(vec![Outgoing::Service(update(constructor, &[]))]).unwrap();
        assert_eq!(h.events(), vec![SessionEvent::DestroyAuthKey { outcome }]);
    }
}

#[test]
fn mtproto_service_constructors_are_never_forwarded_as_updates() {
    let mut h = Harness::new();
    h.flush();
    let mut items = Vec::new();
    for constructor in [
        ids::HTTP_WAIT,
        ids::RPC_ERROR,
        ids::RPC_ANSWER_UNKNOWN,
        ids::FUTURE_SALT,
        ids::MESSAGE,
        ids::VECTOR,
        ids::GET_FUTURE_SALTS,
        ids::RPC_DROP_ANSWER,
        ids::DESTROY_SESSION,
        ids::RES_PQ,
        ids::DH_GEN_OK,
        ids::REQ_PQ_MULTI,
        ids::DESTROY_SESSIONS_RES,
    ] {
        items.push(Outgoing::Content(update(constructor, &[0; 12])));
    }
    h.deliver(items).unwrap();
    assert!(updates_of(&h.events()).is_empty());
    assert_eq!(h.acks_after_delay().len(), 13, "content-related service objects are still acked");
}

#[test]
fn msgs_all_info_drives_resend_and_ack() {
    let mut h = Harness::new();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let first = h.sent_query(&packet, 1);
    let second = h.sent_query(&packet, 2);
    h.deliver(vec![Outgoing::Service(msgs_all_info(&[first, second], &[4 | 8, 2]))]).unwrap();
    assert!(h.events().iter().any(|event| matches!(event, SessionEvent::Acknowledged { id: QueryId(1) })));
    let packet = h.flush().unwrap();
    assert_eq!(packet.messages.iter().filter_map(|m| query_tag(&m.body)).collect::<Vec<_>>(), vec![2]);
}

#[test]
fn outgoing_msg_ids_stay_monotonic_when_the_clock_moves_back() {
    let mut h = Harness::new();
    let mut previous = 0i64;
    for step in 0..20u32 {
        if step % 3 == 0 {
            h.session.set_time_difference(-(step as f64) * 50.0);
        }
        let id = h.sent_one(step + 1);
        assert!(id > previous);
        assert_eq!(id % 4, 0);
        assert_ne!(id & 0xffff_ffff, 0);
        previous = id;
    }
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Item {
        Garbage(Vec<u8>),
        Service { kind: u8, a: usize, b: usize, value: i64, truncate: Option<usize> },
        Container(Vec<(u8, Item)>),
        Gzip(Box<Item>),
        Copy(u8, Box<Item>),
    }

    fn leaf() -> impl Strategy<Value = Item> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..48).prop_map(Item::Garbage),
            (0u8..20, any::<usize>(), any::<usize>(), any::<i64>(), proptest::option::of(0usize..40))
                .prop_map(|(kind, a, b, value, truncate)| Item::Service { kind, a, b, value, truncate }),
        ]
    }

    fn item() -> impl Strategy<Value = Item> {
        leaf().prop_recursive(3, 24, 6, |inner| {
            prop_oneof![
                proptest::collection::vec((any::<u8>(), inner.clone()), 0..6).prop_map(Item::Container),
                inner.clone().prop_map(|item| Item::Gzip(Box::new(item))),
                (any::<u8>(), inner).prop_map(|(choice, item)| Item::Copy(choice, Box::new(item))),
            ]
        })
    }

    #[derive(Debug, Clone)]
    struct Packet {
        outer: u8,
        seq: i32,
        item: Item,
        advance: u8,
    }

    fn packet() -> impl Strategy<Value = Packet> {
        (any::<u8>(), any::<i32>(), item(), any::<u8>()).prop_map(|(outer, seq, item, advance)| Packet {
            outer,
            seq,
            item,
            advance,
        })
    }

    struct Pools {
        ours: Vec<i64>,
        theirs: Vec<i64>,
    }

    impl Pools {
        fn pick(list: &[i64], index: usize, fallback: i64) -> i64 {
            if list.is_empty() { fallback } else { list[index % list.len()] }
        }

        fn ours(&self, index: usize) -> i64 {
            Self::pick(&self.ours, index, index as i64)
        }

        fn theirs(&self, index: usize) -> i64 {
            Self::pick(&self.theirs, index, (index as i64) | 1)
        }
    }

    fn service(kind: u8, a: usize, b: usize, value: i64, pools: &Pools, server: &mut ServerPeer) -> Vec<u8> {
        let ours = pools.ours(a);
        let theirs = pools.theirs(b);
        let small = (value & 0xff) as i32;
        match kind {
            0 => rpc_result(ours, &value.to_le_bytes()),
            1 => rpc_error_raw(ours, small - 128, &value.to_le_bytes()),
            2 => pong(ours, pools.ours(b)),
            3 => bad_msg_notification(ours, small, [16, 17, 18, 19, 20, 32, 33, 34, 35, 48, 64, small][b % 12]),
            4 => bad_server_salt(ours, small, value),
            5 => new_session_created(ours, value, value.rotate_left(7)),
            6 => msgs_ack(&[ours, pools.ours(b)]),
            7 => msg_detailed_info_status(ours, theirs, small, small >> 2),
            8 => msg_new_detailed_info(theirs, small),
            9 => msgs_state_info(ours, &value.to_le_bytes()[..(b % 9)]),
            10 => msgs_all_info(&[ours, pools.ours(b)], &value.to_le_bytes()[..(b % 3)]),
            11 => msgs_state_req(&[theirs, value]),
            12 => msg_resend_req(&[ours, value]),
            13 => msg_resend_ans_req(&[theirs]),
            14 => {
                let now = server.server_time as i32;
                future_salts(ours, now, &[(now - small, now + small * 10, value), (now + 5, now - 5, value + 1)])
            }
            15 => server_ping(value),
            16 => update(
                [ids::DESTROY_AUTH_KEY_OK, ids::DESTROY_SESSION_OK, ids::HTTP_WAIT, ids::RPC_ANSWER_UNKNOWN][b % 4],
                &[0; 12],
            ),
            17 => update(0x74ae_4240, &value.to_le_bytes()),
            18 => rpc_answer(ours, ids::GZIP_PACKED, &value.to_le_bytes()),
            _ => update(value as u32, &[]),
        }
    }

    fn build(item: &Item, pools: &Pools, server: &mut ServerPeer) -> Vec<u8> {
        match item {
            Item::Garbage(bytes) => bytes.clone(),
            Item::Service { kind, a, b, value, truncate } => {
                let mut body = service(*kind, *a, *b, *value, pools, server);
                if let Some(cut) = truncate {
                    body.truncate((*cut).max(4).min(body.len()));
                }
                body
            }
            Item::Container(children) => {
                let messages: Vec<(i64, i32, Vec<u8>)> = children
                    .iter()
                    .map(|(choice, child)| {
                        let msg_id = match choice % 5 {
                            0 => pools.theirs(*choice as usize),
                            1 => server.next_msg_id(true) & !1,
                            _ => server.next_msg_id(choice % 2 == 0),
                        };
                        (msg_id, i32::from(*choice), build(child, pools, server))
                    })
                    .collect();
                container(&messages)
            }
            Item::Gzip(inner) => gzip_packed(&build(inner, pools, server)),
            Item::Copy(choice, inner) => {
                let msg_id = if choice % 2 == 0 { pools.theirs(*choice as usize) } else { server.next_msg_id(true) };
                msg_copy(msg_id, i32::from(*choice), &build(inner, pools, server))
            }
        }
    }

    fn collect_ours(pools: &mut Pools, packet: &DecodedPacket) {
        pools.ours.push(packet.header.msg_id);
        pools.ours.extend(packet.messages.iter().map(|message| message.msg_id));
        if pools.ours.len() > 64 {
            let excess = pools.ours.len() - 64;
            pools.ours.drain(..excess);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn arbitrary_server_packets_never_panic_and_state_stays_bounded(packets in proptest::collection::vec(packet(), 1..40)) {
            let mut h = Harness::new();
            let mut pools = Pools { ours: Vec::new(), theirs: Vec::new() };
            for tag in 1..=4u32 {
                h.session.send(QueryId(tag as u64), query_body(tag), QueryOptions { quick_ack: tag % 2 == 0, invoke_after: None }, h.now);
            }
            if let Some(packet) = h.flush() {
                collect_ours(&mut pools, &packet);
            }
            for (index, packet) in packets.iter().enumerate() {
                let body = build(&packet.item, &pools, &mut h.server);
                let mut body = body;
                body.resize(body.len().div_ceil(4) * 4, 0);
                let msg_id = match packet.outer % 7 {
                    0 => pools.theirs(packet.outer as usize),
                    1 => msg_id_for_time(h.server.server_time - 400.0) | 1,
                    2 => msg_id_for_time(h.server.server_time + 400.0) | 3,
                    3 => h.server.next_msg_id(true) & !1,
                    _ => h.server.next_msg_id(packet.outer % 2 == 0),
                };
                pools.theirs.push(msg_id);
                let sealed = h.server.seal(msg_id, packet.seq, &body);
                let _ = h.session.handle_packet(&sealed, h.now, &mut h.rng);
                h.events();
                if index % 3 == 0 {
                    h.session.handle_quick_ack(packet.seq as u32);
                }
                h.advance(f64::from(packet.advance) * 0.05);
                if h.session.handle_timeout(h.now).is_err() {
                    h.session.connection_closed();
                    h.session.connection_opened(h.now);
                }
                for _ in 0..4 {
                    match h.flush() {
                        Some(sent) => collect_ours(&mut pools, &sent),
                        None => break,
                    }
                }
                h.events();
                prop_assert!(h.session.footprint() < 40_000, "footprint {}", h.session.footprint());
            }
        }
    }
}

#[test]
fn only_odd_seqno_messages_are_acked() {
    let mut h = Harness::new();
    h.sync();
    let even = h.server.next_msg_id(false);
    let odd = h.server.next_msg_id(false);
    h.deliver_sealed(even, 2, &update(0x1357_9bdf, &[0; 4])).unwrap();
    h.deliver_sealed(odd, 3, &update(0x2468_ace0, &[0; 4])).unwrap();
    assert_eq!(updates_of(&h.events()), vec![0x1357_9bdf, 0x2468_ace0]);
    let acked = h.acks_after_delay();
    assert!(acked.contains(&odd));
    assert!(!acked.contains(&even));
}

#[test]
fn msg_new_detailed_info_requests_an_unseen_answer() {
    let mut h = Harness::new();
    h.sync();
    let answer = h.server.next_msg_id(false);
    h.deliver(vec![Outgoing::Service(msg_new_detailed_info(answer, 64))]).unwrap();
    let packet = h.flush().unwrap();
    let request = packet.find(ids::MSG_RESEND_REQ).expect("resend request");
    assert_eq!(read_vector_after_constructor(&request.body), vec![answer]);
    assert!(!request.is_content_related());
    h.deliver_sealed(answer, 1, &update(0x0f0f_0f0f, &[0; 4])).unwrap();
    assert_eq!(updates_of(&h.events()), vec![0x0f0f_0f0f]);
    assert!(!h.session.is_performing_service_tasks());
}

#[test]
fn rpc_result_for_unknown_or_zero_request_is_dropped_and_acked() {
    let mut h = Harness::new();
    h.sync();
    let result_id = h.server.next_msg_id(true);
    let zero_id = h.server.next_msg_id(true);
    h.deliver_sealed(result_id, 1, &rpc_result(msg_id_for_time(START) + 400, &[1, 2, 3, 4])).unwrap();
    h.deliver_sealed(zero_id, 1, &rpc_result(0, &[1, 2, 3, 4])).unwrap();
    assert!(h.events().is_empty());
    let acked = h.acks_after_delay();
    assert!(acked.contains(&result_id) && acked.contains(&zero_id));
}

#[test]
fn incoming_salt_is_not_validated() {
    let mut h = Harness::new();
    h.sync();
    h.server.salt = 0x00dd_5a17;
    h.deliver(vec![Outgoing::Content(update(0x3141_5926, &[0; 4]))]).unwrap();
    assert_eq!(updates_of(&h.events()), vec![0x3141_5926]);
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    assert_eq!(
        h.flush().unwrap().header.salt,
        101,
        "only bad_server_salt, future_salts and new_session_created change our salt"
    );
}

#[test]
fn empty_containers_and_empty_bodies_are_harmless() {
    let mut h = Harness::new();
    h.sync();
    let empty_container = h.server.next_msg_id(false);
    h.deliver_sealed(empty_container, 0, &container(&[])).unwrap();
    let empty_body = h.server.next_msg_id(false);
    h.deliver_sealed(empty_body, 1, &[]).unwrap();
    let short_body = h.server.next_msg_id(false);
    h.deliver_sealed(short_body, 1, &[0xcc; 4][..2].iter().chain(&[0, 0]).copied().collect::<Vec<u8>>()).unwrap();
    let events = h.events();
    assert!(!events.iter().any(|event| matches!(event, SessionEvent::LocalSessionReset { .. })));
    let acked = h.acks_after_delay();
    assert!(acked.contains(&empty_body) && acked.contains(&short_body));
    assert!(!acked.contains(&empty_container));
}

fn flood_newer_messages(h: &mut Harness, count: usize) {
    for chunk in 0..count.div_ceil(100) {
        let children: Vec<(i64, i32, Vec<u8>)> = (0..100)
            .map(|index| (h.server.next_msg_id(false), 1, update(0x7000_0000 + (chunk * 100 + index) as u32, &[0; 4])))
            .collect();
        h.deliver(vec![Outgoing::Service(container(&children))]).unwrap();
    }
    h.events();
}

#[test]
fn hostile_detailed_info_fan_out_stays_bounded() {
    let mut h = Harness::new();
    h.sync();
    let started = std::time::Instant::now();
    for _ in 0..3 {
        let mut outer = Vec::new();
        for _ in 0..64 {
            let children: Vec<(i64, i32, Vec<u8>)> = (0..400)
                .map(|_| {
                    let answer = h.server.next_msg_id(true);
                    (h.server.next_msg_id(true), 0, msg_new_detailed_info(answer, 100))
                })
                .collect();
            outer.push((h.server.next_msg_id(false), 0, container(&children)));
        }
        let packet_id = h.server.next_msg_id(false);
        let _ = h.deliver_sealed(packet_id, 0, &container(&outer));
    }
    assert!(h.session.awaited_answers.len() <= MAX_AWAITED_ANSWERS, "{}", h.session.awaited_answers.len());
    h.session.connection_closed();
    h.session.connection_opened(h.now);
    assert!(h.session.to_resend_answer.len() <= MAX_AWAITED_ANSWERS);
    assert!(started.elapsed() < std::time::Duration::from_secs(3), "{:?}", started.elapsed());
}

#[test]
fn gzip_bombs_are_refused_without_unpacking_them() {
    let mut h = Harness::new();
    h.session = Session::new(
        SessionConfig { max_unpacked_bytes: 1 << 20, ..SessionConfig::default() },
        key(),
        &h.session.salts(),
        0.0,
        h.now,
        &mut h.rng,
    );
    h.session.connection_opened(h.now);
    h.flush();
    let mut lying = crate::tl::mtproto::gzip(&vec![0u8; 2 << 20]);
    let trailer = lying.len() - 4;
    lying[trailer..].copy_from_slice(&64u32.to_le_bytes());
    let mut writer = Writer::new();
    writer.write_u32(ids::GZIP_PACKED);
    writer.write_bytes(&lying);
    let bomb = writer.into_inner();
    let honest = gzip_packed(&vec![0u8; 2 << 20]);
    let mut children: Vec<(i64, i32, Vec<u8>)> = (0..400)
        .map(|index| (h.server.next_msg_id(false), 1, if index % 2 == 0 { bomb.clone() } else { honest.clone() }))
        .collect();
    children.push((h.server.next_msg_id(false), 1, gzip_packed(&update(0x4242_4242, &[0; 64]))));
    let started = std::time::Instant::now();
    h.deliver(vec![Outgoing::Service(container(&children))]).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(300), "{:?}", started.elapsed());
    assert_eq!(updates_of(&h.events()), vec![0x4242_4242], "bombs are refused without unpacking them");
}

#[test]
fn replayed_old_salt_and_bad_msg_notifications_are_ignored() {
    let mut h = Harness::new();
    h.sync();
    let query = h.sent_one(1);
    let salt_id = h.server.next_msg_id(false);
    let recorded_salt = h.server.seal(salt_id, 0, &bad_server_salt(query, 0, 999));
    h.session.handle_packet(&recorded_salt, h.now, &mut h.rng).unwrap();
    assert_eq!(h.session.salts.current_value(), 999);
    let resent = h.flush_all();
    let resent_query = resent.iter().flat_map(|packet| packet.queries()).map(|message| message.msg_id).next().unwrap();
    h.server.salt = 999;
    let notice_id = h.server.next_msg_id(false);
    let recorded_notice = h.server.seal(notice_id, 0, &bad_msg_notification(resent_query, 0, 16));
    let _ = h.session.handle_packet(&recorded_notice, h.now, &mut h.rng);
    h.flush_all();
    h.events();
    flood_newer_messages(&mut h, 2500);
    let fresh = h.sent_one(2);
    h.deliver(vec![Outgoing::Service(bad_server_salt(fresh, 0, 777))]).unwrap();
    assert_eq!(h.session.salts.current_value(), 777);
    h.flush_all();
    h.events();
    let session_id = h.session.session_id();
    let time_difference = h.session.time_difference();
    let _ = h.session.handle_packet(&recorded_salt, h.now, &mut h.rng);
    let _ = h.session.handle_packet(&recorded_notice, h.now, &mut h.rng);
    assert_eq!(h.session.salts.current_value(), 777, "a replayed salt is not applied");
    assert_eq!(h.session.session_id(), session_id);
    assert_eq!(h.session.time_difference(), time_difference, "a replayed notification does not move the clock");
    let events = h.events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            SessionEvent::SaltsUpdated { .. } | SessionEvent::TimeDifferenceUpdated { .. }
        )),
        "{events:?}"
    );
}

#[test]
fn an_answer_redelivered_with_an_evicted_msg_id_still_completes_its_query() {
    let mut h = Harness::new();
    h.sync();
    let query = h.sent_one(1);
    let answer_id = h.server.next_msg_id(true);
    flood_newer_messages(&mut h, 1100);
    h.deliver_sealed(answer_id, 1, &rpc_result(query, &[9, 0, 0, 0])).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![9, 0, 0, 0])]);
}

#[test]
fn a_server_rejecting_every_send_cannot_hold_a_query_in_a_resend_loop() {
    let mut h = Harness::new();
    h.sync();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    let mut sends = 0;
    let mut salt = 500;
    for _ in 0..200 {
        h.advance(0.01);
        let packets = h.flush_all();
        let sent: Vec<i64> = packets
            .iter()
            .flat_map(|packet| packet.messages.iter())
            .filter(|message| query_tag(&message.body) == Some(1))
            .map(|message| message.msg_id)
            .collect();
        sends += sent.len();
        for msg_id in sent {
            salt += 1;
            h.server.salt = salt - 1;
            h.deliver(vec![Outgoing::Service(bad_server_salt(msg_id, 1, salt))]).unwrap();
        }
        let failed = h.events().into_iter().any(|event| {
            matches!(event, SessionEvent::Error { id: QueryId(1), code: 500, ref message, .. } if message == PROTOCOL_REJECTED)
        });
        if failed {
            assert!(sends as u32 <= MAX_QUERY_REJECTIONS + 1, "{sends} sends before giving up");
            return;
        }
    }
    panic!("the query was resent {sends} times without ever failing");
}

#[test]
fn a_server_cannot_make_the_client_upload_a_query_forever() {
    let mut h = Harness::new();
    h.sync();
    let big = {
        let mut body = query_body(1);
        body.extend(std::iter::repeat_n(0x5a, 256 * 1024));
        body
    };
    h.session.send(QueryId(1), big, QueryOptions::default(), h.now);
    let mut uploads = 0;
    for _ in 0..100 {
        h.advance(0.05);
        let packets = h.flush_all();
        let sent: Vec<i64> = packets
            .iter()
            .flat_map(|packet| packet.messages.iter())
            .filter(|message| query_tag(&message.body) == Some(1))
            .map(|message| message.msg_id)
            .collect();
        uploads += sent.len();
        for msg_id in sent {
            h.deliver(vec![Outgoing::Service(msg_resend_req(&[msg_id]))]).unwrap();
        }
    }
    assert!(uploads as u32 <= MAX_SERVER_RESENDS + 1, "{uploads} uploads of the same query");
}

#[test]
fn outgoing_containers_never_exceed_1024_messages() {
    let mut h = Harness::new();
    h.sync();
    for tag in 0..1500u32 {
        h.session.send(QueryId(tag as u64 + 1), query_body(tag), QueryOptions::default(), h.now);
    }
    h.flush_all();
    let sent: Vec<i64> = (0..1500u64).filter_map(|tag| h.session.query_msg_id(QueryId(tag + 1))).collect();
    assert_eq!(sent.len(), 1500);
    for tag in 0..1500u64 {
        let _ = h.session.cancel(QueryId(tag + 1));
    }
    for msg_id in sent {
        h.session.drop_answer(msg_id, h.now);
    }
    let mut drops = 0;
    for _ in 0..10 {
        h.advance(0.01);
        let Some(transmit) = h.session.poll_transmit(h.now, &mut h.rng) else {
            break;
        };
        let packet = h.server.decode(&transmit.data);
        assert!(
            packet.messages.len() <= MAX_CONTAINER_MESSAGES_OUT,
            "{} messages in one container",
            packet.messages.len()
        );
        drops += packet.messages.iter().filter(|message| message.constructor() == ids::RPC_DROP_ANSWER).count();
    }
    assert_eq!(drops, 1500, "every cancelled query's answer is dropped eventually");
}

#[test]
fn a_failed_batched_answer_request_is_retried_one_by_one_before_any_query_is_resent() {
    let mut h = Harness::new();
    h.sync();
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    let packet = h.flush().unwrap();
    let (first, second) = (h.sent_query(&packet, 1), h.sent_query(&packet, 2));
    let (answer_one, answer_two) = (h.server.next_msg_id(true), h.server.next_msg_id(true));
    h.deliver(vec![
        Outgoing::Service(msg_detailed_info(first, answer_one, 100)),
        Outgoing::Service(msg_detailed_info(second, answer_two, 100)),
    ])
    .unwrap();
    let packet = h.flush().unwrap();
    let batch = packet.find(ids::MSG_RESEND_REQ).unwrap();
    assert_eq!(read_vector_after_constructor(&batch.body).len(), 2);
    h.deliver(vec![Outgoing::Service(msgs_state_info(batch.msg_id, &[4, 1]))]).unwrap();
    let packet = h.flush().unwrap();
    assert!(packet.queries().is_empty(), "no query is resent while one of the answers may still exist");
    let singles: Vec<(i64, Vec<i64>)> = packet
        .messages
        .iter()
        .filter(|message| message.constructor() == ids::MSG_RESEND_REQ)
        .map(|message| (message.msg_id, read_vector_after_constructor(&message.body)))
        .collect();
    assert_eq!(singles.len(), 2);
    assert!(singles.iter().all(|(_, ids)| ids.len() == 1));
    h.deliver_sealed(answer_one, 1, &rpc_result(first, &[1, 1, 1, 1])).unwrap();
    let missing = singles.iter().find(|(_, ids)| ids[0] == answer_two).unwrap().0;
    h.deliver(vec![Outgoing::Service(msgs_state_info(missing, &[1]))]).unwrap();
    let packet = h.flush().unwrap();
    let resent: Vec<u32> = packet.queries().iter().filter_map(|message| query_tag(&message.body)).collect();
    assert_eq!(resent, vec![2], "only the query whose answer is gone is resent");
    assert_eq!(h.results(), vec![(QueryId(1), vec![1, 1, 1, 1])]);
}
