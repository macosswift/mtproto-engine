use super::*;

fn long_salt_harness() -> Harness {
    let mut h = Harness::with_salts(vec![ServerSalt {
        salt: 101,
        valid_since: START - 100.0,
        valid_until: START + 10_000_000.0,
    }]);
    h.sync();
    h
}

/// Answers the ask for `answer` with "no such message"; false when it was not asked for.
fn reply_gone(h: &mut Harness, answer: i64) -> bool {
    let ask = h
        .flush_all()
        .iter()
        .flat_map(|packet| packet.messages.iter())
        .find(|m| m.constructor() == ids::MSG_RESEND_REQ && read_vector_after_constructor(&m.body).contains(&answer))
        .map(|m| m.msg_id);
    let Some(ask) = ask else {
        return false;
    };
    h.deliver(vec![Outgoing::Service(msgs_state_info(ask, &[2]))]).unwrap();
    true
}

fn answer_lost_for_call_1(events: &[SessionEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event, SessionEvent::Error { id: QueryId(1), code: 500, message, .. } if message == ANSWER_LOST)
    })
}

fn asks_in(packet: &DecodedPacket) -> Vec<i64> {
    packet
        .messages
        .iter()
        .filter(|message| message.constructor() == ids::MSG_RESEND_REQ)
        .flat_map(|message| read_vector_after_constructor(&message.body))
        .collect()
}

/// HTTP: an answer announced with msg_new_detailed_info (no query) is fetched only after an outage longer
/// than the time window. The server re-sends it under its old msg_id and re-announces it in every other
/// response while it stays unacknowledged: the requested message is taken and acknowledged, so it is
/// asked for once and the session does not stay "updating".
#[test]
fn an_unattributed_answer_fetched_after_a_long_outage_over_http_is_taken() {
    let mut h = long_salt_harness();
    h.session.set_http(true);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_new_detailed_info(answer, 100))]).unwrap();
    h.session.connection_closed();
    h.advance(400.0);
    h.session.connection_opened(h.now);
    let (mut asks, mut acked, mut busy) = (0, false, 0);
    let mut next_poll_return = h.now.mono + 10.0;
    for _ in 0..600 {
        h.advance(0.5);
        h.session.handle_timeout(h.now).unwrap();
        while let Some(transmit) = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true) {
            let packet = h.server.decode(&transmit.data);
            acked |= packet
                .messages
                .iter()
                .filter(|m| m.constructor() == ids::MSGS_ACK)
                .any(|m| read_vector_after_constructor(&m.body).contains(&answer));
            h.session.http_packet_delivered(transmit.packet_seq, h.now);
            if asks_in(&packet).contains(&answer) {
                asks += 1;
                let sealed = h.server.seal(answer, 1, &update(0x0101_0101, &[0; 4]));
                let _ = h.session.handle_packet(&sealed, h.now, &mut h.rng);
            } else {
                h.deliver(vec![Outgoing::Service(msgs_ack(&[]))]).unwrap();
            }
        }
        if h.now.mono >= next_poll_return {
            next_poll_return = h.now.mono + 10.0;
            if !acked {
                h.deliver(vec![Outgoing::Service(msg_new_detailed_info(answer, 100))]).unwrap();
            }
        }
        if h.session.is_performing_service_tasks() {
            busy += 1;
        }
        h.events();
    }
    assert_eq!(asks, 1);
    assert!(acked, "the requested message is acknowledged");
    assert!(busy <= 6, "'updating' for {} s of 300", busy / 2);
}

/// TCP, reconnecting every 30 s: the same unattributed answer, fetched after a long outage, is taken once
/// and not asked for on every new connection.
#[test]
fn an_unattributed_answer_fetched_after_a_long_outage_over_tcp_is_taken() {
    let mut h = long_salt_harness();
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_new_detailed_info(answer, 100))]).unwrap();
    h.session.connection_closed();
    h.advance(400.0);
    h.session.connection_opened(h.now);
    let (mut asks, mut busy) = (0, 0);
    for second in 0..600 {
        if second % 30 == 29 {
            h.session.connection_closed();
            h.advance(0.5);
            h.session.connection_opened(h.now);
        }
        h.advance(1.0);
        let _ = h.session.handle_timeout(h.now);
        while let Some(packet) = h.flush() {
            h.answer_pings(&packet);
            if asks_in(&packet).contains(&answer) {
                asks += 1;
                let _ = h.deliver_sealed(answer, 1, &update(0x0101_0101, &[0; 4]));
            }
        }
        if h.session.is_performing_service_tasks() {
            busy += 1;
        }
        h.events();
    }
    assert_eq!(asks, 1);
    assert!(busy <= 5, "'updating' for {busy} s of 600");
}

/// A call whose announced answer is queued for an ask completes another way (its answer arrives in a
/// msg_copy under another msg_id) before the ask goes out: no ask goes out for an answer nobody awaits.
#[test]
fn no_ask_goes_out_for_a_call_completed_before_it() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, answer, 100))]).unwrap();
    let copy_id = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Content(msg_copy(copy_id, 1, &rpc_result(query, &[1, 2, 3, 4])))]).unwrap();
    let mut asked = Vec::new();
    while let Some(packet) = h.flush() {
        asked.extend(asks_in(&packet));
    }
    assert!(!asked.contains(&answer), "asked for {answer:#x} after its call completed");
    assert!(!h.session.is_performing_service_tasks());
}

/// HTTP: the response carrying a call's answer is lost; another response re-announces the answer, so the
/// call waits for it; then the server loses its session. The call goes again under its msg_id in the new
/// server session's first request (it was queued for retransmission), with the ask for the old answer.
/// The new session runs it and reports `new_session_created`, then says it has no such answer: the call
/// does not fail, and the new session's result reaches it.
#[test]
fn a_call_carried_into_a_new_server_session_gets_the_new_sessions_result() {
    let mut h = long_salt_harness();
    h.session.set_http(true);
    h.session.send(QueryId(1), query_body(1), QueryOptions::default(), h.now);
    h.advance(0.002);
    let first = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::long_poll(25_000), false, true).unwrap();
    let decoded = h.server.decode(&first.data);
    let query = h.sent_query(&decoded, 1);
    let old_answer = h.server.next_msg_id(true);
    h.advance(0.3);
    h.session.http_packet_lost(first.packet_seq, h.now);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, old_answer, 100))]).unwrap();
    h.advance(2.0);
    let mut requests = Vec::new();
    for _ in 0..70 {
        while let Some(transmit) = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true) {
            requests.push(h.server.decode(&transmit.data));
            h.session.http_packet_delivered(transmit.packet_seq, h.now);
        }
        if requests.iter().any(|packet| packet.find(ids::MSG_RESEND_REQ).is_some()) {
            break;
        }
        h.advance(0.5);
        h.session.handle_timeout(h.now).unwrap();
    }
    let ask_id = requests
        .iter()
        .flat_map(|packet| packet.messages.iter())
        .find(|m| m.constructor() == ids::MSG_RESEND_REQ)
        .map(|m| m.msg_id)
        .expect("the old answer is asked for");
    let first_in_new_session = requests[0].messages.iter().map(|m| m.msg_id).min().unwrap();
    h.deliver(vec![
        Outgoing::Service(new_session_created(first_in_new_session, 4242, 101)),
        Outgoing::Service(msgs_state_info(ask_id, &[2])),
    ])
    .unwrap();
    let failed = h.events().into_iter().any(|event| matches!(event, SessionEvent::Error { .. }));
    assert!(!failed, "the call failed although the new session runs it");
    while let Some(transmit) = h.session.poll_http_transmit(h.now, &mut h.rng, HttpWait::IMMEDIATE, false, true) {
        h.session.http_packet_delivered(transmit.packet_seq, h.now);
    }
    h.advance(0.5);
    h.deliver(vec![Outgoing::Content(rpc_result(query, &[9, 9, 9, 9]))]).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![9, 9, 9, 9])]);
}

/// An announcement from the old server session arrives after `new_session_created`, for a call the new
/// session runs (it was carried there under its msg_id): the new session saying it has no such answer does
/// not fail the call, and the new session's result reaches it.
#[test]
fn a_late_announcement_from_the_old_server_session_does_not_fail_the_call() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    let old_answer = h.server.next_msg_id(true);
    let old_announcement = h.server.next_msg_id(true);
    h.session.connection_closed();
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packets = h.flush_all();
    assert!(packets.iter().any(|p| p.messages.iter().any(|m| m.msg_id == query)), "carried under its msg_id");
    h.deliver(vec![Outgoing::Service(new_session_created(query, 4242, 101))]).unwrap();
    h.events();
    h.deliver_sealed(old_announcement, 0, &msg_detailed_info(query, old_answer, 100)).unwrap();
    let ask = h
        .flush_all()
        .iter()
        .flat_map(|packet| packet.messages.iter())
        .find(|m| {
            m.constructor() == ids::MSG_RESEND_REQ && read_vector_after_constructor(&m.body).contains(&old_answer)
        })
        .map(|m| m.msg_id);
    if let Some(ask) = ask {
        h.deliver(vec![Outgoing::Service(msgs_state_info(ask, &[2]))]).unwrap();
    }
    h.deliver(vec![Outgoing::Content(rpc_result(query, &[9, 9, 9, 9]))]).unwrap();
    let events = h.events();
    assert!(events.iter().all(|event| !matches!(event, SessionEvent::Error { .. })), "the call failed");
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
}

/// The server repeats `new_session_created` (same unique_id, higher msg_id) for a late message: the repeat
/// is ignored, so an announcement the live session made between the two notices is its own: asked for,
/// and the server saying it has none fails the call.
#[test]
fn a_repeated_notice_does_not_move_the_server_session_boundary() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    h.deliver(vec![Outgoing::Service(new_session_created(query, 77, 101))]).unwrap();
    h.events();
    let answer = h.server.next_msg_id(true);
    let announcement = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(new_session_created(query - 4096, 77, 101))]).unwrap();
    h.events();
    h.deliver_sealed(announcement, 0, &msg_detailed_info(query, answer, 100)).unwrap();
    assert!(reply_gone(&mut h, answer), "the live session's announcement was not asked for");
    assert!(answer_lost_for_call_1(&h.events()), "the live session's answer was taken for an old one");
}

/// A later server session's notice carries a lower msg_id than the previous one (server clocks differ):
/// its own announcements are still asked for at once.
#[test]
fn a_later_server_sessions_announcement_below_the_last_notice_is_asked_for() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    let skewed_notice = h.server.next_msg_id(true);
    let answer = h.server.next_msg_id(true);
    let announcement = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(new_session_created(query, 1, 101))]).unwrap();
    h.events();
    h.deliver_sealed(skewed_notice, 0, &new_session_created(query, 2, 101)).unwrap();
    h.events();
    h.deliver_sealed(announcement, 0, &msg_detailed_info(query, answer, 100)).unwrap();
    let asked: Vec<i64> = h.flush_all().iter().flat_map(asks_in).collect();
    assert!(asked.contains(&answer));
}

/// After a local session reset the server session boundary starts over: the new client session's
/// announcement is its own even when its notice's msg_id is below the old boundary.
#[test]
fn a_session_reset_starts_the_server_session_boundary_over() {
    let mut h = long_salt_harness();
    let early_notice = h.server.next_msg_id(true);
    let answer = h.server.next_msg_id(true);
    let announcement = h.server.next_msg_id(true);
    let query = h.sent_one(1);
    h.deliver(vec![Outgoing::Service(new_session_created(query, 1, 101))]).unwrap();
    h.events();
    h.session.reset(&mut h.rng);
    h.events();
    let query = h
        .flush_all()
        .iter()
        .flat_map(|p| p.messages.iter())
        .find(|m| query_tag(&m.body) == Some(1))
        .map(|m| m.msg_id)
        .expect("sent again in the new session");
    h.deliver_sealed(early_notice, 0, &new_session_created(query, 2, 101)).unwrap();
    h.events();
    h.deliver_sealed(announcement, 0, &msg_detailed_info(query, answer, 100)).unwrap();
    assert!(reply_gone(&mut h, answer), "the new client session's announcement was not asked for");
    assert!(answer_lost_for_call_1(&h.events()), "the new client session's answer was taken for an old one");
}

/// HTTP responses out of order: the new server session's announcement is processed before its
/// `new_session_created`; that answer is the new session's and is still asked for.
#[test]
fn the_new_sessions_announcement_processed_before_its_notice_is_kept() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    let notice_id = h.server.next_msg_id(true);
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_detailed_info(query, answer, 100))]).unwrap();
    h.deliver_sealed(notice_id, 0, &new_session_created(query, 9, 101)).unwrap();
    h.events();
    let asked: Vec<i64> = h.flush_all().iter().flat_map(asks_in).collect();
    assert!(asked.contains(&answer), "the new session's answer is still asked for");
}

/// A call has two announced answers; the server says one is gone: the call waits for the other and
/// gets it.
#[test]
fn giving_up_one_of_two_announced_answers_keeps_the_call() {
    let mut h = long_salt_harness();
    let query = h.sent_one(1);
    let first_answer = h.server.next_msg_id(true);
    let second_answer = h.server.next_msg_id(true);
    h.deliver(vec![
        Outgoing::Service(msg_detailed_info(query, first_answer, 100)),
        Outgoing::Service(msg_detailed_info(query, second_answer, 100)),
    ])
    .unwrap();
    let mut asks: Vec<(i64, Vec<i64>)> = Vec::new();
    while let Some(packet) = h.flush() {
        asks.extend(
            packet
                .messages
                .iter()
                .filter(|m| m.constructor() == ids::MSG_RESEND_REQ)
                .map(|m| (m.msg_id, read_vector_after_constructor(&m.body))),
        );
    }
    let ask = match asks.iter().find(|(_, wanted)| wanted == &vec![first_answer]) {
        Some((ask, _)) => *ask,
        None => {
            let batch = asks.iter().find(|(_, wanted)| wanted.contains(&first_answer)).expect("asked").0;
            h.deliver(vec![Outgoing::Service(msgs_state_info(batch, &[2, 2]))]).unwrap();
            let mut single = None;
            while let Some(packet) = h.flush() {
                for message in packet.messages.iter().filter(|m| m.constructor() == ids::MSG_RESEND_REQ) {
                    if read_vector_after_constructor(&message.body) == vec![first_answer] {
                        single = Some(message.msg_id);
                    }
                }
            }
            single.expect("asked alone")
        }
    };
    h.deliver(vec![Outgoing::Service(msgs_state_info(ask, &[2]))]).unwrap();
    assert!(h.events().iter().all(|event| !matches!(event, SessionEvent::Error { .. })), "the call failed");
    h.deliver_sealed(second_answer, 1, &rpc_result(query, &[5, 5, 5, 5])).unwrap();
    assert_eq!(h.results(), vec![(QueryId(1), vec![5, 5, 5, 5])]);
}

/// An unattributed answer whose msg_id is past both the duplicate window and the time window when it is
/// re-sent on request: taken once, acknowledged, counted fresh.
#[test]
fn an_unattributed_answer_past_both_windows_is_taken() {
    let mut h = long_salt_harness();
    let answer = h.server.next_msg_id(true);
    h.deliver(vec![Outgoing::Service(msg_new_detailed_info(answer, 100))]).unwrap();
    for _ in 0..2100 {
        h.deliver(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]).unwrap();
    }
    h.advance(400.0);
    h.deliver(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]).unwrap();
    h.events();
    let fresh_before = h.session.fresh_packets();
    h.deliver_sealed(answer, 1, &update(0x0202_0202, &[0; 4])).unwrap();
    assert!(!h.session.awaited_answers.contains_key(&answer));
    assert_eq!(h.session.fresh_packets(), fresh_before + 1);
    assert!(h.acks_after_delay().contains(&answer));
}
