use super::*;

fn sent(h: &mut Harness, tag: u32) -> (DecodedPacket, i64) {
    h.session.send(QueryId(u64::from(tag)), query_body(tag), QueryOptions::default(), h.now);
    let packet = h.flush().expect("packet");
    let msg_id = h.sent_query(&packet, tag);
    (packet, msg_id)
}

fn released(events: &[SessionEvent]) -> Vec<(QueryId, bool)> {
    events
        .iter()
        .filter_map(|event| match event {
            SessionEvent::Released { id, may_have_run } => Some((*id, *may_have_run)),
            _ => None,
        })
        .collect()
}

fn query_msg_ids(packets: &[DecodedPacket], tag: u32) -> Vec<i64> {
    packets
        .iter()
        .flat_map(|packet| packet.messages.iter())
        .filter(|message| query_tag(&message.body) == Some(tag))
        .map(|message| message.msg_id)
        .collect()
}

#[test]
fn a_session_handing_over_sends_no_query_it_had_not_sent_and_does_not_spin() {
    let mut h = Harness::new();
    let _ = sent(&mut h, 1);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    h.session.hand_over();
    let packets = h.flush_all();
    assert!(query_msg_ids(&packets, 2).is_empty(), "a query never sent stays unsent");
    assert!(!h.session.has_queries_to_send());
    let next = h.session.poll_timeout(h.now).expect("pings and liveness still run");
    assert!(next > h.now.mono, "nothing is due at once: {next} vs {}", h.now.mono);
    assert!(h.flush().is_none());
}

#[test]
fn an_answer_that_comes_while_handing_over_completes_the_query() {
    let mut h = Harness::new();
    let (_, msg_id) = sent(&mut h, 1);
    h.session.hand_over();
    h.deliver(vec![Outgoing::Content(rpc_result(msg_id, &[9, 9, 9, 9]))]).unwrap();
    let events = h.events();
    assert!(released(&events).is_empty());
    assert!(events.iter().any(|event| matches!(event, SessionEvent::Result { id: QueryId(1), .. })));
}

#[test]
fn a_query_whose_connection_closed_goes_again_only_under_its_own_msg_id() {
    let mut h = Harness::new();
    let (_, msg_id) = sent(&mut h, 1);
    h.session.hand_over();
    h.session.connection_closed();
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packets = h.flush_all();
    assert_eq!(query_msg_ids(&packets, 1), vec![msg_id], "retransmitted, never under a new msg_id");
    assert!(released(&h.events()).is_empty());
}

#[test]
fn a_rejected_query_the_server_never_ran_is_released_as_not_run() {
    let mut h = Harness::new();
    let (packet, _) = sent(&mut h, 1);
    h.session.hand_over();
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 555))]).unwrap();
    assert_eq!(released(&h.events()), vec![(QueryId(1), false)]);
    let packets = h.flush_all();
    assert!(query_msg_ids(&packets, 1).is_empty(), "it went back to the host, not out again");
    assert!(!h.session.has_queries());
}

#[test]
fn a_bad_salt_for_a_query_that_may_have_arrived_retransmits_it_under_its_msg_id() {
    let mut h = Harness::new();
    let (_, msg_id) = sent(&mut h, 1);
    h.session.connection_closed();
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().expect("retransmission");
    assert_eq!(h.sent_query(&packet, 1), msg_id);
    h.session.hand_over();
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 556))]).unwrap();
    assert!(released(&h.events()).is_empty());
    let packets = h.flush_all();
    assert_eq!(query_msg_ids(&packets, 1), vec![msg_id], "under the new salt, same msg_id");
}

#[test]
fn a_query_the_server_says_it_did_not_receive_is_released_as_not_run() {
    let mut h = Harness::new();
    let (_, msg_id) = sent(&mut h, 1);
    h.session.connection_closed();
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().expect("retransmission");
    assert_eq!(h.sent_query(&packet, 1), msg_id);
    h.session.hand_over();
    h.deliver(vec![Outgoing::Service(bad_msg_notification(packet.header.msg_id, packet.header.seq_no, 16))]).unwrap();
    assert!(released(&h.events()).is_empty(), "it may have arrived on the closed connection: asked about first");
    let packet = h.flush().expect("state request");
    let request = packet.find(ids::MSGS_STATE_REQ).expect("msgs_state_req");
    assert_eq!(read_vector_after_constructor(&request.body), vec![msg_id]);
    assert!(packet.queries().is_empty(), "no copy goes out under a new msg_id");
    h.deliver(vec![Outgoing::Service(msgs_state_info(request.msg_id, &[2]))]).unwrap();
    assert_eq!(released(&h.events()), vec![(QueryId(1), false)]);
    assert!(!h.session.has_queries());
}

#[test]
fn a_query_the_server_knows_nothing_about_is_released_as_possibly_run() {
    let mut h = Harness::new();
    let (_, msg_id) = sent(&mut h, 1);
    h.session.connection_closed();
    h.advance(1.0);
    h.session.connection_opened(h.now);
    let packet = h.flush().expect("retransmission");
    h.session.hand_over();
    h.deliver(vec![Outgoing::Service(bad_msg_notification(packet.header.msg_id, packet.header.seq_no, 16))]).unwrap();
    let packet = h.flush().expect("state request");
    let request = packet.find(ids::MSGS_STATE_REQ).expect("msgs_state_req");
    assert_eq!(read_vector_after_constructor(&request.body), vec![msg_id]);
    h.deliver(vec![Outgoing::Service(msgs_state_info(request.msg_id, &[1]))]).unwrap();
    assert_eq!(
        released(&h.events()),
        vec![(QueryId(1), true)],
        "status 1: the msg_id may be too old for the server to remember running it"
    );
}

#[test]
fn a_query_that_went_back_to_the_queue_before_the_handover_stays_possibly_run() {
    let mut h = Harness::new();
    let (packet, msg_id) = sent(&mut h, 1);
    let first = packet.header.msg_id.max(msg_id) + 4;
    h.deliver(vec![Outgoing::Service(new_session_created(first, 31, 101))]).unwrap();
    assert!(!h.session.was_transmitted(QueryId(1)), "queued again for a new msg_id");
    assert!(h.session.may_have_run(QueryId(1)), "its first copy may have run");
    let packet = h.flush_all().into_iter().find(|packet| !packet.queries().is_empty()).expect("second copy");
    let second = h.sent_query(&packet, 1);
    assert_ne!(second, msg_id);
    h.session.hand_over();
    h.deliver(vec![Outgoing::Service(bad_msg_notification(packet.header.msg_id, packet.header.seq_no, 16))]).unwrap();
    assert_eq!(
        released(&h.events()),
        vec![(QueryId(1), true)],
        "the server refused the second copy, but the first may have run"
    );
}

#[test]
fn a_new_server_session_covering_a_query_releases_it_as_possibly_run() {
    let mut h = Harness::new();
    let (packet, msg_id) = sent(&mut h, 1);
    h.session.hand_over();
    let first = packet.header.msg_id.max(msg_id) + 4;
    h.deliver(vec![Outgoing::Service(new_session_created(first, 31, 101))]).unwrap();
    assert_eq!(released(&h.events()), vec![(QueryId(1), true)]);
    let packets = h.flush_all();
    assert!(query_msg_ids(&packets, 1).is_empty());
}

#[test]
fn a_local_session_reset_releases_what_went_out_as_possibly_run_and_keeps_the_rest() {
    let mut h = Harness::new();
    let _ = sent(&mut h, 1);
    h.session.send(QueryId(2), query_body(2), QueryOptions::default(), h.now);
    h.session.hand_over();
    h.session.reset(&mut h.rng);
    assert_eq!(released(&h.events()), vec![(QueryId(1), true)]);
    assert!(h.session.contains(QueryId(2)), "the host takes back what never went out");
    assert!(!h.session.contains(QueryId(1)));
}

#[test]
fn without_handing_over_the_same_cases_resend_as_before() {
    let mut h = Harness::new();
    let (packet, first_id) = sent(&mut h, 1);
    h.deliver(vec![Outgoing::Service(bad_server_salt(packet.header.msg_id, packet.header.seq_no, 557))]).unwrap();
    assert!(released(&h.events()).is_empty());
    let packets = h.flush_all();
    let ids = query_msg_ids(&packets, 1);
    assert_eq!(ids.len(), 1);
    assert_ne!(ids[0], first_id, "a rejected query goes again under a new msg_id");
}
