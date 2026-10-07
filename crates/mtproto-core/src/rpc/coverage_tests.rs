//! Paths the rest of the suite left unexercised, found with coverage measurement.
use super::*;
use crate::msg_id::msg_id_for_time;

fn call_ids(h: &mut Harness) -> Vec<u32> {
    h.flush_calls().iter().map(|call| call.2).collect()
}

#[test]
fn a_request_id_already_open_is_not_sent_twice() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(1, RequestFlags::default());
    assert!(h.client.contains(RequestId(1)));
    assert_eq!(h.client.request_count(), 1);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    h.reply(vec![Outgoing::Content(rpc_result(calls[0].0, &[1, 0, 0, 0]))]);
    let completed = h.events().iter().filter(|event| matches!(event, RpcEvent::Completed { .. })).count();
    assert_eq!(completed, 1);
    assert!(!h.client.contains(RequestId(1)));
}

#[test]
fn adopting_a_request_already_open_keeps_the_open_one() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let duplicate = PendingRequest::new(
        RpcRequest { id: RequestId(1), body: call(99), flags: RequestFlags::default(), invoke_after: None },
        h.now,
    );
    assert_eq!(duplicate.request().body, call(99));
    h.client.adopt(duplicate, h.now);
    assert_eq!(call_ids(&mut h), vec![1], "the adopted copy did not replace the open request");
}

#[test]
fn accessors_report_how_the_client_was_made() {
    let h = Harness::new(SessionRole::Worker { requires_auth_token: true }, Some("stored"));
    assert_eq!(h.client.role(), SessionRole::Worker { requires_auth_token: true });
    assert_eq!(h.client.environment().map(|environment| environment.init_hash.as_str()), Some("h1"));
    assert_eq!(h.client.stored_init_hash(), Some("stored"));
    assert!(h.client.needs_initialization(), "the stored hash is not the environment's");
    let mut cdn = Harness::new(SessionRole::Cdn, None);
    assert_eq!(cdn.client.role(), SessionRole::Cdn);
    assert!(cdn.client.poll_event().is_none());
}

#[test]
fn open_requests_are_handed_over_in_submission_order() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for tag in [5, 3, 9] {
        h.send(tag, RequestFlags::default());
    }
    let calls = h.flush_calls();
    let answered = calls.iter().find(|call| call.2 == 3).unwrap().0;
    h.reply(vec![Outgoing::Content(rpc_result(answered, &[1, 0, 0, 0]))]);
    let requests = h.client.into_requests();
    let tags: Vec<u64> = requests.iter().map(|request| request.id.0).collect();
    assert_eq!(tags, vec![5, 9], "answered requests are gone, the rest keep their order");
    assert_eq!(requests[0].body, call(5));
}

/// A transport-level rejection (-429/-444) means the server never read the packet: the call goes again
/// as a new message rather than as a retransmission the server would deduplicate.
#[test]
fn a_rejected_connection_sends_its_calls_again_as_new_messages() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let first = h.flush_calls();
    assert_eq!(first.len(), 1);
    h.client.connection_rejected(h.now);
    assert!(!h.client.session().is_connected(), "rejection closes the connection");
    h.client.connection_opened(h.now);
    h.advance(5.0);
    let again = h.flush_calls();
    assert_eq!(again.iter().map(|call| call.2).collect::<Vec<_>>(), vec![1], "the call goes again");
    assert!(again[0].0 > first[0].0, "under a new msg_id");
    h.reply(vec![Outgoing::Content(rpc_result(again[0].0, &[1, 0, 0, 0]))]);
    assert!(h.events().iter().any(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. })));
}

#[test]
fn a_flood_wait_question_answered_yes_waits_out_the_flood_in_the_next_session() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let flags = RequestFlags { delegate_retry_decisions: true, timeout_timer: true, ..Default::default() };
    h.send(1, flags);
    let calls = h.flush_calls();
    assert!(h.client.has_timeout_timer_requests());
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_30"))]);
    assert!(
        h.events().iter().any(|event| matches!(event, RpcEvent::RetryDecisionRequired { flood_wait_seconds: 30, .. }))
    );
    assert!(!h.client.has_timeout_timer_requests(), "a request out of the session no longer counts for timeouts");
    let now = h.now;
    let mut pending = h.client.into_pending();
    assert_eq!(pending.len(), 1);
    pending[0].resolve_verification(Verification::Recaptcha { token: "t".into() });
    assert_eq!(pending[0].decide_retry(true, now), Some(None), "retry once the flood wait is over");
    let mut next = Harness::new(SessionRole::Main, Some("h1"));
    next.client.adopt(pending.pop().unwrap(), now);
    next.advance(20.0);
    assert!(next.flush_calls().is_empty(), "still inside the flood wait");
    next.advance(11.0);
    let calls = next.flush_calls();
    assert_eq!(calls.iter().map(|call| call.2).collect::<Vec<_>>(), vec![1]);
    assert!(calls[0].1.contains(&INVOKE_WITH_RECAPTCHA), "the verification travels with the retry");
    let request = PendingRequest::new(
        RpcRequest { id: RequestId(7), body: call(7), flags: RequestFlags::default(), invoke_after: None },
        now,
    )
    .into_request();
    assert_eq!(request.id, RequestId(7));
}

#[test]
fn a_bind_answered_false_fails_and_keeps_queries_held() {
    let mut h = Harness::new(SessionRole::Main, None);
    h.client.hold_until_bound();
    h.send(1, RequestFlags::default());
    let perm = AuthKey::new([0x31; 256]);
    h.client.bind_temporary_key(perm, START as i32 + 86_400, h.now, &mut h.rng);
    h.advance(0.002);
    let transmit = h.client.poll_transmit(h.now, &mut h.rng).expect("the bind");
    let packet = h.server.decode(&transmit.data);
    let bind = packet
        .messages
        .iter()
        .find(|message| unwrap_call(&message.body).1.is_none() && message.is_content_related())
        .expect("bind query")
        .msg_id;
    let mut writer = Writer::new();
    writer.write_u32(ids::BOOL_FALSE);
    h.reply(vec![Outgoing::Content(rpc_result(bind, &writer.into_inner()))]);
    let events = h.events();
    assert!(
        events.contains(&RpcEvent::TemporaryKeyBindFailed { code: 0, message: "BIND_RETURNED_FALSE".into() }),
        "{events:?}"
    );
    assert!(h.flush_calls().is_empty(), "queries stay held until a bind succeeds");
}

#[test]
fn megabytes_of_answers_to_forgotten_queries_reset_the_connection() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.flush_calls();
    let large = vec![0x42u8; 1 << 20];
    let mut resets = 0;
    for index in 0..10i64 {
        let forgotten = msg_id_for_time(START - 30.0) + index * 4;
        h.reply(vec![Outgoing::Content(rpc_result(forgotten, &large))]);
        resets += h.events().iter().filter(|event| **event == RpcEvent::ConnectionShouldReset).count();
    }
    assert_eq!(resets, 1, "over 8 MB of answers nobody asked for within seconds end the connection once");
}
