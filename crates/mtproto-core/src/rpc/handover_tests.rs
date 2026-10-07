use super::*;

fn delegating() -> RequestFlags {
    RequestFlags {
        delegate_retry_decisions: true,
        automatic_flood_wait: false,
        retry_server_errors: false,
        ..Default::default()
    }
}

fn released(events: &[RpcEvent]) -> Vec<(u64, bool)> {
    events
        .iter()
        .filter_map(|event| match event {
            RpcEvent::Released { id, may_have_run, .. } => Some((id.0, *may_have_run)),
            _ => None,
        })
        .collect()
}

fn chained(h: &mut Harness, tag: u32, after: u32) {
    h.client.send(
        RpcRequest {
            id: RequestId(u64::from(tag)),
            body: call(tag),
            flags: RequestFlags::default(),
            invoke_after: Some(RequestId(u64::from(after))),
        },
        h.now,
    );
}

#[test]
fn requests_that_never_went_out_are_released_at_once_and_sent_ones_wait() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    h.send(2, RequestFlags::default());
    h.send(3, RequestFlags::default());
    h.client.start_handover(h.now);
    assert_eq!(released(&h.events()), vec![(2, false), (3, false)]);
    assert_eq!(h.client.held_request_count(), 1);
    assert!(h.flush_calls().is_empty(), "nothing new goes out, and the sent call not again");
    h.reply(vec![Outgoing::Content(rpc_result(calls[0].0, &[1, 0, 0, 0]))]);
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. })));
    assert_eq!(h.client.held_request_count(), 0);
}

#[test]
fn a_request_chained_to_one_still_waiting_follows_it() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    chained(&mut h, 2, 1);
    chained(&mut h, 3, 2);
    h.send(4, RequestFlags::default());
    h.client.start_handover(h.now);
    assert_eq!(released(&h.events()), vec![(4, false)], "the chain waits for its first call");
    h.reply(vec![Outgoing::Content(rpc_result(calls[0].0, &[1, 0, 0, 0]))]);
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. })));
    assert_eq!(released(&events), vec![(2, false), (3, false)], "in their order once the first is answered");
}

#[test]
fn at_the_end_what_went_out_leaves_as_possibly_run_before_the_calls_chained_to_it() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let _ = h.flush_calls();
    chained(&mut h, 2, 1);
    h.client.start_handover(h.now);
    assert!(released(&h.events()).is_empty());
    h.client.release_all(h.now);
    assert_eq!(released(&h.events()), vec![(1, true), (2, false)]);
    assert_eq!(h.client.held_request_count(), 0);
    assert!(!h.client.session().has_queries());
}

#[test]
fn a_flood_wait_the_host_waits_out_is_released_with_what_is_left_of_it() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, delegating());
    let calls = h.flush_calls();
    h.client.start_handover(h.now);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_30"))]);
    let events = h.events();
    assert!(events.iter().any(|event| matches!(event, RpcEvent::RetryDecisionRequired { .. })));
    assert!(released(&events).is_empty(), "held while the host decides");
    h.advance(1.0);
    h.client.decide_retry(RequestId(1), true, h.now);
    let events = h.events();
    let retry_after = events.iter().find_map(|event| match event {
        RpcEvent::Released { id: RequestId(1), may_have_run: false, retry_after } => Some(*retry_after),
        _ => None,
    });
    let retry_after = retry_after.expect("released once the host chose to wait");
    assert!((28.5..=30.0).contains(&retry_after), "{retry_after}");
}

#[test]
fn a_retry_the_host_refuses_fails_the_request_as_before() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, delegating());
    let calls = h.flush_calls();
    h.client.start_handover(h.now);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 500, "INTERNAL"))]);
    let _ = h.events();
    h.client.decide_retry(RequestId(1), false, h.now);
    let events = h.events();
    assert!(released(&events).is_empty());
    assert!(events.iter().any(|event| matches!(event, RpcEvent::Failed { id: RequestId(1), code: 500, .. })));
}

#[test]
fn a_request_sent_to_a_client_handing_over_comes_straight_back() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.client.start_handover(h.now);
    h.send(7, RequestFlags::default());
    assert_eq!(released(&h.events()), vec![(7, false)]);
    assert!(h.flush_calls().is_empty());
}

#[test]
fn a_request_that_went_out_under_an_earlier_session_is_released_as_possibly_run() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let _ = h.flush_calls();
    let next = Harness::new(SessionRole::Main, Some("h1"));
    let old = std::mem::replace(&mut h.client, next.client);
    let pending = old.into_pending();
    assert!(pending[0].may_have_run());
    for request in pending {
        h.client.adopt(request, h.now);
    }
    h.client.start_handover(h.now);
    assert_eq!(released(&h.events()), vec![(1, true)], "its earlier copy can no longer be answered");
}

#[test]
fn a_request_queued_again_after_a_new_server_session_is_released_as_possibly_run() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 2);
    let first = calls.iter().map(|call| call.0).max().unwrap() + (1 << 32);
    h.reply(vec![
        Outgoing::Content(rpc_result(calls[1].0, &[1, 0, 0, 0])),
        Outgoing::Content(new_session_created(first, 1, 5)),
    ]);
    let _ = h.events();
    assert!(!h.client.session().was_transmitted(QueryId(1)));
    h.client.start_handover(h.now);
    assert_eq!(
        released(&h.events()),
        vec![(1, true)],
        "queued for a new msg_id, its first copy may have run: it leaves at once, as possibly run"
    );
    assert_eq!(h.client.held_request_count(), 0);
    assert!(h.flush_calls().is_empty());
}

#[test]
fn a_request_re_wrapped_for_initialization_stays_possibly_run() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    let first = calls.iter().map(|call| call.0).max().unwrap() + (1 << 32);
    h.reply(vec![
        Outgoing::Content(rpc_result(calls[1].0, &[1, 0, 0, 0])),
        Outgoing::Content(new_session_created(first, 1, 5)),
    ]);
    let _ = h.events();
    assert!(h.client.session().may_have_run(QueryId(1)));
    h.client.set_stored_init_hash(None);
    h.client.start_handover(h.now);
    assert_eq!(
        released(&h.events()),
        vec![(1, true)],
        "taken back to be wrapped with initConnection again, its first copy may still have run"
    );
}
