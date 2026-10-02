use super::*;
use crate::auth_key::AuthKey;
use crate::crypto::XorShiftRandom;
use crate::session::SessionConfig;
use crate::test_support::server_peer::*;
use crate::tl::{Reader, Writer, ids};

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5566_7788;

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3)))
}

fn environment(hash: &str) -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: hash.into(),
        disable_updates: false,
    }
}

fn call(tag: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(CALL);
    writer.write_u32(tag);
    writer.into_inner()
}

fn unwrap_call(body: &[u8]) -> (Vec<u32>, Option<u32>) {
    let mut reader = Reader::new(body);
    let mut wrappers = Vec::new();
    loop {
        let constructor = reader.read_u32().unwrap();
        match constructor {
            ids::INVOKE_AFTER_MSG => {
                wrappers.push(constructor);
                reader.read_i64().unwrap();
            }
            ids::INVOKE_WITHOUT_UPDATES => wrappers.push(constructor),
            ids::INVOKE_WITH_LAYER => {
                wrappers.push(constructor);
                reader.read_i32().unwrap();
                assert_eq!(reader.read_u32().unwrap(), INIT_CONNECTION);
                wrappers.push(INIT_CONNECTION);
                reader.read_i32().unwrap();
                reader.read_i32().unwrap();
                for _ in 0..6 {
                    reader.read_bytes().unwrap();
                }
            }
            INVOKE_WITH_APNS_SECRET => {
                wrappers.push(constructor);
                reader.read_bytes().unwrap();
                reader.read_bytes().unwrap();
            }
            INVOKE_WITH_RECAPTCHA => {
                wrappers.push(constructor);
                reader.read_bytes().unwrap();
            }
            CALL => return (wrappers, Some(reader.read_u32().unwrap())),
            _ => return (wrappers, None),
        }
    }
}

struct Harness {
    client: RpcClient,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

impl Harness {
    fn new(role: SessionRole, stored_hash: Option<&str>) -> Self {
        let mut rng = XorShiftRandom::new(9);
        let now = Now { mono: 10.0, unix: START };
        let salts = [
            ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 },
            ServerSalt { salt: 6, valid_since: START + 100_000.0, valid_until: START + 200_000.0 },
        ];
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let client = RpcClient::new(session, role, Some(environment("h1")), stored_hash.map(str::to_string));
        let mut server = ServerPeer::new(key(), START);
        server.salt = 5;
        Self { client, server, rng, now }
    }

    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.server_time += seconds;
    }

    fn send(&mut self, tag: u32, flags: RequestFlags) {
        self.client
            .send(RpcRequest { id: RequestId(tag as u64), body: call(tag), flags, invoke_after: None }, self.now);
    }

    fn flush_calls(&mut self) -> Vec<(i64, Vec<u32>, u32)> {
        let mut calls = Vec::new();
        let mut idle = 0;
        for _ in 0..40 {
            self.advance(0.002);
            let _ = self.client.handle_timeout(self.now);
            let Some(transmit) = self.client.poll_transmit(self.now, &mut self.rng) else {
                idle += 1;
                if idle > 3 {
                    break;
                }
                continue;
            };
            idle = 0;
            let packet = self.server.decode(&transmit.data);
            for message in packet.messages {
                let (wrappers, tag) = unwrap_call(&message.body);
                if let Some(tag) = tag {
                    calls.push((message.msg_id, wrappers, tag));
                }
            }
        }
        calls
    }

    fn reply(&mut self, items: Vec<Outgoing>) {
        let packet = self.server.encode(items);
        self.client.handle_packet(&packet, self.now, &mut self.rng).unwrap();
    }

    fn events(&mut self) -> Vec<RpcEvent> {
        self.client.drain_events()
    }
}

#[test]
fn init_connection_until_first_success_then_hash_stored() {
    let mut h = Harness::new(SessionRole::Main, None);
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 2);
    for (_, wrappers, _) in &calls {
        assert_eq!(wrappers, &vec![ids::INVOKE_WITH_LAYER, INIT_CONNECTION]);
    }
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 400, "SOMETHING"))]);
    assert!(!h.events().iter().any(|e| matches!(e, RpcEvent::InitHashStored { .. })));
    h.reply(vec![Outgoing::Content(rpc_result(calls[1].0, &[1, 0, 0, 0]))]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::InitHashStored { hash: "h1".into() }));
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Completed { id: RequestId(2), .. })));
    h.send(3, RequestFlags::default());
    let calls = h.flush_calls();
    assert_eq!(calls[0].1, Vec::<u32>::new());
}

#[test]
fn stored_hash_skips_initialization_and_change_reinitializes() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    assert_eq!(h.flush_calls()[0].1, Vec::<u32>::new());
    let noop = RpcRequest { id: RequestId(100), body: call(100), flags: RequestFlags::default(), invoke_after: None };
    h.client.update_environment(environment("h2"), Some(noop), h.now);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2, 100);
    assert_eq!(calls[0].1, vec![ids::INVOKE_WITH_LAYER, INIT_CONNECTION]);
}

#[test]
fn connection_not_inited_clears_hash_and_retries_wrapped() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 400, "CONNECTION_NOT_INITED"))]);
    assert!(h.events().contains(&RpcEvent::InitHashCleared));
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, vec![ids::INVOKE_WITH_LAYER, INIT_CONNECTION]);
}

#[test]
fn without_updates_wraps_outside_layer() {
    let mut h = Harness::new(SessionRole::Worker { requires_auth_token: false }, None);
    h.send(1, RequestFlags { without_updates: true, ..Default::default() });
    assert_eq!(h.flush_calls()[0].1, vec![ids::INVOKE_WITHOUT_UPDATES, ids::INVOKE_WITH_LAYER, INIT_CONNECTION]);
}

#[test]
fn flood_wait_is_waited_out_and_reported() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags { report_flood_wait: true, ..Default::default() });
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_3"))]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::FloodWaitReported { id: RequestId(1), message: "FLOOD_WAIT_3".into() }));
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Failed { .. })));
    assert!(h.flush_calls().is_empty());
    let deadline = h.client.poll_timeout(h.now).unwrap();
    assert!(deadline >= h.now.mono + 2.9);
    h.advance(3.1);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
}

#[test]
fn flood_wait_surfaces_without_automatic_wait() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags { automatic_flood_wait: false, ..Default::default() });
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_PREMIUM_WAIT_5"))]);
    assert!(h.events().iter().any(|e| matches!(e, RpcEvent::Failed { id: RequestId(1), code: 420, .. })));
}

#[test]
fn unparsable_flood_and_frozen_method_surface() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 420, "SLOWMODE_WAIT_10")),
        Outgoing::Content(rpc_error(calls[1].0, 420, "FROZEN_METHOD_INVALID")),
    ]);
    let failed = h.events().into_iter().filter(|e| matches!(e, RpcEvent::Failed { .. })).count();
    assert_eq!(failed, 2);
}

#[test]
fn server_errors_retry_with_backoff_or_fail() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags { retry_server_errors: false, ..Default::default() });
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 500, "INTERNAL")),
        Outgoing::Content(rpc_error(calls[1].0, 500, "INTERNAL")),
    ]);
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Failed { id: RequestId(2), .. })));
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Failed { id: RequestId(1), .. })));
    h.advance(1.0);
    assert!(h.flush_calls().is_empty());
    h.advance(1.1);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, -500, "Timeout"))]);
    h.advance(2.1);
    assert!(h.flush_calls().is_empty(), "second retry waits 4s");
    h.advance(2.0);
    assert_eq!(h.flush_calls().len(), 1);
}

#[test]
fn main_session_401_requires_authorization_and_surfaces() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_UNREGISTERED")),
        Outgoing::Content(rpc_error(calls[1].0, 401, "SESSION_PASSWORD_NEEDED")),
    ]);
    let events = h.events();
    assert_eq!(events.iter().filter(|e| matches!(e, RpcEvent::AuthorizationRequired { .. })).count(), 1);
    assert_eq!(events.iter().filter(|e| matches!(e, RpcEvent::Failed { .. })).count(), 2);
}

#[test]
fn auth_key_perm_empty_never_surfaces() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_PERM_EMPTY"))]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::TemporaryKeyRejected));
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Failed { .. } | RpcEvent::AuthorizationRequired { .. })));
    assert!(h.flush_calls().is_empty(), "parked instead of a hot resend loop");
    h.advance(TEMPORARY_KEY_RETRY_DELAY);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_PERM_EMPTY"))]);
    assert!(!h.events().contains(&RpcEvent::TemporaryKeyRejected), "reported once per key");
    h.advance(1.0);
    assert!(h.flush_calls().is_empty(), "backoff grows");
    let replacement = AuthKey::new([0x5a; 256]);
    h.server.auth_key = replacement.clone();
    let salts = h.client.session().salts();
    h.client.session_mut().replace_auth_key(replacement, &salts, h.now);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1, "a new key releases the request immediately");
    h.reply(vec![Outgoing::Content(rpc_result(calls[0].0, &[1, 0, 0, 0]))]);
    assert!(h.events().iter().any(|e| matches!(e, RpcEvent::Completed { id: RequestId(1), .. })));
}

#[test]
fn worker_token_wait_parks_requests() {
    let mut h = Harness::new(SessionRole::Worker { requires_auth_token: true }, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_UNREGISTERED"))]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::AuthTokenRequired));
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Failed { .. } | RpcEvent::AuthorizationRequired { .. })));
    h.send(2, RequestFlags::default());
    assert!(h.flush_calls().is_empty());
    h.client.set_auth_token_ready(true, h.now);
    let mut tags: Vec<u32> = h.flush_calls().into_iter().map(|c| c.2).collect();
    tags.sort_unstable();
    assert_eq!(tags, vec![1, 2]);
}

#[test]
fn apns_and_recaptcha_verification_park_until_resolved() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 403, "APNS_VERIFY_CHECK_abc")),
        Outgoing::Content(rpc_error(calls[1].0, 403, "RECAPTCHA_CHECK_auth.sendCode__site123")),
    ]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::VerificationRequired {
        id: RequestId(1),
        kind: VerificationKind::Apns { nonce: "abc".into() }
    }));
    assert!(events.contains(&RpcEvent::VerificationRequired {
        id: RequestId(2),
        kind: VerificationKind::Recaptcha { method: "auth.sendCode".into(), site_key: "site123".into() }
    }));
    assert!(h.flush_calls().is_empty());
    h.client.resolve_verification(RequestId(1), Verification::Apns { nonce: "abc".into(), secret: "s".into() }, h.now);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, vec![INVOKE_WITH_APNS_SECRET]);
    h.client.fail_request(RequestId(2), 403, "RECAPTCHA_TIMEOUT", h.now);
    assert!(
        h.events()
            .iter()
            .any(|e| matches!(e, RpcEvent::Failed { id: RequestId(2), message, .. } if message == "RECAPTCHA_TIMEOUT"))
    );
}

#[test]
fn soft_auth_reset_is_reported_and_surfaced() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 406, "AUTH_KEY_DUPLICATED"))]);
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, RpcEvent::SoftAuthReset { .. })));
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Failed { code: 406, .. })));
}

#[test]
fn migrate_errors_surface_verbatim() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 303, "PHONE_MIGRATE_4"))]);
    assert!(
        h.events()
            .iter()
            .any(|e| matches!(e, RpcEvent::Failed { code: 303, message, .. } if message == "PHONE_MIGRATE_4"))
    );
}

#[test]
fn dependency_ordering_and_msg_wait_timeout() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.client.send(
        RpcRequest {
            id: RequestId(2),
            body: call(2),
            flags: RequestFlags::default(),
            invoke_after: Some(RequestId(1)),
        },
        h.now,
    );
    let calls = h.flush_calls();
    let dependent = calls.iter().find(|c| c.2 == 2).unwrap();
    assert_eq!(dependent.1, vec![ids::INVOKE_AFTER_MSG]);
    let first = calls.iter().find(|c| c.2 == 1).unwrap().0;
    h.reply(vec![Outgoing::Content(rpc_error(dependent.0, 400, "MSG_WAIT_TIMEOUT"))]);
    assert!(h.flush_calls().is_empty(), "waits for dependency");
    h.reply(vec![Outgoing::Content(rpc_result(first, &[0; 4]))]);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2, 2);
    assert!(calls[0].1.is_empty());
}

#[test]
fn quick_ack_events_only_for_requests_that_asked() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags { quick_ack: true, ..Default::default() });
    h.advance(0.01);
    let transmit = h.client.poll_transmit(h.now, &mut h.rng).unwrap();
    h.client.handle_quick_ack(transmit.quick_ack_token.unwrap(), h.now);
    assert!(h.events().contains(&RpcEvent::Acknowledged { id: RequestId(1) }));
}

#[test]
fn cancelling_in_flight_requests_drops_answers_without_resetting_the_connection() {
    let mut h = Harness::new(SessionRole::Worker { requires_auth_token: false }, Some("h1"));
    h.send(1, RequestFlags { expected_response_size: 1024 * 1024, ..Default::default() });
    h.send(2, RequestFlags { expected_response_size: 128 * 1024, ..Default::default() });
    let calls = h.flush_calls();
    assert!(h.client.cancel(RequestId(1), h.now));
    assert!(h.client.cancel(RequestId(2), h.now));
    assert!(!h.events().contains(&RpcEvent::ConnectionShouldReset), "other in-flight parts keep their connection");
    h.advance(0.01);
    let mut dropped = Vec::new();
    while let Some(transmit) = h.client.poll_transmit(h.now, &mut h.rng) {
        let packet = h.server.decode(&transmit.data);
        for message in &packet.messages {
            if message.constructor() == ids::RPC_DROP_ANSWER {
                dropped.push(i64::from_le_bytes(message.body[4..12].try_into().unwrap()));
            }
        }
    }
    dropped.sort_unstable();
    let mut expected: Vec<i64> = calls.iter().map(|call| call.0).collect();
    expected.sort_unstable();
    assert_eq!(dropped, expected);
}

#[test]
fn updates_too_long_and_session_resets_emit_updates_reset() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(update(0xe317af7e, &[])), Outgoing::Content(new_session_created(calls[0].0, 1, 5))]);
    let resets = h.events().into_iter().filter(|e| *e == RpcEvent::UpdatesReset).count();
    assert_eq!(resets, 2);
}

#[test]
fn delegated_retry_decisions_for_flood_and_server_errors() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let flags = RequestFlags { delegate_retry_decisions: true, ..Default::default() };
    h.send(1, flags);
    h.send(2, flags);
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_2")),
        Outgoing::Content(rpc_error(calls[1].0, 500, "INTERNAL")),
    ]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::RetryDecisionRequired {
        id: RequestId(1),
        code: 420,
        message: "FLOOD_WAIT_2".into(),
        flood_wait_seconds: 2,
        flood_wait_text: Some("FLOOD_WAIT_2".into()),
        server_errors: 0,
    }));
    assert!(events.contains(&RpcEvent::RetryDecisionRequired {
        id: RequestId(2),
        code: 500,
        message: "INTERNAL".into(),
        flood_wait_seconds: 0,
        flood_wait_text: None,
        server_errors: 1,
    }));
    h.advance(10.0);
    assert!(h.flush_calls().is_empty(), "parked until decided");
    h.client.decide_retry(RequestId(1), true, h.now);
    h.client.decide_retry(RequestId(2), false, h.now);
    let events = h.events();
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Failed { id: RequestId(2), code: 500, .. })));
    assert!(h.flush_calls().is_empty(), "flood delay still applies");
    h.advance(2.1);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2, 1);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 500, "INTERNAL"))]);
    assert!(h.events().contains(&RpcEvent::RetryDecisionRequired {
        id: RequestId(1),
        code: 500,
        message: "INTERNAL".into(),
        flood_wait_seconds: 2,
        flood_wait_text: Some("FLOOD_WAIT_2".into()),
        server_errors: 1,
    }));
    h.client.decide_retry(RequestId(77), true, h.now);
}

fn failed_with(events: &[RpcEvent], id: u64) -> Option<(i32, String)> {
    events.iter().find_map(|event| match event {
        RpcEvent::Failed { id: RequestId(found), code, message, .. } if *found == id => Some((*code, message.clone())),
        _ => None,
    })
}

impl Harness {
    fn single_error(&mut self, role: SessionRole, code: i32, message: &str) -> Vec<RpcEvent> {
        *self = Harness::new(role, Some("h1"));
        self.send(1, RequestFlags::default());
        let calls = self.flush_calls();
        self.reply(vec![Outgoing::Content(rpc_error(calls[0].0, code, message))]);
        self.events()
    }
}

#[test]
fn local_unpack_failures_are_terminal_and_never_retried() {
    for flags in [RequestFlags::default(), RequestFlags { delegate_retry_decisions: true, ..Default::default() }] {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        h.send(1, flags);
        let calls = h.flush_calls();
        let mut broken = Writer::new();
        broken.write_u32(ids::GZIP_PACKED);
        broken.write_bytes(&[9, 9, 9, 9, 9]);
        h.reply(vec![Outgoing::Content(rpc_result(calls[0].0, broken.as_slice()))]);
        let events = h.events();
        let (code, message) = failed_with(&events, 1).expect("surfaced");
        assert_eq!(code, 500);
        assert!(message.starts_with("RESPONSE_UNPACK_FAILED"));
        assert!(!events.iter().any(|e| matches!(e, RpcEvent::RetryDecisionRequired { .. })));
        h.advance(30.0);
        assert!(h.flush_calls().is_empty(), "a response we cannot parse is not re-executed");
    }
}

#[test]
fn protocol_errors_after_repeated_rejections_are_terminal() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let mut events = Vec::new();
    for _ in 0..crate::session::MAX_PROTOCOL_STRIKES {
        let calls = h.flush_calls();
        assert_eq!(calls.len(), 1);
        h.reply(vec![Outgoing::Service(bad_msg_notification(calls[0].0, 1, 35))]);
        events.extend(h.events());
    }
    assert_eq!(failed_with(&events, 1), Some((500, "PROTOCOL_ERROR_BAD_MSG_35".into())));
    h.advance(30.0);
    assert!(h.flush_calls().is_empty());
}

#[test]
fn msg_wait_errors_wait_for_the_dependency_with_any_code() {
    for (code, message) in
        [(400, "MSG_WAIT_FAILED"), (500, "MSG_WAIT_FAILED"), (-503, "MSG_WAIT_TIMEOUT"), (400, "MSG_WAIT_TIMEOUT")]
    {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        h.send(1, RequestFlags::default());
        h.client.send(
            RpcRequest {
                id: RequestId(2),
                body: call(2),
                flags: RequestFlags::default(),
                invoke_after: Some(RequestId(1)),
            },
            h.now,
        );
        let calls = h.flush_calls();
        let first = calls.iter().find(|c| c.2 == 1).unwrap().0;
        let dependent = calls.iter().find(|c| c.2 == 2).unwrap().0;
        h.reply(vec![Outgoing::Content(rpc_error(dependent, code, message))]);
        assert!(failed_with(&h.events(), 2).is_none(), "{code} {message}");
        assert!(h.flush_calls().is_empty(), "{code} {message}: waits for the dependency");
        h.reply(vec![Outgoing::Content(rpc_error(first, 400, "PEER_ID_INVALID"))]);
        let calls = h.flush_calls();
        assert_eq!(calls.iter().map(|c| c.2).collect::<Vec<_>>(), vec![2], "{code} {message}");
        assert!(calls[0].1.is_empty(), "resent without the stale wrapper");
    }
}

#[test]
fn negative_and_normalized_codes_are_retried_as_server_errors() {
    for (code, message) in [
        (-500, "SOMETHING"),
        (0, "ZERO_CODE"),
        (12345, "HUGE"),
        (500, "INTERDC_2_CALL_ERROR"),
        (500, "WORKER_BUSY_TOO_LONG_RETRY"),
        (500, "RANDOM_ID_DUPLICATE"),
        (500, "TL_PARSING_ERROR"),
        (500, "AUTH_KEY_UNSYNCHRONIZED"),
    ] {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        h.send(1, RequestFlags::default());
        let calls = h.flush_calls();
        h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, code, message))]);
        assert!(failed_with(&h.events(), 1).is_none(), "{code} {message}");
        h.advance(SERVER_ERROR_RETRY_DELAY + 0.1);
        assert_eq!(h.flush_calls().len(), 1, "{code} {message}");
    }
}

#[test]
fn other_negative_codes_surface_like_mtprotokit() {
    for (code, message) in [(-503, "Timeout"), (-1, "X"), (-400, "NEGATIVE")] {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        let flags =
            RequestFlags { retry_server_errors: true, delegate_retry_decisions: true, ..RequestFlags::default() };
        h.send(1, flags);
        let calls = h.flush_calls();
        h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, code, message))]);
        let events = h.events();
        assert_eq!(failed_with(&events, 1), Some((code, message.into())), "{code} {message}");
        assert!(!events.iter().any(|event| matches!(event, RpcEvent::RetryDecisionRequired { .. })));
        h.advance(30.0);
        assert!(h.flush_calls().is_empty(), "{code} {message}: sent exactly once");
    }
}

#[test]
fn delegated_server_error_retries_back_off() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let flags = RequestFlags { delegate_retry_decisions: true, ..RequestFlags::default() };
    h.send(1, flags);
    let mut expected = [2.0, 4.0, 8.0, 16.0, 16.0].into_iter();
    for round in 0..5 {
        let calls = h.flush_calls();
        assert_eq!(calls.len(), 1, "round {round}");
        h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 500, "INTERNAL"))]);
        h.client.decide_retry(RequestId(1), true, h.now);
        let delay = expected.next().unwrap();
        h.advance(delay - 0.1);
        assert!(h.flush_calls().is_empty(), "round {round}: waits {delay} s");
        h.advance(0.2);
    }
}

#[test]
fn flood_wait_delays_are_bounded() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_0"))]);
    assert!(h.flush_calls().is_empty(), "FLOOD_WAIT_0 still waits a second");
    h.advance(1.1);
    assert_eq!(h.flush_calls().len(), 1);

    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_99999999999"))]);
    let deadline = h.client.poll_timeout(h.now).unwrap();
    assert!(deadline <= h.now.mono + MAX_FLOOD_WAIT_SECONDS as f64 + 1.0);
    assert!(failed_with(&h.events(), 1).is_none());

    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 420, "FLOOD_WAIT_999999999999999999999999"))]);
    assert!(failed_with(&h.events(), 1).is_some(), "an unparsable wait surfaces");
}

#[test]
fn every_migrate_error_surfaces_verbatim() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for (code, message) in [
        (303, "PHONE_MIGRATE_4"),
        (303, "NETWORK_MIGRATE_2"),
        (303, "USER_MIGRATE_5"),
        (303, "FILE_MIGRATE_3"),
        (303, "STATS_MIGRATE_1"),
        (400, "FILE_MIGRATE_3"),
    ] {
        let events = h.single_error(SessionRole::Main, code, message);
        assert_eq!(failed_with(&events, 1), Some((code, message.to_string())));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, RpcEvent::AuthorizationRequired { .. } | RpcEvent::SoftAuthReset { .. }))
        );
    }
}

#[test]
fn main_session_401_family_requires_authorization() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for message in [
        "AUTH_KEY_UNREGISTERED",
        "AUTH_KEY_INVALID",
        "USER_DEACTIVATED",
        "USER_DEACTIVATED_BAN",
        "SESSION_REVOKED",
        "SESSION_EXPIRED",
    ] {
        let events = h.single_error(SessionRole::Main, 401, message);
        assert!(events.contains(&RpcEvent::AuthorizationRequired { message: message.into() }), "{message}");
        assert_eq!(failed_with(&events, 1), Some((401, message.to_string())));
    }
    let events = h.single_error(SessionRole::Main, 401, "SESSION_PASSWORD_NEEDED");
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::AuthorizationRequired { .. })));
    assert_eq!(failed_with(&events, 1), Some((401, "SESSION_PASSWORD_NEEDED".into())));
}

#[test]
fn token_workers_refresh_the_token_on_any_401_but_park_only_revocations() {
    let role = SessionRole::Worker { requires_auth_token: true };
    let mut h = Harness::new(role, Some("h1"));
    for message in ["AUTH_KEY_INVALID", "USER_DEACTIVATED", "SESSION_EXPIRED"] {
        let events = h.single_error(role, 401, message);
        assert!(events.contains(&RpcEvent::AuthTokenRequired), "{message}");
        assert_eq!(failed_with(&events, 1), Some((401, message.to_string())));
        assert!(!events.iter().any(|e| matches!(e, RpcEvent::AuthorizationRequired { .. })));
    }
    for message in ["AUTH_KEY_UNREGISTERED", "SESSION_REVOKED"] {
        let events = h.single_error(role, 401, message);
        assert!(events.contains(&RpcEvent::AuthTokenRequired));
        assert!(failed_with(&events, 1).is_none(), "{message} parks the request");
    }
    let events = h.single_error(role, 401, "SESSION_PASSWORD_NEEDED");
    assert!(!events.contains(&RpcEvent::AuthTokenRequired));
}

#[test]
fn plain_workers_and_cdn_never_log_out() {
    for role in [SessionRole::Worker { requires_auth_token: false }, SessionRole::Cdn] {
        let mut h = Harness::new(role, Some("h1"));
        let events = h.single_error(role, 401, "AUTH_KEY_UNREGISTERED");
        assert_eq!(failed_with(&events, 1), Some((401, "AUTH_KEY_UNREGISTERED".into())));
        assert!(
            !events.iter().any(|e| matches!(e, RpcEvent::AuthorizationRequired { .. } | RpcEvent::AuthTokenRequired))
        );
        let events = h.single_error(role, 406, "AUTH_KEY_DUPLICATED");
        assert_eq!(failed_with(&events, 1), Some((406, "AUTH_KEY_DUPLICATED".into())));
        assert!(!events.iter().any(|e| matches!(e, RpcEvent::SoftAuthReset { .. })));
    }
}

#[test]
fn other_error_classes_surface_verbatim() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for (code, message) in [
        (400, "PEER_ID_INVALID"),
        (400, "CONNECTION_API_ID_INVALID"),
        (400, "INPUT_METHOD_INVALID"),
        (400, "ENCRYPTED_MESSAGE_INVALID"),
        (400, "TEMP_AUTH_KEY_EMPTY"),
        (403, "CHAT_WRITE_FORBIDDEN"),
        (403, "RECAPTCHA_CHECK_MISSING_SEPARATOR"),
        (404, "METHOD_INVALID"),
        (406, "UPDATE_APP_TO_LOGIN"),
        (418, "I_AM_A_TEAPOT"),
        (420, "SLOWMODE_WAIT_10"),
        (420, "2FA_CONFIRM_WAIT_100"),
        (420, "TAKEOUT_INIT_DELAY_5"),
        (420, "PREMIUM_SUB_ACTIVE_UNTIL_1700000000"),
        (420, "FROZEN_METHOD_INVALID"),
        (502, "BAD_GATEWAY"),
        (400, ""),
    ] {
        let events = h.single_error(SessionRole::Main, code, message);
        assert_eq!(failed_with(&events, 1), Some((code, message.to_string())), "{code} {message}");
    }
    let events = h.single_error(SessionRole::Main, 406, "UPDATE_APP_TO_LOGIN");
    assert!(events.iter().any(|e| matches!(e, RpcEvent::SoftAuthReset { .. })));
}

#[test]
fn connection_initialization_errors_are_retried_a_bounded_number_of_times() {
    for message in ["CONNECTION_NOT_INITED", "CONNECTION_LAYER_INVALID"] {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        h.send(1, RequestFlags::default());
        let mut surfaced = None;
        for attempt in 0..=MAX_CONNECTION_NOT_INITED_RETRIES {
            let calls = h.flush_calls();
            assert_eq!(calls.len(), 1, "{message} attempt {attempt}");
            if attempt > 0 {
                assert_eq!(calls[0].1, vec![ids::INVOKE_WITH_LAYER, INIT_CONNECTION]);
            }
            h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 400, message))]);
            surfaced = failed_with(&h.events(), 1);
        }
        assert_eq!(surfaced, Some((400, message.to_string())));
    }
}

#[test]
fn invalid_utf8_error_messages_are_replaced() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error_raw(calls[0].0, 400, &[0xc3, 0x28, 0x41]))]);
    assert_eq!(failed_with(&h.events(), 1), Some((400, "INVALID_UTF8_ERROR_MESSAGE".into())));
}

#[test]
fn temporary_key_rejection_does_not_drop_sibling_results() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, RequestFlags::default());
    h.send(2, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![
        Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_PERM_EMPTY")),
        Outgoing::Content(rpc_result(calls[1].0, &[2, 0, 0, 0])),
        Outgoing::Content(update(0x74ae4240, &[0; 4])),
    ]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::TemporaryKeyRejected));
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Completed { id: RequestId(2), .. })));
    assert!(events.iter().any(|e| matches!(e, RpcEvent::Update { .. })));
}

#[test]
fn lost_updates_ask_the_host_for_a_difference() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.flush_calls();
    let old = h.server.next_msg_id(false);
    for _ in 0..2001 {
        h.reply(vec![Outgoing::Content(update(0x0101_0101, &[0; 4]))]);
    }
    h.events();
    let fresh = h.server.next_msg_id(false);
    let body = container(&[(old, 1, update(0x74ae4240, &[0; 4]))]);
    let packet = h.server.seal(fresh, 0, &body);
    h.client.handle_packet(&packet, h.now, &mut h.rng).unwrap();
    let events = h.events();
    assert!(events.contains(&RpcEvent::UpdatesReset));
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Update { .. })));
}

#[test]
fn msg_wait_errors_without_a_dependency_follow_their_code() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let events = h.single_error(SessionRole::Main, 400, "MSG_WAIT_FAILED");
    assert_eq!(failed_with(&events, 1), Some((400, "MSG_WAIT_FAILED".into())), "no hot loop without a dependency");
    let events = h.single_error(SessionRole::Main, -500, "MSG_WAIT_TIMEOUT");
    assert!(failed_with(&events, 1).is_none(), "retried as a server error");
    h.advance(SERVER_ERROR_RETRY_DELAY + 0.1);
    assert_eq!(h.flush_calls().len(), 1);
}

#[test]
fn cdn_sessions_never_forward_updates() {
    let mut h = Harness::new(SessionRole::Cdn, Some("h1"));
    h.flush_calls();
    h.reply(vec![Outgoing::Content(update(0x1234_5678, &[0; 8]))]);
    let events = h.events();
    assert!(
        !events.iter().any(|event| matches!(event, RpcEvent::Update { .. } | RpcEvent::UpdatesReset)),
        "{events:?}"
    );
}

#[test]
fn oversized_or_unaligned_requests_fail_locally_instead_of_reaching_the_wire() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for (id, body) in [(1u64, vec![0u8; MAX_REQUEST_BYTES + 4]), (2, vec![0u8; 6]), (3, Vec::new())] {
        h.client
            .send(RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None }, h.now);
    }
    let failed: Vec<u64> = h
        .events()
        .into_iter()
        .filter_map(|event| match event {
            RpcEvent::Failed { id, code: 400, message, .. } if message == REQUEST_INVALID_SIZE => Some(id.0),
            _ => None,
        })
        .collect();
    assert_eq!(failed, vec![1, 2, 3]);
    assert!(h.flush_calls().is_empty());
}
