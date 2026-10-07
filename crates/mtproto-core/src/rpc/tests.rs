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

fn first_init_connection(role: SessionRole) -> (i32, Vec<Vec<u8>>, Vec<u8>) {
    let mut h = Harness::new(role, None);
    let mut env = environment("h1");
    env.proxy = Some(ClientProxy { address: "proxy.example".into(), port: 443 });
    env.params = Some(vec![0x99, 0x71, 0xb5, 0x99, 0, 0, 0, 0]);
    h.client.update_environment(env, None, h.now);
    h.send(1, RequestFlags::default());
    let mut body = None;
    for _ in 0..10 {
        h.advance(0.002);
        let _ = h.client.handle_timeout(h.now);
        if let Some(transmit) = h.client.poll_transmit(h.now, &mut h.rng) {
            let packet = h.server.decode(&transmit.data);
            body = packet
                .messages
                .into_iter()
                .map(|message| message.body)
                .find(|body| body.starts_with(&ids::INVOKE_WITH_LAYER.to_le_bytes()));
            if body.is_some() {
                break;
            }
        }
    }
    let body = body.expect("the initializing call");
    let mut reader = Reader::new(&body);
    assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITH_LAYER);
    reader.read_i32().unwrap();
    assert_eq!(reader.read_u32().unwrap(), INIT_CONNECTION);
    let flags = reader.read_i32().unwrap();
    reader.read_i32().unwrap();
    let fields = (0..6).map(|_| reader.read_bytes().unwrap().to_vec()).collect();
    (flags, fields, reader.rest().to_vec())
}

#[test]
fn cdn_sessions_send_an_anonymous_init_connection() {
    let (flags, fields, rest) = first_init_connection(SessionRole::Cdn);
    assert_eq!(flags, 0, "no proxy and no params for a CDN");
    assert_eq!(fields[0], b"n/a");
    assert_eq!(fields[1], b"n/a");
    assert_eq!(fields[2], b"1");
    assert_eq!(fields[3], b"en");
    assert!(fields[4].is_empty() && fields[5].is_empty(), "no lang pack or lang code");
    assert_eq!(&rest[..4], &CALL.to_le_bytes());

    let (flags, fields, rest) = first_init_connection(SessionRole::Main);
    assert_eq!(flags, 3);
    assert_eq!(fields[0], b"Mac");
    assert_eq!(fields[4], b"macos");
    assert_eq!(&rest[..4], &INPUT_CLIENT_PROXY.to_le_bytes());
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
fn cdn_auth_key_perm_empty_surfaces_after_one_retry() {
    let mut h = Harness::new(SessionRole::Cdn, None);
    h.send(1, RequestFlags::default());
    let calls = h.flush_calls();
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_PERM_EMPTY"))]);
    let events = h.events();
    assert!(events.contains(&RpcEvent::TemporaryKeyRejected), "the host is asked for a fresh CDN key");
    assert!(!events.iter().any(|e| matches!(e, RpcEvent::Failed { .. })), "the first rejection is retried");
    h.advance(TEMPORARY_KEY_RETRY_DELAY);
    let calls = h.flush_calls();
    assert_eq!(calls.len(), 1);
    h.reply(vec![Outgoing::Content(rpc_error(calls[0].0, 401, "AUTH_KEY_PERM_EMPTY"))]);
    assert!(
        h.events().iter().any(|e| matches!(e, RpcEvent::Failed { id: RequestId(1), code: 401, .. })),
        "a CDN that keeps rejecting fails the request so the download falls back to the master DC"
    );
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
fn transmitted_requests_and_the_chains_hanging_off_them_are_found() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let chained = |id: u64, after: u64| RpcRequest {
        id: RequestId(id),
        body: call(id as u32),
        flags: RequestFlags::default(),
        invoke_after: Some(RequestId(after)),
    };
    assert!(!h.client.has_transmitted_requests());
    h.send(1, RequestFlags::default());
    h.client.send(chained(2, 1), h.now);
    h.flush_calls();
    h.client.send(chained(3, 2), h.now);
    h.send(4, RequestFlags::default());
    h.client.send(chained(5, 4), h.now);
    assert!(h.client.has_transmitted_requests());
    let mut transmitted = h.client.transmitted_requests();
    transmitted.sort();
    assert_eq!(transmitted, vec![RequestId(1), RequestId(2)]);
    assert_eq!(h.client.dependents_of(&[RequestId(1)]), vec![RequestId(2), RequestId(3)]);
    assert_eq!(h.client.dependents_of(&transmitted), vec![RequestId(3)]);
    assert!(h.client.dependents_of(&[RequestId(5)]).is_empty());
}

#[test]
fn requests_carried_to_a_new_session_keep_their_open_retry_questions() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    let flags = RequestFlags { delegate_retry_decisions: true, ..Default::default() };
    h.send(1, flags);
    h.send(3, flags);
    let calls = h.flush_calls();
    h.reply(calls.iter().map(|call| Outgoing::Content(rpc_error(call.0, 500, "INTERNAL"))).collect());
    assert_eq!(h.events().iter().filter(|event| matches!(event, RpcEvent::RetryDecisionRequired { .. })).count(), 2);
    h.send(2, RequestFlags::default());
    let now = h.now;
    let mut pending = h.client.into_pending();
    assert_eq!(pending.iter().map(PendingRequest::id).collect::<Vec<_>>(), [RequestId(1), RequestId(3), RequestId(2)]);
    let failed = pending[1].decide_retry(false, now).expect("a question is open").expect("a failure to report");
    assert!(
        matches!(failed, RpcEvent::Failed { id: RequestId(3), code: 500, ref message, .. } if message == "INTERNAL")
    );
    assert!(pending[1].decide_retry(true, now).is_none(), "answered once");
    pending.remove(1);
    let mut next = Harness::new(SessionRole::Main, Some("h1"));
    for request in pending {
        next.client.adopt(request, next.now);
    }
    next.advance(10.0);
    let tags: Vec<u32> = next.flush_calls().iter().map(|call| call.2).collect();
    assert_eq!(tags, [2], "the request with an open question waits for the host");
    next.client.decide_retry(RequestId(1), true, next.now);
    next.advance(10.0);
    let tags: Vec<u32> = next.flush_calls().iter().map(|call| call.2).collect();
    assert_eq!(tags, [1]);
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

mod pfs {
    use super::*;
    use crate::message::decrypt_message_v1;
    use crate::tl::TlRead;
    use crate::tl::mtproto::BindAuthKeyInner;

    fn perm_key() -> AuthKey {
        AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(91)))
    }

    struct SentBind {
        msg_id: i64,
        perm_id: i64,
        nonce: i64,
        expires_at: i32,
        inner_msg_id: i64,
        inner_seq_no: i32,
        inner: BindAuthKeyInner,
    }

    fn sent_bind(packet: &DecodedPacket) -> Option<SentBind> {
        let message = packet.messages.iter().find(|message| message.constructor() == ids::AUTH_BIND_TEMP_AUTH_KEY)?;
        let mut reader = Reader::new(&message.body[4..]);
        let perm_id = reader.read_i64().unwrap();
        let nonce = reader.read_i64().unwrap();
        let expires_at = reader.read_i32().unwrap();
        let encrypted = reader.read_bytes().unwrap().to_vec();
        let decrypted = decrypt_message_v1(&perm_key(), &encrypted, crate::crypto::Side::Client).expect("perm key");
        let inner = BindAuthKeyInner::read_from(&mut Reader::new(decrypted.body())).unwrap();
        Some(SentBind {
            msg_id: message.msg_id,
            perm_id,
            nonce,
            expires_at,
            inner_msg_id: decrypted.header.msg_id,
            inner_seq_no: decrypted.header.seq_no,
            inner,
        })
    }

    fn transmit(h: &mut Harness) -> Option<DecodedPacket> {
        h.advance(0.002);
        let transmit = h.client.poll_transmit(h.now, &mut h.rng)?;
        Some(h.server.decode(&transmit.data))
    }

    fn calls_in(packet: &DecodedPacket) -> Vec<u32> {
        packet.messages.iter().filter_map(|message| unwrap_call(&message.body).1).collect()
    }

    #[test]
    fn the_bind_goes_first_alone_and_carries_its_own_msg_id_and_session() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.client.hold_until_bound();
        h.send(1, RequestFlags::default());
        h.send(2, RequestFlags::default());
        let mut held = Vec::new();
        while let Some(packet) = transmit(&mut h) {
            held.extend(calls_in(&packet));
        }
        assert!(held.is_empty(), "no query before the bind: {held:?}");
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        let packet = transmit(&mut h).expect("the bind");
        let bind = sent_bind(&packet).expect("bind query");
        assert!(calls_in(&packet).is_empty(), "the bind travels alone");
        assert_eq!(bind.inner_msg_id, bind.msg_id, "inner msg_id is the bind's own");
        assert_eq!(bind.inner_seq_no, 0);
        assert_eq!(bind.perm_id, perm_key().id() as i64);
        assert_eq!(bind.inner.perm_auth_key_id, perm_key().id() as i64);
        assert_eq!(bind.inner.temp_auth_key_id, key().id() as i64);
        assert_eq!(bind.inner.temp_session_id, packet.header.session_id);
        assert_eq!(bind.inner.nonce, bind.nonce);
        assert_eq!(bind.inner.expires_at, bind.expires_at);
        assert!(transmit(&mut h).is_none_or(|packet| calls_in(&packet).is_empty()), "still held while unanswered");

        let mut writer = Writer::new();
        writer.write_u32(0x997275b5);
        let reply = h.server.encode(vec![Outgoing::Content(rpc_result(bind.msg_id, &writer.into_inner()))]);
        h.client.handle_packet(&reply, h.now, &mut h.rng).unwrap();
        let events: Vec<RpcEvent> = h.client.drain_events();
        assert!(events.contains(&RpcEvent::TemporaryKeyBound), "{events:?}");
        let mut sent = Vec::new();
        while let Some(packet) = transmit(&mut h) {
            sent.extend(calls_in(&packet));
        }
        sent.sort_unstable();
        assert_eq!(sent, vec![1, 2], "held queries go once bound");
    }

    #[test]
    fn a_refused_bind_keeps_queries_held_until_a_bind_succeeds() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.client.hold_until_bound();
        h.send(1, RequestFlags::default());
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        let first = sent_bind(&transmit(&mut h).unwrap()).unwrap();
        let reply = h.server.encode(vec![Outgoing::Content(rpc_error(first.msg_id, 400, "ENCRYPTED_MESSAGE_INVALID"))]);
        h.client.handle_packet(&reply, h.now, &mut h.rng).unwrap();
        let events = h.client.drain_events();
        assert!(
            events
                .contains(&RpcEvent::TemporaryKeyBindFailed { code: 400, message: "ENCRYPTED_MESSAGE_INVALID".into() }),
            "{events:?}"
        );
        assert!(!events.iter().any(|event| matches!(event, RpcEvent::Failed { .. })), "no host request fails");
        while let Some(packet) = transmit(&mut h) {
            assert!(calls_in(&packet).is_empty(), "still held after a refusal");
        }
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        let second = sent_bind(&transmit(&mut h).unwrap()).unwrap();
        assert_ne!(second.nonce, first.nonce);
        let mut writer = Writer::new();
        writer.write_u32(0x997275b5);
        let reply = h.server.encode(vec![Outgoing::Content(rpc_result(second.msg_id, &writer.into_inner()))]);
        h.client.handle_packet(&reply, h.now, &mut h.rng).unwrap();
        let mut sent = Vec::new();
        while let Some(packet) = transmit(&mut h) {
            sent.extend(calls_in(&packet));
        }
        assert_eq!(sent, vec![1]);
    }

    #[test]
    fn a_bind_resent_under_a_new_msg_id_is_encrypted_again_for_it() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.client.hold_until_bound();
        h.send(1, RequestFlags::default());
        h.send(2, RequestFlags::default());
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        let first = sent_bind(&transmit(&mut h).unwrap()).unwrap();
        let reply = h.server.encode(vec![Outgoing::Service(bad_server_salt(first.msg_id, 1, 6))]);
        h.client.handle_packet(&reply, h.now, &mut h.rng).unwrap();
        let second = sent_bind(&transmit(&mut h).expect("resent")).expect("bind again");
        assert_ne!(second.msg_id, first.msg_id);
        assert_eq!(second.inner_msg_id, second.msg_id, "the inner message follows the new msg_id");
    }

    #[test]
    fn a_rebind_goes_out_past_an_older_query_waiting_to_be_retransmitted() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.send(1, RequestFlags::default());
        assert_eq!(calls_in(&transmit(&mut h).expect("query 1")).len(), 1);
        h.advance(0.5);
        h.client.hold_until_bound();
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        sent_bind(&transmit(&mut h).expect("bind packet")).expect("bind query");
        h.client.connection_closed(h.now);
        h.advance(0.5);
        h.client.connection_opened(h.now);
        let mut binds = 0;
        while let Some(packet) = transmit(&mut h) {
            binds += usize::from(sent_bind(&packet).is_some());
            assert!(calls_in(&packet).is_empty(), "the held query stays held");
        }
        assert_eq!(binds, 1, "the bind goes again after the reconnect");
        assert!(h.client.poll_timeout(h.now).is_none_or(|at| at > h.now.mono), "no deadline in the past");
    }

    #[test]
    fn a_new_bind_goes_out_while_an_older_query_waits_to_be_retransmitted() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.send(1, RequestFlags::default());
        assert_eq!(calls_in(&transmit(&mut h).expect("query 1")).len(), 1);
        h.client.connection_closed(h.now);
        h.advance(0.5);
        h.client.hold_until_bound();
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        h.client.connection_opened(h.now);
        let mut binds = 0;
        while let Some(packet) = transmit(&mut h) {
            binds += usize::from(sent_bind(&packet).is_some());
        }
        assert_eq!(binds, 1);
        assert!(h.client.poll_timeout(h.now).is_none_or(|at| at > h.now.mono), "no deadline in the past");
    }

    #[test]
    fn over_http_a_held_retransmission_neither_blocks_the_bind_nor_floods_requests() {
        let mut h = Harness::new(SessionRole::Main, None);
        h.client.session_mut().set_http(true);
        h.send(1, RequestFlags::default());
        h.advance(0.002);
        let first = h
            .client
            .poll_http_transmit(h.now, &mut h.rng, crate::session::HttpWait::IMMEDIATE, false, true)
            .expect("query 1");
        h.client.http_packet_lost(first.packet_seq, h.now);
        h.client.hold_until_bound();
        h.client.bind_temporary_key(perm_key(), START as i32 + 86_400, h.now, &mut h.rng);
        let (mut requests, mut binds) = (0, 0);
        for _ in 0..100 {
            h.advance(0.002);
            if !h.client.wants_http_transmit(h.now) {
                break;
            }
            if let Some(transmit) =
                h.client.poll_http_transmit(h.now, &mut h.rng, crate::session::HttpWait::IMMEDIATE, false, true)
            {
                requests += 1;
                binds += usize::from(sent_bind(&h.server.decode(&transmit.data)).is_some());
                h.client.session_mut().http_packet_delivered(transmit.packet_seq, h.now);
            }
        }
        assert_eq!(binds, 1);
        assert!(requests < 5, "{requests} requests");
    }
}

fn rejected_every_time(flags: RequestFlags, rounds: usize) -> (usize, Vec<String>) {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send(1, flags);
    let mut sends = 0;
    let mut surfaced = Vec::new();
    for _ in 0..rounds {
        let calls = h.flush_calls();
        for (msg_id, _, _) in &calls {
            sends += 1;
            h.reply(vec![Outgoing::Service(bad_msg_notification(*msg_id, 1, 16))]);
        }
        for event in h.events() {
            match event {
                RpcEvent::Failed { message, .. } => surfaced.push(message),
                RpcEvent::RetryDecisionRequired { id, message, .. } => {
                    surfaced.push(format!("decision:{message}"));
                    h.client.decide_retry(id, true, h.now);
                }
                _ => {}
            }
        }
        if calls.is_empty() {
            h.advance(1.0);
        }
    }
    (sends, surfaced)
}

/// The session gives up on a query the server keeps rejecting (a salt or time loop) with
/// `PROTOCOL_ERROR_REJECTED`; the call fails to the host once instead of going again as a new query
/// with the rejection count back at zero, for good.
#[test]
fn a_query_rejected_too_often_fails_instead_of_starting_over() {
    for flags in [RequestFlags::default(), RequestFlags { delegate_retry_decisions: true, ..RequestFlags::default() }] {
        let (sends, surfaced) = rejected_every_time(flags, 600);
        assert_eq!(surfaced, vec![crate::session::PROTOCOL_REJECTED.to_string()], "{sends} sends");
        assert!(sends <= 20, "{sends} sends");
    }
}

/// The server ran a call whose answer it announced. While the answer does not come the call waits; once
/// the server says it no longer has it, the call fails to the host
/// once with `PROTOCOL_ERROR_ANSWER_LOST`, never as a retry decision, and it is never sent again as a new
/// message, which would run it a second time.
#[test]
fn a_call_whose_announced_answer_never_comes_fails_instead_of_running_again() {
    for flags in [RequestFlags::default(), RequestFlags { delegate_retry_decisions: true, ..RequestFlags::default() }] {
        let mut h = Harness::new(SessionRole::Main, Some("h1"));
        h.send(1, flags);
        let calls = h.flush_calls();
        assert_eq!(calls.len(), 1);
        let answer = h.server.next_msg_id(true);
        h.reply(vec![Outgoing::Service(msg_detailed_info(calls[0].0, answer, 40_000))]);
        let mut sends = calls.len();
        let mut surfaced = Vec::new();
        let mut last_request = None;
        let mut requests = 0;
        for second in 0..200 {
            if second == 150 {
                h.reply(vec![Outgoing::Service(msg_detailed_info(calls[0].0, answer, 40_000))]);
            }
            if second == 152 {
                let request = last_request.expect("the answer was asked for");
                h.reply(vec![Outgoing::Service(msgs_state_info(request, &[1]))]);
            }
            h.advance(1.0);
            let _ = h.client.handle_timeout(h.now);
            while let Some(transmit) = h.client.poll_transmit(h.now, &mut h.rng) {
                let packet = h.server.decode(&transmit.data);
                let mut pongs = Vec::new();
                for message in &packet.messages {
                    if unwrap_call(&message.body).1.is_some() {
                        sends += 1;
                    }
                    if message.constructor() == ids::MSG_RESEND_REQ {
                        requests += 1;
                        last_request = Some(message.msg_id);
                    }
                    if message.constructor() == ids::PING_DELAY_DISCONNECT || message.constructor() == ids::PING {
                        let ping_id = i64::from_le_bytes(message.body[4..12].try_into().unwrap());
                        pongs.push(Outgoing::Service(pong(message.msg_id, ping_id)));
                    }
                }
                if !pongs.is_empty() {
                    h.reply(pongs);
                }
            }
            for event in h.events() {
                match event {
                    RpcEvent::Failed { message, .. } => surfaced.push(message),
                    RpcEvent::RetryDecisionRequired { id, message, .. } => {
                        surfaced.push(format!("decision:{message}"));
                        h.client.decide_retry(id, true, h.now);
                    }
                    _ => {}
                }
            }
            if second == 149 {
                assert!(surfaced.is_empty(), "the call waits while its answer may still come: {surfaced:?}");
                assert!(requests >= 1, "the answer is asked for: {requests}");
            }
        }
        assert_eq!(sends, 1);
        assert_eq!(surfaced, vec![crate::session::ANSWER_LOST.to_string()]);
    }
}

#[path = "coverage_tests.rs"]
mod coverage;
