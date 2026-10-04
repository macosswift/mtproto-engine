#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event));
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("LOG {message}");
        }
    }
}

impl Collector {
    fn wait<F: Fn(&[(SessionHandle, EngineEvent)]) -> bool>(&self, timeout: Duration, predicate: F) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            if predicate(&events) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, event)| predicate(event)).count()
    }
}

fn completions(events: &[(SessionHandle, EngineEvent)]) -> usize {
    events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))).count()
}

fn completed(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events
        .iter()
        .any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
}

fn binds(events: &[(SessionHandle, EngineEvent)]) -> usize {
    events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyBound))).count()
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

const PERM_SEED: u64 = 400;

fn server() -> TestServer {
    TestServer::start(
        vec![random_key(PERM_SEED)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

fn material(key: AuthKey) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn pfs_setup(port: u16, perm: Option<AuthKey>, lifetime: i32) -> SessionSetup {
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = perm.map(material);
    setup.pfs = Some(PfsSetup {
        lifetime,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup.http_port = None;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);

/// Logout under engine-run PFS: `destroy_auth_key` has to reach the server under the permanent key
/// (tdlib turns PFS off for it); destroying the temporary key leaves the permanent key alive.
#[test]
fn destroy_auth_key_under_pfs_destroys_the_permanent_key() {
    let mut outcomes = Vec::new();
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let server = server();
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let perm = random_key(PERM_SEED);
        let mut setup = pfs_setup(server.address.port(), Some(perm.clone()), 86_400);
        setup.transport = transport;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(WAIT, |events| completions(events) == 1), "{transport:?}: call 1");
        engine.destroy_auth_key(session);
        let destroyed = collector.wait(WAIT, |events| {
            events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. })))
        });
        let keys = server.with_stats(|stats| stats.destroyed_keys.clone());
        engine.shutdown();
        eprintln!(
            "{transport:?}: destroyed event {destroyed}, destroy_auth_key arrived under {keys:x?}, perm {:x}",
            perm.id()
        );
        outcomes.push((transport, destroyed, keys.contains(&perm.id()), keys));
    }
    for (transport, destroyed, perm_destroyed, keys) in outcomes {
        assert!(destroyed, "{transport:?}: no AuthKeyDestroyed");
        assert!(
            perm_destroyed,
            "{transport:?}: destroy_auth_key went under {keys:x?}, not the permanent key: the permanent key survives logout"
        );
    }
}

/// A request the host was asked to decide on (RetryDecisionRequired) must wait for the decision; a
/// routine key rotation must not quietly send it again.
#[test]
fn a_rotation_does_not_resend_a_request_waiting_for_a_retry_decision() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 60));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let mut decided = request(2, TAG_SERVER_ERROR_ONCE);
    decided.flags.delegate_retry_decisions = true;
    engine.send(session, decided);
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::RetryDecisionRequired { .. })))
    }));
    let rotated = collector.wait(Duration::from_secs(70), |events| binds(events) >= 2);
    std::thread::sleep(Duration::from_secs(3));
    let executions = server.executions(TAG_SERVER_ERROR_ONCE);
    let ran = completed(&collector.events.lock().unwrap(), 2);
    engine.shutdown();
    eprintln!("decision pending: rotated {rotated}, executions {executions}, completed without a decision {ran}");
    assert!(rotated, "no rotation within 70 s");
    assert!(
        !ran && executions == 1,
        "the rotation re-sent a request still waiting for the host's retry decision ({executions} executions, completed {ran})"
    );
}

/// Control for the test above: without a rotation the request waits for the decision.
#[test]
fn control_without_rotation_a_request_waits_for_its_retry_decision() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let mut decided = request(2, TAG_SERVER_ERROR_ONCE);
    decided.flags.delegate_retry_decisions = true;
    engine.send(session, decided);
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::RetryDecisionRequired { .. })))
    }));
    std::thread::sleep(Duration::from_secs(50));
    let executions = server.executions(TAG_SERVER_ERROR_ONCE);
    let ran = completed(&collector.events.lock().unwrap(), 2);
    engine.shutdown();
    eprintln!("control: executions {executions}, completed {ran}");
    assert!(!ran && executions == 1);
}

/// Auto with TCP blackholed runs on HTTP; the key rotation closes every connection and must carry on
/// over HTTP without a stall.
#[test]
fn auto_on_http_rotates_keys_and_calls_keep_flowing() {
    let server = server();
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 60);
    setup.transport = TransportPreference::Auto;
    let session = engine.create_session(setup);
    let started = Instant::now();
    let mut id = 0u64;
    let mut slowest = Duration::ZERO;
    while started.elapsed() < Duration::from_secs(62) {
        id += 1;
        let sent = Instant::now();
        engine.send(session, request(id, (id % 900) as u32));
        assert!(collector.wait(Duration::from_secs(20), |events| completions(events) == id as usize), "call {id}");
        if id > 1 {
            slowest = slowest.max(sent.elapsed());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let temps = server.with_stats(|stats| stats.temporary_keys);
    let dups = server.with_stats(|stats| stats.duplicate_executions);
    let rotated = collector.count(
        |event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { message, .. }) if message == "TEMP_KEY_ROTATED"),
    );
    engine.shutdown();
    eprintln!(
        "auto on http: {id} calls, {temps} temporary keys, slowest {slowest:?}, dups {dups}, rotated failures {rotated}"
    );
    assert!(temps >= 2);
    assert_eq!(dups, 0);
    assert!(slowest < Duration::from_secs(8), "a call took {slowest:?}");
}

/// The host hands the session a different permanent key (another authorization). Without PFS the next
/// call runs under the new key at once; under engine PFS it must not keep running under a temporary
/// key bound to the old permanent key.
#[test]
fn calls_after_a_permanent_key_change_do_not_run_under_the_old_binding() {
    let old_perm = random_key(PERM_SEED);
    let new_perm = random_key(PERM_SEED + 1);
    let server = TestServer::start(
        vec![old_perm.clone(), new_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(old_perm.clone()), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    engine.send(session, request(2, TAG_SLOW));
    std::thread::sleep(Duration::from_millis(50));
    engine.set_auth_key(session, Some(material(new_perm.clone())));
    engine.send(session, request(3, 3));
    assert!(collector.wait(WAIT, |events| completed(events, 3)));
    let call2_rotated = collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| {
            matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) if id.0 == 2 && message == "TEMP_KEY_ROTATED")
        })
    });
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    engine.shutdown();
    assert!(call2_rotated, "call 2, in flight under the old authorization, did not fail as TEMP_KEY_ROTATED");
    let call3 = ran.iter().find(|(tag, _)| *tag == 3).map(|(_, perm)| *perm);
    eprintln!("calls and the permanent key they ran under: {ran:x?}; old {:x}, new {:x}", old_perm.id(), new_perm.id());
    assert_eq!(
        call3,
        Some(new_perm.id()),
        "call 3, sent after set_auth_key(new), ran under the old permanent key's binding"
    );
}

/// The server refuses every bind with a key error: each refusal asks for a new temporary key, and key
/// creation must back off rather than run handshakes (each on a fresh connection) back to back.
#[test]
fn binds_refused_with_a_key_error_do_not_storm_handshakes() {
    let mut worst = 0;
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        for error in ["TEMP_AUTH_KEY_EMPTY", "TEMP_AUTH_KEY_ALREADY_BOUND", "EXPIRES_AT_INVALID"] {
            let server = TestServer::start(
                vec![random_key(PERM_SEED)],
                ServerOptions {
                    handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
                    refuse_binds: Some(error),
                    ..Default::default()
                },
            );
            let collector = Arc::new(Collector::default());
            let engine = engine(&collector);
            let mut setup = pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400);
            setup.transport = transport;
            let session = engine.create_session(setup);
            engine.send(session, request(1, 1));
            std::thread::sleep(Duration::from_secs(5));
            let temps = server.with_stats(|stats| stats.temporary_keys);
            let connections = server.with_stats(|stats| stats.connections);
            let http = server.with_stats(|stats| stats.http.requests);
            engine.shutdown();
            eprintln!(
                "{transport:?} {error}: {temps} temporary keys, {connections} connections, {http} HTTP requests in 5 s"
            );
            worst = worst.max(temps);
        }
    }
    assert!(worst <= 5, "up to {worst} temporary keys in 5 s");
}

mod middlebox;

/// HTTP handshake answered once with 429 (and once with 502): one failure event, a back-off, then
/// the key is made.
#[test]
fn http_handshake_status_errors_back_off_once_and_recover() {
    for status in [429u16, 502] {
        let server = TestServer::start(
            vec![],
            ServerOptions {
                handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
                ..Default::default()
            },
        );
        let (port, stats) = middlebox::start(
            server.address,
            Arc::new(move |info: middlebox::Info| {
                if info.plain && info.plain_index == 0 {
                    middlebox::Action::Respond(status, Vec::new())
                } else {
                    middlebox::Action::Forward
                }
            }),
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        setup.key_generation = Some(mtproto_engine::KeyGeneration {
            temporary_expires_in: None,
            public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        });
        setup.transport = TransportPreference::Http;
        setup.http_port = None;
        let session = engine.create_session(setup);
        let started = Instant::now();
        engine.send(session, request(1, 1));
        let done = collector.wait(Duration::from_secs(30), |events| completions(events) == 1);
        let took = started.elapsed();
        let failed = collector.count(|event| matches!(event, EngineEvent::AuthKeyCreationFailed { .. }));
        let floods = collector.count(|event| matches!(event, EngineEvent::TransportFlood));
        let drops: Vec<String> = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::ConnectionDropped { reason, .. } => Some(reason.name().to_string()),
                _ => None,
            })
            .collect();
        let plain = stats.plain.load(std::sync::atomic::Ordering::SeqCst);
        engine.shutdown();
        eprintln!(
            "{status}: done {done} in {took:?}, creation failures {failed}, floods {floods}, drops {drops:?}, plain {plain}"
        );
        assert!(done);
        assert_eq!(failed, 1, "{status}");
    }
}

/// An idle session that disconnects when idle: what does a rotation cost, and is the new key bound?
#[test]
fn idle_session_rotation_binds_the_key_it_makes() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 60);
    setup.keep_connected = false;
    setup.idle_disconnect_after = Some(2.0);
    setup.role = SessionRole::Worker { requires_auth_token: false };
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    std::thread::sleep(Duration::from_secs(65));
    let temps = server.with_stats(|stats| stats.temporary_keys);
    let binds = server.with_stats(|stats| stats.binds);
    let connections = server.with_stats(|stats| stats.connections);
    let started = Instant::now();
    engine.send(session, request(2, 2));
    let done = collector.wait(WAIT, |events| completions(events) == 2);
    let took = started.elapsed();
    let temps_after = server.with_stats(|stats| stats.temporary_keys);
    let rejections = server.with_stats(|stats| stats.expired_key_rejections);
    engine.shutdown();
    eprintln!(
        "idle: after 65 s {temps} temporary keys, {binds} binds, {connections} connections; call 2 done {done} in {took:?}, keys now {temps_after}, expired-key rejections {rejections}"
    );
    assert!(done);
    assert!(binds >= temps, "{temps} temporary keys made while idle but only {binds} bound");
    assert_eq!(temps, 1, "an idle session made a new key it had no call for");
}
