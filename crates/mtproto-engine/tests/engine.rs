use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, ProxyConfig,
    SessionHandle, SessionSetup, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    threads: Mutex<HashSet<String>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        if let Some(name) = std::thread::current().name() {
            self.threads.lock().unwrap().insert(name.to_string());
        }
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

    fn completed(&self, session: SessionHandle) -> Vec<(RequestId, Vec<u8>)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _)| *handle == session)
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, body, .. }) => Some((*id, body.clone())),
                _ => None,
            })
            .collect()
    }

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, event)| predicate(event)).count()
    }
}

fn completions(events: &[(SessionHandle, EngineEvent)], session: SessionHandle) -> usize {
    events
        .iter()
        .filter(|(handle, event)| *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })))
        .count()
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup(server: &TestServer, key: &AuthKey, role: SessionRole) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        role,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>, workers: usize) -> Engine {
    Engine::new(EngineConfig { worker_threads: workers, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(10);

#[test]
fn requests_complete_with_correct_payloads() {
    let key = random_key(1);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    for id in 1..=50u64 {
        engine.send(session, request(id, (id % 900) as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 50));
    for (id, body) in collector.completed(session) {
        let (tag, payload) = parse_result(&body).expect("result");
        assert_eq!(tag as u64, id.0 % 900);
        assert_eq!(payload, id.0.to_le_bytes());
    }
    assert_eq!(server.with_stats(|stats| stats.connections), 1);
    engine.shutdown();
}

#[test]
fn many_sessions_run_on_separate_threads_concurrently() {
    let key = random_key(2);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 4);
    let mut sessions = vec![engine.create_session(setup(&server, &key, SessionRole::Main))];
    for _ in 0..6 {
        sessions.push(engine.create_session(setup(&server, &key, SessionRole::Worker { requires_auth_token: false })));
    }
    let threads: Vec<_> = sessions
        .iter()
        .enumerate()
        .map(|(index, session)| {
            let engine = engine.clone();
            let session = *session;
            std::thread::spawn(move || {
                for n in 0..200u64 {
                    engine.send(session, request(index as u64 * 1000 + n, (n % 500) as u32));
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(
        collector.wait(Duration::from_secs(20), |events| sessions
            .iter()
            .all(|session| completions(events, *session) == 200))
    );
    let names = collector.threads.lock().unwrap().clone();
    assert!(names.contains("mtproto-main"));
    assert!(names.iter().filter(|name| name.starts_with("mtproto-worker")).count() >= 2, "{names:?}");
    engine.shutdown();
}

#[test]
fn dropped_connection_recovers_without_duplicate_execution() {
    let key = random_key(3);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_DROP_CONNECTION_ONCE));
    engine.send(session, request(2, 5));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    assert_eq!(server.executions(TAG_DROP_CONNECTION_ONCE), 1, "query must not be executed twice");
    assert!(server.with_stats(|stats| stats.connections) >= 2);
    assert_eq!(server.with_stats(|stats| stats.state_requests), 0, "recovered without a state round trip");
    let results = collector.completed(session);
    assert_eq!(results.iter().filter(|(id, _)| id.0 == 1).count(), 1);
    engine.shutdown();
}

#[test]
fn flood_wait_and_server_errors_are_retried_transparently() {
    let key = random_key(4);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    let started = Instant::now();
    engine.send(session, request(1, TAG_FLOOD_ONCE));
    engine.send(session, request(2, TAG_SERVER_ERROR_ONCE));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(server.executions(TAG_FLOOD_ONCE), 2);
    assert_eq!(server.executions(TAG_SERVER_ERROR_ONCE), 2);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. }))), 0);
    engine.shutdown();
}

#[test]
fn large_response_reports_progress() {
    let key = random_key(5);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Worker { requires_auth_token: false }));
    let mut large = request(1, TAG_LARGE);
    large.flags.progress = true;
    engine.send(session, large);
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    let (_, body) = collector.completed(session).pop().unwrap();
    assert_eq!(parse_result(&body).unwrap().1.len(), LARGE_SIZE);
    let progress: Vec<f32> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::Progress { id, progress, .. } if *id == RequestId(1) => Some(*progress),
            _ => None,
        })
        .collect();
    assert!(!progress.is_empty(), "expected progress events");
    assert!(progress.windows(2).all(|w| w[0] <= w[1]));
    engine.shutdown();
}

#[test]
fn cancelled_requests_never_complete() {
    let key = random_key(6);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_SLOW));
    engine.send(session, request(2, 7));
    std::thread::sleep(Duration::from_millis(100));
    engine.cancel(session, RequestId(1));
    assert!(collector.wait(WAIT, |events| completions(events, session) >= 1));
    std::thread::sleep(Duration::from_millis(600));
    let completed: Vec<u64> = collector.completed(session).iter().map(|(id, _)| id.0).collect();
    assert_eq!(completed, vec![2]);
    engine.shutdown();
}

#[test]
fn paused_sessions_do_not_connect_until_resumed() {
    let key = random_key(7);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut paused = setup(&server, &key, SessionRole::Main);
    paused.paused = true;
    let session = engine.create_session(paused);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(server.with_stats(|stats| stats.connections), 0);
    engine.set_paused(session, false);
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_millis(200));
    assert!(server.with_stats(|stats| stats.closed_by_client) >= 1);
    engine.shutdown();
}

#[test]
fn generates_auth_key_with_handshake_then_serves_requests() {
    let server = TestServer::start(
        vec![],
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut generated = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    generated.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let session = engine.create_session(generated);
    engine.send(session, request(1, 9));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })), 1);
    assert_eq!(server.with_stats(|stats| stats.handshakes), 1);
    engine.shutdown();
}

#[test]
fn idle_workers_disconnect_and_reconnect_on_demand() {
    let key = random_key(8);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut worker = setup(&server, &key, SessionRole::Worker { requires_auth_token: false });
    worker.idle_disconnect_after = Some(0.3);
    let session = engine.create_session(worker);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    std::thread::sleep(Duration::from_millis(800));
    assert!(server.with_stats(|stats| stats.closed_by_client) >= 1);
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    assert!(server.with_stats(|stats| stats.connections) >= 2);
    engine.shutdown();
}

fn run_proxy_case(options: ServerOptions, proxy: Option<ProxyConfig>, address_secret: Option<Vec<u8>>) {
    let key = random_key(9);
    let server = TestServer::start(vec![key.clone()], options);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut config = setup(&server, &key, SessionRole::Main);
    config.addresses[0].secret = address_secret;
    if let Some(proxy) = proxy {
        config.proxy = Some(match proxy {
            ProxyConfig::Socks5 { username, password, .. } => {
                ProxyConfig::Socks5 { host: "127.0.0.1".into(), port: server.address.port(), username, password }
            }
            ProxyConfig::MtProxy { secret, .. } => {
                ProxyConfig::MtProxy { host: "localhost".into(), port: server.address.port(), secret }
            }
        });
        config.addresses[0].host = "149.154.167.51".into();
        config.addresses[0].port = 443;
    }
    let session = engine.create_session(config);
    for id in 1..=20 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 20));
    engine.shutdown();
}

#[test]
fn socks5_proxy_without_and_with_credentials() {
    run_proxy_case(
        ServerOptions { socks5: true, ..Default::default() },
        Some(ProxyConfig::Socks5 { host: String::new(), port: 0, username: None, password: None }),
        None,
    );
    run_proxy_case(
        ServerOptions { socks5: true, ..Default::default() },
        Some(ProxyConfig::Socks5 {
            host: String::new(),
            port: 0,
            username: Some("user".into()),
            password: Some("secret".into()),
        }),
        None,
    );
}

#[test]
fn mtproxy_simple_padded_and_fake_tls() {
    let simple = vec![0x11u8; 16];
    let mut padded = vec![0xdd];
    padded.extend_from_slice(&[0x22; 16]);
    let mut fake_tls = vec![0xee];
    fake_tls.extend_from_slice(&[0x33; 16]);
    fake_tls.extend_from_slice(b"www.example.com");
    for secret in [simple, padded, fake_tls] {
        run_proxy_case(
            ServerOptions { secret: Some(secret.clone()), ..Default::default() },
            Some(ProxyConfig::MtProxy { host: String::new(), port: 0, secret: secret.clone() }),
            None,
        );
        run_proxy_case(ServerOptions { secret: Some(secret.clone()), ..Default::default() }, None, Some(secret));
    }
}

#[test]
fn unknown_key_reports_invalid_and_recovers_with_new_key() {
    let old = random_key(10);
    let new = random_key(11);
    let server = TestServer::start(vec![new.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &old, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(
        collector
            .wait(WAIT, |events| events.iter().any(|(_, e)| matches!(e, EngineEvent::AuthKeyInvalid { code: -404 })))
    );
    assert_eq!(
        collector.count(|event| matches!(event, EngineEvent::AddressResult { success: false, .. })),
        0,
        "a routine -404 does not mark the address as broken"
    );
    engine.set_auth_key(session, Some(AuthKeyMaterial { key: new, salts: salts(), init_hash: None }));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.shutdown();
}

#[test]
fn bad_server_salt_rotates_salt_and_executes_once() {
    let key = random_key(12);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_BAD_SALT_ONCE));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert_eq!(server.executions(TAG_BAD_SALT_ONCE), 1);
    assert!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::SaltsUpdated { .. }))) >= 1);
    engine.shutdown();
}

#[test]
fn updates_and_session_resets_are_delivered() {
    let key = random_key(13);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_UPDATE_PUSH));
    engine.send(session, request(2, TAG_NEW_SESSION));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    assert!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. }))) >= 1);
    assert!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::UpdatesReset))) >= 1);
    engine.shutdown();
}

#[test]
fn main_session_401_requests_authorization() {
    let key = random_key(14);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_UNAUTHORIZED));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, e)| matches!(e, EngineEvent::Rpc(RpcEvent::Failed { code: 401, .. })))
    }));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::AuthorizationRequired { .. }))), 1);
    engine.shutdown();
}

#[test]
fn network_unavailable_blocks_connections() {
    let key = random_key(15);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    engine.set_network_available(false);
    std::thread::sleep(Duration::from_millis(50));
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(server.with_stats(|stats| stats.connections), 0);
    engine.set_network_available(true);
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.shutdown();
}

#[test]
fn stalled_timed_requests_reconnect_and_retransmit_without_reexecution() {
    let key = random_key(16);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut worker = setup(&server, &key, SessionRole::Worker { requires_auth_token: false });
    worker.request_timeout = 0.4;
    let session = engine.create_session(worker);
    let mut stalled = request(1, TAG_NEVER);
    stalled.flags.timeout_timer = true;
    engine.send(session, stalled);
    assert!(collector.wait(WAIT, |_| server.with_stats(|stats| stats.connections) >= 2));
    assert!(collector.wait(WAIT, |_| server.with_stats(|stats| stats.duplicate_msg_ids) >= 1));
    assert_eq!(server.executions(TAG_NEVER), 1);
    engine.shutdown();
}

#[test]
fn destroyed_sessions_report_closed_and_reject_requests() {
    let key = random_key(17);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.destroy_session(session);
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, e)| matches!(e, EngineEvent::Closed))));
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, e)| matches!(e, EngineEvent::Rpc(RpcEvent::Failed { id: RequestId(2), .. })))
    }));
    engine.shutdown();
}

#[test]
fn connection_state_reports_connected_main_session() {
    let key = random_key(18);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(handle, e)| *handle == session
        && matches!(e, EngineEvent::ConnectionState { state, .. } if state.connected && !state.updating_connection_context))));
    engine.shutdown();
}

fn raw_request(id: u64, body: Vec<u8>) -> RpcRequest {
    RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None }
}

fn completed_ids(collector: &Collector, session: SessionHandle) -> Vec<u64> {
    collector.completed(session).iter().map(|(id, _)| id.0).collect()
}

#[test]
fn transport_flood_backs_off_and_retransmits_without_reexecution() {
    let key = random_key(30);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    let started = Instant::now();
    engine.send(session, raw_request(1, transport_error_call(-429)));
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events, session) == 1));
    assert!(started.elapsed() >= Duration::from_millis(900), "waited {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(4), "waited {:?}", started.elapsed());
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::TransportFlood)), 1);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
    assert_eq!(server.executions(TAG_TRANSPORT_ERROR_ONCE), 2);
    assert_eq!(
        server.with_stats(|stats| stats.state_requests),
        0,
        "retransmitted under the same msg_id, no state round trip"
    );
    engine.shutdown();
}

#[test]
fn other_transport_errors_reconnect_quickly() {
    for code in [-444, -403, -1, 7] {
        let key = random_key(31);
        let server = TestServer::start(vec![key.clone()], ServerOptions::default());
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector, 2);
        let session = engine.create_session(setup(&server, &key, SessionRole::Main));
        let started = Instant::now();
        engine.send(session, raw_request(1, transport_error_call(code)));
        assert!(collector.wait(WAIT, |events| completions(events, session) == 1), "code {code}");
        assert!(started.elapsed() < Duration::from_secs(4), "code {code}: {:?}", started.elapsed());
        assert!(server.with_stats(|stats| stats.connections) >= 2);
        assert_eq!(collector.count(|event| matches!(event, EngineEvent::TransportFlood)), 0);
        assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
        assert_eq!(
            collector.count(|event| matches!(event, EngineEvent::AddressResult { success: false, .. })),
            0,
            "code {code}"
        );
        engine.shutdown();
    }
}

fn generating_setup(server: &TestServer) -> SessionSetup {
    let mut generated = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    generated.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    generated
}

fn handshake_server(faults: Vec<HandshakeFault>) -> TestServer {
    TestServer::start(
        vec![],
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            handshake_faults: faults,
            ..Default::default()
        },
    )
}

#[test]
fn handshake_transport_error_restarts_key_generation_without_key_invalid() {
    let server = handshake_server(vec![
        HandshakeFault::TransportError(-404),
        HandshakeFault::TransportError(-444),
        HandshakeFault::TransportError(-429),
    ]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(generating_setup(&server));
    let started = Instant::now();
    engine.send(session, request(1, 9));
    assert!(collector.wait(Duration::from_secs(25), |events| completions(events, session) == 1));
    assert!(started.elapsed() >= Duration::from_millis(900), "the handshake flood delay applies");
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::TransportFlood)), 1);
    assert_eq!(
        collector.count(
            |event| matches!(event, EngineEvent::AuthKeyCreationFailed { reason } if reason.contains("transport error"))
        ),
        3
    );
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })), 1);
    engine.shutdown();
}

#[test]
fn stalled_handshake_is_raced_away_and_the_key_is_created() {
    let server = handshake_server(vec![HandshakeFault::Stall]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(generating_setup(&server));
    let started = Instant::now();
    engine.send(session, request(1, 9));
    assert!(collector.wait(Duration::from_secs(25), |events| completions(events, session) == 1));
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "silent handshake must not cost the 10 s timeout ({:?})",
        started.elapsed()
    );
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })), 1);
    engine.shutdown();
}

#[test]
fn server_pings_are_answered() {
    let key = random_key(32);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_SERVER_PING));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert!(collector.wait(WAIT, |_| server.with_stats(|stats| stats.client_pongs) >= 1));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. }))), 0);
    engine.shutdown();
}

#[test]
fn server_resend_request_is_answered_with_the_original_message() {
    let key = random_key(33);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_RESEND_REQ_ONCE));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert_eq!(server.with_stats(|stats| stats.retransmissions), 1);
    assert_eq!(server.with_stats(|stats| stats.retransmissions_in_container), 1);
    assert_eq!(server.with_stats(|stats| stats.connections), 1);
    engine.shutdown();
}

#[test]
fn copied_gzipped_and_noisy_answers_complete_on_one_connection() {
    let key = random_key(34);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_MSG_COPY));
    engine.send(session, request(2, TAG_GZIP));
    engine.send(session, request(3, TAG_GARBAGE_SIBLINGS));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 3));
    let mut ids = completed_ids(&collector, session);
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3]);
    for (id, body) in collector.completed(session) {
        let (_, payload) = parse_result(&body).expect("result");
        assert_eq!(payload, id.0.to_le_bytes());
    }
    assert_eq!(server.with_stats(|stats| stats.connections), 1, "garbage never forces a reconnect");
    assert_eq!(server.with_stats(|stats| stats.session_ids.len()), 1, "and never resets the session");
    assert!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. }))) >= 2);
    engine.shutdown();
}

#[test]
fn bad_msg_notifications_are_recovered_end_to_end() {
    for (code, container) in [
        (16, false),
        (20, false),
        (32, false),
        (33, false),
        (34, false),
        (48, false),
        (64, true),
        (19, true),
        (99, false),
    ] {
        let key = random_key(35);
        let server = TestServer::start(vec![key.clone()], ServerOptions::default());
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector, 2);
        let session = engine.create_session(setup(&server, &key, SessionRole::Main));
        engine.send(session, raw_request(1, bad_msg_call(code, container)));
        assert!(collector.wait(WAIT, |events| completions(events, session) == 1), "code {code}");
        assert_eq!(server.with_stats(|stats| stats.bad_msgs_sent), 1, "code {code}");
        let expected_sessions = if matches!(code, 32 | 33) { 2 } else { 1 };
        assert_eq!(server.with_stats(|stats| stats.session_ids.len()), expected_sessions, "code {code}");
        assert_eq!(server.with_stats(|stats| stats.connections), 1, "code {code}");
        engine.shutdown();
    }
}

#[test]
fn clock_skew_in_either_direction_is_corrected() {
    for offset in [1000.0, -1000.0, 200.0] {
        let key = random_key(36);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions { clock_offset: offset, validate_msg_id_time: true, ..Default::default() },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector, 2);
        let session = engine.create_session(setup(&server, &key, SessionRole::Main));
        for id in 1..=3 {
            engine.send(session, request(id, id as u32));
        }
        assert!(collector.wait(WAIT, |events| completions(events, session) == 3), "offset {offset}");
        let differences: Vec<f64> = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::TimeDifferenceUpdated { difference }) => Some(*difference),
                _ => None,
            })
            .collect();
        let last = *differences.last().expect("time difference reported");
        assert!((last - offset).abs() < 2.0, "offset {offset}: {differences:?}");
        engine.shutdown();
    }
}

#[test]
fn token_gate_survives_key_replacement() {
    let old = random_key(40);
    let new = random_key(41);
    let server = TestServer::start(vec![new.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &old, SessionRole::Worker { requires_auth_token: true }));
    engine.set_auth_token_ready(session, false);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_millis(300));
    engine.set_auth_key(session, Some(AuthKeyMaterial { key: new, salts: salts(), init_hash: None }));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(server.executions(1), 0, "requests must wait for the token after a key swap");
    engine.set_auth_token_ready(session, true);
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.shutdown();
}

#[test]
fn removing_the_key_keeps_pending_requests() {
    let key = random_key(42);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut paused = setup(&server, &key, SessionRole::Main);
    paused.paused = true;
    let session = engine.create_session(paused);
    engine.send(session, request(1, 1));
    engine.send(session, request(2, 2));
    engine.set_auth_key(session, None);
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, e)| matches!(e, EngineEvent::AuthKeyRequired))));
    engine.set_auth_key(session, Some(AuthKeyMaterial { key, salts: salts(), init_hash: None }));
    engine.set_paused(session, false);
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    engine.shutdown();
}

#[test]
fn obfuscation_dc_id_can_change_on_a_live_session() {
    let key = random_key(43);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.set_obfuscation_dc_id(session, -2);
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    let ids = server.with_stats(|stats| stats.obfuscation_dc_ids.clone());
    assert_eq!(ids.first(), Some(&2));
    assert_eq!(ids.last(), Some(&-2));
    engine.shutdown();
}

#[test]
fn connect_timeouts_report_failed_addresses() {
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(
        EngineConfig { worker_threads: 2, connect_timeout: 0.5, ..EngineConfig::default() },
        collector.clone(),
    )
    .unwrap();
    let key = random_key(44);
    let mut config =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "192.0.2.1".into(), port: 443, secret: None }]);
    config.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
    let session = engine.create_session(config);
    assert!(collector.wait(WAIT, |events| {
        events
            .iter()
            .any(|(handle, e)| *handle == session && matches!(e, EngineEvent::AddressResult { success: false, .. }))
    }));
    engine.shutdown();
}

#[test]
fn network_usage_reports_interface_kind() {
    let key = random_key(45);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(
        EngineConfig { worker_threads: 2, usage_report_interval: 0.1, ..EngineConfig::default() },
        collector.clone(),
    )
    .unwrap();
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| {
        events
            .iter()
            .any(|(_, e)| matches!(e, EngineEvent::NetworkUsage { incoming, cellular: false, .. } if *incoming > 0))
    }));
    engine.shutdown();
}

#[test]
fn connect_race_reaches_a_live_address_when_the_first_one_swallows_syns() {
    let key = random_key(40);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut session_setup = setup(&server, &key, SessionRole::Main);
    session_setup.addresses.insert(0, DcAddress { host: "192.0.2.1".into(), port: 443, secret: None });
    let started = std::time::Instant::now();
    let session = engine.create_session(session_setup);
    engine.send(session, request(1, 9));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "a black-holed first address must not cost the 12 s connect timeout ({:?})",
        started.elapsed()
    );
    engine.shutdown();
}

#[test]
fn verified_race_leaves_an_address_that_accepts_but_never_answers() {
    let key = random_key(41);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_address = silent.local_addr().unwrap();
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let keeper = {
        let held = held.clone();
        std::thread::spawn(move || {
            for stream in silent.incoming().take(4).flatten() {
                held.lock().unwrap().push(stream);
            }
        })
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let mut session_setup = setup(&server, &key, SessionRole::Main);
    session_setup
        .addresses
        .insert(0, DcAddress { host: silent_address.ip().to_string(), port: silent_address.port(), secret: None });
    let started = Instant::now();
    let session = engine.create_session(session_setup);
    engine.send(session, request(1, 9));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "a silent first address must be raced away in about 1.5 s ({:?})",
        started.elapsed()
    );
    assert_eq!(server.executions(9), 1);
    engine.shutdown();
    drop(keeper);
}

#[allow(unsafe_code)]
fn process_cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 * 1e-6;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 * 1e-6;
    user + system
}

#[test]
fn unresolvable_proxy_host_backs_off_instead_of_spinning() {
    let key = random_key(41);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut sessions = Vec::new();
    for role in [SessionRole::Main, SessionRole::Worker { requires_auth_token: false }, SessionRole::Cdn] {
        let mut config = setup(&server, &key, role);
        config.proxy = Some(ProxyConfig::Socks5 {
            host: "mtproto-engine-test.invalid".into(),
            port: 1080,
            username: None,
            password: None,
        });
        let session = engine.create_session(config);
        engine.send(session, request(1, 1));
        sessions.push(session);
    }
    std::thread::sleep(Duration::from_millis(300));
    let before = process_cpu_seconds();
    std::thread::sleep(Duration::from_secs(3));
    let used = process_cpu_seconds() - before;
    assert!(used < 0.6, "{used:.2} s of CPU in 3 s while the proxy host does not resolve");
    for session in sessions {
        assert!(collector.completed(session).is_empty());
    }
    engine.shutdown();
}

#[test]
fn a_racer_fed_endless_garbage_is_dropped_without_starving_the_worker() {
    use std::io::Write;
    let key = random_key(43);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_address = silent.local_addr().unwrap();
    let held = Arc::new(Mutex::new(Vec::new()));
    let keeper = {
        let held = held.clone();
        std::thread::spawn(move || {
            for stream in silent.incoming().take(8).flatten() {
                held.lock().unwrap().push(stream);
            }
        })
    };
    let garbage = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let garbage_address = garbage.local_addr().unwrap();
    let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let streamer = {
        let written = written.clone();
        let stop = stop.clone();
        garbage.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let chunk: Vec<u8> = (0..65536u32).map(|index| (index.wrapping_mul(2654435761) >> 13) as u8).collect();
            let mut streams: Vec<std::net::TcpStream> = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok((stream, _)) = garbage.accept() {
                    stream.set_write_timeout(Some(Duration::from_millis(50))).unwrap();
                    streams.push(stream);
                }
                streams.retain_mut(|stream| match stream.write(&chunk) {
                    Ok(count) => {
                        written.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
                        true
                    }
                    Err(error) => {
                        matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
                    }
                });
                if streams.is_empty() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut hostile = setup(&server, &key, SessionRole::Main);
    hostile.addresses = vec![
        DcAddress { host: silent_address.ip().to_string(), port: silent_address.port(), secret: None },
        DcAddress { host: garbage_address.ip().to_string(), port: garbage_address.port(), secret: None },
    ];
    let hostile_session = engine.create_session(hostile);
    engine.send(hostile_session, request(1, 7));
    std::thread::sleep(Duration::from_millis(2500));
    let healthy = engine.create_session(setup(&server, &key, SessionRole::Worker { requires_auth_token: false }));
    for id in 1..=5 {
        engine.send(healthy, request(id, 30 + id as u32));
    }
    assert!(
        collector.wait(WAIT, |events| completions(events, healthy) == 5),
        "a session sharing the worker must keep working while a racer is fed garbage"
    );
    let total = written.load(std::sync::atomic::Ordering::Relaxed);
    assert!(total < 64 * 1024 * 1024, "the engine kept reading garbage: {total} bytes");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    engine.shutdown();
    let _ = streamer.join();
    drop(keeper);
}

fn run_hostile_case(name: &str, chaos: mtproto_testserver::chaos::ChaosConfig, requests: u64) -> Result<(), String> {
    let key = random_key(77);
    let server = TestServer::start(vec![key.clone()], ServerOptions { chaos: Some(chaos), ..ServerOptions::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    let mut done = true;
    for wave in (1..=requests).collect::<Vec<_>>().chunks(4) {
        for &id in wave {
            engine.send(session, request(id, 100 + (id % 40) as u32));
        }
        let expected = *wave.last().unwrap();
        if !collector.wait(Duration::from_secs(30), |events| completions(events, session) as u64 >= expected) {
            done = false;
            break;
        }
    }
    let duplicates = server.with_stats(|stats| stats.duplicate_executions);
    let injected: usize = server.with_stats(|stats| stats.chaos_injected.values().sum());
    let connections = server.with_stats(|stats| stats.connections);
    if std::env::var_os("MTPROTO_HOSTILE_REPORT").is_some() {
        eprintln!("{name}: injected {injected}, connections {connections}");
    }
    engine.shutdown();
    if !done {
        return Err(format!("{name}: {} of {requests} completed", collector.completed(session).len()));
    }
    if duplicates != 0 {
        return Err(format!("{name}: {duplicates} duplicate executions"));
    }
    if injected == 0 {
        return Err(format!("{name}: no fault was injected"));
    }
    Ok(())
}

#[test]
fn hostile_server_faults_never_break_exactly_once_delivery() {
    use mtproto_testserver::chaos::{ChaosConfig, Fault};
    let mut cases: Vec<(String, ChaosConfig)> = Fault::HOSTILE
        .into_iter()
        .enumerate()
        .map(|(index, fault)| (fault.name().to_string(), ChaosConfig::only(900 + index as u64, fault, 0.2)))
        .collect();
    cases.push(("all-hostile".into(), ChaosConfig::hostile(999, 0.02)));
    let handles: Vec<_> =
        cases.into_iter().map(|(name, chaos)| std::thread::spawn(move || run_hostile_case(&name, chaos, 80))).collect();
    let failures: Vec<String> = handles.into_iter().filter_map(|handle| handle.join().unwrap().err()).collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

fn count_connections_in(
    listener: std::net::TcpListener,
    window: Duration,
    relay_to: Option<std::net::SocketAddr>,
) -> usize {
    use std::io::{Read, Write};
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + window;
    let mut accepted = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut client, _)) => {
                accepted += 1;
                if let Some(target) = relay_to {
                    std::thread::spawn(move || {
                        let Ok(mut upstream) = std::net::TcpStream::connect(target) else {
                            return;
                        };
                        client.set_nonblocking(false).unwrap();
                        let mut client_reader = client.try_clone().unwrap();
                        let mut upstream_writer = upstream.try_clone().unwrap();
                        std::thread::spawn(move || {
                            let mut buffer = [0u8; 65536];
                            while let Ok(read) = client_reader.read(&mut buffer) {
                                if read == 0 || upstream_writer.write_all(&buffer[..read]).is_err() {
                                    break;
                                }
                            }
                        });
                        let mut buffer = [0u8; 65536];
                        if let Ok(read) = upstream.read(&mut buffer)
                            && read > 0
                        {
                            let _ = client.write_all(&buffer[..read]);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                        let _ = client.shutdown(std::net::Shutdown::Both);
                        let _ = upstream.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(2)),
        }
    }
    accepted
}

#[test]
fn a_server_that_closes_every_connection_is_retried_at_a_bounded_rate() {
    let key = random_key(51);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let rejecting = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rejecting_address = rejecting.local_addr().unwrap();
    let mut config = setup(&server, &key, SessionRole::Main);
    config.addresses =
        vec![DcAddress { host: rejecting_address.ip().to_string(), port: rejecting_address.port(), secret: None }];
    config.keep_connected = true;
    let session = engine.create_session(config);
    engine.send(session, request(1, 1));
    let connections = count_connections_in(rejecting, Duration::from_secs(10), None);
    engine.shutdown();
    assert!((3..=20).contains(&connections), "{connections} connections in 10 s to a server that drops them all");
}

#[test]
fn a_path_that_cuts_every_connection_after_the_first_answer_does_not_cause_a_reconnect_storm() {
    let key = random_key(52);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let cutting = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cutting_address = cutting.local_addr().unwrap();
    let mut config = setup(&server, &key, SessionRole::Main);
    config.addresses =
        vec![DcAddress { host: cutting_address.ip().to_string(), port: cutting_address.port(), secret: None }];
    config.keep_connected = true;
    let session = engine.create_session(config);
    for id in 1..=3 {
        engine.send(session, request(id, id as u32));
    }
    let connections = count_connections_in(cutting, Duration::from_secs(15), Some(server.address));
    let completed = collector.completed(session).len();
    engine.shutdown();
    assert!(completed >= 1, "requests still get through a cutting path");
    assert!(connections <= 25, "{connections} connections in 15 s through a path that cuts each one");
}

#[test]
fn destroying_the_auth_key_on_logout_reaches_the_server() {
    let key = random_key(61);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    engine.destroy_auth_key(session);
    assert!(collector.wait(WAIT, |events| events.iter().any(|(handle, event)| *handle == session
        && matches!(
            event,
            EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed {
                outcome: mtproto_engine::mtproto_core::session::DestroyAuthKeyOutcome::Ok
            })
        ))));
    engine.shutdown();
}

#[test]
fn trickling_or_noisy_connections_are_abandoned_and_requests_complete() {
    std::thread::scope(|scope| {
        for mode in [0u64, 1, 2] {
            scope.spawn(move || {
                let key = random_key(60 + mode);
                let server = TestServer::start(vec![key.clone()], ServerOptions::default());
                let collector = Arc::new(Collector::default());
                let engine = engine(&collector, 1);
                let session = engine.create_session(setup(&server, &key, SessionRole::Main));
                let started = Instant::now();
                engine.send(session, raw_request(1, call(TAG_TRICKLE_ONCE, &mode.to_le_bytes())));
                assert!(
                    collector.wait(Duration::from_secs(60), |events| completions(events, session) == 1),
                    "mode {mode}: the request never completed"
                );
                let elapsed = started.elapsed();
                if mode == 0 {
                    assert!(elapsed >= Duration::from_secs(10), "mode {mode}: a progressing frame gets its grace");
                }
                assert!(elapsed < Duration::from_secs(45), "mode {mode}: abandoned after {elapsed:?}");
                assert!(server.with_stats(|stats| stats.connections) >= 2, "mode {mode}: reconnected");
                engine.shutdown();
            });
        }
    });
}

#[test]
fn persistent_transport_rejections_back_off() {
    let key = random_key(70);
    let server = TestServer::start(vec![key.clone()], ServerOptions { reject_with: Some(-444), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let session = engine.create_session(setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(10));
    let connections = server.with_stats(|stats| stats.connections);
    assert!((3..=6).contains(&connections), "{connections} connections in 10 s");
    assert!(collector.count(|event| matches!(event, EngineEvent::AddressResult { success: false, .. })) >= 1);
    engine.shutdown();
}

#[test]
fn slow_uplink_uploads_complete_without_reconnect_loops() {
    let key = random_key(80);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sim = mtproto_netsim::NetSim::start(server.address, mtproto_netsim::Profile::slow_uplink(), 7).unwrap();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut worker = setup(&server, &key, SessionRole::Worker { requires_auth_token: false });
    worker.addresses = vec![DcAddress { host: "127.0.0.1".into(), port: sim.address.port(), secret: None }];
    let session = engine.create_session(worker);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut payload: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    payload[..4].copy_from_slice(&16u32.to_le_bytes());
    let started = Instant::now();
    for id in 1..=2u64 {
        engine.send(session, raw_request(id, call(TAG_SIZED, &payload)));
    }
    assert!(
        collector.wait(Duration::from_secs(60), |events| completions(events, session) == 2),
        "uploads never finished; {} connections",
        sim.stats().connections
    );
    let stats = sim.stats();
    assert!(
        started.elapsed() > Duration::from_secs(8),
        "the link really was slow ({:?}, {} bytes up, {} down, {} connections)",
        started.elapsed(),
        stats.bytes_up,
        stats.bytes_down,
        stats.connections
    );
    assert!(sim.stats().connections <= 2, "{} connections: the upload was restarted", sim.stats().connections);
    engine.shutdown();
}
