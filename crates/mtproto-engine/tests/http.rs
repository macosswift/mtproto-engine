use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, DropReason, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration,
    ProxyConfig, SessionHandle, SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::chaos::ChaosConfig;
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

    fn drops(&self) -> Vec<(DropReason, bool)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::ConnectionDropped { reason, answered, .. } => Some((*reason, *answered)),
                _ => None,
            })
            .collect()
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

fn http_setup(server: &TestServer, key: &AuthKey, role: SessionRole) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        role,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
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

fn raw_request(id: u64, body: Vec<u8>) -> RpcRequest {
    RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(10);

fn assert_payloads(collector: &Collector, session: SessionHandle) {
    let completed = collector.completed(session);
    let mut seen = HashSet::new();
    for (id, body) in completed {
        assert!(seen.insert(id), "request {} completed twice", id.0);
        let (_, payload) = parse_result(&body).expect("result");
        assert_eq!(payload, id.0.to_le_bytes(), "request {}", id.0);
    }
}

#[test]
fn requests_complete_over_http() {
    let key = random_key(101);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    for id in 1..=60u64 {
        engine.send(session, request(id, (id % 900) as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 60));
    assert_payloads(&collector, session);
    let (requests, connections, duplicates) =
        server.with_stats(|stats| (stats.http.requests, stats.connections, stats.duplicate_executions));
    eprintln!("clean: {:?}", server.with_stats(|stats| stats.http.clone()));
    assert!(requests > 0);
    assert!(connections <= 6, "{connections} connections");
    assert_eq!(duplicates, 0);
    assert!(collector.drops().is_empty(), "{:?}", collector.drops());
    engine.shutdown();
}

#[test]
fn a_single_call_takes_one_round_trip() {
    let key = random_key(102);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    let started = Instant::now();
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 2));
    assert!(started.elapsed() < Duration::from_millis(80), "{:?}", started.elapsed());
    engine.shutdown();
}

#[test]
fn slow_answers_arrive_on_a_parked_long_poll() {
    let key = random_key(103);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    let started = Instant::now();
    for id in 1..=5u64 {
        engine.send(session, request(id, TAG_SLOW));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 5));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(700), "slow answers waited for a long poll to come back: {elapsed:?}");
    assert!(server.with_stats(|stats| stats.http.long_polls) >= 1);
    assert_payloads(&collector, session);
    engine.shutdown();
}

#[test]
fn megabyte_answers_are_not_downloaded_twice() {
    let key = random_key(104);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Worker { requires_auth_token: false }));
    for id in 1..=8u64 {
        engine.send(session, raw_request(id, call(TAG_LARGE, &id.to_le_bytes())));
    }
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events, session) == 8));
    let usage: u64 = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::NetworkUsage { incoming, .. } => Some(*incoming),
            _ => None,
        })
        .sum();
    engine.shutdown();
    let inline = server.with_stats(|stats| stats.http.inline_resends);
    assert!(usage < 8 * LARGE_SIZE as u64 * 5 / 4, "downloaded {usage} bytes for 8 MB of answers");
    assert_eq!(inline, 0, "no large answer is resent in full");
}

#[test]
fn the_auth_key_is_created_over_http() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut generated = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    generated.transport = TransportPreference::Http;
    generated.http_port = None;
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
fn http_404_follows_the_key_rejection_rule() {
    let old = random_key(105);
    let server = TestServer::start(vec![random_key(106)], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &old, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| {
        events
            .iter()
            .any(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { reason: DropReason::KeyInvalid, .. }))
    }));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { code: -404 })), 1);
    let drops = collector.drops();
    assert!(drops.contains(&(DropReason::KeyRejectedOnce, false)), "{drops:?}");
    assert!(drops.contains(&(DropReason::KeyInvalid, false)), "{drops:?}");
    engine.shutdown();
}

#[test]
fn idle_connections_closed_by_the_server_are_replaced_quietly() {
    let key = random_key(107);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { http_idle_timeout: Some(0.3), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Worker { requires_auth_token: false });
    setup.idle_disconnect_after = Some(30.0);
    let session = engine.create_session(setup);
    for id in 1..=4u64 {
        engine.send(session, request(id, id as u32));
        assert!(collector.wait(WAIT, |events| completions(events, session) == id as usize));
        std::thread::sleep(Duration::from_millis(600));
    }
    assert_payloads(&collector, session);
    assert!(server.with_stats(|stats| stats.http.idle_closes) >= 2);
    assert!(collector.drops().is_empty(), "an idle close is no failure: {:?}", collector.drops());
    engine.shutdown();
}

#[test]
fn a_connection_dropped_after_execution_resends_and_never_executes_twice() {
    let key = random_key(108);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_DROP_CONNECTION_ONCE));
    for id in 2..=10u64 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 10));
    assert_payloads(&collector, session);
    assert_eq!(server.executions(TAG_DROP_CONNECTION_ONCE), 1);
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    engine.shutdown();
}

#[test]
fn updates_reach_the_main_session_through_long_polls() {
    let key = random_key(109);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    engine.send(session, request(1, TAG_UPDATE_PUSH));
    assert!(collector.wait(WAIT, |events| completions(events, session) == 1));
    assert!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. }))) >= 1);
    engine.shutdown();
}

#[test]
fn uploads_of_half_megabyte_parts() {
    let key = random_key(110);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Worker { requires_auth_token: false }));
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for id in 1..=8u64 {
        let mut part = vec![0u8; 512 * 1024];
        for chunk in part.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        engine.send(session, raw_request(id, call(TAG_UPLOAD, &part)));
    }
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events, session) == 8));
    assert_eq!(server.executions(TAG_UPLOAD), 8);
    engine.shutdown();
}

#[test]
fn transport_flood_status_backs_off_and_retransmits() {
    let key = random_key(111);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
    let started = Instant::now();
    engine.send(session, raw_request(1, transport_error_call(-429)));
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events, session) == 1));
    assert!(started.elapsed() >= Duration::from_millis(900), "{:?}", started.elapsed());
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::TransportFlood)), 1);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
    engine.shutdown();
}

#[test]
fn through_a_socks5_proxy() {
    let key = random_key(112);
    let server = TestServer::start(vec![key.clone()], ServerOptions { socks5: true, ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some("secret".into()),
    });
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let session = engine.create_session(setup);
    for id in 1..=20 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 20));
    assert_payloads(&collector, session);
    engine.shutdown();
}

#[test]
fn mixed_chaos_completes_everything_exactly_once() {
    for seed in 1..=3u64 {
        let key = random_key(200 + seed);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions { chaos: Some(ChaosConfig::mixed(seed, 0.02)), ..Default::default() },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let session = engine.create_session(http_setup(&server, &key, SessionRole::Main));
        for id in 1..=200u64 {
            engine.send(session, request(id, (id % 900) as u32));
        }
        let done = collector.wait(Duration::from_secs(60), |events| completions(events, session) == 200);
        let duplicates = server.with_stats(|stats| stats.duplicate_records.clone());
        eprintln!("seed {seed}: {:?}", server.with_stats(|stats| stats.http.clone()));
        if !done {
            let finished: HashSet<u64> = collector.completed(session).iter().map(|(id, _)| id.0).collect();
            let missing: Vec<u64> = (1..=200).filter(|id| !finished.contains(id)).collect();
            let faults = server.with_stats(|stats| format!("{:?} http {:?}", stats.chaos_injected, stats.http));
            eprintln!("seed {seed}: missing {missing:?}; {faults}; drops {:?}", collector.drops());
        }
        assert!(done, "seed {seed}: {} of 200", collector.completed(session).len());
        assert_payloads(&collector, session);
        assert!(duplicates.is_empty(), "seed {seed}: {duplicates:?}");
        engine.shutdown();
    }
}

fn auto_setup(server: &TestServer, key: &AuthKey) -> SessionSetup {
    let mut setup = http_setup(server, key, SessionRole::Main);
    setup.transport = TransportPreference::Auto;
    setup
}

#[test]
fn auto_stays_on_tcp_while_tcp_works() {
    let key = random_key(120);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(auto_setup(&server, &key));
    for id in 1..=20u64 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 20));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(server.with_stats(|stats| stats.http.requests), 0, "no HTTP while TCP answers");
    engine.shutdown();
}

#[test]
fn auto_moves_to_http_when_tcp_is_blackholed() {
    let key = random_key(121);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(auto_setup(&server, &key));
    let started = Instant::now();
    for id in 1..=20u64 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, session) == 20));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(7), "fallback took {elapsed:?}");
    assert_payloads(&collector, session);
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    assert!(
        collector.drops().iter().any(|(reason, _)| *reason == DropReason::TransportSwitch),
        "{:?}",
        collector.drops()
    );
    engine.shutdown();
}

#[test]
fn auto_creates_the_key_over_http_when_tcp_is_blackholed() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            ..Default::default()
        },
    );
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut generated = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    generated.transport = TransportPreference::Auto;
    generated.http_port = None;
    generated.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let session = engine.create_session(generated);
    engine.send(session, request(1, 9));
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events, session) == 1));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })), 1);
    engine.shutdown();
}

#[test]
fn auto_returns_to_tcp_once_it_answers_again() {
    let key = random_key(122);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = auto_setup(&server, &key);
    setup.tcp_recheck_after = 1.0;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, session) == 1));
    std::thread::sleep(Duration::from_millis(1500));
    server.set_tcp_blackhole(false);
    let unblocked = Instant::now();
    let mut id = 1u64;
    let back_on_tcp = loop {
        id += 1;
        let http_before = server.with_stats(|stats| stats.http.requests);
        engine.send(session, request(id, id as u32));
        assert!(collector.wait(WAIT, |events| completions(events, session) == id as usize));
        if server.with_stats(|stats| stats.http.requests) == http_before {
            break unblocked.elapsed();
        }
        assert!(unblocked.elapsed() < Duration::from_secs(20), "still on HTTP after TCP came back");
        std::thread::sleep(Duration::from_millis(250));
    };
    assert!(back_on_tcp < Duration::from_secs(12), "{back_on_tcp:?}");
    assert_payloads(&collector, session);
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    engine.shutdown();
}

#[test]
fn auto_keeps_http_while_tcp_stays_blocked_without_flapping() {
    let key = random_key(123);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = auto_setup(&server, &key);
    setup.tcp_recheck_after = 0.5;
    let session = engine.create_session(setup);
    let started = Instant::now();
    let mut id = 0u64;
    while started.elapsed() < Duration::from_secs(8) {
        id += 1;
        let sent = Instant::now();
        engine.send(session, request(id, id as u32));
        assert!(collector.wait(Duration::from_secs(15), |events| completions(events, session) == id as usize));
        if id > 1 {
            assert!(sent.elapsed() < Duration::from_millis(500), "call {id} took {:?}", sent.elapsed());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let switches = collector.drops().iter().filter(|(reason, _)| *reason == DropReason::TransportSwitch).count();
    assert!(switches <= 1, "{:?}", collector.drops());
    engine.shutdown();
}

fn http_proxy(server: &TestServer, credentials: Option<(&str, &str)>) -> ProxyConfig {
    ProxyConfig::Http {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: credentials.map(|(user, _)| user.to_string()),
        password: credentials.map(|(_, password)| password.to_string()),
    }
}

#[test]
fn tcp_goes_through_an_http_connect_proxy() {
    let key = random_key(130);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            http_proxy: Some(HttpProxyMode::Both),
            http_proxy_credentials: Some("user:secret".into()),
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.transport = TransportPreference::Tcp;
    setup.proxy = Some(http_proxy(&server, Some(("user", "secret"))));
    setup.addresses[0].host = "149.154.167.51".into();
    let session = engine.create_session(setup);
    for id in 1..=10 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 10));
    assert!(server.with_stats(|stats| stats.proxy_tunnels) >= 1);
    assert_eq!(server.with_stats(|stats| stats.http.requests), 0);
    engine.shutdown();
}

#[test]
fn http_is_forwarded_by_an_http_proxy() {
    let key = random_key(131);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions { http_proxy: Some(HttpProxyMode::ForwardOnly), ..Default::default() },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.proxy = Some(http_proxy(&server, None));
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let session = engine.create_session(setup);
    for id in 1..=10 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events, session) == 10));
    assert!(server.with_stats(|stats| stats.http.requests) >= 1);
    assert_payloads(&collector, session);
    engine.shutdown();
}

#[test]
fn auto_forwards_http_when_the_proxy_refuses_connect() {
    let key = random_key(132);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions { http_proxy: Some(HttpProxyMode::ForwardOnly), ..Default::default() },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = auto_setup(&server, &key);
    setup.proxy = Some(http_proxy(&server, None));
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let session = engine.create_session(setup);
    let started = Instant::now();
    for id in 1..=10 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, session) == 10));
    assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
    assert!(server.with_stats(|stats| stats.proxy_refusals) >= 1);
    assert_payloads(&collector, session);
    engine.shutdown();
}

#[test]
fn wrong_proxy_credentials_back_off_instead_of_hammering() {
    let key = random_key(133);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            http_proxy: Some(HttpProxyMode::Both),
            http_proxy_credentials: Some("user:secret".into()),
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = auto_setup(&server, &key);
    setup.proxy = Some(http_proxy(&server, Some(("user", "wrong"))));
    setup.addresses[0].host = "149.154.167.51".into();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(6));
    let refusals = server.with_stats(|stats| stats.proxy_refusals);
    assert!(refusals >= 1);
    assert!(refusals <= 25, "{refusals} attempts in 6 s");
    assert_eq!(completions(&collector.events.lock().unwrap(), session), 0);
    let state = collector.events.lock().unwrap().iter().rev().find_map(|(_, event)| match event {
        EngineEvent::ConnectionState { state, .. } => Some(*state),
        _ => None,
    });
    assert!(state.is_some_and(|state| state.proxy_has_connection_issues), "{state:?}");
    engine.shutdown();
}

#[test]
fn parallel_large_answers_never_wait_for_a_read_timeout() {
    let key = random_key(140);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(http_setup(&server, &key, SessionRole::Worker { requires_auth_token: false }));
    let mut worst = Duration::ZERO;
    let mut total = 0usize;
    for round in 0..6u64 {
        let started = Instant::now();
        for index in 0..24u64 {
            let id = round * 100 + index + 1;
            let mut payload = 900_000u32.to_le_bytes().to_vec();
            payload.extend_from_slice(&id.to_le_bytes());
            engine.send(session, raw_request(id, call(TAG_SIZED, &payload)));
        }
        total += 24;
        assert!(
            collector.wait(Duration::from_secs(60), |events| completions(events, session) == total),
            "round {round}"
        );
        worst = worst.max(started.elapsed());
    }
    engine.shutdown();
    assert!(collector.drops().is_empty(), "{:?}", collector.drops());
    assert!(worst < Duration::from_secs(3), "a round took {worst:?}");
}

/// Answers every POST with a 404 page, as captive portals and proxy deny pages do.
fn start_captive_portal() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let counter = counter.clone();
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                let mut seen = Vec::new();
                loop {
                    let Ok(read) = stream.read(&mut buffer) else { return };
                    if read == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buffer[..read]);
                    while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&seen[..end]).to_string();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if seen.len() < end + 4 + length {
                            break;
                        }
                        seen.drain(..end + 4 + length);
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let body = b"<html><body>Please log in to the hotel Wi-Fi</body></html>";
                        let head = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body);
                    }
                }
            });
        }
    });
    (port, requests)
}

#[test]
fn a_captive_portal_404_never_counts_as_a_lost_key() {
    let (port, requests) = start_captive_portal();
    let key = random_key(141);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let now = unix_seconds();
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let invalid = collector.wait(Duration::from_secs(10), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { .. }))
    });
    engine.shutdown();
    assert!(!invalid, "a portal's 404 made the key count as lost");
    let sent = requests.load(std::sync::atomic::Ordering::Relaxed);
    assert!(sent <= 12, "{sent} requests to the portal in 10 s");
}

#[test]
fn auto_sessions_learn_from_each_other_that_only_http_gets_through() {
    let key = random_key(150);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let first = engine.create_session(auto_setup(&server, &key));
    engine.send(first, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, first) == 1));
    let mut worker = auto_setup(&server, &key);
    worker.role = SessionRole::Worker { requires_auth_token: false };
    let second = engine.create_session(worker);
    let started = Instant::now();
    engine.send(second, request(2, 2));
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, second) == 1));
    assert!(started.elapsed() < Duration::from_millis(1500), "the second session took {:?}", started.elapsed());
    engine.shutdown();
}
