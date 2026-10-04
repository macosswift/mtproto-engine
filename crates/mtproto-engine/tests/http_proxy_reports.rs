//! Review round 7 repros that do not measure CPU.
#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, ProxyConfig, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

mod middlebox;

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
            eprintln!("{:?} LOG {message}", Instant::now());
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

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

/// HTTP through a proxy that worked; the user then enters credentials the proxy refuses. The host
/// should hear about proxy issues as it does when the session starts with the wrong credentials
/// (`http_through_a_proxy_refusing_credentials_reports_proxy_issues`).
#[test]
fn proxy_issues_are_reported_after_a_proxy_change_over_http() {
    let key = random_key(7101);
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
    let proxy = |password: &str| ProxyConfig::Http {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some(password.into()),
    };
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.proxy = Some(proxy("secret"));
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completions(events, session) == 1), "first call");
    let mark = collector.events.lock().unwrap().len();
    let refused_before = server.with_stats(|stats| stats.proxy_refusals);
    engine.set_proxy(session, Some(proxy("wrong")));
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(10));
    let refusals = server.with_stats(|stats| stats.proxy_refusals) - refused_before;
    let states: Vec<_> = collector.events.lock().unwrap()[mark..]
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::ConnectionState { state, .. } => Some(*state),
            _ => None,
        })
        .collect();
    engine.shutdown();
    eprintln!("after the change: {refusals} refusals; states {states:?}");
    assert!(refusals >= 3, "only {refusals} refusals");
    assert!(
        states.iter().any(|state| state.proxy_has_connection_issues),
        "{refusals} refusals in 10 s after the proxy change and never proxy_has_connection_issues"
    );
}

/// The HTTP proxy the user entered is down (nothing listens). TCP through it reports proxy issues after
/// three failed attempts; HTTP through the same proxy never does.
#[test]
fn an_unreachable_proxy_is_reported_over_http_as_over_tcp() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut results = Vec::new();
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = SessionSetup::new(
            2,
            SessionRole::Main,
            vec![DcAddress { host: "149.154.167.51".into(), port: 443, secret: None }],
        );
        setup.auth_key = Some(AuthKeyMaterial { key: random_key(7102), salts: salts(), init_hash: None });
        setup.transport = transport;
        setup.http_port = Some(80);
        setup.proxy = Some(ProxyConfig::Http { host: "127.0.0.1".into(), port, username: None, password: None });
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        let reported = collector.wait(Duration::from_secs(15), |events| {
            events.iter().any(|(_, event)| {
                matches!(event, EngineEvent::ConnectionState { state, .. } if state.proxy_has_connection_issues)
            })
        });
        let drops = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
            .count();
        engine.shutdown();
        eprintln!("{transport:?}: proxy issues reported {reported} ({drops} failed connections)");
        results.push((transport, reported, drops));
    }
    for (transport, reported, drops) in results {
        assert!(
            reported,
            "{transport:?}: {drops} failed connections to the proxy in 15 s, never proxy_has_connection_issues"
        );
    }
}
