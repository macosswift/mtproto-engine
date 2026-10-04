//! Its own test binary, so that the process's CPU time measures nothing but the engine under test.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    completed: Mutex<usize>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })) {
            *self.completed.lock().unwrap() += 1;
            self.condvar.notify_all();
        }
    }
}

impl Collector {
    fn wait_for(&self, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut completed = self.completed.lock().unwrap();
        while *completed < count {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            completed = self.condvar.wait_timeout(completed, deadline - now).unwrap().0;
        }
        true
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn session_setup(
    port: u16,
    key: &mtproto_engine::mtproto_core::auth_key::AuthKey,
    transport: TransportPreference,
) -> SessionSetup {
    let now = unix_seconds();
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = transport;
    setup.http_port = None;
    setup.online = true;
    setup
}

fn measure(seconds: f64) -> f64 {
    let started = cpu_seconds();
    std::thread::sleep(Duration::from_secs_f64(seconds));
    (cpu_seconds() - started) / seconds
}

#[test]
fn idle_and_stalled_http_sessions_cost_next_to_no_cpu() {
    let key = random_key(301);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let session = engine.create_session(session_setup(server.address.port(), &key, TransportPreference::Http));
    engine.send(session, request(1, 1));
    assert!(collector.wait_for(1, Duration::from_secs(10)));
    std::thread::sleep(Duration::from_millis(500));
    let idle = measure(6.0);

    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_millis(500));
    let unanswered = measure(6.0);
    engine.shutdown();

    let blackholed = {
        server.set_tcp_blackhole(true);
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let mut setup = session_setup(server.address.port(), &key, TransportPreference::Auto);
        setup.addresses.push(DcAddress { host: "192.0.2.1".into(), port: 443, secret: None });
        let session = engine.create_session(setup);
        engine.send(session, request(3, 3));
        assert!(collector.wait_for(1, Duration::from_secs(20)));
        std::thread::sleep(Duration::from_millis(500));
        let cost = measure(6.0);
        engine.shutdown();
        cost
    };

    let unreachable = {
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let session = engine.create_session(session_setup(port, &key, TransportPreference::Http));
        engine.send(session, request(4, 4));
        std::thread::sleep(Duration::from_millis(1500));
        let cost = measure(6.0);
        engine.shutdown();
        cost
    };

    let without_route = {
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let mut http = session_setup(server.address.port(), &key, TransportPreference::Http);
        http.proxy = Some(mtproto_engine::ProxyConfig::MtProxy {
            host: "127.0.0.1".into(),
            port: server.address.port(),
            secret: vec![0x11; 16],
        });
        let first = engine.create_session(http);
        engine.send(first, request(5, 5));
        let mut auto = session_setup(server.address.port(), &key, TransportPreference::Auto);
        auto.addresses[0].secret = Some(vec![0x22; 16]);
        let second = engine.create_session(auto);
        engine.send(second, request(6, 6));
        std::thread::sleep(Duration::from_secs(5));
        let cost = measure(6.0);
        engine.shutdown();
        cost
    };

    eprintln!(
        "CPU s/s: idle {idle:.4}, unanswered {unanswered:.4}, auto on HTTP {blackholed:.4}, unreachable {unreachable:.4}, no HTTP route {without_route:.4}"
    );
    assert!(without_route < 0.01, "HTTP with no possible route: {without_route:.4} CPU s/s");
    assert!(idle < 0.01, "idle HTTP session: {idle:.4} CPU s/s");
    assert!(unanswered < 0.01, "unanswered request over HTTP: {unanswered:.4} CPU s/s");
    assert!(blackholed < 0.02, "Auto on HTTP with TCP rechecks: {blackholed:.4} CPU s/s");
    assert!(unreachable < 0.01, "unreachable HTTP endpoint: {unreachable:.4} CPU s/s");
}
