//! Its own test binary, so that the process's CPU time measures nothing but the engine under test.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::ServerHandshake;
use mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
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
}

fn completed(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events
        .iter()
        .any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
}

fn failed(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id: done, .. }) if done.0 == id))
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn measure(seconds: f64) -> f64 {
    let started = cpu_seconds();
    std::thread::sleep(Duration::from_secs_f64(seconds));
    (cpu_seconds() - started) / seconds
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn material(key: &mtproto_engine::mtproto_core::auth_key::AuthKey) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn http_setup(port: u16, key: &mtproto_engine::mtproto_core::auth_key::AuthKey) -> SessionSetup {
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(material(key));
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.online = true;
    setup
}

/// HTTP session, paused: the host fails its unanswered call (`fail_request`) and drops the key. The
/// Failed event goes to `undelivered`; both deadline functions then return "now", but `drive_http`
/// returns before `pump_rpc_events` whenever the session wants no link (paused), so nothing drains it.
#[test]
fn paused_http_session_with_an_undelivered_event_does_not_spin() {
    let key = random_key(5001);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let session = engine.create_session(http_setup(server.address.port(), &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completed(events, 1)), "call 1");
    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_millis(300));
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_millis(200));
    let baseline = measure(2.0);
    engine.fail_request(session, RequestId(2), 500, "HOST_TIMEOUT".into());
    let reported_while_paused = collector.wait(Duration::from_millis(500), |events| failed(events, 2));
    engine.set_auth_key(session, None);
    std::thread::sleep(Duration::from_millis(300));
    let after_drop = measure(3.0);
    let reported = collector.wait(Duration::from_millis(10), |events| failed(events, 2));
    engine.shutdown();
    eprintln!(
        "CPU s/s paused idle {baseline:.4}; after fail_request + set_auth_key(None) {after_drop:.4}; \
         Failed(2) reported while paused before the key drop {reported_while_paused}, at the end {reported}"
    );
    assert!(after_drop < 0.05, "paused HTTP session with an undelivered event spins: {after_drop:.4} CPU s/s");
}

/// The same under engine PFS: paused HTTP session, fail_request and a new permanent key in one turn
/// (the R4 scenario `a_host_failed_call_is_reported_when_the_permanent_key_changes_in_the_same_turn`, on
/// HTTP while paused). drive_pfs regenerates even while paused and retire_rpc parks the event.
#[test]
fn paused_http_pfs_session_changing_its_permanent_key_does_not_spin() {
    let old_perm = random_key(5002);
    let new_perm = random_key(5003);
    let server = TestServer::start(
        vec![old_perm.clone(), new_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let mut setup = http_setup(server.address.port(), &old_perm);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| completed(events, 1)), "call 1");
    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_millis(300));
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_millis(200));
    engine.fail_request(session, RequestId(2), 500, "HOST_TIMEOUT".into());
    std::thread::sleep(Duration::from_millis(200));
    engine.set_auth_key(session, Some(material(&new_perm)));
    std::thread::sleep(Duration::from_millis(300));
    let cost = measure(3.0);
    let reported = collector.wait(Duration::from_millis(10), |events| failed(events, 2));
    engine.shutdown();
    eprintln!(
        "CPU s/s after fail_request + new permanent key while paused on HTTP {cost:.4}; Failed(2) reported {reported}"
    );
    assert!(cost < 0.05, "paused HTTP PFS session spins after a permanent key change: {cost:.4} CPU s/s");
}

/// Cost of a session whose destroy_auth_key was lost (requests held under the gate for good), over HTTP
/// and over TCP.
#[test]
fn cost_of_a_lost_destroy() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut costs = Vec::new();
    for http in [true, false] {
        let perm = random_key(5100 + u64::from(http));
        let server = TestServer::start(
            vec![perm.clone()],
            ServerOptions {
                handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
                ..Default::default()
            },
        );
        let hold_next = Arc::new(AtomicBool::new(false));
        let (port, _stats) = {
            let hold_next = hold_next.clone();
            middlebox::start(
                server.address,
                Arc::new(move |info: middlebox::Info| {
                    if !info.plain && hold_next.swap(false, Ordering::SeqCst) {
                        middlebox::Action::Hold
                    } else {
                        middlebox::Action::Forward
                    }
                }),
            )
        };
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let mut setup = http_setup(if http { port } else { server.address.port() }, &perm);
        if !http {
            setup.transport = TransportPreference::Tcp;
        }
        setup.pfs = Some(PfsSetup {
            lifetime: 86_400,
            public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
            ..Default::default()
        });
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(Duration::from_secs(15), |events| completed(events, 1)), "call 1");
        std::thread::sleep(Duration::from_millis(300));
        if http {
            hold_next.store(true, Ordering::SeqCst);
        } else {
            server.set_tcp_blackhole(true);
        }
        engine.destroy_auth_key(session);
        std::thread::sleep(Duration::from_millis(600));
        server.set_tcp_blackhole(false);
        let mut flagged = request(2, 2);
        flagged.flags.timeout_timer = true;
        engine.send(session, flagged);
        std::thread::sleep(Duration::from_secs(12));
        let cost = measure(6.0);
        let connections = server.with_stats(|stats| (stats.connections, stats.http.requests));
        let drops = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
            .count();
        let call2 = collector.wait(Duration::from_millis(10), |events| completed(events, 2));
        engine.shutdown();
        eprintln!(
            "http {http}: CPU s/s {cost:.4}, call 2 {call2}, server (connections, http requests) {connections:?}, drops {drops}"
        );
        costs.push((http, cost));
    }
    for (http, cost) in costs {
        assert!(cost < 0.02, "http {http}: {cost:.4}");
    }
}

/// Control for `paused_http_session_with_an_undelivered_event_does_not_spin`: the same steps
/// over TCP, where `drive` always reaches `pump_rpc_events`.
#[test]
fn control_paused_tcp_session_with_an_undelivered_event() {
    let key = random_key(5004);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let mut setup = http_setup(server.address.port(), &key);
    setup.transport = TransportPreference::Tcp;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completed(events, 1)), "call 1");
    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_millis(300));
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_millis(200));
    engine.fail_request(session, RequestId(2), 500, "HOST_TIMEOUT".into());
    let reported_while_paused = collector.wait(Duration::from_millis(500), |events| failed(events, 2));
    engine.set_auth_key(session, None);
    std::thread::sleep(Duration::from_millis(300));
    let after_drop = measure(3.0);
    engine.shutdown();
    eprintln!("TCP control: CPU s/s {after_drop:.4}; Failed(2) reported while paused {reported_while_paused}");
    assert!(after_drop < 0.05);
    assert!(reported_while_paused);
}
