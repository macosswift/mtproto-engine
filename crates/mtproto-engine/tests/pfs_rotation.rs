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

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn server() -> TestServer {
    let perm = random_key(400);
    TestServer::start(
        vec![perm],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

fn pfs_setup(server: &TestServer, perm: Option<AuthKey>, lifetime: i32) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = perm.map(|key| AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.pfs = Some(PfsSetup {
        lifetime,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup.http_port = None;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);

fn temporary_keys_created(collector: &Collector) -> usize {
    collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: Some(_), .. }))
}

/// The key must go while answers are still on their way over TCP: the new key's handshake on the
/// same connection must not die on the old session's packets.
#[test]
fn a_rotation_with_answers_in_flight_over_tcp_does_not_break_the_new_handshake() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 60));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let started = Instant::now();
    let mut id = 1000u64;
    while started.elapsed() < Duration::from_secs(62) {
        id += 1;
        engine.send(session, request(id, TAG_SLOW));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_secs(2));
    let failures = collector.count(|event| matches!(event, EngineEvent::AuthKeyCreationFailed { .. }));
    let reasons: Vec<String> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::AuthKeyCreationFailed { reason } => Some(reason.clone()),
            _ => None,
        })
        .collect();
    let rotated = collector.count(
        |event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { message, .. }) if message == "TEMP_KEY_ROTATED"),
    );
    let drops = collector.count(|event| matches!(event, EngineEvent::ConnectionDropped { .. }));
    let temps = temporary_keys_created(&collector);
    eprintln!("rotation: failures {failures} {reasons:?}, rotated {rotated}, drops {drops}, temp keys {temps}");
    engine.shutdown();
    assert_eq!(failures, 0, "the new key's handshake failed: {reasons:?}");
}

/// The host drops the session's key under PFS: the engine must not keep binding new temporary keys to
/// the permanent key the host just discarded.
#[test]
fn clearing_the_key_under_pfs_stops_using_the_old_permanent_key() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let binds_before = server.with_stats(|stats| stats.binds);
    engine.set_auth_key(session, None);
    engine.send(session, request(2, 2));
    let _ = collector.wait(Duration::from_secs(8), |events| completions(events) == 2);
    let binds_after = server.with_stats(|stats| stats.binds);
    let permanent_made = collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: None, .. }));
    let key_required = collector.count(|event| matches!(event, EngineEvent::AuthKeyRequired));
    let completed = collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })));
    eprintln!(
        "cleared key: binds {binds_before}->{binds_after}, permanent keys made {permanent_made}, key required {key_required}, completed {completed}"
    );
    engine.shutdown();
    assert!(
        permanent_made > 0 || key_required > 0,
        "after set_auth_key(None) the engine bound a new temporary key to the discarded permanent key ({binds_before}->{binds_after} binds) and ran call 2 under it"
    );
}

/// Over HTTP an answer the server pushes later rides a parked long poll. After a key rotation the
/// old session's long polls must not stand in for the new session's.
#[test]
fn after_a_rotation_over_http_late_answers_still_arrive_promptly() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, Some(random_key(400)), 60);
    setup.transport = TransportPreference::Http;
    setup.online = true;
    setup.keep_connected = true;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    std::thread::sleep(Duration::from_secs(2));
    let started = Instant::now();
    engine.send(session, request(2, TAG_SLOW));
    assert!(collector.wait(WAIT, |events| completions(events) == 2));
    let before = started.elapsed();
    assert!(collector.wait(Duration::from_secs(70), |events| {
        events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyBound))).count() >= 2
    }));
    let started = Instant::now();
    engine.send(session, request(3, TAG_SLOW));
    assert!(collector.wait(Duration::from_secs(30), |events| completions(events) == 3));
    let after = started.elapsed();
    eprintln!("late answer: before rotation {before:?}, after rotation {after:?}");
    engine.shutdown();
    assert!(after < Duration::from_secs(2), "a 300 ms answer took {after:?} after the rotation (before: {before:?})");
}

/// Auto on a slow but working TCP path while the session still makes its keys: the handshake's
/// answers show TCP works, so the session must not move to HTTP.
#[test]
fn auto_does_not_leave_a_working_slow_tcp_path_while_keys_are_made() {
    let server = server();
    let mut profile = mtproto_netsim::Profile::perfect();
    profile.latency = Duration::from_millis(250);
    profile.connect_delay = Duration::from_millis(500);
    let sim = mtproto_netsim::NetSim::start(server.address, profile, 21).unwrap();
    for transport in [TransportPreference::Tcp, TransportPreference::Auto] {
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = pfs_setup(&server, None, 86_400);
        setup.addresses[0].port = sim.address.port();
        setup.transport = transport;
        let http_before = server.with_stats(|stats| stats.http.requests);
        let session = engine.create_session(setup);
        let started = Instant::now();
        engine.send(session, request(1, 1));
        let done = collector.wait(Duration::from_secs(30), |events| completions(events) == 1);
        let took = started.elapsed();
        let http = server.with_stats(|stats| stats.http.requests) - http_before;
        let switched = collector.count(|event| {
            matches!(event, EngineEvent::ConnectionDropped { reason: mtproto_engine::DropReason::TransportSwitch, .. })
        });
        engine.shutdown();
        eprintln!(
            "slow TCP: {transport:?}: done {done} in {took:?}, HTTP requests {http}, transport switches {switched}"
        );
        assert!(done);
        if transport == TransportPreference::Auto {
            assert_eq!(
                switched, 0,
                "Auto moved to HTTP although TCP was answering the handshake ({http} HTTP requests)"
            );
        }
    }
}
