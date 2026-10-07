use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, SessionHandle,
    SessionSetup, unix_seconds,
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

fn key_lost(event: &EngineEvent) -> bool {
    matches!(event, EngineEvent::AuthKeyInvalid { .. } | EngineEvent::PermanentKeyInvalid)
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn address(server: &TestServer) -> DcAddress {
    DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }
}

fn real_server(key: &AuthKey) -> TestServer {
    TestServer::start(
        vec![key.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

/// A session under its permanent key that may make keys itself (it has the RSA keys).
fn setup(server: &TestServer, key: &AuthKey) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(2, SessionRole::Main, vec![address(server)]);
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    setup.keep_connected = true;
    setup.http_port = None;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);

/// The path to the datacenter is taken over (an on-path attacker, or DNS or routing pointing at a
/// fake datacenter) and every connection is answered with the 4-byte `-404` frame. A transport error
/// is not authenticated, so the key that worked a moment ago must not be reported invalid: the session
/// checks it with a temporary key bound to it, and goes on once the real server is reachable again.
#[test]
fn forged_404_frames_never_report_a_working_permanent_key() {
    let key = random_key(9101);
    let server = real_server(&key);
    let fake = TestServer::start(Vec::new(), ServerOptions { reject_with: Some(-404), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));

    engine.set_addresses(session, vec![address(&fake)]);
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(5));
    let forged = fake.with_stats(|stats| stats.transport_errors_sent);
    assert!(forged >= 2, "the fake datacenter answered {forged} connections");
    assert_eq!(collector.count(key_lost), 0, "{forged} forged -404 frames reported the key invalid");

    engine.set_addresses(session, vec![address(&server)]);
    let settled = collector.wait(Duration::from_secs(30), |events| {
        events.iter().any(|(_, event)| match event {
            EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => id.0 == 2,
            EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) => id.0 == 2 && message == "TEMP_KEY_ROTATED",
            _ => false,
        })
    });
    engine.send(session, request(3, 3));
    let done = collector.wait(Duration::from_secs(30), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id, .. }) if id.0 == 3))
    });
    let bound = server.with_stats(|stats| stats.binds);
    let temporary_keys_reported =
        collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: Some(_), .. }));
    let in_use_reported = collector.count(|event| matches!(event, EngineEvent::TemporaryKeyInUse { .. }));
    engine.shutdown();
    assert!(settled, "the call made during the attack completes, or fails as TEMP_KEY_ROTATED");
    assert!(done, "calls go through once the real server is back");
    assert!(bound >= 1, "the permanent key was proven by a bound temporary key");
    assert_eq!(temporary_keys_reported, 0, "a key made for the check is never handed to the host");
    assert_eq!(in_use_reported, 0, "nor reported in use");
    assert_eq!(collector.count(key_lost), 0);
    assert!(server.keys().iter().any(|stored| stored.id() == key.id()));
}

/// A permanent key the server really lost is still reported, with the event the host expects for a
/// session under its permanent key, once binds to it fail with ENCRYPTED_MESSAGE_INVALID; the session
/// then makes a new permanent key as it did before the check, and the call goes through under it.
#[test]
fn a_permanent_key_the_server_lost_is_reported_after_the_check() {
    let key = random_key(9102);
    let server = real_server(&key);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    server.remove_key(key.id());
    engine.send(session, request(2, 2));
    let reported = collector.wait(Duration::from_secs(30), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { code: -404 }))
    });
    let recovered = collector.wait(Duration::from_secs(30), |events| completions(events) == 2);
    let permanent_keys_made =
        collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: None, .. }));
    engine.shutdown();
    assert!(reported, "a key the server lost is reported");
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::PermanentKeyInvalid)), 0);
    assert_eq!(permanent_keys_made, 1, "a new permanent key is made, as without the check");
    assert!(recovered, "the call goes through under the new key");
}

/// The host turns engine PFS on while the session runs it only to check its permanent key after -404s:
/// the session goes on with the host's PFS. The check's own key was never reported in use; the next
/// temporary key is made with the host's lifetime and reported, and a permanent key the server lost
/// is then reported the PFS way.
#[test]
fn enabling_pfs_during_a_key_check_hands_the_session_to_the_hosts_pfs() {
    let key = random_key(9203);
    let server = real_server(&key);
    let fake = TestServer::start(Vec::new(), ServerOptions { reject_with: Some(-404), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    engine.set_addresses(session, vec![address(&fake)]);
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(5));
    let in_use = |events: &[(SessionHandle, EngineEvent)]| {
        events.iter().filter(|(_, event)| matches!(event, EngineEvent::TemporaryKeyInUse { .. })).count()
    };
    let before = in_use(&collector.events.lock().unwrap());
    engine.enable_pfs(
        session,
        mtproto_engine::PfsSetup {
            lifetime: 3600,
            public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
            permanent_key_from_host: false,
            temporary_key: None,
        },
    );
    engine.set_addresses(session, vec![address(&server)]);
    assert!(collector.wait(Duration::from_secs(30), |events| completions(events) == 2));
    assert!(collector.wait(Duration::from_secs(15), |events| in_use(events) > before), "the host's key is reported");
    let lifetimes: Vec<f64> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::TemporaryKeyInUse { expires_at, .. } => Some(f64::from(*expires_at) - unix_seconds()),
            _ => None,
        })
        .collect();
    assert!(lifetimes.iter().all(|left| *left <= 3700.0), "a key in use outlives the host's lifetime: {lifetimes:?}");
    server.remove_key(key.id());
    server.drop_temporary_keys();
    engine.send(session, request(3, 3));
    assert!(collector.wait(Duration::from_secs(60), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::PermanentKeyInvalid))
    }));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
    engine.shutdown();
}
