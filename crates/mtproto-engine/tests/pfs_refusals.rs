//! Engine-run PFS against servers that keep refusing: every refusal ends in a new key, a backoff or
//! the host hearing of it, never the same request again and again for good.

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
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags { delegate_retry_decisions: true, ..RequestFlags::default() },
        invoke_after: None,
    }
}

const PERM_SEED: u64 = 400;

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
    setup.transport = TransportPreference::Tcp;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn refused_binds(code: i32, error: &'static str, seconds: u64) -> (usize, usize, usize) {
    let server = TestServer::start(
        vec![random_key(PERM_SEED)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            refuse_binds: Some(error),
            refuse_binds_code: Some(code),
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400));
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(seconds));
    let (binds, temps, connections) =
        server.with_stats(|stats| (stats.bind_failures.len(), stats.temporary_keys, stats.connections));
    engine.shutdown();
    eprintln!(
        "{code} {error}: {binds} binds of {temps} temporary key(s) on {connections} connection(s) in {seconds} s"
    );
    (binds, temps, connections)
}

/// 401, 403 and 406 on a bind refuse the key as a 400 does: a new one is made (with the refusal backoff)
/// instead of the same key being bound again for good.
#[test]
fn binds_refused_with_401_or_406_get_a_new_key() {
    for (code, error) in [(401, "AUTH_KEY_UNREGISTERED"), (406, "AUTH_KEY_DUPLICATED")] {
        let (binds, temps, _) = refused_binds(code, error, 12);
        assert!(temps >= 3, "{code}: {temps} temporary keys for {binds} binds");
        assert!(temps <= 8, "{code}: {temps} temporary keys: no backoff");
    }
}

/// FLOOD_WAIT_X on a bind is waited out: the key is not bound again before X seconds.
#[test]
fn a_bind_answered_with_flood_wait_waits_it_out() {
    let (binds, temps, _) = refused_binds(420, "FLOOD_WAIT_3600", 10);
    assert_eq!((binds, temps), (1, 1));
}

/// Binds that fail for no reason about the key (500, boolFalse) go again on the same key a few times,
/// then the key is replaced, as in MtProtoKit.
#[test]
fn a_key_whose_binds_keep_failing_is_replaced() {
    let (binds, temps, _) = refused_binds(500, "RPC_CALL_FAIL", 16);
    assert!(binds >= 3, "{binds}");
    assert!(temps >= 2, "{temps} temporary keys for {binds} binds");
}

/// A key handshake that always fails is retried with a backoff growing to a minute, not every second.
#[test]
fn a_handshake_that_always_fails_backs_off() {
    let server = TestServer::start(
        vec![random_key(PERM_SEED)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, foreign_fingerprint: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400));
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(20));
    let connections = server.with_stats(|stats| stats.connections);
    engine.shutdown();
    eprintln!("20 s of a handshake that always fails: {connections} connections");
    assert!(connections <= 7, "{connections}");
}

/// While calls wait for a temporary key to be bound, the session reports itself updating, so the
/// host shows "Connecting..." instead of a connected account whose calls never go out.
#[test]
fn a_session_waiting_for_a_bind_reports_updating() {
    for (code, error, perm_seed) in [(500, "RPC_CALL_FAIL", PERM_SEED), (400, "", 999)] {
        let server = TestServer::start(
            vec![random_key(PERM_SEED)],
            ServerOptions {
                handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
                refuse_binds: (!error.is_empty()).then_some(error),
                refuse_binds_code: Some(code),
                ..Default::default()
            },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(perm_seed)), 86_400));
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(8));
        let last_state = collector.events.lock().unwrap().iter().rev().find_map(|(_, e)| match e {
            EngineEvent::ConnectionState { state, .. } => Some(*state),
            _ => None,
        });
        engine.shutdown();
        let state = last_state.expect("a state");
        assert!(state.updating_connection_context, "bind refused ({code} {error:?}): {state:?}");
        assert!(state.awaiting_key_binding, "the link answers, so the route is not in question: {state:?}");
    }
}

/// The host replaces the permanent key and the server does not take binds under the new one at first:
/// as in tdlib, a key got less than a minute ago is not reported unknown (the host would drop it and
/// make another), the binds are tried again after a while instead.
#[test]
fn a_permanent_key_got_just_now_is_not_reported_unknown_at_once() {
    let server = TestServer::start(
        vec![random_key(PERM_SEED)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| {
        events.iter().any(|(_, e)| matches!(e, EngineEvent::Rpc(RpcEvent::Completed { id, .. }) if id.0 == 1))
    }));
    engine.set_auth_key(session, Some(material(random_key(999))));
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(15));
    let binds = server.with_stats(|stats| stats.bind_failures.len());
    let reported =
        collector.events.lock().unwrap().iter().any(|(_, event)| matches!(event, EngineEvent::PermanentKeyInvalid));
    engine.shutdown();
    assert!(binds >= 2, "the new key was tried: {binds} failed binds");
    assert!(!reported, "a key got just now was reported unknown");
}

/// The server answers AUTH_KEY_PERM_EMPTY again after the key was bound once more: the binding does not
/// hold, so the key is replaced (tdlib drops it on every AUTH_KEY_PERM_EMPTY) and the call goes out.
#[test]
fn a_binding_lost_again_after_a_rebind_gets_a_new_key() {
    let server = Arc::new(TestServer::start(
        vec![random_key(PERM_SEED)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    ));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| {
        events.iter().any(|(_, e)| matches!(e, EngineEvent::Rpc(RpcEvent::Completed { id, .. }) if id.0 == 1))
    }));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let unbinder = {
        let server = server.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                server.unbind_temporary_keys();
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    engine.send(session, request(2, 2));
    let temps_before = server.with_stats(|s| s.temporary_keys);
    let replaced = collector.wait(Duration::from_secs(60), |_| server.with_stats(|s| s.temporary_keys) > temps_before);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    unbinder.join().unwrap();
    engine.shutdown();
    assert!(replaced, "the temporary key was never replaced");
}
