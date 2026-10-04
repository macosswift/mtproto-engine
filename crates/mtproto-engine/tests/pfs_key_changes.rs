#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
    SessionSetup, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    condvar: Condvar,
    logs: Mutex<Vec<String>>,
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
        self.logs.lock().unwrap().push(message.to_string());
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

fn completed(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events
        .iter()
        .any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
}

fn finished(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events.iter().any(|(_, event)| {
        matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) | EngineEvent::Rpc(RpcEvent::Failed { id: done, .. }) if done.0 == id)
    })
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

fn server_with(keys: Vec<AuthKey>) -> TestServer {
    TestServer::start(
        keys,
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

fn public_keys() -> Vec<mtproto_engine::mtproto_core::crypto::RsaPublicKey> {
    vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()]
}

fn pfs_setup(port: u16, perm: Option<AuthKey>, lifetime: i32, role: SessionRole) -> SessionSetup {
    let mut setup = SessionSetup::new(2, role, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = perm.map(material);
    setup.pfs = Some(PfsSetup { lifetime, public_keys: public_keys(), ..Default::default() });
    setup.http_port = None;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);
const WORKER: SessionRole = SessionRole::Worker { requires_auth_token: true };

/// A worker call parked for the auth token (401 AUTH_KEY_UNREGISTERED) is moved to the next session
/// by a key change. The host's set_auth_token_ready(true) lands while the new key is being made (no
/// client exists): the parked call must go again once the key is there.
#[test]
fn a_call_waiting_for_the_auth_token_resumes_when_the_token_arrives_during_a_key_change() {
    let mut results = Vec::new();
    for swap in [false, true] {
        let old_perm = random_key(PERM_SEED);
        let new_perm = random_key(PERM_SEED + 1);
        let server = server_with(vec![old_perm.clone(), new_perm.clone()]);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let session = engine.create_session(pfs_setup(server.address.port(), Some(old_perm), 86_400, WORKER));
        engine.send(session, request(1, 1));
        assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
        engine.send(session, request(2, TAG_UNAUTHORIZED));
        assert!(collector.wait(WAIT, |events| {
            events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthTokenRequired)))
        }));
        std::thread::sleep(Duration::from_millis(100));
        engine.set_paused(session, true);
        if swap {
            engine.set_auth_key(session, Some(material(new_perm.clone())));
        }
        std::thread::sleep(Duration::from_millis(100));
        engine.set_auth_token_ready(session, true);
        std::thread::sleep(Duration::from_millis(100));
        engine.set_paused(session, false);
        engine.send(session, request(3, 3));
        assert!(collector.wait(WAIT, |events| completed(events, 3)), "swap {swap}: call 3");
        std::thread::sleep(Duration::from_secs(2));
        let executions = server.executions(TAG_UNAUTHORIZED);
        let call2_done = finished(&collector.events.lock().unwrap(), 2);
        engine.shutdown();
        eprintln!("swap {swap}: call 2 executions {executions}, finished {call2_done}");
        results.push((swap, executions));
    }
    for (swap, executions) in results {
        assert!(
            executions >= 2,
            "key change {swap}: the call parked for the auth token never went again after set_auth_token_ready(true) ({executions} executions)"
        );
    }
}

/// Same without PFS: set_auth_key(None) while a worker call waits for the token, the token arrives
/// while the session makes its next key.
#[test]
fn without_pfs_a_call_waiting_for_the_auth_token_survives_a_key_drop() {
    let key = random_key(PERM_SEED + 7);
    let server = server_with(vec![key.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = SessionSetup::new(
        2,
        WORKER,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(material(key));
    setup.key_generation =
        Some(mtproto_engine::KeyGeneration { temporary_expires_in: None, public_keys: public_keys() });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
    engine.send(session, request(2, TAG_UNAUTHORIZED));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthTokenRequired)))
    }));
    std::thread::sleep(Duration::from_millis(100));
    engine.set_paused(session, true);
    engine.set_auth_key(session, None);
    engine.set_auth_token_ready(session, true);
    std::thread::sleep(Duration::from_millis(100));
    engine.set_paused(session, false);
    engine.send(session, request(3, 3));
    assert!(collector.wait(WAIT, |events| completed(events, 3)), "call 3");
    std::thread::sleep(Duration::from_secs(2));
    let executions = server.executions(TAG_UNAUTHORIZED);
    engine.shutdown();
    eprintln!("no pfs: call 2 executions {executions}");
    assert!(executions >= 2, "the call parked for the auth token never went again ({executions} executions)");
}

/// destroy_auth_key under engine PFS: the session leaves PFS to send it under the permanent key. Calls
/// still waiting then (and calls made afterwards) must not go out under the permanent key itself:
/// tdlib's destroying session sends no queries (Session::need_send_query is false while
/// can_destroy_auth_key()).
#[test]
fn calls_around_destroy_auth_key_under_pfs_do_not_run_under_the_permanent_key() {
    let perm = random_key(PERM_SEED);
    let server = server_with(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session =
        engine.create_session(pfs_setup(server.address.port(), Some(perm.clone()), 86_400, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_millis(100));
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_millis(50));
    engine.destroy_auth_key(session);
    std::thread::sleep(Duration::from_millis(50));
    engine.set_paused(session, false);
    let destroyed = collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. })))
    });
    let call2 = collector.wait(Duration::from_secs(3), |events| completed(events, 2));
    engine.send(session, request(3, 3));
    let call3 = collector.wait(Duration::from_secs(3), |events| completed(events, 3));
    let raw = server.with_stats(|stats| stats.executed_with_key.clone());
    engine.shutdown();
    eprintln!(
        "destroyed {destroyed}, call 2 {call2}, call 3 {call3}, calls and the key they arrived under {raw:x?}, perm {:x}",
        perm.id()
    );
    let under_perm: Vec<u32> = raw.iter().filter(|(_, key)| *key == perm.id()).map(|(tag, _)| *tag).collect();
    assert!(under_perm.is_empty(), "calls {under_perm:?} of a PFS session ran under the permanent key itself");
}

fn failed_with(events: &[(SessionHandle, EngineEvent)], id: u64) -> Option<String> {
    events.iter().find_map(|(_, event)| match event {
        EngineEvent::Rpc(RpcEvent::Failed { id: done, message, .. }) if done.0 == id => Some(message.clone()),
        _ => None,
    })
}

/// The host fails its only call in flight (`fail_request`, e.g. its own timeout) while the temporary
/// key is due: the session turns quiet and the key is replaced in the same turn. The host must still
/// get the Failed event it asked for.
#[test]
fn a_host_failed_call_is_reported_when_the_key_rotates_in_the_same_turn() {
    let server = server_with(vec![random_key(PERM_SEED)]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let started = Instant::now();
    let session =
        engine.create_session(pfs_setup(server.address.port(), Some(random_key(PERM_SEED)), 60, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
    std::thread::sleep(Duration::from_secs(40).saturating_sub(started.elapsed()));
    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_secs(50).saturating_sub(started.elapsed()));
    let binds_before = binds(&collector.events.lock().unwrap());
    engine.fail_request(session, RequestId(2), 500, "HOST_TIMEOUT".into());
    let reported = collector.wait(Duration::from_secs(5), |events| failed_with(events, 2).is_some());
    let rotated = collector.wait(Duration::from_secs(10), |events| binds(events) > binds_before);
    let message = failed_with(&collector.events.lock().unwrap(), 2);
    engine.shutdown();
    eprintln!("binds before {binds_before}, rotated after {rotated}, call 2 failed event {message:?}");
    assert!(rotated, "no rotation");
    assert!(reported, "fail_request(2) was never reported to the host: the event went with the replaced client");
}

/// The same with the key change forced by the host: fail_request and set_auth_key(new) in one turn.
#[test]
fn a_host_failed_call_is_reported_when_the_permanent_key_changes_in_the_same_turn() {
    let old_perm = random_key(PERM_SEED);
    let new_perm = random_key(PERM_SEED + 1);
    let server = server_with(vec![old_perm.clone(), new_perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(old_perm), 86_400, SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
    engine.send(session, request(2, TAG_NEVER));
    std::thread::sleep(Duration::from_millis(300));
    engine.fail_request(session, RequestId(2), 500, "HOST_TIMEOUT".into());
    engine.set_auth_key(session, Some(material(new_perm)));
    engine.send(session, request(3, 3));
    assert!(collector.wait(WAIT, |events| completed(events, 3)), "call 3");
    let message = failed_with(&collector.events.lock().unwrap(), 2);
    engine.shutdown();
    eprintln!("call 2 failed event {message:?}");
    assert!(message.is_some(), "fail_request(2) was never reported to the host");
}

/// Logout destroys every datacenter's key, also on worker sessions that are idle (keep_connected
/// false) and, under engine PFS, lazy (no temporary key since the last rotation). destroy_auth_key must
/// reach the server without waiting for some unrelated call.
#[test]
fn destroy_auth_key_on_an_idle_worker_session_reaches_the_server() {
    let mut outcomes = Vec::new();
    for pfs in [false, true] {
        let perm = random_key(PERM_SEED);
        let server = server_with(vec![perm.clone()]);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = pfs_setup(
            server.address.port(),
            Some(perm.clone()),
            86_400,
            SessionRole::Worker { requires_auth_token: false },
        );
        if !pfs {
            setup.pfs = None;
        }
        setup.idle_disconnect_after = Some(1.0);
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
        std::thread::sleep(Duration::from_secs(2));
        engine.destroy_auth_key(session);
        let destroyed = collector.wait(Duration::from_secs(5), |events| {
            events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. })))
        });
        let keys = server.with_stats(|stats| stats.destroyed_keys.clone());
        engine.shutdown();
        eprintln!("pfs {pfs}: destroyed event {destroyed}, destroy_auth_key arrived under {keys:x?}");
        outcomes.push((pfs, destroyed));
    }
    for (pfs, destroyed) in outcomes {
        assert!(destroyed, "pfs {pfs}: destroy_auth_key on an idle worker session never went out");
    }
}

/// A request of an invalid size (not a multiple of 4, empty, over 8 MB) fails at once with
/// REQUEST_INVALID_SIZE when the session has a key. Sent while the key is still being made (under PFS:
/// always before the first temporary key), it must fail the same way and not reach the server.
#[test]
fn invalid_size_requests_sent_before_the_key_exists_fail_like_after() {
    let perm = random_key(PERM_SEED);
    let server = server_with(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), Some(perm), 86_400, SessionRole::Main));
    let mut odd = request(2, 2);
    odd.body.extend_from_slice(&[0u8; 2]);
    let empty = RpcRequest { id: RequestId(3), body: Vec::new(), flags: RequestFlags::default(), invoke_after: None };
    engine.send(session, odd);
    engine.send(session, empty);
    engine.send(session, request(1, 1));
    let done = collector.wait(WAIT, |events| completed(events, 1));
    std::thread::sleep(Duration::from_secs(3));
    let events = collector.events.lock().unwrap().clone();
    let drops: Vec<String> = events
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::ConnectionDropped { reason, .. } => Some(reason.name().to_string()),
            _ => None,
        })
        .collect();
    let connections = server.with_stats(|stats| stats.connections);
    let invalid2 = failed_with(&events, 2);
    let invalid3 = failed_with(&events, 3);
    engine.shutdown();
    eprintln!(
        "call 1 done {done}; call 2 {invalid2:?}; call 3 {invalid3:?}; drops {drops:?}; connections {connections}"
    );
    assert_eq!(invalid2.as_deref(), Some("REQUEST_INVALID_SIZE"));
    assert_eq!(invalid3.as_deref(), Some("REQUEST_INVALID_SIZE"));
}
