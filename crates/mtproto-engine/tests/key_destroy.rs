#![allow(dead_code)]

mod middlebox;

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
    logs: Mutex<Vec<String>>,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        if std::env::var_os("MTPROTO_TEST_EVENTS").is_some() {
            eprintln!("EVENT {event:?}");
        }
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

fn destroyed(events: &[(SessionHandle, EngineEvent)]) -> bool {
    events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. })))
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

const PERM_SEED: u64 = 5400;
const WAIT: Duration = Duration::from_secs(15);

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

/// destroy_auth_key under PFS: the session reconnects under the permanent key and writes
/// destroy_auth_key on the fresh connection. That connection dies before the answer (here: the server
/// swallows it, as a dropped path does). `Session::sent_destroy_auth_key` is never reset by a new
/// connection, so destroy_auth_key is never sent again: the requests held under the bind gate wait
/// forever and the session never gets the AuthKeyDestroyed answer. tdlib sends it again on every new
/// connection (`Session::connection_open_finish` calls `destroy_key()` on the fresh SessionConnection).
#[test]
fn a_destroy_auth_key_lost_with_its_connection_is_sent_again() {
    let mut results = Vec::new();
    for pfs in [true, false] {
        let perm = random_key(PERM_SEED);
        let server = server_with(vec![perm.clone()]);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = pfs_setup(server.address.port(), Some(perm.clone()), 86_400, SessionRole::Main);
        if !pfs {
            setup.pfs = None;
        }
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
        if !pfs {
            server.set_tcp_blackhole(true);
            engine.reset_connections();
            std::thread::sleep(Duration::from_millis(300));
        } else {
            server.set_tcp_blackhole(true);
        }
        engine.destroy_auth_key(session);
        std::thread::sleep(Duration::from_millis(600));
        server.set_tcp_blackhole(false);
        engine.send(session, request(2, 2));
        let got_destroyed = collector.wait(Duration::from_secs(25), destroyed);
        let call2 = collector.wait(Duration::from_secs(5), |events| finished(events, 2));
        let destroyed_keys = server.with_stats(|stats| stats.destroyed_keys.len());
        let connections = server.with_stats(|stats| stats.connections);
        engine.shutdown();
        eprintln!(
            "pfs {pfs}: AuthKeyDestroyed {got_destroyed}, destroy_auth_key reached the server {destroyed_keys} times, \
             call 2 finished {call2}, server connections {connections}"
        );
        results.push((pfs, got_destroyed, call2));
    }
    for (pfs, got_destroyed, call2) in results {
        assert!(got_destroyed, "pfs {pfs}: destroy_auth_key lost with its connection is never sent again");
        if pfs {
            assert!(call2, "pfs {pfs}: the call held for the destroy never goes");
        }
    }
}

/// The same over HTTP: the HTTP request that carried destroy_auth_key is lost (held by a middlebox
/// until the engine gives up on it). `http_packet_lost` re-queues queries and service requests but not
/// destroy_auth_key, so it is never sent again and the held calls wait forever.
#[test]
fn a_destroy_auth_key_lost_with_its_http_request_is_sent_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let perm = random_key(PERM_SEED + 1);
    let server = server_with(vec![perm.clone()]);
    let hold_next = Arc::new(AtomicBool::new(false));
    let held = Arc::new(AtomicBool::new(false));
    let (port, _stats) = {
        let hold_next = hold_next.clone();
        let held = held.clone();
        middlebox::start(
            server.address,
            Arc::new(move |info: middlebox::Info| {
                if !info.plain && hold_next.swap(false, Ordering::SeqCst) {
                    held.store(true, Ordering::SeqCst);
                    middlebox::Action::Hold
                } else {
                    middlebox::Action::Forward
                }
            }),
        )
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(port, Some(perm.clone()), 86_400, SessionRole::Main);
    setup.transport = TransportPreference::Http;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
    std::thread::sleep(Duration::from_millis(300));
    hold_next.store(true, Ordering::SeqCst);
    engine.destroy_auth_key(session);
    engine.send(session, request(2, 2));
    let got_destroyed = collector.wait(Duration::from_secs(40), destroyed);
    let call2 = collector.wait(Duration::from_secs(5), |events| finished(events, 2));
    let destroyed_keys = server.with_stats(|stats| stats.destroyed_keys.len());
    engine.shutdown();
    eprintln!(
        "http: held one request {}, AuthKeyDestroyed {got_destroyed}, destroy_auth_key reached the server {destroyed_keys} times, call 2 finished {call2}",
        held.load(Ordering::SeqCst)
    );
    assert!(got_destroyed, "http: destroy_auth_key lost with its request is never sent again");
    assert!(call2, "http: the call held for the destroy never goes");
}

/// Without PFS: destroy_auth_key answered, then the host gives the same session a new key. The core
/// session keeps `need_destroy_auth_key` (only `sent_destroy_auth_key` and `destroy_answered` change),
/// and `message_failed` re-arms it on any bad_msg_notification: destroy_auth_key then goes out under
/// the new key. Variant "unsent": destroy asked while paused, new key, unpaused.
#[test]
fn a_new_key_after_destroy_auth_key_is_not_destroyed_too() {
    let mut results = Vec::new();
    for unsent in [false, true] {
        let old = random_key(PERM_SEED + 10);
        let new = random_key(PERM_SEED + 11);
        let server = server_with(vec![old.clone(), new.clone()]);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = pfs_setup(server.address.port(), Some(old.clone()), 86_400, SessionRole::Main);
        setup.pfs = None;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(WAIT, |events| completed(events, 1)), "call 1");
        if unsent {
            engine.set_paused(session, true);
            std::thread::sleep(Duration::from_millis(100));
            engine.destroy_auth_key(session);
            engine.set_auth_key(session, Some(material(new.clone())));
            std::thread::sleep(Duration::from_millis(100));
            engine.set_paused(session, false);
        } else {
            engine.destroy_auth_key(session);
            assert!(collector.wait(WAIT, destroyed), "destroy answered");
            engine.set_auth_key(session, Some(material(new.clone())));
            engine.send(
                session,
                RpcRequest {
                    id: RequestId(2),
                    body: bad_msg_call(48, false),
                    flags: RequestFlags::default(),
                    invoke_after: None,
                },
            );
        }
        engine.send(session, request(3, 3));
        let call3 = collector.wait(WAIT, |events| completed(events, 3));
        std::thread::sleep(Duration::from_secs(1));
        let keys = server.with_stats(|stats| stats.destroyed_keys.clone());
        engine.shutdown();
        let new_destroyed = keys.contains(&new.id());
        eprintln!(
            "unsent {unsent}: call 3 {call3}; destroy_auth_key arrived under {keys:x?} (old {:x}, new {:x})",
            old.id(),
            new.id()
        );
        results.push((unsent, new_destroyed));
    }
    for (unsent, new_destroyed) in results {
        assert!(!new_destroyed, "unsent {unsent}: destroy_auth_key went out under the new key");
    }
}

/// Probe: the HTTP request carrying auth.bindTempAuthKey is lost; the bind must go again.
#[test]
fn a_bind_lost_with_its_http_request_is_sent_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let perm = random_key(PERM_SEED + 2);
    let server = server_with(vec![perm.clone()]);
    let held = Arc::new(AtomicBool::new(false));
    let (port, _stats) = {
        let held = held.clone();
        middlebox::start(
            server.address,
            Arc::new(move |info: middlebox::Info| {
                if !info.plain && !held.swap(true, Ordering::SeqCst) {
                    middlebox::Action::Hold
                } else {
                    middlebox::Action::Forward
                }
            }),
        )
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(port, Some(perm.clone()), 86_400, SessionRole::Main);
    setup.transport = TransportPreference::Http;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let call1 = collector.wait(Duration::from_secs(40), |events| completed(events, 1));
    let binds = server.with_stats(|stats| stats.binds);
    engine.shutdown();
    eprintln!("bind over http lost once: call 1 {call1}, binds at the server {binds}");
    assert!(call1);
}

/// Auto on HTTP, then paused (or offline): `maybe_recheck_tcp` does not look at `wants_connection`, so a
/// paused session still opens a TCP recheck connection every `tcp_recheck_after`.
#[test]
fn a_paused_auto_session_on_http_opens_no_tcp_rechecks() {
    let mut results = Vec::new();
    for offline in [false, true] {
        let key = random_key(PERM_SEED + 20);
        let server = server_with(vec![key.clone()]);
        server.set_tcp_blackhole(true);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = SessionSetup::new(
            2,
            SessionRole::Main,
            vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
        );
        setup.auth_key = Some(material(key));
        setup.transport = TransportPreference::Auto;
        setup.http_port = None;
        setup.tcp_recheck_after = 2.0;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait(Duration::from_secs(20), |events| completed(events, 1)), "call 1 over HTTP");
        if offline {
            engine.set_network_available(false);
        } else {
            engine.set_paused(session, true);
        }
        std::thread::sleep(Duration::from_millis(500));
        let before = server.with_stats(|stats| (stats.connections, stats.http.requests));
        std::thread::sleep(Duration::from_secs(10));
        let after = server.with_stats(|stats| (stats.connections, stats.http.requests));
        engine.shutdown();
        eprintln!(
            "offline {offline}: server (connections, http requests) while paused/offline: before {before:?}, after 10 s {after:?}"
        );
        results.push((offline, after.0 - before.0));
    }
    for (offline, opened) in results {
        assert_eq!(opened, 0, "offline {offline}: connections opened while the session must stay quiet");
    }
}
