use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, BoundTemporaryKey, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup,
    SessionHandle, SessionSetup, TransportPreference, unix_seconds,
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
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[(SessionHandle, EngineEvent)]) -> bool) -> bool {
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

    fn of(&self, session: SessionHandle) -> Vec<EngineEvent> {
        self.events.lock().unwrap().iter().filter(|(s, _)| *s == session).map(|(_, event)| event.clone()).collect()
    }

    fn wait_completed(&self, session: SessionHandle, id: u64) -> bool {
        self.wait(WAIT, |events| {
            events.iter().any(|(s, event)| {
                *s == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id)
            })
        })
    }

    fn in_use(&self, session: SessionHandle) -> Vec<(i64, bool)> {
        self.of(session)
            .iter()
            .filter_map(|event| match event {
                EngineEvent::TemporaryKeyInUse { key_id, adopted, .. } => Some((*key_id, *adopted)),
                _ => None,
            })
            .collect()
    }

    fn dropped(&self, session: SessionHandle) -> Vec<i64> {
        self.of(session)
            .iter()
            .filter_map(|event| match event {
                EngineEvent::TemporaryKeyDropped { key_id } => Some(*key_id),
                _ => None,
            })
            .collect()
    }

    /// The bound temporary key the session made and is talking under, as a host would keep it.
    fn bound_key(&self, session: SessionHandle) -> BoundTemporaryKey {
        let events = self.of(session);
        let (key_id, expires_at, permanent_key_id) = events
            .iter()
            .rev()
            .find_map(|event| match event {
                EngineEvent::TemporaryKeyInUse { key_id, expires_at, adopted: false, permanent_key_id, .. } => {
                    Some((*key_id, *expires_at, *permanent_key_id))
                }
                _ => None,
            })
            .expect("a temporary key in use");
        let (key, salt) = events
            .iter()
            .find_map(|event| match event {
                EngineEvent::AuthKeyCreated { key, salt, expires_at: Some(_), .. } => {
                    let key = AuthKey::from_slice(key).expect("256 bytes");
                    (key.id() as i64 == key_id).then_some((key, *salt))
                }
                _ => None,
            })
            .expect("the key's AuthKeyCreated");
        let now = unix_seconds();
        BoundTemporaryKey {
            material: AuthKeyMaterial {
                key,
                salts: vec![ServerSalt { salt, valid_since: now - 60.0, valid_until: now + 1800.0 }],
                init_hash: None,
            },
            expires_at,
            bound_to: Some(permanent_key_id as u64),
        }
    }
}

const WAIT: Duration = Duration::from_secs(15);

fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(id as u32, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn server() -> TestServer {
    TestServer::start(
        vec![random_key(400)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

fn perm() -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key: random_key(400),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn setup(server: &TestServer, perm: Option<AuthKeyMaterial>, pfs: PfsSetup) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = perm;
    setup.pfs = Some(PfsSetup {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..pfs
    });
    setup.http_port = None;
    setup
}

fn pfs(lifetime: i32) -> PfsSetup {
    PfsSetup { lifetime, ..Default::default() }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn material(key: AuthKey) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

/// B-83 with a kept offer: the session keeps a bound key the host offered (bound to the old permanent
/// key) while it talks under its own; the host then hands over another permanent key. The temporary
/// key goes at once, as B-83 asks, but the replacement must not be the kept offer bound to the old
/// permanent key.
#[test]
fn a_kept_offer_bound_to_the_old_permanent_key_is_not_taken_after_a_permanent_key_change() {
    let old_perm = random_key(400);
    let new_perm = random_key(401);
    let server = TestServer::start(
        vec![old_perm.clone(), new_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let first = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    let second = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    engine.send(first, request(1));
    engine.send(second, request(2));
    assert!(collector.wait_completed(first, 1) && collector.wait_completed(second, 2));
    let offered = collector.bound_key(second);
    let offered_id = offered.material.key.id() as i64;
    engine.offer_temporary_key(first, offered);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(collector.in_use(first).len(), 1, "a key in use is not replaced by an offer");

    engine.set_auth_key(first, Some(material(new_perm.clone())));
    engine.send(first, request(3));
    assert!(collector.wait_completed(first, 3), "events {:?}", collector.of(first));
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    let in_use = collector.in_use(first);
    engine.shutdown();
    let call3 = ran.iter().find(|(tag, _)| *tag == 3).map(|(_, perm)| *perm);
    eprintln!(
        "keys in use {in_use:x?} (offer {offered_id:x}); calls and permanent keys {ran:x?}; old {:x} new {:x}",
        old_perm.id(),
        new_perm.id()
    );
    assert_eq!(
        call3,
        Some(new_perm.id()),
        "call 3, sent after set_auth_key(new), ran under the old permanent key through the kept offer"
    );
}

/// A session allowed to make its permanent key (none given) gets an offer before it has one: the
/// offer was bound to another permanent key. The session makes its own permanent key and must not
/// then talk under the offered key's binding.
#[test]
fn an_offer_kept_while_the_session_makes_its_own_permanent_key_is_not_taken_for_it() {
    let host_perm = random_key(400);
    let server = TestServer::start(
        vec![host_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let other = engine.create_session(setup(&server, Some(material(host_perm.clone())), pfs(86_400)));
    engine.send(other, request(1));
    assert!(collector.wait_completed(other, 1));
    let offered = collector.bound_key(other);
    let offered_id = offered.material.key.id() as i64;

    let session = engine.create_session(setup(&server, None, pfs(86_400)));
    engine.offer_temporary_key(session, offered);
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    let made_perm = collector
        .of(session)
        .iter()
        .find_map(|event| match event {
            EngineEvent::AuthKeyCreated { key, expires_at: None, .. } => AuthKey::from_slice(key).map(|key| key.id()),
            _ => None,
        })
        .expect("the session made a permanent key");
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    let in_use = collector.in_use(session);
    engine.shutdown();
    let call2 = ran.iter().find(|(tag, _)| *tag == 2).map(|(_, perm)| *perm);
    eprintln!(
        "keys in use {in_use:x?} (offer {offered_id:x}); calls {ran:x?}; made perm {made_perm:x}, host perm {:x}",
        host_perm.id()
    );
    assert_eq!(call2, Some(made_perm), "call 2 ran under the offer's permanent key, not the session's own");
}

/// Offers racing rotations: the session's key is dropped by the server or replaced by a class change
/// while the host keeps offering keys bound to the same permanent key, with calls in flight. Every
/// call ends once, the server runs none twice, all run under the permanent key, and a key the session
/// saw dropped is never taken again.
#[test]
fn offers_racing_rotations_keep_every_call_single_and_never_retake_a_dropped_key() {
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let perm_key = random_key(400);
        let server = server();
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut others = Vec::new();
        for index in 0..4u64 {
            let mut other_setup = setup(&server, Some(material(perm_key.clone())), pfs(86_400));
            other_setup.transport = transport;
            let other = engine.create_session(other_setup);
            engine.send(other, request(1000 + index));
            others.push(other);
        }
        for (index, other) in others.iter().enumerate() {
            assert!(collector.wait_completed(*other, 1000 + index as u64), "{transport:?}: other {index}");
        }
        let keys: Vec<BoundTemporaryKey> = others.iter().map(|other| collector.bound_key(*other)).collect();
        let mut session_setup = setup(&server, Some(material(perm_key.clone())), pfs(86_400));
        session_setup.transport = transport;
        let session = engine.create_session(session_setup);
        engine.send(session, request(1));
        assert!(collector.wait_completed(session, 1), "{transport:?}: {:?}", collector.of(session));
        let mut next_id = 2u64;
        let mut sent = vec![1u64];
        let mut obfuscation = 2i16;
        let mut removed_keys: Vec<String> = Vec::new();
        for round in 0..8usize {
            for _ in 0..3 {
                engine.send(session, request(next_id));
                sent.push(next_id);
                next_id += 1;
            }
            let offered = keys[round % keys.len()].clone();
            if round % 2 == 0 {
                if let Some((current, _)) = collector.in_use(session).last().copied() {
                    server.remove_key(current as u64);
                    removed_keys.push(format!("round {round}: {current:x}"));
                }
                engine.offer_temporary_key(session, offered);
            } else {
                engine.offer_temporary_key(session, offered);
                obfuscation = if obfuscation == 2 { -2 } else { 2 };
                engine.set_obfuscation_dc_id(session, obfuscation);
                engine.offer_temporary_key(session, keys[(round + 1) % keys.len()].clone());
            }
            engine.send(session, request(next_id));
            sent.push(next_id);
            next_id += 1;
            std::thread::sleep(Duration::from_millis(150));
        }
        let ended = |id: u64| {
            collector
                .of(session)
                .iter()
                .filter(|event| match event {
                    EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) => done.0 == id,
                    EngineEvent::Rpc(RpcEvent::Failed { id: done, .. }) => done.0 == id,
                    _ => false,
                })
                .count()
        };
        let all_ended = collector.wait(Duration::from_secs(40), |_| true) && {
            let deadline = Instant::now() + Duration::from_secs(40);
            loop {
                if sent.iter().all(|id| ended(*id) >= 1) || Instant::now() >= deadline {
                    break sent.iter().all(|id| ended(*id) >= 1);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        let events = collector.of(session);
        let in_use = collector.in_use(session);
        let dropped = collector.dropped(session);
        let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
        engine.shutdown();
        let unended: Vec<u64> = sent.iter().copied().filter(|id| ended(*id) == 0).collect();
        let twice: Vec<u64> = sent.iter().copied().filter(|id| ended(*id) > 1).collect();
        let run_twice: Vec<u64> =
            sent.iter().copied().filter(|id| ran.iter().filter(|(tag, _)| *tag == *id as u32).count() > 1).collect();
        let foreign: Vec<(u32, u64)> = ran.iter().copied().filter(|(_, under)| *under != perm_key.id()).collect();
        let failed: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) => Some(format!("{}:{message}", id.0)),
                _ => None,
            })
            .collect();
        let mut retaken = Vec::new();
        let mut seen_dropped = std::collections::HashSet::new();
        let mut order = Vec::new();
        for event in &events {
            match event {
                EngineEvent::TemporaryKeyDropped { key_id } => {
                    seen_dropped.insert(*key_id);
                    order.push(format!("drop {key_id:x}"));
                }
                EngineEvent::TemporaryKeyInUse { key_id, adopted, dc_id, .. } => {
                    if seen_dropped.contains(key_id) {
                        retaken.push(*key_id);
                    }
                    order.push(format!("use {key_id:x} adopted {adopted} dc {dc_id}"));
                }
                _ => {}
            }
        }
        eprintln!("{transport:?}: key events {order:?}; removed on the server {removed_keys:?}");
        let removed: Vec<String> = Vec::new();
        let _ = removed;
        eprintln!(
            "{transport:?}: {} calls, unended {unended:?}, ended twice {twice:?}, run twice {run_twice:?}, failed {failed:?}, keys in use {}, adopted {}, dropped {}, foreign {foreign:x?}",
            sent.len(),
            in_use.len(),
            in_use.iter().filter(|(_, adopted)| *adopted).count(),
            dropped.len()
        );
        assert!(all_ended, "{transport:?}: calls never ended: {unended:?}");
        assert!(twice.is_empty(), "{transport:?}: calls ended twice: {twice:?}");
        assert!(run_twice.is_empty(), "{transport:?}: the server ran calls twice: {run_twice:?}");
        assert!(foreign.is_empty(), "{transport:?}: calls ran under another permanent key: {foreign:x?}");
        assert!(retaken.is_empty(), "{transport:?}: dropped keys taken again: {retaken:x?}");
        assert!(
            failed.iter().all(|failure| failure.ends_with("TEMP_KEY_ROTATED")),
            "{transport:?}: unexpected failures {failed:?}"
        );
    }
}

#[test]
fn an_offer_bound_to_another_permanent_key_is_refused() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let first = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    let second = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(first, request(1));
    engine.send(second, request(2));
    assert!(collector.wait_completed(first, 1) && collector.wait_completed(second, 2));
    let first_key = collector.bound_key(first).material.key.id();
    let mut foreign = collector.bound_key(second);
    foreign.bound_to = Some(foreign.bound_to.expect("bound") ^ 1);
    engine.offer_temporary_key(first, foreign);
    let handshakes = server.with_stats(|stats| stats.handshakes);
    server.remove_key(first_key);
    engine.send(first, request(3));
    assert!(collector.wait_completed(first, 3), "events {:?}", collector.of(first));
    assert!(
        collector.in_use(first).iter().all(|(_, adopted)| !adopted),
        "a key bound to another permanent key was taken"
    );
    assert_eq!(server.with_stats(|stats| stats.handshakes), handshakes + 1, "a new key was made instead");
}

/// Review 14: the Swift host installs a new permanent key and at once offers the context's stored
/// temporary key (`install` -> `offerStoredTemporaryKey`). A key MtProtoKit made carries no binding
/// (`bound_to` None), and MTContext keeps its ephemeral keys when the persistent key changes, so the
/// stored key can still be bound to the old permanent key. Calls sent after the change must not run
/// under the old permanent key.
#[test]
fn an_unknown_binding_offer_after_a_permanent_key_change_does_not_run_calls_under_the_old_key() {
    let old_perm = random_key(400);
    let new_perm = random_key(401);
    let server = TestServer::start(
        vec![old_perm.clone(), new_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mtprotokit = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    engine.send(mtprotokit, request(1));
    assert!(collector.wait_completed(mtprotokit, 1));
    let mut stored = collector.bound_key(mtprotokit);
    stored.bound_to = None;
    let session = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2));

    engine.set_auth_key(session, Some(material(new_perm.clone())));
    engine.offer_temporary_key(session, stored);
    engine.send(session, request(3));
    assert!(collector.wait_completed(session, 3), "events {:?}", collector.of(session));
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    engine.shutdown();
    let call3 = ran.iter().find(|(tag, _)| *tag == 3).map(|(_, perm)| *perm);
    assert_eq!(call3, Some(new_perm.id()), "call 3, sent after set_auth_key(new), ran under the old permanent key");
}

/// The same at session start: the stored MtProtoKit key goes in as `pfs_temporary_key` of a session
/// created with the new permanent key (after a restart: MTContext keeps it in the keychain).
#[test]
fn an_unknown_binding_setup_key_does_not_run_the_first_call_under_the_old_key() {
    let old_perm = random_key(400);
    let new_perm = random_key(401);
    let server = TestServer::start(
        vec![old_perm.clone(), new_perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mtprotokit = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    engine.send(mtprotokit, request(1));
    assert!(collector.wait_completed(mtprotokit, 1));
    let mut stored = collector.bound_key(mtprotokit);
    stored.bound_to = None;
    let session = engine.create_session(setup(
        &server,
        Some(material(new_perm.clone())),
        PfsSetup { temporary_key: Some(stored), ..pfs(86_400) },
    ));
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    engine.shutdown();
    let call2 = ran.iter().find(|(tag, _)| *tag == 2).map(|(_, perm)| *perm);
    assert_eq!(call2, Some(new_perm.id()), "the session's first call ran under the old permanent key");
}
