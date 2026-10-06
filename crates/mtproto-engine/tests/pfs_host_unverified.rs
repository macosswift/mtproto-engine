use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, BoundTemporaryKey, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup,
    SessionHandle, SessionSetup, unix_seconds,
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

fn made_temporary_key(collector: &Collector, session: SessionHandle) -> BoundTemporaryKey {
    assert!(
        collector.wait(WAIT, |events| events.iter().any(
            |(s, event)| *s == session && matches!(event, EngineEvent::AuthKeyCreated { expires_at: Some(_), .. })
        )),
        "the donor made no temporary key"
    );
    let (key, salt, expires_at) = collector
        .of(session)
        .iter()
        .find_map(|event| match event {
            EngineEvent::AuthKeyCreated { key, salt, expires_at: Some(expires_at), .. } => {
                Some((AuthKey::from_slice(key).expect("256 bytes"), *salt, *expires_at))
            }
            _ => None,
        })
        .unwrap();
    let now = unix_seconds();
    BoundTemporaryKey {
        material: AuthKeyMaterial {
            key,
            salts: vec![ServerSalt { salt, valid_since: now - 60.0, valid_until: now + 1800.0 }],
            init_hash: None,
        },
        expires_at,
        bound_to: None,
    }
}

fn made_keys(collector: &Collector, session: SessionHandle) -> usize {
    collector.of(session).iter().filter(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })).count()
}

fn holds_calls_while_the_bind_of_an_unverified_key_is_not_answered(options: ServerOptions, label: &str) {
    let perm = random_key(400);
    let server = TestServer::start(vec![perm.clone()], options);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let donor = engine.create_session(setup(&server, Some(material(perm.clone())), pfs(86_400)));
    engine.send(donor, request(1));
    let key = made_temporary_key(&collector, donor);
    engine.destroy_session(donor);
    let session = engine.create_session(setup(
        &server,
        Some(material(perm.clone())),
        PfsSetup { temporary_key: Some(key.clone()), ..pfs(86_400) },
    ));
    engine.send(session, request(2));
    std::thread::sleep(Duration::from_secs(7));
    let (executions, failures, binds, perm_empty) = server.with_stats(|stats| {
        (
            stats.executions.get(&2).copied().unwrap_or(0),
            stats.bind_failures.clone(),
            stats.binds,
            stats.perm_empty_errors,
        )
    });
    let events = collector.of(session);
    engine.shutdown();
    eprintln!(
        "{label}: call 2 executions {executions}; calls under the unbound key {perm_empty}; bind failures {failures:?}; binds {binds}; session made {} keys; in use {:?}",
        events.iter().filter(|e| matches!(e, EngineEvent::AuthKeyCreated { .. })).count(),
        events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::TemporaryKeyInUse { key_id, adopted, .. } => Some((*key_id, *adopted)),
                _ => None,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(executions, 0, "{label}: a call ran under the unverified key before its bind was answered");
    assert_eq!(perm_empty, 0, "{label}: a call went out under the unverified key before its bind was answered");
    assert!(
        !events.iter().any(|event| matches!(event, EngineEvent::TemporaryKeyInUse { .. })),
        "{label}: the unverified key was reported in use without a bind"
    );
}

#[test]
fn an_unanswered_bind_of_an_unverified_key_holds_calls() {
    holds_calls_while_the_bind_of_an_unverified_key_is_not_answered(
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ignore_binds: true,
            ..Default::default()
        },
        "ignored binds",
    );
}

#[test]
fn a_retried_bind_of_an_unverified_key_holds_calls() {
    holds_calls_while_the_bind_of_an_unverified_key_is_not_answered(
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            refuse_binds: Some("RPC_CALL_FAIL"),
            refuse_binds_code: Some(500),
            ..Default::default()
        },
        "generic bind failures",
    );
}

#[test]
fn an_unverified_key_bound_to_the_sessions_permanent_key_is_bound_again_and_used() {
    let perm = random_key(400);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let donor = engine.create_session(setup(&server, Some(material(perm.clone())), pfs(86_400)));
    engine.send(donor, request(1));
    assert!(collector.wait_completed(donor, 1));
    let mut key = collector.bound_key(donor);
    key.bound_to = None;
    let binds_before = server.with_stats(|stats| stats.binds);
    let session = engine.create_session(setup(&server, Some(material(perm.clone())), pfs(86_400)));
    engine.offer_temporary_key(session, key.clone());
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    let (ran, binds) = server.with_stats(|stats| (stats.executed_with_key.clone(), stats.binds));
    let in_use = collector.in_use(session);
    let made = made_keys(&collector, session);
    engine.shutdown();
    eprintln!("binds {binds_before}->{binds}; in use {in_use:x?}; made {made}");
    assert_eq!(made, 0, "a key was made though the offered one is good");
    assert_eq!(binds, binds_before + 1, "the unverified key was bound once more");
    assert_eq!(in_use, vec![(key.material.key.id() as i64, false)]);
    assert_eq!(ran.iter().find(|(tag, _)| *tag == 2).map(|(_, key)| *key), Some(key.material.key.id()));
}

/// A key bound to another permanent key and offered without its binding is bound to this session's
/// permanent key first: Telegram moves the binding of a key that carried calls (it never answers
/// TEMP_AUTH_KEY_ALREADY_BOUND), so the calls run under this session's authorization.
#[test]
fn an_unverified_key_bound_to_another_permanent_key_is_moved_to_this_one() {
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
    let donor = engine.create_session(setup(&server, Some(material(old_perm.clone())), pfs(86_400)));
    engine.send(donor, request(1));
    assert!(collector.wait_completed(donor, 1));
    let mut stale = collector.bound_key(donor);
    stale.bound_to = None;
    let session = engine.create_session(setup(
        &server,
        Some(material(new_perm.clone())),
        PfsSetup { temporary_key: Some(stale.clone()), ..pfs(86_400) },
    ));
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    let (failures, ran) = server.with_stats(|stats| (stats.bind_failures.clone(), stats.executed_under.clone()));
    let in_use = collector.in_use(session);
    engine.shutdown();
    eprintln!("failures {failures:?}; in use {in_use:x?}; ran {ran:x?}");
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(in_use, vec![(stale.material.key.id() as i64, false)]);
    assert_eq!(ran.iter().find(|(tag, _)| *tag == 2).map(|(_, perm)| *perm), Some(new_perm.id()));
}

/// The app's MtProtoKit made and bound a temporary key and used it without initConnection; Telegram
/// then answers every bind of it with CONNECTION_NOT_INITED (seen live: after PHONE_MIGRATE_2 the login
/// session retried that bind forever and auth.sendCode never went out). The session drops the key and
/// makes its own.
#[test]
fn an_offered_key_whose_bind_is_refused_with_connection_not_inited_is_replaced() {
    let perm = random_key(410);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            refuse_rebinds: Some("CONNECTION_NOT_INITED"),
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let donor = engine.create_session(setup(&server, Some(material(perm.clone())), pfs(86_400)));
    engine.send(donor, request(1));
    assert!(collector.wait_completed(donor, 1));
    let mut used = collector.bound_key(donor);
    used.bound_to = None;
    let session = engine.create_session(setup(
        &server,
        Some(material(perm.clone())),
        PfsSetup { temporary_key: Some(used.clone()), ..pfs(86_400) },
    ));
    engine.send(session, request(2));
    let done = collector.wait_completed(session, 2);
    let (failures, ran) = server.with_stats(|stats| (stats.bind_failures.clone(), stats.executed_under.clone()));
    let in_use = collector.in_use(session);
    let dropped = collector.dropped(session);
    engine.shutdown();
    eprintln!("failures {failures:?}; in use {in_use:x?}; dropped {dropped:x?}");
    assert!(done, "the call went out under a key of the session's own");
    assert_eq!(failures, vec!["CONNECTION_NOT_INITED".to_string()], "the refused key was bound once, not again");
    assert_eq!(dropped, vec![used.material.key.id() as i64], "the host heard the key is dead");
    assert!(!in_use.iter().any(|(id, _)| *id == used.material.key.id() as i64));
    assert_eq!(ran.iter().find(|(tag, _)| *tag == 2).map(|(_, key)| *key), Some(perm.id()));
}
