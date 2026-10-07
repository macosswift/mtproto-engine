//! Temporary keys under engine-run PFS: where they live (B-42), one per session (B-43), their salts kept
//! apart from the permanent key's (B-45), and dropped with the authorization they were bound to (B-46).

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

#[path = "support/sec_rows_tap.rs"]
mod tap;

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

    fn wait_completed(&self, id: u64) -> bool {
        self.wait(WAIT, |events| events.iter().any(|(_, event)| completed(event, id)))
    }

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, event)| predicate(event)).count()
    }

    /// The temporary keys a session made, with the salt of their handshake, in order.
    fn made_temporary_keys(&self, session: SessionHandle) -> Vec<(AuthKey, i64)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _)| *handle == session)
            .filter_map(|(_, event)| match event {
                EngineEvent::AuthKeyCreated { key, salt, expires_at: Some(_), .. } => {
                    Some((AuthKey::from_slice(key).expect("256 bytes"), *salt))
                }
                _ => None,
            })
            .collect()
    }

    /// The temporary keys a session reported in use: key id, adopted from the host, permanent key id.
    fn in_use(&self, session: SessionHandle) -> Vec<(u64, bool, u64)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _)| *handle == session)
            .filter_map(|(_, event)| match event {
                EngineEvent::TemporaryKeyInUse { key_id, adopted, permanent_key_id, .. } => {
                    Some((*key_id as u64, *adopted, *permanent_key_id as u64))
                }
                _ => None,
            })
            .collect()
    }
}

fn completed(event: &EngineEvent, id: u64) -> bool {
    matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id)
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn server(keys: Vec<AuthKey>) -> TestServer {
    TestServer::start(
        keys,
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

fn material(key: AuthKey, salt: i64) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn pfs_setup(port: u16, perm: AuthKeyMaterial, role: SessionRole, permanent_key_from_host: bool) -> SessionSetup {
    let mut setup = SessionSetup::new(2, role, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(perm);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        permanent_key_from_host,
        temporary_key: None,
    });
    setup.http_port = None;
    setup
}

fn engine(collector: &Arc<Collector>, workers: usize) -> Engine {
    Engine::new(EngineConfig { worker_threads: workers, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn key_of_call(server: &TestServer, tag: u32) -> Vec<u64> {
    server.with_stats(|stats| stats.executed_with_key.iter().filter(|(t, _)| *t == tag).map(|(_, key)| *key).collect())
}

fn permanent_key_of_call(server: &TestServer, tag: u32) -> Vec<u64> {
    server.with_stats(|stats| stats.executed_under.iter().filter(|(t, _)| *t == tag).map(|(_, key)| *key).collect())
}

const WAIT: Duration = Duration::from_secs(15);
const PERM_SALT: i64 = 0x0b42_5a17_0045_0001;

/// The docs allow keeping temporary keys in RAM only. The engine keeps nothing between sessions or
/// runs: each new session, and each new engine (an app restart), makes and binds a fresh temporary key
/// unless the host offers one it kept. A key the engine makes is handed over marked temporary
/// (`expires_at`) and announced in use with the permanent key it is bound to, so keeping it is the
/// host's decision.
#[test]
fn a_temporary_key_is_never_reused_by_a_later_session_or_engine_unless_the_host_offers_it() {
    let perm = random_key(4201);
    let server = server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let mut made = Vec::new();

    let first_engine = engine(&collector, 1);
    let first = first_engine.create_session(pfs_setup(
        server.address.port(),
        material(perm.clone(), SERVER_SALT),
        SessionRole::Main,
        false,
    ));
    first_engine.send(first, request(1, 1));
    assert!(collector.wait_completed(1));
    made.push((first, collector.made_temporary_keys(first)));
    first_engine.destroy_session(first);

    let second = first_engine.create_session(pfs_setup(
        server.address.port(),
        material(perm.clone(), SERVER_SALT),
        SessionRole::Main,
        false,
    ));
    first_engine.send(second, request(2, 2));
    assert!(collector.wait_completed(2));
    made.push((second, collector.made_temporary_keys(second)));
    first_engine.shutdown();

    let restarted = Arc::new(Collector::default());
    let second_engine = engine(&restarted, 1);
    let third = second_engine.create_session(pfs_setup(
        server.address.port(),
        material(perm.clone(), SERVER_SALT),
        SessionRole::Main,
        false,
    ));
    second_engine.send(third, request(3, 3));
    assert!(restarted.wait_completed(3));
    made.push((third, restarted.made_temporary_keys(third)));
    second_engine.shutdown();

    let mut ids = Vec::new();
    for (tag, (session, keys)) in (1u32..).zip(&made) {
        assert_eq!(keys.len(), 1, "session {tag} made one temporary key and reported it as temporary");
        let id = keys[0].0.id();
        assert_ne!(id, perm.id());
        let reported = if tag == 3 { &restarted } else { &collector };
        assert_eq!(
            reported.in_use(*session),
            vec![(id, false, perm.id())],
            "session {tag} announced the key it made, bound to the permanent key"
        );
        assert_eq!(key_of_call(&server, tag), vec![id], "call {tag} ran under its own session's key");
        assert_eq!(permanent_key_of_call(&server, tag), vec![perm.id()]);
        ids.push(id);
    }
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3, "no temporary key was taken up again without the host offering it");
    assert_eq!(server.with_stats(|stats| (stats.temporary_keys, stats.binds)), (3, 3));
    for reported in [&collector, &restarted] {
        assert_eq!(reported.count(|event| matches!(event, EngineEvent::TemporaryKeyInUse { adopted: true, .. })), 0);
    }
}

/// With several sessions on one datacenter (tmp_sessions > 1, or upload and download sessions next to
/// the main one), each session under engine PFS makes its own temporary key and binds it to the same
/// permanent key: concurrent sessions never share a temporary key under different session ids.
#[test]
fn each_pfs_session_makes_and_binds_its_own_temporary_key_to_the_shared_permanent_key() {
    let perm = random_key(4301);
    let server = server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 3);
    let port = server.address.port();
    let main = engine.create_session(pfs_setup(port, material(perm.clone(), SERVER_SALT), SessionRole::Main, false));
    let upload = engine.create_session(pfs_setup(
        port,
        material(perm.clone(), SERVER_SALT),
        SessionRole::Worker { requires_auth_token: false },
        false,
    ));
    let download = engine.create_session(pfs_setup(
        port,
        material(perm.clone(), SERVER_SALT),
        SessionRole::Worker { requires_auth_token: false },
        false,
    ));
    let sessions = [(main, 10u32), (upload, 20), (download, 30)];
    for (session, base) in sessions {
        for n in 0..3u32 {
            engine.send(session, request(u64::from(base + n), base + n));
        }
    }
    for (_, base) in sessions {
        for n in 0..3u32 {
            assert!(collector.wait_completed(u64::from(base + n)), "call {}", base + n);
        }
    }
    let mut keys = Vec::new();
    for (session, base) in sessions {
        let in_use = collector.in_use(session);
        assert_eq!(in_use.len(), 1, "{in_use:x?}");
        let (key, adopted, bound_to) = in_use[0];
        assert!(!adopted);
        assert_eq!(bound_to, perm.id(), "every temporary key is bound to the one permanent key");
        assert_ne!(key, perm.id(), "no session talks under the permanent key");
        for tag in base..base + 3 {
            assert_eq!(key_of_call(&server, tag), vec![key], "call {tag} ran under its own session's key");
            assert_eq!(permanent_key_of_call(&server, tag), vec![perm.id()]);
        }
        keys.push(key);
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 3, "three concurrent sessions, three temporary keys");
    assert_eq!(server.with_stats(|stats| (stats.temporary_keys, stats.binds)), (3, 3));
    assert!(server.with_stats(|stats| stats.session_ids.len()) >= 3);
    engine.shutdown();
}

/// Salts belong to an auth key. The host gives the permanent key with its salt; the session under a
/// temporary key starts from the salt of that key's own handshake and never sends the permanent key's,
/// and the permanent key, used again for `destroy_auth_key`, starts from its own salt, not one learned
/// under the temporary key.
#[test]
fn salts_of_the_permanent_key_and_of_its_temporary_keys_are_kept_apart() {
    let perm = random_key(4501);
    let server = server(vec![perm.clone()]);
    let tap = tap::Tap::start(server.address);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let session = engine.create_session(pfs_setup(
        tap.address.port(),
        material(perm.clone(), PERM_SALT),
        SessionRole::Main,
        false,
    ));
    engine.send(session, request(1, 1));
    engine.send(session, request(2, 2));
    assert!(collector.wait_completed(1) && collector.wait_completed(2));
    engine.destroy_auth_key(session);
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. })))
    }));
    let made = collector.made_temporary_keys(session);
    engine.shutdown();
    assert_eq!(made.len(), 1, "one temporary key before the destroy");
    let (temporary, handshake_salt) = made[0].clone();
    assert_ne!(handshake_salt, PERM_SALT);

    let frames = tap.client_frames();
    let under_temporary = tap::open(&frames, std::slice::from_ref(&temporary));
    let under_permanent = tap::open(&frames, std::slice::from_ref(&perm));
    assert!(!under_temporary.is_empty() && !under_permanent.is_empty());
    let temporary_salts: Vec<i64> = under_temporary.iter().map(|packet| packet.salt).collect();
    assert_eq!(temporary_salts[0], handshake_salt, "the temporary key starts from its own handshake's salt");
    assert!(
        temporary_salts.iter().all(|salt| *salt == handshake_salt || *salt == SERVER_SALT),
        "only the temporary key's salts, or the one the server gave for it: {temporary_salts:x?}"
    );
    assert!(!temporary_salts.contains(&PERM_SALT), "the permanent key's salt went out under the temporary key");
    let permanent_salts: Vec<i64> = under_permanent.iter().map(|packet| packet.salt).collect();
    assert_eq!(permanent_salts[0], PERM_SALT, "the permanent key starts from its own salt: {permanent_salts:x?}");
    assert!(!permanent_salts.contains(&handshake_salt), "a temporary key's salt went out under the permanent key");
    assert_eq!(server.with_stats(|stats| stats.destroyed_keys.clone()), vec![perm.id()]);
}

/// tdlib drops the temporary key with the authorization (`set_auth_flag(false)`). Here the host hears
/// `AuthorizationRequired` on a 401 and logs out by clearing the key: the temporary key bound to it
/// goes at once, nothing more runs under it, and after the next login the calls run under a new
/// temporary key bound to the new permanent key.
#[test]
fn losing_the_authorization_drops_the_temporary_key_bound_to_it() {
    let perm = random_key(4601);
    let next_perm = random_key(4602);
    let server = server(vec![perm.clone(), next_perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let session = engine.create_session(pfs_setup(
        server.address.port(),
        material(perm.clone(), SERVER_SALT),
        SessionRole::Main,
        true,
    ));
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(1));
    let first_key = collector.in_use(session)[0].0;

    engine.send(session, request(2, TAG_UNAUTHORIZED));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthorizationRequired { .. })))
    }));
    engine.set_auth_key(session, None);
    engine.send(session, request(3, 3));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(server.executions(3), 0, "call 3 ran after the logout, under the dropped temporary key");
    assert!(
        collector.wait(WAIT, |events| events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyRequired)))
    );

    engine.set_auth_key(session, Some(material(next_perm.clone(), SERVER_SALT)));
    assert!(collector.wait_completed(3));
    let in_use = collector.in_use(session);
    engine.shutdown();
    let second_key = in_use.last().unwrap().0;
    assert_ne!(second_key, first_key);
    assert_eq!(in_use.last().unwrap().2, next_perm.id());
    assert_eq!(key_of_call(&server, 3), vec![second_key], "call 3 ran under the new temporary key");
    assert_eq!(permanent_key_of_call(&server, 3), vec![next_perm.id()]);
    assert!(
        server.with_stats(|stats| stats
            .executed_with_key
            .iter()
            .all(|(tag, key)| *tag == 1 || *tag == TAG_UNAUTHORIZED || *key != first_key)),
        "a call after call 1 ran under the temporary key bound to the lost authorization"
    );
}
