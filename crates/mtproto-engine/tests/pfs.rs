use std::collections::HashSet;
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

    fn completed_ids(&self) -> Vec<u64> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => Some(id.0),
                _ => None,
            })
            .collect()
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

#[test]
fn a_temporary_key_is_made_and_bound_before_the_first_call() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 86_400));
    for id in 1..=10 {
        engine.send(session, request(id, id as u32));
    }
    let done = collector.wait(WAIT, |events| completions(events) == 10);
    if !done {
        let events: Vec<String> = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|(_, event)| format!("{event:?}").chars().take(120).collect())
            .collect();
        eprintln!("events {events:#?}");
        eprintln!(
            "server {:?}",
            server.with_stats(|stats| (
                stats.temporary_keys,
                stats.binds,
                stats.bind_failures.clone(),
                stats.perm_empty_errors,
                stats.handshakes,
                stats.client_packets
            ))
        );
    }
    assert!(done);
    assert_eq!(temporary_keys_created(&collector), 1);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyBound))), 1);
    let (temporary, binds, perm_empty, failures) = server
        .with_stats(|stats| (stats.temporary_keys, stats.binds, stats.perm_empty_errors, stats.bind_failures.clone()));
    assert_eq!((temporary, binds, perm_empty), (1, 1, 0), "{failures:?}");
    assert_eq!(server.with_stats(|stats| stats.handshakes), 1, "the permanent key was given");
    engine.shutdown();
}

#[test]
fn both_keys_are_made_from_scratch() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, None, 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: None, .. })), 1);
    assert_eq!(temporary_keys_created(&collector), 1);
    assert_eq!(server.with_stats(|stats| (stats.handshakes, stats.binds)), (2, 1));
    engine.shutdown();
}

#[test]
fn keys_rotate_before_they_expire_and_no_call_runs_twice() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 60));
    let started = Instant::now();
    let mut id = 0u64;
    while started.elapsed() < Duration::from_secs(50) {
        id += 1;
        engine.send(session, request(id, (id % 900) as u32));
        assert!(collector.wait(WAIT, |events| completions(events) == id as usize), "call {id}");
        std::thread::sleep(Duration::from_millis(250));
    }
    let created = temporary_keys_created(&collector);
    assert!((2..=3).contains(&created), "{created} temporary keys over 50 s of 60 s keys");
    assert_eq!(server.with_stats(|stats| stats.expired_key_rejections), 0, "replaced before expiry");
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    let ids: HashSet<u64> = collector.completed_ids().into_iter().collect();
    assert_eq!(ids.len(), id as usize);
    engine.shutdown();
}

#[test]
fn a_lost_temporary_key_is_replaced_without_bothering_the_host() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    server.drop_temporary_keys();
    for id in 2..=6 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events) == 6));
    assert!(temporary_keys_created(&collector) >= 2);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. })), 0);
    engine.shutdown();
}

#[test]
fn a_forgotten_binding_is_restored() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    server.unbind_temporary_keys();
    for id in 2..=6 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(Duration::from_secs(20), |events| completions(events) == 6));
    assert!(server.with_stats(|stats| stats.binds) >= 2);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyRejected))), 0);
    engine.shutdown();
}

#[test]
fn an_unknown_permanent_key_is_reported_and_calls_wait() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(999)), 86_400));
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(20), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::PermanentKeyInvalid))
    }));
    assert_eq!(completions(&collector.events.lock().unwrap()), 0);
    assert_eq!(collector.count(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. }))), 0);
    assert_eq!(server.with_stats(|stats| stats.perm_empty_errors), 0, "no call went out unbound");
    engine.shutdown();
}

#[test]
fn pfs_over_http() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, Some(random_key(400)), 86_400);
    setup.transport = TransportPreference::Http;
    let session = engine.create_session(setup);
    for id in 1..=10 {
        engine.send(session, request(id, id as u32));
    }
    assert!(collector.wait(WAIT, |events| completions(events) == 10));
    assert_eq!(server.with_stats(|stats| stats.binds), 1);
    assert!(server.with_stats(|stats| stats.http.requests) > 0);
    engine.shutdown();
}

#[test]
fn enabling_pfs_on_a_running_session_moves_it_to_a_temporary_key() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, Some(random_key(400)), 86_400);
    let pfs = setup.pfs.take().unwrap();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    assert_eq!(server.with_stats(|stats| stats.temporary_keys), 0);
    engine.enable_pfs(session, pfs);
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, |events| completions(events) == 2));
    assert_eq!(server.with_stats(|stats| (stats.temporary_keys, stats.binds)), (1, 1));
    engine.shutdown();
}

#[test]
fn keys_rotate_over_http_and_calls_keep_flowing() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, Some(random_key(400)), 60);
    setup.transport = TransportPreference::Http;
    let session = engine.create_session(setup);
    let started = Instant::now();
    let mut id = 0u64;
    while started.elapsed() < Duration::from_secs(55) {
        id += 1;
        engine.send(session, request(id, (id % 900) as u32));
        assert!(collector.wait(WAIT, |events| completions(events) == id as usize), "call {id}");
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(temporary_keys_created(&collector) >= 2);
    assert!(server.with_stats(|stats| stats.binds) >= 2);
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    engine.shutdown();
}

#[test]
fn a_query_still_unanswered_when_the_key_must_go_fails_instead_of_running_twice() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, Some(random_key(400)), 60));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    engine.send(session, request(5000, TAG_NEVER));
    let started = Instant::now();
    let mut id = 1u64;
    while started.elapsed() < Duration::from_secs(62) {
        id += 1;
        engine.send(session, request(id, (id % 900) as u32));
        assert!(collector.wait(WAIT, |events| completions(events) == id as usize), "call {id}");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(server.executions(TAG_NEVER), 1, "never sent again under the new session");
    assert!(temporary_keys_created(&collector) >= 2, "the key was replaced");
    let failed = collector.count(|event| {
        matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) if id.0 == 5000 && message == "TEMP_KEY_ROTATED")
    });
    assert_eq!(failed, 1, "the host learns the query's fate");
    engine.shutdown();
}

#[test]
fn enabling_pfs_on_a_busy_session_waits_for_its_calls() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, Some(random_key(400)), 86_400);
    let pfs = setup.pfs.take().unwrap();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    engine.send(session, request(2, TAG_SLOW));
    std::thread::sleep(Duration::from_millis(50));
    engine.enable_pfs(session, pfs);
    engine.send(session, request(3, 3));
    assert!(collector.wait(WAIT, |events| completions(events) == 3));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyBound)))
    }));
    engine.send(session, request(4, 4));
    assert!(collector.wait(WAIT, |events| completions(events) == 4));
    assert_eq!(server.executions(TAG_SLOW), 1);
    assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0);
    assert_eq!(server.with_stats(|stats| (stats.temporary_keys, stats.binds)), (1, 1));
    engine.shutdown();
}
