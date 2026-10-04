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

    fn completed(&self, session: SessionHandle, id: u64) -> bool {
        self.of(session)
            .iter()
            .any(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
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

    fn in_use_dcs(&self, session: SessionHandle) -> Vec<i32> {
        self.of(session)
            .iter()
            .filter_map(|event| match event {
                EngineEvent::TemporaryKeyInUse { dc_id, .. } => Some(*dc_id),
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

    fn created(&self, session: SessionHandle, temporary: bool) -> usize {
        self.of(session)
            .iter()
            .filter(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at, .. } if expires_at.is_some() == temporary))
            .count()
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

#[test]
fn a_session_without_a_permanent_key_asks_the_host_and_makes_none() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session =
        engine.create_session(setup(&server, None, PfsSetup { permanent_key_from_host: true, ..pfs(86_400) }));
    engine.send(session, request(1));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, event)| *event == EngineEvent::AuthKeyRequired)));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        server.with_stats(|stats| (stats.connections, stats.handshakes)),
        (0, 0),
        "no handshake before the host's key"
    );
    assert!(!collector.completed(session, 1));

    engine.set_auth_key(session, Some(perm()));
    assert!(collector.wait_completed(session, 1), "events {:?}", collector.of(session));
    assert_eq!(server.with_stats(|stats| stats.handshake_dcs.clone()), vec![(2, true)], "only a temporary key is made");
    assert_eq!((collector.created(session, false), collector.created(session, true)), (0, 1));
    assert_eq!(collector.in_use(session).iter().map(|(_, adopted)| *adopted).collect::<Vec<_>>(), vec![false]);
    assert_eq!(server.with_stats(|stats| stats.binds), 1);
}

#[test]
fn a_waiting_session_may_be_allowed_to_make_the_permanent_key() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session =
        engine.create_session(setup(&server, None, PfsSetup { permanent_key_from_host: true, ..pfs(86_400) }));
    engine.send(session, request(1));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, event)| *event == EngineEvent::AuthKeyRequired)));
    engine.allow_permanent_key(session, true);
    assert!(collector.wait_completed(session, 1), "events {:?}", collector.of(session));
    assert_eq!(server.with_stats(|stats| stats.handshake_dcs.clone()), vec![(2, false), (2, true)]);
    assert_eq!((collector.created(session, false), collector.created(session, true)), (1, 1));
}

#[test]
fn a_bound_key_from_the_host_needs_no_handshake_and_no_bind() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let first = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(first, request(1));
    assert!(collector.wait_completed(first, 1));
    let kept = collector.bound_key(first);
    let kept_id = kept.material.key.id() as i64;
    let before = server.with_stats(|stats| (stats.handshakes, stats.binds));

    let second =
        engine.create_session(setup(&server, Some(perm()), PfsSetup { temporary_key: Some(kept), ..pfs(86_400) }));
    engine.send(second, request(2));
    assert!(collector.wait_completed(second, 2), "events {:?}", collector.of(second));
    assert_eq!(server.with_stats(|stats| (stats.handshakes, stats.binds)), before, "the kept key needs neither");
    assert_eq!(collector.in_use(second), vec![(kept_id, true)]);
    let perm_id = random_key(400).id();
    assert!(
        server.with_stats(|stats| stats.executed_under.contains(&(2, perm_id))),
        "the call ran for the permanent key"
    );
}

#[test]
fn an_offered_key_replaces_the_handshake_after_the_server_drops_the_key() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let first = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    let second = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(first, request(1));
    engine.send(second, request(2));
    assert!(collector.wait_completed(first, 1) && collector.wait_completed(second, 2));
    let first_key = collector.bound_key(first).material.key.id();
    let offered = collector.bound_key(second);
    let offered_id = offered.material.key.id() as i64;
    engine.offer_temporary_key(first, offered);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(collector.in_use(first).len(), 1, "a key in use is not replaced by an offer");

    let handshakes = server.with_stats(|stats| stats.handshakes);
    server.remove_key(first_key);
    engine.send(first, request(3));
    assert!(collector.wait_completed(first, 3), "events {:?}", collector.of(first));
    assert_eq!(collector.dropped(first), vec![first_key as i64]);
    assert_eq!(collector.in_use(first).last(), Some(&(offered_id, true)));
    assert_eq!(server.with_stats(|stats| stats.handshakes), handshakes, "the offer saved the handshake");
}

#[test]
fn a_key_the_server_dropped_is_never_taken_again() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1));
    let dropped = collector.bound_key(session);
    let dropped_id = dropped.material.key.id();

    server.remove_key(dropped_id);
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    assert_eq!(collector.dropped(session), vec![dropped_id as i64]);
    let replacement = collector.bound_key(session).material.key.id();
    assert_ne!(replacement, dropped_id);

    engine.offer_temporary_key(session, dropped);
    let handshakes = server.with_stats(|stats| stats.handshakes);
    server.remove_key(replacement);
    engine.send(session, request(3));
    assert!(collector.wait_completed(session, 3), "events {:?}", collector.of(session));
    assert!(collector.in_use(session).iter().all(|(_, adopted)| !adopted), "the dropped key came back");
    assert_eq!(server.with_stats(|stats| stats.handshakes), handshakes + 1);
}

#[test]
fn keys_are_made_for_the_datacenter_id_the_connection_announces() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut media = setup(&server, Some(perm()), pfs(86_400));
    media.obfuscation_dc_id = -2;
    let session = engine.create_session(media);
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1));
    assert_eq!(
        server.with_stats(|stats| stats.handshake_dcs.clone()),
        vec![(-2, true)],
        "a media key, as MtProtoKit makes it"
    );

    engine.set_obfuscation_dc_id(session, 2);
    engine.send(session, request(2));
    assert!(collector.wait_completed(session, 2), "events {:?}", collector.of(session));
    assert_eq!(
        server.with_stats(|stats| stats.handshake_dcs.clone()),
        vec![(-2, true), (2, true)],
        "the class change replaced the key"
    );
    assert_eq!(collector.in_use_dcs(session), vec![-2, 2], "each key reports the class it was made for");
    let keys: Vec<i64> = collector.in_use(session).iter().map(|(id, _)| *id).collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn a_test_environment_key_carries_the_test_offset() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut test = setup(&server, Some(perm()), pfs(86_400));
    test.obfuscation_dc_id = 10_002;
    let session = engine.create_session(test);
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1));
    assert_eq!(server.with_stats(|stats| stats.handshake_dcs.clone()), vec![(10_002, true)]);
}

#[test]
fn with_tcp_blocked_auto_makes_binds_and_reuses_keys_over_http() {
    let server = server();
    server.set_tcp_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut first = setup(&server, None, PfsSetup { permanent_key_from_host: true, ..pfs(86_400) });
    first.transport = TransportPreference::Auto;
    let first = engine.create_session(first);
    engine.send(first, request(1));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, event)| *event == EngineEvent::AuthKeyRequired)));
    engine.set_auth_key(first, Some(perm()));
    assert!(collector.wait_completed(first, 1), "events {:?}", collector.of(first));
    assert_eq!(server.with_stats(|stats| (stats.handshake_dcs.clone(), stats.binds)), (vec![(2, true)], 1));
    assert!(server.with_stats(|stats| stats.http.requests) > 0, "the key was made over HTTP");

    let kept = collector.bound_key(first);
    let mut second = setup(&server, Some(perm()), PfsSetup { temporary_key: Some(kept), ..pfs(86_400) });
    second.transport = TransportPreference::Auto;
    let second = engine.create_session(second);
    engine.send(second, request(2));
    assert!(collector.wait_completed(second, 2), "events {:?}", collector.of(second));
    assert_eq!(server.with_stats(|stats| (stats.handshakes, stats.binds)), (1, 1), "the second session reused the key");
}

#[test]
fn calls_failed_by_a_key_change_are_reported_in_the_order_they_were_sent() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1));
    let ids: Vec<u64> = (10..18).collect();
    for (index, id) in ids.iter().enumerate() {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(*id),
                body: call(TAG_NEVER, &id.to_le_bytes()),
                flags: RequestFlags::default(),
                invoke_after: (index > 0).then(|| RequestId(ids[index - 1])),
            },
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    engine.set_obfuscation_dc_id(session, -2);
    assert!(collector.wait(WAIT, |events| {
        events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. }))).count()
            == ids.len()
    }));
    let failed: Vec<u64> = collector
        .of(session)
        .iter()
        .filter_map(|event| match event {
            EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) if message == "TEMP_KEY_ROTATED" => Some(id.0),
            _ => None,
        })
        .collect();
    assert_eq!(failed, ids, "a host sending them again in this order keeps the chain");
}

#[test]
fn a_call_chained_to_a_call_failed_by_a_key_change_fails_the_same_way() {
    let server = server();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(&server, Some(perm()), pfs(86_400)));
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1));
    engine.send(
        session,
        RpcRequest {
            id: RequestId(10),
            body: call(TAG_NEVER, &10u64.to_le_bytes()),
            flags: RequestFlags::default(),
            invoke_after: None,
        },
    );
    std::thread::sleep(Duration::from_millis(500));
    engine.set_obfuscation_dc_id(session, -2);
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| {
            matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) if id.0 == 10 && message == "TEMP_KEY_ROTATED")
        })
    }));
    for (id, after) in [(30u64, 10u64), (31, 30)] {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: call(id as u32, &id.to_le_bytes()),
                flags: RequestFlags::default(),
                invoke_after: Some(RequestId(after)),
            },
        );
    }
    assert!(
        collector.wait(WAIT, |events| {
            [30u64, 31].iter().all(|wanted| {
                events.iter().any(|(_, event)| {
                    matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) if id.0 == *wanted && message == "TEMP_KEY_ROTATED")
                })
            })
        }),
        "events {:?}",
        collector.of(session)
    );
    assert!(!collector.completed(session, 30) && !collector.completed(session, 31));
    assert_eq!(
        server.executions(30) + server.executions(31),
        0,
        "nothing of the chain ran ahead of the call it waits for"
    );
}
