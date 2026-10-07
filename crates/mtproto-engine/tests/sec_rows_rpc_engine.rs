//! Security requirements on 401 handling under engine PFS (B-31), CDN updates (B-33), initConnection
//! after restarts and binds (B-70) and test datacenters (B-74), end to end against the test server.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{ApiEnvironment, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, PfsSetup,
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

    fn wait_completed(&self, session: SessionHandle, id: u64) -> bool {
        self.wait(WAIT, |events| {
            events.iter().any(|(handle, event)| {
                *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: RequestId(found), .. }) if *found == id)
            })
        })
    }

    fn count(&self, session: SessionHandle, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(handle, event)| *handle == session && predicate(event)).count()
    }
}

const WAIT: Duration = Duration::from_secs(20);

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 4,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "sec-rows-init".into(),
        disable_updates: false,
    }
}

fn material(key: AuthKey, init_hash: Option<&str>) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: init_hash.map(str::to_string),
    }
}

fn live_server(keys: Vec<AuthKey>) -> TestServer {
    TestServer::start(
        keys,
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    )
}

fn plain_setup(server: &TestServer, role: SessionRole) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        role,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.http_port = None;
    setup
}

fn pfs_setup(server: &TestServer, perm: AuthKey, role: SessionRole) -> SessionSetup {
    let mut setup = plain_setup(server, role);
    setup.auth_key = Some(material(perm, None));
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn is_key_loss(event: &EngineEvent) -> bool {
    matches!(
        event,
        EngineEvent::AuthKeyInvalid { .. }
            | EngineEvent::PermanentKeyInvalid
            | EngineEvent::AuthKeyRequired
            | EngineEvent::Rpc(RpcEvent::AuthorizationRequired { .. })
            | EngineEvent::AuthKeyCreated { expires_at: None, .. }
    )
}

#[test]
fn auth_key_perm_empty_under_engine_pfs_never_touches_the_permanent_key() {
    let perm = random_key(7301);
    let server = live_server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, perm.clone(), SessionRole::Main));
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(session, 1));

    server.unbind_temporary_keys();
    engine.send(session, request(2, 2));
    assert!(collector.wait_completed(session, 2), "the call goes out again after the rebind");
    assert!(server.with_stats(|stats| stats.perm_empty_errors) >= 1, "the server refused the unbound key");

    let (temporary, binds) = server.with_stats(|stats| (stats.temporary_keys, stats.binds));
    assert_eq!((temporary, binds), (1, 2), "the temporary key was bound again, nothing else was made");

    assert_eq!(collector.count(session, is_key_loss), 0, "the permanent key was never dropped or replaced");
    assert_eq!(collector.count(session, |event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. }))), 0);
    let (handshakes, executed_under, duplicates) = server
        .with_stats(|stats| (stats.handshake_dcs.clone(), stats.executed_under.clone(), stats.duplicate_executions));
    assert!(handshakes.iter().all(|(_, temporary)| *temporary), "only temporary keys were made: {handshakes:?}");
    assert!(executed_under.iter().all(|(_, perm_id)| *perm_id == perm.id()), "{executed_under:?}");
    assert_eq!(duplicates, 0);
    engine.shutdown();
}

#[test]
#[ignore = "B-31: a 401 on a non-main session under engine PFS keeps the temporary key (tdlib drops it)"]
fn a_401_on_a_non_main_session_under_engine_pfs_replaces_its_temporary_key() {
    let perm = random_key(7302);
    let server = live_server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, perm, SessionRole::Worker { requires_auth_token: true }));
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(session, 1));
    assert_eq!(server.with_stats(|stats| stats.temporary_keys), 1);
    engine.send(session, request(2, TAG_UNAUTHORIZED));
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::AuthTokenRequired)))
    }));
    engine.set_auth_token_ready(session, true);
    engine.send(session, request(3, 3));
    assert!(collector.wait_completed(session, 3));
    let temporary = server.with_stats(|stats| stats.temporary_keys);
    engine.shutdown();
    assert!(temporary >= 2, "the temporary key was kept after the 401 ({temporary} made)");
}

#[test]
fn a_cdn_session_never_delivers_a_pushed_update() {
    let key = random_key(7303);
    let server = live_server(vec![key.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut cdn = plain_setup(&server, SessionRole::Cdn);
    cdn.auth_key = Some(material(key.clone(), None));
    let cdn = engine.create_session(cdn);
    let mut main = plain_setup(&server, SessionRole::Main);
    main.auth_key = Some(material(key, None));
    let main = engine.create_session(main);
    engine.send(cdn, request(1, TAG_UPDATE_PUSH));
    engine.send(main, request(2, TAG_UPDATE_PUSH));
    assert!(collector.wait_completed(cdn, 1), "the CDN's answer still arrives");
    assert!(collector.wait_completed(main, 2));
    assert!(collector.wait(WAIT, |events| {
        events
            .iter()
            .any(|(handle, event)| *handle == main && matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. })))
    }));
    assert_eq!(server.executions(TAG_UPDATE_PUSH), 2);
    let leaked = collector
        .count(cdn, |event| matches!(event, EngineEvent::Rpc(RpcEvent::Update { .. } | RpcEvent::UpdatesReset)));
    engine.shutdown();
    assert_eq!(leaked, 0, "a CDN pushed an update to the host");
}

fn init_connections(server: &TestServer) -> usize {
    server.with_stats(|stats| stats.init_connections)
}

#[test]
fn init_connection_goes_with_the_first_call_under_every_new_temporary_key() {
    let perm = random_key(7304);
    let server = live_server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, perm, SessionRole::Main);
    setup.environment = Some(environment());
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(session, 1));
    assert_eq!(init_connections(&server), 1, "the first call after the bind is initialized");
    engine.send(session, request(2, 2));
    assert!(collector.wait_completed(session, 2));
    assert_eq!(init_connections(&server), 1, "an initialized key is not initialized again");

    for round in 0..2 {
        server.drop_temporary_keys();
        let binds = server.with_stats(|stats| stats.binds);
        let id = 3 + round;
        engine.send(session, request(id, id as u32));
        assert!(collector.wait_completed(session, id));
        assert!(server.with_stats(|stats| stats.binds) > binds, "round {round}: a new key was bound");
        assert_eq!(init_connections(&server), 2 + round as usize, "round {round}: the new key's first call");
    }
    engine.shutdown();
}

#[test]
#[ignore = "B-70: a rebind of the same temporary key after AUTH_KEY_PERM_EMPTY is not followed by initConnection"]
fn init_connection_goes_with_the_first_call_after_a_rebind_of_the_same_temporary_key() {
    let perm = random_key(7305);
    let server = live_server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = pfs_setup(&server, perm, SessionRole::Main);
    setup.environment = Some(environment());
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(session, 1));
    assert_eq!(init_connections(&server), 1);
    server.unbind_temporary_keys();
    engine.send(session, request(2, 2));
    assert!(collector.wait_completed(session, 2));
    let (temporary, binds) = server.with_stats(|stats| (stats.temporary_keys, stats.binds));
    let inits = init_connections(&server);
    engine.shutdown();
    assert_eq!((temporary, binds), (1, 2), "the same key was bound again");
    assert_eq!(inits, 2, "the call after the second auth.bindTempAuthKey carries initConnection");
}

#[test]
fn a_stored_init_hash_from_an_earlier_run_does_not_skip_init_connection() {
    let key = random_key(7306);
    let server = live_server(vec![key.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let hash = environment().init_hash;
    let mut first = plain_setup(&server, SessionRole::Main);
    first.environment = Some(environment());
    first.auth_key = Some(material(key.clone(), Some(&hash)));
    let first = engine.create_session(first);
    engine.send(first, request(1, 1));
    assert!(collector.wait_completed(first, 1));
    assert_eq!(init_connections(&server), 1, "a hash the host kept from an earlier run is not trusted");
    assert!(collector.wait(WAIT, |events| {
        events.iter().any(|(handle, event)| {
            *handle == first && matches!(event, EngineEvent::Rpc(RpcEvent::InitHashStored { .. }))
        })
    }));

    let mut second = plain_setup(&server, SessionRole::Worker { requires_auth_token: false });
    second.environment = Some(environment());
    second.auth_key = Some(material(key, Some(&hash)));
    let second = engine.create_session(second);
    engine.send(second, request(2, 2));
    assert!(collector.wait_completed(second, 2));
    assert_eq!(init_connections(&server), 1, "a key initialized in this process keeps its hash");

    let mut changed = environment();
    changed.system_lang_code = "de".into();
    changed.init_hash = "sec-rows-init-de".into();
    engine.update_environment(first, changed, None);
    engine.send(first, request(3, 3));
    assert!(collector.wait_completed(first, 3));
    assert_eq!(init_connections(&server), 2, "a changed parameter initializes the connection again");
    engine.shutdown();
}

#[test]
fn a_test_datacenter_key_is_made_for_the_id_its_obfuscation_header_carries() {
    for (obfuscation_dc_id, expected) in [(10_002i16, 10_002i32), (2, 2)] {
        let server = live_server(Vec::new());
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = plain_setup(&server, SessionRole::Main);
        setup.obfuscation_dc_id = obfuscation_dc_id;
        setup.key_generation = Some(KeyGeneration {
            public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
            temporary_expires_in: None,
        });
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        assert!(collector.wait_completed(session, 1));
        let (dcs, headers) = server.with_stats(|stats| (stats.handshake_dcs.clone(), stats.obfuscation_dc_ids.clone()));
        engine.shutdown();
        assert_eq!(dcs, vec![(expected, false)], "p_q_inner_data_dc names the datacenter with its test offset");
        assert!(!headers.is_empty() && headers.iter().all(|dc| i32::from(*dc) == expected), "{headers:?}");
    }
}

#[test]
fn a_datacenter_mismatch_rejection_never_drops_or_replaces_the_key() {
    let key = random_key(7307);
    let server = TestServer::start(vec![key.clone()], ServerOptions { reject_with: Some(-444), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = plain_setup(&server, SessionRole::Main);
    setup.auth_key = Some(material(key, None));
    setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |_| server.with_stats(|stats| stats.transport_errors_sent) >= 2));
    std::thread::sleep(Duration::from_secs(2));
    let (handshakes, rejections) = server.with_stats(|stats| (stats.handshakes, stats.transport_errors_sent));
    let lost = collector.count(session, is_key_loss);
    let failed = collector.count(session, |event| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. })));
    engine.shutdown();
    assert!(rejections >= 2);
    assert_eq!(handshakes, 0, "no key is made for another environment");
    assert_eq!(lost, 0, "a -444 is not a lost key");
    assert_eq!(failed, 0, "the call waits for a datacenter that takes it");
}
