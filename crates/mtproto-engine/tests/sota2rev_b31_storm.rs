#![allow(dead_code, unused_imports)]
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

/// A host that retries a call the server keeps refusing with 401 on a worker without the token gate
/// (requires_auth_token: false, the home datacenter's media and upload sessions) must not get one
/// temporary-key handshake per refusal: every new key binds, which resets `refusals`, so
/// `regenerate_after_refusal` never backs off.
#[test]
fn repeated_401s_on_a_worker_do_not_make_a_temporary_key_each() {
    let perm = random_key(7399);
    let server = live_server(vec![perm.clone()]);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(&server, perm, SessionRole::Worker { requires_auth_token: false }));
    engine.send(session, request(1, 1));
    assert!(collector.wait_completed(session, 1));
    let started = Instant::now();
    let rounds = 8u64;
    for round in 0..rounds {
        let id = 100 + round;
        engine.send(session, request(id, TAG_UNAUTHORIZED));
        assert!(collector.wait(WAIT, |events| {
            events.iter().any(|(handle, event)| {
                *handle == session
                    && matches!(event, EngineEvent::Rpc(RpcEvent::Failed { id: RequestId(found), code: 401, .. }) if *found == id)
            })
        }), "round {round}: the 401 reached the host");
    }
    let elapsed = started.elapsed().as_secs_f64();
    let temporary = server.with_stats(|stats| stats.temporary_keys);
    engine.shutdown();
    eprintln!("{temporary} temporary keys for {rounds} refusals in {elapsed:.2} s");
    assert!(temporary <= 4, "{temporary} temporary-key handshakes for {rounds} 401s in {elapsed:.2} s");
}
