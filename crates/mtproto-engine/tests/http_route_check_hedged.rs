use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, DropReason, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle,
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

    fn drops(&self) -> Vec<(DropReason, bool)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::ConnectionDropped { reason, answered, .. } => Some((*reason, *answered)),
                _ => None,
            })
            .collect()
    }
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn http_setup(server: &TestServer, key: &AuthKey, role: SessionRole) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        role,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap()
}

#[test]
fn a_late_route_check_answer_is_not_taken_for_a_hijacked_route() {
    let old = random_key(905);
    let server = TestServer::start(vec![random_key(906)], ServerOptions::default());
    let profile = mtproto_netsim::Profile {
        name: "slow-round-trips".into(),
        latency: Duration::from_millis(2500),
        ..mtproto_netsim::Profile::perfect()
    };
    let sim = mtproto_netsim::NetSim::start(server.address, profile, 17).unwrap();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &old, SessionRole::Main);
    setup.addresses[0].port = sim.address.port();
    let started = Instant::now();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let invalid = collector.wait(Duration::from_secs(60), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { .. }))
    });
    eprintln!("after {:?}: key invalid reported {invalid}, drops {:?}", started.elapsed(), collector.drops());
    assert!(
        !collector.drops().iter().any(|(reason, _)| *reason == DropReason::AddressRejected),
        "a late res_pq to an earlier route check was taken for a route that answers instead of the server"
    );
    assert!(invalid);
    engine.shutdown();
}
