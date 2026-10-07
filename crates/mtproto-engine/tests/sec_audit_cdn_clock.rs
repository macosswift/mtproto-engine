use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
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

    fn time_differences(&self) -> Vec<f64> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::TimeDifferenceUpdated { difference }) => Some(*difference),
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

fn setup(server: &TestServer, key: &AuthKey, role: SessionRole) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        role,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup
}

/// A CDN datacenter is not trusted with anything but file bytes. One whose clock is off (or that lies
/// about it, with msg_ids from any time it likes) still gets its own session's time right, but its
/// clock never reaches the host as the server's time; a main session's does.
#[test]
fn a_cdn_session_never_reports_its_clock_to_the_host() {
    const OFFSET: f64 = 1_000.0;
    let key = random_key(9201);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions { clock_offset: OFFSET, validate_msg_id_time: true, ..Default::default() },
    );
    for role in [SessionRole::Cdn, SessionRole::Main] {
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let session = engine.create_session(setup(&server, &key, role));
        engine.send(session, request(1, 1));
        let done = collector.wait(Duration::from_secs(15), |events| completions(events) == 1);
        let differences = collector.time_differences();
        engine.shutdown();
        assert!(done, "{role:?}: the session works with the server's clock");
        match role {
            SessionRole::Cdn => assert!(differences.is_empty(), "the CDN's clock reached the host: {differences:?}"),
            _ => assert!(differences.iter().any(|difference| (difference - OFFSET).abs() < 5.0), "{differences:?}"),
        }
    }
}
