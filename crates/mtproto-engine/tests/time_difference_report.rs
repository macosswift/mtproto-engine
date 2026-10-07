//! The host is told the clock difference the session ends up using, even when the host had pushed a
//! different one itself (crashes.md, fix-02).

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<EngineEvent>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push(event);
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, _message: &str) {}
}

impl Collector {
    fn wait_for(&self, id: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut events = self.events.lock().unwrap();
        loop {
            if events
                .iter()
                .any(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, Duration::from_millis(50)).unwrap().0;
        }
    }
}

fn request(id: u64) -> RpcRequest {
    RpcRequest { id: RequestId(id), body: call(id as u32, &[]), flags: RequestFlags::default(), invoke_after: None }
}

#[test]
fn a_difference_the_host_pushed_and_the_server_corrected_is_reported_back() {
    let key = random_key(7201);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { validate_msg_id_time: true, ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    let now = unix_seconds();
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1));
    assert!(collector.wait_for(1));
    engine.set_time_difference(session, 20_000.0);
    engine.send(session, request(2));
    let started = std::time::Instant::now();
    assert!(collector.wait_for(2), "the call stalled after the host pushed a clock difference");
    assert!(started.elapsed() < Duration::from_secs(10), "it waited {:?}", started.elapsed());
    let reported: Vec<f64> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            EngineEvent::Rpc(RpcEvent::TimeDifferenceUpdated { difference }) => Some(*difference),
            _ => None,
        })
        .collect();
    assert!(
        reported.last().is_some_and(|difference| difference.abs() < 60.0),
        "the host pushed +20000 s; the corrected difference must reach it: {reported:?}"
    );
    engine.shutdown();
}
