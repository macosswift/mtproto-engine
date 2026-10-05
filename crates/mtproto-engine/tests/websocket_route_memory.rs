use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, WebEndpoint, unix_seconds,
};
use mtproto_testserver::*;

#[path = "support/stream_host.rs"]
mod stream_host;

use stream_host::TestStreamHost;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    logs: Mutex<Vec<String>>,
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
        self.logs.lock().unwrap().push(message.to_string());
    }
}

impl Collector {
    fn wait_completed(&self, session: SessionHandle, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            let done = events
                .iter()
                .filter(|(handle, event)| {
                    *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))
                })
                .count();
            if done >= count {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }

    fn logged(&self, text: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|line| line.contains(text))
    }
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn web_endpoint(front: &WebFront) -> WebEndpoint {
    WebEndpoint {
        host: WEB_FRONT_NAME.into(),
        port: front.address.port(),
        path: "/apiw1".into(),
        ws_path: "/apiws".into(),
        address: Some("127.0.0.1".into()),
    }
}

fn setup(address: SocketAddr, key: &AuthKey, transport: TransportPreference, web: Option<WebEndpoint>) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: address.ip().to_string(), port: address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = transport;
    setup.http_port = None;
    setup.web = web;
    setup
}

fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(1, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn completed_within(
    collector: &Collector,
    engine: &Engine,
    session: SessionHandle,
    ids: std::ops::RangeInclusive<u64>,
    timeout: Duration,
) -> bool {
    let count = ids.clone().count();
    let before = {
        let events = collector.events.lock().unwrap();
        events
            .iter()
            .filter(|(handle, event)| {
                *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))
            })
            .count()
    };
    for id in ids {
        engine.send(session, request(id));
    }
    collector.wait_completed(session, before + count, timeout)
}

#[test]
fn a_websocket_reconnect_does_not_wipe_the_route_memory() {
    let key = random_key(9311);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    engine.set_network(b"office");
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    assert!(completed_within(&collector, &engine, session, 1..=2, Duration::from_secs(20)));
    assert!(collector.logged("moving the stream there"));
    std::thread::sleep(Duration::from_millis(300));
    let learned = engine.route_memory();
    eprintln!("memory after adopting the WebSocket: {} bytes", learned.len());
    front.drop_connections();
    std::thread::sleep(Duration::from_millis(300));
    assert!(completed_within(&collector, &engine, session, 3..=4, Duration::from_secs(20)));
    std::thread::sleep(Duration::from_millis(300));
    let after = engine.route_memory();
    eprintln!("memory after the WebSocket reconnected: {} bytes", after.len());
    eprintln!(
        "tcp answered logs: {:?}",
        collector
            .logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains("TCP") || l.contains("WebSocket") || l.contains("closed"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        after.len(),
        learned.len(),
        "the network was forgotten as one that blocks TCP although TCP never answered"
    );
}
