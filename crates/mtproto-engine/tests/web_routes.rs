use std::net::SocketAddr;
use std::sync::atomic::Ordering;
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

#[test]
fn auto_moves_to_telegram_web_when_tcp_and_plain_http_get_no_answer() {
    let key = random_key(9101);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    front.set_websocket_refused(true);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    assert!(collector.wait_completed(session, 3, Duration::from_secs(20)), "the calls went through Telegram Web");
    let elapsed = started.elapsed();
    eprintln!("first calls over HTTPS after {elapsed:?}");
    assert!(elapsed < Duration::from_secs(6), "the web route is tried with the first HTTP probe: {elapsed:?}");
    assert!(collector.logged("moving to HTTPS"));
    let stats = front.stats();
    assert!(stats.server_names.iter().all(|name| name == WEB_FRONT_NAME), "{stats:?}");
    assert!(stats.alpn.iter().all(|protocol| protocol == "http/1.1"), "{stats:?}");
    assert!(
        stats
            .requests
            .iter()
            .all(|line| line == &format!("POST /apiw1 HTTP/1.1 @ {WEB_FRONT_NAME}:{}", front.address.port())
                || line.starts_with("GET /apiws ")),
        "{stats:?}"
    );
    let targets = host.targets.lock().unwrap().clone();
    assert!(targets.iter().all(|target| target.host == "127.0.0.1"
        && target.port == front.address.port()
        && target.tls_server_name.as_deref() == Some(WEB_FRONT_NAME)
        && target.alpn == ["http/1.1"]));
    engine.shutdown();
}

#[test]
fn http_mode_takes_the_web_route_next_to_a_dead_address() {
    let key = random_key(9102);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Http, Some(web_endpoint(&front))));
    for id in 1..=5 {
        engine.send(session, request(id));
    }
    assert!(collector.wait_completed(session, 5, Duration::from_secs(20)));
    eprintln!("HTTP mode over the web route after {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    engine.shutdown();
}

#[test]
fn without_a_stream_host_the_web_route_is_not_tried() {
    let key = random_key(9103);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    engine.send(session, request(1));
    assert!(!collector.wait_completed(session, 1, Duration::from_secs(4)));
    assert_eq!(front.stats().connections, 0);
    engine.shutdown();
}

#[test]
fn a_dead_web_front_does_not_hold_up_plain_http() {
    let key = random_key(9104);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    server.set_tcp_blackhole(true);
    let front = WebFront::start(server.address);
    front.set_blackhole(true);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session =
        engine.create_session(setup(server.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    assert!(collector.wait_completed(session, 3, Duration::from_secs(20)));
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert!(collector.logged("moving to HTTP"));
    assert_eq!(front.stats().handshakes, 0);
    engine.shutdown();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(host.open_streams(), 0, "every stream the engine opened was closed");
}

#[test]
fn refused_host_streams_cost_a_round_and_then_work() {
    let key = random_key(9105);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.refuse.store(true, Ordering::Relaxed);
    host.attach(&engine);
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    engine.send(session, request(1));
    assert!(!collector.wait_completed(session, 1, Duration::from_secs(4)));
    host.refuse.store(false, Ordering::Relaxed);
    assert!(collector.wait_completed(session, 1, Duration::from_secs(30)), "the next round of probes got through");
    engine.shutdown();
}

#[test]
fn big_downloads_and_uploads_cross_the_web_route() {
    let key = random_key(9106);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Http, Some(web_endpoint(&front))));
    let started = Instant::now();
    for id in 1..=8u64 {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: sized_call(1_000_000),
                flags: RequestFlags::default(),
                invoke_after: None,
            },
        );
    }
    for id in 9..=12u64 {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: call(TAG_UPLOAD, &vec![id as u8; 900_000]),
                flags: RequestFlags::default(),
                invoke_after: None,
            },
        );
    }
    assert!(collector.wait_completed(session, 12, Duration::from_secs(30)));
    eprintln!("8 MB down and 3.6 MB up over the web route in {:?}", started.elapsed());
    let events = collector.events.lock().unwrap();
    for (_, event) in events.iter() {
        if let EngineEvent::Rpc(RpcEvent::Completed { id, body: result, .. }) = event
            && id.0 <= 8
        {
            assert!(result.len() >= 1_000_000, "download {} came back whole: {}", id.0, result.len());
        }
    }
    drop(events);
    engine.shutdown();
}

fn engine_with(collector: &Arc<Collector>, connect_timeout: f64) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, connect_timeout, ..EngineConfig::default() }, collector.clone())
        .unwrap()
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
fn auto_moves_the_stream_to_the_websocket_endpoint_when_tcp_and_plain_http_get_no_answer() {
    let key = random_key(9111);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    assert!(completed_within(&collector, &engine, session, 1..=3, Duration::from_secs(20)));
    let elapsed = started.elapsed();
    eprintln!("first calls over the WebSocket endpoint after {elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    assert!(collector.logged("moving the stream there"));
    let stats = front.stats();
    assert_eq!(stats.violations, 0, "no ping, pong, text or empty frame: {stats:?}");
    assert!(stats.websockets >= 1);
    assert!(
        stats
            .requests
            .iter()
            .all(|line| line == &format!("GET /apiws HTTP/1.1 @ {WEB_FRONT_NAME}:{}", front.address.port())),
        "HTTPS was not needed: {stats:?}"
    );
    let big = RpcRequest {
        id: RequestId(50),
        body: sized_call(1_000_000),
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    engine.send(session, big);
    let upload = RpcRequest {
        id: RequestId(51),
        body: call(TAG_UPLOAD, &vec![3u8; 900_000]),
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    engine.send(session, upload);
    assert!(
        collector.wait_completed(session, 5, Duration::from_secs(20)),
        "a download and an upload over the WebSocket"
    );
    engine.shutdown();
}

#[test]
fn https_takes_over_when_the_websocket_upgrade_is_refused() {
    let key = random_key(9112);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    front.set_websocket_refused(true);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    assert!(completed_within(&collector, &engine, session, 1..=3, Duration::from_secs(20)));
    let elapsed = started.elapsed();
    eprintln!("calls over HTTPS after a refused upgrade after {elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "a refused upgrade gives HTTPS its turn at once: {elapsed:?}");
    assert!(collector.logged("moving to HTTPS"));
    let stats = front.stats();
    assert_eq!(stats.websockets, 0);
    assert!(stats.requests.iter().any(|line| line.starts_with("POST /apiw1 ")), "{stats:?}");
    engine.shutdown();
}

#[test]
fn https_gets_its_turn_when_the_websocket_upgrade_goes_unanswered() {
    let key = random_key(9113);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let silent_front = WebFront::start(server.address);
    silent_front.set_blackhole(true);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&silent_front))));
    engine.send(session, request(1));
    std::thread::sleep(Duration::from_millis(5_000));
    let targets = host.targets.lock().unwrap().len();
    assert!(targets >= 2, "the WebSocket probe, then HTTPS after its head start: {targets} streams");
    engine.shutdown();
}

#[test]
fn the_websocket_session_goes_back_to_tcp_once_tcp_answers() {
    let key = random_key(9114);
    let direct = TestServer::start(vec![key.clone()], ServerOptions { http_disabled: true, ..Default::default() });
    direct.set_tcp_blackhole(true);
    let behind_front = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(behind_front.address);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let mut session_setup = setup(direct.address, &key, TransportPreference::Auto, Some(web_endpoint(&front)));
    session_setup.tcp_recheck_after = 1.0;
    let session = engine.create_session(session_setup);
    assert!(completed_within(&collector, &engine, session, 1..=2, Duration::from_secs(20)));
    assert!(collector.logged("moving the stream there"));
    direct.set_tcp_blackhole(false);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !collector.logged("leaving the WebSocket endpoint") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(collector.logged("leaving the WebSocket endpoint"), "the TCP recheck brought the stream back");
    let executed_direct = direct.executions(1);
    assert!(completed_within(&collector, &engine, session, 10..=12, Duration::from_secs(10)));
    assert!(direct.executions(1) > executed_direct, "the calls after it went over TCP");
    engine.shutdown();
}

#[test]
fn a_websocket_endpoint_that_keeps_failing_hands_back_to_tcp() {
    let key = random_key(9115);
    let direct = TestServer::start(vec![key.clone()], ServerOptions { http_disabled: true, ..Default::default() });
    direct.set_tcp_blackhole(true);
    let behind_front = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(behind_front.address);
    let collector = Arc::new(Collector::default());
    let engine = engine_with(&collector, 2.0);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let mut session_setup = setup(direct.address, &key, TransportPreference::Auto, Some(web_endpoint(&front)));
    session_setup.tcp_recheck_after = 600.0;
    let session = engine.create_session(session_setup);
    assert!(completed_within(&collector, &engine, session, 1..=2, Duration::from_secs(20)));
    assert!(collector.logged("moving the stream there"));
    front.set_blackhole(true);
    front.drop_connections();
    direct.set_tcp_blackhole(false);
    assert!(
        completed_within(&collector, &engine, session, 10..=11, Duration::from_secs(30)),
        "TCP after the endpoint failed twice"
    );
    assert!(collector.logged("keeps failing; trying TCP again"));
    engine.shutdown();
}

/// A front closes the WebSocket right behind the server's last bytes, often in the same read: a -429
/// before the close frame still counts, so the session backs off instead of reconnecting at once.
#[test]
fn an_error_code_in_the_same_read_as_the_close_frame_still_counts() {
    let key = random_key(9131);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let session =
        engine.create_session(setup(dead.address, &key, TransportPreference::Auto, Some(web_endpoint(&front))));
    assert!(completed_within(&collector, &engine, session, 1..=2, Duration::from_secs(20)));
    assert!(collector.logged("moving the stream there"));
    front.set_close_with_last_bytes(true);
    let flood = RpcRequest {
        id: RequestId(10),
        body: transport_error_call(-429),
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    engine.send(session, flood);
    let flooded = |events: &[(SessionHandle, EngineEvent)]| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::TransportFlood))
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !flooded(&collector.events.lock().unwrap()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    front.set_close_with_last_bytes(false);
    assert_eq!(server.with_stats(|stats| stats.transport_errors_sent), 1);
    assert!(flooded(&collector.events.lock().unwrap()), "the -429 before the close frame was read");
    assert!(collector.wait_completed(session, 3, Duration::from_secs(20)), "the call went again after the backoff");
    engine.shutdown();
}
