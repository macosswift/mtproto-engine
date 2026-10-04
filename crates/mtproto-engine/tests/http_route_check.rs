mod middlebox;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use middlebox::{Action, Info};
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
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

fn setup(port: u16, key: &mtproto_engine::mtproto_core::auth_key::AuthKey) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup
}

/// One odd answer to the route check (an empty 200, as a middlebox may give) after one 404 must not
/// stop the session for good: the next requests reach the real server.
#[test]
fn a_route_check_answered_with_an_empty_200_does_not_hold_traffic_forever() {
    let key = random_key(901);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (port, stats) = middlebox::start(
        server.address,
        Arc::new(|info: Info| {
            if !info.plain && info.encrypted_index == 0 {
                Action::Respond(404, b"<html>not here</html>".to_vec())
            } else if info.plain && info.plain_index == 0 {
                Action::Respond(200, Vec::new())
            } else {
                Action::Forward
            }
        }),
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let session = engine.create_session(setup(port, &key));
    engine.send(session, request(1, 1));
    let done = collector.wait(Duration::from_secs(20), |events| completions(events) == 1);
    let plain = stats.plain.load(Ordering::SeqCst);
    let encrypted = stats.encrypted.load(Ordering::SeqCst);
    engine.shutdown();
    assert!(done, "request never completed; middlebox saw {plain} plain and {encrypted} encrypted requests");
}

/// A route check answered with a plain packet that is not our res_pq: the probe must back off, not
/// open a fresh connection per round trip.
#[test]
fn a_route_check_answered_with_a_foreign_plain_packet_backs_off() {
    let key = random_key(902);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (port, stats) = middlebox::start(
        server.address,
        Arc::new(|info: Info| {
            if !info.plain {
                Action::Respond(404, b"<html>not here</html>".to_vec())
            } else {
                let mut body = vec![0u8; 8];
                body.extend_from_slice(&[0x11; 32]);
                Action::Respond(200, body)
            }
        }),
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let session = engine.create_session(setup(port, &key));
    engine.send(session, request(1, 1));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) && stats.plain.load(Ordering::SeqCst) < 200 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = started.elapsed();
    let plain = stats.plain.load(Ordering::SeqCst);
    let connections = stats.connections.load(Ordering::SeqCst);
    engine.shutdown();
    eprintln!("route check storm: {plain} route checks and {connections} connections in {elapsed:?}");
    assert!(plain <= 10, "{plain} route checks and {connections} connections in {elapsed:?}");
}

/// A captive portal answers every POST with 404 while the session still has to make its key: the
/// handshake must back off like any refused route, not reconnect once per round trip.
#[test]
fn a_captive_portal_404_during_the_handshake_backs_off() {
    let server = TestServer::start(vec![], ServerOptions::default());
    let (port, stats) =
        middlebox::start(server.address, Arc::new(|_info: Info| Action::Respond(404, b"<html>log in</html>".to_vec())));
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.key_generation = Some(mtproto_engine::KeyGeneration {
        temporary_expires_in: None,
        public_keys: vec![
            mtproto_engine::mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key(),
        ],
    });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) && stats.plain.load(Ordering::SeqCst) < 200 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = started.elapsed();
    let plain = stats.plain.load(Ordering::SeqCst);
    let connections = stats.connections.load(Ordering::SeqCst);
    let failures = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, event)| matches!(event, EngineEvent::AuthKeyCreationFailed { .. }))
        .count();
    engine.shutdown();
    eprintln!(
        "handshake behind 404: {plain} handshake requests, {connections} connections, {failures} failure events in {elapsed:?}"
    );
    assert!(plain <= 10, "{plain} handshake requests and {connections} connections in {elapsed:?}");
}

/// Two pipelined requests answered with 429 in one read: the second one's queries must still go
/// again; its response was parsed before the first one failed the connection.
#[test]
fn a_pipelined_request_behind_a_refused_one_is_not_forgotten() {
    let key = random_key(905);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (port, paired) = middlebox::start_pipeline_flood(server.address);
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let session = engine.create_session(setup(port, &key));
    let mut id = 0u64;
    let mut stuck = None;
    for _ in 0..20 {
        id += 1;
        engine.send(session, request(id, id as u32));
        if !collector.wait(Duration::from_secs(20), |events| completions(events) == id as usize) {
            stuck = Some(id);
            break;
        }
        std::thread::sleep(Duration::from_millis(60));
        if paired.load(Ordering::SeqCst) {
            id += 1;
            engine.send(session, request(id, id as u32));
            if !collector.wait(Duration::from_secs(20), |events| completions(events) == id as usize) {
                stuck = Some(id);
            }
            break;
        }
    }
    let was_paired = paired.load(Ordering::SeqCst);
    engine.shutdown();
    eprintln!("pipelined pair: paired {was_paired}, stuck {stuck:?}, sent {id}");
    assert!(
        stuck.is_none(),
        "request {stuck:?} never completed after a pipelined pair was refused (paired: {was_paired})"
    );
}

fn trickling_server(chunk: &'static [u8]) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                if client.read(&mut buffer).unwrap_or(0) == 0 {
                    return;
                }
                if client.write_all(b"HTTP/1.1 ").is_err() {
                    return;
                }
                while client.write_all(chunk).is_ok() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
        }
    });
    port
}

/// A middlebox that trickles a response head, or sends 1xx responses forever, keeps showing progress
/// but never answers: the request is given up on all the same.
#[test]
fn a_response_head_that_never_ends_is_given_up_on() {
    for chunk in [&b"X"[..], &b"100 Continue\r\n\r\nHTTP/1.1 "[..]] {
        let key = random_key(906);
        let port = trickling_server(chunk);
        let collector = Arc::new(Collector::default());
        let engine =
            Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
        let session = engine.create_session(setup(port, &key));
        engine.send(session, request(1, 1));
        let started = Instant::now();
        let dropped = collector.wait(Duration::from_secs(40), |events| {
            events.iter().any(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
        });
        let took = started.elapsed();
        engine.shutdown();
        assert!(dropped, "a head trickling {:?} was never given up on", String::from_utf8_lossy(chunk));
        assert!(took < Duration::from_secs(30), "given up on after {took:?}");
    }
}
