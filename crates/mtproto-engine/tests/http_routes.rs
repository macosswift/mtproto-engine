#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, ProxyConfig, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

type Upstream = (std::net::TcpStream, Vec<u8>);

mod middlebox;

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

fn completions(events: &[(SessionHandle, EngineEvent)], session: SessionHandle) -> usize {
    events
        .iter()
        .filter(|(handle, event)| *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })))
        .count()
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
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn proxy_named(server: &TestServer, host: &str) -> ProxyConfig {
    ProxyConfig::Http { host: host.into(), port: server.address.port(), username: None, password: None }
}

/// HTTP transport through an HTTP proxy given by name, as users type them. The control run with the
/// same proxy as an IP literal completes at once.
#[test]
fn http_through_a_proxy_given_by_host_name() {
    for host in ["127.0.0.1", "localhost"] {
        let key = random_key(6001);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions { http_proxy: Some(HttpProxyMode::ForwardOnly), ..Default::default() },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = http_setup(&server, &key, SessionRole::Main);
        setup.proxy = Some(proxy_named(&server, host));
        setup.addresses[0].host = "149.154.167.51".into();
        setup.http_port = Some(80);
        let session = engine.create_session(setup);
        for id in 1..=3 {
            engine.send(session, request(id, id as u32));
        }
        let done = collector.wait(Duration::from_secs(10), |events| completions(events, session) == 3);
        let http_requests = server.with_stats(|stats| stats.http.requests);
        engine.shutdown();
        assert!(done, "proxy {host}: {http_requests} HTTP requests reached the proxy in 10 s");
    }
}

/// HTTP transport straight to a datacenter address given by name.
#[test]
fn http_to_a_datacenter_address_given_by_host_name() {
    let key = random_key(6002);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.addresses[0].host = "localhost".into();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let done = collector.wait(Duration::from_secs(10), |events| completions(events, session) == 1);
    let http_requests = server.with_stats(|stats| stats.http.requests);
    engine.shutdown();
    assert!(done, "{http_requests} HTTP requests in 10 s");
}

/// Answers every POST with `status` and `body`, as captive portals and proxy pages do.
fn start_portal(status: &'static str, body: &'static [u8]) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let counter = counter.clone();
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                let mut seen = Vec::new();
                loop {
                    let Ok(read) = stream.read(&mut buffer) else { return };
                    if read == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buffer[..read]);
                    while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&seen[..end]).to_string();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if seen.len() < end + 4 + length {
                            break;
                        }
                        seen.drain(..end + 4 + length);
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let head = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body);
                    }
                }
            });
        }
    });
    (port, requests)
}

/// A captive portal (or a proxy's block page) that answers every POST with 200 and its login page.
/// The 404 variant is bounded by the route check; a 200 page is taken for a delivered, empty answer.
#[test]
fn a_captive_portal_answering_200_is_not_hammered() {
    let mut results = Vec::new();
    for (status, body) in
        [("200 OK", &b"<html><body>Please log in to the hotel Wi-Fi</body></html>"[..]), ("200 OK", &b""[..])]
    {
        let (port, requests) = start_portal(status, body);
        let key = random_key(6004);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        setup.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
        setup.transport = TransportPreference::Http;
        setup.http_port = None;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(1));
        let before = cpu_seconds();
        let counted = requests.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(5));
        let cpu = (cpu_seconds() - before) / 5.0;
        let sent = requests.load(std::sync::atomic::Ordering::Relaxed) - counted;
        engine.shutdown();
        eprintln!("portal {status} with {} body bytes: {sent} requests in 5 s, {cpu:.2} cores", body.len());
        results.push((status, body.len(), sent));
    }
    for (status, bytes, sent) in results {
        assert!(sent <= 30, "portal {status} ({bytes} bytes): {sent} requests in 5 s");
    }
}

/// HTTP transport through an HTTP proxy that refuses the credentials: the host is never told the proxy
/// has issues (the TCP-through-CONNECT variant reports it, `wrong_proxy_credentials_back_off...`).
#[test]
fn http_through_a_proxy_refusing_credentials_reports_proxy_issues() {
    let key = random_key(6005);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            http_proxy: Some(HttpProxyMode::Both),
            http_proxy_credentials: Some("user:secret".into()),
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.proxy = Some(ProxyConfig::Http {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some("wrong".into()),
    });
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(8));
    let refusals = server.with_stats(|stats| stats.proxy_refusals);
    let states: Vec<_> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::ConnectionState { state, .. } => Some(*state),
            _ => None,
        })
        .collect();
    engine.shutdown();
    eprintln!("refusals {refusals}; states {states:?}");
    assert!(refusals >= 1);
    assert!(
        states.iter().any(|state| state.proxy_has_connection_issues),
        "{refusals} refusals in 8 s and never proxy_has_connection_issues"
    );
}

/// TCP only, through an HTTP proxy that refuses CONNECT: the same proxy given by IP and by name.
#[test]
fn tcp_through_a_refusing_proxy_backs_off_whether_given_by_ip_or_name() {
    let mut results = Vec::new();
    for host in ["127.0.0.1", "localhost"] {
        let key = random_key(6006);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions { http_proxy: Some(HttpProxyMode::ForwardOnly), ..Default::default() },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = http_setup(&server, &key, SessionRole::Main);
        setup.transport = TransportPreference::Tcp;
        setup.proxy = Some(proxy_named(&server, host));
        setup.addresses[0].host = "149.154.167.51".into();
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(1));
        let before = cpu_seconds();
        let refused_before = server.with_stats(|stats| stats.proxy_refusals);
        std::thread::sleep(Duration::from_secs(5));
        let cpu = (cpu_seconds() - before) / 5.0;
        let refusals = server.with_stats(|stats| stats.proxy_refusals) - refused_before;
        engine.shutdown();
        eprintln!("proxy {host}: {refusals} CONNECT refusals in 5 s, {cpu:.2} cores");
        results.push((host, refusals, cpu));
    }
    for (host, refusals, _) in results {
        assert!(refusals <= 25, "proxy {host}: {refusals} CONNECT attempts in 5 s");
    }
}

/// Accepts connections, reads one request and closes, as DPI boxes that cut a flow once they see the
/// request do. Counts connections.
fn start_cutter() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = connections.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                let mut seen = Vec::new();
                loop {
                    let Ok(read) = stream.read(&mut buffer) else { return };
                    if read == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buffer[..read]);
                    if seen.windows(4).any(|window| window == b"\r\n\r\n") {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
            });
        }
    });
    (port, connections)
}

/// Every HTTP request is cut right after it is sent. The TCP transport backs off to one attempt a
/// second; HTTP resets its open backoff whenever a TCP handshake completes.
#[test]
fn http_requests_cut_by_a_middlebox_back_off() {
    let mut results = Vec::new();
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let (port, connections) = start_cutter();
        let key = random_key(6007);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        setup.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
        setup.transport = transport;
        setup.http_port = None;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(3));
        let counted = connections.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(5));
        let opened = connections.load(std::sync::atomic::Ordering::Relaxed) - counted;
        engine.shutdown();
        eprintln!("{transport:?}: {opened} connections in 5 s");
        results.push((transport, opened));
    }
    for (transport, opened) in results {
        assert!(opened <= 6, "{transport:?}: {opened} connections in 5 s");
    }
}

fn read_http_message(stream: &mut std::net::TcpStream, buffer: &mut Vec<u8>) -> Option<(String, Vec<u8>)> {
    use std::io::Read;
    let mut scratch = vec![0u8; 65536];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                let body = buffer[end + 4..end + 4 + length].to_vec();
                buffer.drain(..end + 4 + length);
                return Some((head, body));
            }
        }
        let read = stream.read(&mut scratch).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
}

/// A route without keep-alive, as HTTP/1.0 proxies: every response says `Connection: close` and the
/// connection ends after it. Upstream it keeps one connection to the server, so the server's
/// handshake state is kept as the real servers keep it (by nonce, whatever the connection).
fn start_closing_route(upstream: std::net::SocketAddr, close: bool) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = requests.clone();
    let shared: Arc<Mutex<Option<Upstream>>> = Arc::new(Mutex::new(None));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            let counter = counter.clone();
            let shared = shared.clone();
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                loop {
                    let Some((head, body)) = read_http_message(&mut client, &mut buffer) else { return };
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let response = {
                        let mut guard = shared.lock().unwrap();
                        if guard.is_none() {
                            let Ok(stream) = std::net::TcpStream::connect(upstream) else { return };
                            *guard = Some((stream, Vec::new()));
                        }
                        let (up, up_buffer) = guard.as_mut().unwrap();
                        let mut out = format!("{head}\r\n\r\n").into_bytes();
                        out.extend_from_slice(&body);
                        if up.write_all(&out).is_err() {
                            *guard = None;
                            return;
                        }
                        let Some(response) = read_http_message(up, up_buffer) else {
                            *guard = None;
                            return;
                        };
                        response
                    };
                    let (head, body) = response;
                    let head = if close { head.replace("Connection: keep-alive", "Connection: close") } else { head };
                    let mut out = format!("{head}\r\n\r\n").into_bytes();
                    out.extend_from_slice(&body);
                    let _ = client.write_all(&out);
                    if close {
                        let _ = client.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
            });
        }
    });
    (port, requests)
}

/// The auth key made over HTTP through a route that closes every connection after its response.
#[test]
fn the_auth_key_is_created_over_http_without_keep_alive() {
    let mut results = Vec::new();
    for close in [false, true] {
        let server = TestServer::start(
            Vec::new(),
            ServerOptions {
                handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                    server_time: unix_seconds() as i32,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let (port, requests) = start_closing_route(server.address, close);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut generated =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        generated.transport = TransportPreference::Http;
        generated.http_port = None;
        generated.key_generation = Some(mtproto_engine::KeyGeneration {
            public_keys: vec![
                mtproto_engine::mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key(),
            ],
            temporary_expires_in: None,
        });
        let session = engine.create_session(generated);
        engine.send(session, request(1, 9));
        let done = collector.wait(Duration::from_secs(20), |events| completions(events, session) == 1);
        let created = collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::AuthKeyCreated { .. }))
            .count();
        let handshakes = server.with_stats(|stats| stats.handshakes);
        let sent = requests.load(std::sync::atomic::Ordering::Relaxed);
        engine.shutdown();
        eprintln!(
            "close {close}: call done {done}, keys created {created}, server handshakes {handshakes}, requests through the route {sent}"
        );
        results.push((close, created, done, sent));
    }
    for (close, created, done, sent) in results {
        assert!(created == 1 && done, "close {close}: no key ({sent} requests through the route)");
    }
}

/// The host says the network is unavailable and the datacenter is unreachable (refused): TCP tries
/// once every 30 s. Counts connection drops (one per failed attempt) over 75 s.
fn offline_attempts(transport: TransportPreference) -> usize {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let key = random_key(6008);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    engine.set_network_available(false);
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
    setup.transport = transport;
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let count = || {
        collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
            .count()
    };
    let mut samples = Vec::new();
    for _ in 0..12 {
        std::thread::sleep(Duration::from_secs(10));
        samples.push(count());
    }
    eprintln!("{transport:?}: drops every 10 s: {samples:?}");
    let drops = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
        .count();
    engine.shutdown();
    eprintln!("{transport:?}: {drops} failed attempts in 120 s while the network is marked unavailable");
    drops
}

#[test]
fn offline_tcp_attempts() {
    assert!(offline_attempts(TransportPreference::Tcp) <= 5);
}

#[test]
fn offline_http_attempts() {
    let attempts = offline_attempts(TransportPreference::Http);
    assert!(attempts <= 5, "{attempts} attempts in 120 s while offline");
}

/// HTTP through a proxy that refuses the credentials backs off; the user then fixes the credentials.
/// TCP starts over at once after `set_proxy`; HTTP keeps waiting out the old refusal backoff.
#[test]
fn fixed_proxy_credentials_take_effect_at_once_over_http() {
    let mut results = Vec::new();
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let key = random_key(6009);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions {
                http_proxy: Some(HttpProxyMode::Both),
                http_proxy_credentials: Some("user:secret".into()),
                ..Default::default()
            },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let proxy = |password: &str| ProxyConfig::Http {
            host: "127.0.0.1".into(),
            port: server.address.port(),
            username: Some("user".into()),
            password: Some(password.into()),
        };
        let mut setup = http_setup(&server, &key, SessionRole::Main);
        setup.transport = transport;
        setup.proxy = Some(proxy("wrong"));
        setup.addresses[0].host = "149.154.167.51".into();
        setup.http_port = Some(80);
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(20));
        let refusals = server.with_stats(|stats| stats.proxy_refusals);
        engine.set_proxy(session, Some(proxy("secret")));
        let fixed = Instant::now();
        let done = collector.wait(Duration::from_secs(30), |events| completions(events, session) == 1);
        let took = fixed.elapsed();
        engine.shutdown();
        eprintln!("{transport:?}: {refusals} refusals in 20 s; after the fix the call took {took:?} (done {done})");
        results.push((transport, took));
    }
    for (transport, took) in results {
        assert!(took < Duration::from_secs(3), "{transport:?}: {took:?} after the credentials were fixed");
    }
}

/// Auto, on HTTP because TCP gets nowhere (the middlebox speaks only HTTP), then the Wi-Fi's portal
/// starts answering every POST with 200 and its login page, without the host noticing a new network.
#[test]
fn auto_on_http_behind_a_portal_that_starts_answering_200() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let key = random_key(6010);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let portal = Arc::new(AtomicBool::new(false));
    let answered = Arc::new(AtomicUsize::new(0));
    let (port, _stats) = {
        let portal = portal.clone();
        let answered = answered.clone();
        middlebox::start(
            server.address,
            Arc::new(move |_info: middlebox::Info| {
                if portal.load(Ordering::SeqCst) {
                    answered.fetch_add(1, Ordering::SeqCst);
                    middlebox::Action::Respond(200, b"<html>Please log in</html>".to_vec())
                } else {
                    middlebox::Action::Forward
                }
            }),
        )
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
    setup.transport = TransportPreference::Auto;
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events, session) == 1), "on HTTP");
    portal.store(true, Ordering::SeqCst);
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(5));
    let before = cpu_seconds();
    let counted = answered.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(5));
    let cpu = (cpu_seconds() - before) / 5.0;
    let sent = answered.load(Ordering::SeqCst) - counted;
    engine.shutdown();
    eprintln!("auto on HTTP behind a 200 portal: {sent} requests in 5 s, {cpu:.2} cores");
    assert!(sent <= 30, "{sent} requests in 5 s");
}

/// HTTP_ONLINE_SLOT_WAIT says two staggered long polls answer at least every 5 s on the online main
/// session. Records when the quiet session's requests reach the server.
#[test]
fn online_long_polls_are_staggered() {
    let key = random_key(6011);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let started = Instant::now();
    let times = Arc::new(Mutex::new(Vec::<f64>::new()));
    let (port, _stats) = {
        let times = times.clone();
        middlebox::start(
            server.address,
            Arc::new(move |info: middlebox::Info| {
                if !info.plain {
                    times.lock().unwrap().push(started.elapsed().as_secs_f64());
                }
                middlebox::Action::Forward
            }),
        )
    };
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial { key, salts: salts(), init_hash: None });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.online = true;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completions(events, session) == 1));
    std::thread::sleep(Duration::from_secs(45));
    engine.shutdown();
    let times = times.lock().unwrap().clone();
    let quiet: Vec<f64> = times.iter().copied().filter(|time| *time > 15.0).collect();
    let gaps: Vec<f64> = quiet.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let rounded: Vec<String> = quiet.iter().map(|time| format!("{time:.2}")).collect();
    eprintln!("requests after 15 s: {rounded:?}");
    let longest = gaps.iter().copied().fold(0.0, f64::max);
    assert!(longest < 7.0, "a quiet online session goes {longest:.1} s without a request: {rounded:?}");
}
