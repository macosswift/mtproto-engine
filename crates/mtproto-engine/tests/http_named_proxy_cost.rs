//! Its own test binary, so that the process's CPU time measures nothing but this engine.
#![allow(dead_code)]
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

/// Auto behind a corporate proxy that refuses CONNECT and is given by name: TCP fails, the HTTP probe
/// has to resolve the proxy's name, which never comes back resolved, and the auto deadline is in the past.
#[test]
fn auto_probe_through_a_named_proxy_neither_spins_nor_stalls() {
    let key = random_key(6003);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions { http_proxy: Some(HttpProxyMode::ForwardOnly), ..Default::default() },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = http_setup(&server, &key, SessionRole::Main);
    setup.transport = TransportPreference::Auto;
    setup.proxy = Some(proxy_named(&server, "localhost"));
    setup.addresses[0].host = "149.154.167.51".into();
    setup.http_port = Some(80);
    let before = cpu_seconds();
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(6));
    let cpu = (cpu_seconds() - before) / 6.0;
    let done = collector.wait(Duration::from_secs(4), |events| completions(events, session) == 1);
    let refusals = server.with_stats(|stats| stats.proxy_refusals);
    let http_requests = server.with_stats(|stats| stats.http.requests);
    engine.shutdown();
    eprintln!("done {done}, cpu {cpu:.2} cores, refusals {refusals}, http requests {http_requests}");
    assert!(cpu < 0.2, "{cpu:.2} cores while the probe waits for a name");
    assert!(done, "never reached HTTP through the named proxy");
}
