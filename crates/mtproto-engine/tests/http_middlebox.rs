//! HTTP behind middleboxes that replay, refuse, cut, empty or corrupt answers: the session backs off and never spins.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    condvar: Condvar,
    long_polls: AtomicUsize,
    sends: AtomicUsize,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event));
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if message.contains("HTTP long poll packet") {
            self.long_polls.fetch_add(1, Ordering::Relaxed);
        } else if message.contains("HTTP send packet") {
            self.sends.fetch_add(1, Ordering::Relaxed);
        }
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("{:?} LOG {message}", Instant::now());
        }
    }
}

#[allow(unsafe_code)]
fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 * 1e-6;
    tv(usage.ru_utime) + tv(usage.ru_stime)
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

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, event)| predicate(event)).count()
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

fn setup_to(port: u16, key: &AuthKey, transport: TransportPreference) -> SessionSetup {
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = transport;
    setup.http_port = None;
    setup
}

/// What the middlebox does with each POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Relays it to the server and the answer back.
    Forward,
    /// Answers every encrypted POST at once with a copy of the last encrypted answer it relayed.
    ReplayLast,
    /// Relays plain (handshake / route-check) POSTs; answers encrypted ones with this status.
    StatusForEncrypted(u16),
    /// Answers every POST with this status and an HTML page.
    StatusForAll(u16),
    /// Answers every POST with an empty 200.
    Empty200,
    /// Reads the POST and closes the connection without an answer.
    CloseAfterRequest,
    /// Relays everything, flipping a byte of every encrypted answer (a "content optimizer").
    CorruptEncrypted,
}

struct Middlebox {
    port: u16,
    mode: Arc<Mutex<Mode>>,
    requests: Arc<AtomicUsize>,
    encrypted_requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    last_encrypted_answer: Arc<Mutex<Option<Vec<u8>>>>,
}

fn read_message(stream: &mut TcpStream, seen: &mut Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buffer = vec![0u8; 65536];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if seen.len() >= end + 4 + length {
                let head = seen[..end + 4].to_vec();
                let body = seen[end + 4..end + 4 + length].to_vec();
                seen.drain(..end + 4 + length);
                return Some((head, body));
            }
        }
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        seen.extend_from_slice(&buffer[..read]);
    }
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

impl Middlebox {
    fn start(upstream: Option<std::net::SocketAddr>, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = Arc::new(Mutex::new(mode));
        let requests = Arc::new(AtomicUsize::new(0));
        let encrypted_requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let last_encrypted_answer = Arc::new(Mutex::new(None));
        let shared = (
            mode.clone(),
            requests.clone(),
            encrypted_requests.clone(),
            connections.clone(),
            last_encrypted_answer.clone(),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { continue };
                let (mode, requests, encrypted_requests, connections, last) = shared.clone();
                connections.fetch_add(1, Ordering::Relaxed);
                std::thread::spawn(move || {
                    let mut seen = Vec::new();
                    let mut upstream_conn: Option<(TcpStream, Vec<u8>)> = None;
                    loop {
                        let Some((head, body)) = read_message(&mut client, &mut seen) else { return };
                        requests.fetch_add(1, Ordering::Relaxed);
                        let encrypted = body.len() >= 8 && body[..8] != [0u8; 8];
                        if encrypted {
                            encrypted_requests.fetch_add(1, Ordering::Relaxed);
                        }
                        let current = *mode.lock().unwrap();
                        let forward = match current {
                            Mode::Forward | Mode::CorruptEncrypted => true,
                            Mode::StatusForEncrypted(_) => !encrypted,
                            Mode::ReplayLast => !encrypted || last.lock().unwrap().is_none(),
                            _ => false,
                        };
                        if forward {
                            let Some(upstream) = upstream else { return };
                            if upstream_conn.is_none() {
                                let Ok(conn) = TcpStream::connect(upstream) else { return };
                                upstream_conn = Some((conn, Vec::new()));
                            }
                            let (conn, buffer) = upstream_conn.as_mut().unwrap();
                            let mut message = head.clone();
                            message.extend_from_slice(&body);
                            if conn.write_all(&message).is_err() {
                                return;
                            }
                            let Some((answer_head, answer_body)) = read_message(conn, buffer) else { return };
                            if *mode.lock().unwrap() == Mode::CloseAfterRequest {
                                return;
                            }
                            if encrypted && answer_head.starts_with(b"HTTP/1.1 200") && answer_body.len() >= 8 {
                                *last.lock().unwrap() = Some(answer_body.clone());
                            }
                            let mut answer_body = answer_body;
                            if current == Mode::CorruptEncrypted
                                && answer_body.len() > 40
                                && answer_body[..8] != [0u8; 8]
                            {
                                answer_body[30] ^= 0x55;
                            }
                            let mut out = answer_head;
                            out.extend_from_slice(&answer_body);
                            if client.write_all(&out).is_err() {
                                return;
                            }
                            continue;
                        }
                        let out = match current {
                            Mode::ReplayLast => response(200, last.lock().unwrap().as_deref().unwrap_or_default()),
                            Mode::StatusForEncrypted(status) | Mode::StatusForAll(status) => {
                                let page = b"<html><body>denied</body></html>";
                                let mut out = format!(
                                    "HTTP/1.1 {status} X\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                    page.len()
                                )
                                .into_bytes();
                                out.extend_from_slice(page);
                                out
                            }
                            Mode::Empty200 => response(200, b""),
                            Mode::CloseAfterRequest => return,
                            Mode::Forward | Mode::CorruptEncrypted => unreachable!(),
                        };
                        if client.write_all(&out).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { port, mode, requests, encrypted_requests, connections, last_encrypted_answer }
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.requests.load(Ordering::Relaxed),
            self.encrypted_requests.load(Ordering::Relaxed),
            self.connections.load(Ordering::Relaxed),
        )
    }
}

/// A middlebox on the plain-HTTP path replays one captured encrypted answer to every encrypted POST.
/// The session takes each replay as an answer (the packet decrypts; it is a duplicate, so `Ok(())`),
/// clears `rejections`, and parks the next long poll at once: a request loop at round-trip rate.
#[test]
fn replayed_http_answers_do_not_make_the_long_polls_spin() {
    let key = random_key(9101);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(server.address), Mode::Forward);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(middlebox.port, &key, TransportPreference::Http);
    setup.keep_connected = true;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completions(events, session) == 1), "first call");
    assert!(middlebox.last_encrypted_answer.lock().unwrap().is_some());
    std::thread::sleep(Duration::from_secs(2));
    let idle_cpu = cpu_seconds();
    let idle_started = Instant::now();
    let idle_requests = middlebox.snapshot().0;
    std::thread::sleep(Duration::from_secs(5));
    eprintln!(
        "before the replay: {} requests and {:.2} CPU s in {:.1} s",
        middlebox.snapshot().0 - idle_requests,
        cpu_seconds() - idle_cpu,
        idle_started.elapsed().as_secs_f64()
    );
    middlebox.set_mode(Mode::ReplayLast);
    let switched = Instant::now();
    let start_requests = middlebox.snapshot().0;
    while middlebox.snapshot().0 == start_requests && switched.elapsed() < Duration::from_secs(40) {
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "first request after the switch came {:.1} s later (parked long polls run out first)",
        switched.elapsed().as_secs_f64()
    );
    std::thread::sleep(Duration::from_millis(500));
    let (before, before_encrypted, before_connections) = middlebox.snapshot();
    let (polls_before, sends_before) =
        (collector.long_polls.load(Ordering::Relaxed), collector.sends.load(Ordering::Relaxed));
    let cpu_before = cpu_seconds();
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(5));
    let (after, after_encrypted, after_connections) = middlebox.snapshot();
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "during the replay: {:.2} CPU s (whole process, middlebox threads included); engine long polls {} sends {}",
        cpu_seconds() - cpu_before,
        collector.long_polls.load(Ordering::Relaxed) - polls_before,
        collector.sends.load(Ordering::Relaxed) - sends_before
    );
    let drops = collector.count(|event| matches!(event, EngineEvent::ConnectionDropped { .. }));
    engine.shutdown();
    let rate = (after - before) as f64 / elapsed;
    eprintln!(
        "replay: {} requests ({} encrypted) on {} new connections in {elapsed:.1} s = {rate:.0} requests/s; {drops} drops",
        after - before,
        after_encrypted - before_encrypted,
        after_connections - before_connections
    );
    assert!(rate < 5.0, "{rate:.0} requests/s while every answer is a replay");
}

/// Encrypted POSTs are answered with 404 by something on the way that lets plain POSTs through (the
/// route check's req_pq gets the server's res_pq): the session concludes the key is gone.
#[test]
fn http_404_for_encrypted_posts_only_is_taken_for_a_lost_key() {
    let key = random_key(9102);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(server.address), Mode::StatusForEncrypted(404));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_to(middlebox.port, &key, TransportPreference::Http));
    engine.send(session, request(1, 1));
    let started = Instant::now();
    let invalid = collector.wait(Duration::from_secs(15), |events| {
        events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { .. }))
    });
    let (requests, encrypted, connections) = middlebox.snapshot();
    engine.shutdown();
    eprintln!(
        "404-for-encrypted: AuthKeyInvalid {invalid} after {:.1} s; {requests} requests ({encrypted} encrypted), {connections} connections",
        started.elapsed().as_secs_f64()
    );
}

/// The same middlebox, against a session that holds the RSA keys: a 404 is no proof, so the session
/// checks its key with a temporary key bound to it instead of reporting it. The middlebox 404s the
/// bind as well, so nothing completes, but the key is never reported.
#[test]
fn http_404_for_encrypted_posts_never_reports_a_key_the_session_can_check() {
    use mtproto_engine::KeyGeneration;
    use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
    let key = random_key(9105);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let middlebox = Middlebox::start(Some(server.address), Mode::StatusForEncrypted(404));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(middlebox.port, &key, TransportPreference::Http);
    setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(15));
    let reported =
        collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. } | EngineEvent::PermanentKeyInvalid));
    let (requests, encrypted, connections) = middlebox.snapshot();
    engine.shutdown();
    eprintln!("{requests} requests ({encrypted} encrypted), {connections} connections in 15 s");
    assert_eq!(reported, 0, "a 404 from the path reported the key");
}

fn steady_rate(mode: Mode, seconds: u64) -> (usize, usize, usize) {
    let key = random_key(9103);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(server.address), mode);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_to(middlebox.port, &key, TransportPreference::Http));
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(seconds));
    let snapshot = middlebox.snapshot();
    let invalid = collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. }));
    engine.shutdown();
    eprintln!("{mode:?}: {snapshot:?} (requests, encrypted, connections) in {seconds} s; AuthKeyInvalid {invalid}");
    snapshot
}

#[test]
fn http_steady_rates_against_hostile_answers() {
    let seconds = 40;
    let handles: Vec<_> = [
        Mode::StatusForAll(502),
        Mode::StatusForAll(403),
        Mode::Empty200,
        Mode::CloseAfterRequest,
        Mode::StatusForEncrypted(502),
    ]
    .into_iter()
    .map(|mode| std::thread::spawn(move || (mode, steady_rate(mode, seconds))))
    .collect();
    for handle in handles {
        let (mode, (requests, _, connections)) = handle.join().unwrap();
        eprintln!(
            "  {mode:?}: {:.2} requests/s, {:.2} connections/s",
            requests as f64 / seconds as f64,
            connections as f64 / seconds as f64
        );
        assert!(requests as f64 / seconds as f64 <= 1.5, "{mode:?}: {requests} requests in {seconds} s");
    }
}

/// A CONNECT proxy that refuses the credentials forever: how often each transport knocks.
#[test]
fn proxy_refusing_credentials_steady_rate() {
    let seconds = 40u64;
    let handles: Vec<_> = [TransportPreference::Tcp, TransportPreference::Auto, TransportPreference::Http]
        .into_iter()
        .map(|transport| {
            std::thread::spawn(move || {
                let key = random_key(9104);
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
                let mut setup = setup_to(server.address.port(), &key, transport);
                setup.addresses[0].host = "149.154.167.51".into();
                setup.addresses[0].port = 443;
                setup.http_port = Some(80);
                setup.proxy = Some(ProxyConfig::Http {
                    host: "127.0.0.1".into(),
                    port: server.address.port(),
                    username: Some("user".into()),
                    password: Some("wrong".into()),
                });
                let session = engine.create_session(setup);
                engine.send(session, request(1, 1));
                std::thread::sleep(Duration::from_secs(10));
                let early = server.with_stats(|stats| stats.proxy_refusals);
                std::thread::sleep(Duration::from_secs(seconds - 10));
                let refusals = server.with_stats(|stats| stats.proxy_refusals);
                let issues = collector.count(|event| {
                    matches!(event, EngineEvent::ConnectionState { state, .. } if state.proxy_has_connection_issues)
                });
                engine.shutdown();
                (transport, early, refusals, issues)
            })
        })
        .collect();
    for handle in handles {
        let (transport, early, refusals, issues) = handle.join().unwrap();
        eprintln!(
            "{transport:?}: {refusals} proxy refusals in {seconds} s ({early} in the first 10 s, {:.2}/s after); proxy issues reported {issues}x",
            (refusals - early) as f64 / (seconds - 10) as f64
        );
    }
}

#[test]
fn http_close_after_request_single() {
    let (requests, _, connections) = steady_rate(Mode::CloseAfterRequest, 20);
    eprintln!("close-after-request: {requests} requests on {connections} connections in 20 s");
}

/// Auto moved to HTTP because TCP was blocked, and a few TCP rechecks failed since. Then HTTP stops
/// working and TCP comes back: nothing about HTTP failing brings the recheck forward, so calls wait for
/// the doubled recheck interval (60 s doubling to 900 s in production; base 2 s here).
#[test]
fn auto_on_a_dead_http_route_waits_out_the_tcp_recheck_interval() {
    let key = random_key(9105);
    let server = TestServer::start(vec![key.clone()], ServerOptions { http_disabled: true, ..Default::default() });
    server.set_tcp_blackhole(true);
    let http_server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(http_server.address), Mode::Forward);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(server.address.port(), &key, TransportPreference::Auto);
    setup.http_port = Some(middlebox.port);
    setup.tcp_recheck_after = 2.0;
    setup.keep_connected = true;
    setup.online = true;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(
        collector.wait(Duration::from_secs(20), |events| completions(events, session) == 1),
        "first call over HTTP"
    );
    std::thread::sleep(Duration::from_secs(16));
    let (http_before, _, _) = middlebox.snapshot();
    server.set_tcp_blackhole(false);
    middlebox.set_mode(Mode::CloseAfterRequest);
    let started = Instant::now();
    engine.send(session, request(2, 2));
    let done = collector.wait(Duration::from_secs(60), |events| completions(events, session) == 2);
    let waited = started.elapsed().as_secs_f64();
    let (http_after, _, connections) = middlebox.snapshot();
    engine.shutdown();
    eprintln!(
        "HTTP dead, TCP back: second call done {done} after {waited:.1} s; {} HTTP requests meanwhile ({connections} HTTP connections overall)",
        http_after - http_before
    );
}

#[test]
fn http_corrupted_answers_rate() {
    let seconds = 30;
    let key = random_key(9106);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(server.address), Mode::CorruptEncrypted);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_to(middlebox.port, &key, TransportPreference::Http));
    for id in 1..=3u64 {
        engine.send(session, request(id, id as u32));
    }
    std::thread::sleep(Duration::from_secs(seconds));
    let (requests, encrypted, connections) = middlebox.snapshot();
    let executions = server.with_stats(|stats| stats.duplicate_executions);
    let drops = collector.count(|event| matches!(event, EngineEvent::ConnectionDropped { .. }));
    engine.shutdown();
    eprintln!(
        "corrupted answers: {requests} requests ({encrypted} encrypted) on {connections} connections in {seconds} s; {drops} drops; duplicate executions {executions}"
    );
}

/// PFS over HTTP through something that answers every encrypted POST with 404 but lets plain ones
/// (handshakes, route checks) through: how many temporary-key handshakes the engine runs.
#[test]
fn http_pfs_behind_a_404_for_encrypted_middlebox_handshake_rate() {
    use mtproto_engine::PfsSetup;
    use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
    let seconds = 30;
    let perm = random_key(9107);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let middlebox = Middlebox::start(Some(server.address), Mode::StatusForEncrypted(404));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(middlebox.port, &perm, TransportPreference::Http);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    std::thread::sleep(Duration::from_secs(seconds));
    let (requests, encrypted, connections) = middlebox.snapshot();
    let (handshakes, temporary) = server.with_stats(|stats| (stats.handshakes, stats.temporary_keys));
    let invalid =
        collector.count(|event| matches!(event, EngineEvent::AuthKeyInvalid { .. } | EngineEvent::PermanentKeyInvalid));
    let dropped = collector.count(|event| matches!(event, EngineEvent::TemporaryKeyDropped { .. }));
    engine.shutdown();
    eprintln!(
        "PFS behind 404-for-encrypted: {handshakes} handshakes ({temporary} temporary keys) in {seconds} s; {requests} requests ({encrypted} encrypted) on {connections} connections; {dropped} temporary keys dropped; key invalid events {invalid}"
    );
    assert!(temporary <= 10, "{temporary} temporary keys in {seconds} s: the lost keys are not backed off");
}

/// The same over TCP: the server loses every temporary key soon after it is made (answers -404).
#[test]
fn tcp_pfs_server_losing_every_temporary_key_handshake_rate() {
    use mtproto_engine::PfsSetup;
    use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
    let seconds = 30;
    let perm = random_key(9108);
    let server = Arc::new(TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    ));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(server.address.port(), &perm, TransportPreference::Tcp);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropper = {
        let server = server.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                server.drop_temporary_keys();
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    let started = Instant::now();
    let mut id = 2u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        engine.send(session, request(id, id as u32));
        id += 1;
        std::thread::sleep(Duration::from_millis(250));
    }
    stop.store(true, Ordering::Relaxed);
    dropper.join().unwrap();
    let done = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })))
        .count();
    let failed = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Failed { .. })))
        .count();
    eprintln!("{} calls sent, {done} completed, {failed} failed", id - 1);
    let (handshakes, temporary, connections) =
        server.with_stats(|stats| (stats.handshakes, stats.temporary_keys, stats.connections));
    let dropped = collector.count(|event| matches!(event, EngineEvent::TemporaryKeyDropped { .. }));
    engine.shutdown();
    eprintln!(
        "TCP, server loses every temporary key: {handshakes} handshakes ({temporary} temporary keys), {connections} connections in {seconds} s; {dropped} temporary keys dropped"
    );
}

fn call_latencies(
    engine: &Engine,
    collector: &Collector,
    session: SessionHandle,
    first_id: u64,
    count: u64,
) -> Vec<f64> {
    let mut latencies = Vec::new();
    for id in first_id..first_id + count {
        let before = completions(&collector.events.lock().unwrap(), session);
        let started = Instant::now();
        engine.send(session, request(id, id as u32));
        if !collector.wait(Duration::from_secs(10), |events| completions(events, session) > before) {
            latencies.push(f64::INFINITY);
            continue;
        }
        latencies.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    latencies.sort_by(f64::total_cmp);
    latencies
}

/// During the replay spin, how a TCP session sharing the worker thread fares.
#[test]
fn http_replay_spin_starves_sessions_on_the_same_worker() {
    let key = random_key(9109);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let middlebox = Middlebox::start(Some(server.address), Mode::Forward);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_to(middlebox.port, &key, TransportPreference::Http);
    setup.keep_connected = true;
    let http_session = engine.create_session(setup);
    let mut other = setup_to(server.address.port(), &key, TransportPreference::Tcp);
    other.role = SessionRole::Main;
    let tcp_session = engine.create_session(other);
    engine.send(http_session, request(1, 1));
    assert!(collector.wait(Duration::from_secs(10), |events| completions(events, http_session) == 1));
    let calm = call_latencies(&engine, &collector, tcp_session, 100, 20);
    middlebox.set_mode(Mode::ReplayLast);
    let switched = Instant::now();
    let start_requests = middlebox.snapshot().0;
    while middlebox.snapshot().0 < start_requests + 1000 && switched.elapsed() < Duration::from_secs(40) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let spinning = call_latencies(&engine, &collector, tcp_session, 200, 20);
    let rate = middlebox.snapshot().0;
    engine.shutdown();
    let summary =
        |values: &[f64]| format!("p50 {:.2} ms, max {:.2} ms", values[values.len() / 2], values[values.len() - 1]);
    eprintln!(
        "TCP calls on the same worker: calm {}; during the spin {} ({} replayed requests overall)",
        summary(&calm),
        summary(&spinning),
        rate
    );
}
