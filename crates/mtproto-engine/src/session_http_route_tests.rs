use super::*;
use crate::types::TransportPreference;
use mtproto_core::auth_key::AuthKey;
use mtproto_core::rpc::{RequestFlags, RpcRequest};

struct Null;

impl EngineCallbacks for Null {
    fn on_event(&self, _session: SessionHandle, _event: EngineEvent) {}
}

struct NoLookups;

impl Resolve for NoLookups {
    fn resolve(&mut self, _session: SessionHandle, host: &str, _port: u16) -> Resolution {
        panic!("looked up {host}");
    }
}

/// The user had an HTTP proxy whose name is still being looked up (a slow DNS failure), and moved to
/// another proxy given by address. The old lookup then fails: the session no longer uses that name,
/// so the new route must not wait for it.
#[test]
fn a_failed_lookup_for_a_name_no_longer_used_does_not_hold_back_the_new_route() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let poll = mio::Poll::new().unwrap();
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "149.154.167.51".into(), port: 443, secret: None }],
    );
    setup.transport = TransportPreference::Http;
    setup.http_port = Some(80);
    setup.proxy =
        Some(ProxyConfig::Http { host: "127.0.0.1".into(), port: proxy_port, username: None, password: None });
    setup.auth_key = Some(AuthKeyMaterial {
        key: AuthKey::new([7u8; 256]),
        salts: vec![ServerSalt { salt: 1, valid_since: start.unix - 60.0, valid_until: start.unix + 3600.0 }],
        init_hash: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(
        RpcRequest {
            id: mtproto_core::rpc::RequestId(1),
            body: vec![1, 2, 3, 4, 5, 6, 7, 8],
            flags: RequestFlags::default(),
            invoke_after: None,
        },
        start,
    );
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    let config = EngineConfig::default();
    runtime.on_resolved("old-proxy.example", 3128, Vec::new(), start);
    eprintln!(
        "after the old name's lookup failed: open failures {}, failures {}",
        runtime.open_failures(),
        runtime.failures
    );
    runtime.drive(poll.registry(), start, &mut NoLookups, &config, &callbacks, &mut rng);
    let opened = runtime.http.as_ref().map_or(0, |http| http.conns.len());
    runtime.shutdown(poll.registry(), start);
    assert_eq!(opened, 1, "the new route opened no connection: it waits out the old name's failed lookup");
}

fn read_http_message(stream: &mut std::net::TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
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
                return Some(buffer.drain(..end + 4 + length).collect());
            }
        }
        let read = stream.read(&mut scratch).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
}

/// Each connection carries one request to the server and is closed after its response.
fn one_shot_route(upstream: SocketAddr) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = served.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            let counter = counter.clone();
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let Some(request) = read_http_message(&mut client, &mut buffer) else { return };
                let Ok(mut up) = std::net::TcpStream::connect(upstream) else { return };
                if up.write_all(&request).is_err() {
                    return;
                }
                let mut up_buffer = Vec::new();
                let Some(response) = read_http_message(&mut up, &mut up_buffer) else { return };
                let _ = client.write_all(&response);
                let _ = client.shutdown(std::net::Shutdown::Both);
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });
    (port, served)
}

/// A session with no key yet, marked offline: its HTTP probe reaches a route that closes each
/// connection after the response, so the key handshake's first step is answered and the probe is
/// over. Simulated time runs on to the next probe: counts the turns that ask to be driven at once.
#[test]
fn a_handshake_left_between_steps_by_an_offline_probe_does_not_spin() {
    use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
    use mtproto_testserver::{ServerOptions, TestServer};
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let (port, served) = one_shot_route(server.address);
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.key_generation = Some(crate::types::KeyGeneration {
        public_keys: vec![ServerHandshake::new(Default::default()).public_key()],
        temporary_expires_in: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.set_network_available(false, start, poll.registry());
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    let config = EngineConfig::default();
    let mut resolver = NoLookups;
    let probe = Now { mono: start.mono + UNAVAILABLE_PROBE_INTERVAL, unix: start.unix + UNAVAILABLE_PROBE_INTERVAL };
    let mut answered = false;
    let real = std::time::Instant::now();
    while !answered && real.elapsed() < std::time::Duration::from_secs(5) {
        poll.poll(&mut events, Some(std::time::Duration::from_millis(5))).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                probe,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), probe, &mut resolver, &config, &callbacks, &mut rng);
        answered = served.load(std::sync::atomic::Ordering::SeqCst) >= 1
            && runtime.http.as_ref().is_some_and(|http| http.conns.is_empty());
    }
    assert!(answered, "the probe's handshake never got its first answer");
    eprintln!("first step answered and the connection closed; handshake kept {}", runtime.handshake.is_some());
    let mut immediate = 0usize;
    let mut first = None;
    let mut elapsed = 0.0;
    while elapsed < UNAVAILABLE_PROBE_INTERVAL - 1.0 {
        let now = Now { mono: probe.mono + elapsed, unix: probe.unix + elapsed };
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        if runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
            immediate += 1;
            first.get_or_insert(elapsed);
        }
        elapsed += 0.5;
    }
    eprintln!(
        "{immediate} of {} turns asked to be driven at once (first {first:?} s after the probe); handshake kept {}",
        ((UNAVAILABLE_PROBE_INTERVAL - 1.0) / 0.5) as usize,
        runtime.handshake.is_some()
    );
    runtime.shutdown(poll.registry(), probe);
    assert!(immediate < 3, "{immediate} turns asked to be driven at once, first {first:?} s after the probe");
}

struct Fixed(Vec<std::net::SocketAddr>);

impl Resolve for Fixed {
    fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
        Resolution::Resolved(self.0.clone())
    }
}

/// A front may answer the WebSocket probe and still cut every session's connection: the probe backoff
/// earned before the adoption has to outlast it until the WebSocket carries the session, or such a
/// front is probed and adopted every 5 s for good.
#[test]
fn an_adopted_websocket_keeps_the_probe_backoff_until_it_carries_the_session() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: address.port(), secret: None }],
    );
    setup.transport = TransportPreference::Auto;
    setup.http_port = None;
    setup.web = Some(crate::types::WebEndpoint {
        host: "venus.web.telegram.org".into(),
        port: 443,
        path: "/apiw1".into(),
        ws_path: "/apiws".into(),
        address: None,
    });
    setup.auth_key = Some(AuthKeyMaterial {
        key: AuthKey::new([7u8; 256]),
        salts: vec![ServerSalt { salt: 1, valid_since: start.unix - 60.0, valid_until: start.unix + 3600.0 }],
        init_hash: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(
        RpcRequest {
            id: mtproto_core::rpc::RequestId(1),
            body: vec![1, 2, 3, 4, 5, 6, 7, 8],
            flags: RequestFlags::default(),
            invoke_after: None,
        },
        start,
    );
    for _ in 0..3 {
        runtime.note_probes_failed(start);
    }
    let token = runtime.probe_token(http::ProbeKind::WebSocket);
    let transport =
        TransportConfig { framing: runtime.setup.framing, dc_id: 2, secret: None, unix_time: start.unix as i32 };
    let connection = Connection::connect(registry, token, address, &transport, None, 0, start.mono, &mut rng).unwrap();
    runtime.auto.probes.push(http::Probe::new(
        http::ProbeKind::WebSocket,
        http::ProbeLink::Stream(Box::new(connection)),
        [0u8; 16],
        start.mono,
    ));
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    runtime.adopt_websocket_probe(token, registry, start, &callbacks, &mut rng);
    let adopted = runtime.auto.describe(start.mono);
    assert!(adopted.contains("probe_failures 3"), "{adopted}");
    let now = Now { mono: start.mono + 0.01, unix: start.unix + 0.01 };
    runtime.drive(registry, now, &mut Fixed(vec![address]), &EngineConfig::default(), &callbacks, &mut rng);
    let driven = runtime.auto.describe(now.mono);
    assert!(driven.contains("on_websocket true"), "{driven}");
    assert!(
        driven.contains("probe_failures 3"),
        "the backoff was gone before the WebSocket carried anything: {driven}"
    );
}
