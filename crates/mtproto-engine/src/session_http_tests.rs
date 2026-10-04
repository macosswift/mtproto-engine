use super::*;
use crate::types::TransportPreference;
use mtproto_core::auth_key::AuthKey;
use mtproto_core::rpc::{RequestFlags, RpcEvent, RpcRequest};

struct Null;

impl EngineCallbacks for Null {
    fn on_event(&self, _session: SessionHandle, _event: EngineEvent) {}
}

/// As `ThreadResolver`: every lookup is asynchronous and nothing is cached once delivered.
struct AsyncResolver {
    calls: usize,
}

impl Resolve for AsyncResolver {
    fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
        self.calls += 1;
        Resolution::Pending
    }
}

/// Answers every lookup at once with the same list, in the same order, as a resolver would.
struct FixedResolver {
    addresses: Vec<SocketAddr>,
    calls: usize,
}

impl Resolve for FixedResolver {
    fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
        self.calls += 1;
        Resolution::Resolved(self.addresses.clone())
    }
}

fn runtime(host: &str, port: u16, transport: TransportPreference, start: Now, rng: &mut OsRandom) -> SessionRuntime {
    let mut setup = SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: host.into(), port, secret: None }]);
    setup.transport = transport;
    setup.http_port = None;
    setup.auth_key = Some(AuthKeyMaterial {
        key: AuthKey::new([7u8; 256]),
        salts: vec![ServerSalt { salt: 1, valid_since: start.unix - 60.0, valid_until: start.unix + 3600.0 }],
        init_hash: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, rng);
    runtime.send(
        RpcRequest {
            id: mtproto_core::rpc::RequestId(1),
            body: vec![1, 2, 3, 4, 5, 6, 7, 8],
            flags: RequestFlags::default(),
            invoke_after: None,
        },
        start,
    );
    runtime
}

/// A host name that does not resolve (NXDOMAIN, or no DNS at all): counts lookups in 120 s. Every
/// lookup answers at once with nothing, as the resolver thread does.
fn failing_lookups(transport: TransportPreference, offline: bool) -> usize {
    let poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut runtime = runtime("dc.invalid", 443, transport, start, &mut rng);
    if offline {
        runtime.set_network_available(false, start, registry);
    }
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    let config = EngineConfig::default();
    let mut resolver = AsyncResolver { calls: 0 };
    let mut delivered = 0;
    let mut elapsed = 0.0;
    while elapsed < 120.0 {
        let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
        runtime.drive(registry, now, &mut resolver, &config, &callbacks, &mut rng);
        if resolver.calls > delivered {
            delivered = resolver.calls;
            let later = Now { mono: now.mono + 0.01, unix: now.unix + 0.01 };
            runtime.on_resolved("dc.invalid", 443, Vec::new(), later);
        }
        elapsed += 0.01;
    }
    runtime.shutdown(registry, Now { mono: start.mono + elapsed, unix: start.unix + elapsed });
    resolver.calls
}

#[test]
fn a_name_that_does_not_resolve_is_looked_up_with_backoff() {
    let tcp = failing_lookups(TransportPreference::Tcp, false);
    let http = failing_lookups(TransportPreference::Http, false);
    let tcp_offline = failing_lookups(TransportPreference::Tcp, true);
    let http_offline = failing_lookups(TransportPreference::Http, true);
    eprintln!("lookups in 120 s: TCP {tcp}, HTTP {http}; offline: TCP {tcp_offline}, HTTP {http_offline}");
    assert!(http <= tcp * 2 + 5, "HTTP looked the name up {http} times in 120 s (TCP {tcp})");
    assert!(http_offline <= 6, "offline, HTTP looked the name up {http_offline} times in 120 s (TCP {tcp_offline})");
}

/// A name with two addresses, the first refusing connections. Simulated 120 s: does any attempt reach
/// the second?
fn reaches_second_address(transport: TransportPreference, dead_first: bool) -> (bool, usize) {
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let live = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    live.set_nonblocking(true).unwrap();
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut runtime = runtime("dc.example", 443, transport, start, &mut rng);
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    let config = EngineConfig::default();
    let addresses =
        if dead_first { vec![dead, live.local_addr().unwrap()] } else { vec![live.local_addr().unwrap(), dead] };
    let mut resolver = FixedResolver { addresses, calls: 0 };
    let mut elapsed = 0.0;
    let mut reached = false;
    while elapsed < 120.0 && !reached {
        let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
        poll.poll(&mut events, Some(std::time::Duration::from_millis(1))).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        reached = live.accept().is_ok();
        elapsed += 0.05;
    }
    runtime.shutdown(poll.registry(), Now { mono: start.mono + elapsed, unix: start.unix + elapsed });
    (reached, resolver.calls)
}

#[test]
fn a_dead_first_address_of_a_name_is_not_tried_forever() {
    let (sanity, _) = reaches_second_address(TransportPreference::Http, false);
    assert!(sanity, "control: HTTP never reached a live first address");
    let (tcp, tcp_lookups) = reaches_second_address(TransportPreference::Tcp, true);
    let (http, http_lookups) = reaches_second_address(TransportPreference::Http, true);
    eprintln!("second address reached: TCP {tcp} ({tcp_lookups} lookups), HTTP {http} ({http_lookups} lookups)");
    assert!(tcp, "control: TCP never tried the second address");
    assert!(http, "HTTP kept connecting to the dead first address for 120 s");
}

/// A worker session on HTTP ran a call (here: cancelled, the endpoint never answers) and went idle.
/// Its connections go (closed idle, or failed); it then wants no link. Simulated time runs past its
/// salt's change time, as it does every half hour in production: counts the turns in which the
/// session asks to be driven again at once although driving it changes nothing.
#[test]
fn an_idle_http_session_without_connections_does_not_ask_to_be_driven_at_once() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }],
    );
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.auth_key = Some(AuthKeyMaterial {
        key: AuthKey::new([7u8; 256]),
        salts: vec![ServerSalt { salt: 1, valid_since: start.unix - 60.0, valid_until: start.unix + 200.0 }],
        init_hash: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    let id = mtproto_core::rpc::RequestId(1);
    runtime.send(
        RpcRequest { id, body: vec![1, 2, 3, 4, 5, 6, 7, 8], flags: RequestFlags::default(), invoke_after: None },
        start,
    );
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Null);
    let config = EngineConfig::default();
    let mut resolver = FixedResolver { addresses: Vec::new(), calls: 0 };
    let mut elapsed = 0.0;
    let mut immediate = 0usize;
    let mut cancelled = false;
    let mut first_immediate = None;
    while elapsed < 180.0 {
        let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
        poll.poll(&mut events, Some(std::time::Duration::ZERO)).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        if !cancelled && elapsed > 1.0 {
            cancelled = true;
            runtime.cancel(id, now, poll.registry(), &callbacks);
        }
        let links = runtime.http.as_ref().map_or(0, |http| http.conns.len());
        if elapsed > 100.0 && links == 0 && runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
            immediate += 1;
            first_immediate.get_or_insert(elapsed);
        }
        elapsed += 0.01;
    }
    eprintln!(
        "turns asking to be driven at once while idle without a link: {immediate} of 8000 (first at {first_immediate:?} s), wants {}",
        runtime.wants_connection(Now { mono: start.mono + elapsed, unix: start.unix + elapsed })
    );
    assert!(immediate < 10, "{immediate} turns of 8000 asked to be driven at once, first at {first_immediate:?} s");
}

#[derive(Default)]
struct Completions(std::sync::Mutex<usize>);

impl EngineCallbacks for Completions {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })) {
            *self.0.lock().unwrap() += 1;
        }
    }
}

/// A worker session on HTTP completes a call against the test server in real time, then goes idle:
/// its connections close after 50 s idle (HTTP_IDLE_CLOSE, shorter than its 60 s idle disconnect).
/// Simulated time then runs on for an hour, past the salt change the server's future salts bring.
#[test]
fn an_idle_http_worker_does_not_spin_after_its_salt_changes() {
    use mtproto_testserver::{SERVER_SALT, TestServer, call, random_key};
    let key = random_key(7003);
    let server = TestServer::start(vec![key.clone()], Default::default());
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 256 * 1024];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: start.unix - 60.0, valid_until: start.unix + 3600.0 }],
        init_hash: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(
        RpcRequest {
            id: mtproto_core::rpc::RequestId(1),
            body: call(1, &1u64.to_le_bytes()),
            flags: RequestFlags::default(),
            invoke_after: None,
        },
        start,
    );
    let completions = Arc::new(Completions::default());
    let callbacks: Arc<dyn EngineCallbacks> = completions.clone();
    let config = EngineConfig::default();
    let mut resolver = FixedResolver { addresses: Vec::new(), calls: 0 };
    let mut now = start;
    while *completions.0.lock().unwrap() == 0 && now.mono - start.mono < 10.0 {
        poll.poll(&mut events, Some(std::time::Duration::from_millis(5))).unwrap();
        now = crate::clock::now();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
    }
    assert_eq!(*completions.0.lock().unwrap(), 1, "the call completed");
    for _ in 0..50 {
        poll.poll(&mut events, Some(std::time::Duration::from_millis(5))).unwrap();
        now = crate::clock::now();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
    }
    let base = now;
    let mut elapsed = 0.0;
    let mut immediate = 0usize;
    let mut first = None;
    let mut turns = 0usize;
    while elapsed < 3700.0 {
        let now = Now { mono: base.mono + elapsed, unix: base.unix + elapsed };
        poll.poll(&mut events, Some(std::time::Duration::ZERO)).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        let links = runtime.http.as_ref().map_or(0, |http| http.conns.len());
        turns += 1;
        if links == 0 && runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
            immediate += 1;
            first.get_or_insert(elapsed);
        }
        elapsed += 0.5;
    }
    let end = Now { mono: base.mono + elapsed, unix: base.unix + elapsed };
    eprintln!(
        "idle worker: {immediate} of {turns} turns asked to be driven at once (first {first:?} s after the call); wants {}",
        runtime.wants_connection(end)
    );
    assert!(
        immediate < 10,
        "{immediate} of {turns} turns asked to be driven at once, first {first:?} s after the call"
    );
}

#[derive(Default)]
struct CompletionRecorder {
    completed: std::sync::Mutex<Vec<mtproto_core::rpc::RequestId>>,
}

impl EngineCallbacks for CompletionRecorder {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if let EngineEvent::Rpc(RpcEvent::Completed { id, .. }) = event {
            self.completed.lock().unwrap().push(id);
        }
    }
}

/// A name with a black-holed first address: once the second answered, a later drop must not send
/// every attempt back to the dead first one (the cached list was read from the failure count, which
/// an answer clears).
#[test]
fn a_name_does_not_go_back_to_its_dead_first_address_after_the_second_answered() {
    use mtproto_testserver::{ServerOptions, TestServer, call};
    let key = AuthKey::new([7u8; 256]);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let black = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    black.set_nonblocking(true).unwrap();
    let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut held = Vec::new();
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "dc.example".into(), port: 443, secret: None }]);
    setup.transport = TransportPreference::Tcp;
    setup.keep_connected = true;
    setup.auth_key = Some(AuthKeyMaterial { key, salts: Vec::new(), init_hash: None });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    let request = |id: u64| RpcRequest {
        id: mtproto_core::rpc::RequestId(id),
        body: call(1, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    runtime.set_online(true, start);
    runtime.send(request(1), start);
    let recorder = Arc::new(CompletionRecorder::default());
    let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
    let config = EngineConfig::default();
    let mut resolver = FixedResolver { addresses: vec![black.local_addr().unwrap(), refused], calls: 0 };
    let mut elapsed = 0.0;
    let mut phase = 0;
    let mut black_before = 0;
    let mut second_sent_at = 0.0;
    let mut second_done_at = None;
    while elapsed < 1800.0 && second_done_at.is_none() {
        let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
        poll.poll(&mut events, Some(std::time::Duration::from_millis(1))).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        while let Ok((stream, _)) = black.accept() {
            held.push(stream);
        }
        let completed = recorder.completed.lock().unwrap().clone();
        if phase == 0 && runtime.failures >= 10 {
            phase = 1;
            resolver.addresses = vec![black.local_addr().unwrap(), server.address];
        } else if phase == 1 && completed.contains(&mtproto_core::rpc::RequestId(1)) {
            phase = 2;
            black_before = held.len();
            runtime.close_connection(poll.registry(), now, true);
            runtime.send(request(2), now);
            second_sent_at = elapsed;
        } else if phase == 2 && completed.contains(&mtproto_core::rpc::RequestId(2)) {
            second_done_at = Some(elapsed);
        }
        elapsed += 0.05;
    }
    let black_after = held.len() - black_before;
    runtime.shutdown(poll.registry(), Now { mono: start.mono + elapsed, unix: start.unix + elapsed });
    assert!(phase == 2, "call 1 never completed (phase {phase})");
    assert!(
        second_done_at.is_some_and(|at| at - second_sent_at < 40.0),
        "after the second address had answered, {black_after} connections went to the black-holed first one; call 2 took {:?} s",
        second_done_at.map(|at| at - second_sent_at)
    );
    assert!(black_after <= 1, "{black_after} connections went back to the dead first address");
}

#[derive(Default)]
struct KeyRequests {
    asked: std::sync::Mutex<usize>,
}

impl EngineCallbacks for KeyRequests {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if matches!(event, EngineEvent::AuthKeyRequired) {
            *self.asked.lock().unwrap() += 1;
        }
    }
}

/// Review 13: a PFS session waiting for the host's permanent key, with a call queued, on every
/// transport: no connection, one AuthKeyRequired, and no turn asking to be driven at once.
#[test]
fn a_session_waiting_for_the_hosts_permanent_key_neither_connects_nor_spins() {
    for transport in [TransportPreference::Tcp, TransportPreference::Http, TransportPreference::Auto] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(64);
        let mut scratch = vec![0u8; 65536];
        let mut rng = OsRandom::new();
        let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
        let mut setup =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        setup.transport = transport;
        setup.http_port = None;
        setup.keep_connected = true;
        setup.pfs = Some(crate::types::PfsSetup {
            lifetime: 86_400,
            public_keys: vec![mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key()],
            permanent_key_from_host: true,
            temporary_key: None,
        });
        let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
        runtime.set_online(true, start);
        runtime.send(
            RpcRequest {
                id: mtproto_core::rpc::RequestId(1),
                body: vec![1, 2, 3, 4, 5, 6, 7, 8],
                flags: RequestFlags::default(),
                invoke_after: None,
            },
            start,
        );
        let recorder = Arc::new(KeyRequests::default());
        let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
        let config = EngineConfig::default();
        let mut resolver = FixedResolver { addresses: Vec::new(), calls: 0 };
        let mut elapsed = 0.0;
        let mut immediate = 0usize;
        let mut accepted = 0usize;
        while elapsed < 120.0 {
            let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
            poll.poll(&mut events, Some(std::time::Duration::ZERO)).unwrap();
            for event in events.iter() {
                let readable = event.is_readable() || event.is_read_closed() || event.is_error();
                let writable = event.is_writable() || event.is_write_closed();
                runtime.handle_io(
                    event.token(),
                    readable,
                    writable,
                    poll.registry(),
                    &mut scratch,
                    now,
                    &callbacks,
                    &mut rng,
                );
            }
            runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
            while listener.accept().is_ok() {
                accepted += 1;
            }
            if runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
                immediate += 1;
            }
            elapsed += 0.01;
        }
        let asked = *recorder.asked.lock().unwrap();
        eprintln!("{transport:?}: {accepted} connections, {asked} AuthKeyRequired, {immediate} immediate turns");
        assert_eq!(accepted, 0, "{transport:?}: connected without a key to make");
        assert_eq!(asked, 1, "{transport:?}: AuthKeyRequired {asked} times");
        assert!(immediate <= 5, "{transport:?}: {immediate} turns asked to be driven at once");
    }
}

/// Review 13 (FFI generate_key=1 with pfs_lifetime>0, make_permanent_key=0): a PFS session waiting for the host's permanent key, with a call queued, on every
/// transport: no connection, one AuthKeyRequired, and no turn asking to be driven at once.
#[test]
fn generate_key_with_pfs_waiting_for_the_hosts_permanent_key() {
    for transport in [TransportPreference::Tcp, TransportPreference::Http, TransportPreference::Auto] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(64);
        let mut scratch = vec![0u8; 65536];
        let mut rng = OsRandom::new();
        let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
        let mut setup =
            SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
        setup.transport = transport;
        setup.http_port = None;
        setup.keep_connected = true;
        setup.pfs = Some(crate::types::PfsSetup {
            lifetime: 86_400,
            public_keys: vec![mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key()],
            permanent_key_from_host: true,
            temporary_key: None,
        });
        setup.key_generation = Some(crate::types::KeyGeneration {
            public_keys: vec![mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key()],
            temporary_expires_in: None,
        });
        let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
        runtime.set_online(true, start);
        runtime.send(
            RpcRequest {
                id: mtproto_core::rpc::RequestId(1),
                body: vec![1, 2, 3, 4, 5, 6, 7, 8],
                flags: RequestFlags::default(),
                invoke_after: None,
            },
            start,
        );
        let recorder = Arc::new(KeyRequests::default());
        let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
        let config = EngineConfig::default();
        let mut resolver = FixedResolver { addresses: Vec::new(), calls: 0 };
        let mut elapsed = 0.0;
        let mut immediate = 0usize;
        let mut accepted = 0usize;
        while elapsed < 120.0 {
            let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
            poll.poll(&mut events, Some(std::time::Duration::ZERO)).unwrap();
            for event in events.iter() {
                let readable = event.is_readable() || event.is_read_closed() || event.is_error();
                let writable = event.is_writable() || event.is_write_closed();
                runtime.handle_io(
                    event.token(),
                    readable,
                    writable,
                    poll.registry(),
                    &mut scratch,
                    now,
                    &callbacks,
                    &mut rng,
                );
            }
            runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
            while listener.accept().is_ok() {
                accepted += 1;
            }
            if runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
                immediate += 1;
            }
            elapsed += 0.01;
        }
        let asked = *recorder.asked.lock().unwrap();
        eprintln!("{transport:?}: {accepted} connections, {asked} AuthKeyRequired, {immediate} immediate turns");
        assert_eq!(accepted, 0, "{transport:?}: connected without a key to make");
        assert_eq!(asked, 1, "{transport:?}: AuthKeyRequired {asked} times");
        assert!(immediate <= 5, "{transport:?}: {immediate} turns asked to be driven at once");
    }
}

#[derive(Default)]
struct PermEvents {
    made: std::sync::Mutex<Vec<u64>>,
    completed: std::sync::Mutex<Vec<u64>>,
}

impl EngineCallbacks for PermEvents {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        match event {
            EngineEvent::AuthKeyCreated { key, expires_at: None, .. } => {
                if let Some(key) = AuthKey::from_slice(&key) {
                    self.made.lock().unwrap().push(key.id());
                }
            }
            EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => self.completed.lock().unwrap().push(id.0),
            _ => {}
        }
    }
}

/// Review 13: a PFS session allowed to make its permanent key is given the host's permanent key while
/// its own permanent-key handshake is under way. The host's key must win: the call runs under it.
#[test]
fn the_hosts_permanent_key_given_mid_handshake_is_not_overwritten_by_the_one_made() {
    use mtproto_testserver::{ServerOptions, TestServer, call, random_key};
    let host_perm = random_key(400);
    let server = TestServer::start(
        vec![host_perm.clone()],
        ServerOptions {
            handshake: mtproto_core::test_support::ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = TransportPreference::Tcp;
    setup.http_port = None;
    setup.pfs = Some(crate::types::PfsSetup {
        lifetime: 86_400,
        public_keys: vec![mtproto_core::test_support::ServerHandshake::new(Default::default()).public_key()],
        permanent_key_from_host: false,
        temporary_key: None,
    });
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.set_online(true, start);
    runtime.send(
        RpcRequest {
            id: mtproto_core::rpc::RequestId(7),
            body: call(7, &7u64.to_le_bytes()),
            flags: RequestFlags::default(),
            invoke_after: None,
        },
        start,
    );
    let recorder = Arc::new(PermEvents::default());
    let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
    let config = EngineConfig::default();
    let mut resolver = FixedResolver { addresses: Vec::new(), calls: 0 };
    let mut given = false;
    let real = std::time::Instant::now();
    while real.elapsed() < std::time::Duration::from_secs(10) && !recorder.completed.lock().unwrap().contains(&7) {
        let now = crate::clock::now();
        poll.poll(&mut events, Some(std::time::Duration::from_millis(1))).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
            if !given && runtime.handshake.is_some() && runtime.pfs.as_ref().is_some_and(|pfs| pfs.perm.is_none()) {
                given = true;
                let material = AuthKeyMaterial {
                    key: host_perm.clone(),
                    salts: vec![ServerSalt {
                        salt: mtproto_testserver::SERVER_SALT,
                        valid_since: now.unix - 60.0,
                        valid_until: now.unix + 3600.0,
                    }],
                    init_hash: None,
                };
                runtime.set_auth_key(Some(material), now, poll.registry(), &callbacks, &mut rng);
            }
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
    }
    let ran: Vec<(u32, u64)> = server.with_stats(|stats| stats.executed_under.clone());
    let made = recorder.made.lock().unwrap().clone();
    let session_perm = runtime.pfs.as_ref().and_then(|pfs| pfs.perm.as_ref().map(|perm| perm.key.id()));
    runtime.shutdown(poll.registry(), crate::clock::now());
    eprintln!(
        "given mid-handshake {given}; made {made:x?}; host {:x}; session perm now {session_perm:x?}; calls {ran:x?}",
        host_perm.id()
    );
    assert!(given, "never saw the permanent-key handshake under way");
    assert_eq!(
        ran.iter().find(|(tag, _)| *tag == 7).map(|(_, perm)| *perm),
        Some(host_perm.id()),
        "the call ran under the permanent key the session made, not the host's"
    );
}
