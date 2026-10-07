//! Engine paths no other test reached (found with `cargo llvm-cov`): host decisions about requests
//! queued before the session has a key, environment and clock changes, and what the public types
//! print.

use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{
    ApiEnvironment, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole, Verification,
};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, DropReason, Engine, EngineCallbacks, EngineConfig, EngineEvent, ProxyConfig,
    SessionHandle, SessionSetup, unix_seconds,
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

    fn on_log(&self, _level: mtproto_engine::LogLevel, _message: &str) {}
}

impl Collector {
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[(SessionHandle, EngineEvent)]) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        while !predicate(&events) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
        true
    }

    fn rpc(&self, predicate: impl Fn(&RpcEvent) -> bool) -> Vec<RpcEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(rpc) if predicate(rpc) => Some(rpc.clone()),
                _ => None,
            })
            .collect()
    }
}

fn finished(id: u64) -> impl Fn(&[(SessionHandle, EngineEvent)]) -> bool {
    move |events| {
        events.iter().any(|(_, event)| {
            matches!(
                event,
                EngineEvent::Rpc(RpcEvent::Completed { id: done, .. } | RpcEvent::Failed { id: done, .. }) if done.0 == id
            )
        })
    }
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn material(key: AuthKey) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn environment(hash: &str) -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: hash.into(),
        disable_updates: false,
    }
}

fn setup(port: u16, key: Option<AuthKey>) -> SessionSetup {
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = key.map(material);
    setup.environment = Some(environment("first"));
    setup
}

const WAIT: Duration = Duration::from_secs(15);

#[test]
fn requests_queued_before_a_key_follow_the_hosts_decisions() {
    let key = random_key(7100);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let session = engine.create_session(setup(server.address.port(), None));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, event)| *event == EngineEvent::AuthKeyRequired)));
    for id in 1..=5 {
        engine.send(session, request(id, id as u32));
    }
    engine.fail_request(session, RequestId(1), 400, "HOST_GAVE_UP".into());
    assert!(collector.wait(WAIT, finished(1)));
    let failed = collector.rpc(|event| matches!(event, RpcEvent::Failed { id: RequestId(1), .. }));
    assert!(matches!(&failed[..], [RpcEvent::Failed { code: 400, message, .. }] if message == "HOST_GAVE_UP"));

    engine.decide_retry(session, RequestId(2), false);
    assert!(collector.wait(WAIT, finished(2)));
    let failed = collector.rpc(|event| matches!(event, RpcEvent::Failed { id: RequestId(2), .. }));
    assert!(
        matches!(&failed[..], [RpcEvent::Failed { code: 500, message, .. }] if message == "SESSION_RESET"),
        "a queued request the host will not retry fails: {failed:?}"
    );
    engine.decide_retry(session, RequestId(3), true);
    engine.resolve_verification(session, RequestId(4), Verification::Recaptcha { token: "token".into() });
    engine.set_auth_token_ready(session, true);
    engine.update_environment(session, environment("second"), None);
    engine.set_time_difference(session, 0.0);
    engine.invalidate_initialization(session);
    engine.set_online(session, false);
    std::thread::sleep(Duration::from_millis(300));
    assert!(!finished(3)(&collector.events.lock().unwrap()), "nothing goes out without a key");

    engine.set_auth_key(session, Some(material(key.clone())));
    for id in 3..=5 {
        assert!(collector.wait(WAIT, finished(id)), "request {id}");
    }
    assert_eq!(collector.rpc(|event| matches!(event, RpcEvent::Completed { .. })).len(), 3);
    assert!(
        !collector.rpc(|event| matches!(event, RpcEvent::InitHashStored { hash } if hash == "second")).is_empty(),
        "the environment given while waiting for the key is the one sent"
    );
    assert_eq!(server.executions(2), 0, "the request failed by the host never ran");
    assert_eq!(server.executions(1), 0);
    engine.shutdown();
}

#[test]
fn a_clock_set_far_off_is_corrected_by_the_server() {
    let key = random_key(7101);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { validate_msg_id_time: true, ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let session = engine.create_session(setup(server.address.port(), Some(key)));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, finished(1)));
    assert_eq!(server.with_stats(|stats| stats.bad_msgs_sent), 0);
    engine.set_time_difference(session, 20_000.0);
    engine.set_online(session, true);
    engine.send(session, request(2, 2));
    assert!(collector.wait(WAIT, finished(2)));
    assert!(
        !collector.rpc(|event| matches!(event, RpcEvent::Completed { id: RequestId(2), .. })).is_empty(),
        "the call completes once the server has corrected the clock"
    );
    assert_eq!(server.with_stats(|stats| stats.bad_msgs_sent), 1, "msg_ids 20000 s ahead are refused once");
    assert_eq!(server.executions(2), 1);
    engine.shutdown();
}

#[test]
fn an_address_change_moves_a_running_session() {
    let key = random_key(7102);
    let first = TestServer::start(vec![key.clone()], ServerOptions::default());
    let second = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let session = engine.create_session(setup(first.address.port(), Some(key)));
    engine.send(session, request(1, 31));
    assert!(collector.wait(WAIT, finished(1)));
    engine.set_addresses(
        session,
        vec![DcAddress { host: "127.0.0.1".into(), port: second.address.port(), secret: None }],
    );
    engine.reset_connections();
    engine.send(session, request(2, 32));
    assert!(collector.wait(WAIT, finished(2)));
    assert_eq!((first.executions(32), second.executions(32)), (0, 1));
    engine.shutdown();
}

#[test]
fn worker_threads_are_clamped() {
    let collector = Arc::new(Collector::default());
    for (asked, expected) in [(0usize, 1usize), (3, 3), (40, 16)] {
        let engine =
            Engine::new(EngineConfig { worker_threads: asked, ..EngineConfig::default() }, collector.clone()).unwrap();
        assert_eq!(engine.worker_count(), expected, "{asked} threads asked");
        engine.shutdown();
    }
}

#[test]
fn proxies_and_keys_print_without_their_secrets() {
    let proxies = [
        ProxyConfig::Socks5 {
            host: "10.0.0.1".into(),
            port: 1080,
            username: Some("user".into()),
            password: Some("hunter2".into()),
        },
        ProxyConfig::MtProxy { host: "mt.example".into(), port: 443, secret: vec![0x5e; 16] },
        ProxyConfig::Http {
            host: "proxy.example".into(),
            port: 3128,
            username: Some("user".into()),
            password: Some("hunter2".into()),
        },
        ProxyConfig::Web { host: "web.example".into(), secret: vec![0x5e; 16] },
    ];
    let printed: Vec<String> = proxies.iter().map(|proxy| format!("{proxy:?}")).collect();
    assert_eq!(
        printed,
        ["Socks5(10.0.0.1:1080)", "MtProxy(mt.example:443)", "Http(proxy.example:3128)", "Web(web.example)"]
    );
    for (proxy, printed) in proxies.iter().zip(&printed) {
        assert!(!printed.contains("hunter2") && !printed.contains("user") && !printed.contains("5e5e"));
        assert!(printed.contains(&proxy.display_address()));
    }
    let key = AuthKey::new([0x77; 256]);
    let printed = format!("{:?}", material(key.clone()));
    assert!(printed.contains(&format!("{:#018x}", key.id())), "{printed}");
    assert!(printed.contains("salts: 1") && !printed.contains("119, 119"), "{printed}");
}

#[test]
fn drop_reasons_have_distinct_stable_names() {
    let reasons = [
        DropReason::Closed,
        DropReason::IoError,
        DropReason::Protocol,
        DropReason::ConnectTimeout,
        DropReason::HandshakeTimeout,
        DropReason::PingTimeout,
        DropReason::ReadTimeout,
        DropReason::ProbeTimeout,
        DropReason::RequestTimeout,
        DropReason::SessionError,
        DropReason::KeyInvalid,
        DropReason::KeyRejectedOnce,
        DropReason::AddressRejected,
        DropReason::HandshakeFailed,
        DropReason::TransportFlood,
        DropReason::SlowConnect,
        DropReason::RacerWon,
        DropReason::TransportSwitch,
    ];
    let names: HashSet<&str> = reasons.iter().map(|reason| reason.name()).collect();
    assert_eq!(names.len(), reasons.len(), "the host tells drops apart by name");
    assert!(names.iter().all(|name| name.chars().all(|c| c.is_ascii_lowercase() || c == '_')), "{names:?}");
    assert_eq!(DropReason::KeyRejectedOnce.name(), "key_rejected_once");
    assert_eq!(DropReason::TransportSwitch.name(), "transport_switch");
}

/// The address type, address and port each client asked a SOCKS5 proxy for.
type SeenTargets = Arc<Mutex<Vec<(u8, Vec<u8>, u16)>>>;

/// A SOCKS5 proxy that records the target each client asks for and connects every one to `upstream`.
fn recording_socks5(upstream: std::net::SocketAddr) -> (u16, SeenTargets) {
    recording_socks5_with(upstream, None)
}

/// With `credentials`, the proxy insists on username/password authentication and checks them.
fn recording_socks5_with(
    upstream: std::net::SocketAddr,
    credentials: Option<(&'static str, &'static str)>,
) -> (u16, SeenTargets) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { return };
            let record = record.clone();
            std::thread::spawn(move || {
                let mut head = [0u8; 2];
                client.read_exact(&mut head)?;
                let mut methods = vec![0u8; usize::from(head[1])];
                client.read_exact(&mut methods)?;
                if let Some((user, pass)) = credentials {
                    if !methods.contains(&2) {
                        client.write_all(&[5, 0xff])?;
                        return Ok(());
                    }
                    client.write_all(&[5, 2])?;
                    let mut version_and_length = [0u8; 2];
                    client.read_exact(&mut version_and_length)?;
                    let mut username = vec![0u8; usize::from(version_and_length[1])];
                    client.read_exact(&mut username)?;
                    let mut length = [0u8; 1];
                    client.read_exact(&mut length)?;
                    let mut password = vec![0u8; usize::from(length[0])];
                    client.read_exact(&mut password)?;
                    let accepted = username == user.as_bytes() && password == pass.as_bytes();
                    client.write_all(&[1, if accepted { 0 } else { 1 }])?;
                    if !accepted {
                        return Ok(());
                    }
                } else {
                    client.write_all(&[5, 0])?;
                }
                let mut request = [0u8; 4];
                client.read_exact(&mut request)?;
                let address = match request[3] {
                    1 => {
                        let mut v4 = vec![0u8; 4];
                        client.read_exact(&mut v4)?;
                        v4
                    }
                    4 => {
                        let mut v6 = vec![0u8; 16];
                        client.read_exact(&mut v6)?;
                        v6
                    }
                    _ => {
                        let mut length = [0u8; 1];
                        client.read_exact(&mut length)?;
                        let mut name = vec![0u8; usize::from(length[0])];
                        client.read_exact(&mut name)?;
                        name
                    }
                };
                let mut port = [0u8; 2];
                client.read_exact(&mut port)?;
                record.lock().unwrap().push((request[3], address, u16::from_be_bytes(port)));
                let mut server = std::net::TcpStream::connect(upstream)?;
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])?;
                let mut reader = client.try_clone()?;
                let mut writer = server.try_clone()?;
                std::thread::spawn(move || std::io::copy(&mut reader, &mut writer));
                std::io::copy(&mut server, &mut client)?;
                Ok::<(), std::io::Error>(())
            });
        }
    });
    (port, seen)
}

#[test]
fn a_socks5_proxy_is_given_names_and_ipv6_addresses_as_they_are() {
    let key = random_key(7103);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (proxy_port, seen) = recording_socks5(server.address);
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let mut by_name = setup(0, Some(key.clone()));
    by_name.addresses = vec![DcAddress { host: "dc2.example.invalid".into(), port: 443, secret: None }];
    by_name.proxy =
        Some(ProxyConfig::Socks5 { host: "127.0.0.1".into(), port: proxy_port, username: None, password: None });
    let named = engine.create_session(by_name);
    engine.send(named, request(1, 41));
    assert!(collector.wait(WAIT, finished(1)));
    let mut by_v6 = setup(0, Some(key));
    by_v6.addresses = vec![DcAddress { host: "2001:b28:f23d:f001::a".into(), port: 443, secret: None }];
    by_v6.proxy =
        Some(ProxyConfig::Socks5 { host: "127.0.0.1".into(), port: proxy_port, username: None, password: None });
    let v6 = engine.create_session(by_v6);
    engine.send(v6, request(2, 42));
    assert!(collector.wait(WAIT, finished(2)));
    assert_eq!(collector.rpc(|event| matches!(event, RpcEvent::Completed { .. })).len(), 2);
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.contains(&(3, b"dc2.example.invalid".to_vec(), 443)),
        "the name goes to the proxy unresolved, so no DNS query leaves the device: {seen:?}"
    );
    let v6_bytes: Vec<u8> = "2001:b28:f23d:f001::a".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec();
    assert!(seen.contains(&(4, v6_bytes, 443)), "{seen:?}");
    engine.shutdown();
}

#[test]
fn http_through_an_authenticating_socks5_proxy_names_the_datacenter() {
    let key = random_key(7104);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (proxy_port, seen) = recording_socks5_with(server.address, Some(("alice", "s3cret")));
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let mut http = setup(0, Some(key));
    http.addresses = vec![DcAddress { host: "dc2-http.example.invalid".into(), port: 80, secret: None }];
    http.transport = mtproto_engine::TransportPreference::Http;
    http.http_port = None;
    http.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: proxy_port,
        username: Some("alice".into()),
        password: Some("s3cret".into()),
    });
    let session = engine.create_session(http);
    engine.send(session, request(1, 51));
    assert!(collector.wait(WAIT, finished(1)));
    assert!(!collector.rpc(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. })).is_empty());
    assert!(server.with_stats(|stats| stats.http.requests) > 0, "the call went over HTTP");
    assert!(seen.lock().unwrap().iter().all(|target| *target == (3, b"dc2-http.example.invalid".to_vec(), 80)));
    engine.shutdown();
}

#[test]
fn http_status_429_backs_off_like_a_transport_flood() {
    let key = random_key(7105);
    let server = TestServer::start(vec![key.clone()], ServerOptions { reject_with: Some(-429), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let mut http = setup(server.address.port(), Some(key));
    http.transport = mtproto_engine::TransportPreference::Http;
    http.http_port = None;
    let session = engine.create_session(http);
    engine.send(session, request(1, 52));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, event)| *event == EngineEvent::TransportFlood)));
    std::thread::sleep(Duration::from_secs(4));
    let rejected = server.with_stats(|stats| stats.transport_errors_sent);
    assert!((1..=8).contains(&rejected), "429s back the session off instead of a request storm: {rejected}");
    assert!(collector.rpc(|event| matches!(event, RpcEvent::Failed { .. })).is_empty(), "the call is kept, not failed");
    engine.shutdown();
}

#[test]
fn key_generation_over_http_survives_a_refused_and_a_silent_handshake() {
    let server = TestServer::start(
        vec![],
        ServerOptions {
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                server_time: unix_seconds() as i32,
                ..Default::default()
            },
            handshake_faults: vec![HandshakeFault::TransportError(-404), HandshakeFault::Stall],
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig::default(), collector.clone()).unwrap();
    let mut generated = setup(server.address.port(), None);
    generated.transport = mtproto_engine::TransportPreference::Http;
    generated.http_port = None;
    generated.key_generation = Some(mtproto_engine::KeyGeneration {
        public_keys: vec![mtproto_engine::mtproto_core::test_support::test_rsa_key_pair().public],
        temporary_expires_in: None,
    });
    let session = engine.create_session(generated);
    engine.send(session, request(1, 61));
    assert!(collector.wait(Duration::from_secs(40), finished(1)), "the call completes once a key is made");
    let events = collector.events.lock().unwrap().clone();
    let failures: Vec<String> = events
        .iter()
        .filter_map(|(_, event)| match event {
            EngineEvent::AuthKeyCreationFailed { reason } => Some(reason.clone()),
            _ => None,
        })
        .collect();
    assert!(failures.iter().any(|reason| reason.contains("404")), "the refused handshake is reported: {failures:?}");
    let created = events.iter().filter(|(_, event)| matches!(event, EngineEvent::AuthKeyCreated { .. })).count();
    assert_eq!(created, 1, "exactly one key comes out of it");
    assert!(!collector.rpc(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. })).is_empty());
    assert_eq!(server.executions(61), 1);
    engine.shutdown();
}
