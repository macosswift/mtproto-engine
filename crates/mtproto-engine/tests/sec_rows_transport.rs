//! Transport rows of the security table checked on the running engine: errors on a stream are sticky,
//! dcOption secrets key the obfuscation and keep addresses off plain HTTP, and packets failing a check
//! never reach the host.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::crypto::XorShiftRandom;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_result};
use mtproto_engine::mtproto_core::transport::{FrameDecoder, InputBuffer, accept_obfuscated_header, encode_frame};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, ProxyConfig, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::chaos::{ChaosConfig, Fault};
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

    fn completed(&self) -> Vec<(RequestId, Vec<u8>)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, body, .. }) => Some((*id, body.clone())),
                _ => None,
            })
            .collect()
    }

    fn updates(&self) -> Vec<Vec<u8>> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, event)| match event {
                EngineEvent::Rpc(RpcEvent::Update { body }) => Some(body.clone()),
                _ => None,
            })
            .collect()
    }
}

fn completions(events: &[(SessionHandle, EngineEvent)]) -> usize {
    events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))).count()
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup_for(address: SocketAddr, key: &AuthKey, secret: Option<Vec<u8>>) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: address.ip().to_string(), port: address.port(), secret }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup
}

fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(id as u32, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const STALE: [u8; 8] = [0x51, 0x51, 0x51, 0x51, 1, 0, 0, 0];
const FRESH: [u8; 8] = [0xf2, 0xf2, 0xf2, 0xf2, 2, 0, 0, 0];

#[derive(Clone, Copy)]
enum FirstError {
    CorruptedPacket,
    TransportError(i32),
    RepeatedTransportError(i32),
}

/// A datacenter that holds the session's key. On the first connection it answers the call with a bad
/// frame and, in the same write, a genuine answer marked stale; on later connections with the fresh
/// answer.
struct StickyDc {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
}

impl StickyDc {
    fn start(key: AuthKey, first: FirstError) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let call_msg_id = Arc::new(Mutex::new(None::<i64>));
        {
            let (stop, connections) = (stop.clone(), connections.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let index = connections.fetch_add(1, Ordering::SeqCst);
                            let (key, stop, call_msg_id) = (key.clone(), stop.clone(), call_msg_id.clone());
                            std::thread::spawn(move || {
                                let _ = serve_sticky(stream, key, first, index, call_msg_id, &stop);
                            });
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            });
        }
        Self { address, stop, connections }
    }
}

impl Drop for StickyDc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve_sticky(
    mut stream: TcpStream,
    key: AuthKey,
    first: FirstError,
    index: usize,
    call_msg_id: Arc<Mutex<Option<i64>>>,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    while raw.len() < 64 {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    let header: [u8; 64] = raw[..64].try_into().unwrap();
    let Some(mut obfuscation) = accept_obfuscated_header(&header, None) else {
        return Ok(());
    };
    let framing = obfuscation.framing;
    let decoder = FrameDecoder::new(framing);
    let mut input = InputBuffer::new();
    let mut rest = raw[64..].to_vec();
    obfuscation.decryptor.apply(&mut rest);
    input.extend(&rest);
    let mut peer = ServerPeer::new(key, unix_seconds());
    peer.salt = SERVER_SALT;
    let mut rng = XorShiftRandom::new(index as u64 + 1);
    let mut answered = false;
    loop {
        while let Ok(Some((payload, _))) = decoder.decode_client_frame(&mut input) {
            if answered || payload.len() < 8 || payload[..8] == [0u8; 8] {
                continue;
            }
            peer.server_time = unix_seconds();
            let packet = peer.decode(&payload);
            let in_packet = packet.messages.iter().find(|message| message.constructor() == CALL).map(|m| m.msg_id);
            let target = {
                let mut known = call_msg_id.lock().unwrap();
                if in_packet.is_some() {
                    *known = in_packet;
                }
                *known
            };
            let Some(target) = target else {
                continue;
            };
            answered = true;
            let mut frames = Vec::new();
            if index == 0 {
                match first {
                    FirstError::CorruptedPacket => {
                        let mut bad = peer.encode(vec![Outgoing::Content(rpc_result(target, &STALE))]);
                        let middle = 24 + (bad.len() - 24) / 2;
                        bad[middle] ^= 0x10;
                        encode_frame(framing, &bad, false, &mut rng, &mut frames);
                    }
                    FirstError::TransportError(code) => {
                        encode_frame(framing, &code.to_le_bytes(), false, &mut rng, &mut frames);
                    }
                    FirstError::RepeatedTransportError(code) => {
                        encode_frame(framing, &code.to_le_bytes(), false, &mut rng, &mut frames);
                        encode_frame(framing, &code.to_le_bytes(), false, &mut rng, &mut frames);
                    }
                }
                if !matches!(first, FirstError::RepeatedTransportError(_)) {
                    let stale = peer.encode(vec![Outgoing::Content(rpc_result(target, &STALE))]);
                    encode_frame(framing, &stale, false, &mut rng, &mut frames);
                }
            } else {
                let fresh = peer.encode(vec![Outgoing::Content(rpc_result(target, &FRESH))]);
                encode_frame(framing, &fresh, false, &mut rng, &mut frames);
            }
            obfuscation.encryptor.apply(&mut frames);
            stream.write_all(&frames)?;
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                let mut data = chunk[..read].to_vec();
                obfuscation.decryptor.apply(&mut data);
                input.extend(&data);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(_) => return Ok(()),
        }
    }
}

fn answer_after_first_error(first: FirstError) -> (Vec<u8>, usize) {
    let key = random_key(4401);
    let dc = StickyDc::start(key.clone(), first);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_for(dc.address, &key, None));
    engine.send(session, request(1));
    assert!(collector.wait(Duration::from_secs(15), |events| completions(events) >= 1), "the call never completed");
    std::thread::sleep(Duration::from_millis(200));
    let completed = collector.completed();
    engine.shutdown();
    assert_eq!(completed.len(), 1, "{completed:?}");
    (completed[0].1.clone(), dc.connections.load(Ordering::SeqCst))
}

#[test]
#[ignore = "T-17: frames after a packet that failed its check are still processed (session_runtime.rs handle_io second pass)"]
fn nothing_after_a_failed_packet_is_processed_on_the_same_connection() {
    let (body, connections) = answer_after_first_error(FirstError::CorruptedPacket);
    assert_eq!(body, FRESH, "the answer behind the corrupted packet was taken from the failed connection");
    assert!(connections >= 2);
}

#[test]
#[ignore = "T-17: frames after a transport error frame are still processed (session_runtime.rs handle_io second pass)"]
fn nothing_after_a_transport_error_is_processed_on_the_same_connection() {
    let (body, connections) = answer_after_first_error(FirstError::TransportError(-429));
    assert_eq!(body, FRESH, "the answer behind the transport error was taken from the failed connection");
    assert!(connections >= 2);
}

#[test]
#[ignore = "T-17: two -404 frames in one read count as a rejection confirmed on a fresh connection (session_runtime.rs handle_io second pass)"]
fn two_forged_404_frames_on_one_connection_are_one_rejection() {
    let key = random_key(4407);
    let dc = StickyDc::start(key.clone(), FirstError::RepeatedTransportError(-404));
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_for(dc.address, &key, None));
    engine.send(session, request(1));
    let settled = collector.wait(Duration::from_secs(15), |events| {
        completions(events) >= 1 || events.iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { .. }))
    });
    let invalid =
        collector.events.lock().unwrap().iter().any(|(_, event)| matches!(event, EngineEvent::AuthKeyInvalid { .. }));
    let completed = collector.completed();
    engine.shutdown();
    assert!(settled);
    assert!(!invalid, "two frames injected into one connection reported the key invalid");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].1, FRESH);
    assert!(dc.connections.load(Ordering::SeqCst) >= 2);
}

fn run_with_secrets(server_secret: Option<Vec<u8>>, address_secret: Option<Vec<u8>>, wait: Duration) -> (bool, usize) {
    let key = random_key(4402);
    let server = TestServer::start(vec![key.clone()], ServerOptions { secret: server_secret, ..Default::default() });
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_for(server.address, &key, address_secret));
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    let done = collector.wait(wait, |events| completions(events) == 3);
    engine.shutdown();
    let executed = (1..=3).map(|id| server.executions(id)).sum();
    (done, executed)
}

#[test]
fn a_datacenter_secret_keys_the_obfuscation_and_no_other_secret_connects() {
    let secret = vec![0x5cu8; 16];
    let mut padded = vec![0xdd];
    padded.extend_from_slice(&[0x6du8; 16]);
    for good in [secret.clone(), padded.clone()] {
        assert_eq!(run_with_secrets(Some(good.clone()), Some(good), Duration::from_secs(10)), (true, 3));
    }
    let wait = Duration::from_millis(2500);
    assert_eq!(run_with_secrets(Some(secret.clone()), Some(vec![0x5du8; 16]), wait), (false, 0), "another secret");
    assert_eq!(run_with_secrets(Some(secret.clone()), None, wait), (false, 0), "no secret where one is required");
    assert_eq!(run_with_secrets(None, Some(secret), wait), (false, 0), "the secret is really applied");
}

#[test]
fn an_address_with_a_secret_is_never_tried_over_plain_http() {
    let key = random_key(4403);
    let secret = vec![0x3au8; 16];
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { secret: Some(secret.clone()), ..Default::default() });
    let collector = Arc::new(Collector::default());
    let disguised = engine(&collector);
    let mut setup = setup_for(server.address, &key, Some(secret));
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    let session = disguised.create_session(setup);
    disguised.send(session, request(1));
    assert!(!collector.wait(Duration::from_millis(2500), |events| completions(events) >= 1));
    disguised.shutdown();
    assert_eq!(server.with_stats(|stats| stats.http.requests), 0, "a tcpo_only address was sent plain HTTP");
    assert_eq!(server.executions(1), 0);

    let open = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let plain = engine(&collector);
    let mut setup = setup_for(open.address, &key, None);
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    let session = plain.create_session(setup);
    plain.send(session, request(1));
    assert!(collector.wait(Duration::from_secs(10), |events| completions(events) >= 1), "HTTP works without a secret");
    plain.shutdown();
    assert!(open.with_stats(|stats| stats.http.requests) >= 1);
}

#[test]
#[ignore = "T-13: behind a SOCKS5 or HTTP proxy the dcOption secret of the address is dropped (types.rs proxy_secret)"]
fn a_datacenter_secret_is_kept_behind_a_socks5_proxy() {
    let key = random_key(4404);
    let secret = vec![0x7bu8; 16];
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions { socks5: true, secret: Some(secret.clone()), ..Default::default() },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_for(server.address, &key, Some(secret));
    setup.addresses[0].host = "149.154.167.51".into();
    setup.addresses[0].port = 443;
    setup.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: None,
        password: None,
    });
    let session = engine.create_session(setup);
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    let done = collector.wait(Duration::from_secs(10), |events| completions(events) == 3);
    engine.shutdown();
    assert!(done, "the tcpo_only address lost its secret behind the SOCKS5 proxy");
}

#[test]
fn misaddressed_packets_never_reach_the_host() {
    for (seed, fault, constructor) in
        [(4405u64, Fault::HostileForeignSession, 0x0bad_0001u32), (4406, Fault::HostileEvenMsgId, 0x0bad_0002)]
    {
        let key = random_key(seed);
        let server = TestServer::start(
            vec![key.clone()],
            ServerOptions { chaos: Some(ChaosConfig::only(seed, fault, 1.0)), ..Default::default() },
        );
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let session = engine.create_session(setup_for(server.address, &key, None));
        for id in 1..=6 {
            engine.send(session, request(id));
        }
        assert!(collector.wait(Duration::from_secs(20), |events| completions(events) == 6), "{fault:?}");
        std::thread::sleep(Duration::from_millis(200));
        engine.shutdown();
        assert!(server.with_stats(|stats| stats.chaos_injected.values().sum::<usize>()) > 0, "{fault:?}");
        let leaked: Vec<Vec<u8>> = collector
            .updates()
            .into_iter()
            .filter(|body| body.len() >= 4 && u32::from_le_bytes(body[..4].try_into().unwrap()) == constructor)
            .collect();
        assert!(leaked.is_empty(), "{fault:?}: {leaked:?}");
        assert_eq!(server.with_stats(|stats| stats.duplicate_executions), 0, "{fault:?}");
        let mut ids: Vec<u64> = collector.completed().into_iter().map(|(id, _)| id.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=6).collect::<Vec<u64>>(), "{fault:?}");
    }
}
