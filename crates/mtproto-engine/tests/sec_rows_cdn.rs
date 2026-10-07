//! CDN and media sessions: a CDN key is made only with the RSA keys the host got from the master DC
//! (B-47), a CDN's answers complete only its own session's requests (B-50), a CDN connection carries
//! only the host's calls in the anonymous wrapper (B-52), a CDN session never leaves the addresses the
//! host configured (B-55), and media sessions run on their own connections without updates (B-60).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::crypto::RsaPublicKey;
use mtproto_engine::mtproto_core::rpc::{
    ApiEnvironment, INIT_CONNECTION, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole,
};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::mtproto_core::tl::{Reader, ids};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, PfsSetup,
    SessionHandle, SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[path = "support/sec_rows_tap.rs"]
mod tap;

#[path = "support/stream_host.rs"]
mod stream_host;

use stream_host::TestStreamHost;

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

    fn wait_completed(&self, session: SessionHandle, id: u64) -> bool {
        self.wait(WAIT, |events| events.iter().any(|(handle, event)| *handle == session && completed(event, id)))
    }

    fn of(&self, session: SessionHandle) -> Vec<EngineEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _)| *handle == session)
            .map(|(_, event)| event.clone())
            .collect()
    }
}

fn completed(event: &EngineEvent, id: u64) -> bool {
    matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id)
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn material(key: &AuthKey) -> AuthKeyMaterial {
    let now = unix_seconds();
    AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    }
}

fn address(port: u16) -> DcAddress {
    DcAddress { host: "127.0.0.1".into(), port, secret: None }
}

fn setup(port: u16, key: Option<&AuthKey>, role: SessionRole, datacenter_id: i32) -> SessionSetup {
    let mut setup = SessionSetup::new(datacenter_id, role, vec![address(port)]);
    setup.auth_key = key.map(material);
    setup.http_port = None;
    setup
}

fn environment(disable_updates: bool) -> ApiEnvironment {
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
        init_hash: "sec-rows".into(),
        disable_updates,
    }
}

fn engine(collector: &Arc<Collector>, workers: usize) -> Engine {
    Engine::new(EngineConfig { worker_threads: workers, ..EngineConfig::default() }, collector.clone()).unwrap()
}

/// A 2048-bit RSA key the test server does not have, as a CDN's key the master never vouched for.
fn unvouched_key() -> RsaPublicKey {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut modulus: Vec<u8> = (0..256)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    modulus[0] |= 0x80;
    modulus[255] |= 1;
    RsaPublicKey::from_components(&modulus, &[1, 0, 1]).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);
const CDN_DC: i32 = 203;

/// A CDN is enemy territory: its auth key is made only after its RSA key matched one the host got from
/// `help.getCdnConfig` on the master DC. The engine carries no RSA keys of its own, so a CDN session
/// handed keys that do not include the server's makes no key at all and sends nothing under one; given
/// the CDN's real key it makes its key and the call goes through.
#[test]
fn a_cdn_key_is_made_only_with_rsa_keys_the_host_got_from_the_master_dc() {
    let cdn = TestServer::start(Vec::new(), ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut refused = setup(cdn.address.port(), None, SessionRole::Cdn, CDN_DC);
    refused.key_generation = Some(KeyGeneration { public_keys: vec![unvouched_key()], temporary_expires_in: None });
    let refused = engine.create_session(refused);
    engine.send(refused, request(1, 1));
    let failures = |events: &[(SessionHandle, EngineEvent)]| {
        events
            .iter()
            .filter(|(handle, event)| *handle == refused && matches!(event, EngineEvent::AuthKeyCreationFailed { .. }))
            .count()
    };
    assert!(collector.wait(Duration::from_secs(20), |events| failures(events) >= 2));
    let reasons: Vec<String> = collector
        .of(refused)
        .into_iter()
        .filter_map(|event| match event {
            EngineEvent::AuthKeyCreationFailed { reason } => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons.iter().all(|reason| reason.starts_with("no known RSA key among")),
        "the handshake went past resPQ with a key the server did not offer: {reasons:?}"
    );
    assert!(!collector.of(refused).iter().any(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })));
    assert_eq!(cdn.with_stats(|stats| stats.handshakes), 0);
    assert_eq!(cdn.executions(1), 0);

    let mut vouched = setup(cdn.address.port(), None, SessionRole::Cdn, CDN_DC);
    vouched.key_generation = Some(KeyGeneration {
        public_keys: vec![unvouched_key(), ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let vouched = engine.create_session(vouched);
    engine.send(vouched, request(2, 2));
    assert!(collector.wait_completed(vouched, 2), "{:?}", collector.of(vouched));
    assert!(collector.of(vouched).iter().any(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })));
    assert_eq!(cdn.with_stats(|stats| stats.handshake_dcs.clone()), vec![(CDN_DC, false)]);
    engine.shutdown();
}

/// Pending requests are scoped per session, and so per datacenter, connection and key: a CDN answering
/// a request id the master session also has in flight completes only the CDN session's own request.
#[test]
fn a_cdn_answer_completes_only_the_cdn_sessions_own_request() {
    let master_key = random_key(5001);
    let cdn_key = random_key(5002);
    let master = TestServer::start(vec![master_key.clone()], ServerOptions::default());
    let cdn = TestServer::start(vec![cdn_key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let main = engine.create_session(setup(master.address.port(), Some(&master_key), SessionRole::Main, 2));
    let cdn_session = engine.create_session(setup(cdn.address.port(), Some(&cdn_key), SessionRole::Cdn, CDN_DC));
    engine.send(main, request(77, TAG_NEVER));
    assert!(collector.wait(WAIT, |_| master.executions(TAG_NEVER) == 1));
    engine.send(cdn_session, request(77, 5));
    assert!(collector.wait_completed(cdn_session, 77));
    std::thread::sleep(Duration::from_secs(1));
    let answers: Vec<(SessionHandle, Vec<u8>)> = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(handle, event)| match event {
            EngineEvent::Rpc(RpcEvent::Completed { id, body, .. }) if id.0 == 77 => Some((*handle, body.clone())),
            _ => None,
        })
        .collect();
    engine.shutdown();
    assert_eq!(answers.len(), 1, "one answer for request 77: {answers:?}");
    assert_eq!(answers[0].0, cdn_session, "the CDN's answer was delivered for the master session's request");
    assert_eq!(parse_result(&answers[0].1).map(|(tag, _)| tag), Some(5));
    assert_eq!(cdn.executions(TAG_NEVER), 0);
}

fn service(constructor: u32) -> bool {
    [
        ids::MSGS_ACK,
        ids::PING,
        ids::PING_DELAY_DISCONNECT,
        ids::PONG,
        ids::GET_FUTURE_SALTS,
        ids::MSGS_STATE_REQ,
        ids::MSGS_STATE_INFO,
        ids::MSG_RESEND_REQ,
        ids::MSG_RESEND_ANS_REQ,
        ids::RPC_DROP_ANSWER,
        ids::HTTP_WAIT,
    ]
    .contains(&constructor)
}

/// The host's call inside the wrappers a CDN takes: `invokeWithLayer(initConnection(...))` with the
/// anonymous parameters, or nothing. None for anything else.
fn hosts_call_inside_cdn_wrappers(body: &[u8]) -> Option<(bool, u32)> {
    let mut reader = Reader::new(body);
    let constructor = reader.read_u32().ok()?;
    if constructor == CALL {
        return Some((false, reader.read_u32().ok()?));
    }
    if constructor != ids::INVOKE_WITH_LAYER {
        return None;
    }
    reader.read_i32().ok()?;
    if reader.read_u32().ok()? != INIT_CONNECTION || reader.read_i32().ok()? != 0 {
        return None;
    }
    reader.read_i32().ok()?;
    let fields: Vec<Vec<u8>> =
        (0..6).map(|_| reader.read_bytes().map(<[u8]>::to_vec)).collect::<Result<_, _>>().ok()?;
    if fields[0] != b"n/a" || fields[1] != b"n/a" || !fields[4].is_empty() || !fields[5].is_empty() {
        return None;
    }
    (reader.read_u32().ok()? == CALL).then_some(())?;
    Some((true, reader.read_u32().ok()?))
}

/// A CDN supports only upload.getCdnFile, initConnection and invokeWithLayer. Everything the engine
/// puts on a CDN connection is the host's call, wrapped at most in the anonymous initConnection, or an
/// MTProto service message: the engine adds no API call of its own (no bind, no invokeWithoutUpdates
/// the host did not ask for, no verification wrapper), also through server pings, salt changes and
/// the -404s of a CDN that lost the key, which make the session replace the key, never check it with
/// a temporary key bound on the CDN.
#[test]
fn a_cdn_connection_carries_only_the_hosts_calls_in_the_anonymous_wrapper() {
    let cdn_key = random_key(5201);
    let cdn = TestServer::start(
        vec![cdn_key.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let tap = tap::Tap::start(cdn.address);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut cdn_setup = setup(tap.address.port(), Some(&cdn_key), SessionRole::Cdn, CDN_DC);
    cdn_setup.environment = Some(environment(false));
    cdn_setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        temporary_expires_in: None,
    });
    let session = engine.create_session(cdn_setup);
    for (id, tag) in (1u64..).zip([1u32, TAG_SERVER_PING, TAG_BAD_SALT_ONCE, 2]) {
        engine.send(session, request(id, tag));
        assert!(collector.wait_completed(session, id), "call {id}");
    }
    cdn.remove_key(cdn_key.id());
    engine.send(session, request(5, 3));
    assert!(collector.wait(Duration::from_secs(40), |events| {
        events.iter().any(|(handle, event)| *handle == session && completed(event, 5))
    }));
    let new_keys: Vec<AuthKey> = collector
        .of(session)
        .into_iter()
        .filter_map(|event| match event {
            EngineEvent::AuthKeyCreated { key, .. } => AuthKey::from_slice(&key),
            _ => None,
        })
        .collect();
    engine.shutdown();
    let mut keys = vec![cdn_key.clone()];
    keys.extend(new_keys);
    let frames = tap.client_frames();
    assert_eq!(tap::under_other_keys(&frames, &keys), 0, "packets went to the CDN under a key never reported");
    let opened = tap::open(&frames, &keys);
    assert!(keys.len() >= 2, "the CDN key was replaced after the CDN lost it");
    let mut wrapped = 0;
    let mut calls = Vec::new();
    for packet in &opened {
        for (body, _) in &packet.messages {
            let constructor = u32::from_le_bytes(body[..4].try_into().unwrap());
            if service(constructor) {
                continue;
            }
            match hosts_call_inside_cdn_wrappers(body) {
                Some((initialized, tag)) => {
                    wrapped += usize::from(initialized);
                    calls.push(tag);
                }
                None => panic!("the engine sent {constructor:#010x} to the CDN: {body:02x?}"),
            }
        }
    }
    assert!(wrapped >= 1, "the first call carried the anonymous initConnection");
    for tag in [1, 2, 3] {
        assert!(calls.contains(&tag), "call {tag} reached the CDN: {calls:?}");
    }
}

/// tdlib never runs PFS on a CDN session: a CDN key is never bound, and auth.bindTempAuthKey is not a
/// method a CDN serves. A CDN session the host sets up with PFS still talks under its CDN key and sends
/// no temporary key handshake and no bind to the CDN.
#[test]
fn a_cdn_session_never_binds_a_temporary_key_even_when_the_host_asks_for_pfs() {
    let cdn_key = random_key(5202);
    let cdn = TestServer::start(
        vec![cdn_key.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 1);
    let mut cdn_setup = setup(cdn.address.port(), Some(&cdn_key), SessionRole::Cdn, CDN_DC);
    cdn_setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    let session = engine.create_session(cdn_setup);
    engine.send(session, request(1, 1));
    let done = collector.wait_completed(session, 1);
    let created =
        collector.of(session).iter().filter(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })).count();
    engine.shutdown();
    let (handshakes, temporary_keys, binds) =
        cdn.with_stats(|stats| (stats.handshakes, stats.temporary_keys, stats.binds));
    assert_eq!((handshakes, temporary_keys, binds, created), (0, 0, 0, 0), "PFS ran on the CDN");
    assert!(done, "the call went under the CDN key");
    assert_eq!(cdn.with_stats(|stats| stats.executed_with_key.clone()), vec![(1, cdn_key.id())]);
}

struct WebRig {
    engine: Engine,
    collector: Arc<Collector>,
    host: Arc<TestStreamHost>,
    session: SessionHandle,
    _dead: Blackhole,
}

impl WebRig {
    fn start(role: SessionRole) -> Self {
        let dead = Blackhole::start();
        let key = random_key(5501);
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector, 1);
        let host = Arc::new(TestStreamHost::default());
        host.refuse.store(true, Ordering::Relaxed);
        host.attach(&engine);
        let mut session_setup = setup(dead.address.port(), Some(&key), role, 2);
        session_setup.transport = TransportPreference::Auto;
        let session = engine.create_session(session_setup);
        engine.use_telegram_web(session, false);
        engine.send(session, request(1, 1));
        Self { engine, collector, host, session, _dead: dead }
    }

    fn targets(&self) -> Vec<String> {
        self.host.targets.lock().unwrap().iter().map(|target| format!("{}:{}", target.host, target.port)).collect()
    }

    fn attempts(&self) -> usize {
        self.collector
            .of(self.session)
            .iter()
            .filter(|event| matches!(event, EngineEvent::ConnectionDropped { .. } | EngineEvent::AddressResult { .. }))
            .count()
    }
}

/// The CDN's address comes from the host (a `cdn` dcOption from help.getConfig for the redirect's dc_id).
/// The engine adds no route of its own for a CDN: asked to use Telegram Web, as the host does for every
/// session, a CDN session whose configured address gets no answer never reaches out to a web front,
/// while a session of another role on a dead address does.
#[test]
fn a_cdn_session_never_leaves_the_addresses_the_host_configured() {
    let worker = WebRig::start(SessionRole::Worker { requires_auth_token: false });
    let cdn = WebRig::start(SessionRole::Cdn);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && worker.targets().is_empty() {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(3));
    let (worker_targets, cdn_targets, cdn_attempts) = (worker.targets(), cdn.targets(), cdn.attempts());
    worker.engine.shutdown();
    cdn.engine.shutdown();
    assert!(
        worker_targets.iter().any(|target| target.contains("web.telegram.org")),
        "control: a worker on a dead address tries Telegram Web: {worker_targets:?}"
    );
    assert!(cdn_attempts > 0, "the CDN session tried its configured address");
    assert!(cdn_targets.is_empty(), "a CDN session went to {cdn_targets:?}, not the address the host gave");
}

/// Media sessions (downloads, uploads) are sessions of their own: each runs on its own connection
/// with its own session id, and with the host's environment asking for no updates every call it sends
/// is wrapped in invokeWithoutUpdates, while the main session's calls are not.
#[test]
fn media_sessions_run_on_their_own_connections_and_ask_for_no_updates() {
    let key = random_key(6001);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector, 2);
    let main = engine.create_session(setup(server.address.port(), Some(&key), SessionRole::Main, 2));
    let mut media_setup =
        setup(server.address.port(), Some(&key), SessionRole::Worker { requires_auth_token: false }, 2);
    media_setup.environment = Some(environment(true));
    let media = engine.create_session(media_setup);
    for id in 1..=3u64 {
        engine.send(main, request(id, id as u32));
        engine.send(media, request(10 + id, 10 + id as u32));
    }
    for id in 1..=3u64 {
        assert!(collector.wait_completed(main, id));
        assert!(collector.wait_completed(media, 10 + id));
    }
    let (connections, sessions, without_updates) =
        server.with_stats(|stats| (stats.connections, stats.session_ids.len(), stats.without_updates));
    engine.shutdown();
    assert!(connections >= 2, "the media session shared the main session's connection");
    assert!(sessions >= 2);
    assert_eq!(without_updates, 3, "every media call, and only those, asked for no updates");
}
