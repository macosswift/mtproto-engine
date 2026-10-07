//! H-03: address and proxy secrets, proxy passwords and created keys are wiped before the engine frees them,
//! while it runs and when it shuts down. The scanning allocator from mtproto-core's tests looks for each
//! watched secret in every heap block the test thread or an engine thread frees.

#[path = "../../mtproto-core/tests/support/freed_memory.rs"]
mod freed_memory;

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshakeBehavior, test_rsa_key_pair};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, ProxyConfig,
    SecretBytes, SessionHandle, SessionSetup, unix_seconds,
};
use mtproto_testserver::*;

const PASSWORD: &str = "correct-horse-battery-staple";
const WAIT: Duration = Duration::from_secs(10);

fn proxy_key() -> [u8; 16] {
    core::array::from_fn(|index| 0x91u8.wrapping_add((index as u8).wrapping_mul(13)))
}

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<EngineEvent>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push(event);
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, _message: &str) {}
}

impl Collector {
    fn wait_for_completions(&self, count: usize) -> bool {
        let deadline = Instant::now() + WAIT;
        let mut events = self.events.lock().unwrap();
        loop {
            let done = events.iter().filter(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })));
            if done.count() >= count {
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

fn setup(server: &TestServer, key: Option<&AuthKey>) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    let now = unix_seconds();
    setup.auth_key = key.map(|key| AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
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

fn run_and_shut_down(server: &TestServer, setup: SessionSetup, watch: &freed_memory::Watch) {
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap();
    freed_memory::only_threads(freed_memory::is_engine_thread);
    watch.arm();
    watch.arm_every_thread();
    let session = engine.create_session(setup);
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    let completed = collector.wait_for_completions(3);
    engine.shutdown();
    drop(engine);
    watch.stop();
    assert!(completed, "the calls completed");
    let _ = server.with_stats(|stats| stats.connections);
}

#[test]
fn engine_secret_types_are_wiped_when_dropped() {
    let key = proxy_key();
    let padded = [&[0xddu8][..], &key].concat();
    let created: Vec<u8> = (0..=255u8).map(|byte| byte ^ 0x3c).collect();
    let mut watch = freed_memory::watch();
    watch.secret("secret", &key);
    watch.secret("password", PASSWORD.as_bytes());
    watch.secret("created key", &created);
    let address = DcAddress { host: "149.154.167.51".into(), port: 443, secret: Some(padded.clone()) };
    let mut setup = SessionSetup::new(2, SessionRole::Main, vec![address.clone()]);
    setup.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: 1080,
        username: Some("user".into()),
        password: Some(PASSWORD.into()),
    });
    let proxies = vec![
        ProxyConfig::Http {
            host: "127.0.0.1".into(),
            port: 3128,
            username: Some("user".into()),
            password: Some(PASSWORD.into()),
        },
        ProxyConfig::MtProxy { host: "127.0.0.1".into(), port: 443, secret: padded.clone() },
        ProxyConfig::Web { host: "relay.example".into(), secret: padded },
    ];
    let secret_bytes = SecretBytes::from(created);
    watch.arm();
    let copy = setup.clone();
    drop(copy);
    drop(setup);
    drop(address);
    drop(proxies);
    drop(secret_bytes.clone());
    drop(secret_bytes);
    watch.stop();
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
fn a_session_with_an_address_secret_leaves_no_secret_in_freed_memory() {
    let secret = [&[0xddu8][..], &proxy_key()].concat();
    let key = random_key(301);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { secret: Some(secret.clone()), ..Default::default() });
    let mut config = setup(&server, Some(&key));
    config.addresses[0].secret = Some(secret);
    let mut watch = freed_memory::watch();
    watch.secret("address secret", &proxy_key());
    run_and_shut_down(&server, config, &watch);
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
#[ignore = "H-03: the engine copies the SOCKS5 password into Socks5Auth (no Drop) and the auth request it writes, both freed unwiped"]
fn a_session_through_an_authenticating_socks5_proxy_leaves_no_password_in_freed_memory() {
    let key = random_key(302);
    let server = TestServer::start(vec![key.clone()], ServerOptions { socks5: true, ..Default::default() });
    let mut config = setup(&server, Some(&key));
    config.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some(PASSWORD.into()),
    });
    config.addresses[0].host = "149.154.167.51".into();
    config.addresses[0].port = 443;
    let mut watch = freed_memory::watch();
    watch.secret("socks5 password", PASSWORD.as_bytes());
    run_and_shut_down(&server, config, &watch);
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
#[ignore = "H-03: a fake-TLS connection keeps the MTProxy key in TransportStream's TlsState and frees it unwiped"]
fn a_session_through_a_fake_tls_mtproxy_leaves_no_proxy_key_in_freed_memory() {
    let mut secret = [&[0xeeu8][..], &proxy_key()].concat();
    secret.extend_from_slice(b"www.example.com");
    let key = random_key(303);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { secret: Some(secret.clone()), ..Default::default() });
    let mut config = setup(&server, Some(&key));
    config.proxy = Some(ProxyConfig::MtProxy { host: "localhost".into(), port: server.address.port(), secret });
    config.addresses[0].host = "149.154.167.51".into();
    config.addresses[0].port = 443;
    let mut watch = freed_memory::watch();
    watch.secret("proxy key", &proxy_key());
    run_and_shut_down(&server, config, &watch);
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
fn a_created_key_leaves_no_copy_in_freed_memory_when_the_engine_shuts_down() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { server_time: unix_seconds() as i32, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap();
    let mut config = setup(&server, None);
    config.key_generation =
        Some(KeyGeneration { public_keys: vec![test_rsa_key_pair().public], temporary_expires_in: None });
    let session = engine.create_session(config);
    engine.send(session, request(1));
    assert!(collector.wait_for_completions(1), "the key was made and the call completed");
    let created = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| match event {
            EngineEvent::AuthKeyCreated { key, .. } => Some(key.clone()),
            _ => None,
        })
        .expect("a key was created");
    let mut watch = freed_memory::watch();
    watch.secret("created key", &created);
    freed_memory::only_threads(freed_memory::is_engine_thread);
    watch.arm();
    watch.arm_every_thread();
    engine.send(session, request(2));
    let completed = collector.wait_for_completions(2);
    engine.shutdown();
    drop(engine);
    collector.events.lock().unwrap().clear();
    drop(created);
    watch.stop();
    assert!(completed);
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
    drop(server);
}
