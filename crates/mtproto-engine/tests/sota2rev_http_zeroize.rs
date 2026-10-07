#![allow(dead_code, unused_imports)]
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
    SecretBytes, SessionHandle, SessionSetup, TransportPreference, unix_seconds,
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

fn run_large_calls_and_shut_down(setup: SessionSetup, watch: &freed_memory::Watch) {
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 2, ..EngineConfig::default() }, collector.clone()).unwrap();
    freed_memory::only_threads(freed_memory::is_engine_thread);
    watch.arm();
    watch.arm_every_thread();
    let session = engine.create_session(setup);
    for id in 1..=6u64 {
        let payload = vec![id as u8; 4096 << id];
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: call(id as u32, &payload),
                flags: RequestFlags::default(),
                invoke_after: None,
            },
        );
    }
    let completed = collector.wait_for_completions(6);
    engine.shutdown();
    drop(engine);
    watch.stop();
    assert!(completed, "the calls completed");
}

/// H-03, the part the sota2 patch left out (http_link.rs:276): the HTTP transport forwarded by an
/// authenticating HTTP proxy writes `Proxy-Authorization: Basic ...` into the connection's write buffer,
/// which grows with each body and is cleared, not wiped.
#[test]
fn http_forwarded_through_an_authenticating_proxy_leaves_no_credentials_in_freed_memory() {
    let key = random_key(311);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            http_proxy: Some(HttpProxyMode::ForwardOnly),
            http_proxy_credentials: Some(format!("user:{PASSWORD}")),
            ..Default::default()
        },
    );
    let mut config = setup(&server, Some(&key));
    config.transport = TransportPreference::Http;
    config.http_port = Some(80);
    config.proxy = Some(ProxyConfig::Http {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some(PASSWORD.into()),
    });
    config.addresses[0].host = "149.154.167.51".into();
    let basic = base64_encode(format!("user:{PASSWORD}").as_bytes());
    let mut watch = freed_memory::watch();
    watch.secret("proxy password", PASSWORD.as_bytes());
    watch.secret("Basic credentials", basic.as_bytes());
    run_large_calls_and_shut_down(config, &watch);
    assert!(server.with_stats(|stats| stats.http.requests) > 0, "the calls went over HTTP");
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

/// H-03, http_link.rs:424: the HTTP transport through an authenticating SOCKS5 proxy keeps the
/// username/password request in `socks_out` and frees the handshake's copy unwiped.
#[test]
fn http_through_an_authenticating_socks5_proxy_leaves_no_password_in_freed_memory() {
    let key = random_key(312);
    let server = TestServer::start(vec![key.clone()], ServerOptions { socks5: true, ..Default::default() });
    let mut config = setup(&server, Some(&key));
    config.transport = TransportPreference::Http;
    config.http_port = Some(server.address.port());
    config.proxy = Some(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: server.address.port(),
        username: Some("user".into()),
        password: Some(PASSWORD.into()),
    });
    config.addresses[0].host = "149.154.167.51".into();
    let mut watch = freed_memory::watch();
    watch.secret("socks5 password", PASSWORD.as_bytes());
    run_large_calls_and_shut_down(config, &watch);
    assert!(server.with_stats(|stats| stats.http.requests) > 0, "the calls went over HTTP");
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[((value >> (18 - 6 * index)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
