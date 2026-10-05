use std::net::SocketAddr;
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
    fn wait_completed(&self, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            let done = events
                .iter()
                .filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })))
                .count();
            if done >= count {
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

fn setup(datacenter: SocketAddr, key: &AuthKey, secret: &[u8]) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: datacenter.ip().to_string(), port: datacenter.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Auto;
    setup.proxy = Some(ProxyConfig::Web { host: "relay.web-proxy.test".into(), secret: secret.to_vec() });
    setup
}

fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(1, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn carried(secret: Vec<u8>, seed: u64) {
    let key = random_key(seed);
    let relay =
        TestServer::start(vec![key.clone()], ServerOptions { secret: Some(secret.clone()), ..Default::default() });
    let datacenter = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    *host.carrier_relay.lock().unwrap() = Some(relay.address);
    host.attach(&engine);
    let session = engine.create_session(setup(datacenter.address, &key, &secret));
    for id in 1..=3 {
        engine.send(session, request(id));
    }
    assert!(collector.wait_completed(3, Duration::from_secs(15)), "calls over the carrier");
    let big = RpcRequest {
        id: RequestId(9),
        body: sized_call(1_000_000),
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    engine.send(session, big);
    assert!(collector.wait_completed(4, Duration::from_secs(15)), "a megabyte over the carrier");
    let targets = host.targets.lock().unwrap().clone();
    assert!(!targets.is_empty());
    assert!(
        targets.iter().all(|target| target.carrier
            && target.tls_server_name.is_none()
            && target.host == datacenter.address.ip().to_string()
            && target.port == datacenter.address.port()),
        "every stream went to the carrier, naming the datacenter: {targets:?}"
    );
    assert!(relay.with_stats(|stats| stats.connections) >= 1);
    let tags = relay.with_stats(|stats| stats.obfuscation_dc_ids.clone());
    assert!(
        !tags.is_empty() && tags.iter().all(|tag| *tag == 2),
        "the relay reads the datacenter from the stream: {tags:?}"
    );
    engine.shutdown();
}

#[test]
fn a_web_proxy_carries_the_obfuscated_stream_over_the_hosts_carrier() {
    carried(vec![0x5a; 16], 9301);
}

#[test]
fn a_web_proxy_with_a_padded_secret_carries_the_stream_too() {
    let mut secret = vec![0xdd];
    secret.extend_from_slice(&[0x3c; 16]);
    carried(secret, 9302);
}

/// Without the host's carrier nothing connects: never straight to the datacenter, never over HTTP.
#[test]
fn without_a_carrier_a_web_proxy_session_fails_closed() {
    let key = random_key(9303);
    let datacenter = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(datacenter.address, &key, &[0x5a; 16]));
    engine.send(session, request(1));
    assert!(!collector.wait_completed(1, Duration::from_secs(5)));
    assert_eq!(datacenter.with_stats(|stats| stats.connections), 0, "nothing went to the datacenter directly");
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    assert!(!collector.wait_completed(1, Duration::from_secs(4)), "a host without a relay refuses the carrier");
    assert_eq!(datacenter.with_stats(|stats| stats.connections), 0);
    engine.shutdown();
}
