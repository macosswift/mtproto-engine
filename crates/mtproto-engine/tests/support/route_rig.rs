#![allow(dead_code, unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, WebEndpoint, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
pub struct Collector {
    pub events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    pub logs: Mutex<Vec<(Instant, String)>>,
    pub condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event));
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("{:?} LOG {message}", Instant::now());
        }
        self.logs.lock().unwrap().push((Instant::now(), message.to_string()));
    }
}

impl Collector {
    pub fn completed(&self, session: SessionHandle) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, event)| {
                *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))
            })
            .count()
    }

    pub fn wait_completed(&self, session: SessionHandle, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            let done = events
                .iter()
                .filter(|(handle, event)| {
                    *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))
                })
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

    pub fn logged(&self, text: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|(_, line)| line.contains(text))
    }

    pub fn count_logged(&self, text: &str) -> usize {
        self.logs.lock().unwrap().iter().filter(|(_, line)| line.contains(text)).count()
    }

    pub fn logged_after(&self, text: &str, after: Instant) -> bool {
        self.logs.lock().unwrap().iter().any(|(at, line)| *at >= after && line.contains(text))
    }

    pub fn memories(&self) -> Vec<Vec<u8>> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(session, event)| match event {
                EngineEvent::RouteMemory { memory } if session.0 == 0 => Some(memory.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn dump_logs(&self, filter: &str) {
        for (_, line) in self.logs.lock().unwrap().iter() {
            if line.contains(filter) {
                eprintln!("  {line}");
            }
        }
    }
}

pub fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

pub fn web_endpoint_at(port: u16) -> WebEndpoint {
    WebEndpoint {
        host: WEB_FRONT_NAME.into(),
        port,
        path: "/apiw1".into(),
        ws_path: "/apiws".into(),
        address: Some("127.0.0.1".into()),
    }
}

pub fn setup(
    address: SocketAddr,
    key: &AuthKey,
    transport: TransportPreference,
    web: Option<WebEndpoint>,
) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: address.ip().to_string(), port: address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = transport;
    setup.http_port = None;
    setup.web = web;
    setup
}

pub fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(1, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

pub fn tagged(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

pub fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

pub fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// The route memory the engine stores, for one network known to block TCP since `at`.
pub fn memory_blocking(network: &[u8], at: f64) -> Vec<u8> {
    let mut out = vec![1u8, 1, network.len() as u8];
    out.extend_from_slice(network);
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&0f64.to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out
}
