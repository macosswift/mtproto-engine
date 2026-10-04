//! Review round 8: own binary, so the process's CPU time measures nothing but this engine.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    completed: Mutex<HashMap<u64, Instant>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if let EngineEvent::Rpc(RpcEvent::Completed { id, .. }) = event {
            self.completed.lock().unwrap().insert(id.0, Instant::now());
            self.condvar.notify_all();
        }
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("{:?} LOG {message}", Instant::now());
        }
    }
}

impl Collector {
    fn wait(&self, id: u64, timeout: Duration) -> Option<Instant> {
        let deadline = Instant::now() + timeout;
        let mut completed = self.completed.lock().unwrap();
        loop {
            if let Some(at) = completed.get(&id) {
                return Some(*at);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            completed = self.condvar.wait_timeout(completed, deadline - now).unwrap().0;
        }
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// A call the server never answers is in flight; the server answers another with bad_msg_notification
/// 17 (msg_id too high): the session drains the old session's answers for a grace of 1 s or so, then starts a new one and sends the call again.
/// Returns the engine's CPU over the 4 s after the 17 and how long the call took.
fn after_msg_id_too_high(transport: TransportPreference) -> (f64, f64) {
    let key = random_key(8201);
    let server = TestServer::start(vec![key.clone()], Default::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.online = true;
    setup.transport = transport;
    setup.http_port = None;
    let session = engine.create_session(setup);
    let send = |id: u64, body: Vec<u8>| {
        engine
            .send(session, RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None });
        Instant::now()
    };
    send(1, call(1, &1u64.to_le_bytes()));
    assert!(collector.wait(1, Duration::from_secs(10)).is_some(), "{transport:?}: first call");
    std::thread::sleep(Duration::from_secs(1));
    send(10, call(TAG_NEVER, &10u64.to_le_bytes()));
    std::thread::sleep(Duration::from_millis(500));
    let sent = send(2, bad_msg_call(17, false));
    let cpu_before = cpu_seconds();
    std::thread::sleep(Duration::from_secs(4));
    let cpu = (cpu_seconds() - cpu_before) / 4.0;
    let done = collector.wait(2, Duration::from_secs(30));
    let bad = server.with_stats(|stats| stats.bad_msgs_sent);
    engine.shutdown();
    let latency = done.map_or(f64::INFINITY, |at| at.duration_since(sent).as_secs_f64());
    eprintln!(
        "{transport:?}: {bad} bad_msg_notifications; {cpu:.2} cores over the 4 s after; the call took {latency:.1} s"
    );
    (cpu, latency)
}

#[test]
fn a_drained_session_reset_over_http_neither_spins_nor_waits_for_a_long_poll() {
    let (tcp_cpu, tcp_latency) = after_msg_id_too_high(TransportPreference::Tcp);
    let (http_cpu, http_latency) = after_msg_id_too_high(TransportPreference::Http);
    assert!(http_cpu < 0.05, "HTTP: {http_cpu:.2} cores after a 17 (TCP {tcp_cpu:.2})");
    assert!(
        http_latency < tcp_latency + 2.0,
        "HTTP: the call took {http_latency:.1} s after a 17 (TCP {tcp_latency:.1} s)"
    );
}
