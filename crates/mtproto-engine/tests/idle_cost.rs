//! Its own test binary, so that the process's CPU time measures nothing but the engine under test.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    completed: Mutex<usize>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        if matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. })) {
            *self.completed.lock().unwrap() += 1;
            self.condvar.notify_all();
        }
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, _message: &str) {}
}

impl Collector {
    fn wait_for(&self, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut completed = self.completed.lock().unwrap();
        while *completed < count {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            completed = self.condvar.wait_timeout(completed, deadline - now).unwrap().0;
        }
        true
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn request(id: u64, timeout_timer: bool) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(id as u32, &id.to_le_bytes()),
        flags: RequestFlags { timeout_timer, ..RequestFlags::default() },
        invoke_after: None,
    }
}

/// CPU seconds per second the process spends while a session waits out an outage that refuses every
/// fresh connection, with a timed request pending and an unroutable second address to race.
fn cost_of_waiting_out_an_outage() -> f64 {
    let key = random_key(95);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut profile = mtproto_netsim::Profile::perfect();
    profile.latency = Duration::from_millis(30);
    let sim = mtproto_netsim::NetSim::start(server.address, profile, 14).unwrap();
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![
            DcAddress { host: "127.0.0.1".into(), port: sim.address.port(), secret: None },
            DcAddress { host: "192.0.2.1".into(), port: 443, secret: None },
        ],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.online = true;
    let session = engine.create_session(setup);
    engine.send(session, request(1, false));
    assert!(collector.wait_for(1, Duration::from_secs(10)));
    sim.outage(Duration::from_secs(40));
    std::thread::sleep(Duration::from_secs(6));
    engine.send(session, request(2, true));
    std::thread::sleep(Duration::from_secs(1));
    let started = cpu_seconds();
    std::thread::sleep(Duration::from_secs(8));
    let cost = (cpu_seconds() - started) / 8.0;
    engine.shutdown();
    cost
}

#[test]
fn waiting_out_an_outage_costs_next_to_no_cpu() {
    let cost = cost_of_waiting_out_an_outage();
    assert!(cost < 0.03, "{cost:.3} CPU seconds per second while the connection was held");
}
