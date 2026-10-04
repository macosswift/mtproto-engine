//! Its own test binary, so that the process's CPU time measures nothing but the engine under test.
#![allow(unsafe_code)]
mod middlebox;

use std::sync::Arc;
use std::time::Duration;

use middlebox::{Action, Info};
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

struct Quiet;

impl EngineCallbacks for Quiet {
    fn on_event(&self, _session: SessionHandle, _event: EngineEvent) {}
    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("LOG {message}");
        }
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn measure(seconds: f64) -> f64 {
    let started = cpu_seconds();
    std::thread::sleep(Duration::from_secs_f64(seconds));
    (cpu_seconds() - started) / seconds
}

/// While the route check's req_pq waits for its answer (one round trip on a good path, a response
/// timeout on a bad one), the worker must sleep.
#[test]
fn the_worker_sleeps_while_the_route_check_is_answered() {
    let key = random_key(903);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let (port, _stats) = middlebox::start(
        server.address,
        Arc::new(|info: Info| {
            if !info.plain && info.encrypted_index == 0 {
                Action::Respond(404, b"<html>not here</html>".to_vec())
            } else if info.plain {
                Action::Hold
            } else {
                Action::Forward
            }
        }),
    );
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, Arc::new(Quiet)).unwrap();
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(
        session,
        RpcRequest {
            id: RequestId(1),
            body: call(1, &1u64.to_le_bytes()),
            flags: RequestFlags::default(),
            invoke_after: None,
        },
    );
    std::thread::sleep(Duration::from_millis(300));
    let cost = measure(2.5);
    engine.shutdown();
    eprintln!("CPU s/s while the route check is outstanding: {cost:.3}");
    assert!(cost < 0.05, "busy loop while the route check waits: {cost:.3} CPU s/s");
}
