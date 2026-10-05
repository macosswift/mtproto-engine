//! Its own test binary, so that the process's CPU time measures nothing but the engine under test.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
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

fn run(transport: TransportPreference, bind_error: &'static str, perm_seed: u64) -> (f64, usize, usize) {
    let server = TestServer::start(
        vec![random_key(400)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            refuse_binds: (!bind_error.is_empty()).then_some(bind_error),
            refuse_binds_code: Some(500),
            ..Default::default()
        },
    );
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, Arc::new(Quiet)).unwrap();
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: random_key(perm_seed),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup.transport = transport;
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
    std::thread::sleep(Duration::from_secs(4));
    let cost = measure(4.0);
    let binds = server.with_stats(|stats| stats.bind_failures.len());
    let temps = server.with_stats(|stats| stats.temporary_keys);
    engine.shutdown();
    (cost, binds, temps)
}

/// A bind refused with an error that is not about the key (500) is retried after 2^n s (up to 30 s);
/// the worker must sleep in between, with the session's queries held by the bind gate.
#[test]
fn the_worker_sleeps_between_bind_retries() {
    let mut worst: f64 = 0.0;
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let (cost, binds, temps) = run(transport, "REVIEW3_TRY_LATER", 400);
        eprintln!("{transport:?}: CPU {cost:.3} s/s between bind retries ({binds} refused binds, {temps} keys)");
        worst = worst.max(cost);
    }
    assert!(worst < 0.05, "busy loop between bind retries: {worst:.3} CPU s/s");
}

/// The permanent key is not the server's: after two refused binds PFS holds for 60 s. The worker must
/// sleep through the hold.
#[test]
fn the_worker_sleeps_while_an_unknown_permanent_key_is_held() {
    let mut worst: f64 = 0.0;
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let (cost, binds, temps) = run(transport, "", 999);
        eprintln!(
            "{transport:?}: CPU {cost:.3} s/s while the unknown permanent key is held ({binds} refused binds, {temps} keys)"
        );
        worst = worst.max(cost);
    }
    assert!(worst < 0.05, "busy loop while PFS is held: {worst:.3} CPU s/s");
}
