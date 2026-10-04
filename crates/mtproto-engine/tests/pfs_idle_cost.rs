//! Own test binary: the process's CPU time measures the engine under test only.
#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Quiet {
    events: Mutex<Vec<EngineEvent>>,
}

impl EngineCallbacks for Quiet {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push(event);
    }
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

fn run(transport: TransportPreference, ignore_binds: bool) -> (f64, usize, bool) {
    let server = TestServer::start(
        vec![random_key(400)],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ignore_binds,
            ..Default::default()
        },
    );
    let callbacks = Arc::new(Quiet::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, callbacks.clone()).unwrap();
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: random_key(400),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup.keep_connected = false;
    setup.idle_disconnect_after = Some(1.0);
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
    std::thread::sleep(Duration::from_millis(1500));
    engine.cancel(session, RequestId(1));
    std::thread::sleep(Duration::from_millis(500));
    let cost = measure(3.0);
    let connections = server.with_stats(|stats| stats.connections);
    let bound = callbacks
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, EngineEvent::Rpc(RpcEvent::TemporaryKeyBound)));
    engine.shutdown();
    (cost, connections, bound)
}

#[test]
fn a_cancelled_call_during_a_slow_bind_does_not_spin_the_worker() {
    let mut worst = 0.0f64;
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        for ignore_binds in [false, true] {
            let (cost, connections, bound) = run(transport, ignore_binds);
            eprintln!(
                "{transport:?} bind unanswered {ignore_binds}: CPU {:.1}% , {connections} connections, bound {bound}",
                cost * 100.0
            );
            if ignore_binds {
                worst = worst.max(cost);
            }
        }
    }
    assert!(worst < 0.05, "the worker burned {:.0}% CPU while a bind was pending on an idle session", worst * 100.0);
}
