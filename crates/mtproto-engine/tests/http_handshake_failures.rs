//! Review round 7: its own binary, so the process's CPU time measures nothing but this engine.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

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
            eprintln!("{:?} LOG {message}", Instant::now());
        }
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// The server's RSA key is not among the client's (an outdated key list, a test DC given prod keys):
/// every res_pq fails the handshake. Counts failed key creations in 5 s.
fn failed_handshakes(transport: TransportPreference, at_dh_params: bool) -> (usize, usize, f64) {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior {
                server_time: unix_seconds() as i32,
                foreign_fingerprint: !at_dh_params,
                fail_dh_params: at_dh_params,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = transport;
    setup.http_port = None;
    setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(Default::default()).public_key()],
        temporary_expires_in: None,
    });
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
    std::thread::sleep(Duration::from_secs(1));
    let count = || {
        collector
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::AuthKeyCreationFailed { .. }))
            .count()
    };
    let before = count();
    let cpu_before = cpu_seconds();
    std::thread::sleep(Duration::from_secs(5));
    let failed = count() - before;
    let cpu = (cpu_seconds() - cpu_before) / 5.0;
    let requests = server.with_stats(|stats| stats.http.requests);
    engine.shutdown();
    eprintln!("{transport:?}: {failed} failed key creations in 5 s, {requests} HTTP requests in all, {cpu:.2} cores");
    (failed, requests, cpu)
}

#[test]
fn a_handshake_failing_every_time_backs_off_over_http_as_over_tcp() {
    let (tcp, _, _) = failed_handshakes(TransportPreference::Tcp, false);
    let (http, requests, cpu) = failed_handshakes(TransportPreference::Http, false);
    assert!(
        http <= tcp * 2 + 10,
        "HTTP: {http} failed handshakes in 5 s ({requests} requests, {cpu:.2} cores); TCP: {tcp}"
    );
}

/// The same with the failure one step later (server_DH_params_fail): the valid res_pq before it
/// resets the HTTP open backoff every round.
#[test]
fn a_handshake_failing_at_its_second_step_backs_off_over_http_as_over_tcp() {
    let (tcp, _, _) = failed_handshakes(TransportPreference::Tcp, true);
    let (http, requests, cpu) = failed_handshakes(TransportPreference::Http, true);
    assert!(
        http <= tcp * 2 + 10,
        "HTTP: {http} failed handshakes in 5 s ({requests} requests, {cpu:.2} cores); TCP: {tcp}"
    );
}
