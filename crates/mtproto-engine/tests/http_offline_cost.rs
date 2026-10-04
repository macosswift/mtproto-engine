//! Review round 7: its own binary, so the process's CPU time measures nothing but this engine.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
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

fn start_cutter() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = connections.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                let mut seen = Vec::new();
                loop {
                    let Ok(read) = stream.read(&mut buffer) else { return };
                    if read == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buffer[..read]);
                    if seen.windows(4).any(|window| window == b"\r\n\r\n") {
                        std::thread::sleep(Duration::from_millis(50));
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
            });
        }
    });
    (port, connections)
}

/// The host says the network is unavailable; the offline probe (every 30 s) reaches a route that
/// accepts the connection and then cuts the request. Measures the engine's CPU between probes.
fn offline_cpu(transport: TransportPreference) -> (f64, usize) {
    let (port, connections) = start_cutter();
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    engine.set_network_available(false);
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    let now = unix_seconds();
    setup.auth_key = Some(AuthKeyMaterial {
        key: random_key(7001),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
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
    std::thread::sleep(Duration::from_secs(33));
    let before = cpu_seconds();
    std::thread::sleep(Duration::from_secs(10));
    let cpu = (cpu_seconds() - before) / 10.0;
    let opened = connections.load(std::sync::atomic::Ordering::Relaxed);
    engine.shutdown();
    eprintln!("{transport:?}: {cpu:.2} cores between offline probes, {opened} connections reached the route");
    (cpu, opened)
}

#[test]
fn offline_probe_cut_by_a_middlebox_does_not_spin() {
    let mut results = Vec::new();
    for transport in std::env::var("R7_TRANSPORTS")
        .map(|v| {
            if v == "http" {
                vec![TransportPreference::Http]
            } else {
                vec![TransportPreference::Tcp, TransportPreference::Http]
            }
        })
        .unwrap_or(vec![TransportPreference::Tcp, TransportPreference::Http])
    {
        results.push((transport, offline_cpu(transport)));
    }
    for (transport, (cpu, opened)) in results {
        assert!(opened >= 1, "{transport:?}: the offline probe never reached the route");
        assert!(cpu < 0.02, "{transport:?}: {cpu:.2} cores while offline between probes");
    }
}
