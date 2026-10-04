//! Review round 8: own binary, so the process's CPU time measures nothing but this engine.
#![allow(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, SessionHandle, SessionSetup,
    TransportPreference,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(Instant, EngineEvent)>>,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((Instant::now(), event));
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

fn read_message(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut scratch = vec![0u8; 65536];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                return Some(buffer.drain(..end + 4 + length).collect());
            }
        }
        let read = stream.read(&mut scratch).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
}

/// An HTTP/1.0-style route: every request is forwarded on its own upstream connection and the
/// client connection is closed right after the response, as `Connection: close` routes do.
fn start_one_shot_route(upstream: SocketAddr) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let Some(request) = read_message(&mut client, &mut buffer) else { return };
                let Ok(mut up) = TcpStream::connect(upstream) else { return };
                if up.write_all(&request).is_err() {
                    return;
                }
                let mut up_buffer = Vec::new();
                let Some(response) = read_message(&mut up, &mut up_buffer) else { return };
                let _ = client.write_all(&response);
                let _ = client.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    (port, connections)
}

/// The host says the network is unavailable; a session with no key yet probes every 30 s. The probe
/// reaches a route that closes each connection after its response: the key handshake's first step is
/// answered, the connection is gone, and the probe is over (no link, offline). Measures the engine's
/// CPU between 12 s and 22 s after the probe.
#[test]
fn an_offline_probe_that_starts_a_handshake_does_not_spin_the_worker() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let (port, connections) = start_one_shot_route(server.address);
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    engine.set_network_available(false);
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.key_generation = Some(KeyGeneration {
        public_keys: vec![ServerHandshake::new(Default::default()).public_key()],
        temporary_expires_in: None,
    });
    let created = Instant::now();
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
    while connections.load(Ordering::SeqCst) == 0 && created.elapsed() < Duration::from_secs(40) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let probed = created.elapsed();
    assert!(connections.load(Ordering::SeqCst) >= 1, "the offline probe never reached the route");
    std::thread::sleep(Duration::from_secs(12));
    let before = cpu_seconds();
    std::thread::sleep(Duration::from_secs(10));
    let cpu = (cpu_seconds() - before) / 10.0;
    let reached = connections.load(Ordering::SeqCst);
    let failed = collector
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, event)| matches!(event, EngineEvent::AuthKeyCreationFailed { .. }))
        .count();
    engine.shutdown();
    eprintln!(
        "probe at {:.1} s; {reached} route connections; {failed} failed key creations; {cpu:.2} cores 12-22 s after the probe",
        probed.as_secs_f64()
    );
    assert!(cpu < 0.05, "{cpu:.2} cores while offline between probes, with a handshake left between steps");
}
