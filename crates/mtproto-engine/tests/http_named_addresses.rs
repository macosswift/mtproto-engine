//! Review round 8: a name whose first address is unreachable.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
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
    fn wait_all(&self, ids: &[u64], timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut completed = self.completed.lock().unwrap();
        loop {
            if ids.iter().all(|id| completed.contains_key(id)) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            completed = self.condvar.wait_timeout(completed, deadline - now).unwrap().0;
        }
    }
}

/// A listener whose accept queue is full: SYNs to it are dropped, as on a route that goes nowhere.
fn blackhole(port: u16) -> (i32, Vec<TcpStream>) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    address.sin_family = libc::AF_INET as u8;
    address.sin_port = port.to_be();
    address.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let bound = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(bound, 0, "bind 127.0.0.1:{port}");
    assert_eq!(unsafe { libc::listen(fd, 1) }, 0);
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut filled = Vec::new();
    for _ in 0..16 {
        match TcpStream::connect_timeout(&target, Duration::from_millis(300)) {
            Ok(stream) => filled.push(stream),
            Err(_) => return (fd, filled),
        }
    }
    panic!("the accept queue never filled");
}

/// Forwards every connection on [::1]:port to the server, byte for byte.
fn forwarder(upstream: SocketAddr) -> u16 {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(client) = stream else { continue };
            let Ok(server) = TcpStream::connect(upstream) else { continue };
            let (mut client_read, mut server_write) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let (mut server_read, mut client_write) = (server, client);
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut client_read, &mut server_write);
                let _ = server_write.shutdown(std::net::Shutdown::Both);
            });
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut server_read, &mut client_write);
                let _ = client_write.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    port
}

fn latencies(transport: TransportPreference) -> (f64, Vec<f64>) {
    let key = random_key(8101);
    let server = TestServer::start(vec![key.clone()], Default::default());
    let port = forwarder(server.address);
    let (_fd, _filled) = blackhole(port);
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let now = unix_seconds();
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "localhost".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.online = true;
    setup.transport = transport;
    setup.http_port = None;
    let session = engine.create_session(setup);
    let send = |id: u64| {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: call(1, &id.to_le_bytes()),
                flags: RequestFlags::default(),
                invoke_after: None,
            },
        );
        Instant::now()
    };
    let started = send(1);
    assert!(collector.wait_all(&[1], Duration::from_secs(40)), "{transport:?}: the first call never completed");
    let warmup = collector.completed.lock().unwrap()[&1].duration_since(started).as_secs_f64();
    let mut results = Vec::new();
    for id in 2..=3u64 {
        std::thread::sleep(Duration::from_secs(56));
        let at = send(id);
        assert!(collector.wait_all(&[id], Duration::from_secs(40)), "{transport:?}: call {id} never completed");
        results.push(collector.completed.lock().unwrap()[&id].duration_since(at).as_secs_f64());
    }
    engine.shutdown();
    (warmup, results)
}

/// "localhost" resolves to 127.0.0.1 and ::1 here, the IPv4 address first. 127.0.0.1 is unreachable
/// (its SYNs are dropped), ::1 reaches the server. After the first call found the working address,
/// the session idles 56 s (its spare HTTP connection closes after 50 s idle) and makes one call, twice:
/// neither should wait for a connection to the dead address.
#[test]
fn calls_after_the_first_do_not_wait_on_the_dead_first_address() {
    let runs: Vec<_> = [TransportPreference::Tcp, TransportPreference::Http]
        .into_iter()
        .map(|transport| std::thread::spawn(move || (transport, latencies(transport))))
        .collect();
    let mut report = Vec::new();
    for run in runs {
        let (transport, (warmup, results)) = run.join().unwrap();
        let slow = results.iter().filter(|latency| **latency > 5.0).count();
        eprintln!("{transport:?}: first call {warmup:.1} s; calls after 56 s idle: {results:.1?}");
        report.push((transport, slow, results));
    }
    for (transport, slow, results) in report {
        assert_eq!(slow, 0, "{transport:?}: calls after the first took {results:.1?} s");
    }
}
