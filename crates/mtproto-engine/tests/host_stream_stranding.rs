use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    StreamHost, StreamId, StreamTarget, TransportPreference, WebEndpoint, unix_seconds,
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
            eprintln!("LOG {message}");
        }
    }
}

impl Collector {
    fn wait_request(&self, id: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            if events.iter().any(
                |(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id),
            ) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }

    fn drops(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
            .count()
    }
}

const CHUNK: usize = 4 * 1024 * 1024 - 1;

enum Op {
    Write(Vec<u8>),
    Resume,
    Close,
}

/// Plain TCP to the server (no TLS), handing the engine what arrives in one burst once the socket is
/// quiet, so a big answer fills the receive window and pauses the stream.
#[derive(Default)]
struct BurstHost {
    engine: OnceLock<Engine>,
    streams: Mutex<HashMap<StreamId, Sender<Op>>>,
    delivered: Arc<Mutex<HashMap<StreamId, usize>>>,
    close_siblings_on_resume: AtomicBool,
    resumes: std::sync::atomic::AtomicUsize,
}

impl StreamHost for BurstHost {
    fn open(&self, stream: StreamId, target: &StreamTarget) {
        let engine = self.engine.get().unwrap().clone();
        let (sender, receiver) = channel();
        self.streams.lock().unwrap().insert(stream, sender);
        self.delivered.lock().unwrap().insert(stream, 0);
        let target = target.clone();
        let delivered = self.delivered.clone();
        std::thread::spawn(move || run(engine, stream, target, receiver, delivered));
    }

    fn write(&self, stream: StreamId, bytes: &[u8]) {
        if let Some(sender) = self.streams.lock().unwrap().get(&stream) {
            let _ = sender.send(Op::Write(bytes.to_vec()));
        }
    }

    fn close(&self, stream: StreamId) {
        self.delivered.lock().unwrap().remove(&stream);
        if let Some(sender) = self.streams.lock().unwrap().remove(&stream) {
            let _ = sender.send(Op::Close);
        }
    }

    fn resume(&self, stream: StreamId) {
        self.resumes.fetch_add(1, Ordering::Relaxed);
        if self.close_siblings_on_resume.swap(false, Ordering::Relaxed) {
            let engine = self.engine.get().unwrap();
            let siblings: Vec<StreamId> =
                self.streams.lock().unwrap().keys().copied().filter(|other| *other != stream).collect();
            for other in siblings {
                if let Some(sender) = self.streams.lock().unwrap().remove(&other) {
                    let _ = sender.send(Op::Close);
                }
                engine.stream_closed(other, None);
            }
        }
        if let Some(sender) = self.streams.lock().unwrap().get(&stream) {
            let _ = sender.send(Op::Resume);
        }
    }
}

fn run(
    engine: Engine,
    stream: StreamId,
    target: StreamTarget,
    receiver: Receiver<Op>,
    delivered: Arc<Mutex<HashMap<StreamId, usize>>>,
) {
    let address: SocketAddr = format!("{}:{}", target.host, target.port).parse().unwrap();
    let mut socket = match TcpStream::connect(address) {
        Ok(socket) => socket,
        Err(error) => {
            engine.stream_closed(stream, Some(error.to_string()));
            return;
        }
    };
    let _ = socket.set_nodelay(true);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(1)));
    engine.stream_opened(stream);
    let mut pending: Vec<u8> = Vec::new();
    let mut offset = 0;
    let mut last_data = Instant::now();
    let mut paused = false;
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        loop {
            match receiver.try_recv() {
                Ok(Op::Write(bytes)) => {
                    if socket.write_all(&bytes).is_err() {
                        engine.stream_closed(stream, Some("write".into()));
                        return;
                    }
                    engine.stream_sent(stream, bytes.len());
                }
                Ok(Op::Resume) => paused = false,
                Ok(Op::Close) | Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }
        match socket.read(&mut buffer) {
            Ok(0) => {
                engine.stream_closed(stream, None);
                return;
            }
            Ok(read) => {
                pending.extend_from_slice(&buffer[..read]);
                last_data = Instant::now();
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(error) => {
                engine.stream_closed(stream, Some(error.to_string()));
                return;
            }
        }
        if !paused && offset < pending.len() && last_data.elapsed() > Duration::from_millis(30) {
            while offset < pending.len() {
                let end = (offset + CHUNK).min(pending.len());
                let more = engine.stream_received(stream, &pending[offset..end]);
                if let Some(total) = delivered.lock().unwrap().get_mut(&stream) {
                    *total += end - offset;
                }
                offset = end;
                if !more {
                    paused = true;
                    break;
                }
            }
            if offset == pending.len() {
                pending.clear();
                offset = 0;
            }
        }
    }
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup(dead: SocketAddr, server: SocketAddr, key: &AuthKey) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: dead.ip().to_string(), port: dead.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.transport = TransportPreference::Http;
    setup.keep_connected = true;
    setup.online = true;
    setup.http_port = None;
    setup.web = Some(WebEndpoint {
        host: "venus.web.test".into(),
        port: server.port(),
        path: "/apiw1".into(),
        ws_path: String::new(),
        address: Some(server.ip().to_string()),
    });
    setup
}

fn scenario(trigger: bool) -> (bool, Duration, usize, usize, usize) {
    let key = random_key(9311 + u64::from(trigger));
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let host = Arc::new(BurstHost::default());
    let _ = host.engine.set(engine.clone());
    engine.set_stream_host(Some(host.clone()));
    let mut session_setup = setup(dead.address, server.address, &key);
    session_setup.addresses[0].secret = Some(vec![7; 16]);
    session_setup.role = SessionRole::Worker { requires_auth_token: false };
    session_setup.keep_connected = true;
    session_setup.online = false;
    let session = engine.create_session(session_setup);
    for id in 1..=8 {
        engine.send(
            session,
            RpcRequest {
                id: RequestId(id),
                body: call(TAG_SLOW, b"warm"),
                flags: RequestFlags::default(),
                invoke_after: None,
            },
        );
    }
    for id in 1..=8 {
        assert!(collector.wait_request(id, Duration::from_secs(10)), "warm-up {id}");
    }
    std::thread::sleep(Duration::from_millis(300));
    let streams = host.streams.lock().unwrap().len();
    assert!(streams >= 2, "the session keeps a sibling connection: {streams}");
    host.close_siblings_on_resume.store(trigger, Ordering::Relaxed);
    let drops_before = collector.drops();
    let started = Instant::now();
    engine.send(
        session,
        RpcRequest {
            id: RequestId(9),
            body: sized_call(4 * 1024 * 1024),
            flags: RequestFlags::default(),
            invoke_after: None,
        },
    );
    let done = collector.wait_request(9, Duration::from_secs(25));
    let elapsed = started.elapsed();
    let drops = collector.drops() - drops_before;
    let resumes = host.resumes.load(Ordering::Relaxed);
    engine.shutdown();
    (done, elapsed, drops, streams, resumes)
}

#[test]
fn a_big_answer_that_pauses_its_stream_arrives_at_once() {
    let (done, elapsed, drops, streams, resumes) = scenario(false);
    eprintln!("alone: done {done} after {elapsed:?}, {drops} drops, {streams} streams before, {resumes} resumes");
    assert!(done && elapsed < Duration::from_secs(3));
}

/// Data left buffered on one connection when an event for another connection of the session comes
/// first: the session has to come back for it. A paused stream gets nothing more from the host, so
/// nothing else may wake it; before the worker kept such a session on its list, the answer could stall
/// until the read timeout and be downloaded again (7.6 s here, against 60 ms).
#[test]
fn a_paused_answer_is_read_on_when_another_connection_closes_meanwhile() {
    let (done, elapsed, drops, streams, resumes) = scenario(true);
    eprintln!(
        "sibling closed: done {done} after {elapsed:?}, {drops} drops, {streams} streams before, {resumes} resumes"
    );
    assert!(done && elapsed < Duration::from_secs(3), "stranded: done {done} after {elapsed:?}, {drops} drops");
}
