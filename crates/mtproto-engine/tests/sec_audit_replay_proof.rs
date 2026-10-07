use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
};
use mtproto_testserver::*;

#[allow(dead_code)]
mod mitm {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mtproto_core::crypto::{AesCtr, XorShiftRandom};
    use mtproto_core::transport::{
        FrameDecoder, Framing, Incoming, InputBuffer, accept_obfuscated_header, encode_frame, obfuscated_init,
    };

    /// What the on-path attacker does with each new connection.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Mode {
        /// Passes every frame both ways and records the server's packets.
        Relay,
        /// Answers with one transport error frame and closes, as a forged `-404` would.
        Forge(i32),
        /// Plays back the server packets recorded so far, then sends the transport error (none for 0) and
        /// closes: a fake datacenter that has no key but kept an old conversation.
        ReplayThenForge(i32),
        /// Relays, but first sends these payload frames to the client, as an injection into the stream.
        InjectThenRelay(Vec<Vec<u8>>),
    }

    struct Shared {
        mode: Mutex<Mode>,
        recorded: Mutex<Vec<Vec<u8>>>,
        generation: AtomicUsize,
        connections: AtomicUsize,
        stop: AtomicBool,
    }

    /// An on-path attacker between the engine and a server: it sees the obfuscation keys (no proxy secret
    /// hides them), so it can read, drop, replay and inject frames, but not decrypt MTProto packets.
    pub struct Mitm {
        pub address: SocketAddr,
        shared: Arc<Shared>,
    }

    impl Mitm {
        pub fn start(upstream: SocketAddr, mode: Mode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let shared = Arc::new(Shared {
                mode: Mutex::new(mode),
                recorded: Mutex::new(Vec::new()),
                generation: AtomicUsize::new(0),
                connections: AtomicUsize::new(0),
                stop: AtomicBool::new(false),
            });
            let accept_shared = shared.clone();
            std::thread::spawn(move || {
                let mut seed = 1u64;
                while !accept_shared.stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            accept_shared.connections.fetch_add(1, Ordering::SeqCst);
                            let shared = accept_shared.clone();
                            seed += 1;
                            std::thread::spawn(move || {
                                let _ = serve(stream, upstream, shared, seed);
                            });
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            });
            Self { address, shared }
        }

        /// New connections get `mode`; connections open now are cut.
        pub fn switch(&self, mode: Mode) {
            *self.shared.mode.lock().unwrap() = mode;
            self.shared.generation.fetch_add(1, Ordering::SeqCst);
        }

        pub fn connections(&self) -> usize {
            self.shared.connections.load(Ordering::SeqCst)
        }

        pub fn recorded(&self) -> usize {
            self.shared.recorded.lock().unwrap().len()
        }
    }

    impl Drop for Mitm {
        fn drop(&mut self) {
            self.shared.stop.store(true, Ordering::Relaxed);
            self.shared.generation.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn read_exact_header(stream: &mut TcpStream) -> std::io::Result<[u8; 64]> {
        let mut header = [0u8; 64];
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.read_exact(&mut header)?;
        Ok(header)
    }

    struct ToClient {
        stream: TcpStream,
        encryptor: AesCtr,
        framing: Framing,
        rng: XorShiftRandom,
    }

    impl ToClient {
        fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
            let mut out = Vec::new();
            encode_frame(self.framing, payload, false, &mut self.rng, &mut out);
            self.encryptor.apply(&mut out);
            self.stream.write_all(&out)
        }
    }

    fn serve(mut client: TcpStream, upstream: SocketAddr, shared: Arc<Shared>, seed: u64) -> std::io::Result<()> {
        let generation = shared.generation.load(Ordering::SeqCst);
        let mode = shared.mode.lock().unwrap().clone();
        let header = read_exact_header(&mut client)?;
        let Some(server_side) = accept_obfuscated_header(&header, None) else {
            return Ok(());
        };
        let framing = server_side.framing;
        let mut to_client = ToClient {
            stream: client.try_clone()?,
            encryptor: server_side.encryptor,
            framing,
            rng: XorShiftRandom::new(seed),
        };
        let mut from_client = server_side.decryptor;
        match &mode {
            Mode::Forge(code) => {
                to_client.send(&code.to_le_bytes())?;
                std::thread::sleep(Duration::from_millis(50));
                let _ = client.shutdown(Shutdown::Both);
                return Ok(());
            }
            Mode::ReplayThenForge(code) => {
                let recorded = shared.recorded.lock().unwrap().clone();
                for packet in recorded {
                    to_client.send(&packet)?;
                }
                to_client.send(&code.to_le_bytes())?;
                std::thread::sleep(Duration::from_millis(50));
                let _ = client.shutdown(Shutdown::Both);
                return Ok(());
            }
            Mode::InjectThenRelay(frames) => {
                for frame in frames {
                    to_client.send(frame)?;
                }
            }
            Mode::Relay => {}
        }

        let mut server = TcpStream::connect(upstream)?;
        server.set_nodelay(true)?;
        client.set_nodelay(true)?;
        let mut rng = XorShiftRandom::new(seed ^ 0x5555);
        let init = obfuscated_init(framing, server_side.dc_id, None, false, &mut rng);
        server.write_all(&init.header)?;
        let mut to_server_encryptor = init.encryptor;
        let mut from_server_decryptor = init.decryptor;

        let up_shared = shared.clone();
        let mut client_reader = client.try_clone()?;
        let mut server_writer = server.try_clone()?;
        client_reader.set_read_timeout(Some(Duration::from_millis(20)))?;
        let up = std::thread::spawn(move || {
            let decoder = FrameDecoder::new(framing);
            let mut buffer = InputBuffer::new();
            let mut chunk = [0u8; 16384];
            let mut rng = XorShiftRandom::new(seed ^ 0x7777);
            loop {
                if up_shared.generation.load(Ordering::SeqCst) != generation {
                    break;
                }
                match client_reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        let mut data = chunk[..read].to_vec();
                        from_client.apply(&mut data);
                        buffer.extend(&data);
                        while let Ok(Some((payload, quick_ack))) = decoder.decode_client_frame(&mut buffer) {
                            let mut out = Vec::new();
                            encode_frame(framing, &payload, quick_ack, &mut rng, &mut out);
                            to_server_encryptor.apply(&mut out);
                            if server_writer.write_all(&out).is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
            let _ = server_writer.shutdown(Shutdown::Both);
        });

        server.set_read_timeout(Some(Duration::from_millis(20)))?;
        let decoder = FrameDecoder::new(framing);
        let mut buffer = InputBuffer::new();
        let mut chunk = [0u8; 16384];
        loop {
            if shared.generation.load(Ordering::SeqCst) != generation {
                break;
            }
            match server.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    let mut data = chunk[..read].to_vec();
                    from_server_decryptor.apply(&mut data);
                    buffer.extend(&data);
                    while let Ok(Some(incoming)) = decoder.decode(&mut buffer) {
                        match incoming {
                            Incoming::Packet(packet) => {
                                shared.recorded.lock().unwrap().push(packet.clone());
                                to_client.send(&packet)?;
                            }
                            Incoming::TransportError(code) => to_client.send(&code.to_le_bytes())?,
                            Incoming::QuickAck(_) | Incoming::Nop => {}
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        let _ = up.join();
        Ok(())
    }
}
use mitm::{Mitm, Mode};

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
    fn wait<F: Fn(&[(SessionHandle, EngineEvent)]) -> bool>(&self, timeout: Duration, predicate: F) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            if predicate(&events) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }

    fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    fn since(&self, start: usize) -> Vec<EngineEvent> {
        self.events.lock().unwrap()[start..].iter().map(|(_, event)| event.clone()).collect()
    }
}

fn completions(events: &[(SessionHandle, EngineEvent)]) -> usize {
    events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))).count()
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup_through(address: std::net::SocketAddr, key: &AuthKey) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: address.ip().to_string(), port: address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.keep_connected = true;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);

/// A fake datacenter with no key replays server packets recorded from an earlier connection of the
/// same session: the engine takes the connection as one the server answered.
#[test]
fn replayed_server_packets_never_make_a_fake_datacenter_look_answered() {
    let key = random_key(9003);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let attacker = Mitm::start(server.address, Mode::Relay);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_through(attacker.address, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    assert!(attacker.recorded() > 0);
    let cut = collector.len();
    attacker.switch(Mode::ReplayThenForge(0));
    assert!(collector.wait(WAIT, |events| {
        events[cut..].iter().any(|(_, event)| matches!(event, EngineEvent::ConnectionDropped { .. }))
    }));
    let before = collector.len();
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(4));
    let during = collector.since(before);
    engine.shutdown();
    let answered_drops =
        during.iter().filter(|event| matches!(event, EngineEvent::ConnectionDropped { answered: true, .. })).count();
    let address_successes =
        during.iter().filter(|event| matches!(event, EngineEvent::AddressResult { success: true, .. })).count();
    let completed = during.iter().filter(|event| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))).count();
    eprintln!(
        "{answered_drops} drops reported answered, {address_successes} address successes, {completed} completions"
    );
    assert_eq!(completed, 0, "nothing can complete without the server");
    assert!(
        answered_drops == 0 && address_successes == 0,
        "a replay is not an answer: {answered_drops} answered drops, {address_successes} address successes"
    );
}
