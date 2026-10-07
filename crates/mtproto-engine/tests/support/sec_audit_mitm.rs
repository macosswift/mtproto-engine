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
    /// Plays back the server packets recorded so far, then sends the transport error and closes: a
    /// fake datacenter that has no key but kept an old conversation.
    ReplayThenForge(i32),
    /// Relays, but first sends these payload frames to the client, as an injection into the stream.
    InjectThenRelay(Vec<Vec<u8>>),
    /// Passes the client's frames to the server and drops every answer: the server runs the calls,
    /// the client never hears.
    UpOnly,
    /// Relays, but first sends these raw transport bytes (encrypted with the stream's obfuscation).
    RawThenRelay(Vec<u8>),
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
    client.set_nonblocking(false)?;
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
        Mode::RawThenRelay(bytes) => {
            let mut bytes = bytes.clone();
            to_client.encryptor.apply(&mut bytes);
            to_client.stream.write_all(&bytes)?;
        }
        Mode::Relay | Mode::UpOnly => {}
    }
    let answers = mode != Mode::UpOnly;

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
                            if answers {
                                to_client.send(&packet)?;
                            }
                        }
                        Incoming::TransportError(code) if answers => to_client.send(&code.to_le_bytes())?,
                        Incoming::TransportError(_) => {}
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
