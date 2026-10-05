use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

/// The name the front's self-signed certificate is for.
pub const WEB_FRONT_NAME: &str = "venus.web.test";

const CERTIFICATE: &[u8] = include_bytes!("web_front/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("web_front/key.der");

/// What the front saw.
#[derive(Debug, Default, Clone)]
pub struct WebFrontStats {
    pub connections: usize,
    pub handshakes: usize,
    pub server_names: Vec<String>,
    pub alpn: Vec<String>,
    /// The request line and Host header of every request, as `POST /apiw1 HTTP/1.1 @ venus.web.test`.
    pub requests: Vec<String>,
    /// WebSocket upgrades accepted, client frames relayed, and connections dropped for a frame
    /// Telegram's server does not take (a ping, pong, text or empty frame, or an unmasked one).
    pub websockets: usize,
    pub frames_in: usize,
    pub violations: usize,
}

/// Telegram Web's endpoints in front of a test server: TLS 1.2 only, like the real fronts, with a
/// self-signed certificate for `*.web.test`. HTTP inside is relayed to the server's own port; a
/// WebSocket upgrade (`binary` subprotocol only) carries the obfuscated stream to the same port.
pub struct WebFront {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    switches: Arc<Switches>,
    stats: Arc<Mutex<WebFrontStats>>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Switches {
    blackhole: AtomicBool,
    refuse_websocket: AtomicBool,
    close_with_last_bytes: AtomicBool,
    /// Bumped to drop every connection open now.
    generation: AtomicU64,
}

impl WebFront {
    pub fn start(backend: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERTIFICATE.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(PRIVATE_KEY.to_vec())),
            )
            .expect("certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let stop = Arc::new(AtomicBool::new(false));
        let switches = Arc::new(Switches::default());
        let stats = Arc::new(Mutex::new(WebFrontStats::default()));
        let thread = {
            let (stop, switches, stats) = (stop.clone(), switches.clone(), stats.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stats.lock().unwrap().connections += 1;
                            let (config, stop, switches, stats) =
                                (config.clone(), stop.clone(), switches.clone(), stats.clone());
                            std::thread::spawn(move || {
                                if switches.blackhole.load(Ordering::Relaxed) {
                                    hold_silently(stream, &stop);
                                } else {
                                    let _ = relay(stream, backend, config, &stop, &switches, &stats);
                                }
                            });
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self { address, stop, switches, stats, thread: Some(thread) }
    }

    /// Accepts connections but never answers on them, like a filter that drops this front too.
    pub fn set_blackhole(&self, enabled: bool) {
        self.switches.blackhole.store(enabled, Ordering::Relaxed);
    }

    /// Answers WebSocket upgrades with 404, like a proxy on the way that does not pass them.
    pub fn set_websocket_refused(&self, refused: bool) {
        self.switches.refuse_websocket.store(refused, Ordering::Relaxed);
    }

    /// When the server closes a WebSocket's connection, its last bytes and the close frame leave in one
    /// write, as from a front that sees the close at once (an error code, then the close).
    pub fn set_close_with_last_bytes(&self, enabled: bool) {
        self.switches.close_with_last_bytes.store(enabled, Ordering::Relaxed);
    }

    /// Drops every connection open now, as when the front restarts or a filter cuts them.
    pub fn drop_connections(&self) {
        self.switches.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> WebFrontStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Drop for WebFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A TCP listener that accepts and never answers: an address a filter drops silently.
pub struct Blackhole {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Blackhole {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::spawn(move || {
            let mut held: Vec<TcpStream> = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                if let Ok((stream, _)) = listener.accept() {
                    held.push(stream);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        Self { address, stop }
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn hold_silently(mut stream: TcpStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut sink = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        match stream.read(&mut sink) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(_) => return,
        }
    }
}

/// How much one direction buffers before the front stops reading from that side.
const RELAY_BUFFER_LIMIT: usize = 1024 * 1024;
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

enum Mode {
    /// Nothing decided yet: the first request head tells HTTP from a WebSocket upgrade.
    Undecided,
    Http,
    WebSocket {
        input: Vec<u8>,
    },
}

/// Relays one TLS connection, both directions at once without blocking either, as a real front does:
/// a client may pipeline a request while a large response is still on its way.
fn relay(
    client: TcpStream,
    backend: SocketAddr,
    config: Arc<ServerConfig>,
    stop: &AtomicBool,
    switches: &Switches,
    stats: &Mutex<WebFrontStats>,
) -> std::io::Result<()> {
    let generation = switches.generation.load(Ordering::Relaxed);
    let mut client = client;
    client.set_nodelay(true)?;
    client.set_nonblocking(true)?;
    let mut tls = ServerConnection::new(config).map_err(std::io::Error::other)?;
    let mut server: Option<TcpStream> = None;
    let mut mode = Mode::Undecided;
    let mut head = Vec::new();
    let mut to_server: Vec<u8> = Vec::new();
    let mut to_client: Vec<u8> = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut reported = false;
    while !stop.load(Ordering::Relaxed) && switches.generation.load(Ordering::Relaxed) == generation {
        let mut progress = false;
        if to_server.len() < RELAY_BUFFER_LIMIT {
            match tls.read_tls(&mut client) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    progress = true;
                    if let Err(error) = tls.process_new_packets() {
                        let _ = tls.write_tls(&mut client);
                        return Err(std::io::Error::other(error));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if !tls.is_handshaking() && !reported {
            reported = true;
            let mut stats = stats.lock().unwrap();
            stats.handshakes += 1;
            stats.server_names.push(tls.server_name().unwrap_or_default().to_string());
            stats.alpn.push(String::from_utf8_lossy(tls.alpn_protocol().unwrap_or_default()).to_string());
        }
        loop {
            match tls.reader().read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => {
                    progress = true;
                    match &mut mode {
                        Mode::Undecided => {
                            head.extend_from_slice(&buffer[..read]);
                            let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") else {
                                continue;
                            };
                            if head.starts_with(b"GET ") {
                                let request = String::from_utf8_lossy(&head[..end]).to_string();
                                let refused = switches.refuse_websocket.load(Ordering::Relaxed);
                                let Some(response) = upgrade(&request, refused, stats) else {
                                    tls.writer().write_all(
                                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    )?;
                                    while tls.wants_write() {
                                        let _ = tls.write_tls(&mut client);
                                    }
                                    return Ok(());
                                };
                                tls.writer().write_all(response.as_bytes())?;
                                mode = Mode::WebSocket { input: head[end + 4..].to_vec() };
                                head.clear();
                            } else {
                                let first = std::mem::take(&mut head);
                                note_requests(&mut head, &first, stats);
                                to_server.extend_from_slice(&first);
                                mode = Mode::Http;
                            }
                        }
                        Mode::Http => {
                            note_requests(&mut head, &buffer[..read], stats);
                            to_server.extend_from_slice(&buffer[..read]);
                        }
                        Mode::WebSocket { input } => input.extend_from_slice(&buffer[..read]),
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if let Mode::WebSocket { input } = &mut mode
            && !unframe_client(input, &mut to_server, stats)
        {
            return Ok(());
        }
        if !to_server.is_empty() && server.is_none() {
            let stream = TcpStream::connect(backend)?;
            stream.set_nodelay(true)?;
            stream.set_nonblocking(true)?;
            server = Some(stream);
        }
        if let Some(backend) = &mut server {
            if !to_server.is_empty() {
                match backend.write(&to_server) {
                    Ok(written) => {
                        progress = true;
                        to_server.drain(..written);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            if to_client.len() < RELAY_BUFFER_LIMIT {
                match backend.read(&mut buffer) {
                    Ok(0) => {
                        flush_client(&mut tls, &mut client, &mut to_client)?;
                        tls.send_close_notify();
                        let _ = tls.write_tls(&mut client);
                        return Ok(());
                    }
                    Ok(read) => {
                        progress = true;
                        match mode {
                            Mode::WebSocket { .. } => {
                                frame_server(&buffer[..read], &mut to_client);
                                if switches.close_with_last_bytes.load(Ordering::Relaxed)
                                    && closed_soon(backend, &mut buffer, &mut to_client)?
                                {
                                    to_client.extend_from_slice(&WEBSOCKET_CLOSE);
                                    flush_client(&mut tls, &mut client, &mut to_client)?;
                                    tls.send_close_notify();
                                    let _ = tls.write_tls(&mut client);
                                    return Ok(());
                                }
                            }
                            _ => to_client.extend_from_slice(&buffer[..read]),
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        progress |= flush_client(&mut tls, &mut client, &mut to_client)?;
        if !progress {
            std::thread::sleep(Duration::from_micros(500));
        }
    }
    Ok(())
}

/// A close frame with status 1000.
const WEBSOCKET_CLOSE: [u8; 4] = [0x88, 0x02, 0x03, 0xe8];

/// Whether the server closes within a moment, framing what it sends until then.
fn closed_soon(backend: &mut TcpStream, buffer: &mut [u8], to_client: &mut Vec<u8>) -> std::io::Result<bool> {
    let until = std::time::Instant::now() + Duration::from_millis(50);
    while std::time::Instant::now() < until {
        match backend.read(buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => frame_server(&buffer[..read], to_client),
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// Moves what the client is owed into TLS and TLS records to the socket, as far as they go.
fn flush_client(tls: &mut ServerConnection, client: &mut TcpStream, to_client: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut progress = false;
    if !to_client.is_empty() {
        let taken = tls.writer().write(to_client)?;
        if taken > 0 {
            progress = true;
            to_client.drain(..taken);
        }
    }
    while tls.wants_write() {
        match tls.write_tls(client) {
            Ok(_) => progress = true,
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(progress)
}

/// The 101 answer to a WebSocket upgrade, as Telegram's fronts give it; None (404) without the
/// `binary` subprotocol.
fn upgrade(request: &str, refused: bool, stats: &Mutex<WebFrontStats>) -> Option<String> {
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut key = None;
    let mut binary = false;
    let mut host = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("sec-websocket-key") {
                key = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                binary = value.split(',').any(|protocol| protocol.trim() == "binary");
            } else if name.eq_ignore_ascii_case("host") {
                host = value.to_string();
            }
        }
    }
    stats.lock().unwrap().requests.push(format!("{request_line} @ {host}"));
    let key = key.filter(|_| binary && !refused)?;
    let accept = {
        use base64::Engine;
        use mtproto_core::crypto::sha1;
        let mut material = key.into_bytes();
        material.extend_from_slice(ACCEPT_GUID.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(sha1(&material))
    };
    stats.lock().unwrap().websockets += 1;
    Some(format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
    ))
}

/// Client frames to the stream they carry. False when the client broke one of the rules Telegram's
/// server enforces by dropping the connection: frames must be masked binary ones with a payload, never
/// pings, pongs or text.
fn unframe_client(input: &mut Vec<u8>, out: &mut Vec<u8>, stats: &Mutex<WebFrontStats>) -> bool {
    loop {
        if input.len() < 2 {
            return true;
        }
        let opcode = input[0] & 0x0f;
        let masked = input[1] & 0x80 != 0;
        let (length, mut header) = match input[1] & 0x7f {
            126 if input.len() >= 4 => (usize::from(u16::from_be_bytes([input[2], input[3]])), 4),
            127 if input.len() >= 10 => (u64::from_be_bytes(input[2..10].try_into().unwrap()) as usize, 10),
            126 | 127 => return true,
            short => (usize::from(short), 2),
        };
        if !masked || length == 0 || !matches!(opcode, 0x0 | 0x2) {
            stats.lock().unwrap().violations += 1;
            return false;
        }
        if input.len() < header + 4 + length {
            return true;
        }
        let mask = [input[header], input[header + 1], input[header + 2], input[header + 3]];
        header += 4;
        out.extend(input[header..header + length].iter().enumerate().map(|(index, byte)| byte ^ mask[index & 3]));
        input.drain(..header + length);
        stats.lock().unwrap().frames_in += 1;
    }
}

/// Server bytes as one binary frame per read, as Telegram's server sends a packet per frame.
fn frame_server(payload: &[u8], out: &mut Vec<u8>) {
    out.push(0x82);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= usize::from(u16::MAX) {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
}

/// Collects request heads from the plaintext as it goes by, bodies skipped by their length.
fn note_requests(pending: &mut Vec<u8>, bytes: &[u8], stats: &Mutex<WebFrontStats>) {
    pending.extend_from_slice(bytes);
    loop {
        let Some(end) = pending.windows(4).position(|window| window == b"\r\n\r\n") else {
            return;
        };
        let head = String::from_utf8_lossy(&pending[..end]).to_string();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut host = String::new();
        let mut length = 0usize;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("host") {
                    host = value.trim().to_string();
                } else if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        if pending.len() < end + 4 + length {
            return;
        }
        stats.lock().unwrap().requests.push(format!("{request_line} @ {host}"));
        pending.drain(..end + 4 + length);
    }
}
