//! A WebSocket front for tests: TLS 1.2 like Telegram's, relaying the stream to a test
//! server, with switches for what real fronts and middleboxes do to frames.
#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

const CERTIFICATE: &[u8] = include_bytes!("../../../mtproto-testserver/src/web_front/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("../../../mtproto-testserver/src/web_front/key.der");

#[derive(Default)]
pub struct Switches {
    /// A server ping every this many ms (0: none).
    pub ping_every_ms: AtomicU64,
    /// Each server payload split into this many fragments, a ping between each (0/1: none).
    pub fragments: AtomicUsize,
    /// Closes the WebSocket after this many ms without a client frame (0: never), as the fronts do
    /// after 91 s.
    pub idle_close_ms: AtomicU64,
    /// After this many server payloads, sends half a message and then a close frame (0: never).
    pub close_mid_message_after: AtomicUsize,
    /// A ping frame of this many bytes once, right after the upgrade (control frames are 125 at most).
    pub huge_ping: AtomicUsize,
    /// Answers the upgrade but drops the connection once the client sent this many payload bytes
    /// (0: never), as a filter that lets a probe through and cuts real traffic.
    pub cut_after_client_bytes: AtomicUsize,
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub upgrades: usize,
    pub client_frames: Vec<f64>,
    pub idle_closes: usize,
    pub cuts: usize,
    pub https_requests: usize,
}

pub struct WsFront {
    pub address: SocketAddr,
    pub switches: Arc<Switches>,
    pub stats: Arc<Mutex<Stats>>,
    stop: Arc<AtomicBool>,
    started: Instant,
}

impl WsFront {
    pub fn start(backend: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERTIFICATE.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(PRIVATE_KEY.to_vec())),
            )
            .unwrap();
        let config = Arc::new(config);
        let switches = Arc::new(Switches::default());
        let stats = Arc::new(Mutex::new(Stats::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        {
            let (switches, stats, stop) = (switches.clone(), stats.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let (config, switches, stats, stop) =
                                (config.clone(), switches.clone(), stats.clone(), stop.clone());
                            std::thread::spawn(move || {
                                let _ = relay(stream, backend, config, &switches, &stats, &stop, started);
                            });
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Self { address, switches, stats, stop, started }
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }
}

impl Drop for WsFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn frame(opcode: u8, fin: bool, payload: &[u8], out: &mut Vec<u8>) {
    out.push(if fin { 0x80 } else { 0 } | opcode);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
}

fn flush(tls: &mut ServerConnection, client: &mut TcpStream, to_client: &mut Vec<u8>) -> std::io::Result<bool> {
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

fn relay(
    mut client: TcpStream,
    backend: SocketAddr,
    config: Arc<ServerConfig>,
    switches: &Switches,
    stats: &Mutex<Stats>,
    stop: &AtomicBool,
    started: Instant,
) -> std::io::Result<()> {
    client.set_nodelay(true)?;
    client.set_nonblocking(true)?;
    let mut tls = ServerConnection::new(config).map_err(std::io::Error::other)?;
    let mut head = Vec::new();
    let mut upgraded = false;
    let mut http_mode = false;
    let mut input: Vec<u8> = Vec::new();
    let mut to_server: Vec<u8> = Vec::new();
    let mut to_client: Vec<u8> = Vec::new();
    let mut server: Option<TcpStream> = None;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut last_client_frame = Instant::now();
    let mut last_ping = Instant::now();
    let mut payloads = 0usize;
    let mut client_bytes = 0usize;
    while !stop.load(Ordering::Relaxed) {
        let mut progress = false;
        match tls.read_tls(&mut client) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                progress = true;
                tls.process_new_packets().map_err(std::io::Error::other)?;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        loop {
            match tls.reader().read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => {
                    progress = true;
                    if http_mode {
                        to_server.extend_from_slice(&buffer[..read]);
                    } else if upgraded {
                        input.extend_from_slice(&buffer[..read]);
                    } else if head.is_empty() && buffer[..read].starts_with(b"POST ") {
                        http_mode = true;
                        stats.lock().unwrap().https_requests += 1;
                        to_server.extend_from_slice(&buffer[..read]);
                    } else {
                        head.extend_from_slice(&buffer[..read]);
                        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                            let request = String::from_utf8_lossy(&head[..end]).to_string();
                            let key = request
                                .split("\r\n")
                                .filter_map(|line| line.split_once(':'))
                                .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
                                .map(|(_, value)| value.trim().to_string())
                                .unwrap_or_default();
                            let accept = mtproto_engine::mtproto_core::transport::accept_for(&key);
                            to_client.extend_from_slice(
                                format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: binary\r\n\r\n").as_bytes(),
                            );
                            let huge = switches.huge_ping.load(Ordering::Relaxed);
                            if huge > 0 {
                                frame(0x9, true, &vec![0u8; huge], &mut to_client);
                            }
                            input.extend_from_slice(&head[end + 4..]);
                            head.clear();
                            upgraded = true;
                            last_client_frame = Instant::now();
                            stats.lock().unwrap().upgrades += 1;
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        while input.len() >= 2 {
            let (length, mut header) = match input[1] & 0x7f {
                126 if input.len() >= 4 => (usize::from(u16::from_be_bytes([input[2], input[3]])), 4),
                127 if input.len() >= 10 => (u64::from_be_bytes(input[2..10].try_into().unwrap()) as usize, 10),
                126 | 127 => break,
                short => (usize::from(short), 2),
            };
            if input.len() < header + 4 + length {
                break;
            }
            let mask = [input[header], input[header + 1], input[header + 2], input[header + 3]];
            header += 4;
            to_server
                .extend(input[header..header + length].iter().enumerate().map(|(index, byte)| byte ^ mask[index & 3]));
            input.drain(..header + length);
            client_bytes += length;
            last_client_frame = Instant::now();
            stats.lock().unwrap().client_frames.push(started.elapsed().as_secs_f64());
        }
        let cut = switches.cut_after_client_bytes.load(Ordering::Relaxed);
        if cut > 0 && client_bytes > cut {
            stats.lock().unwrap().cuts += 1;
            return Ok(());
        }
        let idle = switches.idle_close_ms.load(Ordering::Relaxed);
        if upgraded && idle > 0 && last_client_frame.elapsed() >= Duration::from_millis(idle) {
            stats.lock().unwrap().idle_closes += 1;
            frame(0x8, true, &[3, 232], &mut to_client);
            let _ = flush(&mut tls, &mut client, &mut to_client);
            return Ok(());
        }
        let ping_every = switches.ping_every_ms.load(Ordering::Relaxed);
        if upgraded && ping_every > 0 && last_ping.elapsed() >= Duration::from_millis(ping_every) {
            last_ping = Instant::now();
            frame(0x9, true, b"pingpong", &mut to_client);
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
            match backend.read(&mut buffer) {
                Ok(0) if http_mode => {
                    let _ = flush(&mut tls, &mut client, &mut to_client);
                    return Ok(());
                }
                Ok(0) => {
                    frame(0x8, true, &[3, 232], &mut to_client);
                    let _ = flush(&mut tls, &mut client, &mut to_client);
                    return Ok(());
                }
                Ok(read) if http_mode => {
                    progress = true;
                    to_client.extend_from_slice(&buffer[..read]);
                }
                Ok(read) => {
                    progress = true;
                    payloads += 1;
                    let data = &buffer[..read];
                    let close_after = switches.close_mid_message_after.load(Ordering::Relaxed);
                    if close_after > 0 && payloads >= close_after && data.len() >= 2 {
                        frame(0x2, false, &data[..data.len() / 2], &mut to_client);
                        frame(0x8, true, &[3, 232], &mut to_client);
                        let _ = flush(&mut tls, &mut client, &mut to_client);
                        return Ok(());
                    }
                    let pieces = switches.fragments.load(Ordering::Relaxed).max(1).min(data.len());
                    if pieces <= 1 {
                        frame(0x2, true, data, &mut to_client);
                    } else {
                        let size = data.len().div_ceil(pieces);
                        let chunks: Vec<&[u8]> = data.chunks(size).collect();
                        for (index, chunk) in chunks.iter().enumerate() {
                            let opcode = if index == 0 { 0x2 } else { 0x0 };
                            frame(opcode, index + 1 == chunks.len(), chunk, &mut to_client);
                            if index + 1 < chunks.len() {
                                frame(0x9, true, b"mid", &mut to_client);
                            }
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        progress |= flush(&mut tls, &mut client, &mut to_client)?;
        if !progress {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}
