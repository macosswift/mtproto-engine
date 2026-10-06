pub mod api;
pub mod chaos;
mod http;
mod web_front;

pub use http::{HttpStats, INLINE_RESEND_MAX};
pub use web_front::{Blackhole, WEB_FRONT_NAME, WebFront, WebFrontStats};

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{SecureRandom, XorShiftRandom};
use mtproto_core::message::read_auth_key_id;
use mtproto_core::msg_id::msg_id_time;
use mtproto_core::rpc::{INIT_CONNECTION, INPUT_CLIENT_PROXY, INVOKE_WITH_APNS_SECRET, INVOKE_WITH_RECAPTCHA};
use mtproto_core::test_support::server_peer::{self as sp, ServerPeer};
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_core::tl::{Reader, Writer, ids};
use mtproto_core::transport::{
    FrameDecoder, Framing, InputBuffer, ProxySecret, ServerObfuscation, TlsRecordReader, TlsRecordWriter,
    accept_obfuscated_header, encode_frame, server_hello_for_tests, verify_client_hello_for_tests,
};

pub const CALL: u32 = 0x7e57_0001;
pub const CALL_RESULT: u32 = 0x7e57_0002;

pub const TAG_FLOOD_ONCE: u32 = 1001;
pub const TAG_DROP_CONNECTION_ONCE: u32 = 1002;
pub const TAG_LARGE: u32 = 1003;
pub const TAG_NEVER: u32 = 1004;
pub const TAG_SERVER_ERROR_ONCE: u32 = 1005;
pub const TAG_SLOW: u32 = 1006;
pub const TAG_BAD_SALT_ONCE: u32 = 1007;
pub const TAG_KEY_UNKNOWN: u32 = 1008;
pub const TAG_NEW_SESSION: u32 = 1009;
pub const TAG_UNAUTHORIZED: u32 = 1010;
pub const TAG_UPDATE_PUSH: u32 = 1011;
pub const TAG_SIZED: u32 = 1012;
pub const TAG_TRANSPORT_ERROR_ONCE: u32 = 1013;
pub const TAG_BAD_MSG_ONCE: u32 = 1014;
pub const TAG_SERVER_PING: u32 = 1015;
pub const TAG_RESEND_REQ_ONCE: u32 = 1016;
pub const TAG_MSG_COPY: u32 = 1017;
pub const TAG_GARBAGE_SIBLINGS: u32 = 1018;
pub const TAG_GZIP: u32 = 1019;
pub const TAG_TRICKLE_ONCE: u32 = 1020;
pub const TAG_FORGED_404_ONCE: u32 = 1021;
/// An upload part: the answer carries only the number of bytes received.
pub const TAG_UPLOAD: u32 = 1022;
pub const SERVER_PING_ID: i64 = 0x5e57_9149;
pub const LARGE_SIZE: usize = 1024 * 1024;
pub const SERVER_SALT: i64 = 0x5a17;
const MAX_REMEMBERED_ANSWERS: usize = 16 * 1024;

pub fn call(tag: u32, payload: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(CALL);
    writer.write_u32(tag);
    writer.write_bytes(payload);
    writer.into_inner()
}

pub fn sized_call(size: u32) -> Vec<u8> {
    call(TAG_SIZED, &size.to_le_bytes())
}

pub fn transport_error_call(code: i32) -> Vec<u8> {
    call(TAG_TRANSPORT_ERROR_ONCE, &code.to_le_bytes())
}

pub fn bad_msg_call(code: i32, target_container: bool) -> Vec<u8> {
    let mut payload = code.to_le_bytes().to_vec();
    payload.extend_from_slice(&i32::from(target_container).to_le_bytes());
    call(TAG_BAD_MSG_ONCE, &payload)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeFault {
    TransportError(i32),
    Stall,
}

pub fn parse_result(body: &[u8]) -> Option<(u32, Vec<u8>)> {
    let mut reader = Reader::new(body);
    if reader.read_u32().ok()? != CALL_RESULT {
        return None;
    }
    let tag = reader.read_u32().ok()?;
    Some((tag, reader.read_bytes().ok()?.to_vec()))
}

#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    pub secret: Option<Vec<u8>>,
    pub socks5: bool,
    pub handshake: ServerHandshakeBehavior,
    pub handshake_faults: Vec<HandshakeFault>,
    pub clock_offset: f64,
    pub validate_msg_id_time: bool,
    pub datacenter_id: i32,
    pub api: Option<Arc<api::ApiWorld>>,
    pub chaos: Option<chaos::ChaosConfig>,
    pub reject_with: Option<i32>,
    /// HTTP keep-alive connections idle this long are closed; None is the real servers' ~90 s.
    pub http_idle_timeout: Option<f64>,
    /// The most an HTTP response carries; None is 1 MB.
    pub http_response_limit: Option<usize>,
    /// Refuses HTTP requests like a datacenter address reachable only over TCP.
    pub http_disabled: bool,
    /// How long an answer takes to be ready over HTTP; None is 5 ms.
    pub http_processing_delay: Option<f64>,
    /// Acts as an HTTP proxy in front of itself as well.
    pub http_proxy: Option<HttpProxyMode>,
    /// The `user:password` an emulated HTTP proxy demands.
    pub http_proxy_credentials: Option<String>,
    /// Every `auth.bindTempAuthKey` is refused with this error.
    pub refuse_binds: Option<&'static str>,
    /// The code `refuse_binds` answers with: 400 when not given.
    pub refuse_binds_code: Option<i32>,
    /// `auth.bindTempAuthKey` is never answered.
    pub ignore_binds: bool,
    /// `auth.bindTempAuthKey` for a temporary key bound before is refused with this error, as Telegram
    /// answers CONNECTION_NOT_INITED for a key another client bound and used without initConnection.
    pub refuse_rebinds: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProxyMode {
    /// CONNECT tunnels and forwarded requests.
    Both,
    /// Forwarded requests only; CONNECT is refused with 403 as many corporate proxies do.
    ForwardOnly,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub connections: usize,
    pub obfuscation_dc_ids: Vec<i16>,
    pub executions: HashMap<u32, usize>,
    pub init_connections: usize,
    pub without_updates: usize,
    pub invoke_after: usize,
    pub state_requests: usize,
    pub pings: usize,
    pub future_salts_requests: usize,
    pub handshakes: usize,
    pub closed_by_client: usize,
    pub client_pongs: usize,
    pub retransmissions: usize,
    pub retransmissions_in_container: usize,
    pub duplicate_msg_ids: usize,
    pub redelivered_answers: usize,
    pub chaos_injected: HashMap<&'static str, usize>,
    pub unique_executions: HashMap<(u32, u64), u32>,
    pub first_executions: HashMap<(u32, u64), (i64, i64)>,
    pub duplicate_records: Vec<String>,
    pub duplicate_executions: usize,
    pub bad_msgs_sent: usize,
    pub session_ids: HashSet<i64>,
    pub transport_errors_sent: usize,
    pub client_packets: usize,
    pub client_bytes: usize,
    pub loop_rejections: usize,
    pub dripped_packets: usize,
    pub dripped_bytes: usize,
    pub calls_per_packet: HashMap<usize, usize>,
    /// Packets that carried one message, by its constructor.
    pub lone_messages: HashMap<u32, usize>,
    pub http: HttpStats,
    pub proxy_tunnels: usize,
    pub proxy_refusals: usize,
    pub temporary_keys: usize,
    /// Each finished handshake's `dc` field, and whether it made a temporary key.
    pub handshake_dcs: Vec<(i32, bool)>,
    pub binds: usize,
    pub bind_failures: Vec<String>,
    pub perm_empty_errors: usize,
    pub expired_key_rejections: usize,
    /// The auth key ids `destroy_auth_key` arrived under.
    pub destroyed_keys: Vec<u64>,
    /// Each executed call's tag and the permanent key it ran under: the binding of the temporary key it
    /// came under, or that key itself.
    pub executed_under: Vec<(u32, u64)>,
    /// Each executed call's tag and the auth key id it arrived under.
    pub executed_with_key: Vec<(u32, u64)>,
}

/// A key made by a `p_q_inner_data_temp_dc` handshake: it expires, and API calls under it are refused
/// until it is bound to a permanent key.
#[derive(Debug, Clone, Copy)]
struct TempKey {
    expires_at: f64,
    bound_to: Option<u64>,
    /// Calls ran under the key. Telegram counts a key as initialized once a call wrapped in
    /// initConnection came under it; clients without API parameters (tests) never send one, so any call
    /// counts here.
    inited: bool,
    /// The connection, session and expiry of the last bind.
    bound_on: Option<(u64, i64, i32)>,
}

struct SessionState {
    peer: ServerPeer,
    received: HashSet<i64>,
    unacked: Vec<(i64, i32, Vec<u8>)>,
    answered_queries: HashMap<i64, i64>,
    answer_ids: HashMap<i64, i64>,
    clock_offset: f64,
    awaiting_retransmission: HashSet<i64>,
    sent_packets: VecDeque<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum RawHostile {
    Oversized,
    Truncated,
}

fn gzip_bomb_update() -> &'static [u8] {
    static BOMB: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BOMB.get_or_init(|| sp::gzip_packed(&sp::update(0x0bad_0003, &vec![0u8; 65 << 20])))
}

fn hostile_raw_frame(framing: Framing, kind: RawHostile) -> Vec<u8> {
    match (framing, kind) {
        (Framing::Abridged, RawHostile::Oversized) => vec![0x7f, 0xff, 0xff, 0xff],
        (_, RawHostile::Oversized) => 0x7fff_0000u32.to_le_bytes().to_vec(),
        (Framing::Abridged, RawHostile::Truncated) => {
            let mut frame = vec![0x7f, 0x00, 0x01, 0x00];
            frame.extend_from_slice(&[0x55; 10]);
            frame
        }
        (_, RawHostile::Truncated) => {
            let mut frame = 1000u32.to_le_bytes().to_vec();
            frame.extend_from_slice(&[0x55; 10]);
            frame
        }
    }
}

struct Shared {
    keys: HashMap<u64, AuthKey>,
    sessions: HashMap<i64, SessionState>,
    stats: Stats,
    salt: i64,
    previous_salt: Option<(i64, Instant)>,
    /// Time the client skipped on its virtual clock: the server's own timers (long polls, held answers)
    /// run that much ahead of the wall clock.
    skipped: Duration,
    last_salt_change: Option<Instant>,
    last_transport_flood: Option<Instant>,
    bad_salt_sent: bool,
    handshake_faults: VecDeque<HandshakeFault>,
    doomed: HashMap<(u32, u64), chaos::Fault>,
    retransmit_kills: HashMap<i64, u32>,
    lazy_sessions: HashSet<i64>,
    http: http::HttpShared,
    tcp_blackhole: bool,
    temp_keys: HashMap<u64, TempKey>,
}

pub struct TestServer {
    pub address: SocketAddr,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    options: ServerOptions,
}

impl TestServer {
    pub fn start(keys: Vec<AuthKey>, options: ServerOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let shared = Arc::new(Mutex::new(Shared {
            keys: keys.into_iter().map(|key| (key.id(), key)).collect(),
            sessions: HashMap::new(),
            stats: Stats::default(),
            salt: SERVER_SALT,
            previous_salt: None,
            skipped: Duration::ZERO,
            last_salt_change: None,
            last_transport_flood: None,
            bad_salt_sent: false,
            handshake_faults: options.handshake_faults.iter().copied().collect(),
            doomed: HashMap::new(),
            retransmit_kills: HashMap::new(),
            lazy_sessions: HashSet::new(),
            http: http::HttpShared::default(),
            tcp_blackhole: false,
            temp_keys: HashMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let shared = shared.clone();
            let stop = stop.clone();
            let options = options.clone();
            std::thread::spawn(move || {
                let mut seed = 1u64;
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            shared.lock().unwrap().stats.connections += 1;
                            let shared = shared.clone();
                            let stop = stop.clone();
                            let options = options.clone();
                            seed += 1;
                            std::thread::spawn(move || {
                                let _ = serve_connection(stream, shared, stop, options, seed);
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
        Self { address, shared, stop, thread: Some(thread), options }
    }

    /// Accepts TCP transport connections but never answers on them, like a filter that drops
    /// MTProto; HTTP keeps working.
    pub fn set_tcp_blackhole(&self, enabled: bool) {
        self.shared.lock().unwrap().tcp_blackhole = enabled;
    }

    /// Forgets every temporary key, as when they expire or the server loses them: the next packet
    /// under one is answered -404.
    pub fn drop_temporary_keys(&self) {
        let mut guard = self.shared.lock().unwrap();
        let ids: Vec<u64> = guard.temp_keys.keys().copied().collect();
        for id in ids {
            guard.temp_keys.remove(&id);
            guard.keys.remove(&id);
        }
    }

    /// Forgets which permanent keys the temporary ones were bound to: calls under them get
    /// AUTH_KEY_PERM_EMPTY until they are bound again.
    pub fn unbind_temporary_keys(&self) {
        for temp in self.shared.lock().unwrap().temp_keys.values_mut() {
            temp.bound_to = None;
        }
    }

    pub fn options(&self) -> &ServerOptions {
        &self.options
    }

    pub fn add_key(&self, key: AuthKey) {
        self.shared.lock().unwrap().keys.insert(key.id(), key);
    }

    pub fn remove_key(&self, id: u64) {
        self.shared.lock().unwrap().keys.remove(&id);
    }

    /// Moves the server's timers ahead as if `seconds` had passed, for a client on a virtual clock that
    /// just skipped that much: parked long polls and held answers come due on its time.
    pub fn skip_time(&self, seconds: f64) {
        let mut guard = self.shared.lock().unwrap();
        guard.skipped += Duration::from_secs_f64(seconds.max(0.0));
        guard.http.wake_all();
    }

    pub fn executions(&self, tag: u32) -> usize {
        self.shared.lock().unwrap().stats.executions.get(&tag).copied().unwrap_or(0)
    }

    pub fn with_stats<R>(&self, f: impl FnOnce(&Stats) -> R) -> R {
        f(&self.shared.lock().unwrap().stats)
    }

    pub fn keys(&self) -> Vec<AuthKey> {
        self.shared.lock().unwrap().keys.values().cloned().collect()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

struct Wire {
    stream: TcpStream,
    obfuscation: Option<ServerObfuscation>,
    tls: bool,
    tls_writer: TlsRecordWriter,
    tls_reader: TlsRecordReader,
    raw: InputBuffer,
    plain: InputBuffer,
    framing: Framing,
    rng: XorShiftRandom,
}

impl Wire {
    fn read_some(&mut self, stop: &AtomicBool) -> std::io::Result<bool> {
        let mut buffer = [0u8; 65536];
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(false);
            }
            match self.stream.read(&mut buffer) {
                Ok(0) => return Ok(false),
                Ok(read) => {
                    self.raw.extend(&buffer[..read]);
                    return Ok(true);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {
                    return Ok(true);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn decrypt_available(&mut self) -> std::io::Result<()> {
        let Some(obfuscation) = &mut self.obfuscation else {
            return Ok(());
        };
        let mut data = Vec::new();
        if self.tls {
            while self
                .tls_reader
                .read(&mut self.raw, &mut data)
                .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error.to_string()))?
            {}
        } else {
            data = self.raw.as_slice().to_vec();
            self.raw.consume(data.len());
        }
        obfuscation.decryptor.apply(&mut data);
        self.plain.extend(&data);
        Ok(())
    }

    fn send_frame(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = Vec::new();
        encode_frame(self.framing, payload, false, &mut self.rng, &mut frame);
        self.send_raw_frame(frame)
    }

    fn send_raw_frame(&mut self, mut frame: Vec<u8>) -> std::io::Result<()> {
        let obfuscation = self.obfuscation.as_mut().expect("obfuscation");
        obfuscation.encryptor.apply(&mut frame);
        if self.tls {
            let mut out = Vec::new();
            self.tls_writer.write(&frame, &mut out);
            self.stream.write_all(&out)
        } else {
            self.stream.write_all(&frame)
        }
    }

    fn send_frame_drip(&mut self, payload: &[u8], rng: &mut XorShiftRandom) -> std::io::Result<()> {
        let mut frame = Vec::new();
        encode_frame(self.framing, payload, false, &mut self.rng, &mut frame);
        let obfuscation = self.obfuscation.as_mut().expect("obfuscation");
        obfuscation.encryptor.apply(&mut frame);
        let bytes = if self.tls {
            let mut out = Vec::new();
            self.tls_writer.write(&frame, &mut out);
            out
        } else {
            frame
        };
        for chunk in bytes.chunks(1 + (rng.next_u64() % 48) as usize) {
            self.stream.write_all(chunk)?;
            self.stream.flush()?;
            std::thread::sleep(Duration::from_micros(500 + rng.next_u64() % 2500));
        }
        Ok(())
    }

    fn send_quick_ack(&mut self, token: u32) -> std::io::Result<()> {
        let frame = match self.framing {
            Framing::Abridged => (token | 0x8000_0000).to_be_bytes().to_vec(),
            _ => (token | 0x8000_0000).to_le_bytes().to_vec(),
        };
        self.send_raw_frame(frame)
    }
}

fn read_exact_raw(
    stream: &mut TcpStream,
    buffer: &mut InputBuffer,
    count: usize,
    stop: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    let mut chunk = [0u8; 4096];
    while buffer.len() < count {
        if stop.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(ErrorKind::Interrupted, "stopped"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "eof")),
            Ok(read) => buffer.extend(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    Ok(buffer.take(count))
}

fn socks5_accept(stream: &mut TcpStream, buffer: &mut InputBuffer, stop: &AtomicBool) -> std::io::Result<()> {
    let head = read_exact_raw(stream, buffer, 2, stop)?;
    let methods = read_exact_raw(stream, buffer, head[1] as usize, stop)?;
    if methods.contains(&2) {
        stream.write_all(&[5, 2])?;
        let version = read_exact_raw(stream, buffer, 2, stop)?;
        let _user = read_exact_raw(stream, buffer, version[1] as usize, stop)?;
        let password_len = read_exact_raw(stream, buffer, 1, stop)?;
        let password = read_exact_raw(stream, buffer, password_len[0] as usize, stop)?;
        if password == b"wrong" {
            stream.write_all(&[1, 1])?;
            return Err(std::io::Error::new(ErrorKind::PermissionDenied, "bad credentials"));
        }
        stream.write_all(&[1, 0])?;
    } else {
        stream.write_all(&[5, 0])?;
    }
    let request = read_exact_raw(stream, buffer, 4, stop)?;
    let address_len = match request[3] {
        1 => 4,
        4 => 16,
        3 => read_exact_raw(stream, buffer, 1, stop)?[0] as usize,
        _ => return Err(std::io::Error::new(ErrorKind::InvalidData, "address type")),
    };
    read_exact_raw(stream, buffer, address_len + 2, stop)?;
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])?;
    Ok(())
}

/// Emulates an HTTP proxy in front of the server. A CONNECT is answered and the stream then carries
/// whatever the client tunnels; anything else is a forwarded request served as is. False when the
/// connection is refused.
fn http_proxy_accept(
    stream: &mut TcpStream,
    buffer: &mut InputBuffer,
    stop: &AtomicBool,
    mode: HttpProxyMode,
    credentials: Option<&str>,
    shared: &Arc<Mutex<Shared>>,
) -> std::io::Result<bool> {
    let end = loop {
        if let Some(end) = buffer.as_slice().windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if stop.load(Ordering::Relaxed) || buffer.len() > 16 * 1024 {
            return Ok(false);
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(read) => buffer.extend(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    };
    let head = String::from_utf8_lossy(&buffer.as_slice()[..end]).to_string();
    if let Some(expected) = credentials {
        let encoded = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(expected.as_bytes())
        };
        let authorized = head.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("proxy-authorization:")
                && line.split_once(':').is_some_and(|(_, value)| value.trim() == format!("Basic {encoded}"))
        });
        if !authorized {
            shared.lock().unwrap().stats.proxy_refusals += 1;
            stream.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n",
            )?;
            return Ok(false);
        }
    }
    if !head.starts_with("CONNECT ") {
        return Ok(true);
    }
    if mode == HttpProxyMode::ForwardOnly {
        shared.lock().unwrap().stats.proxy_refusals += 1;
        stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(false);
    }
    buffer.consume(end + 4);
    shared.lock().unwrap().stats.proxy_tunnels += 1;
    stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    Ok(true)
}

fn serve_connection(
    mut stream: TcpStream,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    options: ServerOptions,
    seed: u64,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
    stream.set_nodelay(true)?;
    let mut raw = InputBuffer::new();
    if options.socks5 {
        socks5_accept(&mut stream, &mut raw, &stop)?;
    }
    if let Some(mode) = options.http_proxy
        && !http_proxy_accept(&mut stream, &mut raw, &stop, mode, options.http_proxy_credentials.as_deref(), &shared)?
    {
        return Ok(());
    }
    let secret = options.secret.as_ref().map(|secret| ProxySecret::from_binary(secret, true).expect("secret"));
    let tls = secret.as_ref().is_some_and(ProxySecret::emulate_tls);
    let proxy_key = secret.as_ref().map(ProxySecret::proxy_key);
    let mut rng = XorShiftRandom::new(seed);
    let header: [u8; 64];
    let mut tls_reader = TlsRecordReader::new();
    if tls {
        let record_header = read_exact_raw(&mut stream, &mut raw, 5, &stop)?;
        if record_header[0] != 0x16 {
            return Ok(());
        }
        let record_length = ((record_header[3] as usize) << 8) | record_header[4] as usize;
        let mut hello = record_header;
        hello.extend(read_exact_raw(&mut stream, &mut raw, record_length, &stop)?);
        if verify_client_hello_for_tests(&hello, proxy_key.as_ref().unwrap()).is_none() {
            return Ok(());
        }
        let response = server_hello_for_tests(&hello, proxy_key.as_ref().unwrap(), &mut rng);
        stream.write_all(&response)?;
        let prefix = read_exact_raw(&mut stream, &mut raw, 6, &stop)?;
        assert_eq!(prefix, b"\x14\x03\x03\x00\x01\x01");
        let mut collected = Vec::new();
        while collected.len() < 64 {
            if !tls_reader
                .read(&mut raw, &mut collected)
                .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error.to_string()))?
            {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => return Ok(()),
                    Ok(read) => raw.extend(&chunk[..read]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                    Err(error) => return Err(error),
                }
            }
        }
        header = collected[..64].try_into().unwrap();
        let rest = collected[64..].to_vec();
        let mut prefixed = InputBuffer::new();
        let mut obfuscation = accept_obfuscated_header(&header, proxy_key.as_ref()).expect("valid header");
        let mut rest = rest;
        obfuscation.decryptor.apply(&mut rest);
        prefixed.extend(&rest);
        let framing = obfuscation.framing;
        let wire = Wire {
            stream,
            obfuscation: Some(obfuscation),
            tls: true,
            tls_writer: {
                let mut writer = TlsRecordWriter::new();
                let mut sink = Vec::new();
                writer.write(&[], &mut sink);
                writer
            },
            tls_reader,
            raw,
            plain: prefixed,
            framing,
            rng,
        };
        return serve_frames(wire, shared, stop, options);
    }
    while raw.len() < 4 {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => raw.extend(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    if http::starts_like_http(&raw.as_slice()[..4]) {
        if options.http_disabled {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        return http::serve_http(stream, raw, shared, stop, options, seed);
    }
    if shared.lock().unwrap().tcp_blackhole {
        let mut chunk = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            match stream.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(error) => return Err(error),
            }
        }
        return Ok(());
    }
    let head = read_exact_raw(&mut stream, &mut raw, 64, &stop)?;
    header = head.try_into().unwrap();
    let Some(obfuscation) = accept_obfuscated_header(&header, proxy_key.as_ref()) else {
        return Ok(());
    };
    shared.lock().unwrap().stats.obfuscation_dc_ids.push(obfuscation.dc_id);
    let framing = obfuscation.framing;
    let mut wire = Wire {
        stream,
        obfuscation: Some(obfuscation),
        tls: false,
        tls_writer: TlsRecordWriter::new(),
        tls_reader,
        raw,
        plain: InputBuffer::new(),
        framing,
        rng,
    };
    wire.decrypt_available()?;
    serve_frames(wire, shared, stop, options)
}

struct Delayed {
    at: Instant,
    session_id: i64,
    body: Vec<u8>,
}

impl Shared {
    fn clock(&self) -> Instant {
        Instant::now() + self.skipped
    }
}

fn server_now(offset: f64) -> f64 {
    unix_now() + offset
}

fn serve_frames(
    wire: Wire,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    options: ServerOptions,
) -> std::io::Result<()> {
    let mut delayed: Vec<Delayed> = Vec::new();
    let result = serve_frames_inner(wire, shared.clone(), stop, options, &mut delayed);
    let mut guard = shared.lock().unwrap();
    for item in delayed {
        if let Some(session) = guard.sessions.get_mut(&item.session_id) {
            seal_tracked(session, &item.body, true);
        }
    }
    result
}

fn serve_frames_inner(
    mut wire: Wire,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    options: ServerOptions,
    delayed: &mut Vec<Delayed>,
) -> std::io::Result<()> {
    let decoder = FrameDecoder::new(wire.framing);
    let mut handshake: Option<ServerHandshake> = None;
    let mut handshake_stalled = false;
    let mut resent_for = Delivered::default();
    let mut chaos_rng = XorShiftRandom::new(options.chaos.as_ref().map_or(1, |chaos| chaos.seed) ^ wire.rng.next_u64());
    let connection = wire.rng.next_u64();
    let mut encrypted_packets = 0usize;
    let ambush = options.chaos.as_ref().is_some_and(|chaos| {
        chaos::ChaosConfig::chance(&mut chaos_rng, chaos.rate(chaos::Fault::AdaptiveReconnectAmbush))
    });
    let kill_rate = options.chaos.as_ref().map_or(0.0, |chaos| chaos.rate(chaos::Fault::AdaptiveKillOnRetransmit));
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let now = shared.lock().unwrap().clock();
        let (due, later): (Vec<Delayed>, Vec<Delayed>) = delayed.drain(..).partition(|item| item.at <= now);
        *delayed = later;
        for item in due {
            let packet = {
                let mut guard = shared.lock().unwrap();
                let Some(session) = guard.sessions.get_mut(&item.session_id) else {
                    continue;
                };
                seal_tracked(session, &item.body, true)
            };
            wire.send_frame(&packet)?;
        }

        let (packet, quick_ack) = match decoder.decode_client_frame(&mut wire.plain) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                if !wire.read_some(&stop)? {
                    shared.lock().unwrap().stats.closed_by_client += 1;
                    return Ok(());
                }
                wire.decrypt_available()?;
                continue;
            }
            Err(_) => return Ok(()),
        };
        let Some(auth_key_id) = read_auth_key_id(&packet) else {
            continue;
        };
        if auth_key_id == 0 {
            if handshake_stalled {
                continue;
            }
            let starts_handshake = mtproto_core::message::decode_plain_message(&packet)
                .ok()
                .and_then(|message| message.body.get(..4).map(|head| u32::from_le_bytes(head.try_into().unwrap())))
                == Some(ids::REQ_PQ_MULTI);
            if starts_handshake {
                let fault = shared.lock().unwrap().handshake_faults.pop_front();
                match fault {
                    Some(HandshakeFault::TransportError(code)) => {
                        shared.lock().unwrap().stats.transport_errors_sent += 1;
                        wire.send_frame(&code.to_le_bytes())?;
                        let _ = wire.stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                    Some(HandshakeFault::Stall) => {
                        handshake_stalled = true;
                        continue;
                    }
                    None => {}
                }
            }
            let reply = handshake
                .get_or_insert_with(|| ServerHandshake::new(options.handshake.clone()))
                .handle(&packet, &mut wire.rng);
            if let Some(reply) = reply {
                wire.send_frame(&reply)?;
            }
            if let Some(outcome) = handshake.as_ref().and_then(|h| h.outcome.clone()) {
                let mut guard = shared.lock().unwrap();
                guard.stats.handshakes += 1;
                register_key(&mut guard, &outcome, options.clock_offset);
                handshake = None;
            }
            continue;
        }
        if let Some(code) = options.reject_with {
            shared.lock().unwrap().stats.transport_errors_sent += 1;
            wire.send_frame(&code.to_le_bytes())?;
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        let key = usable_key(&mut shared.lock().unwrap(), auth_key_id, options.clock_offset);
        let Some(key) = key else {
            wire.send_frame(&(-404i32).to_le_bytes())?;
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        };
        let plaintext = decrypted_plaintext(&key, &packet);
        encrypted_packets += 1;
        let ambush_step = if ambush && encrypted_packets <= 3 { Some(encrypted_packets) } else { None };
        if quick_ack {
            let hash = mtproto_core::crypto::sha256_parts(&[&key.bytes()[88..120], &plaintext]);
            wire.send_quick_ack(u32::from_le_bytes(hash[..4].try_into().unwrap()) & 0x7fff_ffff)?;
        }
        let Reaction {
            session_id,
            outgoing,
            close_after,
            transport_error,
            stall,
            sealed_extra,
            hostile_frames,
            hostile_raw,
            hostile_quick_acks,
            resend,
            kill_now,
            drip,
            trickle,
        } = process_packet(
            &options,
            &shared,
            &mut resent_for,
            &mut chaos_rng,
            kill_rate,
            delayed,
            &key,
            auth_key_id,
            &packet,
            ambush_step,
            false,
            connection,
        );
        if kill_now {
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        if let Some(mode) = trickle {
            let mut guard = shared.lock().unwrap();
            if let Some(session) = guard.sessions.get_mut(&session_id) {
                for (body, content) in &outgoing {
                    seal_tracked(session, body, *content);
                }
            }
            drop(guard);
            return trickle_forever(&mut wire, mode, &stop, &mut chaos_rng);
        }
        if let Some(code) = transport_error {
            let mut guard = shared.lock().unwrap();
            if let Some(session) = guard.sessions.get_mut(&session_id) {
                for (body, content) in &outgoing {
                    seal_tracked(session, body, *content);
                }
            }
            drop(guard);
            wire.send_frame(&code.to_le_bytes())?;
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        let packets: Vec<Vec<u8>> = {
            let mut guard = shared.lock().unwrap();
            let session = guard.sessions.get_mut(&session_id).unwrap();
            let mut packets: Vec<Vec<u8>> =
                resend.iter().map(|(msg_id, seq, body)| session.peer.seal(*msg_id, *seq, body)).collect();
            for (body, content) in &outgoing {
                packets.push(seal_tracked(session, body, *content));
            }
            resent_for.answers.extend(session.unacked.iter().map(|(id, _, _)| *id));
            if resent_for.answers.len() > 4096 {
                let unacked: HashSet<i64> = session.unacked.iter().map(|(id, _, _)| *id).collect();
                resent_for.answers.retain(|id| unacked.contains(id));
            }
            packets.extend(sealed_extra);
            session.sent_packets.extend(packets.iter().cloned());
            while session.sent_packets.len() > 32 {
                session.sent_packets.pop_front();
            }
            packets
        };
        if let Some(duration) = stall {
            std::thread::sleep(duration);
        }
        for token in hostile_quick_acks {
            wire.send_quick_ack(token & 0x7fff_ffff)?;
        }
        for frame in hostile_frames {
            wire.send_frame(&frame)?;
        }
        if let Some(kind) = hostile_raw {
            wire.send_raw_frame(hostile_raw_frame(wire.framing, kind))?;
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        if drip {
            let mut guard = shared.lock().unwrap();
            guard.stats.dripped_packets += packets.len();
            guard.stats.dripped_bytes += packets.iter().map(Vec::len).sum::<usize>();
        }
        for packet in packets {
            if drip {
                wire.send_frame_drip(&packet, &mut chaos_rng)?;
            } else {
                wire.send_frame(&packet)?;
            }
        }
        if close_after {
            let _ = wire.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
    }
}

/// What a connection already carried: the sessions it re-sent their unacknowledged messages to on
/// their first packet, and every such message it sent since, so that answers the session got elsewhere
/// (an HTTP request, another connection) reach it with its next packet, as the real server pushes a
/// session's messages to the connection it uses.
#[derive(Default)]
pub(crate) struct Delivered {
    sessions: HashSet<i64>,
    answers: HashSet<i64>,
}

#[derive(Default)]
struct Reaction {
    session_id: i64,
    outgoing: Vec<(Vec<u8>, bool)>,
    close_after: bool,
    transport_error: Option<i32>,
    stall: Option<Duration>,
    sealed_extra: Vec<Vec<u8>>,
    hostile_frames: Vec<Vec<u8>>,
    hostile_raw: Option<RawHostile>,
    hostile_quick_acks: Vec<u32>,
    resend: Vec<(i64, i32, Vec<u8>)>,
    kill_now: bool,
    drip: bool,
    trickle: Option<i32>,
}

/// Runs one encrypted client packet through the server's session logic; the caller writes what it
/// returns to its own transport.
#[allow(clippy::too_many_arguments)]
fn process_packet(
    options: &ServerOptions,
    shared: &Arc<Mutex<Shared>>,
    resent_for: &mut Delivered,
    chaos_rng: &mut XorShiftRandom,
    kill_rate: f64,
    delayed: &mut Vec<Delayed>,
    key: &AuthKey,
    auth_key_id: u64,
    packet: &[u8],
    ambush_step: Option<usize>,
    http: bool,
    connection: u64,
) -> Reaction {
    let decoded = ServerPeer::new(key.clone(), unix_now()).decode(packet);
    let session_id = decoded.header.session_id;
    let mut outgoing: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut close_after = false;
    let mut transport_error: Option<i32> = None;
    let mut stall: Option<Duration> = None;
    let mut sealed_extra: Vec<Vec<u8>> = Vec::new();
    let mut hostile_frames: Vec<Vec<u8>> = Vec::new();
    let mut hostile_raw: Option<RawHostile> = None;
    let mut hostile_quick_acks: Vec<u32> = Vec::new();
    let mut resend: Vec<(i64, i32, Vec<u8>)> = Vec::new();
    let mut kill_now = false;
    let mut drip = false;
    let mut trickle: Option<i32> = None;
    {
        let mut guard = shared.lock().unwrap();
        let shared_ref = &mut *guard;
        let clock = shared_ref.clock();
        http::release_delayed(shared_ref);
        let salt = shared_ref.salt;
        let session = shared_ref.sessions.entry(session_id).or_insert_with(|| {
            let mut peer = ServerPeer::new(key.clone(), server_now(options.clock_offset));
            peer.session_id = session_id;
            peer.salt = salt;
            SessionState {
                peer,
                received: HashSet::new(),
                unacked: Vec::new(),
                answered_queries: HashMap::new(),
                answer_ids: HashMap::new(),
                clock_offset: options.clock_offset,
                awaiting_retransmission: HashSet::new(),
                sent_packets: VecDeque::new(),
            }
        });
        session.peer.server_time = server_now(session.clock_offset);
        session.peer.salt = salt;
        if !http {
            let first = resent_for.sessions.insert(session_id);
            if first && shared_ref.lazy_sessions.remove(&session_id) {
                resent_for.answers.extend(session.unacked.iter().map(|(id, _, _)| *id));
            } else {
                resend =
                    session.unacked.iter().filter(|(id, _, _)| !resent_for.answers.contains(id)).cloned().collect();
                resent_for.answers.extend(resend.iter().map(|(id, _, _)| *id));
            }
        }
        let stats = &mut shared_ref.stats;
        stats.session_ids.insert(session_id);
        stats.client_packets += 1;
        stats.client_bytes += packet.len();
        *stats.calls_per_packet.entry(decoded.messages.len()).or_insert(0) += 1;
        if let [message] = decoded.messages.as_slice() {
            *stats.lone_messages.entry(message.constructor()).or_insert(0) += 1;
        }
        let message_time = msg_id_time(decoded.header.msg_id);
        let server_time = server_now(session.clock_offset);
        let time_error = if !options.validate_msg_id_time {
            None
        } else if message_time < server_time - 300.0 {
            Some(16)
        } else if message_time > server_time + 30.0 {
            Some(17)
        } else {
            None
        };
        if let Some(code) = time_error {
            stats.bad_msgs_sent += 1;
            outgoing.push((sp::bad_msg_notification(decoded.header.msg_id, decoded.header.seq_no, code), false));
        } else if let Some(step @ 1..=2) = ambush_step {
            *stats.chaos_injected.entry(chaos::Fault::AdaptiveReconnectAmbush.name()).or_insert(0) += 1;
            if step == 1 {
                let fresh = salt.wrapping_add((chaos_rng.next_u64() >> 1) as i64 | 1);
                shared_ref.salt = fresh;
                shared_ref.previous_salt = None;
                outgoing.push((sp::bad_server_salt(decoded.header.msg_id, decoded.header.seq_no, fresh), false));
            } else {
                stats.bad_msgs_sent += 1;
                outgoing.push((sp::bad_msg_notification(decoded.header.msg_id, decoded.header.seq_no, 16), false));
            }
        } else if decoded.header.salt != salt
            && !shared_ref
                .previous_salt
                .is_some_and(|(previous, until)| previous == decoded.header.salt && Instant::now() < until)
        {
            outgoing.push((sp::bad_server_salt(decoded.header.msg_id, decoded.header.seq_no, salt), false));
        } else {
            if ambush_step == Some(3) {
                close_after = true;
            }
            let recovery_target = decoded.messages.iter().find_map(|message| {
                (session.received.contains(&message.msg_id) || message.constructor() == ids::MSGS_STATE_REQ)
                    .then_some(message.msg_id)
            });
            if let Some(target) = recovery_target
                && chaos::ChaosConfig::chance(chaos_rng, kill_rate)
            {
                let kills = shared_ref.retransmit_kills.entry(target).or_insert(0);
                if *kills < 3 {
                    *kills += 1;
                    *stats.chaos_injected.entry(chaos::Fault::AdaptiveKillOnRetransmit.name()).or_insert(0) += 1;
                    kill_now = true;
                }
            }
            for message in decoded.messages.iter().filter(|_| !kill_now) {
                if !session.received.insert(message.msg_id) {
                    stats.duplicate_msg_ids += 1;
                    let cached = session
                        .answer_ids
                        .get(&message.msg_id)
                        .and_then(|answer_id| session.unacked.iter().find(|(id, _, _)| id == answer_id).cloned());
                    if let Some(answer) = cached
                        && !resend.iter().any(|(id, _, _)| *id == answer.0)
                    {
                        stats.redelivered_answers += 1;
                        resend.push(answer);
                    }
                    continue;
                }
                if session.awaiting_retransmission.remove(&message.msg_id) {
                    stats.retransmissions += 1;
                    if message.container_id.is_some() {
                        stats.retransmissions_in_container += 1;
                    }
                }
                match message.constructor() {
                    ids::PONG => {
                        let ping_id = i64::from_le_bytes(message.body[12..20].try_into().unwrap());
                        if ping_id == SERVER_PING_ID {
                            stats.client_pongs += 1;
                        }
                    }
                    ids::PING | ids::PING_DELAY_DISCONNECT => {
                        stats.pings += 1;
                        let ping_id = i64::from_le_bytes(message.body[4..12].try_into().unwrap());
                        outgoing.push((sp::pong(message.msg_id, ping_id), true));
                    }
                    ids::GET_FUTURE_SALTS => {
                        stats.future_salts_requests += 1;
                        outgoing.push((future_salts_reply(message.msg_id, salt, session.clock_offset), true));
                    }
                    ids::MSGS_ACK => {
                        let acked = sp::read_vector_after_constructor(&message.body);
                        session.unacked.retain(|(id, _, _)| !acked.contains(id));
                    }
                    ids::MSGS_STATE_REQ => {
                        stats.state_requests += 1;
                        let asked = sp::read_vector_after_constructor(&message.body);
                        let info: Vec<u8> =
                            asked.iter().map(|id| if session.received.contains(id) { 4 } else { 2 }).collect();
                        outgoing.push((sp::msgs_state_info(message.msg_id, &info), true));
                    }
                    ids::MSG_RESEND_REQ | ids::MSG_RESEND_ANS_REQ => {
                        let asked = sp::read_vector_after_constructor(&message.body);
                        for entry in &session.unacked {
                            if asked.contains(&entry.0) {
                                resend.push(entry.clone());
                            }
                        }
                    }
                    ids::RPC_DROP_ANSWER => {}
                    ids::AUTH_BIND_TEMP_AUTH_KEY if options.ignore_binds => {}
                    ids::AUTH_BIND_TEMP_AUTH_KEY => {
                        let rebind = shared_ref.temp_keys.get(&auth_key_id).is_some_and(|temp| temp.bound_to.is_some());
                        let checked = match (options.refuse_binds, options.refuse_rebinds) {
                            (Some(error), _) => Err((options.refuse_binds_code.unwrap_or(400), error)),
                            (None, Some(error)) if rebind => Err((400, error)),
                            _ => check_bind(
                                &shared_ref.keys,
                                &mut shared_ref.temp_keys,
                                auth_key_id,
                                session_id,
                                message.msg_id,
                                &message.body,
                                connection,
                            )
                            .map_err(|error| (400, error)),
                        };
                        let reply = match checked {
                            Ok(()) => {
                                stats.binds += 1;
                                let mut writer = Writer::new();
                                writer.write_u32(0x997275b5);
                                sp::rpc_result(message.msg_id, &writer.into_inner())
                            }
                            Err((code, error)) => {
                                stats.bind_failures.push(error.to_string());
                                sp::rpc_error(message.msg_id, code, error)
                            }
                        };
                        outgoing.push((reply, true));
                        session.answered_queries.insert(message.msg_id, 0);
                    }
                    ids::DESTROY_AUTH_KEY => {
                        stats.destroyed_keys.push(auth_key_id);
                        let known = shared_ref.keys.remove(&auth_key_id).is_some();
                        shared_ref.temp_keys.remove(&auth_key_id);
                        shared_ref.temp_keys.retain(|_, temp| temp.bound_to != Some(auth_key_id));
                        let mut writer = Writer::new();
                        writer.write_u32(if known { ids::DESTROY_AUTH_KEY_OK } else { ids::DESTROY_AUTH_KEY_NONE });
                        outgoing.push((writer.into_inner(), false));
                    }
                    ids::HTTP_WAIT => {}
                    _ if shared_ref.temp_keys.get(&auth_key_id).is_some_and(|temp| temp.bound_to.is_none()) => {
                        stats.perm_empty_errors += 1;
                        outgoing.push((sp::rpc_error(message.msg_id, 401, "AUTH_KEY_PERM_EMPTY"), true));
                    }
                    _ => {
                        let (call, flags) = unwrap_wrappers(&message.body);
                        stats.init_connections += usize::from(flags.init_connection);
                        if let Some(temp) = shared_ref.temp_keys.get_mut(&auth_key_id) {
                            temp.inited = true;
                        }
                        stats.without_updates += usize::from(flags.without_updates);
                        stats.invoke_after += usize::from(flags.invoke_after);
                        let (tag, payload) = match call {
                            Some(Inner::Call(tag, payload)) => (tag, payload),
                            Some(Inner::Api(constructor, body)) => {
                                let reply = match &options.api {
                                    Some(world) => world.handle(options.datacenter_id, auth_key_id, constructor, &body),
                                    None => api::ApiReply::Error(400, "METHOD_INVALID".into()),
                                };
                                let body = match reply {
                                    api::ApiReply::Result(result) => sp::rpc_result(message.msg_id, &result),
                                    api::ApiReply::Error(code, text) => sp::rpc_error(message.msg_id, code, &text),
                                };
                                outgoing.push((body, true));
                                session.answered_queries.insert(message.msg_id, 0);
                                continue;
                            }
                            None => continue,
                        };
                        if tag == TAG_BAD_SALT_ONCE && !shared_ref.bad_salt_sent {
                            shared_ref.bad_salt_sent = true;
                            shared_ref.salt = salt.wrapping_add(1);
                            session.received.remove(&message.msg_id);
                            outgoing
                                .push((sp::bad_server_salt(message.msg_id, message.seq_no, shared_ref.salt), false));
                            continue;
                        }
                        let unique = (tag < TAG_FLOOD_ONCE && payload.len() >= 8)
                            .then(|| (tag, u64::from_le_bytes(payload[..8].try_into().unwrap())));
                        let doomed = unique.and_then(|key| shared_ref.doomed.get(&key).copied());
                        let fault = if doomed.is_some() {
                            doomed
                        } else if tag < TAG_FLOOD_ONCE {
                            options.chaos.as_ref().and_then(|chaos| chaos.roll(chaos_rng))
                        } else {
                            None
                        };
                        if let (Some(fault), Some(key)) = (fault, unique)
                            && chaos::Fault::LOOPS.contains(&fault)
                        {
                            if doomed.is_none() {
                                *stats.chaos_injected.entry(fault.name()).or_insert(0) += 1;
                                shared_ref.doomed.insert(key, fault);
                            }
                            stats.loop_rejections += 1;
                            session.received.remove(&message.msg_id);
                            let rejection = match fault {
                                chaos::Fault::HostileSaltLoop => {
                                    sp::bad_server_salt(message.msg_id, message.seq_no, shared_ref.salt)
                                }
                                chaos::Fault::HostileTimeLoop => {
                                    sp::bad_msg_notification(message.msg_id, message.seq_no, 16)
                                }
                                _ => sp::msg_resend_req(&[message.msg_id]),
                            };
                            outgoing.push((rejection, false));
                            continue;
                        }
                        if let Some(fault) = fault {
                            *stats.chaos_injected.entry(fault.name()).or_insert(0) += 1;
                            match fault {
                                chaos::Fault::DropBeforeExecution => {
                                    session.received.remove(&message.msg_id);
                                    close_after = true;
                                    continue;
                                }
                                chaos::Fault::ResendRequest => {
                                    session.received.remove(&message.msg_id);
                                    session.awaiting_retransmission.insert(message.msg_id);
                                    outgoing.push((sp::msg_resend_req(&[message.msg_id]), false));
                                    continue;
                                }
                                chaos::Fault::FloodWait => {
                                    outgoing.push((sp::rpc_error(message.msg_id, 420, "FLOOD_WAIT_1"), true));
                                    continue;
                                }
                                chaos::Fault::InternalError => {
                                    outgoing.push((sp::rpc_error(message.msg_id, 500, "INTERNAL_SERVER_ERROR"), true));
                                    continue;
                                }
                                chaos::Fault::TransportFlood
                                    if shared_ref
                                        .last_transport_flood
                                        .is_none_or(|at| at.elapsed() > Duration::from_secs(30)) =>
                                {
                                    shared_ref.last_transport_flood = Some(Instant::now());
                                    session.received.remove(&message.msg_id);
                                    transport_error = Some(-429);
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        let executed_under = shared_ref
                            .temp_keys
                            .get(&auth_key_id)
                            .map_or(auth_key_id, |temp| temp.bound_to.unwrap_or(0));
                        stats.executed_under.push((tag, executed_under));
                        stats.executed_with_key.push((tag, auth_key_id));
                        let count = {
                            let entry = stats.executions.entry(tag).or_insert(0);
                            *entry += 1;
                            *entry
                        };
                        if tag < TAG_FLOOD_ONCE && payload.len() >= 8 {
                            let key = u64::from_le_bytes(payload[..8].try_into().unwrap());
                            let entry = stats.unique_executions.entry((tag, key)).or_insert(0);
                            *entry += 1;
                            if *entry > 1 {
                                stats.duplicate_executions += 1;
                                let first = stats.first_executions.get(&(tag, key)).copied().unwrap_or((0, 0));
                                if stats.duplicate_records.len() < 64 {
                                    stats.duplicate_records.push(format!(
                                        "key {key}: first session {:x} msg {:x}, again session {:x} msg {:x} container {:?} fault {:?}",
                                        first.0,
                                        first.1,
                                        session_id,
                                        message.msg_id,
                                        message.container_id,
                                        fault.map(chaos::Fault::name)
                                    ));
                                }
                            } else {
                                stats.first_executions.insert((tag, key), (session_id, message.msg_id));
                            }
                        }
                        let reply = sp::rpc_result(message.msg_id, &result_body(tag, &payload));
                        if let Some(fault) = fault {
                            session.peer.server_time = server_now(session.clock_offset);
                            match fault {
                                chaos::Fault::DropAfterExecution => {
                                    let msg_id = session.peer.next_msg_id(true);
                                    session.unacked.push((msg_id, 1, reply));
                                    session.answer_ids.insert(message.msg_id, msg_id);
                                    close_after = true;
                                }
                                chaos::Fault::AdaptiveLazyRedelivery => {
                                    let msg_id = session.peer.next_msg_id(true);
                                    session.unacked.push((msg_id, 1, reply));
                                    session.answer_ids.insert(message.msg_id, msg_id);
                                    shared_ref.lazy_sessions.insert(session_id);
                                    close_after = true;
                                }
                                chaos::Fault::AdaptiveTimeWarp => {
                                    let magnitude = 600.0 + (chaos_rng.next_u64() % 3000) as f64;
                                    let delta = if chaos_rng.next_u64() & 1 == 0 { magnitude } else { -magnitude };
                                    session.clock_offset = (session.clock_offset + delta).clamp(-7200.0, 7200.0);
                                    session.peer.server_time = server_now(session.clock_offset);
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::AdaptiveSlowDrip => {
                                    drip = true;
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::AdaptiveTrickle => {
                                    trickle = Some((chaos_rng.next_u64() % 3) as i32);
                                    let msg_id = session.peer.next_msg_id(true);
                                    session.unacked.push((msg_id, 1, reply));
                                    session.answer_ids.insert(message.msg_id, msg_id);
                                }
                                chaos::Fault::RotateSalt => {
                                    shared_ref.salt = salt.wrapping_add((chaos_rng.next_u64() >> 1) as i64 | 1);
                                    shared_ref.previous_salt = None;
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::ExpireSalt => {
                                    let now = Instant::now();
                                    if shared_ref
                                        .last_salt_change
                                        .is_none_or(|at| now.duration_since(at) > Duration::from_secs(2))
                                    {
                                        shared_ref.previous_salt = Some((salt, now + Duration::from_secs(1)));
                                        shared_ref.salt = salt.wrapping_add((chaos_rng.next_u64() >> 1) as i64 | 1);
                                        shared_ref.last_salt_change = Some(now);
                                    }
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::UnknownSibling => {
                                    let first = session.peer.next_msg_id(true);
                                    let second = session.peer.next_msg_id(true);
                                    track_answer(session, second, &reply);
                                    outgoing.push((
                                        sp::container(&[
                                            (first, 1, sp::update(0x0bad_f00d, &[1, 2, 3, 4])),
                                            (second, 1, reply),
                                        ]),
                                        false,
                                    ));
                                }
                                chaos::Fault::SlowAnswer => delayed.push(Delayed {
                                    at: clock + Duration::from_millis(300 + chaos_rng.next_u64() % 1200),
                                    session_id,
                                    body: reply,
                                }),
                                chaos::Fault::DuplicateAnswer => {
                                    outgoing.push((reply.clone(), true));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::GzipAnswer => {
                                    let msg_id = session.peer.next_msg_id(true);
                                    track_answer(session, msg_id, &reply);
                                    let body = sp::rpc_result_gzipped(message.msg_id, &result_body(tag, &payload));
                                    let packet = session.peer.seal(msg_id, 1, &body);
                                    sealed_extra.push(packet);
                                }
                                chaos::Fault::MsgCopy => {
                                    let inner = session.peer.next_msg_id(true);
                                    track_answer(session, inner, &reply);
                                    outgoing.push((sp::msg_copy(inner, 1, &reply), false));
                                }
                                chaos::Fault::ServerPing => {
                                    outgoing.push((sp::server_ping(SERVER_PING_ID), false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::AckNoise => {
                                    let noise: Vec<i64> = (0..4).map(|_| chaos_rng.next_u64() as i64 & !3).collect();
                                    outgoing.push((sp::msgs_ack(&noise), false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::Stall => {
                                    stall = Some(Duration::from_millis(200 + chaos_rng.next_u64() % 600));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::NewSession => {
                                    outgoing.push((
                                        sp::new_session_created(
                                            message.msg_id,
                                            chaos_rng.next_u64() as i64,
                                            shared_ref.salt,
                                        ),
                                        true,
                                    ));
                                    outgoing.push((reply, true));
                                }
                                fault if fault.closes_connection() => {
                                    let msg_id = session.peer.next_msg_id(true);
                                    session.unacked.push((msg_id, 1, reply.clone()));
                                    session.answer_ids.insert(message.msg_id, msg_id);
                                    close_after = true;
                                    match fault {
                                        chaos::Fault::HostileGarbage => {
                                            let len = (64 + chaos_rng.next_u64() % 2000) as usize & !3;
                                            let mut junk = vec![0u8; len];
                                            chaos_rng.fill(&mut junk);
                                            hostile_frames.push(junk);
                                        }
                                        chaos::Fault::HostileBadMsgKey => {
                                            let mut packet = session.peer.seal(msg_id, 1, &reply);
                                            let index = 24 + chaos_rng.next_u64() as usize % (packet.len() - 24);
                                            packet[index] ^= 0x40;
                                            hostile_frames.push(packet);
                                        }
                                        chaos::Fault::HostileTransportCode
                                        | chaos::Fault::HostileTransportCodeThenGarbage => {
                                            let codes = [-1i32, -2, -100, -500, -9999, i32::MIN];
                                            let code = codes[chaos_rng.next_u64() as usize % codes.len()];
                                            hostile_frames.push(code.to_le_bytes().to_vec());
                                            if fault == chaos::Fault::HostileTransportCodeThenGarbage {
                                                let mut junk = vec![0u8; 256];
                                                chaos_rng.fill(&mut junk);
                                                hostile_frames.push(junk);
                                            }
                                        }
                                        chaos::Fault::HostileOversized => hostile_raw = Some(RawHostile::Oversized),
                                        _ => hostile_raw = Some(RawHostile::Truncated),
                                    }
                                }
                                chaos::Fault::HostileForeignSession => {
                                    let own = session.peer.session_id;
                                    session.peer.session_id = chaos_rng.next_u64() as i64;
                                    let id = session.peer.next_msg_id(false);
                                    hostile_frames.push(session.peer.seal(id, 1, &sp::update(0x0bad_0001, &[0; 8])));
                                    session.peer.session_id = own;
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileEvenMsgId => {
                                    let id = session.peer.next_msg_id(false) & !3;
                                    hostile_frames.push(session.peer.seal(id, 1, &sp::update(0x0bad_0002, &[0; 8])));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileFanOut => {
                                    let children: Vec<(i64, i32, Vec<u8>)> = (0..1024)
                                        .map(|_| {
                                            let answer = chaos_rng.next_u64() as i64 | 1;
                                            (session.peer.next_msg_id(false), 0, sp::msg_new_detailed_info(answer, 128))
                                        })
                                        .collect();
                                    outgoing.push((sp::container(&children), false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileGzipBomb => {
                                    outgoing.push((gzip_bomb_update().to_vec(), true));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileHugeVector => {
                                    let mut body = Writer::new();
                                    body.write_u32(ids::MSGS_ACK);
                                    body.write_u32(ids::VECTOR);
                                    body.write_i32(i32::MAX);
                                    body.write_i64(message.msg_id);
                                    outgoing.push((body.into_inner(), false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileSaltsFlood => {
                                    let now = server_now(session.clock_offset) as i32;
                                    let salts: Vec<(i32, i32, i64)> = (0..65_536)
                                        .map(|index| (now + index, now + index + 1800, chaos_rng.next_u64() as i64))
                                        .collect();
                                    let req = chaos_rng.next_u64() as i64 & !3;
                                    outgoing.push((sp::future_salts(req, now, &salts), false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileReplay => {
                                    if !session.sent_packets.is_empty() {
                                        let index = chaos_rng.next_u64() as usize % session.sent_packets.len();
                                        hostile_frames.push(session.sent_packets[index].clone());
                                    }
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileSaltStorm => {
                                    for _ in 0..64 {
                                        let bad = chaos_rng.next_u64() as i64 & !3;
                                        let salt = chaos_rng.next_u64() as i64;
                                        outgoing.push((sp::bad_server_salt(bad, 0, salt), false));
                                    }
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileUnknownResults => {
                                    for _ in 0..64 {
                                        let mut junk = vec![0u8; 1024];
                                        chaos_rng.fill(&mut junk);
                                        let body = sp::rpc_result(chaos_rng.next_u64() as i64 & !3, &junk);
                                        let id = session.peer.next_msg_id(true);
                                        sealed_extra.push(session.peer.seal(id, 1, &body));
                                    }
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileDeepNest => {
                                    let mut body = sp::update(0x0bad_0004, &[0; 8]);
                                    for depth in 0..24 {
                                        body = if depth % 2 == 0 {
                                            sp::gzip_packed(&body)
                                        } else {
                                            sp::msg_copy(session.peer.next_msg_id(false), 1, &body)
                                        };
                                    }
                                    outgoing.push((body, false));
                                    outgoing.push((reply, true));
                                }
                                chaos::Fault::HostileQuickAckNoise => {
                                    hostile_quick_acks.extend((0..8).map(|_| chaos_rng.next_u64() as u32));
                                    outgoing.push((reply, true));
                                }
                                _ => outgoing.push((reply, true)),
                            }
                            session.answered_queries.insert(message.msg_id, 0);
                            continue;
                        }
                        let payload_word = |index: usize| {
                            payload
                                .get(index * 4..index * 4 + 4)
                                .map(|bytes| i32::from_le_bytes(bytes.try_into().unwrap()))
                                .unwrap_or(0)
                        };
                        match tag {
                            TAG_TRANSPORT_ERROR_ONCE if count == 1 => {
                                session.received.remove(&message.msg_id);
                                stats.transport_errors_sent += 1;
                                transport_error = Some(payload_word(0));
                            }
                            TAG_BAD_MSG_ONCE if count == 1 => {
                                let target = if payload_word(1) == 1 {
                                    message.container_id.unwrap_or(message.msg_id)
                                } else {
                                    message.msg_id
                                };
                                session.received.remove(&message.msg_id);
                                stats.bad_msgs_sent += 1;
                                outgoing
                                    .push((sp::bad_msg_notification(target, message.seq_no, payload_word(0)), false));
                            }
                            TAG_SERVER_PING => {
                                outgoing.push((sp::server_ping(SERVER_PING_ID), false));
                                outgoing.push((reply, true));
                            }
                            TAG_RESEND_REQ_ONCE if count == 1 => {
                                session.received.remove(&message.msg_id);
                                session.awaiting_retransmission.insert(message.msg_id);
                                outgoing.push((sp::msg_resend_req(&[message.msg_id]), false));
                            }
                            TAG_MSG_COPY => {
                                session.peer.server_time = server_now(session.clock_offset);
                                let inner = session.peer.next_msg_id(true);
                                outgoing.push((sp::msg_copy(inner, 1, &reply), false));
                            }
                            TAG_GARBAGE_SIBLINGS => {
                                session.peer.server_time = server_now(session.clock_offset);
                                let ids_: Vec<i64> = (0..4).map(|_| session.peer.next_msg_id(false)).collect();
                                let truncated = sp::bad_msg_notification(message.msg_id, 1, 16)[..12].to_vec();
                                let mut http_wait = Writer::new();
                                mtproto_core::tl::mtproto::write_http_wait(&mut http_wait, 0, 0, 0);
                                let body = sp::container(&[
                                    (ids_[0], 1, sp::update(0xdead_beef, &[0; 8])),
                                    (ids_[1], 1, truncated),
                                    (ids_[2], 0, http_wait.into_inner()),
                                    (ids_[3], 1, reply),
                                ]);
                                outgoing.push((body, false));
                            }
                            TAG_GZIP => {
                                session.peer.server_time = server_now(session.clock_offset);
                                let first = session.peer.next_msg_id(false);
                                let second = session.peer.next_msg_id(true);
                                let body = sp::container(&[
                                    (first, 1, sp::gzip_packed(&sp::update(0x74ae4240, &tag.to_le_bytes()))),
                                    (second, 1, sp::rpc_result_gzipped(message.msg_id, &result_body(tag, &payload))),
                                ]);
                                outgoing.push((sp::gzip_packed(&body), false));
                            }
                            TAG_KEY_UNKNOWN => transport_error = Some(-404),
                            TAG_TRICKLE_ONCE if count == 1 => {
                                session.received.remove(&message.msg_id);
                                trickle = Some(payload_word(0));
                            }
                            TAG_FLOOD_ONCE if count == 1 => {
                                outgoing.push((sp::rpc_error(message.msg_id, 420, "FLOOD_WAIT_1"), true))
                            }
                            TAG_SERVER_ERROR_ONCE if count == 1 => {
                                outgoing.push((sp::rpc_error(message.msg_id, 500, "INTERNAL_SERVER_ERROR"), true))
                            }
                            TAG_UNAUTHORIZED => {
                                outgoing.push((sp::rpc_error(message.msg_id, 401, "AUTH_KEY_UNREGISTERED"), true))
                            }
                            TAG_FORGED_404_ONCE if count == 1 => {
                                outgoing.push((reply, true));
                                transport_error = Some(-404);
                            }
                            TAG_DROP_CONNECTION_ONCE if count == 1 => {
                                session.peer.server_time = server_now(session.clock_offset);
                                let msg_id = session.peer.next_msg_id(true);
                                session.unacked.push((msg_id, 1, reply));
                                close_after = true;
                            }
                            TAG_NEVER => {}
                            TAG_SLOW => delayed.push(Delayed {
                                at: clock + Duration::from_millis(300),
                                session_id,
                                body: reply,
                            }),
                            TAG_LARGE => {
                                let large = vec![0x42u8; LARGE_SIZE];
                                outgoing.push((sp::rpc_result(message.msg_id, &result_body(tag, &large)), true));
                            }
                            TAG_NEW_SESSION if count == 1 => {
                                outgoing.push((sp::new_session_created(message.msg_id + 4, 77, salt), true));
                                outgoing.push((reply, true));
                            }
                            TAG_SIZED => {
                                let size = payload
                                    .get(..4)
                                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
                                    .unwrap_or(0)
                                    .min(4 * 1024 * 1024);
                                let data = vec![(count & 0xff) as u8; size];
                                outgoing.push((sp::rpc_result(message.msg_id, &result_body(tag, &data)), true));
                            }
                            TAG_UPLOAD => {
                                let received = (payload.len() as u32).to_le_bytes();
                                outgoing.push((sp::rpc_result(message.msg_id, &result_body(tag, &received)), true));
                            }
                            TAG_UPDATE_PUSH => {
                                outgoing.push((sp::update(0x74ae4240, &tag.to_le_bytes()), true));
                                outgoing.push((reply, true));
                            }
                            _ => outgoing.push((reply, true)),
                        }
                        session.answered_queries.insert(message.msg_id, 0);
                    }
                }
            }
        }
    }
    Reaction {
        session_id,
        outgoing,
        close_after,
        transport_error,
        stall,
        sealed_extra,
        hostile_frames,
        hostile_raw,
        hostile_quick_acks,
        resend,
        kill_now,
        drip,
        trickle,
    }
}

fn register_key(shared: &mut Shared, outcome: &mtproto_core::test_support::ServerHandshakeOutcome, clock_offset: f64) {
    shared.stats.handshake_dcs.push((outcome.dc, outcome.expires_in.is_some()));
    shared.keys.insert(outcome.auth_key.id(), outcome.auth_key.clone());
    if let Some(expires_in) = outcome.expires_in {
        shared.stats.temporary_keys += 1;
        shared.temp_keys.insert(
            outcome.auth_key.id(),
            TempKey {
                expires_at: server_now(clock_offset) + f64::from(expires_in),
                bound_to: None,
                inited: false,
                bound_on: None,
            },
        );
    }
}

/// The key to decrypt with, unless it is a temporary key past its expiry, which the server forgets.
fn usable_key(shared: &mut Shared, auth_key_id: u64, clock_offset: f64) -> Option<AuthKey> {
    if shared.temp_keys.get(&auth_key_id).is_some_and(|temp| temp.expires_at <= server_now(clock_offset)) {
        shared.temp_keys.remove(&auth_key_id);
        shared.keys.remove(&auth_key_id);
        shared.stats.expired_key_rejections += 1;
        return None;
    }
    shared.keys.get(&auth_key_id).cloned()
}

/// `auth.bindTempAuthKey` as the documentation describes it: the inner message is encrypted with the
/// permanent key under MTProto 1.0 and carries the outer message's msg_id, seqno 0, and the
/// temporary key's id, the permanent key's id, the session and the expiry the outer query names.
fn check_bind(
    keys: &HashMap<u64, AuthKey>,
    temp_keys: &mut HashMap<u64, TempKey>,
    temp_key_id: u64,
    session_id: i64,
    msg_id: i64,
    body: &[u8],
    connection: u64,
) -> Result<(), &'static str> {
    let mut reader = Reader::new(&body[4..]);
    let perm_id = reader.read_i64().map_err(|_| "INPUT_REQUEST_INVALID")? as u64;
    let nonce = reader.read_i64().map_err(|_| "INPUT_REQUEST_INVALID")?;
    let expires_at = reader.read_i32().map_err(|_| "INPUT_REQUEST_INVALID")?;
    let encrypted = reader.read_bytes().map_err(|_| "INPUT_REQUEST_INVALID")?;
    let Some(temp) = temp_keys.get(&temp_key_id).copied() else {
        return Err("TEMP_AUTH_KEY_EMPTY");
    };
    let perm = keys.get(&perm_id).ok_or("ENCRYPTED_MESSAGE_INVALID")?;
    if temp_keys.contains_key(&perm_id) {
        return Err("ENCRYPTED_MESSAGE_INVALID");
    }
    let decrypted = mtproto_core::message::decrypt_message_v1(perm, encrypted, mtproto_core::crypto::Side::Client)
        .map_err(|_| "ENCRYPTED_MESSAGE_INVALID")?;
    let inner = <mtproto_core::tl::mtproto::BindAuthKeyInner as mtproto_core::tl::TlRead>::read_from(&mut Reader::new(
        decrypted.body(),
    ))
    .map_err(|_| "ENCRYPTED_MESSAGE_INVALID")?;
    let valid = decrypted.header.msg_id == msg_id
        && decrypted.header.seq_no == 0
        && inner.nonce == nonce
        && inner.temp_auth_key_id as u64 == temp_key_id
        && inner.perm_auth_key_id as u64 == perm_id
        && inner.temp_session_id == session_id
        && inner.expires_at == expires_at;
    if !valid {
        return Err("ENCRYPTED_MESSAGE_INVALID");
    }
    if f64::from(expires_at) > temp.expires_at + 5.0 {
        return Err("EXPIRES_AT_INVALID");
    }
    // As Telegram does: a key bound before is bound again (to any permanent key) once it carried
    // initConnection; before that, only to the same permanent key, on the connection or the session of
    // its last bind and with the same expiry, and CONNECTION_NOT_INITED otherwise.
    // TEMP_AUTH_KEY_ALREADY_BOUND never comes.
    if temp.bound_to.is_some()
        && !temp.inited
        && !(temp.bound_to == Some(perm_id)
            && temp.bound_on.is_some_and(|(bound_connection, bound_session, bound_expiry)| {
                (bound_connection == connection || bound_session == session_id) && bound_expiry == expires_at
            }))
    {
        return Err("CONNECTION_NOT_INITED");
    }
    if let Some(entry) = temp_keys.get_mut(&temp_key_id) {
        entry.bound_to = Some(perm_id);
        entry.bound_on = Some((connection, session_id, expires_at));
    }
    Ok(())
}

fn trickle_forever(wire: &mut Wire, mode: i32, stop: &AtomicBool, rng: &mut XorShiftRandom) -> std::io::Result<()> {
    let started = Instant::now();
    if mode == 0 || mode == 3 {
        let declared = if mode == 0 { 2u32 << 20 } else { 8u32 << 20 };
        let header = match wire.framing {
            Framing::Abridged => {
                let words = declared / 4;
                vec![0x7f, words as u8, (words >> 8) as u8, (words >> 16) as u8]
            }
            _ => declared.to_le_bytes().to_vec(),
        };
        if wire.send_raw_frame(header).is_err() {
            return Ok(());
        }
    }
    while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(90) {
        std::thread::sleep(Duration::from_millis(300));
        let sent = match mode {
            0 | 3 => wire.send_raw_frame(vec![0x55]),
            1 => wire.send_frame(&0u32.to_le_bytes()),
            _ => wire.send_quick_ack(rng.next_u64() as u32 & 0x7fff_ffff),
        };
        if sent.is_err() {
            break;
        }
    }
    Ok(())
}

fn track_answer(session: &mut SessionState, msg_id: i64, reply: &[u8]) {
    session.unacked.push((msg_id, 1, reply.to_vec()));
    let req_msg_id = i64::from_le_bytes(reply[4..12].try_into().unwrap());
    session.answer_ids.insert(req_msg_id, msg_id);
}

fn seal_tracked(session: &mut SessionState, body: &[u8], content: bool) -> Vec<u8> {
    session.peer.server_time = server_now(session.clock_offset);
    let msg_id = session.peer.next_msg_id(true);
    let seq = if content { 1 } else { 0 };
    if body.len() >= 12 && u32::from_le_bytes(body[..4].try_into().unwrap()) == ids::RPC_RESULT {
        session.unacked.push((msg_id, seq, body.to_vec()));
        let req_msg_id = i64::from_le_bytes(body[4..12].try_into().unwrap());
        session.answer_ids.insert(req_msg_id, msg_id);
        if session.answer_ids.len() > MAX_REMEMBERED_ANSWERS {
            let unacked: HashSet<i64> = session.unacked.iter().map(|(id, _, _)| *id).collect();
            session.answer_ids.retain(|_, answer_id| unacked.contains(answer_id));
        }
    }
    session.peer.seal(msg_id, seq, body)
}

fn decrypted_plaintext(key: &AuthKey, packet: &[u8]) -> Vec<u8> {
    let msg_key: [u8; 16] = packet[8..24].try_into().unwrap();
    let material = mtproto_core::crypto::message_key_v2(key.bytes(), &msg_key, mtproto_core::crypto::Side::Client);
    let mut plain = packet[24..].to_vec();
    mtproto_core::crypto::aes_ige_decrypt(&material.key, &material.iv, &mut plain).unwrap();
    plain
}

fn result_body(tag: u32, payload: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(CALL_RESULT);
    writer.write_u32(tag);
    writer.write_bytes(payload);
    writer.into_inner()
}

fn future_salts_reply(req_msg_id: i64, salt: i64, clock_offset: f64) -> Vec<u8> {
    let now = server_now(clock_offset) as i32;
    sp::future_salts(req_msg_id, now, &[(now - 60, now + 3600, salt), (now + 3600, now + 7200, salt)])
}

#[derive(Default)]
struct WrapperFlags {
    init_connection: bool,
    without_updates: bool,
    invoke_after: bool,
}

enum Inner {
    Call(u32, Vec<u8>),
    Api(u32, Vec<u8>),
}

fn unwrap_wrappers(body: &[u8]) -> (Option<Inner>, WrapperFlags) {
    let mut flags = WrapperFlags::default();
    let mut reader = Reader::new(body);
    loop {
        let Ok(constructor) = reader.read_u32() else {
            return (None, flags);
        };
        match constructor {
            ids::INVOKE_AFTER_MSG => {
                flags.invoke_after = true;
                if reader.read_i64().is_err() {
                    return (None, flags);
                }
            }
            ids::INVOKE_WITHOUT_UPDATES => flags.without_updates = true,
            ids::INVOKE_WITH_LAYER => {
                let _ = reader.read_i32();
                if reader.read_u32().ok() != Some(INIT_CONNECTION) {
                    return (None, flags);
                }
                flags.init_connection = true;
                let flag_bits = reader.read_i32().unwrap_or(0);
                let _ = reader.read_i32();
                for _ in 0..6 {
                    let _ = reader.read_bytes();
                }
                if flag_bits & 1 != 0 {
                    let _ = reader.read_u32().ok().filter(|c| *c == INPUT_CLIENT_PROXY);
                    let _ = reader.read_bytes();
                    let _ = reader.read_i32();
                }
                if flag_bits & 2 != 0 && skip_json_value(&mut reader, 0).is_none() {
                    return (None, flags);
                }
            }
            INVOKE_WITH_APNS_SECRET => {
                let _ = reader.read_bytes();
                let _ = reader.read_bytes();
            }
            INVOKE_WITH_RECAPTCHA => {
                let _ = reader.read_bytes();
            }
            CALL => {
                let tag = reader.read_u32().unwrap_or(0);
                let payload = reader.read_bytes().map(<[u8]>::to_vec).unwrap_or_default();
                return (Some(Inner::Call(tag, payload)), flags);
            }
            constructor if api::ApiWorld::handles(constructor) => {
                return (Some(Inner::Api(constructor, reader.rest().to_vec())), flags);
            }
            ids::GZIP_PACKED => {
                let Some(unpacked) =
                    reader.read_bytes().ok().and_then(|packed| mtproto_core::tl::mtproto::gunzip(packed, 1 << 24).ok())
                else {
                    return (None, flags);
                };
                let (inner, inner_flags) = unwrap_wrappers(&unpacked);
                flags.invoke_after |= inner_flags.invoke_after;
                flags.without_updates |= inner_flags.without_updates;
                flags.init_connection |= inner_flags.init_connection;
                return (inner, flags);
            }
            _ => return (None, flags),
        }
    }
}

/// Skips the JSONValue `initConnection` carries as `params`, which tdlib sends.
fn skip_json_value(reader: &mut Reader<'_>, depth: usize) -> Option<()> {
    const JSON_NULL: u32 = 0x3f6d_7b68;
    const JSON_BOOL: u32 = 0xc734_5e6a;
    const JSON_NUMBER: u32 = 0x2be0_dfa4;
    const JSON_STRING: u32 = 0xb71e_767a;
    const JSON_ARRAY: u32 = 0xf744_4763;
    const JSON_OBJECT: u32 = 0x99c1_d49d;
    const JSON_OBJECT_VALUE: u32 = 0xc0de_1bd9;
    const VECTOR: u32 = 0x1cb5_c415;
    if depth > 16 {
        return None;
    }
    match reader.read_u32().ok()? {
        JSON_NULL => {}
        JSON_BOOL => {
            reader.read_u32().ok()?;
        }
        JSON_NUMBER => {
            reader.read_i64().ok()?;
        }
        JSON_STRING => {
            reader.read_bytes().ok()?;
        }
        JSON_ARRAY => {
            (reader.read_u32().ok()? == VECTOR).then_some(())?;
            for _ in 0..reader.read_u32().ok()? {
                skip_json_value(reader, depth + 1)?;
            }
        }
        JSON_OBJECT => {
            (reader.read_u32().ok()? == VECTOR).then_some(())?;
            for _ in 0..reader.read_u32().ok()? {
                (reader.read_u32().ok()? == JSON_OBJECT_VALUE).then_some(())?;
                reader.read_bytes().ok()?;
                skip_json_value(reader, depth + 1)?;
            }
        }
        _ => return None,
    }
    Some(())
}

pub fn random_key(seed: u64) -> AuthKey {
    let mut rng = XorShiftRandom::new(seed);
    AuthKey::new(rng.array())
}
