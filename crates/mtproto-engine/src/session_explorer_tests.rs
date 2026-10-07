//! A randomized, seeded explorer for the worker's busy loops and for stalls.
//!
//! Each seed builds a plan: one to three sessions (TCP, HTTP or Auto; Main or Worker; with or without
//! engine-run PFS; keep-alive or idle disconnect; preset, generated or host-given keys; proxies and named
//! routes) and a schedule of host commands and network events at virtual times. The plan runs against
//! the test server behind a fault box (pass, blackhole, reset, answers dropped, HTTP 404/429/portal
//! pages), SOCKS5 and HTTP proxies of the harness, dead and blackholed addresses and a scripted resolver,
//! with real sockets and a virtual clock: real time, plus jumps over quiet stretches (nothing read or
//! written for a while) to the next deadline any session asked for, plus scheduled sleeps (which push
//! the rest of the schedule back). The test server is plain, refuses or ignores binds, answers HTTP
//! slowly, or injects its mixed chaos faults. After the schedule the world heals for `HEAL_TIME`
//! (network up, fault box passing, TCP not blackholed, sessions resumed; a broken proxy or address list
//! is replaced, a working named one is kept so that per-name state is tested too) and every request
//! has to finish.
//!
//! Invariants, checked as it runs:
//! - spin: a session's `next_deadline` sits at or before now turn after turn while driving it moves no
//!   byte, emits no event and changes no connection, handshake or key state (as the worker would spin);
//! - stall: after the heal, every request the host sent completes or fails (PFS sessions are exempt
//!   when the server refuses or ignores binds);
//! - duplicates: the test server executed no call twice (re-runs after a host-driven key change without
//!   PFS are reported apart);
//! - duplicates across sessions: `Drain` hands a session's requests back (`SessionRuntime::drain`) and the
//!   host sends each released one on a fresh replacement session, a possibly-run one only when its policy
//!   (a coin) allows; a `Plain` call that ran more often than those allowed re-runs explain is
//!   `DuplicateAcrossSessions`, and a request a drained session neither answered nor released stalls;
//!   re-runs that a local session reset in the session it moved to explains are plain duplicates, as
//!   they would be without the move;
//! - churn: no more than 150 connections accepted in any 10 s;
//! - panics (debug assertions on), and an event for a request after it finished.
//!
//! `explorer_quick` runs a few fixed seeds; `explorer_long` (ignored) runs many and shrinks each new
//! failure to a minimal schedule: `EXPLORER_SEEDS=200 EXPLORER_FIRST=1 EXPLORER_STEPS=40 EXPLORER_JOBS=8
//! cargo test -p mtproto-engine --lib explorer_long -- --ignored --nocapture`. `EXPLORER_SEED=n` replays
//! one with its plan and log; `EXPLORER_PLAN_ONLY=1` prints plans; `EXPLORER_SHRINK_KNOWN=1` also shrinks
//! the classes `known_class` lists (each has a deterministic test at the end of this file: drop its entry
//! once fixed); `EXPLORER_SERVER_PLAIN=1` keeps the server plain; `EXPLORER_REPORT=path` saves the report;
//! `EXPLORER_DRAIN_SHARE=0.2` makes that share of the events drains.

use super::*;
use crate::types::{KeyGeneration, PfsSetup, TransportPreference};
use mtproto_core::auth_key::AuthKey;
use mtproto_core::rpc::{RequestFlags, RpcEvent, RpcRequest};
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_testserver::{
    SERVER_SALT, ServerOptions, TAG_DROP_CONNECTION_ONCE, TAG_FLOOD_ONCE, TAG_FORGED_404_ONCE, TAG_LARGE,
    TAG_NEW_SESSION, TAG_RESEND_REQ_ONCE, TAG_SERVER_ERROR_ONCE, TAG_SLOW, TAG_UPDATE_PUSH, TAG_UPLOAD, TestServer,
    bad_msg_call, call, random_key, sized_call, transport_error_call,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TOKENS: usize = crate::http_link::TOKENS_PER_SESSION;
/// Consecutive turns at or past their deadline without progress, and how long they took at least, before
/// a session counts as spinning.
const SPIN_TURNS: usize = 400;
const SPIN_REAL: Duration = Duration::from_millis(15);
/// Nothing read or written this long (real time) lets the virtual clock jump to the next deadline.
const QUIET: Duration = Duration::from_millis(30);
const MAX_JUMP: f64 = 60.0;
const HEAL_TIME: f64 = 200.0;
const SPIN_GIVE_UP: f64 = 120.0;

// ---------------------------------------------------------------------------------------------------
// Seeded randomness

#[derive(Clone)]
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03 | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize].clone()
    }
}

// ---------------------------------------------------------------------------------------------------
// The network: a fault box in front of the server, proxies, dead and black addresses

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoxMode {
    Pass,
    /// Accepts and reads, never answers; connections already open go silent both ways.
    Blackhole,
    /// Closes every connection, new and old.
    Reset,
    /// Forwards what the client sends, drops every answer.
    DropAnswers,
    /// Answers every request with this HTTP status (a captive portal, a proxy's deny page).
    Status(u16),
}

struct Ctl {
    mode: Mutex<BoxMode>,
    epoch: AtomicU64,
    stop: AtomicBool,
    accepted: AtomicUsize,
}

impl Ctl {
    fn new(mode: BoxMode) -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(mode),
            epoch: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            accepted: AtomicUsize::new(0),
        })
    }

    fn mode(&self) -> BoxMode {
        *self.mode.lock().unwrap()
    }

    fn set(&self, mode: BoxMode) {
        let mut current = self.mode.lock().unwrap();
        if matches!(mode, BoxMode::Reset | BoxMode::Status(_)) && *current != mode {
            self.epoch.fetch_add(1, Ordering::SeqCst);
        }
        *current = mode;
    }

    fn kill(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn gone(&self, epoch: u64) -> bool {
        self.stop.load(Ordering::Relaxed) || self.epoch.load(Ordering::SeqCst) != epoch
    }
}

#[derive(Clone, Copy)]
enum Front {
    Box,
    Socks,
    HttpProxy,
}

fn listen(ctl: Arc<Ctl>, upstream: Option<SocketAddr>, front: Front) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while !ctl.stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    ctl.accepted.fetch_add(1, Ordering::SeqCst);
                    let ctl = ctl.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_nodelay(true);
                        match front {
                            Front::Box => serve_box(stream, upstream, ctl),
                            Front::Socks => serve_socks(stream, upstream, ctl),
                            Front::HttpProxy => serve_http_proxy(stream, upstream, ctl),
                        }
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    port
}

fn timed_out(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
    )
}

fn pump(mut from: TcpStream, mut to: TcpStream, ctl: Arc<Ctl>, epoch: u64, answers: bool) {
    let _ = from.set_read_timeout(Some(Duration::from_millis(20)));
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if ctl.gone(epoch) {
            break;
        }
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => match ctl.mode() {
                BoxMode::Pass => {
                    if to.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
                BoxMode::DropAnswers if answers => {}
                BoxMode::DropAnswers => {
                    if to.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
                BoxMode::Blackhole => {}
                BoxMode::Reset | BoxMode::Status(_) => break,
            },
            Err(error) if timed_out(&error) => {}
            Err(_) => break,
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}

fn relay(client: TcpStream, server: TcpStream, ctl: Arc<Ctl>, epoch: u64) {
    let _ = server.set_nodelay(true);
    let (Ok(client_up), Ok(server_up)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up_ctl = ctl.clone();
    let up = std::thread::spawn(move || pump(client_up, server_up, up_ctl, epoch, false));
    pump(server, client, ctl, epoch, true);
    let _ = up.join();
}

fn swallow(mut client: TcpStream, ctl: Arc<Ctl>, epoch: u64) {
    let _ = client.set_read_timeout(Some(Duration::from_millis(20)));
    let mut buffer = [0u8; 16 * 1024];
    while !ctl.gone(epoch) {
        match client.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if timed_out(&error) => {}
            Err(_) => break,
        }
    }
    let _ = client.shutdown(Shutdown::Both);
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn status_response(code: u16, keep_alive: bool) -> Vec<u8> {
    let (reason, body) = match code {
        200 => ("OK", "<html><body>Welcome to the hotel network. Please sign in.</body></html>"),
        404 => ("Not Found", "<html><body>404</body></html>"),
        429 => ("Too Many Requests", ""),
        _ => ("Error", ""),
    };
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{body}",
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    )
    .into_bytes()
}

fn answer_status(mut client: TcpStream, code: u16, ctl: Arc<Ctl>, epoch: u64) {
    let _ = client.set_read_timeout(Some(Duration::from_millis(20)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    while !ctl.gone(epoch) {
        if buffer.len() >= 4 && !matches!(&buffer[..4], b"POST" | b"GET " | b"HEAD" | b"CONN") {
            let _ = client.write_all(&status_response(code, false));
            break;
        }
        if let Some(end) = find(&buffer, b"\r\n\r\n") {
            let length = content_length(&buffer[..end]);
            if buffer.len() >= end + 4 + length {
                buffer.drain(..end + 4 + length);
                if client.write_all(&status_response(code, true)).is_err() {
                    break;
                }
                continue;
            }
        }
        match client.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) if timed_out(&error) => {}
            Err(_) => break,
        }
    }
    let _ = client.shutdown(Shutdown::Both);
}

fn serve_box(client: TcpStream, upstream: Option<SocketAddr>, ctl: Arc<Ctl>) {
    let epoch = ctl.epoch.load(Ordering::SeqCst);
    match (ctl.mode(), upstream) {
        (BoxMode::Reset, _) => {
            let _ = client.shutdown(Shutdown::Both);
        }
        (BoxMode::Status(code), _) => answer_status(client, code, ctl, epoch),
        (BoxMode::Blackhole, _) | (_, None) => swallow(client, ctl, epoch),
        (_, Some(upstream)) => match TcpStream::connect_timeout(&upstream, Duration::from_secs(2)) {
            Ok(server) => relay(client, server, ctl, epoch),
            Err(_) => {
                let _ = client.shutdown(Shutdown::Both);
            }
        },
    }
}

fn read_exact_timed(stream: &mut TcpStream, length: usize) -> Option<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut out = vec![0u8; length];
    stream.read_exact(&mut out).ok()?;
    Some(out)
}

fn serve_socks(mut client: TcpStream, upstream: Option<SocketAddr>, ctl: Arc<Ctl>) {
    let epoch = ctl.epoch.load(Ordering::SeqCst);
    let Some(greeting) = read_exact_timed(&mut client, 2) else { return };
    if greeting[0] != 5 {
        return;
    }
    let Some(methods) = read_exact_timed(&mut client, greeting[1] as usize) else { return };
    if methods.contains(&0) {
        if client.write_all(&[5, 0]).is_err() {
            return;
        }
    } else if methods.contains(&2) {
        if client.write_all(&[5, 2]).is_err() {
            return;
        }
        let Some(head) = read_exact_timed(&mut client, 2) else { return };
        let Some(_user) = read_exact_timed(&mut client, head[1] as usize) else { return };
        let Some(length) = read_exact_timed(&mut client, 1) else { return };
        let Some(_password) = read_exact_timed(&mut client, length[0] as usize) else { return };
        if client.write_all(&[1, 0]).is_err() {
            return;
        }
    } else {
        let _ = client.write_all(&[5, 0xff]);
        return;
    }
    let Some(request) = read_exact_timed(&mut client, 4) else { return };
    let address_length = match request[3] {
        1 => 4,
        4 => 16,
        3 => match read_exact_timed(&mut client, 1) {
            Some(length) => length[0] as usize,
            None => return,
        },
        _ => return,
    };
    if read_exact_timed(&mut client, address_length + 2).is_none() {
        return;
    }
    let Some(upstream) = upstream else { return };
    let Ok(server) = TcpStream::connect_timeout(&upstream, Duration::from_secs(2)) else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    };
    if client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).is_err() {
        return;
    }
    let _ = client.set_read_timeout(None);
    relay(client, server, ctl, epoch);
}

fn serve_http_proxy(mut client: TcpStream, upstream: Option<SocketAddr>, ctl: Arc<Ctl>) {
    let epoch = ctl.epoch.load(Ordering::SeqCst);
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let end = loop {
        if let Some(end) = find(&buffer, b"\r\n\r\n") {
            break end;
        }
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let Some(upstream) = upstream else { return };
    let Ok(mut server) = TcpStream::connect_timeout(&upstream, Duration::from_secs(2)) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    if buffer.starts_with(b"CONNECT ") {
        if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
            return;
        }
        if server.write_all(&buffer[end + 4..]).is_err() {
            return;
        }
    } else if server.write_all(&buffer).is_err() {
        return;
    }
    let _ = client.set_read_timeout(None);
    relay(client, server, ctl, epoch);
}

fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct World {
    server: TestServer,
    fault: Arc<Ctl>,
    fault_port: u16,
    black: Arc<Ctl>,
    black_port: u16,
    socks: Arc<Ctl>,
    socks_port: u16,
    http_proxy: Arc<Ctl>,
    http_proxy_port: u16,
    dead: u16,
    dead2: u16,
}

impl World {
    fn start(perm: &AuthKey, plan: ServerPlan, seed: u64) -> Self {
        let mut options = ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        };
        match plan {
            ServerPlan::Plain => {}
            ServerPlan::RefuseBinds => options.refuse_binds = Some("ENCRYPTED_MESSAGE_INVALID"),
            ServerPlan::IgnoreBinds => options.ignore_binds = true,
            ServerPlan::SlowHttp => options.http_processing_delay = Some(0.3),
            ServerPlan::Chaos => options.chaos = Some(mtproto_testserver::chaos::ChaosConfig::mixed(seed, 0.01)),
        }
        let server = TestServer::start(vec![perm.clone()], options);
        let fault = Ctl::new(BoxMode::Pass);
        let fault_port = listen(fault.clone(), Some(server.address), Front::Box);
        let black = Ctl::new(BoxMode::Blackhole);
        let black_port = listen(black.clone(), None, Front::Box);
        let socks = Ctl::new(BoxMode::Pass);
        let socks_port = listen(socks.clone(), Some(local(fault_port)), Front::Socks);
        let http_proxy = Ctl::new(BoxMode::Pass);
        let http_proxy_port = listen(http_proxy.clone(), Some(local(fault_port)), Front::HttpProxy);
        Self {
            server,
            fault,
            fault_port,
            black,
            black_port,
            socks,
            socks_port,
            http_proxy,
            http_proxy_port,
            dead: dead_port(),
            dead2: dead_port(),
        }
    }

    fn accepted(&self) -> usize {
        self.fault.accepted.load(Ordering::SeqCst) + self.black.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        for ctl in [&self.fault, &self.black, &self.socks, &self.http_proxy] {
            ctl.stop.store(true, Ordering::SeqCst);
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Names

#[derive(Debug, Clone)]
enum Answer {
    Addrs(Vec<SocketAddr>),
    Nx,
    Hang,
}

struct Dns {
    table: HashMap<String, Answer>,
    asynchronous: bool,
    delay: f64,
    now: f64,
    in_flight: HashMap<(String, u16), (Vec<SessionHandle>, f64)>,
    due: Vec<(f64, String, u16)>,
    calls: usize,
}

impl Resolve for Dns {
    fn resolve(&mut self, session: SessionHandle, host: &str, port: u16) -> Resolution {
        self.calls += 1;
        let answer = self.table.get(host).cloned().unwrap_or(Answer::Nx);
        if !self.asynchronous {
            return match answer {
                Answer::Addrs(addresses) => Resolution::Resolved(addresses),
                Answer::Nx => Resolution::Resolved(Vec::new()),
                Answer::Hang => Resolution::Pending,
            };
        }
        let key = (host.to_string(), port);
        if let Some((waiting, started_at)) = self.in_flight.get_mut(&key) {
            if !waiting.contains(&session) {
                waiting.push(session);
            }
            if self.now - *started_at < RESOLVE_WAIT {
                return Resolution::Pending;
            }
            *started_at = self.now;
        }
        if !matches!(answer, Answer::Hang) {
            self.due.push((self.now + self.delay, host.to_string(), port));
        }
        self.in_flight.entry(key).or_insert_with(|| (vec![session], self.now));
        Resolution::Pending
    }
}

impl Dns {
    fn answer(&self, host: &str) -> Vec<SocketAddr> {
        match self.table.get(host) {
            Some(Answer::Addrs(addresses)) => addresses.clone(),
            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The host

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    logs: Mutex<VecDeque<String>>,
}

impl EngineCallbacks for Recorder {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event));
    }

    fn on_log(&self, level: LogLevel, message: &str) {
        if level <= LogLevel::Info || std::env::var_os("EXPLORER_DEBUG_LOG").is_some() {
            let mut logs = self.logs.lock().unwrap();
            let limit = if std::env::var_os("EXPLORER_DEBUG_LOG").is_some() { 50_000 } else { 400 };
            if logs.len() >= limit {
                logs.pop_front();
            }
            logs.push_back(message.to_string());
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Plans

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyPlan {
    Preset,
    Generate,
    HostLater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    None,
    Socks,
    SocksAuth,
    SocksNamed,
    Http,
    HttpNamed,
    Dead,
    DeadNamed,
    NxNamed,
    HangNamed,
    MtProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrKind {
    Literal,
    Named,
    DeadFirst,
    BlackFirst,
    Shrink,
    DeadLiteralFirst,
    Nx,
    Hang,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Plain,
    Slow,
    Large,
    Sized,
    Upload,
    FloodOnce,
    ServerErrorOnce,
    DropConnectionOnce,
    Flood429Once,
    BadMsg16,
    BadMsg17,
    UpdatePush,
    ResendReqOnce,
    NewSession,
    Forged404Once,
}

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    Send {
        s: usize,
        tag: Tag,
        timeout_timer: bool,
        chain: bool,
        delegate: bool,
    },
    Cancel {
        s: usize,
        pick: u32,
    },
    Fail {
        s: usize,
        pick: u32,
    },
    Network(bool),
    Paused {
        s: usize,
        on: bool,
    },
    Online {
        s: usize,
        on: bool,
    },
    Proxy {
        s: usize,
        kind: ProxyKind,
    },
    Addresses {
        s: usize,
        kind: AddrKind,
    },
    Transport {
        s: usize,
        transport: TransportPreference,
    },
    AuthKeyNone {
        s: usize,
    },
    AuthKeyNew {
        s: usize,
    },
    EnablePfs {
        s: usize,
        lifetime: i32,
    },
    Destroy {
        s: usize,
    },
    Reset,
    ObfuscationDc {
        s: usize,
    },
    TimeDifference {
        s: usize,
        delta: f64,
    },
    AuthTokenReady {
        s: usize,
        ready: bool,
    },
    Box(BoxMode),
    KillConnections,
    TcpBlackhole(bool),
    DropTemporaryKeys,
    UnbindTemporaryKeys,
    RemovePermanent {
        s: usize,
    },
    DnsFlip,
    Sleep(f64),
    /// The host moves session `s` to a new session (a live engine switch), waiting `deadline` seconds at
    /// most for the answers the old one may still get.
    Drain {
        s: usize,
        deadline: f64,
    },
}

#[derive(Debug, Clone)]
struct SessionPlan {
    main: bool,
    transport: TransportPreference,
    keep_connected: bool,
    idle: Option<f64>,
    pfs: Option<i32>,
    key: KeyPlan,
    proxy: ProxyKind,
    addresses: AddrKind,
    online: bool,
}

/// How the test server behaves for the whole run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerPlan {
    Plain,
    /// Every `auth.bindTempAuthKey` is refused: PFS sessions cannot work, and their stalls are expected.
    RefuseBinds,
    /// Binds are never answered: likewise.
    IgnoreBinds,
    /// Answers take 300 ms over HTTP.
    SlowHttp,
    /// The test server's mixed faults at a low rate.
    Chaos,
}

#[derive(Debug, Clone)]
struct Plan {
    seed: u64,
    server: ServerPlan,
    sessions: Vec<SessionPlan>,
    events: Vec<(f64, Ev)>,
    asynchronous_dns: bool,
    dns_delay: f64,
}

fn plan(seed: u64, steps: usize) -> Plan {
    let share = std::env::var("EXPLORER_DRAIN_SHARE").ok().and_then(|value| value.parse().ok()).unwrap_or(0.0);
    plan_with(seed, steps, share)
}

fn random_drain(r: &mut Prng, sessions: usize) -> Ev {
    Ev::Drain { s: r.below(sessions as u64) as usize, deadline: r.pick(&[0.0, 1.0, 5.0, 5.0, 30.0]) }
}

/// A plan in which about `drain_share` of the steps send a few calls to a session and then drain it.
fn plan_with(seed: u64, steps: usize, drain_share: f64) -> Plan {
    let mut r = Prng::new(seed);
    let count = match r.below(20) {
        0..=9 => 1,
        10..=16 => 2,
        _ => 3,
    };
    let transports =
        [TransportPreference::Tcp, TransportPreference::Http, TransportPreference::Http, TransportPreference::Auto];
    let sessions: Vec<SessionPlan> = (0..count)
        .map(|index| {
            let main = if index == 0 { r.chance(0.6) } else { r.chance(0.2) };
            SessionPlan {
                main,
                transport: r.pick(&transports),
                keep_connected: if main { r.chance(0.8) } else { r.chance(0.15) },
                idle: r.pick(&[None, Some(60.0), Some(5.0), Some(20.0)]),
                pfs: if r.chance(0.4) { Some(r.pick(&[60, 90, 300, 86_400])) } else { None },
                key: r.pick(&[
                    KeyPlan::Preset,
                    KeyPlan::Preset,
                    KeyPlan::Preset,
                    KeyPlan::Generate,
                    KeyPlan::HostLater,
                ]),
                proxy: if r.chance(0.75) { ProxyKind::None } else { random_proxy(&mut r) },
                addresses: if r.chance(0.5) { AddrKind::Literal } else { random_addresses(&mut r) },
                online: r.chance(0.5),
            }
        })
        .collect();
    let mut events = Vec::new();
    let mut at = 0.0;
    for _ in 0..steps {
        at += if r.chance(0.1) { 5.0 + r.unit() * 40.0 } else { r.unit() * 3.0 };
        if drain_share > 0.0 && r.chance(drain_share) {
            let Ev::Drain { s, deadline } = random_drain(&mut r, count) else { unreachable!() };
            for _ in 0..=r.below(4) {
                let send = Ev::Send {
                    s,
                    tag: random_tag(&mut r),
                    timeout_timer: false,
                    chain: r.chance(0.3),
                    delegate: r.chance(0.5),
                };
                events.push((at, send));
            }
            at += r.pick(&[0.0, 0.01, 0.05, 0.3]);
            events.push((at, Ev::Drain { s, deadline }));
        } else {
            events.push((at, random_event(&mut r, count)));
        }
    }
    let asynchronous_dns = r.chance(0.7);
    let dns_delay = r.pick(&[0.0, 0.05, 0.5, 2.0]);
    let server = match r.below(20) {
        _ if std::env::var_os("EXPLORER_SERVER_PLAIN").is_some() => ServerPlan::Plain,
        0 => ServerPlan::RefuseBinds,
        1 => ServerPlan::IgnoreBinds,
        2 | 3 => ServerPlan::SlowHttp,
        4..=6 => ServerPlan::Chaos,
        _ => ServerPlan::Plain,
    };
    Plan { seed, server, sessions, events, asynchronous_dns, dns_delay }
}

fn random_proxy(r: &mut Prng) -> ProxyKind {
    r.pick(&[
        ProxyKind::None,
        ProxyKind::Socks,
        ProxyKind::SocksAuth,
        ProxyKind::SocksNamed,
        ProxyKind::Http,
        ProxyKind::Http,
        ProxyKind::HttpNamed,
        ProxyKind::Dead,
        ProxyKind::DeadNamed,
        ProxyKind::NxNamed,
        ProxyKind::HangNamed,
        ProxyKind::MtProxy,
    ])
}

fn random_addresses(r: &mut Prng) -> AddrKind {
    r.pick(&[
        AddrKind::Literal,
        AddrKind::Named,
        AddrKind::DeadFirst,
        AddrKind::BlackFirst,
        AddrKind::Shrink,
        AddrKind::DeadLiteralFirst,
        AddrKind::Nx,
        AddrKind::Hang,
        AddrKind::Empty,
    ])
}

fn random_tag(r: &mut Prng) -> Tag {
    if r.chance(0.6) {
        return Tag::Plain;
    }
    r.pick(&[
        Tag::Slow,
        Tag::Large,
        Tag::Sized,
        Tag::Upload,
        Tag::FloodOnce,
        Tag::ServerErrorOnce,
        Tag::DropConnectionOnce,
        Tag::Flood429Once,
        Tag::BadMsg16,
        Tag::BadMsg17,
        Tag::BadMsg17,
        Tag::UpdatePush,
        Tag::ResendReqOnce,
        Tag::NewSession,
        Tag::Forged404Once,
    ])
}

fn random_event(r: &mut Prng, sessions: usize) -> Ev {
    let s = r.below(sessions as u64) as usize;
    match r.below(100) {
        0..=27 => Ev::Send {
            s,
            tag: random_tag(r),
            timeout_timer: r.chance(0.2),
            chain: r.chance(0.1),
            delegate: r.chance(0.3),
        },
        28..=31 => Ev::Cancel { s, pick: r.next() as u32 },
        32..=33 => Ev::Fail { s, pick: r.next() as u32 },
        34..=39 => Ev::Network(r.chance(0.5)),
        40..=42 => Ev::Paused { s, on: r.chance(0.5) },
        43..=44 => Ev::Online { s, on: r.chance(0.5) },
        45..=49 => Ev::Proxy { s, kind: random_proxy(r) },
        50..=54 => Ev::Addresses { s, kind: random_addresses(r) },
        55..=58 => Ev::Transport {
            s,
            transport: r.pick(&[TransportPreference::Tcp, TransportPreference::Http, TransportPreference::Auto]),
        },
        59..=60 => Ev::AuthKeyNone { s },
        61..=62 => Ev::AuthKeyNew { s },
        63..=64 => Ev::EnablePfs { s, lifetime: r.pick(&[60, 90, 300]) },
        65..=66 => Ev::Destroy { s },
        67..=69 => Ev::Reset,
        70 => Ev::ObfuscationDc { s },
        71 => Ev::TimeDifference { s, delta: r.pick(&[-40.0, -5.0, 5.0, 40.0]) },
        72 => Ev::AuthTokenReady { s, ready: r.chance(0.5) },
        73..=80 => Ev::Box(r.pick(&[
            BoxMode::Pass,
            BoxMode::Pass,
            BoxMode::Blackhole,
            BoxMode::Reset,
            BoxMode::DropAnswers,
            BoxMode::Status(404),
            BoxMode::Status(429),
            BoxMode::Status(200),
        ])),
        81..=83 => Ev::KillConnections,
        84..=87 => Ev::TcpBlackhole(r.chance(0.5)),
        88..=89 => Ev::DropTemporaryKeys,
        90 => Ev::UnbindTemporaryKeys,
        91 => Ev::RemovePermanent { s },
        92..=93 => Ev::DnsFlip,
        94 => random_drain(r, sessions),
        _ => Ev::Sleep(r.pick(&[3.0, 15.0, 45.0, 100.0])),
    }
}

/// The heal: what the world looks like for the last `HEAL_TIME` seconds, and one fresh call per session.
fn heal_events(plan: &Plan) -> Vec<(f64, Ev)> {
    let end = plan.events.last().map_or(0.0, |(at, _)| *at) + 1.0;
    let healed = if std::env::var_os("EXPLORER_SABOTAGE_HEAL").is_some() { BoxMode::Blackhole } else { BoxMode::Pass };
    let mut events = vec![(end, Ev::Box(healed)), (end, Ev::TcpBlackhole(false)), (end, Ev::Network(true))];
    for s in 0..plan.sessions.len() {
        let mut proxy = plan.sessions[s].proxy;
        let mut addresses = plan.sessions[s].addresses;
        for (_, event) in &plan.events {
            match event {
                Ev::Proxy { s: target, kind } if *target == s => proxy = *kind,
                Ev::Addresses { s: target, kind } if *target == s => addresses = *kind,
                _ => {}
            }
        }
        events.push((end, Ev::Paused { s, on: false }));
        if matches!(
            proxy,
            ProxyKind::Dead | ProxyKind::DeadNamed | ProxyKind::NxNamed | ProxyKind::HangNamed | ProxyKind::MtProxy
        ) || std::env::var_os("EXPLORER_HEAL_ALL").is_some()
        {
            events.push((end, Ev::Proxy { s, kind: ProxyKind::None }));
        }
        if matches!(addresses, AddrKind::Nx | AddrKind::Hang | AddrKind::Empty)
            || std::env::var_os("EXPLORER_HEAL_ALL").is_some()
        {
            events.push((end, Ev::Addresses { s, kind: AddrKind::Literal }));
        }
        events.push((end, Ev::AuthTokenReady { s, ready: true }));
        events.push((end + 1.0, Ev::Send { s, tag: Tag::Plain, timeout_timer: false, chain: false, delegate: false }));
    }
    events
}

// ---------------------------------------------------------------------------------------------------
// The run

#[derive(Debug, Clone, PartialEq)]
enum Violation {
    Spin {
        session: usize,
        at: f64,
        lasted: f64,
        state: String,
    },
    Stall {
        session: usize,
        id: u64,
        tag: Tag,
        sent_at: f64,
        history: String,
        state: String,
    },
    Duplicate {
        id: u64,
        tag: Tag,
        executions: u32,
        explained: Option<String>,
        history: String,
    },
    /// A call moved between sessions ran more often than the moves its policy allowed explain.
    DuplicateAcrossSessions {
        id: u64,
        executions: u32,
        allowed: usize,
        history: String,
    },
    Panic {
        message: String,
    },
    AfterFinish {
        session: usize,
        id: u64,
        event: String,
    },
    Churn {
        at: f64,
        accepted: usize,
    },
}

impl Violation {
    fn kind(&self) -> &'static str {
        match self {
            Violation::Spin { .. } => "spin",
            Violation::Stall { .. } => "stall",
            Violation::Duplicate { explained: None, .. } => "duplicate",
            Violation::Duplicate { .. } => "duplicate-explained",
            Violation::DuplicateAcrossSessions { .. } => "duplicate-across-sessions",
            Violation::Panic { .. } => "panic",
            Violation::AfterFinish { .. } => "after-finish",
            Violation::Churn { .. } => "churn",
        }
    }

    fn counts(&self) -> bool {
        !matches!(self, Violation::Duplicate { explained: Some(_), .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ReqState {
    Open,
    Done,
    Failed,
    Cancelled,
}

struct Req {
    session: usize,
    tag: Tag,
    sent_at: f64,
    state: ReqState,
    history: Vec<String>,
    awaiting_decision: bool,
    /// The session ran PFS when the call went out.
    pfs_at_send: bool,
    body: Vec<u8>,
    flags: RequestFlags,
    /// Each time a drained session released it: whether it may have run, and whether the host sent it
    /// on (always when it may not have run, by its policy otherwise).
    moves: Vec<(bool, bool)>,
}

#[derive(Debug)]
enum HostAction {
    DecideRetry(usize, RequestId, bool),
    TokenReady(usize),
    SetKey(usize, Option<AuthKey>),
    NewKey(usize),
    /// The host hands over the key it holds when it acts, not when it was asked: a key it replaced in
    /// between must not come back.
    CurrentKey(usize),
    /// A released request goes on the session that replaced its own, after the wait it was serving.
    Resend(u64),
}

pub(super) struct Outcome {
    violations: Vec<Violation>,
    turns: usize,
    virtual_time: f64,
    real_time: f64,
    requests: usize,
    completed: usize,
    rotated: usize,
    moved: usize,
    immediate: Vec<usize>,
    logs: Vec<String>,
}

type SpinTrack = (usize, Option<(Instant, f64)>, u64, bool);

struct Runner<'a> {
    plan: &'a Plan,
    world: World,
    poll: mio::Poll,
    events: mio::Events,
    scratch: Vec<u8>,
    rng: OsRandom,
    prng: Prng,
    sessions: Vec<SessionRuntime>,
    recorder: Arc<Recorder>,
    callbacks: Arc<dyn EngineCallbacks>,
    config: EngineConfig,
    dns: Dns,
    skip: f64,
    requests: BTreeMap<u64, Req>,
    next_request: u64,
    actions: Vec<(f64, HostAction)>,
    host_keys: Vec<Option<AuthKey>>,
    key_seed: u64,
    more_readable: VecDeque<usize>,
    violations: Vec<Violation>,
    /// Per session: turns in a row at or past the deadline without progress, when that began (real,
    /// virtual), the last progress fingerprint, and whether the spin was reported.
    spin: Vec<SpinTrack>,
    /// Turns that asked to be driven at once, progress or not.
    immediate: Vec<usize>,
    quiet_since: Option<Instant>,
    network: bool,
    churn_window: VecDeque<(f64, usize)>,
    churn_reported: bool,
    turns: usize,
    stop_on: Option<&'static str>,
    start_mono: f64,
    /// Sleeps push the rest of the schedule back by their length.
    schedule_offset: f64,
    heal_started: Option<f64>,
    heal_at: f64,
    /// The session each of the plan's sessions runs on now: a drain replaces it.
    current: Vec<usize>,
    /// The plan's session each session runs for.
    logical: Vec<usize>,
    hints: Arc<crate::route_hints::RouteHints>,
    uploads: Arc<Uploads>,
}

fn material(key: &AuthKey, now: Now) -> AuthKeyMaterial {
    AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now.unix - 600.0, valid_until: now.unix + 7200.0 }],
        init_hash: None,
    }
}

fn public_keys() -> Vec<mtproto_core::crypto::RsaPublicKey> {
    vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()]
}

impl<'a> Runner<'a> {
    fn new(plan: &'a Plan, stop_on: Option<&'static str>) -> Self {
        let perm = random_key(plan.seed.wrapping_mul(7919) ^ 0x5eed);
        let world = World::start(&perm, plan.server, plan.seed);
        let mut table = HashMap::new();
        let fault = local(world.fault_port);
        table.insert("dc.test".to_string(), Answer::Addrs(vec![fault]));
        table.insert("dead-first.test".to_string(), Answer::Addrs(vec![local(world.dead), fault]));
        table.insert("black-first.test".to_string(), Answer::Addrs(vec![local(world.black_port), fault]));
        table.insert(
            "shrink.test".to_string(),
            Answer::Addrs(vec![local(world.dead), local(world.dead2), local(world.black_port), fault]),
        );
        table.insert("nx.test".to_string(), Answer::Nx);
        table.insert("hang.test".to_string(), Answer::Hang);
        table.insert("socks.test".to_string(), Answer::Addrs(vec![local(world.dead), local(world.socks_port)]));
        table.insert(
            "http-proxy.test".to_string(),
            Answer::Addrs(vec![local(world.dead), local(world.http_proxy_port)]),
        );
        table.insert("dead-proxy.test".to_string(), Answer::Addrs(vec![local(world.dead2)]));
        table.insert("nx-proxy.test".to_string(), Answer::Nx);
        table.insert("hang-proxy.test".to_string(), Answer::Hang);
        let recorder = Arc::new(Recorder::default());
        let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
        let mut runner = Self {
            plan,
            world,
            poll: mio::Poll::new().unwrap(),
            events: mio::Events::with_capacity(256),
            scratch: vec![0u8; 256 * 1024],
            rng: OsRandom::new(),
            prng: Prng::new(plan.seed ^ 0xabcdef),
            sessions: Vec::new(),
            recorder,
            callbacks,
            config: EngineConfig::default(),
            dns: Dns {
                table,
                asynchronous: plan.asynchronous_dns,
                delay: plan.dns_delay,
                now: 0.0,
                in_flight: HashMap::new(),
                due: Vec::new(),
                calls: 0,
            },
            skip: 0.0,
            requests: BTreeMap::new(),
            next_request: 1,
            actions: Vec::new(),
            host_keys: Vec::new(),
            key_seed: plan.seed.wrapping_mul(1_000_003),
            more_readable: VecDeque::new(),
            violations: Vec::new(),
            spin: Vec::new(),
            immediate: Vec::new(),
            quiet_since: None,
            network: true,
            churn_window: VecDeque::new(),
            churn_reported: false,
            turns: 0,
            stop_on,
            start_mono: 0.0,
            schedule_offset: 0.0,
            heal_started: None,
            heal_at: f64::INFINITY,
            current: Vec::new(),
            logical: Vec::new(),
            hints: Arc::new(crate::route_hints::RouteHints::default()),
            uploads: Arc::new(Uploads::default()),
        };
        let now = runner.now();
        for (index, session_plan) in plan.sessions.iter().enumerate() {
            let role =
                if session_plan.main { SessionRole::Main } else { SessionRole::Worker { requires_auth_token: false } };
            let mut setup = SessionSetup::new(2, role, runner.addresses(session_plan.addresses));
            setup.transport = session_plan.transport;
            setup.http_port = None;
            setup.keep_connected = session_plan.keep_connected;
            setup.idle_disconnect_after = session_plan.idle;
            setup.online = session_plan.online;
            setup.proxy = runner.proxy(session_plan.proxy);
            setup.tcp_recheck_after = 20.0;
            let mut host_key = None;
            match session_plan.key {
                KeyPlan::Preset => {
                    setup.auth_key = Some(material(&perm, now));
                    host_key = Some(perm.clone());
                }
                KeyPlan::Generate => {
                    setup.key_generation =
                        Some(KeyGeneration { public_keys: public_keys(), temporary_expires_in: None })
                }
                KeyPlan::HostLater => host_key = Some(perm.clone()),
            }
            if let Some(lifetime) = session_plan.pfs {
                setup.pfs = Some(PfsSetup { lifetime, public_keys: public_keys(), ..Default::default() });
            }
            runner.current.push(index);
            runner.add_runtime(setup, host_key, index, now);
        }
        runner
    }

    fn add_runtime(&mut self, setup: SessionSetup, host_key: Option<AuthKey>, logical: usize, now: Now) -> usize {
        let index = self.sessions.len();
        let mut runtime = SessionRuntime::new(
            SessionHandle(index as u64 + 1),
            setup,
            Token(TOKENS * (index + 1)),
            now,
            &mut self.rng,
        );
        runtime.share_uploads(self.uploads.clone());
        runtime.share_route_hints(self.hints.clone());
        self.sessions.push(runtime);
        self.host_keys.push(host_key);
        self.spin.push((0, None, 0, false));
        self.immediate.push(0);
        self.logical.push(logical);
        index
    }

    /// The host moves session `r` to a new one set up as `r` is now, with the key it holds for it.
    fn drain(&mut self, r: usize, deadline: f64, at: f64) {
        if self.sessions[r].is_draining() {
            return;
        }
        let now = self.now();
        let logical = self.logical[r];
        let session_plan = &self.plan.sessions[logical];
        let old = &self.sessions[r].setup;
        let mut setup = SessionSetup::new(2, old.role, old.addresses.clone());
        setup.transport = old.transport;
        setup.http_port = old.http_port;
        setup.keep_connected = old.keep_connected;
        setup.idle_disconnect_after = old.idle_disconnect_after;
        setup.online = old.online;
        setup.paused = old.paused;
        setup.proxy = old.proxy.clone();
        setup.tcp_recheck_after = old.tcp_recheck_after;
        let host_key = self.host_keys[r].clone();
        match &host_key {
            Some(key) if session_plan.key != KeyPlan::HostLater => setup.auth_key = Some(material(key, now)),
            Some(_) => {}
            None => {
                setup.key_generation = Some(KeyGeneration { public_keys: public_keys(), temporary_expires_in: None })
            }
        }
        if let Some(pfs) = &self.sessions[r].pfs {
            setup.pfs = Some(PfsSetup { lifetime: pfs.lifetime, public_keys: public_keys(), ..Default::default() });
        }
        let replacement = self.add_runtime(setup, host_key, logical, now);
        self.current[logical] = replacement;
        self.note_all_open(r, &format!("drained into s{replacement}"), at);
        let registry = self.poll.registry();
        self.sessions[replacement].set_network_available(self.network, now, registry);
        self.sessions[r].drain(deadline, now, registry, &self.callbacks);
    }

    /// The session a plan event for session `s` goes to now.
    fn routed(&self, event: &Ev) -> Ev {
        let mut event = event.clone();
        match &mut event {
            Ev::Send { s, .. }
            | Ev::Cancel { s, .. }
            | Ev::Fail { s, .. }
            | Ev::Paused { s, .. }
            | Ev::Online { s, .. }
            | Ev::Proxy { s, .. }
            | Ev::Addresses { s, .. }
            | Ev::Transport { s, .. }
            | Ev::AuthKeyNone { s }
            | Ev::AuthKeyNew { s }
            | Ev::EnablePfs { s, .. }
            | Ev::Destroy { s }
            | Ev::ObfuscationDc { s }
            | Ev::TimeDifference { s, .. }
            | Ev::AuthTokenReady { s, .. }
            | Ev::RemovePermanent { s }
            | Ev::Drain { s, .. } => *s = self.current[*s],
            _ => {}
        }
        event
    }

    fn now(&self) -> Now {
        let real = crate::clock::now();
        Now { mono: real.mono + self.skip, unix: real.unix + self.skip }
    }

    fn addresses(&self, kind: AddrKind) -> Vec<DcAddress> {
        let named = |host: &str| DcAddress { host: host.into(), port: 443, secret: None };
        let literal = |port: u16| DcAddress { host: "127.0.0.1".into(), port, secret: None };
        match kind {
            AddrKind::Literal => vec![literal(self.world.fault_port)],
            AddrKind::Named => vec![named("dc.test")],
            AddrKind::DeadFirst => vec![named("dead-first.test")],
            AddrKind::BlackFirst => vec![named("black-first.test")],
            AddrKind::Shrink => vec![named("shrink.test")],
            AddrKind::DeadLiteralFirst => vec![literal(self.world.dead), literal(self.world.fault_port)],
            AddrKind::Nx => vec![named("nx.test")],
            AddrKind::Hang => vec![named("hang.test")],
            AddrKind::Empty => Vec::new(),
        }
    }

    fn proxy(&self, kind: ProxyKind) -> Option<ProxyConfig> {
        let socks = |host: &str, port: u16, auth: bool| ProxyConfig::Socks5 {
            host: host.into(),
            port,
            username: auth.then(|| "user".to_string()),
            password: auth.then(|| "secret".to_string()),
        };
        let http =
            |host: &str, port: u16| ProxyConfig::Http { host: host.into(), port, username: None, password: None };
        match kind {
            ProxyKind::None => None,
            ProxyKind::Socks => Some(socks("127.0.0.1", self.world.socks_port, false)),
            ProxyKind::SocksAuth => Some(socks("127.0.0.1", self.world.socks_port, true)),
            ProxyKind::SocksNamed => Some(socks("socks.test", 1080, false)),
            ProxyKind::Http => Some(http("127.0.0.1", self.world.http_proxy_port)),
            ProxyKind::HttpNamed => Some(http("http-proxy.test", 3128)),
            ProxyKind::Dead => Some(http("127.0.0.1", self.world.dead)),
            ProxyKind::DeadNamed => Some(socks("dead-proxy.test", 1080, false)),
            ProxyKind::NxNamed => Some(http("nx-proxy.test", 3128)),
            ProxyKind::HangNamed => Some(socks("hang-proxy.test", 1080, false)),
            ProxyKind::MtProxy => Some(ProxyConfig::MtProxy {
                host: "127.0.0.1".into(),
                port: self.world.fault_port,
                secret: vec![0xdd; 17],
            }),
        }
    }

    fn fresh_key(&mut self) -> AuthKey {
        self.key_seed = self.key_seed.wrapping_add(1);
        let key = random_key(self.key_seed);
        self.world.server.add_key(key.clone());
        key
    }

    /// Virtual time jumps ahead; the test server's timers follow, so that a long poll it parks comes due
    /// on the same clock as the session's deadline for it.
    fn skip_time(&mut self, seconds: f64) {
        self.skip += seconds;
        self.world.server.skip_time(seconds);
    }

    fn note_all_open(&mut self, s: usize, what: &str, at: f64) {
        for request in
            self.requests.values_mut().filter(|request| request.session == s && request.state == ReqState::Open)
        {
            request.history.push(format!("{at:.2} {what}"));
        }
    }

    fn apply(&mut self, event: &Ev) {
        let event = self.routed(event);
        let now = self.now();
        let at = now.mono - self.base_mono();
        let registry = self.poll.registry();
        match event {
            Ev::Send { s, tag, timeout_timer, chain, delegate } => {
                let id = self.next_request;
                self.next_request += 1;
                let body = match tag {
                    Tag::Plain => call(1 + (id % 900) as u32, &id.to_le_bytes()),
                    Tag::Slow => call(TAG_SLOW, &id.to_le_bytes()),
                    Tag::Large => call(TAG_LARGE, &id.to_le_bytes()),
                    Tag::Sized => sized_call(200 * 1024),
                    Tag::Upload => call(TAG_UPLOAD, &vec![(id & 0xff) as u8; 300 * 1024]),
                    Tag::FloodOnce => call(TAG_FLOOD_ONCE, &id.to_le_bytes()),
                    Tag::ServerErrorOnce => call(TAG_SERVER_ERROR_ONCE, &id.to_le_bytes()),
                    Tag::DropConnectionOnce => call(TAG_DROP_CONNECTION_ONCE, &id.to_le_bytes()),
                    Tag::Flood429Once => transport_error_call(-429),
                    Tag::BadMsg16 => bad_msg_call(16, false),
                    Tag::BadMsg17 => bad_msg_call(17, false),
                    Tag::UpdatePush => call(TAG_UPDATE_PUSH, &id.to_le_bytes()),
                    Tag::ResendReqOnce => call(TAG_RESEND_REQ_ONCE, &id.to_le_bytes()),
                    Tag::NewSession => call(TAG_NEW_SESSION, &id.to_le_bytes()),
                    Tag::Forged404Once => call(TAG_FORGED_404_ONCE, &id.to_le_bytes()),
                };
                let invoke_after = if chain {
                    self.requests
                        .iter()
                        .rev()
                        .find(|(_, request)| request.session == s && request.state == ReqState::Open)
                        .map(|(id, _)| RequestId(*id))
                } else {
                    None
                };
                let flags =
                    RequestFlags { timeout_timer, delegate_retry_decisions: delegate, ..RequestFlags::default() };
                self.requests.insert(
                    id,
                    Req {
                        session: s,
                        tag,
                        sent_at: at,
                        state: ReqState::Open,
                        history: vec![format!(
                            "{at:.2} sent{}",
                            if invoke_after.is_some() { " (chained)" } else { "" }
                        )],
                        awaiting_decision: false,
                        pfs_at_send: self.sessions[s].pfs.is_some(),
                        body: body.clone(),
                        flags,
                        moves: Vec::new(),
                    },
                );
                self.sessions[s].send(RpcRequest { id: RequestId(id), body, flags, invoke_after }, now);
            }
            Ev::Cancel { s, pick } => {
                let open: Vec<u64> = self
                    .requests
                    .iter()
                    .filter(|(_, request)| request.session == s && request.state == ReqState::Open)
                    .map(|(id, _)| *id)
                    .collect();
                if !open.is_empty() {
                    let id = open[pick as usize % open.len()];
                    if let Some(request) = self.requests.get_mut(&id) {
                        request.state = ReqState::Cancelled;
                        request.history.push(format!("{at:.2} cancelled"));
                    }
                    self.sessions[s].cancel(RequestId(id), now, registry, &self.callbacks);
                }
            }
            Ev::Fail { s, pick } => {
                let open: Vec<u64> = self
                    .requests
                    .iter()
                    .filter(|(_, request)| request.session == s && request.state == ReqState::Open)
                    .map(|(id, _)| *id)
                    .collect();
                if !open.is_empty() {
                    let id = open[pick as usize % open.len()];
                    if let Some(request) = self.requests.get_mut(&id) {
                        request.history.push(format!("{at:.2} host fails it"));
                    }
                    self.sessions[s].fail_request(RequestId(id), -1, "HOST_FAILED", now, &self.callbacks);
                }
            }
            Ev::Network(available) => {
                self.network = available;
                for session in &mut self.sessions {
                    session.set_network_available(available, now, registry);
                }
            }
            Ev::Paused { s, on } => self.sessions[s].set_paused(on, now, registry),
            Ev::Online { s, on } => self.sessions[s].set_online(on, now),
            Ev::Proxy { s, kind } => {
                let proxy = self.proxy(kind);
                self.sessions[s].set_proxy(proxy, now, self.poll.registry());
            }
            Ev::Addresses { s, kind } => {
                let addresses = self.addresses(kind);
                self.sessions[s].set_addresses(addresses, now, self.poll.registry());
            }
            Ev::Transport { s, transport } => self.sessions[s].set_transport(transport, None, now, registry),
            Ev::AuthKeyNone { s } => {
                self.note_all_open(s, "set_auth_key(None)", at);
                self.sessions[s].set_auth_key(None, now, self.poll.registry(), &self.callbacks, &mut self.rng);
            }
            Ev::AuthKeyNew { s } => {
                self.note_all_open(s, "set_auth_key(new)", at);
                let key = self.fresh_key();
                self.host_keys[s] = Some(key.clone());
                self.sessions[s].set_auth_key(
                    Some(material(&key, now)),
                    now,
                    self.poll.registry(),
                    &self.callbacks,
                    &mut self.rng,
                );
            }
            Ev::EnablePfs { s, lifetime } => {
                self.note_all_open(s, "enable_pfs", at);
                self.sessions[s].enable_pfs(
                    PfsSetup { lifetime, public_keys: public_keys(), ..Default::default() },
                    now,
                    self.poll.registry(),
                    &self.callbacks,
                    &mut self.rng,
                );
            }
            Ev::Destroy { s } => {
                self.note_all_open(s, "destroy_auth_key", at);
                self.sessions[s].destroy_auth_key(now, self.poll.registry(), &self.callbacks, &mut self.rng);
            }
            Ev::Reset => {
                for session in &mut self.sessions {
                    session.reset_connection(now, registry);
                }
            }
            Ev::ObfuscationDc { s } => {
                let dc = if self.sessions[s].setup.obfuscation_dc_id == 2 { -2 } else { 2 };
                self.sessions[s].set_obfuscation_dc_id(dc, now, registry);
            }
            Ev::TimeDifference { s, delta } => {
                let difference = self.sessions[s].time_difference() + delta;
                self.sessions[s].set_time_difference(difference);
            }
            Ev::AuthTokenReady { s, ready } => self.sessions[s].set_auth_token_ready(ready, now),
            Ev::Box(mode) => self.world.fault.set(mode),
            Ev::KillConnections => self.world.fault.kill(),
            Ev::TcpBlackhole(on) => self.world.server.set_tcp_blackhole(on),
            Ev::DropTemporaryKeys => {
                for s in 0..self.sessions.len() {
                    self.note_all_open(s, "server dropped temporary keys", at);
                }
                self.world.server.drop_temporary_keys();
            }
            Ev::UnbindTemporaryKeys => self.world.server.unbind_temporary_keys(),
            Ev::RemovePermanent { s } => {
                self.note_all_open(s, "server forgot the permanent key", at);
                let key = self.sessions[s]
                    .pfs
                    .as_ref()
                    .and_then(|pfs| pfs.perm.as_ref().map(|perm| perm.key.id()))
                    .or_else(|| self.sessions[s].rpc.as_ref().map(|rpc| rpc.session().auth_key_id()));
                if let Some(id) = key {
                    self.world.server.remove_key(id);
                }
            }
            Ev::DnsFlip => {
                let fault = local(self.world.fault_port);
                let shrunk =
                    matches!(self.dns.table.get("shrink.test"), Some(Answer::Addrs(addresses)) if addresses.len() == 1);
                let shrink = if shrunk {
                    vec![local(self.world.dead), local(self.world.dead2), local(self.world.black_port), fault]
                } else {
                    vec![fault]
                };
                self.dns.table.insert("shrink.test".into(), Answer::Addrs(shrink));
                let named = if matches!(self.dns.table.get("dc.test"), Some(Answer::Addrs(addresses)) if addresses.len() == 1)
                {
                    vec![local(self.world.dead), fault]
                } else {
                    vec![fault]
                };
                self.dns.table.insert("dc.test".into(), Answer::Addrs(named));
            }
            Ev::Sleep(seconds) => {
                self.skip_time(seconds);
                self.schedule_offset += seconds;
            }
            Ev::Drain { s, deadline } => self.drain(s, deadline, at),
        }
    }

    fn base_mono(&self) -> f64 {
        self.start_mono
    }

    fn perform(&mut self, action: HostAction) {
        let now = self.now();
        let registry = self.poll.registry();
        match action {
            HostAction::DecideRetry(s, id, retry) => {
                if let Some(request) = self.requests.get_mut(&id.0) {
                    request.awaiting_decision = false;
                }
                self.sessions[s].decide_retry(id, retry, now, &self.callbacks);
            }
            HostAction::TokenReady(s) => self.sessions[s].set_auth_token_ready(true, now),
            HostAction::SetKey(s, key) => {
                let material = key.map(|key| material(&key, now));
                self.sessions[s].set_auth_key(material, now, registry, &self.callbacks, &mut self.rng);
            }
            HostAction::CurrentKey(s) => match self.host_keys[s].clone() {
                Some(key) => {
                    if self.sessions[s].rpc.as_ref().is_some_and(|rpc| rpc.session().auth_key_id() != key.id()) {
                        let at = now.mono - self.start_mono;
                        self.note_all_open(s, "set_auth_key(host)", at);
                    }
                    let material = material(&key, now);
                    self.sessions[s].set_auth_key(
                        Some(material),
                        now,
                        self.poll.registry(),
                        &self.callbacks,
                        &mut self.rng,
                    );
                }
                None => self.perform(HostAction::NewKey(s)),
            },
            HostAction::Resend(id) => {
                let Some(request) = self.requests.get(&id).filter(|request| request.state == ReqState::Open) else {
                    return;
                };
                let (s, body, flags) = (request.session, request.body.clone(), request.flags);
                self.sessions[s].send(RpcRequest { id: RequestId(id), body, flags, invoke_after: None }, now);
            }
            HostAction::NewKey(s) => {
                let key = self.fresh_key();
                self.host_keys[s] = Some(key.clone());
                self.sessions[s].set_auth_key(
                    Some(material(&key, now)),
                    now,
                    self.poll.registry(),
                    &self.callbacks,
                    &mut self.rng,
                );
            }
        }
    }

    /// The host's side: bookkeeping of requests, and the answers a host gives to what the engine asks.
    fn host_events(&mut self, counts: &mut [u64]) {
        let events = std::mem::take(&mut *self.recorder.events.lock().unwrap());
        let now = self.now();
        let at = now.mono - self.start_mono;
        for (handle, event) in events {
            let s = handle.0 as usize - 1;
            counts[s] += 1;
            match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => {
                    self.finish(s, id.0, ReqState::Done, "completed", at)
                }
                EngineEvent::Rpc(RpcEvent::Failed { id, code, message, .. }) => {
                    self.finish(s, id.0, ReqState::Failed, &format!("failed {code} {message}"), at)
                }
                EngineEvent::Rpc(RpcEvent::RetryDecisionRequired { id, code, message, .. }) => {
                    if let Some(request) = self.requests.get_mut(&id.0) {
                        request.awaiting_decision = true;
                        request.history.push(format!("{at:.2} retry decision asked ({code} {message})"));
                    }
                    let retry = self.prng.chance(0.85);
                    let delay = self.prng.unit() * 1.5;
                    self.actions.push((now.mono + delay, HostAction::DecideRetry(s, id, retry)));
                }
                EngineEvent::Rpc(RpcEvent::Released { id, may_have_run, retry_after }) => {
                    let allowed = !may_have_run || self.prng.chance(0.5);
                    let target = self.current[self.logical[s]];
                    let Some(request) = self.requests.get_mut(&id.0) else {
                        continue;
                    };
                    if request.state != ReqState::Open || request.session != s {
                        let event = format!("released by s{s} while {:?} on s{}", request.state, request.session);
                        if request.state == ReqState::Cancelled {
                            request.history.push(format!("{at:.2} {event}"));
                        } else {
                            self.violations.push(Violation::AfterFinish { session: s, id: id.0, event });
                        }
                        continue;
                    }
                    request.moves.push((may_have_run, allowed));
                    request.history.push(format!(
                        "{at:.2} released by s{s} ({}, wait {retry_after:.2}): {}",
                        if may_have_run { "may have run" } else { "never ran" },
                        if allowed { format!("sent on s{target}") } else { "policy refuses, failed".to_string() }
                    ));
                    if allowed {
                        request.session = target;
                        self.actions.push((now.mono + retry_after, HostAction::Resend(id.0)));
                    } else {
                        request.state = ReqState::Failed;
                    }
                }
                EngineEvent::Closed => self.note_all_open(s, "session closed", at),
                EngineEvent::Rpc(RpcEvent::UpdatesReset) => self.note_all_open(s, "session reset", at),
                EngineEvent::Rpc(RpcEvent::TemporaryKeyBound) => self.note_all_open(s, "temporary key bound", at),
                EngineEvent::AuthKeyCreated { expires_at: Some(_), .. } => {
                    self.note_all_open(s, "temporary key made", at)
                }
                EngineEvent::Rpc(RpcEvent::AuthTokenRequired) => {
                    self.actions.push((now.mono + 0.3, HostAction::TokenReady(s)));
                }
                EngineEvent::AuthKeyRequired => {
                    let delay = self.prng.unit();
                    self.actions.push((now.mono + delay, HostAction::CurrentKey(s)));
                }
                EngineEvent::AuthKeyInvalid { .. } => {
                    self.note_all_open(s, "AuthKeyInvalid", at);
                    if self.sessions[s].setup.key_generation.is_none() && self.sessions[s].pfs.is_none() {
                        self.actions.push((now.mono + 0.2, HostAction::SetKey(s, None)));
                        self.actions.push((now.mono + 0.5, HostAction::NewKey(s)));
                    }
                }
                EngineEvent::PermanentKeyInvalid => {
                    self.note_all_open(s, "PermanentKeyInvalid", at);
                    self.actions.push((now.mono + 0.5, HostAction::NewKey(s)));
                }
                EngineEvent::AuthKeyCreated { key, expires_at: None, .. } => {
                    if let Ok(bytes) = <[u8; 256]>::try_from(key.as_slice()) {
                        self.host_keys[s] = Some(AuthKey::new(bytes));
                    }
                }
                EngineEvent::Rpc(RpcEvent::AuthKeyDestroyed { .. }) => {
                    self.note_all_open(s, "AuthKeyDestroyed", at);
                    if self.sessions[s].pfs.is_none() && self.sessions[s].setup.key_generation.is_none() {
                        self.actions.push((now.mono + 0.2, HostAction::SetKey(s, None)));
                        self.actions.push((now.mono + 0.4, HostAction::NewKey(s)));
                    }
                }
                _ => {}
            }
        }
    }

    fn finish(&mut self, s: usize, id: u64, state: ReqState, what: &str, at: f64) {
        let Some(request) = self.requests.get_mut(&id) else {
            return;
        };
        request.history.push(format!("{at:.2} {what}"));
        match request.state {
            ReqState::Open => request.state = state,
            ReqState::Cancelled if state == ReqState::Done => {}
            ReqState::Cancelled => {}
            _ => {
                let violation = Violation::AfterFinish { session: s, id, event: what.to_string() };
                self.violations.push(violation);
            }
        }
    }

    fn fingerprint(&self, s: usize, events: u64, touched: bool) -> u64 {
        use std::hash::{Hash, Hasher};
        let session = &self.sessions[s];
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        events.hash(&mut hasher);
        touched.hash(&mut hasher);
        (session.reported_in, session.reported_out).hash(&mut hasher);
        session.connection.as_ref().map(|c| (c.bytes_in, c.bytes_out, c.is_established())).hash(&mut hasher);
        session.racer.as_ref().map(|c| (c.bytes_in, c.bytes_out)).hash(&mut hasher);
        if let Some(http) = &session.http {
            for conn in &http.conns {
                (conn.token().0, conn.bytes_in, conn.bytes_out, conn.is_ready(), conn.in_flight_len())
                    .hash(&mut hasher);
            }
        }
        session.http.is_some().hash(&mut hasher);
        session.handshake.is_some().hash(&mut hasher);
        session.rpc.as_ref().map(|rpc| (rpc.session().auth_key_id(), rpc.request_count())).hash(&mut hasher);
        session.queued.len().hash(&mut hasher);
        session.pending_plain.len().hash(&mut hasher);
        session.auto.probe_token().map(|token| token.0).hash(&mut hasher);
        hasher.finish()
    }

    fn describe(&mut self, s: usize, now: Now) -> String {
        let config = self.config.clone();
        let session = &mut self.sessions[s];
        let deadline = session.next_deadline(now, &config).map(|at| at - now.mono);
        let poll = session.rpc.as_mut().and_then(|rpc| rpc.poll_timeout(now)).map(|at| at - now.mono);
        let wants = session.wants_connection(now);
        let can_dispatch = session.http_can_dispatch(now);
        let http = session.http.as_ref().map(|http| http.describe(now.mono));
        let pfs = session.pfs.as_ref().map(|pfs| pfs.describe(now.mono));
        let core = session.rpc.as_ref().map(|rpc| {
            let core = rpc.session();
            format!(
                "core(queries {} unanswered {} unknown {} to_send {} bound {} bind_query {:?} grace {:+.2} ping_unanswered {:?} ping_cut {:.1} read_cut {:.1} fresh {} http {} {})",
                core.query_count(),
                core.unanswered_query_count(),
                core.has_unknown_queries(),
                core.has_queries_to_send(),
                core.is_bound(),
                core.bind_query(),
                core.transmit_grace_until() - now.mono,
                core.unanswered_ping_since().map(|at| at - now.mono),
                core.ping_disconnect_delay(),
                core.read_disconnect_delay(),
                core.fresh_packets(),
                core.is_http(),
                core.describe_queries()
            )
        });
        format!(
            "transport {:?} main {} keep {} paused {} net {} wants {} deadline {:?} rpc {} (requests {}, poll_timeout {:?}, connected {}, awaiting {}) {} queued {} handshake {} started {:?} failures {} next_attempt {:+.3} connection {} racer {} {} {} {} can_dispatch {} proxy {:?} addresses {:?}",
            session.setup.transport,
            session.setup.role == SessionRole::Main,
            session.setup.keep_connected,
            session.setup.paused,
            session.network_available,
            wants,
            deadline,
            session.rpc.is_some(),
            session.rpc.as_ref().map_or(0, |rpc| rpc.request_count()),
            poll,
            session.rpc.as_ref().is_some_and(|rpc| rpc.session().is_connected()),
            session.rpc.as_ref().is_some_and(|rpc| rpc.session().is_awaiting_responses()),
            core.unwrap_or_default(),
            session.queued.len(),
            session.handshake.is_some(),
            session.handshake_started_at.map(|at| at - now.mono),
            session.failures,
            session.next_attempt_at - now.mono,
            session.connection.as_ref().map_or("none".to_string(), |c| format!(
                "established {} tcp {} age {:.2}",
                c.is_established(),
                c.is_tcp_connected(),
                now.mono - c.started_at
            )),
            session.racer.is_some(),
            http.unwrap_or_default(),
            pfs.unwrap_or_default(),
            session.auto.describe(now.mono),
            can_dispatch,
            session.setup.proxy,
            session
                .setup
                .addresses
                .iter()
                .map(|address| format!("{}:{}", address.host, address.port))
                .collect::<Vec<_>>()
        )
    }

    fn turn(&mut self, schedule: &mut VecDeque<(f64, Ev)>) {
        self.turns += 1;
        let now = self.now();
        let mut deadline = now.mono + 1.0;
        let config = self.config.clone();
        for session in &mut self.sessions {
            if let Some(at) = session.next_deadline(now, &config) {
                deadline = deadline.min(at);
            }
        }
        if let Some((at, _)) = schedule.front() {
            deadline = deadline.min(self.start_mono + self.schedule_offset + at);
        }
        for (at, _) in &self.actions {
            deadline = deadline.min(*at);
        }
        for (at, _, _) in &self.dns.due {
            deadline = deadline.min(*at);
        }
        let wait = if self.more_readable.is_empty() { (deadline - now.mono).clamp(0.0, 0.005) } else { 0.0 };
        let _ = self.poll.poll(&mut self.events, Some(Duration::from_secs_f64(wait)));
        let io: Vec<(Token, bool, bool)> = self
            .events
            .iter()
            .map(|event| {
                (
                    event.token(),
                    event.is_readable() || event.is_read_closed() || event.is_error(),
                    event.is_writable() || event.is_write_closed(),
                )
            })
            .collect();
        let quiet = io.is_empty() && self.more_readable.is_empty();
        let spinning = self.spin.iter().any(|(turns, _, _, _)| *turns > 0);
        if quiet && !spinning {
            let since = *self.quiet_since.get_or_insert_with(Instant::now);
            let current = self.now();
            let draining =
                self.sessions.iter().any(|session| session.rpc.as_ref().is_some_and(|rpc| rpc.session().is_draining()));
            if since.elapsed() >= QUIET && deadline > current.mono + 0.001 && !draining {
                self.skip_time((deadline - current.mono).min(MAX_JUMP));
                self.quiet_since = None;
            }
        } else {
            self.quiet_since = None;
        }
        let now = self.now();
        let mut touched = vec![false; self.sessions.len()];
        let mut carried: VecDeque<usize> = std::mem::take(&mut self.more_readable);
        for (token, readable, writable) in io {
            let s = token.0 / TOKENS;
            if s == 0 || s > self.sessions.len() {
                continue;
            }
            let s = s - 1;
            touched[s] = true;
            if readable {
                carried.retain(|other| *other != s);
            }
            let more = self.sessions[s].handle_io(
                token,
                readable,
                writable,
                self.poll.registry(),
                &mut self.scratch,
                now,
                &self.callbacks,
                &mut self.rng,
            );
            if more {
                self.more_readable.push_back(s);
            }
        }
        for s in carried {
            touched[s] = true;
            if let Some(token) = self.sessions[s].active_token()
                && self.sessions[s].handle_io(
                    token,
                    true,
                    false,
                    self.poll.registry(),
                    &mut self.scratch,
                    now,
                    &self.callbacks,
                    &mut self.rng,
                )
            {
                self.more_readable.push_back(s);
            }
        }
        while schedule.front().is_some_and(|(at, _)| self.start_mono + self.schedule_offset + at <= now.mono) {
            let (at, event) = schedule.pop_front().expect("front");
            if at >= self.heal_at && self.heal_started.is_none() {
                self.heal_started = Some(now.mono);
            }
            self.apply(&event);
        }
        self.actions.sort_by(|a, b| a.0.total_cmp(&b.0));
        while self.actions.first().is_some_and(|(at, _)| *at <= now.mono) {
            let (_, action) = self.actions.remove(0);
            self.perform(action);
        }
        touched.resize(self.sessions.len(), false);
        self.dns.now = now.mono;
        let mut delivered = Vec::new();
        self.dns.due.retain(|(at, host, port)| {
            if *at <= now.mono {
                delivered.push((host.clone(), *port));
                false
            } else {
                true
            }
        });
        for (host, port) in delivered {
            let waiting =
                self.dns.in_flight.remove(&(host.clone(), port)).map(|(waiting, _)| waiting).unwrap_or_default();
            let addresses = self.dns.answer(&host);
            for handle in waiting {
                self.sessions[handle.0 as usize - 1].on_resolved(&host, port, addresses.clone(), now);
            }
        }
        for s in 0..self.sessions.len() {
            let registry = self.poll.registry();
            self.sessions[s].drive(registry, now, &mut self.dns, &config, &self.callbacks, &mut self.rng);
        }
        let mut counts = vec![0u64; self.sessions.len()];
        self.host_events(&mut counts);
        self.check_spins(now, &counts, &touched);
        self.check_churn(now);
    }

    fn check_spins(&mut self, now: Now, counts: &[u64], touched: &[bool]) {
        let config = self.config.clone();
        for s in 0..self.sessions.len() {
            let immediate = self.sessions[s].next_deadline(now, &config).is_some_and(|at| at <= now.mono);
            let fingerprint = self.fingerprint(s, counts[s], touched[s]);
            if immediate {
                self.immediate[s] += 1;
            }
            if std::env::var_os("EXPLORER_TRACE").is_some() && immediate {
                let session = &self.sessions[s];
                eprintln!(
                    "trace {:.3} s{s} immediate fp {fingerprint:x} events {} io {} out {} in {}",
                    now.mono - self.start_mono,
                    counts[s],
                    touched[s],
                    session.reported_out + session.connection.as_ref().map_or(0, |c| c.bytes_out),
                    session.reported_in + session.connection.as_ref().map_or(0, |c| c.bytes_in),
                );
            }
            let (turns, started, last, reported) = self.spin[s];
            if immediate && fingerprint == last {
                let started = started.unwrap_or((Instant::now(), now.mono));
                let turns = turns + 1;
                let mut reported = reported;
                if !reported && turns >= SPIN_TURNS && started.0.elapsed() >= SPIN_REAL {
                    reported = true;
                    let state = self.describe(s, now);
                    let at = started.1 - self.start_mono;
                    self.violations.push(Violation::Spin { session: s, at, lasted: 0.0, state });
                }
                if reported {
                    self.skip_time(0.01);
                    let lasted = now.mono - started.1;
                    if let Some(Violation::Spin { lasted: recorded, .. }) = self
                        .violations
                        .iter_mut()
                        .rev()
                        .find(|violation| matches!(violation, Violation::Spin { session, .. } if *session == s))
                    {
                        *recorded = lasted;
                    }
                    if lasted > SPIN_GIVE_UP {
                        self.spin[s] = (0, None, fingerprint, false);
                        self.skip_time(1.0);
                        continue;
                    }
                }
                self.spin[s] = (turns, Some(started), fingerprint, reported);
            } else {
                self.spin[s] = (0, None, fingerprint, false);
            }
        }
    }

    fn check_churn(&mut self, now: Now) {
        let accepted = self.world.accepted();
        self.churn_window.push_back((now.mono, accepted));
        while self.churn_window.front().is_some_and(|(at, _)| now.mono - at > 10.0) {
            self.churn_window.pop_front();
        }
        let first = self.churn_window.front().map_or(accepted, |(_, count)| *count);
        if accepted - first > 150 && !self.churn_reported {
            self.churn_reported = true;
            self.violations.push(Violation::Churn { at: now.mono - self.start_mono, accepted: accepted - first });
            if std::env::var_os("EXPLORER_DEBUG_LOG").is_some() {
                let detail = format!(
                    "churn: box {} black {}; sessions: {}",
                    self.world.fault.accepted.load(Ordering::SeqCst),
                    self.world.black.accepted.load(Ordering::SeqCst),
                    (0..self.sessions.len()).map(|s| self.describe(s, now)).collect::<Vec<_>>().join(" || ")
                );
                self.recorder.logs.lock().unwrap().push_back(detail);
            }
        }
    }

    fn run(mut self) -> Outcome {
        let real = Instant::now();
        self.start_mono = self.now().mono;
        let mut schedule: VecDeque<(f64, Ev)> = self.plan.events.iter().cloned().collect();
        let heal = heal_events(self.plan);
        self.heal_at = heal.first().map_or(0.0, |(at, _)| *at);
        schedule.extend(heal);
        let finished = |runner: &Self| runner.heal_started.is_some_and(|at| runner.now().mono - at >= HEAL_TIME);
        while !finished(&self) {
            self.turn(&mut schedule);
            if let Some(kind) = self.stop_on
                && self.violations.iter().any(|violation| violation.kind() == kind)
                && self.spin.iter().all(|(turns, _, _, _)| *turns == 0)
            {
                break;
            }
            if real.elapsed() > Duration::from_secs(600) {
                break;
            }
        }
        let now = self.now();
        if finished(&self) {
            let stalled: Vec<(u64, usize, Tag, f64, String)> = self
                .requests
                .iter()
                .filter(|(_, request)| {
                    let binds_fail = matches!(self.plan.server, ServerPlan::RefuseBinds | ServerPlan::IgnoreBinds)
                        && self.sessions[request.session].pfs.is_some();
                    request.state == ReqState::Open && !request.awaiting_decision && !binds_fail
                })
                .map(|(id, request)| (*id, request.session, request.tag, request.sent_at, request.history.join("; ")))
                .collect();
            let mut states: HashMap<usize, String> = HashMap::new();
            for (_, session, _, _, _) in &stalled {
                if !states.contains_key(session) {
                    let state = format!("server {:?} {}", self.plan.server, self.describe(*session, now));
                    states.insert(*session, state);
                }
            }
            let executed = self.world.server.with_stats(|stats| stats.unique_executions.clone());
            for (id, session, tag, sent_at, history) in stalled {
                let state = states.get(&session).cloned().unwrap_or_default();
                let runs = executed.iter().filter(|((_, key), _)| *key == id).map(|(_, count)| *count).sum::<u32>();
                let history = if matches!(tag, Tag::Plain) {
                    format!("{history}; server ran it {runs} times")
                } else {
                    format!("{history}; server runs of this tag are not counted")
                };
                self.violations.push(Violation::Stall { session, id, tag, sent_at, history, state });
            }
        }
        let executions = self.world.server.with_stats(|stats| stats.unique_executions.clone());
        let records = self.world.server.with_stats(|stats| stats.duplicate_records.clone());
        if !records.is_empty() {
            self.recorder
                .logs
                .lock()
                .unwrap()
                .extend(records.into_iter().map(|record| format!("server duplicate: {record}")));
        }
        for ((_, key), count) in executions {
            if count < 2 {
                continue;
            }
            let Some(request) = self.requests.get(&key) else {
                continue;
            };
            if request.tag != Tag::Plain {
                continue;
            }
            let history = request.history.join("; ");
            let moved = !request.moves.is_empty();
            let allowed = request.moves.iter().filter(|(may_have_run, allowed)| *may_have_run && *allowed).count();
            let first_change = [
                "set_auth_key(None)",
                "set_auth_key(new)",
                "set_auth_key(host)",
                "AuthKeyInvalid",
                "AuthKeyDestroyed",
                "server forgot",
            ]
            .iter()
            .filter_map(|marker| history.find(marker))
            .min();
            let pfs = self.plan.sessions[self.logical[request.session]].pfs.is_some()
                || request.pfs_at_send
                || history.find("enable_pfs").is_some_and(|at| first_change.is_none_or(|change| at < change));
            let key_changes = [
                "set_auth_key(None)",
                "set_auth_key(new)",
                "set_auth_key(host)",
                "AuthKeyInvalid",
                "AuthKeyDestroyed",
                "server forgot",
                "server dropped temporary keys",
                "session reset",
            ]
            .iter()
            .map(|marker| history.matches(marker).count())
            .sum::<usize>();
            let explained = if self.plan.server == ServerPlan::SlowHttp && history.contains("session reset") {
                Some(
                    "harness: the slow HTTP server holds answers in real time, past a reset drain in virtual time"
                        .into(),
                )
            } else if pfs {
                ["server dropped temporary keys", "server forgot"]
                    .iter()
                    .find(|marker| history.contains(**marker))
                    .map(|marker| format!("key lost by the server ({marker}): calls go again under the new key"))
            } else {
                [
                    "set_auth_key(None)",
                    "set_auth_key(new)",
                    "set_auth_key(host)",
                    "AuthKeyInvalid",
                    "AuthKeyDestroyed",
                    "server forgot",
                ]
                .iter()
                .find(|marker| history.contains(**marker))
                .map(|marker| format!("non-PFS key change ({marker})"))
            };
            if moved {
                let in_session = if explained.is_some() { key_changes } else { 0 };
                let last_move = history.rfind(": sent on s").unwrap_or(0);
                let resets_after_move = history[last_move..].matches("session reset").count();
                if count as usize > 1 + allowed + in_session && count as usize <= 1 + allowed + resets_after_move {
                    self.violations.push(Violation::Duplicate {
                        id: key,
                        tag: request.tag,
                        executions: count,
                        explained: None,
                        history,
                    });
                } else if count as usize > 1 + allowed + in_session {
                    self.violations.push(Violation::DuplicateAcrossSessions {
                        id: key,
                        executions: count,
                        allowed,
                        history,
                    });
                } else if allowed > 0 {
                    self.violations.push(Violation::Duplicate {
                        id: key,
                        tag: request.tag,
                        executions: count,
                        explained: Some(format!("moved as possibly run {allowed} times, the host's policy allowed it")),
                        history,
                    });
                } else {
                    let explained = explained.map(|reason| format!("{reason}, then moved"));
                    self.violations.push(Violation::Duplicate {
                        id: key,
                        tag: request.tag,
                        executions: count,
                        explained,
                        history,
                    });
                }
                continue;
            }
            let explained = explained.filter(|_| count as usize <= 1 + key_changes);
            self.violations.push(Violation::Duplicate {
                id: key,
                tag: request.tag,
                executions: count,
                explained,
                history,
            });
        }
        let now_mono = self.now().mono;
        for session in &mut self.sessions {
            session.shutdown(self.poll.registry(), now);
        }
        let completed = self.requests.values().filter(|request| request.state == ReqState::Done).count();
        let rotated = self
            .requests
            .values()
            .filter(|request| request.history.iter().any(|line| line.contains("TEMP_KEY_ROTATED")))
            .count();
        let moved = self.requests.values().filter(|request| !request.moves.is_empty()).count();
        let logs = self.recorder.logs.lock().unwrap().iter().cloned().collect();
        Outcome {
            violations: self.violations,
            turns: self.turns,
            virtual_time: now_mono - self.start_mono,
            real_time: real.elapsed().as_secs_f64(),
            requests: self.requests.len(),
            completed,
            rotated,
            moved,
            immediate: self.immediate,
            logs,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Driving, shrinking, reporting

fn run_plan(plan: &Plan, stop_on: Option<&'static str>) -> Outcome {
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Runner::new(plan, stop_on).run()));
    result.unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_else(|| "panic".into());
        Outcome {
            violations: vec![Violation::Panic { message }],
            turns: 0,
            virtual_time: 0.0,
            real_time: started.elapsed().as_secs_f64(),
            requests: 0,
            completed: 0,
            rotated: 0,
            moved: 0,
            immediate: Vec::new(),
            logs: Vec::new(),
        }
    })
}

/// The classes this round already reproduced deterministically (tests below); the long run counts them
/// apart and only shrinks what is new.
fn known_class(_violation: &Violation) -> Option<&'static str> {
    None
}

fn first_kind(outcome: &Outcome) -> Option<&'static str> {
    outcome
        .violations
        .iter()
        .find(|violation| {
            violation.counts()
                && (known_class(violation).is_none() || std::env::var_os("EXPLORER_SHRINK_KNOWN").is_some())
        })
        .map(Violation::kind)
}

fn reproduces(plan: &Plan, kind: &'static str, attempts: usize) -> bool {
    (0..attempts).any(|_| {
        let stop = if kind == "spin" { Some("spin") } else { None };
        run_plan(plan, stop).violations.iter().any(|violation| violation.kind() == kind)
    })
}

/// Removes chunks of the schedule, then single events, while the failure of `kind` still shows.
fn shrink(plan: &Plan, kind: &'static str) -> Plan {
    let mut current = plan.clone();
    let mut chunk = current.events.len().div_ceil(2).max(1);
    loop {
        let mut index = 0;
        let mut removed = false;
        while index < current.events.len() {
            let mut candidate = current.clone();
            let end = (index + chunk).min(candidate.events.len());
            candidate.events.drain(index..end);
            if reproduces(&candidate, kind, 2) {
                current = candidate;
                removed = true;
            } else {
                index += chunk;
            }
        }
        if chunk == 1 && !removed {
            break;
        }
        if !removed {
            chunk = (chunk / 2).max(1);
        }
    }
    for index in (0..current.sessions.len()).rev() {
        if current.sessions.len() == 1 {
            break;
        }
        let mut candidate = current.clone();
        candidate.sessions.remove(index);
        let referenced = candidate.events.iter().any(|(_, event)| event_session(event) == Some(index));
        if referenced {
            continue;
        }
        for (_, event) in &mut candidate.events {
            renumber(event, index);
        }
        if reproduces(&candidate, kind, 2) {
            current = candidate;
        }
    }
    current
}

fn event_session(event: &Ev) -> Option<usize> {
    match event {
        Ev::Send { s, .. }
        | Ev::Cancel { s, .. }
        | Ev::Fail { s, .. }
        | Ev::Paused { s, .. }
        | Ev::Online { s, .. }
        | Ev::Proxy { s, .. }
        | Ev::Addresses { s, .. }
        | Ev::Transport { s, .. }
        | Ev::AuthKeyNone { s }
        | Ev::AuthKeyNew { s }
        | Ev::EnablePfs { s, .. }
        | Ev::Destroy { s }
        | Ev::ObfuscationDc { s }
        | Ev::TimeDifference { s, .. }
        | Ev::AuthTokenReady { s, .. }
        | Ev::RemovePermanent { s }
        | Ev::Drain { s, .. } => Some(*s),
        _ => None,
    }
}

fn renumber(event: &mut Ev, removed: usize) {
    let s = match event {
        Ev::Send { s, .. }
        | Ev::Cancel { s, .. }
        | Ev::Fail { s, .. }
        | Ev::Paused { s, .. }
        | Ev::Online { s, .. }
        | Ev::Proxy { s, .. }
        | Ev::Addresses { s, .. }
        | Ev::Transport { s, .. }
        | Ev::AuthKeyNone { s }
        | Ev::AuthKeyNew { s }
        | Ev::EnablePfs { s, .. }
        | Ev::Destroy { s }
        | Ev::ObfuscationDc { s }
        | Ev::TimeDifference { s, .. }
        | Ev::AuthTokenReady { s, .. }
        | Ev::RemovePermanent { s }
        | Ev::Drain { s, .. } => s,
        _ => return,
    };
    if *s > removed {
        *s -= 1;
    }
}

fn describe_plan(plan: &Plan) -> String {
    let mut out = format!(
        "seed {} server {:?} dns {} delay {}\n",
        plan.seed,
        plan.server,
        if plan.asynchronous_dns { "async" } else { "sync" },
        plan.dns_delay
    );
    for (index, session) in plan.sessions.iter().enumerate() {
        out.push_str(&format!("  session {index}: {session:?}\n"));
    }
    for (at, event) in &plan.events {
        out.push_str(&format!("  {at:7.2} {event:?}\n"));
    }
    out
}

fn describe_outcome(outcome: &Outcome) -> String {
    let mut out = format!(
        "{} turns ({:?} at once), {:.1} s virtual in {:.1} s real, {} requests ({} completed, {} TEMP_KEY_ROTATED, {} moved)\n",
        outcome.turns,
        outcome.immediate,
        outcome.virtual_time,
        outcome.real_time,
        outcome.requests,
        outcome.completed,
        outcome.rotated,
        outcome.moved
    );
    for violation in &outcome.violations {
        out.push_str(&format!("  {violation:?}\n"));
    }
    out
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

/// A few fixed seeds with short schedules: about a minute.
#[test]
fn explorer_quick() {
    let mut failures = Vec::new();
    let seeds: Vec<u64> = (1..=6).collect();
    let outcomes: Vec<(u64, Outcome)> = std::thread::scope(|scope| {
        let handles: Vec<_> = seeds
            .iter()
            .map(|seed| {
                let seed = *seed;
                scope.spawn(move || (seed, run_plan(&plan(seed, 12), None)))
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    for (seed, outcome) in outcomes {
        eprintln!("seed {seed}: {}", describe_outcome(&outcome));
        if first_kind(&outcome).is_some() {
            failures.push(format!("{}{}", describe_plan(&plan(seed, 12)), describe_outcome(&outcome)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A few fixed seeds whose schedules drain sessions often.
#[test]
fn explorer_drain_quick() {
    let seeds: Vec<u64> = (101..=106).collect();
    let outcomes: Vec<(u64, Outcome)> = std::thread::scope(|scope| {
        let handles: Vec<_> = seeds
            .iter()
            .map(|seed| {
                let seed = *seed;
                scope.spawn(move || (seed, run_plan(&plan_with(seed, 12, 0.25), None)))
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    let mut failures = Vec::new();
    let mut moved = 0;
    for (seed, outcome) in outcomes {
        eprintln!("seed {seed}: {}", describe_outcome(&outcome));
        moved += outcome.moved;
        if first_kind(&outcome).is_some() {
            failures.push(format!("{}{}", describe_plan(&plan_with(seed, 12, 0.25)), describe_outcome(&outcome)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(moved > 0, "the seeds move requests between sessions");
}

/// The long explorer: `EXPLORER_SEEDS` seeds from `EXPLORER_FIRST`, `EXPLORER_STEPS` events each, on
/// `EXPLORER_JOBS` threads; failures are shrunk unless `EXPLORER_NO_SHRINK` is set.
#[test]
#[ignore]
fn explorer_long() {
    let first = env_or("EXPLORER_FIRST", 1);
    let count = env_or("EXPLORER_SEEDS", 64);
    let steps = env_or("EXPLORER_STEPS", 40) as usize;
    let jobs = env_or("EXPLORER_JOBS", 8) as usize;
    let seeds: Vec<u64> = match std::env::var("EXPLORER_SEED").ok().and_then(|seed| seed.parse().ok()) {
        Some(seed) => vec![seed],
        None => (first..first + count).collect(),
    };
    if std::env::var_os("EXPLORER_PLAN_ONLY").is_some() {
        for seed in &seeds {
            eprintln!("{}", describe_plan(&plan(*seed, steps)));
        }
        return;
    }
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(seed) = seeds.get(index).copied() else { break };
                    let plan = plan(seed, steps);
                    let outcome = run_plan(&plan, None);
                    if seeds.len() == 1 {
                        eprintln!("{}", describe_plan(&plan));
                        eprintln!("{}", outcome.logs.join("\n"));
                    }
                    eprintln!("seed {seed}: {}", describe_outcome(&outcome).lines().next().unwrap_or_default());
                    for violation in &outcome.violations {
                        eprintln!("seed {seed}:   {}", format!("{violation:?}").chars().take(600).collect::<String>());
                    }
                    results.lock().unwrap().push((seed, plan, outcome));
                }
            });
        }
    });
    let results = results.into_inner().unwrap();
    let failing: Vec<&(u64, Plan, Outcome)> =
        results.iter().filter(|(_, _, outcome)| first_kind(outcome).is_some()).collect();
    let mut report = format!(
        "{} seeds, {} steps each, {:.0} s; {} failing\n",
        results.len(),
        steps,
        started.elapsed().as_secs_f64(),
        failing.len()
    );
    let mut by_kind: BTreeMap<String, (usize, BTreeSet<u64>)> = BTreeMap::new();
    for (seed, _, outcome) in &results {
        for violation in &outcome.violations {
            let class = known_class(violation).map_or_else(|| format!("NEW {}", violation.kind()), str::to_string);
            let entry = by_kind.entry(class).or_default();
            entry.0 += 1;
            entry.1.insert(*seed);
        }
    }
    for (class, (count, seeds)) in &by_kind {
        report.push_str(&format!("  {class}: {count} in seeds {:?}\n", seeds.iter().take(20).collect::<Vec<_>>()));
    }
    let shrink_enabled = std::env::var_os("EXPLORER_NO_SHRINK").is_none();
    let limit = env_or("EXPLORER_SHRINK_LIMIT", 6) as usize;
    let shrunk: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = failing
            .iter()
            .take(if shrink_enabled { limit } else { 0 })
            .map(|(seed, plan, outcome)| {
                let kind = first_kind(outcome).expect("failing");
                scope.spawn(move || {
                    let small = shrink(plan, kind);
                    let again = run_plan(&small, None);
                    format!(
                        "seed {seed} ({kind}) shrunk to {} events:\n{}{}last log lines:\n{}\n",
                        small.events.len(),
                        describe_plan(&small),
                        describe_outcome(&again),
                        again.logs.iter().rev().take(40).rev().cloned().collect::<Vec<_>>().join("\n")
                    )
                })
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    for text in &shrunk {
        report.push_str(text);
    }
    for (seed, plan, outcome) in failing.iter().skip(if shrink_enabled { limit } else { 0 }) {
        let _ = plan;
        report.push_str(&format!("seed {seed} (not shrunk): {}", describe_outcome(outcome)));
    }
    eprintln!("{report}");
    if let Ok(path) = std::env::var("EXPLORER_REPORT") {
        let _ = std::fs::write(path, &report);
    }
    assert!(failing.is_empty(), "{} failing seeds", failing.len());
}

// ---------------------------------------------------------------------------------------------------
// Deterministic repros of what the explorer and the review found (they fail on fc5bed2)

struct Fixed(Vec<SocketAddr>);

impl Resolve for Fixed {
    fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
        Resolution::Resolved(self.0.clone())
    }
}

fn keyed_setup(addresses: Vec<DcAddress>, transport: TransportPreference, start: Now) -> SessionSetup {
    let mut setup = SessionSetup::new(2, SessionRole::Main, addresses);
    setup.transport = transport;
    setup.http_port = None;
    setup.auth_key = Some(material(&AuthKey::new([7u8; 256]), start));
    setup
}

fn plain_request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(1, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

/// Drives `runtime` in simulated time with real sockets for `seconds`, `step` at a time; `each` runs after
/// every turn and stops the run when it returns true.
fn simulate(
    runtime: &mut SessionRuntime,
    poll: &mut mio::Poll,
    resolver: &mut dyn Resolve,
    start: Now,
    seconds: f64,
    step: f64,
    mut each: impl FnMut(&mut SessionRuntime, Now) -> bool,
) -> f64 {
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 65536];
    let mut rng = OsRandom::new();
    let callbacks: Arc<dyn EngineCallbacks> = Arc::new(Recorder::default());
    let config = EngineConfig::default();
    let mut elapsed = 0.0;
    while elapsed < seconds {
        let now = Now { mono: start.mono + elapsed, unix: start.unix + elapsed };
        poll.poll(&mut events, Some(Duration::from_millis(1))).unwrap();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, resolver, &config, &callbacks, &mut rng);
        if each(runtime, now) {
            break;
        }
        elapsed += step;
    }
    elapsed
}

/// A name with two addresses; both refuse for a while (an outage), then the second comes back. HTTP's
/// per-name cursor runs past the end of the list on the second failure and then never moves again: every
/// later connection goes to the first, dead, address.
fn reaches_second_after_outage(transport: TransportPreference) -> bool {
    let dead = dead_port();
    let later = dead_port();
    let mut poll = mio::Poll::new().unwrap();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut rng = OsRandom::new();
    let setup = keyed_setup(vec![DcAddress { host: "dc.example".into(), port: 443, secret: None }], transport, start);
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(plain_request(1), start);
    let mut resolver = Fixed(vec![local(dead), local(later)]);
    simulate(&mut runtime, &mut poll, &mut resolver, start, 60.0, 0.05, |_, _| false);
    let cursor = runtime.dns_failed.values().cloned().collect::<Vec<_>>();
    let listener = TcpListener::bind(local(later)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let resumed = Now { mono: start.mono + 60.0, unix: start.unix + 60.0 };
    let mut reached = false;
    simulate(&mut runtime, &mut poll, &mut resolver, resumed, 120.0, 0.05, |_, _| {
        reached = listener.accept().is_ok();
        reached
    });
    eprintln!(
        "{transport:?}: failed addresses after the outage {cursor:?}, reached the second address afterwards: {reached}"
    );
    runtime.shutdown(poll.registry(), resumed);
    reached
}

#[test]
fn http_reaches_the_second_address_of_a_name_after_both_failed() {
    assert!(reaches_second_after_outage(TransportPreference::Tcp), "control: TCP never reached the second address");
    assert!(
        reaches_second_after_outage(TransportPreference::Http),
        "HTTP kept connecting to the dead first address for 120 s after the second came back"
    );
}

/// A name whose first address fails at `connect` itself (here an IPv6 address without a route, as an IPv4
/// address does on an IPv6-only network): the failure never reaches the per-name cursor, so HTTP never
/// tries the second address.
fn reaches_second_after_synchronous_failure(transport: TransportPreference) -> Option<bool> {
    let unroutable: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    if mio::net::TcpStream::connect(unroutable).is_ok() {
        return None;
    }
    let live = TcpListener::bind("127.0.0.1:0").unwrap();
    live.set_nonblocking(true).unwrap();
    let mut poll = mio::Poll::new().unwrap();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut rng = OsRandom::new();
    let setup = keyed_setup(vec![DcAddress { host: "dc.example".into(), port: 443, secret: None }], transport, start);
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(plain_request(1), start);
    let mut resolver = Fixed(vec![unroutable, live.local_addr().unwrap()]);
    let mut reached = false;
    simulate(&mut runtime, &mut poll, &mut resolver, start, 120.0, 0.05, |_, _| {
        reached = live.accept().is_ok();
        reached
    });
    runtime.shutdown(poll.registry(), start);
    Some(reached)
}

#[test]
fn http_moves_past_a_name_address_that_fails_at_connect() {
    let Some(tcp) = reaches_second_after_synchronous_failure(TransportPreference::Tcp) else {
        eprintln!("this host routes 2001:db8::/32; skipped");
        return;
    };
    let http = reaches_second_after_synchronous_failure(TransportPreference::Http).unwrap_or(true);
    eprintln!("second address reached: TCP {tcp}, HTTP {http}");
    assert!(tcp, "control: TCP never reached the second address");
    assert!(http, "HTTP kept connecting to the address that fails at connect for 120 s");
}

/// An HTTP session that has no HTTP route (an MTProxy, or only addresses with secrets), marked offline:
/// counts the turns in 60 s that ask to be driven at once.
fn offline_without_http_route(proxy: bool) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut poll = mio::Poll::new().unwrap();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut rng = OsRandom::new();
    let secret = (!proxy).then(|| vec![0xdd; 17]);
    let mut setup =
        keyed_setup(vec![DcAddress { host: "127.0.0.1".into(), port, secret }], TransportPreference::Http, start);
    if proxy {
        setup.proxy = Some(ProxyConfig::MtProxy { host: "127.0.0.1".into(), port, secret: vec![0xdd; 17] });
    }
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.send(plain_request(1), start);
    runtime.set_network_available(false, start, poll.registry());
    let config = EngineConfig::default();
    let mut immediate = 0;
    simulate(&mut runtime, &mut poll, &mut NoLookups, start, 60.0, 0.05, |runtime, now| {
        if runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
            immediate += 1;
        }
        false
    });
    runtime.shutdown(poll.registry(), start);
    immediate
}

struct NoLookups;

impl Resolve for NoLookups {
    fn resolve(&mut self, _session: SessionHandle, host: &str, _port: u16) -> Resolution {
        panic!("looked up {host}");
    }
}

#[test]
fn an_offline_http_session_without_an_http_route_does_not_spin() {
    let mtproxy = offline_without_http_route(true);
    let secrets = offline_without_http_route(false);
    eprintln!("turns of 1200 asking to be driven at once: MTProxy {mtproxy}, addresses with secrets only {secrets}");
    assert!(
        mtproxy < 5 && secrets < 5,
        "MTProxy {mtproxy}, secrets {secrets} of 1200 turns asked to be driven at once"
    );
}

/// A packet whose HTTP response is lost after the server ran its queries (here the test server's forged
/// 404), while a `bad_msg_notification` 17 for another of its messages reaches a parked long poll: the
/// drain does not wait for queries it counts as unknown, the session resets at once, and the lost
/// packet's queries run again under the new session.
fn drain_reset_executions(transport: TransportPreference) -> (u32, bool) {
    use mtproto_testserver::TAG_FORGED_404_ONCE;
    let key = random_key(9001);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 256 * 1024];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = transport;
    setup.http_port = None;
    setup.auth_key = Some(material(&key, start));
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    let recorder = Arc::new(Recorder::default());
    let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
    let config = EngineConfig::default();
    let mut resolver = NoLookups;
    let mut completed = std::collections::HashSet::new();
    let mut reset = false;
    let mut turn = |runtime: &mut SessionRuntime, completed: &mut std::collections::HashSet<u64>, reset: &mut bool| {
        poll.poll(&mut events, Some(Duration::from_millis(2))).unwrap();
        let now = crate::clock::now();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut resolver, &config, &callbacks, &mut rng);
        for (_, event) in std::mem::take(&mut *recorder.events.lock().unwrap()) {
            match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => {
                    completed.insert(id.0);
                }
                EngineEvent::Rpc(RpcEvent::UpdatesReset) => *reset = true,
                _ => {}
            }
        }
    };
    runtime.send(plain_request(1), start);
    let real = Instant::now();
    while !completed.contains(&1) && real.elapsed() < Duration::from_secs(10) {
        turn(&mut runtime, &mut completed, &mut reset);
    }
    let settle = Instant::now();
    while settle.elapsed() < Duration::from_millis(300) {
        turn(&mut runtime, &mut completed, &mut reset);
    }
    let now = crate::clock::now();
    let request = |id: u64, body: Vec<u8>| RpcRequest {
        id: RequestId(id),
        body,
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    runtime.send(request(2, bad_msg_call(17, false)), now);
    runtime.send(request(3, call(1, &3u64.to_le_bytes())), now);
    runtime.send(request(4, call(TAG_FORGED_404_ONCE, &4u64.to_le_bytes())), now);
    let real = Instant::now();
    while real.elapsed() < Duration::from_secs(8) {
        turn(&mut runtime, &mut completed, &mut reset);
    }
    runtime.shutdown(poll.registry(), crate::clock::now());
    let executions = server.with_stats(|stats| stats.unique_executions.get(&(1, 3)).copied().unwrap_or(0));
    eprintln!(
        "{transport:?}: call 3 ran {executions} times, completed {}, session reset {reset}; {:?}",
        completed.contains(&3),
        server.with_stats(|stats| stats.duplicate_records.clone())
    );
    (executions, reset)
}

#[test]
fn a_drain_reset_does_not_run_a_lost_packets_queries_twice() {
    let (http, http_reset) = drain_reset_executions(TransportPreference::Http);
    let (tcp, tcp_reset) = drain_reset_executions(TransportPreference::Tcp);
    eprintln!("executions: HTTP {http} (reset {http_reset}), TCP {tcp} (reset {tcp_reset})");
    assert_eq!(http, 1, "HTTP ran the call {http} times");
    assert_eq!(tcp, 1, "TCP ran the call {tcp} times");
}

/// A worker session with an idle disconnect makes a key (here its first, after the network came back
/// later than its idle time; the same holds for a PFS key after the server lost the temporary one): the
/// idle deadline is already past, but the session wants its link for the handshake, so every turn asks to
/// be driven at once until the handshake ends. Against a server that never answers that is the whole
/// handshake timeout, again with every retry.
fn idle_worker_handshake_turns(transport: TransportPreference, idle: Option<f64>, pfs: bool) -> (usize, usize) {
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    let mut poll = mio::Poll::new().unwrap();
    let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
    let mut rng = OsRandom::new();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }],
    );
    setup.transport = transport;
    setup.http_port = None;
    setup.idle_disconnect_after = idle;
    if pfs {
        setup.auth_key = Some(material(&AuthKey::new([7u8; 256]), start));
        setup.pfs = Some(PfsSetup { lifetime: 86_400, public_keys: public_keys(), ..Default::default() });
    } else {
        setup.key_generation = Some(KeyGeneration { public_keys: public_keys(), temporary_expires_in: None });
    }
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    runtime.set_network_available(false, start, poll.registry());
    let online = Now { mono: start.mono + 10.0, unix: start.unix + 10.0 };
    runtime.set_network_available(true, online, poll.registry());
    let config = EngineConfig::default();
    let (mut immediate, mut turns) = (0, 0);
    simulate(&mut runtime, &mut poll, &mut NoLookups, online, 30.0, 0.01, |runtime, now| {
        turns += 1;
        if runtime.next_deadline(now, &config).is_some_and(|at| at <= now.mono) {
            immediate += 1;
        }
        false
    });
    runtime.shutdown(poll.registry(), online);
    drop(silent);
    (immediate, turns)
}

#[test]
fn an_idle_worker_making_a_key_does_not_spin() {
    let (tcp_control, _) = idle_worker_handshake_turns(TransportPreference::Tcp, None, false);
    let (http_control, _) = idle_worker_handshake_turns(TransportPreference::Http, None, false);
    let (tcp, turns) = idle_worker_handshake_turns(TransportPreference::Tcp, Some(5.0), false);
    let (http, _) = idle_worker_handshake_turns(TransportPreference::Http, Some(5.0), false);
    let (tcp_pfs, _) = idle_worker_handshake_turns(TransportPreference::Tcp, Some(5.0), true);
    let (http_pfs, _) = idle_worker_handshake_turns(TransportPreference::Http, Some(5.0), true);
    eprintln!(
        "turns of {turns} asking to be driven at once while the handshake waits: TCP {tcp}, HTTP {http}; PFS temporary key: TCP {tcp_pfs}, HTTP {http_pfs}; without an idle disconnect: TCP {tcp_control}, HTTP {http_control}"
    );
    assert!(
        tcp < 10 && http < 10 && tcp_pfs < 10 && http_pfs < 10,
        "TCP {tcp}, HTTP {http}, PFS TCP {tcp_pfs}, PFS HTTP {http_pfs} of {turns} turns asked to be driven at once"
    );
}

/// HTTP during a bad_msg 17 drain: no long poll is renewed (`poll_http_transmit` sends nothing while a
/// drain waits), so answers that come after the parked polls are used up never arrive; the drain then
/// gives up and the session resets, and those queries run again.
fn drain_without_polls(transport: TransportPreference) -> (usize, usize) {
    let key = random_key(9002);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 256 * 1024];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = transport;
    setup.http_port = None;
    setup.auth_key = Some(material(&key, start));
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    let recorder = Arc::new(Recorder::default());
    let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
    let config = EngineConfig::default();
    let mut turn = |runtime: &mut SessionRuntime| {
        poll.poll(&mut events, Some(Duration::from_millis(2))).unwrap();
        let now = crate::clock::now();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(
                event.token(),
                readable,
                writable,
                poll.registry(),
                &mut scratch,
                now,
                &callbacks,
                &mut rng,
            );
        }
        runtime.drive(poll.registry(), now, &mut NoLookups, &config, &callbacks, &mut rng);
    };
    runtime.send(plain_request(1), start);
    let real = Instant::now();
    while real.elapsed() < Duration::from_secs(2) {
        turn(&mut runtime);
    }
    let request = |id: u64, body: Vec<u8>| RpcRequest {
        id: RequestId(id),
        body,
        flags: RequestFlags::default(),
        invoke_after: None,
    };
    let slow = 6;
    for id in 0..slow {
        runtime.send(request(10 + id, call(TAG_SLOW, &(10 + id).to_le_bytes())), crate::clock::now());
        let pause = Instant::now();
        while pause.elapsed() < Duration::from_millis(40) {
            turn(&mut runtime);
        }
    }
    runtime.send(request(2, bad_msg_call(17, false)), crate::clock::now());
    let real = Instant::now();
    while real.elapsed() < Duration::from_secs(8) {
        turn(&mut runtime);
    }
    runtime.shutdown(poll.registry(), crate::clock::now());
    let executions = server.executions(TAG_SLOW);
    eprintln!("{transport:?}: {slow} slow calls ran {executions} times");
    (slow as usize, executions)
}

#[test]
fn a_drain_over_http_keeps_receiving_answers() {
    let (sent, http) = drain_without_polls(TransportPreference::Http);
    let (_, tcp) = drain_without_polls(TransportPreference::Tcp);
    assert_eq!(tcp, sent, "control: TCP ran the slow calls {tcp} times");
    assert_eq!(http, sent, "HTTP ran the slow calls {http} times");
}

/// A lookup that takes long (a resolver thread stuck on a dead DNS server): TCP waits for the answer,
/// HTTP asks again every 0.25 s.
struct Stuck {
    calls: usize,
}

impl Resolve for Stuck {
    fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
        self.calls += 1;
        Resolution::Pending
    }
}

#[test]
fn a_slow_lookup_does_not_wake_http_four_times_a_second() {
    let mut counts = Vec::new();
    for transport in [TransportPreference::Tcp, TransportPreference::Http] {
        let mut poll = mio::Poll::new().unwrap();
        let start = Now { mono: 1000.0, unix: 1_727_000_000.0 };
        let mut rng = OsRandom::new();
        let setup =
            keyed_setup(vec![DcAddress { host: "dc.example".into(), port: 443, secret: None }], transport, start);
        let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
        runtime.send(plain_request(1), start);
        let mut resolver = Stuck { calls: 0 };
        let config = EngineConfig::default();
        let mut wakeups = 0;
        let mut next = start.mono;
        simulate(&mut runtime, &mut poll, &mut resolver, start, 60.0, 0.01, |runtime, now| {
            if now.mono >= next {
                wakeups += 1;
                next = runtime.next_deadline(now, &config).unwrap_or(f64::INFINITY);
            }
            false
        });
        counts.push((transport, resolver.calls, wakeups));
        runtime.shutdown(poll.registry(), start);
    }
    eprintln!("60 s of a lookup that never returns, (transport, lookups asked, wakeups): {counts:?}");
    let http_wakeups = counts[1].2;
    assert!(http_wakeups < 30, "HTTP woke {http_wakeups} times in 60 s waiting for one lookup");
}

/// The explorer's minimal schedule for the stuck per-name cursor (seeds 288, 329, 1064, 1118, 1146 shrink
/// to this shape): one HTTP worker whose name resolves to a blackholed address and the server; the route
/// to the server resets for a while, so both addresses fail once; after the heal every connection goes to
/// the blackholed address and the call never completes.
#[test]
fn explorer_minimal_stuck_name_cursor() {
    let session = SessionPlan {
        main: false,
        transport: TransportPreference::Http,
        keep_connected: false,
        idle: Some(60.0),
        pfs: None,
        key: KeyPlan::Preset,
        proxy: ProxyKind::None,
        addresses: AddrKind::BlackFirst,
        online: false,
    };
    let plan = Plan {
        seed: 288,
        server: ServerPlan::Plain,
        sessions: vec![session],
        events: vec![
            (1.0, Ev::Box(BoxMode::Reset)),
            (2.0, Ev::Send { s: 0, tag: Tag::Plain, timeout_timer: false, chain: false, delegate: false }),
            (90.0, Ev::Box(BoxMode::Pass)),
        ],
        asynchronous_dns: false,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    eprintln!("{}{}", describe_plan(&plan), describe_outcome(&outcome));
    assert!(
        !outcome.violations.iter().any(|violation| matches!(violation, Violation::Stall { .. })),
        "the call stalled"
    );
}

/// Seed 3040: a call answered while the session was on HTTP, then the session moved to TCP. The
/// answer must still arrive (the test server released HTTP-delayed answers only from HTTP threads).
#[test]
fn explorer_minimal_answer_across_a_switch_to_tcp() {
    let session = SessionPlan {
        main: true,
        transport: TransportPreference::Http,
        keep_connected: true,
        idle: Some(20.0),
        pfs: None,
        key: KeyPlan::Preset,
        proxy: ProxyKind::None,
        addresses: AddrKind::Empty,
        online: false,
    };
    let plan = Plan {
        seed: 3040,
        server: ServerPlan::Plain,
        sessions: vec![session],
        events: vec![
            (54.24, Ev::Addresses { s: 0, kind: AddrKind::BlackFirst }),
            (55.41, Ev::Box(BoxMode::Reset)),
            (
                112.26,
                Ev::Send { s: 0, tag: Tag::DropConnectionOnce, timeout_timer: false, chain: false, delegate: false },
            ),
            (114.19, Ev::Send { s: 0, tag: Tag::Plain, timeout_timer: true, chain: false, delegate: true }),
            (117.00, Ev::Reset),
            (118.80, Ev::Box(BoxMode::Pass)),
            (120.90, Ev::Transport { s: 0, transport: TransportPreference::Auto }),
        ],
        asynchronous_dns: false,
        dns_delay: 0.5,
    };
    let outcome = run_plan(&plan, None);
    eprintln!("{}{}", describe_plan(&plan), describe_outcome(&outcome));
    assert!(
        !outcome.violations.iter().any(|violation| matches!(violation, Violation::Stall { .. })),
        "the call stalled"
    );
}

/// Seed 4082: a call on a TCP connection the server stalls while it runs the call; the engine races a
/// fresh connection and sends the call again. The answer must arrive (the test server cached the
/// answer for duplicates only after the stall).
#[test]
fn explorer_minimal_answer_after_a_stalled_connection_is_raced() {
    let session = SessionPlan {
        main: false,
        transport: TransportPreference::Http,
        keep_connected: true,
        idle: None,
        pfs: None,
        key: KeyPlan::Generate,
        proxy: ProxyKind::None,
        addresses: AddrKind::Empty,
        online: true,
    };
    let plan = Plan {
        seed: 4082,
        server: ServerPlan::Chaos,
        sessions: vec![session],
        events: vec![
            (51.35, Ev::Send { s: 0, tag: Tag::Plain, timeout_timer: true, chain: false, delegate: false }),
            (55.77, Ev::Transport { s: 0, transport: TransportPreference::Auto }),
        ],
        asynchronous_dns: true,
        dns_delay: 2.0,
    };
    let outcome = run_plan(&plan, None);
    eprintln!("{}{}", describe_plan(&plan), describe_outcome(&outcome));
    assert!(
        !outcome.violations.iter().any(|violation| matches!(violation, Violation::Stall { .. })),
        "the call stalled"
    );
}

// ---------------------------------------------------------------------------------------------------
// Fixed schedules from explorer failures (seeds 4129, 4132, 4284, 5218)

fn fixed_session(
    main: bool,
    transport: TransportPreference,
    keep_connected: bool,
    idle: Option<f64>,
    pfs: Option<i32>,
    key: KeyPlan,
    online: bool,
) -> SessionPlan {
    SessionPlan {
        main,
        transport,
        keep_connected,
        idle,
        pfs,
        key,
        proxy: ProxyKind::None,
        addresses: AddrKind::Literal,
        online,
    }
}

fn fixed_send(s: usize, tag: Tag) -> Ev {
    Ev::Send { s, tag, timeout_timer: false, chain: false, delegate: false }
}

fn fixed_report(name: &str, plan: &Plan, outcome: &Outcome) {
    eprintln!("{name}:\n{}{}", describe_plan(plan), describe_outcome(outcome));
    if std::env::var_os("EXPLORER_LOGS").is_some() {
        eprintln!("{}", outcome.logs.join("\n"));
    }
}

/// Seed 4129 shrunk: a TCP session making its own keys, `destroy_auth_key`, then `enable_pfs` and a call.
#[test]
fn explorer_minimal_pfs_after_destroy_runs_each_call_once() {
    let plan = Plan {
        seed: 4129,
        server: ServerPlan::SlowHttp,
        sessions: vec![fixed_session(true, TransportPreference::Tcp, true, Some(5.0), None, KeyPlan::Generate, true)],
        events: vec![
            (72.05, Ev::Box(BoxMode::Status(429))),
            (119.05, Ev::Destroy { s: 0 }),
            (122.51, Ev::Send { s: 0, tag: Tag::Forged404Once, timeout_timer: false, chain: false, delegate: true }),
            (148.05, Ev::EnablePfs { s: 0, lifetime: 90 }),
            (149.32, fixed_send(0, Tag::Plain)),
        ],
        asynchronous_dns: true,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    fixed_report("seed 4129", &plan, &outcome);
    assert!(!outcome.violations.iter().any(|v| v.kind() == "duplicate"), "a call ran twice");
}

/// Seed 4132 shrunk: an HTTP session on a server that refuses every bind; PFS enabled, then the host
/// gives a new permanent key.
#[test]
fn explorer_minimal_refused_binds_do_not_churn_connections() {
    let plan = Plan {
        seed: 4132,
        server: ServerPlan::RefuseBinds,
        sessions: vec![fixed_session(true, TransportPreference::Http, true, Some(5.0), None, KeyPlan::Preset, true)],
        events: vec![(14.39, Ev::EnablePfs { s: 0, lifetime: 90 }), (16.85, Ev::AuthKeyNew { s: 0 })],
        asynchronous_dns: true,
        dns_delay: 0.5,
    };
    let outcome = run_plan(&plan, None);
    fixed_report("seed 4132", &plan, &outcome);
    assert!(!outcome.violations.iter().any(|v| v.kind() == "churn"), "connections churned");
}

/// Seed 4284's mechanism alone: answers are dropped while the clock runs past 300 s; the server keeps the
/// answer and re-sends it with its original msg_id on every new connection, the session discards it (older
/// than 300 s by its server-time estimate, and the request was sent more than 300 s ago), the server says
/// "received" to `msgs_state_req`, and the call waits for ever. `outage` is the virtual time the answers
/// are lost for.
fn answer_outage(outage: f64) -> Outcome {
    let plan = Plan {
        seed: 4284,
        server: ServerPlan::Plain,
        sessions: vec![fixed_session(true, TransportPreference::Tcp, true, None, None, KeyPlan::Preset, false)],
        events: vec![(1.0, Ev::Box(BoxMode::DropAnswers)), (2.0, fixed_send(0, Tag::Plain)), (2.5, Ev::Sleep(outage))],
        asynchronous_dns: false,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    fixed_report(&format!("answer outage {outage} s"), &plan, &outcome);
    outcome
}

#[test]
fn an_answer_held_past_the_time_window_still_completes_its_call() {
    let short = answer_outage(200.0);
    assert!(!short.violations.iter().any(|v| v.kind() == "stall"), "control: the call stalled after a 200 s outage");
    let long = answer_outage(330.0);
    assert!(!long.violations.iter().any(|v| v.kind() == "stall"), "the call stalled after a 330 s outage");
}

/// Seed 4129's first half: `destroy_auth_key` on a session without PFS does not hold the calls sent after
/// it; they go out in the same container, under the key being destroyed.
/// What the server saw: calls with the key they ran under, keys destroyed, refused binds, runs of call 2,
/// and whether the engine reported the permanent key invalid.
type AfterDestroy = (Vec<(u32, u64)>, Vec<u64>, Vec<String>, u32, bool);

fn calls_after_destroy(pfs_after: bool) -> AfterDestroy {
    use mtproto_core::rpc::RpcEvent;
    let key = random_key(4129);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(64);
    let mut scratch = vec![0u8; 256 * 1024];
    let mut rng = OsRandom::new();
    let start = crate::clock::now();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.transport = TransportPreference::Tcp;
    setup.http_port = None;
    setup.auth_key = Some(material(&key, start));
    let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(16), start, &mut rng);
    let recorder = Arc::new(Recorder::default());
    let callbacks: Arc<dyn EngineCallbacks> = recorder.clone();
    let config = EngineConfig::default();
    let mut completed = std::collections::HashSet::new();
    let mut permanent_invalid = false;
    #[allow(clippy::too_many_arguments)]
    fn turn(
        runtime: &mut SessionRuntime,
        poll: &mut mio::Poll,
        events: &mut mio::Events,
        scratch: &mut [u8],
        rng: &mut OsRandom,
        recorder: &Arc<Recorder>,
        callbacks: &Arc<dyn EngineCallbacks>,
        config: &EngineConfig,
        completed: &mut std::collections::HashSet<u64>,
        invalid: &mut bool,
    ) {
        poll.poll(events, Some(Duration::from_millis(2))).unwrap();
        let now = crate::clock::now();
        for event in events.iter() {
            let readable = event.is_readable() || event.is_read_closed() || event.is_error();
            let writable = event.is_writable() || event.is_write_closed();
            runtime.handle_io(event.token(), readable, writable, poll.registry(), scratch, now, callbacks, rng);
        }
        runtime.drive(poll.registry(), now, &mut NoLookups, config, callbacks, rng);
        for (_, event) in std::mem::take(&mut *recorder.events.lock().unwrap()) {
            match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => {
                    completed.insert(id.0);
                }
                EngineEvent::PermanentKeyInvalid => *invalid = true,
                _ => {}
            }
        }
    }
    runtime.send(plain_request(1), start);
    let real = Instant::now();
    while !completed.contains(&1) && real.elapsed() < Duration::from_secs(10) {
        turn(
            &mut runtime,
            &mut poll,
            &mut events,
            &mut scratch,
            &mut rng,
            &recorder,
            &callbacks,
            &config,
            &mut completed,
            &mut permanent_invalid,
        );
    }
    let now = crate::clock::now();
    runtime.destroy_auth_key(now, poll.registry(), &callbacks, &mut rng);
    if pfs_after {
        runtime.enable_pfs(
            PfsSetup { lifetime: 90, public_keys: public_keys(), ..Default::default() },
            now,
            poll.registry(),
            &callbacks,
            &mut rng,
        );
    }
    runtime.send(plain_request(2), now);
    let real = Instant::now();
    while real.elapsed() < Duration::from_secs(5) {
        turn(
            &mut runtime,
            &mut poll,
            &mut events,
            &mut scratch,
            &mut rng,
            &recorder,
            &callbacks,
            &config,
            &mut completed,
            &mut permanent_invalid,
        );
    }
    runtime.shutdown(poll.registry(), crate::clock::now());
    let (executed, destroyed, binds) = server.with_stats(|stats| {
        (stats.executed_with_key.clone(), stats.destroyed_keys.clone(), stats.bind_failures.clone())
    });
    let runs = server.with_stats(|stats| stats.unique_executions.get(&(1, 2)).copied().unwrap_or(0));
    (executed, destroyed, binds, runs, permanent_invalid)
}

#[test]
fn calls_sent_during_destroy_auth_key_wait_for_it() {
    let key_id = random_key(4129).id();
    let (executed, destroyed, _, runs, _) = calls_after_destroy(false);
    eprintln!("without PFS: executed (tag, key) {executed:?}, destroyed {destroyed:?}, call 2 ran {runs} times");
    assert!(destroyed.contains(&key_id), "control: destroy_auth_key never reached the server");
    let under_destroyed = executed.iter().filter(|(tag, key)| *tag == 1 && *key == key_id).count();
    assert!(under_destroyed <= 1, "call 2, sent after destroy_auth_key, ran under the key being destroyed");
}

#[test]
fn enable_pfs_during_destroy_auth_key_finishes_the_destroy_first() {
    let key_id = random_key(4129).id();
    let (executed, destroyed, binds, runs, invalid) = calls_after_destroy(true);
    eprintln!(
        "PFS enabled during the destroy: executed (tag, key) {executed:?}, destroyed {destroyed:?}, bind failures {binds:?}, PermanentKeyInvalid {invalid}, call 2 ran {runs} times"
    );
    assert!(destroyed.contains(&key_id), "the host's destroy_auth_key never reached the server");
    assert!(binds.is_empty() && !invalid, "PFS took the key being destroyed as its permanent key: binds {binds:?}");
}

/// Seed 5218's shape: an HTTP session whose name lists a black-holed address first. Long polls parked on
/// black-holed connections fill the slot target, so no long poll is parked where the server can answer;
/// a `bad_msg_notification` 17 then starts a drain that cannot receive the answers of the queries the
/// server acknowledged, the session resets, and those queries run again.
fn drain_with_dead_slots(variant: u32) -> Outcome {
    let mut session = fixed_session(false, TransportPreference::Http, true, Some(60.0), None, KeyPlan::Preset, true);
    session.addresses = if variant >= 2 { AddrKind::Literal } else { AddrKind::BlackFirst };
    let events = match variant {
        2 => vec![
            (1.0, Ev::Box(BoxMode::Blackhole)),
            (2.0, fixed_send(0, Tag::Plain)),
            (2.2, fixed_send(0, Tag::Plain)),
            (2.4, fixed_send(0, Tag::BadMsg17)),
            (2.6, fixed_send(0, Tag::Plain)),
            (5.0, Ev::Addresses { s: 0, kind: AddrKind::BlackFirst }),
        ],
        3 => vec![
            (1.0, Ev::Box(BoxMode::Blackhole)),
            (2.0, fixed_send(0, Tag::Plain)),
            (2.2, fixed_send(0, Tag::Plain)),
            (2.4, fixed_send(0, Tag::BadMsg17)),
            (2.6, fixed_send(0, Tag::Plain)),
            (40.0, Ev::Addresses { s: 0, kind: AddrKind::BlackFirst }),
        ],
        0 => vec![
            (1.0, fixed_send(0, Tag::Plain)),
            (1.2, fixed_send(0, Tag::Plain)),
            (1.4, fixed_send(0, Tag::BadMsg17)),
            (1.6, fixed_send(0, Tag::Plain)),
        ],
        _ => vec![
            (1.0, fixed_send(0, Tag::Plain)),
            (30.0, Ev::Box(BoxMode::Reset)),
            (32.0, Ev::Box(BoxMode::Pass)),
            (40.0, fixed_send(0, Tag::Plain)),
            (40.1, fixed_send(0, Tag::Plain)),
            (40.2, fixed_send(0, Tag::BadMsg17)),
            (40.3, fixed_send(0, Tag::Plain)),
        ],
    };
    let plan = Plan {
        seed: 5218,
        server: ServerPlan::Plain,
        sessions: vec![session],
        events,
        asynchronous_dns: false,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    fixed_report(&format!("drain with dead slots, variant {variant}"), &plan, &outcome);
    outcome
}

#[test]
fn a_drain_over_http_with_long_polls_on_dead_connections_runs_each_call_once() {
    let variant = env_or("R10_VARIANT", 2) as u32;
    let outcome = drain_with_dead_slots(variant);
    assert!(!outcome.violations.iter().any(|v| v.kind() == "duplicate"), "calls ran twice");
}

/// Seed 6001: Auto counted TCP as struggling after two failed connections even while the current one
/// answered, so every turn opened an HTTP probe that the next turn cancelled.
#[test]
fn explorer_minimal_no_http_probe_while_tcp_answers() {
    let plan = Plan {
        seed: 6001,
        server: ServerPlan::Chaos,
        sessions: vec![
            SessionPlan {
                main: false,
                transport: TransportPreference::Http,
                keep_connected: false,
                idle: Some(5.0),
                pfs: None,
                key: KeyPlan::HostLater,
                proxy: ProxyKind::None,
                addresses: AddrKind::DeadFirst,
                online: false,
            },
            SessionPlan {
                main: true,
                transport: TransportPreference::Auto,
                keep_connected: true,
                idle: Some(60.0),
                pfs: Some(86400),
                key: KeyPlan::Preset,
                proxy: ProxyKind::None,
                addresses: AddrKind::Nx,
                online: false,
            },
        ],
        events: vec![
            (1.60, Ev::EnablePfs { s: 0, lifetime: 90 }),
            (13.73, Ev::Transport { s: 0, transport: TransportPreference::Auto }),
            (85.86, Ev::Addresses { s: 1, kind: AddrKind::BlackFirst }),
            (90.15, Ev::Box(BoxMode::Reset)),
            (93.11, Ev::Send { s: 0, tag: Tag::Plain, timeout_timer: false, chain: false, delegate: false }),
            (104.14, Ev::AuthKeyNone { s: 1 }),
        ],
        asynchronous_dns: true,
        dns_delay: 0.5,
    };
    let outcome = run_plan(&plan, None);
    eprintln!("{}{}", describe_plan(&plan), describe_outcome(&outcome));
    assert!(!outcome.violations.iter().any(|violation| violation.kind() == "churn"), "connections churned");
}

/// Seed 6028: a call answered while the session moved from HTTP back to TCP; the answer has to reach
/// the TCP connection (the test server delivered a session's queued answers only on a connection's first
/// packet).
#[test]
fn explorer_minimal_answer_across_a_switch_back_to_tcp() {
    let plan = Plan {
        seed: 6028,
        server: ServerPlan::Chaos,
        sessions: vec![
            SessionPlan {
                main: true,
                transport: TransportPreference::Auto,
                keep_connected: true,
                idle: Some(60.0),
                pfs: None,
                key: KeyPlan::Preset,
                proxy: ProxyKind::None,
                addresses: AddrKind::BlackFirst,
                online: false,
            },
            SessionPlan {
                main: false,
                transport: TransportPreference::Auto,
                keep_connected: false,
                idle: None,
                pfs: None,
                key: KeyPlan::Preset,
                proxy: ProxyKind::None,
                addresses: AddrKind::Literal,
                online: false,
            },
        ],
        events: vec![
            (112.33, Ev::TcpBlackhole(true)),
            (117.78, Ev::EnablePfs { s: 0, lifetime: 90 }),
            (147.45, Ev::Send { s: 1, tag: Tag::Plain, timeout_timer: false, chain: false, delegate: true }),
            (167.22, Ev::Sleep(15.0)),
        ],
        asynchronous_dns: false,
        dns_delay: 0.5,
    };
    let outcome = run_plan(&plan, None);
    eprintln!("{}{}", describe_plan(&plan), describe_outcome(&outcome));
    assert!(
        !outcome.violations.iter().any(|violation| matches!(violation, Violation::Stall { .. })),
        "the call stalled"
    );
}

// ---------------------------------------------------------------------------------------------------
// Fixed schedules: calls in flight around destroy_auth_key

fn destroy_then_pfs(pfs_from_start: bool, enable_pfs: bool) -> Outcome {
    let mut session = fixed_session(true, TransportPreference::Tcp, true, None, None, KeyPlan::Preset, true);
    if pfs_from_start {
        session.pfs = Some(90);
    }
    let mut events =
        vec![(20.0, Ev::Box(BoxMode::DropAnswers)), (21.0, fixed_send(0, Tag::Plain)), (22.0, Ev::Destroy { s: 0 })];
    if enable_pfs {
        events.push((23.0, Ev::EnablePfs { s: 0, lifetime: 90 }));
    }
    events.push((25.0, Ev::Box(BoxMode::Pass)));
    let plan = Plan {
        seed: 11_001,
        server: ServerPlan::Plain,
        sessions: vec![session],
        events,
        asynchronous_dns: false,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    fixed_report(&format!("destroy (pfs from start {pfs_from_start}, enable_pfs {enable_pfs})"), &plan, &outcome);
    outcome
}

#[test]
fn a_pfs_session_destroy_fails_the_call_in_flight() {
    let outcome = destroy_then_pfs(true, false);
    assert!(
        !outcome.violations.iter().any(|v| v.kind().starts_with("duplicate")),
        "control: PFS destroy re-ran a call"
    );
}

#[test]
fn enable_pfs_during_destroy_runs_the_call_in_flight_once() {
    let outcome = destroy_then_pfs(false, true);
    assert!(!outcome.violations.iter().any(|v| v.kind().starts_with("duplicate")), "the call in flight ran twice");
}

#[test]
fn enable_pfs_during_answered_destroy_runs_the_call_in_flight_once() {
    let session = fixed_session(true, TransportPreference::Tcp, true, None, None, KeyPlan::Preset, true);
    let events = vec![
        (20.0, Ev::Box(BoxMode::DropAnswers)),
        (21.0, fixed_send(0, Tag::Plain)),
        (21.5, Ev::Box(BoxMode::Pass)),
        (22.0, Ev::Destroy { s: 0 }),
        (22.2, Ev::EnablePfs { s: 0, lifetime: 90 }),
    ];
    let plan = Plan {
        seed: 11_002,
        server: ServerPlan::Plain,
        sessions: vec![session],
        events,
        asynchronous_dns: false,
        dns_delay: 0.0,
    };
    let outcome = run_plan(&plan, None);
    fixed_report("answered destroy then enable_pfs", &plan, &outcome);
    assert!(!outcome.violations.iter().any(|v| v.kind().starts_with("duplicate")), "the call in flight ran twice");
}
