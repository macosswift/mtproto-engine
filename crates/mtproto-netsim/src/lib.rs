#![allow(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackholeEnd {
    Resume,
    Reset,
    Dead,
}

#[derive(Debug, Clone, Copy)]
pub struct Blackhole {
    pub after_min: Duration,
    pub after_max: Duration,
    pub duration: Duration,
    pub end: BlackholeEnd,
}

/// Periodic outages of the whole link, as in a tunnel: every `every_min`–`every_max` the link goes
/// dark for `length`, swallowing live connections and refusing new ones.
#[derive(Debug, Clone, Copy)]
pub struct Tunnel {
    pub every_min: Duration,
    pub every_max: Duration,
    pub length: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiAction {
    Reset,
    Blackhole,
}

#[derive(Debug, Clone, Copy)]
pub struct Dpi {
    pub after_bytes_up: u64,
    pub action: DpiAction,
    pub fraction: f64,
    /// Lets connections through that start like an HTTP request, as a firewall that only allows
    /// web traffic does.
    pub spare_http: bool,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub latency: Duration,
    pub jitter: Duration,
    pub bandwidth: Option<u64>,
    /// Bytes per second from the client when it differs from `bandwidth`.
    pub uplink: Option<u64>,
    pub max_chunk: usize,
    pub stall_probability: f64,
    pub stall: Duration,
    pub reset_after: Option<(Duration, Duration)>,
    pub blackhole: Option<Blackhole>,
    pub tunnel: Option<Tunnel>,
    pub refuse_probability: f64,
    pub connect_delay: Duration,
    pub dpi: Option<Dpi>,
    pub queue_limit: Option<usize>,
    /// One first-in, first-out bottleneck queue per direction shared by all connections, holding up
    /// to this much transfer time, as a cellular modem's buffer does: bulk data sent first delays
    /// everything sent after it on any connection. Without it connections share the link fairly.
    pub fifo_queue: Option<Duration>,
    /// A carrier NAT or firewall forgets a connection that carried nothing either way for this long
    /// and from then on silently drops its packets both ways.
    pub idle_timeout: Option<Duration>,
}

impl Profile {
    pub fn perfect() -> Self {
        Self {
            name: "perfect".into(),
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            bandwidth: None,
            uplink: None,
            max_chunk: 64 * 1024,
            stall_probability: 0.0,
            stall: Duration::ZERO,
            reset_after: None,
            blackhole: None,
            tunnel: None,
            refuse_probability: 0.0,
            connect_delay: Duration::ZERO,
            dpi: None,
            queue_limit: None,
            fifo_queue: None,
            idle_timeout: None,
        }
    }

    pub fn slow_uplink() -> Self {
        Self {
            name: "slow-uplink".into(),
            latency: Duration::from_millis(20),
            jitter: Duration::from_millis(2),
            bandwidth: Some(30_000),
            max_chunk: 4096,
            queue_limit: Some(64 * 1024),
            ..Self::perfect()
        }
    }

    pub fn edge() -> Self {
        Self {
            name: "edge".into(),
            latency: Duration::from_millis(450),
            jitter: Duration::from_millis(300),
            bandwidth: Some(64_000 / 8),
            max_chunk: 512,
            stall_probability: 0.03,
            stall: Duration::from_millis(1500),
            refuse_probability: 0.1,
            connect_delay: Duration::from_millis(600),
            ..Self::perfect()
        }
    }

    pub fn edge_flaky() -> Self {
        Self {
            name: "edge-flaky".into(),
            reset_after: Some((Duration::from_secs(8), Duration::from_secs(25))),
            ..Self::edge()
        }
    }

    pub fn dpi(name: &str, action: DpiAction, fraction: f64) -> Self {
        Self {
            name: name.into(),
            latency: Duration::from_millis(30),
            jitter: Duration::from_millis(10),
            dpi: Some(Dpi { after_bytes_up: 0, action, fraction, spare_http: false }),
            ..Self::perfect()
        }
    }

    /// `base` behind a filter that only lets HTTP through: anything else is blackholed (or reset,
    /// when `base` already resets) from its first byte.
    pub fn http_only(name: &str, base: Self) -> Self {
        let action = base.dpi.map_or(DpiAction::Blackhole, |dpi| dpi.action);
        Self {
            name: name.into(),
            dpi: Some(Dpi { after_bytes_up: 0, action, fraction: 1.0, spare_http: true }),
            ..base
        }
    }

    pub fn broadband() -> Self {
        Self {
            name: "broadband".into(),
            latency: Duration::from_millis(15),
            jitter: Duration::from_millis(3),
            bandwidth: Some(50 * 1024 * 1024 / 8),
            ..Self::perfect()
        }
    }

    pub fn wan() -> Self {
        Self {
            name: "wan".into(),
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            bandwidth: Some(200_000_000 / 8),
            ..Self::perfect()
        }
    }

    pub fn mobile_3g() -> Self {
        Self {
            name: "3g".into(),
            latency: Duration::from_millis(150),
            jitter: Duration::from_millis(60),
            bandwidth: Some(1_500_000 / 8),
            max_chunk: 1400,
            stall_probability: 0.01,
            stall: Duration::from_millis(400),
            ..Self::perfect()
        }
    }

    pub fn lossy() -> Self {
        Self {
            name: "lossy".into(),
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(40),
            bandwidth: Some(4_000_000 / 8),
            max_chunk: 1400,
            stall_probability: 0.05,
            stall: Duration::from_millis(600),
            ..Self::perfect()
        }
    }

    pub fn flaky() -> Self {
        Self {
            name: "flaky".into(),
            latency: Duration::from_millis(60),
            jitter: Duration::from_millis(30),
            bandwidth: Some(8_000_000 / 8),
            max_chunk: 4096,
            reset_after: Some((Duration::from_secs(2), Duration::from_secs(6))),
            refuse_probability: 0.2,
            connect_delay: Duration::from_millis(100),
            ..Self::perfect()
        }
    }

    pub fn blackholes() -> Self {
        Self {
            name: "blackholes".into(),
            latency: Duration::from_millis(40),
            jitter: Duration::from_millis(10),
            bandwidth: Some(10_000_000 / 8),
            blackhole: Some(Blackhole {
                after_min: Duration::from_secs(2),
                after_max: Duration::from_secs(5),
                duration: Duration::from_secs(3),
                end: BlackholeEnd::Dead,
            }),
            ..Self::perfect()
        }
    }

    /// GPRS/EDGE at the edge of coverage: long and jumpy round trips, a trickle of bandwidth,
    /// multi-second stalls and slow, sometimes refused connects.
    pub fn gprs() -> Self {
        Self {
            name: "gprs".into(),
            latency: Duration::from_millis(500),
            jitter: Duration::from_millis(250),
            bandwidth: Some(48_000 / 8),
            max_chunk: 256,
            stall_probability: 0.05,
            stall: Duration::from_millis(2500),
            refuse_probability: 0.1,
            connect_delay: Duration::from_millis(1500),
            ..Self::perfect()
        }
    }

    /// A geostationary satellite link: 600 ms round trips with little jitter.
    pub fn satellite() -> Self {
        Self {
            name: "satellite".into(),
            latency: Duration::from_millis(300),
            jitter: Duration::from_millis(15),
            bandwidth: Some(4_000_000 / 8),
            max_chunk: 1400,
            ..Self::perfect()
        }
    }

    /// A mobile link on a train: 3G-like, with a tunnel every 8–20 s in which the whole link is
    /// dark for 6 s, live connections and new ones alike.
    pub fn train() -> Self {
        Self {
            name: "train".into(),
            latency: Duration::from_millis(120),
            jitter: Duration::from_millis(80),
            bandwidth: Some(1_000_000 / 8),
            max_chunk: 1400,
            tunnel: Some(Tunnel {
                every_min: Duration::from_secs(8),
                every_max: Duration::from_secs(20),
                length: Duration::from_secs(6),
            }),
            ..Self::perfect()
        }
    }

    /// Heavy loss: every eighth chunk or so stalls for most of a second.
    pub fn lossy_heavy() -> Self {
        Self {
            name: "lossy-heavy".into(),
            latency: Duration::from_millis(100),
            jitter: Duration::from_millis(80),
            bandwidth: Some(2_000_000 / 8),
            max_chunk: 1400,
            stall_probability: 0.12,
            stall: Duration::from_millis(900),
            ..Self::perfect()
        }
    }

    /// A usable downlink with a starved uplink, as on congested cells: sending media crawls.
    pub fn uplink_starved() -> Self {
        Self {
            name: "uplink-starved".into(),
            latency: Duration::from_millis(60),
            jitter: Duration::from_millis(20),
            bandwidth: Some(8_000_000 / 8),
            uplink: Some(64_000 / 8),
            max_chunk: 1400,
            ..Self::perfect()
        }
    }

    /// A 3G link behind a carrier NAT that forgets connections idle for 30 s, as many do: an app that
    /// pings less often finds its connection silently dead after every pause.
    pub fn nat() -> Self {
        Self {
            name: "nat".into(),
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(30),
            bandwidth: Some(1_500_000 / 8),
            max_chunk: 1400,
            idle_timeout: Some(Duration::from_secs(30)),
            ..Self::perfect()
        }
    }

    /// A loaded LTE cell: a fair downlink, a 256 kbit/s uplink behind a modem buffer holding 3 s of
    /// data, so a running upload delays every request sent after it.
    pub fn bufferbloat() -> Self {
        Self {
            name: "bufferbloat".into(),
            latency: Duration::from_millis(40),
            jitter: Duration::from_millis(10),
            bandwidth: Some(4_000_000 / 8),
            uplink: Some(256_000 / 8),
            max_chunk: 1400,
            fifo_queue: Some(Duration::from_secs(3)),
            ..Self::perfect()
        }
    }

    /// A congested cell's downlink: 1 Mbit/s behind a base-station buffer holding 5 s of data, so a
    /// running download delays every answer and pong behind it by seconds. The buffer is per
    /// direction, so the 512 kbit/s uplink queues up to 5 s behind an upload as well.
    pub fn bufferbloat_down() -> Self {
        Self {
            name: "bufferbloat-down".into(),
            latency: Duration::from_millis(40),
            jitter: Duration::from_millis(10),
            bandwidth: Some(1_000_000 / 8),
            uplink: Some(512_000 / 8),
            max_chunk: 1400,
            fifo_queue: Some(Duration::from_secs(5)),
            ..Self::perfect()
        }
    }

    /// Wi-Fi to cellular handovers: connections reset every 4–12 s, reconnects are slow and some
    /// are refused.
    pub fn handover() -> Self {
        Self {
            name: "handover".into(),
            latency: Duration::from_millis(40),
            jitter: Duration::from_millis(15),
            bandwidth: Some(10_000_000 / 8),
            reset_after: Some((Duration::from_secs(4), Duration::from_secs(12))),
            refuse_probability: 0.15,
            connect_delay: Duration::from_millis(800),
            ..Self::perfect()
        }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "perfect" => Some(Self::perfect()),
            "broadband" => Some(Self::broadband()),
            "slow-uplink" => Some(Self::slow_uplink()),
            "wan" => Some(Self::wan()),
            "3g" => Some(Self::mobile_3g()),
            "lossy" => Some(Self::lossy()),
            "flaky" => Some(Self::flaky()),
            "blackholes" => Some(Self::blackholes()),
            "edge" => Some(Self::edge()),
            "edge-flaky" => Some(Self::edge_flaky()),
            "gprs" => Some(Self::gprs()),
            "satellite" => Some(Self::satellite()),
            "train" => Some(Self::train()),
            "lossy-heavy" => Some(Self::lossy_heavy()),
            "uplink-starved" => Some(Self::uplink_starved()),
            "handover" => Some(Self::handover()),
            "bufferbloat" => Some(Self::bufferbloat()),
            "bufferbloat-down" => Some(Self::bufferbloat_down()),
            "nat" => Some(Self::nat()),
            "dpi-reset" => Some(Self::dpi("dpi-reset", DpiAction::Reset, 1.0)),
            "dpi-blackhole" => Some(Self::dpi("dpi-blackhole", DpiAction::Blackhole, 1.0)),
            "dpi-half" => Some(Self::dpi("dpi-half", DpiAction::Blackhole, 0.5)),
            "http-only" => Some(Self::http_only("http-only", Self::dpi("http-only", DpiAction::Blackhole, 1.0))),
            "http-only-reset" => Some(Self::http_only("http-only-reset", Self::dpi("x", DpiAction::Reset, 1.0))),
            "http-only-3g" => Some(Self::http_only("http-only-3g", Self::mobile_3g())),
            "http-only-lossy" => Some(Self::http_only("http-only-lossy", Self::lossy())),
            _ => None,
        }
    }

    pub fn all_names() -> &'static [&'static str] {
        &[
            "perfect",
            "broadband",
            "slow-uplink",
            "wan",
            "3g",
            "lossy",
            "flaky",
            "blackholes",
            "edge",
            "edge-flaky",
            "gprs",
            "satellite",
            "train",
            "lossy-heavy",
            "uplink-starved",
            "handover",
            "bufferbloat",
            "bufferbloat-down",
            "nat",
            "dpi-reset",
            "dpi-blackhole",
            "dpi-half",
            "http-only",
            "http-only-reset",
            "http-only-3g",
            "http-only-lossy",
        ]
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub connections: u64,
    pub refused: u64,
    pub resets: u64,
    pub blackholes: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

struct Bucket {
    rate: Option<f64>,
    available: f64,
    last: Instant,
    /// When the FIFO bottleneck finishes sending what is queued in it.
    busy_until: Instant,
}

impl Bucket {
    fn new(rate: Option<f64>) -> Self {
        let now = Instant::now();
        Self { rate, available: 0.0, last: now, busy_until: now }
    }

    fn queued(&self, now: Instant) -> Duration {
        self.busy_until.saturating_duration_since(now)
    }

    /// Queues `bytes` behind everything already in the FIFO bottleneck; returns when they are through.
    fn enqueue(&mut self, bytes: usize, now: Instant) -> Instant {
        let Some(rate) = self.rate else {
            return now;
        };
        self.busy_until = self.busy_until.max(now) + Duration::from_secs_f64(bytes as f64 / rate);
        self.busy_until
    }

    fn delay_for(&mut self, bytes: usize) -> Duration {
        let Some(rate) = self.rate else {
            return Duration::ZERO;
        };
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.available = (self.available + elapsed * rate).min(rate * 0.05);
        self.available -= bytes as f64;
        if self.available >= 0.0 { Duration::ZERO } else { Duration::from_secs_f64(-self.available / rate) }
    }
}

struct Random(u64);

impl Random {
    /// Spreads the seed over the whole state: xorshift draws small numbers first from a small state,
    /// which refused every first connection, and `seed | 1` alone made neighbouring seeds identical.
    fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Self((z ^ (z >> 31)) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn between(&mut self, min: Duration, max: Duration) -> Duration {
        if max <= min {
            return min;
        }
        min + Duration::from_secs_f64((max - min).as_secs_f64() * self.unit())
    }
}

type Chunk = Option<(Instant, Vec<u8>)>;

struct ConnectionControl {
    client: TcpStream,
    upstream: TcpStream,
    blackholed: AtomicBool,
    dead: AtomicBool,
    closed: AtomicBool,
    /// Blackholed by a tunnel, to come back when it ends.
    tunneled: AtomicBool,
    /// When the connection last carried bytes either way.
    active_at: Mutex<Instant>,
}

impl ConnectionControl {
    fn reset(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        for stream in [&self.client, &self.upstream] {
            let linger = libc::linger { l_onoff: 1, l_linger: 0 };
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    &linger as *const libc::linger as *const libc::c_void,
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                );
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct Shared {
    profile: Mutex<Profile>,
    up: Mutex<Bucket>,
    down: Mutex<Bucket>,
    stop: AtomicBool,
    outage_until: Mutex<Option<Instant>>,
    live: Mutex<Vec<Arc<ConnectionControl>>>,
    connections: AtomicU64,
    refused: AtomicU64,
    resets: AtomicU64,
    blackholes: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    seed: AtomicU64,
}

pub struct NetSim {
    pub address: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    tunnel_thread: Option<JoinHandle<()>>,
}

/// A tunnel stops all traffic and refuses new connections, but live connections survive it as TCP
/// connections do: what was sent meanwhile arrives once the link is back.
fn begin_tunnel(shared: &Shared, length: Duration) {
    *shared.outage_until.lock().unwrap() = Some(Instant::now() + length);
    for control in shared.live.lock().unwrap().iter() {
        if !control.blackholed.swap(true, Ordering::SeqCst) {
            control.tunneled.store(true, Ordering::SeqCst);
        }
    }
}

fn end_tunnel(shared: &Shared) {
    for control in shared.live.lock().unwrap().iter() {
        if control.tunneled.swap(false, Ordering::SeqCst) && !control.dead.load(Ordering::SeqCst) {
            control.blackholed.store(false, Ordering::SeqCst);
        }
    }
}

fn begin_outage(shared: &Shared, duration: Duration) {
    *shared.outage_until.lock().unwrap() = Some(Instant::now() + duration);
    for control in shared.live.lock().unwrap().iter() {
        control.dead.store(true, Ordering::SeqCst);
        control.blackholed.store(true, Ordering::SeqCst);
    }
}

/// Sleeps up to `duration`, waking early when the simulator stops. Returns false if it stopped.
fn sleep_unless_stopped(shared: &Shared, duration: Duration) -> bool {
    let until = Instant::now() + duration;
    while Instant::now() < until {
        if shared.stop.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep((until - Instant::now()).min(Duration::from_millis(20)));
    }
    !shared.stop.load(Ordering::Relaxed)
}

fn run_tunnels(shared: Arc<Shared>, seed: u64) {
    let mut random = Random::new(seed);
    loop {
        let Some(tunnel) = shared.profile.lock().unwrap().tunnel else {
            if !sleep_unless_stopped(&shared, Duration::from_millis(200)) {
                return;
            }
            continue;
        };
        let span = tunnel.every_max.saturating_sub(tunnel.every_min);
        let wait = tunnel.every_min + span.mul_f64(random.unit());
        if !sleep_unless_stopped(&shared, wait) {
            return;
        }
        begin_tunnel(&shared, tunnel.length);
        if !sleep_unless_stopped(&shared, tunnel.length) {
            return;
        }
        end_tunnel(&shared);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Upstream {
    Fixed(SocketAddr),
    Socks5,
}

impl NetSim {
    pub fn start(upstream: SocketAddr, profile: Profile, seed: u64) -> std::io::Result<Self> {
        Self::start_with(Upstream::Fixed(upstream), profile, seed, "127.0.0.1:0")
    }

    pub fn start_socks5(profile: Profile, seed: u64, bind: &str) -> std::io::Result<Self> {
        Self::start_with(Upstream::Socks5, profile, seed, bind)
    }

    pub fn start_with(upstream: Upstream, profile: Profile, seed: u64, bind: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        if let Some(limit) = profile.queue_limit {
            set_receive_buffer(&listener, limit);
        }
        let address = listener.local_addr()?;
        let rate = profile.bandwidth.map(|value| value as f64);
        let up_rate = profile.uplink.or(profile.bandwidth).map(|value| value as f64);
        let shared = Arc::new(Shared {
            profile: Mutex::new(profile),
            up: Mutex::new(Bucket::new(up_rate)),
            down: Mutex::new(Bucket::new(rate)),
            stop: AtomicBool::new(false),
            outage_until: Mutex::new(None),
            live: Mutex::new(Vec::new()),
            connections: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            resets: AtomicU64::new(0),
            blackholes: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            seed: AtomicU64::new(seed),
        });
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new().name("netsim-accept".into()).spawn(move || {
                while !shared.stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            let shared = shared.clone();
                            std::thread::spawn(move || handle_connection(client, upstream, shared));
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(_) => break,
                    }
                }
            })?
        };
        let tunnel_thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("netsim-tunnel".into())
                .spawn(move || run_tunnels(shared, seed ^ 0x7475_6e6e_656c))?
        };
        Ok(Self { address, shared, thread: Some(thread), tunnel_thread: Some(tunnel_thread) })
    }

    pub fn set_profile(&self, profile: Profile) {
        let rate = profile.bandwidth.map(|value| value as f64);
        self.shared.up.lock().unwrap().rate = profile.uplink.or(profile.bandwidth).map(|value| value as f64);
        self.shared.down.lock().unwrap().rate = rate;
        *self.shared.profile.lock().unwrap() = profile;
    }

    pub fn outage(&self, duration: Duration) {
        begin_outage(&self.shared, duration);
    }

    /// A tunnel that lasts until `end_tunnel`: new connections are refused, live ones wait it out.
    pub fn begin_tunnel(&self) {
        begin_tunnel(&self.shared, Duration::from_secs(24 * 3600));
    }

    pub fn end_tunnel(&self) {
        *self.shared.outage_until.lock().unwrap() = None;
        end_tunnel(&self.shared);
    }

    /// Ends an outage early: new connections get through again, the ones it killed stay dead.
    pub fn end_outage(&self) {
        *self.shared.outage_until.lock().unwrap() = None;
    }

    pub fn reset_all(&self) {
        let live: Vec<Arc<ConnectionControl>> = self.shared.live.lock().unwrap().drain(..).collect();
        for control in live {
            self.shared.resets.fetch_add(1, Ordering::Relaxed);
            control.reset();
        }
    }

    pub fn in_outage(&self) -> bool {
        self.shared.outage_until.lock().unwrap().is_some_and(|until| Instant::now() < until)
    }

    pub fn stats(&self) -> Stats {
        Stats {
            connections: self.shared.connections.load(Ordering::Relaxed),
            refused: self.shared.refused.load(Ordering::Relaxed),
            resets: self.shared.resets.load(Ordering::Relaxed),
            blackholes: self.shared.blackholes.load(Ordering::Relaxed),
            bytes_up: self.shared.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.shared.bytes_down.load(Ordering::Relaxed),
        }
    }
}

impl Drop for NetSim {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.reset_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.tunnel_thread.take() {
            let _ = thread.join();
        }
    }
}

fn socks5_accept(client: &mut TcpStream) -> Option<SocketAddr> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = [0u8; 2];
    client.read_exact(&mut head).ok()?;
    if head[0] != 5 {
        return None;
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).ok()?;
    client.write_all(&[5, 0]).ok()?;
    let mut request = [0u8; 4];
    client.read_exact(&mut request).ok()?;
    if request[0] != 5 || request[1] != 1 {
        return None;
    }
    let target = match request[3] {
        1 => {
            let mut address = [0u8; 6];
            client.read_exact(&mut address).ok()?;
            SocketAddr::from((
                [address[0], address[1], address[2], address[3]],
                u16::from_be_bytes([address[4], address[5]]),
            ))
        }
        4 => {
            let mut address = [0u8; 18];
            client.read_exact(&mut address).ok()?;
            let ip: [u8; 16] = address[..16].try_into().ok()?;
            SocketAddr::from((ip, u16::from_be_bytes([address[16], address[17]])))
        }
        3 => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).ok()?;
            let mut name = vec![0u8; length[0] as usize + 2];
            client.read_exact(&mut name).ok()?;
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            let host = String::from_utf8_lossy(&name[..name.len() - 2]).into_owned();
            (host.as_str(), port).to_socket_addrs().ok()?.next()?
        }
        _ => return None,
    };
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;
    let _ = client.set_read_timeout(None);
    Some(target)
}

fn set_receive_buffer(socket: &impl AsRawFd, bytes: usize) {
    let value = bytes.min(i32::MAX as usize) as libc::c_int;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// The client closed the connection while it was being set up, without sending anything.
fn client_gone(client: &TcpStream) -> bool {
    let _ = client.set_nonblocking(true);
    let mut probe = [0u8; 1];
    let gone = match client.peek(&mut probe) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => error.kind() != ErrorKind::WouldBlock,
    };
    let _ = client.set_nonblocking(false);
    gone
}

fn handle_connection(mut client: TcpStream, upstream: Upstream, shared: Arc<Shared>) {
    let _ = client.set_nonblocking(false);
    let profile = shared.profile.lock().unwrap().clone();
    if let Some(limit) = profile.queue_limit {
        set_receive_buffer(&client, limit);
    }
    let mut random = Random::new(shared.seed.fetch_add(1, Ordering::Relaxed));
    let outage = shared.outage_until.lock().unwrap().is_some_and(|until| Instant::now() < until);
    if outage || random.unit() < profile.refuse_probability {
        shared.refused.fetch_add(1, Ordering::Relaxed);
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        return;
    }
    let target = match upstream {
        Upstream::Fixed(address) => address,
        Upstream::Socks5 => match socks5_accept(&mut client) {
            Some(address) => address,
            None => return,
        },
    };
    if !profile.connect_delay.is_zero() {
        std::thread::sleep(profile.connect_delay);
        if client_gone(&client) {
            return;
        }
    }
    let Ok(upstream) = TcpStream::connect_timeout(&target, Duration::from_secs(10)) else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    shared.connections.fetch_add(1, Ordering::Relaxed);
    let (Ok(client_clone), Ok(upstream_clone)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let control = Arc::new(ConnectionControl {
        client: client_clone,
        upstream: upstream_clone,
        blackholed: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        tunneled: AtomicBool::new(false),
        active_at: Mutex::new(Instant::now()),
    });
    shared.live.lock().unwrap().push(control.clone());

    if let Some((min, max)) = profile.reset_after {
        let delay = random.between(min, max);
        let control = control.clone();
        let shared = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            if !control.closed.load(Ordering::SeqCst) {
                shared.resets.fetch_add(1, Ordering::Relaxed);
                control.reset();
            }
        });
    }
    if let Some(timeout) = profile.idle_timeout {
        let control = control.clone();
        let shared = shared.clone();
        std::thread::spawn(move || {
            while !control.closed.load(Ordering::SeqCst) && !shared.stop.load(Ordering::Relaxed) {
                let idle = control.active_at.lock().unwrap().elapsed();
                if idle >= timeout {
                    if !control.dead.swap(true, Ordering::SeqCst) {
                        shared.blackholes.fetch_add(1, Ordering::Relaxed);
                    }
                    control.blackholed.store(true, Ordering::SeqCst);
                    return;
                }
                std::thread::sleep((timeout - idle).min(Duration::from_millis(200)));
            }
        });
    }
    if let Some(blackhole) = profile.blackhole {
        let delay = random.between(blackhole.after_min, blackhole.after_max);
        let control = control.clone();
        let shared = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            if control.closed.load(Ordering::SeqCst) {
                return;
            }
            shared.blackholes.fetch_add(1, Ordering::Relaxed);
            control.blackholed.store(true, Ordering::SeqCst);
            if blackhole.end == BlackholeEnd::Dead {
                control.dead.store(true, Ordering::SeqCst);
            }
            std::thread::sleep(blackhole.duration);
            match blackhole.end {
                BlackholeEnd::Resume => control.blackholed.store(false, Ordering::SeqCst),
                BlackholeEnd::Reset => {
                    shared.resets.fetch_add(1, Ordering::Relaxed);
                    control.reset();
                }
                BlackholeEnd::Dead => {}
            }
        });
    }

    let dpi = profile.dpi.filter(|dpi| random.unit() < dpi.fraction);
    let up_seed = random.next();
    let down_seed = random.next();
    let (Ok(client_read), Ok(upstream_read)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = spawn_direction(client_read, upstream, shared.clone(), control.clone(), true, up_seed, dpi);
    let down = spawn_direction(upstream_read, client, shared.clone(), control.clone(), false, down_seed, None);
    let _ = up.join();
    let _ = down.join();
    control.closed.store(true, Ordering::SeqCst);
    shared.live.lock().unwrap().retain(|other| !Arc::ptr_eq(other, &control));
}

fn spawn_direction(
    mut source: TcpStream,
    destination: TcpStream,
    shared: Arc<Shared>,
    control: Arc<ConnectionControl>,
    upstream: bool,
    seed: u64,
    mut dpi: Option<Dpi>,
) -> JoinHandle<()> {
    let (queue_limit, max_chunk) = {
        let profile = shared.profile.lock().unwrap();
        (profile.queue_limit, profile.max_chunk.max(1))
    };
    let (sender, receiver): (ChunkSender, Receiver<Chunk>) = match queue_limit {
        Some(limit) => {
            let (sender, receiver) = sync_channel((limit / max_chunk).max(2));
            (ChunkSender::Bounded(sender), receiver)
        }
        None => {
            let (sender, receiver) = channel();
            (ChunkSender::Unbounded(sender), receiver)
        }
    };
    let writer = {
        let shared = shared.clone();
        let control = control.clone();
        std::thread::spawn(move || deliver(receiver, destination, shared, control, upstream))
    };
    std::thread::spawn(move || {
        let mut random = Random::new(seed);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut last_delivery = Instant::now();
        let mut seen: u64 = 0;
        let mut head: Vec<u8> = Vec::with_capacity(4);
        loop {
            match source.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    let _ = sender.send(None);
                    break;
                }
                Ok(read) => {
                    if dpi.is_some_and(|dpi| dpi.spare_http) && head.len() < 4 {
                        let take = (4 - head.len()).min(read);
                        head.extend_from_slice(&buffer[..take]);
                        if head.len() == 4 && matches!(head.as_slice(), b"POST" | b"GET " | b"HEAD" | b"OPTI" | b"PUT ")
                        {
                            dpi = None;
                        }
                    }
                    seen += read as u64;
                    *control.active_at.lock().unwrap() = Instant::now();
                    if let Some(dpi) = dpi
                        && seen > dpi.after_bytes_up
                        && !(dpi.spare_http && head.len() < 4)
                    {
                        match dpi.action {
                            DpiAction::Reset => {
                                shared.resets.fetch_add(1, Ordering::Relaxed);
                                control.reset();
                                let _ = sender.send(None);
                                break;
                            }
                            DpiAction::Blackhole => {
                                if !control.dead.swap(true, Ordering::SeqCst) {
                                    shared.blackholes.fetch_add(1, Ordering::Relaxed);
                                }
                                control.blackholed.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    let profile = shared.profile.lock().unwrap().clone();
                    let bucket = if upstream { &shared.up } else { &shared.down };
                    for chunk in buffer[..read].chunks(profile.max_chunk.max(1)) {
                        let mut delay = profile.latency + random.between(Duration::ZERO, profile.jitter);
                        if profile.stall_probability > 0.0 && random.unit() < profile.stall_probability {
                            delay += profile.stall;
                        }
                        let sent = match profile.fifo_queue {
                            Some(depth) => {
                                loop {
                                    let queued = bucket.lock().unwrap().queued(Instant::now());
                                    if queued <= depth || shared.stop.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    std::thread::sleep((queued - depth).min(Duration::from_millis(20)));
                                }
                                bucket.lock().unwrap().enqueue(chunk.len(), Instant::now())
                            }
                            None => Instant::now(),
                        };
                        let at = (sent + delay).max(last_delivery);
                        last_delivery = at;
                        if sender.send(Some((at, chunk.to_vec()))).is_err() {
                            return;
                        }
                    }
                }
            }
        }
        let _ = writer.join();
    })
}

enum ChunkSender {
    Unbounded(Sender<Chunk>),
    Bounded(SyncSender<Chunk>),
}

impl ChunkSender {
    fn send(&self, chunk: Chunk) -> Result<(), ()> {
        match self {
            ChunkSender::Unbounded(sender) => sender.send(chunk).map_err(|_| ()),
            ChunkSender::Bounded(sender) => sender.send(chunk).map_err(|_| ()),
        }
    }
}

/// Holds `bytes` for as long as the fairly shared link takes to pass them.
fn pace(shared: &Shared, upstream: bool, bytes: usize) {
    let bucket = if upstream { &shared.up } else { &shared.down };
    let wait = bucket.lock().unwrap().delay_for(bytes);
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

fn deliver(
    receiver: Receiver<Chunk>,
    mut destination: TcpStream,
    shared: Arc<Shared>,
    control: Arc<ConnectionControl>,
    upstream: bool,
) {
    let mut held: Vec<Vec<u8>> = Vec::new();
    loop {
        let item = match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(item) => Some(item),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if control.closed.load(Ordering::SeqCst) {
            return;
        }
        if control.blackholed.load(Ordering::SeqCst) {
            if let Some(Some((_, data))) = item
                && !control.dead.load(Ordering::SeqCst)
            {
                held.push(data);
            }
            continue;
        }
        if !held.is_empty() {
            let (latency, fifo) = {
                let profile = shared.profile.lock().unwrap();
                (profile.latency, profile.fifo_queue.is_some())
            };
            std::thread::sleep(latency);
            for data in held.drain(..) {
                if !fifo {
                    pace(&shared, upstream, data.len());
                }
                if destination.write_all(&data).is_err() {
                    return;
                }
                let counter = if upstream { &shared.bytes_up } else { &shared.bytes_down };
                counter.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        let Some(item) = item else {
            continue;
        };
        let Some((at, data)) = item else {
            let _ = destination.shutdown(Shutdown::Write);
            return;
        };
        let now = Instant::now();
        if at > now {
            std::thread::sleep(at - now);
        }
        if shared.profile.lock().unwrap().fifo_queue.is_none() {
            pace(&shared, upstream, data.len());
        }
        if control.blackholed.load(Ordering::SeqCst) {
            if !control.dead.load(Ordering::SeqCst) {
                held.push(data);
            }
            continue;
        }
        if destination.write_all(&data).is_err() {
            return;
        }
        let counter = if upstream { &shared.bytes_up } else { &shared.bytes_down };
        counter.fetch_add(data.len() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                if stream.write_all(&buffer[..read]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        address
    }

    #[test]
    fn relays_with_latency() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.latency = Duration::from_millis(50);
        let sim = NetSim::start(upstream, profile, 1).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        let started = Instant::now();
        stream.write_all(b"hello").unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"hello");
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn queue_limit_pushes_back_on_the_sender() {
        let upstream = echo_server();
        let sim = NetSim::start(upstream, Profile::slow_uplink(), 4).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        stream.set_nonblocking(true).unwrap();
        let chunk = vec![1u8; 16 * 1024];
        let mut accepted = 0usize;
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(500) {
            match stream.write(&chunk) {
                Ok(written) => accepted += written,
                Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("{error}"),
            }
        }
        let mut unsent: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                (&mut unsent as *mut libc::c_int).cast(),
                &mut length,
            );
        }
        let consumed = accepted - unsent as usize;
        assert!(consumed < 1024 * 1024, "the relay consumed {consumed} bytes of a 30 KB/s link in 0.5 s");
    }

    #[test]
    fn bandwidth_limit_is_enforced() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.bandwidth = Some(200_000);
        let sim = NetSim::start(upstream, profile, 2).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        let data = vec![7u8; 100_000];
        let started = Instant::now();
        let mut writer = stream.try_clone().unwrap();
        let sender = std::thread::spawn(move || writer.write_all(&data).unwrap());
        let mut received = vec![0u8; 100_000];
        stream.read_exact(&mut received).unwrap();
        sender.join().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(400), "{:?}", started.elapsed());
    }

    #[test]
    fn tunnels_hold_the_whole_link_and_then_let_it_resume() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.tunnel = Some(Tunnel {
            every_min: Duration::from_millis(800),
            every_max: Duration::from_millis(800),
            length: Duration::from_millis(600),
        });
        let started = Instant::now();
        let sim = NetSim::start(upstream, profile, 6).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        stream.write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).unwrap();
        std::thread::sleep(Duration::from_millis(900).saturating_sub(started.elapsed()));
        assert!(sim.in_outage(), "the tunnel started");
        stream.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let _ = stream.write_all(b"y");
        assert!(stream.read(&mut one).is_err() || one == [b'x'], "nothing gets through the tunnel");
        let mut refused = TcpStream::connect(sim.address).unwrap();
        refused.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let _ = refused.write_all(b"z");
        let mut buffer = [0u8; 1];
        assert!(!matches!(refused.read(&mut buffer), Ok(1)), "new connections do not get through either");
        std::thread::sleep(Duration::from_millis(1600).saturating_sub(started.elapsed()));
        assert!(!sim.in_outage(), "the tunnel ended");
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.read_exact(&mut one).unwrap();
        assert_eq!(one, [b'y'], "the live connection survived the tunnel and delivers what was held");
        assert!(Profile::train().tunnel.is_some());
    }

    fn echo_delay(sim: &NetSim, bulk: usize) -> Duration {
        let mut bulk_stream = TcpStream::connect(sim.address).unwrap();
        let mut probe = TcpStream::connect(sim.address).unwrap();
        bulk_stream.write_all(&vec![7u8; bulk]).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        probe.write_all(b"p").unwrap();
        let mut one = [0u8; 1];
        probe.read_exact(&mut one).unwrap();
        started.elapsed()
    }

    #[test]
    fn a_fifo_bottleneck_queues_every_connection_behind_bulk_data() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.uplink = Some(10_000);
        profile.max_chunk = 1000;
        let fair = NetSim::start(upstream, profile.clone(), 3).unwrap();
        assert!(echo_delay(&fair, 30_000) < Duration::from_millis(800), "fair sharing lets the probe through");
        profile.fifo_queue = Some(Duration::from_secs(2));
        let bloated = NetSim::start(upstream, profile, 3).unwrap();
        let delay = echo_delay(&bloated, 30_000);
        assert!(delay >= Duration::from_millis(1500), "the probe waits behind the queued bulk data: {delay:?}");
        assert!(delay < Duration::from_secs(4), "but no longer than the queue holds: {delay:?}");
        assert_eq!(Profile::bufferbloat().fifo_queue, Some(Duration::from_secs(3)));
        assert_eq!(Profile::bufferbloat_down().fifo_queue, Some(Duration::from_secs(5)));
    }

    #[test]
    fn seeds_spread_and_first_connections_are_not_always_refused() {
        let first: Vec<f64> = (0..64u64).map(|seed| Random::new(seed).unit()).collect();
        assert!(first.iter().filter(|draw| **draw < 0.1).count() < 16, "{first:?}");
        assert_ne!(Random::new(5000).next(), Random::new(5001).next(), "neighbouring seeds differ");
    }

    #[test]
    fn a_nat_forgets_an_idle_connection_but_not_a_busy_one() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.idle_timeout = Some(Duration::from_millis(400));
        let sim = NetSim::start(upstream, profile, 8).unwrap();
        let mut busy = TcpStream::connect(sim.address).unwrap();
        let mut idle = TcpStream::connect(sim.address).unwrap();
        let mut one = [0u8; 1];
        for stream in [&mut busy, &mut idle] {
            stream.write_all(b"a").unwrap();
            stream.read_exact(&mut one).unwrap();
        }
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(150));
            busy.write_all(b"b").unwrap();
            busy.read_exact(&mut one).unwrap();
        }
        assert_eq!(sim.stats().blackholes, 1, "only the idle connection was forgotten");
        idle.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        idle.write_all(b"c").unwrap();
        assert!(idle.read(&mut one).is_err(), "the idle connection drops packets");
        assert_eq!(Profile::nat().idle_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn uplink_limit_applies_to_client_traffic_only() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.uplink = Some(50_000);
        let sim = NetSim::start(upstream, profile, 5).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        let data = vec![9u8; 50_000];
        let started = Instant::now();
        let mut writer = stream.try_clone().unwrap();
        let sender = std::thread::spawn(move || writer.write_all(&data).unwrap());
        let mut received = vec![0u8; 50_000];
        stream.read_exact(&mut received).unwrap();
        sender.join().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());
        assert_eq!(Profile::uplink_starved().uplink, Some(8_000));

        let mut fast_uplink = Profile::perfect();
        fast_uplink.bandwidth = Some(50_000);
        fast_uplink.uplink = Some(10_000_000);
        sim.set_profile(fast_uplink);
        assert_eq!(sim.shared.up.lock().unwrap().rate, Some(10_000_000.0));
        assert_eq!(sim.shared.down.lock().unwrap().rate, Some(50_000.0));
        assert!(Profile::all_names().iter().all(|name| Profile::by_name(name).is_some()));
    }

    #[test]
    fn reset_all_breaks_connections_and_outage_refuses() {
        let upstream = echo_server();
        let sim = NetSim::start(upstream, Profile::perfect(), 3).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        stream.write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).unwrap();
        sim.reset_all();
        std::thread::sleep(Duration::from_millis(50));
        let mut buffer = [0u8; 1];
        assert!(matches!(stream.read(&mut buffer), Ok(0) | Err(_)));
        sim.outage(Duration::from_millis(300));
        let mut refused = TcpStream::connect(sim.address).unwrap();
        refused.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let _ = refused.write_all(b"y");
        assert!(matches!(refused.read(&mut buffer), Ok(0) | Err(_)));
        assert!(sim.stats().refused >= 1);
        std::thread::sleep(Duration::from_millis(350));
        let mut fine = TcpStream::connect(sim.address).unwrap();
        fine.write_all(b"z").unwrap();
        fine.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"z");
    }

    #[test]
    fn dead_blackhole_stops_traffic_without_closing() {
        let upstream = echo_server();
        let mut profile = Profile::perfect();
        profile.blackhole = Some(Blackhole {
            after_min: Duration::from_millis(100),
            after_max: Duration::from_millis(100),
            duration: Duration::from_secs(10),
            end: BlackholeEnd::Dead,
        });
        let sim = NetSim::start(upstream, profile, 4).unwrap();
        let mut stream = TcpStream::connect(sim.address).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        stream.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        stream.write_all(b"lost").unwrap();
        let mut buffer = [0u8; 4];
        let result = stream.read(&mut buffer);
        assert!(
            matches!(result, Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut),
            "{result:?}"
        );
    }
}
