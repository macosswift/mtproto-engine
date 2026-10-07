use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::RsaPublicKey;
use mtproto_core::rpc::{ApiEnvironment, RequestId, RpcEvent, SessionRole};
use mtproto_core::session::ServerSalt;
use mtproto_core::transport::{Framing, ProxySecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionHandle(pub u64);

#[derive(Clone, PartialEq, Eq)]
pub struct DcAddress {
    pub host: String,
    pub port: u16,
    pub secret: Option<Vec<u8>>,
}

impl Drop for DcAddress {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            mtproto_core::Zeroize::zeroize(secret);
        }
    }
}

impl core::fmt::Debug for DcAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DcAddress")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("secret", &self.secret.as_ref().map(|secret| format!("<{} bytes>", secret.len())))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProxyConfig {
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    MtProxy {
        host: String,
        port: u16,
        secret: Vec<u8>,
    },
    /// An HTTP proxy: TCP goes through a CONNECT tunnel, HTTP is forwarded by it.
    Http {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    /// A WEB proxy: the MTProxy transport, obfuscated with `secret`, over the host's carrier to the relay
    /// at `host` (a page in a web view the host runs). The engine opens no connection of its own and
    /// looks nothing up; without the host's carrier the session does not connect at all.
    Web {
        host: String,
        secret: Vec<u8>,
    },
}

impl Drop for ProxyConfig {
    fn drop(&mut self) {
        match self {
            ProxyConfig::Socks5 { password, .. } | ProxyConfig::Http { password, .. } => {
                if let Some(password) = password.as_mut() {
                    mtproto_core::Zeroize::zeroize(password);
                }
            }
            ProxyConfig::MtProxy { secret, .. } | ProxyConfig::Web { secret, .. } => {
                mtproto_core::Zeroize::zeroize(secret)
            }
        }
    }
}

impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProxyConfig::Socks5 { host, port, .. } => write!(f, "Socks5({host}:{port})"),
            ProxyConfig::MtProxy { host, port, .. } => write!(f, "MtProxy({host}:{port})"),
            ProxyConfig::Http { host, port, .. } => write!(f, "Http({host}:{port})"),
            ProxyConfig::Web { host, .. } => write!(f, "Web({host})"),
        }
    }
}

impl ProxyConfig {
    pub fn display_address(&self) -> String {
        match self {
            ProxyConfig::Socks5 { host, port, .. }
            | ProxyConfig::MtProxy { host, port, .. }
            | ProxyConfig::Http { host, port, .. } => format!("{host}:{port}"),
            ProxyConfig::Web { host, .. } => host.clone(),
        }
    }
}

/// Key bytes handed to the host: never printed by `Debug`, zeroized when dropped.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl core::ops::Deref for SecretBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        mtproto_core::Zeroize::zeroize(&mut self.0);
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{} secret bytes>", self.0.len())
    }
}

#[derive(Clone)]
pub struct AuthKeyMaterial {
    pub key: AuthKey,
    pub salts: Vec<ServerSalt>,
    pub init_hash: Option<String>,
}

impl core::fmt::Debug for AuthKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthKeyMaterial").field("key", &self.key).field("salts", &self.salts.len()).finish()
    }
}

#[derive(Debug, Clone)]
pub struct KeyGeneration {
    pub public_keys: Vec<RsaPublicKey>,
    pub temporary_expires_in: Option<i32>,
}

/// Perfect forward secrecy run by the engine, as tdlib does: the session talks under temporary
/// keys it makes and binds to the permanent key itself.
#[derive(Debug, Clone, Default)]
pub struct PfsSetup {
    /// Seconds each temporary key lives.
    pub lifetime: i32,
    pub public_keys: Vec<RsaPublicKey>,
    /// Without a permanent key the session asks the host for one (`AuthKeyRequired`) instead of
    /// making it, so that one place makes each permanent key.
    pub permanent_key_from_host: bool,
    /// A temporary key already bound to the permanent key, kept by the host from an earlier run or
    /// another session: the session starts under it without a handshake.
    pub temporary_key: Option<BoundTemporaryKey>,
}

/// A temporary key the server has bound to the session's permanent key.
#[derive(Debug, Clone)]
pub struct BoundTemporaryKey {
    pub material: AuthKeyMaterial,
    /// When the key expires, in server time.
    pub expires_at: i32,
    /// The permanent key it is bound to, when the host knows: a key bound to another one is refused.
    pub bound_to: Option<u64>,
}

/// Which transports a session may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPreference {
    /// The obfuscated TCP transports only.
    #[default]
    Tcp,
    /// HTTP/1.1 only.
    Http,
    /// TCP, moving to HTTP while no TCP route gets through and back once one does.
    Auto,
}

#[derive(Debug, Clone)]
pub struct SessionSetup {
    pub datacenter_id: i32,
    pub obfuscation_dc_id: i16,
    pub role: SessionRole,
    pub addresses: Vec<DcAddress>,
    pub proxy: Option<ProxyConfig>,
    pub framing: Framing,
    pub auth_key: Option<AuthKeyMaterial>,
    pub key_generation: Option<KeyGeneration>,
    pub environment: Option<ApiEnvironment>,
    pub time_difference: f64,
    pub online: bool,
    pub paused: bool,
    pub keep_connected: bool,
    pub idle_disconnect_after: Option<f64>,
    pub request_timeout: f64,
    pub transport: TransportPreference,
    /// The port HTTP goes to; None uses each address's own port.
    pub http_port: Option<u16>,
    /// Auto on HTTP: when TCP is tried again first; later tries wait twice as long each.
    pub tcp_recheck_after: f64,
    /// The engine makes and binds temporary keys itself; `auth_key` is then the permanent key.
    pub pfs: Option<PfsSetup>,
    /// Telegram Web's HTTPS endpoint, tried as one more HTTP route through the host's streams.
    pub web: Option<WebEndpoint>,
}

/// Telegram Web's endpoints for a datacenter on one web front, inside TLS the host opens (`StreamHost`)
/// with the platform's own TLS, so the traffic looks like a browser on Telegram Web: the WebSocket
/// endpoint carries the obfuscated stream transport as TCP would, the HTTPS endpoint the same MTProto
/// messages as plain HTTP.
#[derive(Debug, Clone, PartialEq)]
pub struct WebEndpoint {
    /// The name TLS presents and the Host header carries, as `venus.web.telegram.org`.
    pub host: String,
    pub port: u16,
    /// `/apiw1`, or `/apiw_test1` on the test servers.
    pub path: String,
    /// The WebSocket endpoint on the same front: `/apiws`, or `/apiws_test`.
    pub ws_path: String,
    /// Where the host connects instead of looking `host` up: tests, or a front known to work.
    pub address: Option<String>,
}

const WEB_HOSTS: [&str; 5] = ["pluto", "venus", "aurora", "vesta", "flora"];

impl WebEndpoint {
    /// The Host header: the name, with the port unless it is HTTPS's own.
    pub fn authority(&self) -> String {
        if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    /// Telegram Web's own endpoint for datacenter 1-5, production or test. Sessions other than the
    /// main one use the `-1` fronts, as Telegram Web does for downloads and uploads.
    pub fn telegram(datacenter_id: i32, role: SessionRole, test: bool) -> Option<Self> {
        if role == SessionRole::Cdn {
            return None;
        }
        let name = WEB_HOSTS.get(usize::try_from(datacenter_id).ok()?.checked_sub(1)?)?;
        let suffix = if role == SessionRole::Main { "" } else { "-1" };
        Some(Self {
            host: format!("{name}{suffix}.web.telegram.org"),
            port: 443,
            path: if test { "/apiw_test1".into() } else { "/apiw1".into() },
            ws_path: if test { "/apiws_test".into() } else { "/apiws".into() },
            address: None,
        })
    }
}

impl SessionSetup {
    pub fn new(datacenter_id: i32, role: SessionRole, addresses: Vec<DcAddress>) -> Self {
        Self {
            datacenter_id,
            obfuscation_dc_id: datacenter_id as i16,
            role,
            addresses,
            proxy: None,
            framing: Framing::Abridged,
            auth_key: None,
            key_generation: None,
            environment: None,
            time_difference: 0.0,
            online: false,
            paused: false,
            keep_connected: matches!(role, SessionRole::Main),
            idle_disconnect_after: match role {
                SessionRole::Main => None,
                _ => Some(60.0),
            },
            request_timeout: 5.0,
            transport: TransportPreference::Tcp,
            http_port: Some(80),
            tcp_recheck_after: 60.0,
            pfs: None,
            web: None,
        }
    }

    pub fn proxy_host(&self) -> Option<(&str, u16)> {
        match &self.proxy {
            Some(ProxyConfig::Socks5 { host, port, .. })
            | Some(ProxyConfig::MtProxy { host, port, .. })
            | Some(ProxyConfig::Http { host, port, .. }) => Some((host.as_str(), *port)),
            Some(ProxyConfig::Web { .. }) | None => None,
        }
    }

    /// No HTTP route goes through the proxy: an MTProxy or a WEB proxy carries the stream transport only.
    pub fn proxy_blocks_http(&self) -> bool {
        matches!(self.proxy, Some(ProxyConfig::MtProxy { .. }) | Some(ProxyConfig::Web { .. }))
    }

    pub fn web_proxy(&self) -> bool {
        matches!(self.proxy, Some(ProxyConfig::Web { .. }))
    }

    pub fn proxy_secret(&self, address: &DcAddress) -> Option<ProxySecret> {
        match &self.proxy {
            Some(ProxyConfig::MtProxy { secret, .. }) | Some(ProxyConfig::Web { secret, .. }) => {
                ProxySecret::from_binary(secret, true).ok()
            }
            Some(ProxyConfig::Socks5 { .. }) | Some(ProxyConfig::Http { .. }) | None => {
                address.secret.as_ref().and_then(|secret| ProxySecret::from_binary(secret, true).ok())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectionState {
    pub network_available: bool,
    pub connected: bool,
    pub updating_connection_context: bool,
    pub performing_service_tasks: bool,
    pub proxy_has_connection_issues: bool,
    /// The link answers, and the session waits for its temporary key to be bound: it is updating, yet
    /// says nothing against the route.
    pub awaiting_key_binding: bool,
}

/// Why the engine gave up on a connection: which of its checks decided, for the host's diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// The server or something on the path closed it.
    Closed,
    /// Reading or writing failed, as after a reset.
    IoError,
    /// The transport or the SOCKS5 proxy sent bytes that cannot be right.
    Protocol,
    /// It did not connect within the connect timeout.
    ConnectTimeout,
    /// The auth key handshake on it did not finish in time.
    HandshakeTimeout,
    /// No pong or packet within the ping disconnect delay.
    PingTimeout,
    /// Nothing read within the read disconnect delay.
    ReadTimeout,
    /// A ping sat unanswered after everything ahead of it had left the socket.
    ProbeTimeout,
    /// A request waited past its timeout with nothing arriving.
    RequestTimeout,
    /// The session could not take a packet that arrived (msg_key mismatch, malformed message), or
    /// failed on it in another way.
    SessionError,
    /// The server does not know the auth key: a -404 again, on a connection the key had not
    /// decrypted a packet on, after an earlier -404.
    KeyInvalid,
    /// A -404 not believed: the first since the key last worked, or one on a connection where the
    /// key had decrypted a packet. The connection is retried.
    KeyRejectedOnce,
    /// The server refused the connection with a transport error such as a wrong datacenter.
    AddressRejected,
    /// The auth key handshake on it failed.
    HandshakeFailed,
    /// The server answered -429: too many connections from this address.
    TransportFlood,
    /// An alternate connection started while this one was still connecting got through first.
    SlowConnect,
    /// A connection raced against this silent one answered first and replaced it.
    RacerWon,
    /// The session moved to the other transport: HTTP answered where TCP did not.
    TransportSwitch,
}

impl DropReason {
    pub fn name(self) -> &'static str {
        match self {
            DropReason::Closed => "closed",
            DropReason::IoError => "io_error",
            DropReason::Protocol => "protocol",
            DropReason::ConnectTimeout => "connect_timeout",
            DropReason::HandshakeTimeout => "handshake_timeout",
            DropReason::PingTimeout => "ping_timeout",
            DropReason::ReadTimeout => "read_timeout",
            DropReason::ProbeTimeout => "probe_timeout",
            DropReason::RequestTimeout => "request_timeout",
            DropReason::SessionError => "session_error",
            DropReason::KeyInvalid => "key_invalid",
            DropReason::KeyRejectedOnce => "key_rejected_once",
            DropReason::AddressRejected => "address_rejected",
            DropReason::HandshakeFailed => "handshake_failed",
            DropReason::TransportFlood => "transport_flood",
            DropReason::SlowConnect => "slow_connect",
            DropReason::RacerWon => "racer_won",
            DropReason::TransportSwitch => "transport_switch",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    Rpc(RpcEvent),
    Progress {
        id: RequestId,
        progress: f32,
        packet_length: usize,
    },
    ConnectionState {
        state: ConnectionState,
        proxy_address: Option<String>,
    },
    AuthKeyRequired,
    AuthKeyInvalid {
        code: i32,
    },
    AuthKeyCreated {
        key: SecretBytes,
        salt: i64,
        time_difference: f64,
        expires_at: Option<i32>,
    },
    AuthKeyCreationFailed {
        reason: String,
    },
    /// PFS: binds with fresh temporary keys keep failing with `ENCRYPTED_MESSAGE_INVALID`, so the
    /// server does not know the permanent key.
    PermanentKeyInvalid,
    /// PFS: the session talks under this bound temporary key from now on; `adopted` when the host
    /// gave it, otherwise the session made it (its `AuthKeyCreated` came before) and bound it.
    /// `dc_id` is the datacenter id the key was made for (negative for media addresses),
    /// `permanent_key_id` the permanent key it is bound to.
    TemporaryKeyInUse {
        key_id: i64,
        expires_at: i32,
        adopted: bool,
        dc_id: i32,
        permanent_key_id: i64,
    },
    /// PFS: the session stopped using this temporary key because the server no longer takes it; a
    /// host keeping it for other sessions drops it.
    TemporaryKeyDropped {
        key_id: i64,
    },
    TransportFlood,
    NetworkUsage {
        incoming: u64,
        outgoing: u64,
        cellular: bool,
    },
    AddressResult {
        index: usize,
        success: bool,
    },
    /// The engine dropped a connection; `answered` when the session had taken a packet from it (the
    /// auth key handshake does not count), `age` in seconds since it started connecting.
    ConnectionDropped {
        reason: DropReason,
        answered: bool,
        age: f64,
    },
    Closed,
    /// Engine-wide, reported for session 0: what was learned about named networks changed; the host
    /// stores it and gives it back with `Engine::set_route_memory` on the next run.
    RouteMemory {
        memory: Vec<u8>,
    },
}

pub trait EngineCallbacks: Send + Sync + 'static {
    fn on_event(&self, session: SessionHandle, event: EngineEvent);

    fn on_log(&self, _level: LogLevel, _message: &str) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub worker_threads: usize,
    pub connect_timeout: f64,
    pub max_reconnect_delay: f64,
    pub usage_report_interval: f64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        Self {
            worker_threads: (parallelism / 2).clamp(2, 4),
            connect_timeout: 12.0,
            max_reconnect_delay: 8.0,
            usage_report_interval: 2.0,
        }
    }
}
