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
    Socks5 { host: String, port: u16, username: Option<String>, password: Option<String> },
    MtProxy { host: String, port: u16, secret: Vec<u8> },
}

impl Drop for ProxyConfig {
    fn drop(&mut self) {
        match self {
            ProxyConfig::Socks5 { password, .. } => {
                if let Some(password) = password.as_mut() {
                    mtproto_core::Zeroize::zeroize(password);
                }
            }
            ProxyConfig::MtProxy { secret, .. } => mtproto_core::Zeroize::zeroize(secret),
        }
    }
}

impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProxyConfig::Socks5 { host, port, .. } => write!(f, "Socks5({host}:{port})"),
            ProxyConfig::MtProxy { host, port, .. } => write!(f, "MtProxy({host}:{port})"),
        }
    }
}

impl ProxyConfig {
    pub fn display_address(&self) -> String {
        match self {
            ProxyConfig::Socks5 { host, port, .. } | ProxyConfig::MtProxy { host, port, .. } => {
                format!("{host}:{port}")
            }
        }
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
        }
    }

    pub fn proxy_secret(&self, address: &DcAddress) -> Option<ProxySecret> {
        match &self.proxy {
            Some(ProxyConfig::MtProxy { secret, .. }) => ProxySecret::from_binary(secret, true).ok(),
            Some(ProxyConfig::Socks5 { .. }) => None,
            None => address.secret.as_ref().and_then(|secret| ProxySecret::from_binary(secret, true).ok()),
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
        key: Vec<u8>,
        salt: i64,
        time_difference: f64,
        expires_at: Option<i32>,
    },
    AuthKeyCreationFailed {
        reason: String,
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
