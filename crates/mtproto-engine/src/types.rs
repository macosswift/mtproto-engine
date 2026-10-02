use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::RsaPublicKey;
use mtproto_core::rpc::{ApiEnvironment, RequestId, RpcEvent, SessionRole};
use mtproto_core::session::ServerSalt;
use mtproto_core::transport::{Framing, ProxySecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionHandle(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcAddress {
    pub host: String,
    pub port: u16,
    pub secret: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProxyConfig {
    Socks5 { host: String, port: u16, username: Option<String>, password: Option<String> },
    MtProxy { host: String, port: u16, secret: Vec<u8> },
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

#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    Rpc(RpcEvent),
    Progress { id: RequestId, progress: f32, packet_length: usize },
    ConnectionState { state: ConnectionState, proxy_address: Option<String> },
    AuthKeyRequired,
    AuthKeyInvalid { code: i32 },
    AuthKeyCreated { key: Vec<u8>, salt: i64, time_difference: f64, expires_at: Option<i32> },
    AuthKeyCreationFailed { reason: String },
    TransportFlood,
    NetworkUsage { incoming: u64, outgoing: u64, cellular: bool },
    AddressResult { index: usize, success: bool },
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
