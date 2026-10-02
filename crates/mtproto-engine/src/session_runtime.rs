use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use mio::{Registry, Token};
use mtproto_core::crypto::{OsRandom, SecureRandom};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeStep};
use mtproto_core::message::{PaddingPolicy, decode_plain_message, encode_plain_message};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::rpc::{ApiEnvironment, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole, Verification};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig, SessionError};
use mtproto_core::tl::mtproto::ReqPqMulti;
use mtproto_core::tl::{TlWrite, Writer, ids};
use mtproto_core::transport::{
    Incoming, STABLE_CONNECTION_AFTER, Socks5Auth, Socks5Target, TransportConfig, TransportErrorKind, flap_delay,
    reconnect_delay, transport_flood_delay, urgent_reconnect_delay,
};

use crate::connection::{ChunkStatus, Connection, ConnectionError};
use crate::resolver::parse_literal;
use crate::types::{
    AuthKeyMaterial, ConnectionState, DcAddress, EngineCallbacks, EngineConfig, EngineEvent, LogLevel, ProxyConfig,
    SessionHandle, SessionSetup,
};

const PROGRESS_THRESHOLD: usize = 4096;
pub const FRAME_PROGRESS_GRACE: f64 = 15.0;
pub const FRAME_MIN_RATE: f64 = 512.0;
const PROGRESS_HEAD: usize = 128;
const HANDSHAKE_TIMEOUT: f64 = 10.0;
pub const READ_BUDGET_PER_TURN: usize = 512 * 1024;
pub const RACE_AFTER: f64 = 1.0;
pub const RACE_SILENT_AFTER: f64 = 1.5;
pub const RACE_VERIFY_TIMEOUT: f64 = 4.0;
pub const RACER_MAX_CHUNKS: usize = 2;
pub const DIRECT_PADDING_BLOCKS: usize = 4;
pub const PROXY_PADDING_BLOCKS: usize = 15;
pub const RACE_RETRY_BASE: f64 = 1.0;
pub const RACE_RETRY_MAX: f64 = 8.0;
pub const RACER_MAX_BUFFERED: usize = 16 * 1024;
pub const RESOLVE_WAIT: f64 = 30.0;
pub const DNS_TTL: f64 = 299.0;
pub const REJECTION_MAX_DELAY: f64 = 16.0;
pub const TIME_DIFFERENCE_REPORT_THRESHOLD: f64 = 1.0;
pub const OUTBOUND_PROGRESS_MIN_BACKLOG: usize = 16 * 1024;
const MAX_INITIALIZED_KEYS: usize = 256;
pub const UNAVAILABLE_PROBE_INTERVAL: f64 = 30.0;
pub const RESOLVE_RETRY_MIN: f64 = 1.0;
pub const RESOLVE_RETRY_MAX: f64 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    ServerRejected,
    AddressRejected,
    TransportFlood,
    HandshakeFailed,
}

pub enum Resolution {
    Resolved(Vec<SocketAddr>),
    Pending,
}

enum Pick {
    Ready(usize, SocketAddr, DcAddress),
    Resolving,
    Unavailable,
}

pub trait Resolve {
    fn resolve(&mut self, session: SessionHandle, host: &str, port: u16) -> Resolution;
}

struct ProgressTracking {
    frame_length: usize,
    target: Option<RequestId>,
    last_reported: usize,
}

#[derive(Debug, Clone, Copy)]
struct RacerCheck {
    nonce: [u8; 16],
    sent: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct AddressHealth {
    ok_at: f64,
    error_at: f64,
}

impl AddressHealth {
    fn rank(&self) -> (u8, f64) {
        if self.ok_at > 0.0 && self.ok_at >= self.error_at {
            (0, -self.ok_at)
        } else if self.error_at == 0.0 {
            (1, 0.0)
        } else {
            (2, self.error_at)
        }
    }
}

struct ResolvedHost {
    key: String,
    addresses: Vec<SocketAddr>,
    expires_at: f64,
    failures_at: u32,
}

struct FrameWatch {
    length: usize,
    started_at: f64,
}

pub struct SessionRuntime {
    pub handle: SessionHandle,
    setup: SessionSetup,
    rpc: Option<RpcClient>,
    queued: VecDeque<RpcRequest>,
    pending_plain: VecDeque<Vec<u8>>,
    handshake: Option<Handshake>,
    connection: Option<Connection>,
    racer: Option<Connection>,
    racer_check: Option<RacerCheck>,
    racer_failures: u32,
    racer_retry_at: f64,
    flaps: u32,
    deliveries: u64,
    deliveries_at_open: u64,
    address_health: HashMap<(String, u16), AddressHealth>,
    token: Token,
    next_attempt_at: f64,
    failures: u32,
    address_cursor: usize,
    last_activity_at: f64,
    timeout_fired: bool,
    reported_key_required: bool,
    network_available: bool,
    last_state: Option<(ConnectionState, Option<String>)>,
    progress: Option<ProgressTracking>,
    frame_watch: Option<FrameWatch>,
    acknowledged_out: u64,
    outbound_backlog_sample: usize,
    reported_time_difference: Option<f64>,
    reported_salts: Vec<ServerSalt>,
    reported_in: u64,
    reported_out: u64,
    last_usage_report: f64,
    resolved: Option<ResolvedHost>,
    unavailable_probe_at: f64,
    closed: bool,
    auth_token_ready: bool,
    cellular: bool,
    close_reason: Option<CloseReason>,
    transport_floods: u32,
    rejections: u32,
    handshake_started_at: Option<f64>,
    jitter_state: u64,
}

impl SessionRuntime {
    pub fn new(handle: SessionHandle, setup: SessionSetup, token: Token, now: Now, rng: &mut OsRandom) -> Self {
        let mut runtime = Self {
            handle,
            rpc: None,
            queued: VecDeque::new(),
            pending_plain: VecDeque::new(),
            handshake: None,
            connection: None,
            racer: None,
            racer_check: None,
            racer_failures: 0,
            racer_retry_at: 0.0,
            flaps: 0,
            deliveries: 0,
            deliveries_at_open: 0,
            address_health: HashMap::new(),
            token,
            next_attempt_at: now.mono,
            failures: 0,
            address_cursor: 0,
            last_activity_at: now.mono,
            timeout_fired: false,
            reported_key_required: false,
            network_available: true,
            last_state: None,
            progress: None,
            frame_watch: None,
            acknowledged_out: 0,
            outbound_backlog_sample: 0,
            reported_time_difference: Some(setup.time_difference),
            reported_salts: Vec::new(),
            reported_in: 0,
            reported_out: 0,
            last_usage_report: now.mono,
            resolved: None,
            unavailable_probe_at: 0.0,
            closed: false,
            auth_token_ready: true,
            cellular: false,
            close_reason: None,
            transport_floods: 0,
            rejections: 0,
            handshake_started_at: None,
            jitter_state: rng.next_u64() | 1,
            setup,
        };
        if let Some(material) = runtime.setup.auth_key.take() {
            runtime.install_key(material, now, rng);
        }
        runtime
    }

    pub fn active_token(&self) -> Option<Token> {
        self.connection.as_ref().map(Connection::token)
    }

    pub fn race_token(&self) -> Token {
        Token(self.token.0 + 1)
    }

    fn free_token(&self) -> Token {
        let used = self.connection.as_ref().or(self.racer.as_ref()).map(Connection::token);
        if used == Some(self.token) { self.race_token() } else { self.token }
    }

    pub fn token(&self) -> Token {
        self.token
    }

    fn session_config(&self) -> SessionConfig {
        let disguised =
            self.setup.proxy.is_some() || self.setup.addresses.iter().any(|address| address.secret.is_some());
        let extra_random_blocks = if disguised { PROXY_PADDING_BLOCKS } else { DIRECT_PADDING_BLOCKS };
        SessionConfig {
            is_main: self.setup.role == SessionRole::Main,
            padding: PaddingPolicy { extra_random_blocks },
            ..SessionConfig::default()
        }
    }

    fn install_key(&mut self, material: AuthKeyMaterial, now: Now, rng: &mut OsRandom) {
        let init_hash = initialized_in_this_process(material.key.id(), material.init_hash);
        match &mut self.rpc {
            Some(rpc) => {
                if rpc.session().auth_key_id() != material.key.id() {
                    rpc.session_mut().replace_auth_key(material.key, &material.salts, now);
                    rpc.reset_session(now, rng);
                    rpc.set_stored_init_hash(init_hash);
                } else {
                    rpc.session_mut().merge_salts(&material.salts, now);
                }
            }
            None => {
                let mut session = Session::new(
                    self.session_config(),
                    material.key,
                    &material.salts,
                    self.setup.time_difference,
                    now,
                    rng,
                );
                session.set_online(self.setup.online, now);
                let mut rpc = RpcClient::new(session, self.setup.role, self.setup.environment.clone(), init_hash);
                if !self.auth_token_ready {
                    rpc.set_auth_token_ready(false, now);
                }
                if self.connection.as_ref().is_some_and(Connection::is_established) && self.handshake.is_none() {
                    rpc.connection_opened(now);
                }
                for request in self.queued.drain(..) {
                    rpc.send(request, now);
                }
                self.rpc = Some(rpc);
            }
        }
        self.reported_key_required = false;
    }

    pub fn has_work(&self) -> bool {
        self.rpc.as_ref().is_some_and(|rpc| rpc.request_count() > 0) || !self.queued.is_empty()
    }

    fn wants_connection(&self, now: Now) -> bool {
        if !self.network_available && self.connection.is_none() && now.mono < self.unavailable_probe_at {
            return false;
        }
        self.wants_connection_ignoring_network(now)
    }

    fn wants_connection_ignoring_network(&self, now: Now) -> bool {
        if self.setup.paused || self.closed || self.setup.addresses.is_empty() {
            return false;
        }
        if self.rpc.is_none() {
            return self.setup.key_generation.is_some();
        }
        if self.setup.keep_connected || self.has_work() {
            return true;
        }
        match (self.setup.idle_disconnect_after, &self.connection) {
            (Some(idle), Some(_)) => now.mono - self.last_activity_at < idle,
            _ => false,
        }
    }

    pub fn send(&mut self, request: RpcRequest, now: Now) {
        self.last_activity_at = now.mono;
        match &mut self.rpc {
            Some(rpc) => rpc.send(request, now),
            None => self.queued.push_back(request),
        }
    }

    pub fn cancel(&mut self, id: RequestId, now: Now, registry: &Registry, callbacks: &Arc<dyn EngineCallbacks>) {
        if let Some(position) = self.queued.iter().position(|request| request.id == id) {
            self.queued.remove(position);
            return;
        }
        if let Some(rpc) = &mut self.rpc {
            rpc.cancel(id, now);
        }
        self.pump_rpc_events(now, registry, callbacks);
    }

    pub fn destroy_auth_key(&mut self, now: Now) {
        if let Some(rpc) = &mut self.rpc {
            rpc.destroy_auth_key(now);
            self.next_attempt_at = self.next_attempt_at.min(now.mono);
        }
    }

    pub fn set_paused(&mut self, paused: bool, now: Now, registry: &Registry) {
        if self.setup.paused == paused {
            return;
        }
        self.setup.paused = paused;
        if paused {
            self.close_connection(registry, now, false);
        } else {
            self.next_attempt_at = now.mono;
            self.failures = 0;
            self.flaps = 0;
        }
    }

    pub fn set_online(&mut self, online: bool, now: Now) {
        self.setup.online = online;
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().set_online(online, now);
        }
    }

    pub fn set_auth_key(
        &mut self,
        material: Option<AuthKeyMaterial>,
        now: Now,
        registry: &Registry,
        rng: &mut OsRandom,
    ) {
        match material {
            Some(material) => {
                let changed = self.rpc.as_ref().is_some_and(|rpc| rpc.session().auth_key_id() != material.key.id());
                self.install_key(material, now, rng);
                if changed {
                    self.close_connection(registry, now, false);
                    self.next_attempt_at = now.mono;
                }
            }
            None => {
                self.close_connection(registry, now, false);
                if let Some(rpc) = self.rpc.take() {
                    let mut requests = rpc.into_requests();
                    requests.extend(self.queued.drain(..));
                    self.queued = requests.into();
                }
                self.reported_key_required = false;
            }
        }
    }

    pub fn set_addresses(&mut self, addresses: Vec<DcAddress>, now: Now, registry: &Registry) {
        if self.setup.addresses != addresses {
            self.setup.addresses = addresses;
            self.address_cursor = 0;
            self.resolved = None;
            self.close_connection(registry, now, false);
            self.next_attempt_at = now.mono;
            self.failures = 0;
            self.flaps = 0;
        }
    }

    pub fn set_obfuscation_dc_id(&mut self, dc_id: i16, now: Now, registry: &Registry) {
        if self.setup.obfuscation_dc_id != dc_id {
            self.setup.obfuscation_dc_id = dc_id;
            self.close_connection(registry, now, false);
            self.next_attempt_at = now.mono;
        }
    }

    pub fn set_proxy(&mut self, proxy: Option<ProxyConfig>, now: Now, registry: &Registry) {
        if self.setup.proxy != proxy {
            self.setup.proxy = proxy;
            self.resolved = None;
            self.close_connection(registry, now, false);
            self.next_attempt_at = now.mono;
            self.failures = 0;
            self.flaps = 0;
        }
    }

    pub fn update_environment(&mut self, environment: ApiEnvironment, noop: Option<RpcRequest>, now: Now) {
        self.setup.environment = Some(environment.clone());
        if let Some(rpc) = &mut self.rpc {
            rpc.update_environment(environment, noop, now);
        }
    }

    pub fn set_auth_token_ready(&mut self, ready: bool, now: Now) {
        self.auth_token_ready = ready;
        if let Some(rpc) = &mut self.rpc {
            rpc.set_auth_token_ready(ready, now);
        }
    }

    pub fn resolve_verification(&mut self, id: RequestId, verification: Verification, now: Now) {
        if let Some(rpc) = &mut self.rpc {
            rpc.resolve_verification(id, verification, now);
        }
    }

    pub fn decide_retry(&mut self, id: RequestId, retry: bool, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        if let Some(rpc) = &mut self.rpc {
            rpc.decide_retry(id, retry, now);
        } else if !retry {
            self.fail_queued(id, 500, "SESSION_RESET", now, callbacks);
        }
    }

    pub fn fail_request(
        &mut self,
        id: RequestId,
        code: i32,
        message: &str,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) {
        if let Some(rpc) = &mut self.rpc {
            rpc.fail_request(id, code, message, now);
        } else {
            self.fail_queued(id, code, message, now, callbacks);
        }
    }

    fn fail_queued(&mut self, id: RequestId, code: i32, message: &str, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        if let Some(position) = self.queued.iter().position(|request| request.id == id) {
            self.queued.remove(position);
            callbacks.on_event(
                self.handle,
                EngineEvent::Rpc(RpcEvent::Failed {
                    id,
                    code,
                    message: message.to_string(),
                    response_time: now.unix,
                    duration: 0.0,
                }),
            );
        }
    }

    pub fn invalidate_initialization(&mut self) {
        if let Some(rpc) = &mut self.rpc {
            rpc.invalidate_initialization();
        }
    }

    pub fn set_time_difference(&mut self, difference: f64) {
        self.setup.time_difference = difference;
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().set_time_difference(difference);
        }
    }

    pub fn set_network_available(&mut self, available: bool, now: Now, registry: &Registry) {
        if self.network_available != available {
            self.network_available = available;
            self.resolved = None;
            if !available {
                self.close_connection(registry, now, false);
                self.unavailable_probe_at = now.mono + UNAVAILABLE_PROBE_INTERVAL;
            } else {
                self.failures = 0;
                self.flaps = 0;
                self.rejections = 0;
                self.next_attempt_at = now.mono;
            }
        }
    }

    pub fn reset_connection(&mut self, now: Now, registry: &Registry) {
        self.close_connection(registry, now, false);
        self.resolved = None;
        self.failures = 0;
        self.flaps = 0;
        self.next_attempt_at = now.mono;
    }

    pub fn shutdown(&mut self, registry: &Registry, now: Now) {
        self.closed = true;
        self.close_connection(registry, now, false);
    }

    fn address_key(&self, index: usize) -> Option<(String, u16)> {
        self.setup.addresses.get(index).map(|address| (address.host.clone(), address.port))
    }

    fn report_address(&mut self, index: usize, success: bool, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        self.note_address(index, success, now);
        callbacks.on_event(self.handle, EngineEvent::AddressResult { index, success });
    }

    fn note_address(&mut self, index: usize, success: bool, now: Now) {
        if let Some(key) = self.address_key(index) {
            let health = self.address_health.entry(key).or_default();
            if success {
                health.ok_at = now.mono;
            } else {
                health.error_at = now.mono;
            }
        }
    }

    fn best_address(&self, exclude: Option<usize>) -> Option<usize> {
        (0..self.setup.addresses.len()).filter(|index| Some(*index) != exclude).min_by(|a, b| {
            let rank = |index: usize| {
                self.address_key(index)
                    .and_then(|key| self.address_health.get(&key).copied())
                    .unwrap_or_default()
                    .rank()
            };
            let (left, right) = (rank(*a), rank(*b));
            left.0.cmp(&right.0).then(left.1.total_cmp(&right.1)).then(a.cmp(b))
        })
    }

    fn has_waiting_work(&self) -> bool {
        !self.queued.is_empty() || self.rpc.as_ref().is_some_and(|rpc| rpc.session().is_awaiting_responses())
    }

    fn reconnect_delay(&mut self) -> f64 {
        let jitter = self.next_jitter();
        if self.has_waiting_work() {
            urgent_reconnect_delay(self.failures, jitter)
        } else {
            reconnect_delay(self.failures, jitter)
        }
    }

    fn next_jitter(&mut self) -> u32 {
        self.jitter_state ^= self.jitter_state << 13;
        self.jitter_state ^= self.jitter_state >> 7;
        self.jitter_state ^= self.jitter_state << 17;
        (self.jitter_state >> 32) as u32
    }

    fn fail_racer(&mut self, registry: &Registry, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        let Some(index) = self.racer.as_ref().map(|racer| racer.address_index) else {
            return;
        };
        self.drop_racer(registry);
        self.report_address(index, false, now, callbacks);
        let backoff = RACE_RETRY_BASE * 2f64.powi(self.racer_failures.min(8) as i32);
        self.racer_failures = self.racer_failures.saturating_add(1);
        self.racer_retry_at = now.mono + backoff.min(RACE_RETRY_MAX);
    }

    fn drop_racer(&mut self, registry: &Registry) {
        self.racer_check = None;
        if let Some(mut racer) = self.racer.take() {
            self.account_usage(&racer);
            racer.deregister(registry);
        }
    }

    fn close_connection(&mut self, registry: &Registry, now: Now, failed: bool) {
        self.close_reason = None;
        self.drop_racer(registry);
        if let Some(mut connection) = self.connection.take() {
            self.account_usage(&connection);
            connection.deregister(registry);
            let index = connection.address_index;
            if failed {
                self.failures = self.failures.saturating_add(1);
                let jitter = self.next_jitter();
                let delay = self.reconnect_delay().max(flap_delay(self.flaps, jitter));
                self.next_attempt_at = self.next_attempt_at.max(now.mono + delay);
                self.address_cursor = index + 1;
            }
            if let Some(rpc) = &mut self.rpc {
                rpc.connection_closed(now);
            }
            self.handshake = None;
            self.handshake_started_at = None;
            self.pending_plain.clear();
            self.progress = None;
            self.frame_watch = None;
        }
    }

    fn close_dropped_connection(&mut self, registry: &Registry, now: Now, failed: bool) {
        if let Some(connection) = &self.connection
            && connection.received_packet
        {
            let lived = connection.established_at.map_or(0.0, |at| now.mono - at);
            let productive = self.deliveries != self.deliveries_at_open;
            self.flaps = if lived < STABLE_CONNECTION_AFTER && !productive { self.flaps.saturating_add(1) } else { 0 };
        }
        self.close_connection(registry, now, failed);
        let jitter = self.next_jitter();
        self.next_attempt_at = self.next_attempt_at.max(now.mono + flap_delay(self.flaps, jitter));
    }

    fn account_usage(&mut self, connection: &Connection) {
        self.reported_in += connection.bytes_in;
        self.reported_out += connection.bytes_out;
    }

    fn pick_address(&mut self, resolver: &mut dyn Resolve, now: Now) -> Pick {
        let index = self.best_address(None).unwrap_or(self.address_cursor);
        self.pick_address_at(index, resolver, now)
    }

    fn pick_address_at(&mut self, cursor: usize, resolver: &mut dyn Resolve, now: Now) -> Pick {
        let count = self.setup.addresses.len();
        if count == 0 {
            return Pick::Unavailable;
        }
        let index = cursor % count;
        let address = self.setup.addresses[index].clone();
        let (host, port) = match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { host, port, .. }) | Some(ProxyConfig::MtProxy { host, port, .. }) => {
                (host.clone(), *port)
            }
            None => (address.host.clone(), address.port),
        };
        let socket_address = match parse_literal(&host, port) {
            Some(address) => address,
            None => {
                let key = format!("{host}:{port}");
                let failures = self.failures;
                let cached = self.resolved.as_ref().filter(|cached| {
                    cached.key == key
                        && !cached.addresses.is_empty()
                        && now.mono < cached.expires_at
                        && (failures.saturating_sub(cached.failures_at) as usize) < cached.addresses.len()
                });
                match cached {
                    Some(cached) => {
                        cached.addresses[failures.saturating_sub(cached.failures_at) as usize % cached.addresses.len()]
                    }
                    None => match resolver.resolve(self.handle, &host, port) {
                        Resolution::Resolved(addresses) if !addresses.is_empty() => {
                            let first = addresses[0];
                            self.resolved = Some(ResolvedHost {
                                key,
                                addresses,
                                expires_at: now.mono + DNS_TTL,
                                failures_at: failures,
                            });
                            first
                        }
                        Resolution::Resolved(_) => return Pick::Unavailable,
                        Resolution::Pending => return Pick::Resolving,
                    },
                }
            }
        };
        Pick::Ready(index, socket_address, address)
    }

    fn targets_host(&self, host: &str, port: u16) -> bool {
        match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { host: proxy_host, port: proxy_port, .. })
            | Some(ProxyConfig::MtProxy { host: proxy_host, port: proxy_port, .. }) => {
                proxy_host == host && *proxy_port == port
            }
            None => self.setup.addresses.iter().any(|address| address.host == host && address.port == port),
        }
    }

    pub fn on_resolved(&mut self, host: &str, port: u16, addresses: Vec<SocketAddr>, now: Now) {
        if !self.targets_host(host, port) {
            return;
        }
        if addresses.is_empty() {
            self.resolved = None;
            self.failures = self.failures.saturating_add(1);
            self.next_attempt_at = now.mono + self.reconnect_delay().clamp(RESOLVE_RETRY_MIN, RESOLVE_RETRY_MAX);
        } else {
            self.resolved = Some(ResolvedHost {
                key: format!("{host}:{port}"),
                addresses,
                expires_at: now.mono + DNS_TTL,
                failures_at: self.failures,
            });
            self.next_attempt_at = now.mono;
        }
    }

    fn defer_connection(&mut self, pick: Pick, now: Now) {
        match pick {
            Pick::Resolving => self.next_attempt_at = now.mono + RESOLVE_WAIT,
            Pick::Unavailable | Pick::Ready(..) => {
                self.failures = self.failures.saturating_add(1);
                self.next_attempt_at = now.mono + self.reconnect_delay().clamp(RESOLVE_RETRY_MIN, RESOLVE_RETRY_MAX);
            }
        }
    }

    fn start_connection(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        config: &EngineConfig,
        rng: &mut OsRandom,
    ) {
        if !self.network_available {
            self.unavailable_probe_at = now.mono + UNAVAILABLE_PROBE_INTERVAL;
        }
        let (index, socket_address, address) = match self.pick_address(resolver, now) {
            Pick::Ready(index, socket_address, address) => (index, socket_address, address),
            pick => return self.defer_connection(pick, now),
        };
        let socks = match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { username, password, .. }) => {
                let target = match parse_literal(&address.host, address.port) {
                    Some(SocketAddr::V4(v4)) => Socks5Target::Ipv4(v4.ip().octets(), address.port),
                    Some(SocketAddr::V6(v6)) => Socks5Target::Ipv6(v6.ip().octets(), address.port),
                    None => Socks5Target::Domain(address.host.clone(), address.port),
                };
                let auth = match (username, password) {
                    (Some(username), Some(password)) if !username.is_empty() => {
                        Some(Socks5Auth { username: username.clone(), password: password.clone() })
                    }
                    _ => None,
                };
                Some((target, auth))
            }
            _ => None,
        };
        let transport = TransportConfig {
            framing: self.setup.framing,
            dc_id: self.setup.obfuscation_dc_id,
            secret: self.setup.proxy_secret(&address),
            unix_time: (now.unix + self.time_difference()) as i32,
        };
        let token = self.free_token();
        match Connection::connect(registry, token, socket_address, &transport, socks, index, now.mono, rng) {
            Ok(connection) => {
                self.connection = Some(connection);
                let _ = config;
            }
            Err(_) => {
                self.failures += 1;
                self.address_cursor = index + 1;
                self.note_address(index, false, now);
                self.next_attempt_at = now.mono + self.reconnect_delay().max(0.05);
            }
        }
    }

    fn start_racer(&mut self, registry: &Registry, now: Now, resolver: &mut dyn Resolve, rng: &mut OsRandom) {
        let Some(primary) = &self.connection else {
            return;
        };
        if self.racer.is_some()
            || self.setup.proxy.is_some()
            || self.setup.addresses.is_empty()
            || now.mono < self.racer_retry_at
        {
            return;
        }
        let slow_connect = !primary.is_tcp_connected() && now.mono - primary.started_at >= RACE_AFTER;
        let silent_after = self
            .rpc
            .as_ref()
            .and_then(|rpc| rpc.session().smoothed_rtt())
            .map_or(RACE_SILENT_AFTER, |rtt| (rtt * 3.0 + 0.3).max(1.0));
        let silent = primary.is_established()
            && !primary.received_bytes
            && primary.established_at.is_some_and(|at| now.mono - at >= silent_after);
        if !slow_connect && !silent {
            return;
        }
        let primary_index = primary.address_index;
        let next = self.best_address(Some(primary_index)).unwrap_or(primary_index);
        let Pick::Ready(index, socket_address, address) = self.pick_address_at(next, resolver, now) else {
            return;
        };
        let transport = TransportConfig {
            framing: self.setup.framing,
            dc_id: self.setup.obfuscation_dc_id,
            secret: self.setup.proxy_secret(&address),
            unix_time: (now.unix + self.time_difference()) as i32,
        };
        let token = self.free_token();
        if let Ok(racer) = Connection::connect(registry, token, socket_address, &transport, None, index, now.mono, rng)
        {
            self.racer = Some(racer);
            self.racer_check = silent.then(|| RacerCheck { nonce: rng.array(), sent: false });
        }
    }

    fn race_deadline(&self, now: Now, config: &EngineConfig) -> Option<f64> {
        if let Some(racer) = &self.racer {
            let limit = if self.racer_check.is_some() { RACE_VERIFY_TIMEOUT } else { config.connect_timeout };
            return Some(racer.started_at + limit + 0.01);
        }
        let primary = self.connection.as_ref()?;
        if self.setup.proxy.is_some() || self.setup.addresses.is_empty() {
            return None;
        }
        let start_at = if !primary.is_tcp_connected() {
            primary.started_at + RACE_AFTER
        } else if primary.is_established() && !primary.received_bytes {
            let silent_after = self
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.session().smoothed_rtt())
                .map_or(RACE_SILENT_AFTER, |rtt| (rtt * 3.0 + 0.3).max(1.0));
            primary.established_at? + silent_after
        } else {
            return None;
        };
        let at = start_at.max(self.racer_retry_at) + 0.001;
        (at > now.mono).then_some(at)
    }

    fn send_racer_check(
        &mut self,
        registry: &Registry,
        server_time: f64,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> bool {
        let (Some(racer), Some(check)) = (self.racer.as_mut(), self.racer_check) else {
            return true;
        };
        if check.sent || !racer.is_established() {
            return true;
        }
        let mut writer = Writer::with_capacity(24);
        ReqPqMulti { nonce: check.nonce }.write_to(&mut writer);
        let msg_id = msg_id_for_time(server_time) & !3;
        let packet = encode_plain_message(msg_id, &writer.into_inner());
        if racer.send_packet(registry, &packet, false, rng).and_then(|_| racer.flush(registry)).is_err() {
            self.fail_racer(registry, now, callbacks);
            return false;
        }
        self.racer_check = Some(RacerCheck { sent: true, ..check });
        true
    }

    fn promote_racer(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        self.racer_check = None;
        let Some(winner) = self.racer.take() else {
            return;
        };
        if let Some(mut loser) = self.connection.take() {
            self.report_address(loser.address_index, false, now, callbacks);
            self.account_usage(&loser);
            loser.deregister(registry);
        }
        if let Some(rpc) = &mut self.rpc {
            rpc.connection_closed(now);
        }
        self.handshake = None;
        self.handshake_started_at = None;
        self.pending_plain.clear();
        self.progress = None;
        self.frame_watch = None;
        self.address_cursor = winner.address_index;
        let connected = winner.is_tcp_connected();
        self.connection = Some(winner);
        self.log(callbacks, LogLevel::Info, "connection race won by the alternate address");
        if connected {
            self.on_established(now, callbacks, rng);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_racer_io(
        &mut self,
        readable: bool,
        registry: &Registry,
        scratch: &mut [u8],
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let server_time = now.unix + self.time_difference();
        let Some(racer) = &mut self.racer else {
            return;
        };
        if let Err(error) = racer.handle_writable(registry, now.mono) {
            self.fail_racer(registry, now, callbacks);
            self.log(callbacks, LogLevel::Debug, &format!("connection race lost: {error}"));
            return;
        }
        if !racer.is_tcp_connected() {
            return;
        }
        if self.racer_check.is_none() {
            self.promote_racer(registry, now, callbacks, rng);
            return;
        }
        if !self.send_racer_check(registry, server_time, now, callbacks, rng) {
            return;
        }
        if !readable {
            return;
        }
        let mut verified = false;
        let mut failed = false;
        let mut chunks = 0;
        while !verified && !failed {
            let Some(racer) = self.racer.as_mut() else {
                return;
            };
            match racer.read_chunk(registry, scratch, now.mono) {
                Ok(ChunkStatus::Data { .. }) => {}
                Ok(ChunkStatus::WouldBlock) => break,
                Ok(ChunkStatus::Eof) | Err(_) => {
                    failed = true;
                    break;
                }
            }
            if !self.send_racer_check(registry, server_time, now, callbacks, rng) {
                return;
            }
            let (Some(racer), Some(check)) = (self.racer.as_mut(), self.racer_check) else {
                return;
            };
            if check.sent {
                chunks += 1;
            }
            match racer.next_incoming() {
                Ok(Some(Incoming::Packet(packet))) if is_res_pq_for(&packet, &check.nonce) => verified = true,
                Ok(Some(_)) | Err(_) => failed = true,
                Ok(None) => {}
            }
            if !verified && (chunks >= RACER_MAX_CHUNKS || racer.buffered_input_len() > RACER_MAX_BUFFERED) {
                failed = true;
            }
        }
        let Some(racer) = self.racer.as_ref() else {
            return;
        };
        if verified {
            let index = racer.address_index;
            self.racer_failures = 0;
            self.note_address(index, true, now);
            if self.connection.as_ref().is_some_and(|primary| primary.received_bytes) {
                self.drop_racer(registry);
            } else {
                self.promote_racer(registry, now, callbacks, rng);
            }
        } else if failed {
            self.fail_racer(registry, now, callbacks);
        }
    }

    fn time_difference(&self) -> f64 {
        self.rpc.as_ref().map(|rpc| rpc.session().time_difference()).unwrap_or(self.setup.time_difference)
    }

    fn on_established(&mut self, now: Now, callbacks: &Arc<dyn EngineCallbacks>, rng: &mut OsRandom) {
        match &mut self.connection {
            Some(connection) => {
                connection.last_progress_at = now.mono;
                self.acknowledged_out = connection.acknowledged_bytes().unwrap_or(0);
                self.outbound_backlog_sample = 0;
            }
            None => return,
        }
        self.deliveries_at_open = self.deliveries;
        if self.rpc.is_some() {
            if let Some(rpc) = &mut self.rpc {
                rpc.connection_opened(now);
            }
        } else if let Some(generation) = &self.setup.key_generation {
            let config = HandshakeConfig {
                dc_id: self.setup.datacenter_id,
                temp_key_expires_in: generation.temporary_expires_in,
                public_keys: generation.public_keys.clone(),
            };
            let (handshake, packet) = Handshake::start(config, now.unix + self.setup.time_difference, rng);
            self.handshake = Some(handshake);
            self.handshake_started_at = Some(now.mono);
            let _ = callbacks;
            self.pending_plain.push_back(packet);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_io(
        &mut self,
        token: Token,
        readable: bool,
        writable: bool,
        registry: &Registry,
        scratch: &mut [u8],
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> bool {
        if self.racer.as_ref().is_some_and(|racer| racer.token() == token) {
            if readable || writable {
                self.handle_racer_io(readable, registry, scratch, now, callbacks, rng);
            }
            return false;
        }
        if self.connection.as_ref().is_none_or(|connection| connection.token() != token) {
            return false;
        }
        let mut more_readable = false;
        let mut failure: Option<ConnectionError> = None;
        if writable {
            let result = self.connection.as_mut().expect("connection").handle_writable(registry, now.mono);
            if self.racer.is_some() && self.connection.as_ref().is_some_and(Connection::is_tcp_connected) {
                self.drop_racer(registry);
            }
            match result {
                Ok(true) => self.on_established(now, callbacks, rng),
                Ok(false) => {}
                Err(error) => failure = Some(error),
            }
        }
        if readable && failure.is_none() {
            let mut budget = READ_BUDGET_PER_TURN;
            while let Some(connection) = self.connection.as_mut() {
                if budget == 0 {
                    more_readable = true;
                    break;
                }
                let before = connection.bytes_in;
                match connection.read_chunk(registry, scratch, now.mono) {
                    Ok(ChunkStatus::Data { became_ready }) => {
                        let read = self.connection.as_ref().map_or(0, |connection| connection.bytes_in - before);
                        budget = budget.saturating_sub(read as usize);
                        if became_ready {
                            self.on_established(now, callbacks, rng);
                        }
                        if let Err(error) = self.process_incoming(registry, now, callbacks, rng) {
                            failure = Some(error);
                            break;
                        }
                        if self.frame_is_progressing(now) {
                            if let Some(rpc) = &mut self.rpc {
                                rpc.note_bytes_received(now);
                            }
                            if let Some(connection) = &mut self.connection {
                                connection.last_progress_at = now.mono;
                            }
                        }
                    }
                    Ok(ChunkStatus::WouldBlock) => break,
                    Ok(ChunkStatus::Eof) => {
                        failure = Some(ConnectionError::Closed);
                        break;
                    }
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
        }
        if failure.is_none() {
            if let Err(error) = self.process_incoming(registry, now, callbacks, rng) {
                failure = Some(error);
            }
        } else if matches!(failure, Some(ConnectionError::Closed) | Some(ConnectionError::Io(_)))
            && let Err(error) = self.process_incoming(registry, now, callbacks, rng)
        {
            failure = Some(error);
        }
        if let Some(error) = failure {
            if self.connection.is_none() {
                return false;
            }
            self.log(callbacks, LogLevel::Info, &format!("connection closed: {error}"));
            let established = self.connection.as_ref().is_some_and(Connection::is_established);
            let reason = self.close_reason.take();
            let reachable = matches!(reason, Some(CloseReason::ServerRejected) | Some(CloseReason::TransportFlood))
                || (matches!(reason, Some(CloseReason::AddressRejected)) && self.rejections < 2);
            if let Some((index, success)) = self
                .connection
                .as_ref()
                .map(|connection| (connection.address_index, connection.received_packet || reachable))
            {
                self.report_address(index, success, now, callbacks);
            }
            let received = self.connection_received_packet();
            let failed = match reason {
                Some(CloseReason::ServerRejected)
                | Some(CloseReason::AddressRejected)
                | Some(CloseReason::HandshakeFailed) => true,
                Some(CloseReason::TransportFlood) => false,
                None => !established || !received,
            };
            self.close_dropped_connection(registry, now, failed);
            return false;
        }
        more_readable
    }

    fn frame_is_progressing(&mut self, now: Now) -> bool {
        let Some((length, received)) = self
            .connection
            .as_ref()
            .and_then(Connection::pending_frame_head)
            .map(|(length, head)| (length, head.len()))
        else {
            self.frame_watch = None;
            return false;
        };
        let watch = self.frame_watch.get_or_insert(FrameWatch { length, started_at: now.mono });
        if watch.length != length {
            *watch = FrameWatch { length, started_at: now.mono };
        }
        let elapsed = now.mono - watch.started_at;
        elapsed <= FRAME_PROGRESS_GRACE || received as f64 >= elapsed * FRAME_MIN_RATE
    }

    fn note_outbound_progress(&mut self, now: Now) {
        let Some(connection) = self.connection.as_mut().filter(|connection| connection.is_established()) else {
            return;
        };
        let (Some(acknowledged), Some(backlog)) = (connection.acknowledged_bytes(), connection.outbound_backlog())
        else {
            return;
        };
        let was_pushing = self.outbound_backlog_sample >= OUTBOUND_PROGRESS_MIN_BACKLOG;
        self.outbound_backlog_sample = backlog;
        if acknowledged > self.acknowledged_out {
            self.acknowledged_out = acknowledged;
            if was_pushing {
                connection.last_progress_at = now.mono;
                if let Some(rpc) = &mut self.rpc {
                    rpc.note_bytes_received(now);
                }
            }
        }
    }

    fn connection_received_packet(&self) -> bool {
        self.connection.as_ref().is_some_and(|connection| connection.received_packet)
    }

    fn process_incoming(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> Result<(), ConnectionError> {
        loop {
            let Some(connection) = &mut self.connection else {
                return Ok(());
            };
            let incoming = connection.next_incoming()?;
            let Some(incoming) = incoming else {
                break;
            };
            self.progress = None;
            self.frame_watch = None;
            match incoming {
                Incoming::Packet(packet) => {
                    if let Some(handshake) = &mut self.handshake {
                        match handshake.on_packet(&packet, now.unix, None, rng) {
                            Ok(HandshakeStep::Send(next)) => self.pending_plain.push_back(next),
                            Ok(HandshakeStep::Done(result)) => {
                                self.handshake = None;
                                self.handshake_started_at = None;
                                self.failures = 0;
                                let expires_at = result.expires_at;
                                let server_time = now.unix + result.time_difference;
                                self.setup.time_difference = result.time_difference;
                                callbacks.on_event(
                                    self.handle,
                                    EngineEvent::AuthKeyCreated {
                                        key: result.auth_key.bytes().to_vec(),
                                        salt: result.server_salt,
                                        time_difference: result.time_difference,
                                        expires_at,
                                    },
                                );
                                let material = AuthKeyMaterial {
                                    key: result.auth_key,
                                    salts: vec![ServerSalt {
                                        salt: result.server_salt,
                                        valid_since: server_time - 1.0,
                                        valid_until: server_time + 600.0,
                                    }],
                                    init_hash: None,
                                };
                                self.install_key(material, now, rng);
                                if let Some(rpc) = &mut self.rpc {
                                    rpc.connection_opened(now);
                                }
                            }
                            Err(error) => {
                                callbacks.on_event(
                                    self.handle,
                                    EngineEvent::AuthKeyCreationFailed { reason: error.to_string() },
                                );
                                self.close_reason = Some(CloseReason::HandshakeFailed);
                                return Err(ConnectionError::Closed);
                            }
                        }
                        continue;
                    }
                    let Some(rpc) = &mut self.rpc else {
                        continue;
                    };
                    let fresh_before = rpc.session().fresh_packets();
                    let result = rpc.handle_packet(&packet, now, rng);
                    if rpc.session().fresh_packets() != fresh_before
                        && let Some(connection) = &mut self.connection
                    {
                        connection.last_progress_at = now.mono;
                    }
                    match result {
                        Ok(()) => {
                            self.transport_floods = 0;
                            self.rejections = 0;
                            if !self.network_available {
                                self.network_available = true;
                                self.log(
                                    callbacks,
                                    LogLevel::Info,
                                    "received a packet while marked offline; treating the network as available",
                                );
                            }
                            if let Some(connection) = &mut self.connection
                                && !connection.received_packet
                            {
                                connection.received_packet = true;
                                self.failures = 0;
                                let index = connection.address_index;
                                self.report_address(index, true, now, callbacks);
                                self.drop_racer(registry);
                            }
                            self.timeout_fired = false;
                        }
                        Err(SessionError::ForeignSession)
                        | Err(SessionError::TooOld)
                        | Err(SessionError::EvenServerMsgId(_)) => {}
                        Err(error) => {
                            self.log(callbacks, LogLevel::Warning, &format!("session error: {error}"));
                            self.pump_rpc_events(now, registry, callbacks);
                            return Err(ConnectionError::Closed);
                        }
                    }
                    self.pump_rpc_events(now, registry, callbacks);
                }
                Incoming::QuickAck(token) => {
                    if let Some(rpc) = &mut self.rpc {
                        rpc.handle_quick_ack(token, now);
                    }
                    self.pump_rpc_events(now, registry, callbacks);
                }
                Incoming::TransportError(code) => {
                    self.log(callbacks, LogLevel::Warning, &format!("transport error {code}"));
                    self.on_transport_error(code, now, callbacks);
                    return Err(ConnectionError::Closed);
                }
                Incoming::Nop => {}
            }
        }
        self.update_progress(callbacks);
        Ok(())
    }

    fn on_transport_error(&mut self, code: i32, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        let kind = TransportErrorKind::from_code(code);
        if self.handshake.is_some() {
            callbacks.on_event(
                self.handle,
                EngineEvent::AuthKeyCreationFailed { reason: format!("transport error {code}") },
            );
            if kind == TransportErrorKind::Flood {
                self.transport_floods += 1;
                callbacks.on_event(self.handle, EngineEvent::TransportFlood);
                self.next_attempt_at =
                    self.next_attempt_at.max(now.mono + transport_flood_delay(self.transport_floods));
            }
            self.close_reason = Some(CloseReason::HandshakeFailed);
            return;
        }
        match kind {
            TransportErrorKind::AuthKeyNotFound => {
                callbacks.on_event(self.handle, EngineEvent::AuthKeyInvalid { code });
                if let Some(rpc) = self.rpc.take() {
                    for request in rpc_pending_requests(rpc) {
                        self.queued.push_back(request);
                    }
                }
                self.close_reason = Some(CloseReason::ServerRejected);
            }
            TransportErrorKind::Flood => {
                self.transport_floods += 1;
                callbacks.on_event(self.handle, EngineEvent::TransportFlood);
                self.next_attempt_at =
                    self.next_attempt_at.max(now.mono + transport_flood_delay(self.transport_floods));
                self.close_reason = Some(CloseReason::TransportFlood);
            }
            TransportErrorKind::InvalidDc | TransportErrorKind::Forbidden | TransportErrorKind::Other => {
                self.rejections = self.rejections.saturating_add(1);
                let delay = transport_flood_delay(self.rejections).min(REJECTION_MAX_DELAY);
                self.next_attempt_at = self.next_attempt_at.max(now.mono + delay);
                self.close_reason = Some(CloseReason::AddressRejected);
            }
        }
    }

    fn update_progress(&mut self, callbacks: &Arc<dyn EngineCallbacks>) {
        let (Some(connection), Some(rpc)) = (&self.connection, &self.rpc) else {
            return;
        };
        let Some((length, available)) = connection.pending_frame_head() else {
            self.progress = None;
            return;
        };
        if length < PROGRESS_THRESHOLD || available.len() < PROGRESS_HEAD {
            return;
        }
        let is_tracked = matches!(&self.progress, Some(tracking) if tracking.frame_length == length);
        if !is_tracked {
            let target = rpc.progress_target(&available[..PROGRESS_HEAD.min(available.len())]);
            self.progress = Some(ProgressTracking { frame_length: length, target, last_reported: 0 });
        }
        let tracking = self.progress.as_mut().expect("tracking exists");
        let Some(target) = tracking.target else {
            return;
        };
        let received = available.len();
        if received - tracking.last_reported >= (length / 100).max(16 * 1024) || received == length {
            tracking.last_reported = received;
            callbacks.on_event(
                self.handle,
                EngineEvent::Progress { id: target, progress: received as f32 / length as f32, packet_length: length },
            );
        }
    }

    fn pump_rpc_events(&mut self, now: Now, registry: &Registry, callbacks: &Arc<dyn EngineCallbacks>) {
        let mut reset_connection = false;
        if let Some(rpc) = &mut self.rpc {
            while let Some(event) = rpc.poll_event() {
                match &event {
                    RpcEvent::ConnectionShouldReset => {
                        reset_connection = true;
                        continue;
                    }
                    RpcEvent::TimeDifferenceUpdated { difference } => {
                        self.setup.time_difference = *difference;
                        if self
                            .reported_time_difference
                            .is_some_and(|reported| (difference - reported).abs() < TIME_DIFFERENCE_REPORT_THRESHOLD)
                        {
                            continue;
                        }
                        self.reported_time_difference = Some(*difference);
                    }
                    RpcEvent::SaltsUpdated { salts } => {
                        if *salts == self.reported_salts {
                            continue;
                        }
                        self.reported_salts = salts.clone();
                    }
                    RpcEvent::InitHashStored { hash } => remember_initialized(rpc.session().auth_key_id(), hash),
                    RpcEvent::AuthTokenRequired => self.auth_token_ready = false,
                    RpcEvent::Completed { .. } | RpcEvent::Failed { .. } => {
                        self.last_activity_at = now.mono;
                        self.deliveries = self.deliveries.wrapping_add(1);
                    }
                    RpcEvent::Update { .. } => self.deliveries = self.deliveries.wrapping_add(1),
                    _ => {}
                }
                callbacks.on_event(self.handle, EngineEvent::Rpc(event));
            }
        }
        if reset_connection && self.connection.is_some() {
            self.close_connection(registry, now, false);
            self.next_attempt_at = now.mono;
        }
    }

    fn log(&self, callbacks: &Arc<dyn EngineCallbacks>, level: LogLevel, message: &str) {
        callbacks.on_log(level, &format!("[MTProtoEngine#{} dc{}] {message}", self.handle.0, self.setup.datacenter_id));
    }

    pub fn drive(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        config: &EngineConfig,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        if self.rpc.is_none() && self.setup.key_generation.is_none() && !self.reported_key_required && !self.closed {
            self.reported_key_required = true;
            callbacks.on_event(self.handle, EngineEvent::AuthKeyRequired);
        }

        let wants = self.wants_connection(now);
        if !wants && self.connection.is_some() {
            self.close_connection(registry, now, false);
        }
        if wants && self.connection.is_none() && now.mono >= self.next_attempt_at {
            self.start_connection(registry, now, resolver, config, rng);
        }

        self.start_racer(registry, now, resolver, rng);
        let racer_limit = if self.racer_check.is_some() { RACE_VERIFY_TIMEOUT } else { config.connect_timeout };
        if self.racer.as_ref().is_some_and(|racer| now.mono - racer.started_at > racer_limit) {
            self.fail_racer(registry, now, callbacks);
        }
        let mut failure = None;
        if let Some(connection) = &self.connection
            && !connection.is_established()
            && now.mono - connection.started_at > config.connect_timeout
        {
            let index = connection.address_index;
            let tcp_connected = connection.is_tcp_connected();
            if !tcp_connected && let Some(racer) = self.racer.take() {
                self.report_address(index, false, now, callbacks);
                if let Some(mut loser) = self.connection.take() {
                    self.account_usage(&loser);
                    loser.deregister(registry);
                }
                self.connection = Some(racer);
            } else {
                failure = Some("connect timeout");
            }
        }
        if failure.is_none() && self.handshake_started_at.is_some_and(|started| now.mono - started > HANDSHAKE_TIMEOUT)
        {
            callbacks.on_event(self.handle, EngineEvent::AuthKeyCreationFailed { reason: "handshake timeout".into() });
            self.log(callbacks, LogLevel::Info, "handshake timeout");
            self.close_connection(registry, now, true);
        }
        if failure.is_none()
            && let (Some(rpc), Some(connection)) = (&mut self.rpc, &self.connection)
            && connection.is_established()
            && self.handshake.is_none()
            && rpc.wants_outbound_backlog()
        {
            rpc.note_outbound_backlog(connection.outbound_backlog(), now);
        }
        if failure.is_none() && self.handshake.is_none() {
            self.note_outbound_progress(now);
        }
        if failure.is_none()
            && let Some(rpc) = &mut self.rpc
            && self.connection.as_ref().is_some_and(Connection::is_established)
            && self.handshake.is_none()
            && let Err(error) = rpc.handle_timeout(now)
        {
            failure = Some(match error {
                SessionError::PingTimeout => "ping timeout",
                SessionError::ReadTimeout => "read timeout",
                SessionError::ProbeTimeout => "probe timeout",
                _ => "session timeout",
            });
        }
        if failure.is_none()
            && let (Some(connection), Some(rpc)) = (&self.connection, &self.rpc)
            && connection.is_established()
            && !self.timeout_fired
            && rpc.has_timeout_timer_requests()
            && now.mono - connection.last_progress_at > self.setup.request_timeout
        {
            self.timeout_fired = true;
            failure = Some("request timeout");
        }
        self.pump_rpc_events(now, registry, callbacks);
        if let Some(reason) = failure {
            self.log(callbacks, LogLevel::Info, reason);
            let received = self.connection_received_packet();
            if !received && let Some(index) = self.connection.as_ref().map(|connection| connection.address_index) {
                self.report_address(index, false, now, callbacks);
            }
            if received {
                self.next_attempt_at = now.mono;
            }
            self.close_dropped_connection(registry, now, !received);
        }

        self.flush_output(registry, now, callbacks, rng);
        if let (Some(rpc), Some(connection)) = (&mut self.rpc, &self.connection)
            && connection.is_established()
            && rpc.wants_outbound_backlog()
        {
            rpc.note_outbound_backlog(connection.outbound_backlog(), now);
        }
        self.report_state(now, callbacks);
        self.report_usage(now, config, callbacks);
    }

    fn flush_output(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(connection) = &mut self.connection else {
            return;
        };
        if !connection.is_tcp_connected() {
            return;
        }
        let mut failed = None;
        while let Some(packet) = self.pending_plain.pop_front() {
            if let Err(error) = connection.send_packet(registry, &packet, false, rng) {
                failed = Some(error);
                break;
            }
        }
        if failed.is_none()
            && self.handshake.is_none()
            && let Some(rpc) = &mut self.rpc
            && connection.is_established()
        {
            while let Some(transmit) = rpc.poll_transmit(now, rng) {
                if let Err(error) =
                    connection.send_packet(registry, &transmit.data, transmit.quick_ack_token.is_some(), rng)
                {
                    failed = Some(error);
                    break;
                }
            }
        }
        if failed.is_none()
            && let Err(error) = connection.flush(registry)
        {
            failed = Some(error);
        }
        self.pump_rpc_events(now, registry, callbacks);
        if let Some(error) = failed {
            self.log(callbacks, LogLevel::Info, &format!("write failed: {error}"));
            self.close_dropped_connection(registry, now, true);
        }
    }

    pub fn connection_state(&self) -> (ConnectionState, Option<String>) {
        let connected = self.connection.as_ref().is_some_and(Connection::is_established);
        let received = self.connection_received_packet();
        let state = ConnectionState {
            network_available: self.network_available && !self.setup.paused,
            connected,
            updating_connection_context: connected && !received,
            performing_service_tasks: connected
                && self.rpc.as_ref().is_some_and(|rpc| rpc.session().is_performing_service_tasks()),
            proxy_has_connection_issues: self.setup.proxy.is_some() && !connected && self.failures >= 3,
        };
        (state, self.setup.proxy.as_ref().map(ProxyConfig::display_address))
    }

    fn report_state(&mut self, _now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        let current = self.connection_state();
        if self.last_state.as_ref() != Some(&current) {
            self.last_state = Some(current.clone());
            callbacks
                .on_event(self.handle, EngineEvent::ConnectionState { state: current.0, proxy_address: current.1 });
        }
    }

    fn report_usage(&mut self, now: Now, config: &EngineConfig, callbacks: &Arc<dyn EngineCallbacks>) {
        if now.mono - self.last_usage_report < config.usage_report_interval {
            return;
        }
        self.last_usage_report = now.mono;
        let (mut incoming, mut outgoing) = (self.reported_in, self.reported_out);
        if let Some(connection) = &mut self.connection {
            self.cellular = connection.cellular;
            incoming += connection.bytes_in;
            outgoing += connection.bytes_out;
            connection.bytes_in = 0;
            connection.bytes_out = 0;
        }
        self.reported_in = 0;
        self.reported_out = 0;
        if incoming > 0 || outgoing > 0 {
            callbacks.on_event(self.handle, EngineEvent::NetworkUsage { incoming, outgoing, cellular: self.cellular });
        }
    }

    pub fn next_deadline(&mut self, now: Now, config: &EngineConfig) -> Option<f64> {
        let mut deadline = f64::INFINITY;
        let wants = self.wants_connection(now);
        if wants && self.connection.is_none() {
            deadline = deadline.min(self.next_attempt_at.max(now.mono));
        } else if !self.network_available && self.connection.is_none() && self.wants_connection_ignoring_network(now) {
            deadline = deadline.min(self.unavailable_probe_at.max(self.next_attempt_at).max(now.mono));
        }
        if let Some(started) = self.handshake_started_at {
            deadline = deadline.min(started + HANDSHAKE_TIMEOUT + 0.01);
        }
        if let Some(at) = self.race_deadline(now, config) {
            deadline = deadline.min(at);
        }
        if let Some(connection) = &self.connection {
            if !connection.is_established() {
                deadline = deadline.min(connection.started_at + config.connect_timeout);
            }
            if let Some(rpc) = &mut self.rpc
                && connection.is_established()
            {
                if let Some(at) = rpc.poll_timeout(now) {
                    deadline = deadline.min(at);
                }
                if rpc.has_timeout_timer_requests() && !self.timeout_fired {
                    deadline = deadline.min(connection.last_progress_at + self.setup.request_timeout);
                }
            }
        } else if let Some(rpc) = &mut self.rpc
            && let Some(at) = rpc.poll_timeout(now)
        {
            deadline = deadline.min(at.max(now.mono + 0.5));
        }
        if let (Some(idle), Some(_)) = (self.setup.idle_disconnect_after, &self.connection)
            && !self.setup.keep_connected
            && !self.has_work()
        {
            deadline = deadline.min(self.last_activity_at + idle);
        }
        if self.reported_in > 0
            || self.reported_out > 0
            || self.connection.as_ref().is_some_and(|connection| connection.bytes_in > 0 || connection.bytes_out > 0)
        {
            deadline = deadline.min(self.last_usage_report + config.usage_report_interval);
        }
        deadline.is_finite().then_some(deadline)
    }

    pub fn shrink(&mut self) {
        if let Some(connection) = &mut self.connection {
            connection.shrink();
        }
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().shrink();
        }
    }
}

fn initialized_keys() -> &'static std::sync::Mutex<std::collections::HashSet<(u64, String)>> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
}

fn initialized_in_this_process(auth_key_id: u64, hash: Option<String>) -> Option<String> {
    hash.filter(|hash| initialized_keys().lock().is_ok_and(|keys| keys.contains(&(auth_key_id, hash.clone()))))
}

fn remember_initialized(auth_key_id: u64, hash: &str) {
    if let Ok(mut keys) = initialized_keys().lock() {
        if keys.len() >= MAX_INITIALIZED_KEYS {
            keys.clear();
        }
        keys.insert((auth_key_id, hash.to_string()));
    }
}

fn is_res_pq_for(packet: &[u8], nonce: &[u8; 16]) -> bool {
    decode_plain_message(packet).is_ok_and(|message| {
        message.body.len() >= 20
            && u32::from_le_bytes(message.body[..4].try_into().expect("4")) == ids::RES_PQ
            && message.body[4..20] == nonce[..]
    })
}

fn rpc_pending_requests(rpc: RpcClient) -> Vec<RpcRequest> {
    rpc.into_requests()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct ScriptedResolver {
        answers: VecDeque<Vec<SocketAddr>>,
        calls: usize,
    }

    impl Resolve for ScriptedResolver {
        fn resolve(&mut self, _session: SessionHandle, _host: &str, _port: u16) -> Resolution {
            self.calls += 1;
            Resolution::Resolved(self.answers.pop_front().unwrap_or_default())
        }
    }

    fn address(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 443)
    }

    fn ready_address(pick: Pick) -> SocketAddr {
        match pick {
            Pick::Ready(_, address, _) => address,
            Pick::Resolving => panic!("still resolving"),
            Pick::Unavailable => panic!("unavailable"),
        }
    }

    #[test]
    fn resolved_addresses_expire_and_are_refreshed_after_every_one_failed() {
        let now = Now { mono: 1000.0, unix: 1_727_000_000.0 };
        let setup = SessionSetup::new(
            2,
            SessionRole::Main,
            vec![DcAddress { host: "dc.example".into(), port: 443, secret: None }],
        );
        let mut runtime = SessionRuntime::new(SessionHandle(1), setup, Token(1), now, &mut OsRandom::new());
        let mut resolver = ScriptedResolver {
            answers: VecDeque::from([vec![address(1), address(2)], vec![address(3)], vec![address(4)]]),
            calls: 0,
        };

        assert_eq!(ready_address(runtime.pick_address_at(0, &mut resolver, now)), address(1));
        assert_eq!(ready_address(runtime.pick_address_at(0, &mut resolver, now)), address(1));
        assert_eq!(resolver.calls, 1, "cached within its lifetime");

        runtime.failures += 1;
        assert_eq!(ready_address(runtime.pick_address_at(0, &mut resolver, now)), address(2), "rotates on failure");
        runtime.failures += 1;
        assert_eq!(
            ready_address(runtime.pick_address_at(0, &mut resolver, now)),
            address(3),
            "every cached address failed"
        );
        assert_eq!(resolver.calls, 2);

        let later = Now { mono: now.mono + DNS_TTL + 1.0, unix: now.unix + DNS_TTL + 1.0 };
        assert_eq!(ready_address(runtime.pick_address_at(0, &mut resolver, later)), address(4), "expired");
        assert_eq!(resolver.calls, 3);

        runtime.on_resolved("moved.example", 443, vec![address(9)], later);
        assert_eq!(
            ready_address(runtime.pick_address_at(0, &mut resolver, later)),
            address(4),
            "foreign result ignored"
        );
        assert_eq!(resolver.calls, 3);
    }
}
