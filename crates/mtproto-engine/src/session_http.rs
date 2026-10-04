use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use mio::{Registry, Token};
use mtproto_core::crypto::{OsRandom, SecureRandom};
use mtproto_core::message::read_auth_key_id;
use mtproto_core::rpc::SessionRole;
use mtproto_core::session::{HttpWait, Now, SessionError};
use mtproto_core::transport::{
    HttpResponse, HttpRoute, Socks5Auth, Socks5Target, TransportErrorKind, authority, reconnect_delay,
};

use super::{AddressHealth, CloseReason, FRAME_MIN_RATE, FRAME_PROGRESS_GRACE, Resolution, Resolve, SessionRuntime};
use crate::http_link::{HTTP_FIRST_TOKEN_OFFSET, HTTP_MAX_CONNECTIONS, HttpConn, HttpConnError, HttpIo, RequestMeta};
use crate::resolver::parse_literal;
use crate::types::{DropReason, EngineCallbacks, EngineConfig, LogLevel, ProxyConfig};

/// How long a request carrying queries lets the server wait for their answers before it answers
/// anyway: a quick answer comes back on it, a slow one later on a parked long poll, and the round
/// trip doubles as the liveness check that pings are on the stream transports.
pub const HTTP_SEND_WAIT: f64 = 0.1;
/// Long polls while the user is online: two staggered ones answer at least every 5 s, so a dead
/// path is noticed about as fast as by the stream transports' pings.
pub const HTTP_ONLINE_SLOT_WAIT: f64 = 10.0;
/// Long polls otherwise; longer ones may be cut by proxies on the way.
pub const HTTP_SLOT_WAIT: f64 = 25.0;
/// The server closes an idle keep-alive connection after about 90 s; one idle this long is closed
/// first so no request is ever written into a connection being torn down.
pub const HTTP_IDLE_CLOSE: f64 = 50.0;
/// Spare idle connections kept beyond the parked long polls for the next requests.
pub const HTTP_SPARE_IDLE: usize = 2;
pub const HTTP_SPARE_IDLE_AFTER: f64 = 5.0;
pub const HTTP_RESPONSE_TIMEOUT_INITIAL: f64 = 4.0;
pub const HTTP_RESPONSE_TIMEOUT_MIN: f64 = 1.0;
pub const HTTP_RESPONSE_TIMEOUT_MAX: f64 = 8.0;
/// The uplink assumed for a request body until one was measured.
pub const HTTP_UPLINK_INITIAL: f64 = 32.0 * 1024.0;
pub const HTTP_UPLINK_MIN: f64 = 4.0 * 1024.0;
pub const HTTP_TRANSFER_ALLOWANCE_MAX: f64 = 120.0;
pub const HTTP_MAX_CONNECTING: usize = 2;
pub const HTTP_READ_BUDGET: usize = 512 * 1024;
pub const HTTP_PIPELINE_DEPTH: usize = 2;

/// A name a connection was opened to, and which of its addresses.
type NamedAddress = ((String, u16), SocketAddr);

#[derive(Default)]
pub(super) struct HttpState {
    pub(super) conns: Vec<HttpConn>,
    /// The session saw the link open and has not seen it close.
    opened: bool,
    next_open_at: f64,
    open_failures: u32,
    /// Connections to an address of a name: which name, and which of its addresses.
    named: Vec<(Token, NamedAddress)>,
    /// Connections in a row that opened and then went without a single answer, as when a middlebox
    /// cuts every request: they back off like flapping stream connections.
    cut_in_a_row: u32,
    health: HashMap<(String, u16), AddressHealth>,
    cursor: usize,
    more_readable: Vec<Token>,
    /// A packet the key decrypted came over the link: it works end to end.
    answered: bool,
    /// Connections that decrypted a packet, by token.
    proven: Vec<Token>,
    handshake_token: Option<Token>,
    /// Bytes per second request bodies crossed the uplink at, lately.
    uplink_rate: Option<f64>,
    logged_proxy: bool,
    /// Nothing is sent before then: the server asked to back off (-429) or refused the request.
    hold_until: f64,
    /// A plain req_pq on this route came back with the server's answer, and no 404 was counted since:
    /// the next 404 is Telegram's. Captive portals and proxy deny pages answer 404 too, and a 404 taken
    /// for Telegram's makes the key count as lost.
    route_checked: bool,
    route_check_needed: bool,
    route_check_nonce: Option<[u8; 16]>,
}

impl HttpState {
    pub(super) fn owns(&self, token: Token) -> bool {
        self.conns.iter().any(|conn| conn.token() == token)
    }

    fn index(&self, token: Token) -> Option<usize> {
        self.conns.iter().position(|conn| conn.token() == token)
    }

    /// A new session (a new key) has to see the link open again.
    pub(super) fn forget_opened(&mut self) {
        self.opened = false;
    }

    pub(super) fn next_open_at(&self) -> f64 {
        self.next_open_at
    }

    /// A lookup the next connection waits for came back: it goes at once, not after the wait for it.
    pub(super) fn note_lookup_done(&mut self, now: f64) {
        if self.open_failures == 0 {
            self.next_open_at = self.next_open_at.min(now);
        }
    }

    pub(super) fn forget_backoff(&mut self) {
        self.hold_until = 0.0;
        self.next_open_at = 0.0;
        self.open_failures = 0;
        self.cut_in_a_row = 0;
    }

    /// Long polls parked. While a reset waits for the old session's answers only those on connections
    /// that answered count, once one has: a long poll on a connection that never answered (a black-holed
    /// address) would leave those answers no way back.
    fn parked_long_polls(&self, draining: bool) -> usize {
        let proven = |conn: &&HttpConn| self.proven.contains(&conn.token());
        let parked = self.conns.iter().filter(|conn| conn.has_slot());
        if draining && self.conns.iter().any(|conn| proven(&conn)) {
            parked.filter(proven).count()
        } else {
            parked.count()
        }
    }

    pub(super) fn is_connected(&self) -> bool {
        self.conns.iter().any(HttpConn::is_ready)
    }

    pub(super) fn has_conns(&self) -> bool {
        !self.conns.is_empty()
    }

    pub(super) fn answered(&self) -> bool {
        self.answered
    }

    pub(super) fn first_more_readable(&self) -> Option<Token> {
        self.more_readable.first().copied()
    }

    pub(super) fn take_usage(&mut self) -> (u64, u64, bool) {
        let (mut incoming, mut outgoing, mut cellular) = (0, 0, false);
        for conn in &mut self.conns {
            incoming += conn.bytes_in;
            outgoing += conn.bytes_out;
            cellular |= conn.cellular;
            conn.bytes_in = 0;
            conn.bytes_out = 0;
        }
        (incoming, outgoing, cellular)
    }

    pub(super) fn has_usage(&self) -> bool {
        self.conns.iter().any(|conn| conn.bytes_in > 0 || conn.bytes_out > 0)
    }

    pub(super) fn shrink(&mut self) {
        for conn in &mut self.conns {
            conn.shrink();
        }
    }

    #[cfg(test)]
    pub(super) fn describe(&self, now: f64) -> String {
        let conns: Vec<String> = self
            .conns
            .iter()
            .map(|conn| {
                format!(
                    "[{} ready {} free {} in_flight {} slot {} responses {} idle {:+.2}]",
                    conn.token().0,
                    conn.is_ready(),
                    conn.is_free(),
                    conn.in_flight_len(),
                    conn.has_slot(),
                    conn.responses,
                    conn.idle_since - now
                )
            })
            .collect();
        format!(
            "http(opened {} next_open {:+.3} hold {:+.3} open_failures {} cut {} route_checked {} check_needed {} check_sent {} handshake_token {:?} answered {} named {} conns {})",
            self.opened,
            self.next_open_at - now,
            self.hold_until - now,
            self.open_failures,
            self.cut_in_a_row,
            self.route_checked,
            self.route_check_needed,
            self.route_check_nonce.is_some(),
            self.handshake_token.map(|token| token.0),
            self.answered,
            self.named.len(),
            conns.join("")
        )
    }
}

impl SessionRuntime {
    /// Moves the session onto HTTP; the stream connection, if any, is closed first.
    pub(super) fn enter_http(&mut self, registry: &Registry, now: Now) {
        if self.http.is_some() {
            return;
        }
        self.close_connection(registry, now, false);
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().set_http(true);
        }
        self.http = Some(HttpState::default());
    }

    pub(super) fn leave_http(&mut self, registry: &Registry, now: Now) {
        if self.http.is_none() {
            return;
        }
        self.close_http(registry, now);
        self.http = None;
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().set_http(false);
        }
    }

    /// Closes every HTTP connection; the session sees the link close.
    pub(super) fn close_http(&mut self, registry: &Registry, now: Now) {
        let Some(mut http) = self.http.take() else {
            return;
        };
        for mut conn in http.conns.drain(..) {
            self.reported_in += conn.bytes_in;
            self.reported_out += conn.bytes_out;
            conn.deregister(registry);
        }
        http.more_readable.clear();
        http.proven.clear();
        http.named.clear();
        http.route_checked = false;
        http.route_check_nonce = None;
        http.answered = false;
        if http.handshake_token.take().is_some() || self.handshake.is_some() {
            self.handshake = None;
            self.handshake_started_at = None;
            self.pending_plain.clear();
        }
        if http.opened {
            http.opened = false;
            if let Some(rpc) = &mut self.rpc {
                rpc.connection_closed(now);
            }
        }
        self.http = Some(http);
    }

    fn http_candidates(&self) -> Vec<(usize, String, u16)> {
        self.setup
            .addresses
            .iter()
            .enumerate()
            .filter(|(_, address)| address.secret.is_none())
            .flat_map(|(index, address)| {
                let mut ports = vec![self.setup.http_port.unwrap_or(address.port)];
                if !ports.contains(&address.port) {
                    ports.push(address.port);
                }
                ports.into_iter().map(move |port| (index, address.host.clone(), port))
            })
            .collect()
    }

    fn http_route(&self, host: &str, port: u16) -> HttpRoute {
        match &self.setup.proxy {
            Some(ProxyConfig::Http { username, password, .. }) => HttpRoute::Forwarded {
                authority: authority(host, port),
                credentials: super::http_credentials(username, password),
            },
            _ => HttpRoute::Direct { authority: authority(host, port) },
        }
    }

    fn http_free_token(&self) -> Option<Token> {
        let http = self.http.as_ref()?;
        (0..HTTP_MAX_CONNECTIONS)
            .map(|offset| Token(self.token.0 + HTTP_FIRST_TOKEN_OFFSET + offset))
            .find(|token| !http.owns(*token))
    }

    fn open_http_conn(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> Option<usize> {
        let http = self.http.as_ref()?;
        if now.mono < http.next_open_at
            || http.conns.len() >= HTTP_MAX_CONNECTIONS
            || http.conns.iter().filter(|conn| !conn.is_ready()).count() >= HTTP_MAX_CONNECTING
        {
            return None;
        }
        if matches!(self.setup.proxy, Some(ProxyConfig::MtProxy { .. })) {
            if let Some(http) = &mut self.http
                && !http.logged_proxy
            {
                http.logged_proxy = true;
                self.log(callbacks, LogLevel::Warning, "HTTP cannot go through an MTProxy");
            }
            return None;
        }
        let candidates = self.http_candidates();
        if candidates.is_empty() {
            return None;
        }
        let ranked = {
            let http = self.http.as_ref()?;
            let rank =
                |host: &String, port: u16| http.health.get(&(host.clone(), port)).copied().unwrap_or_default().rank();
            let mut order: Vec<usize> = (0..candidates.len()).collect();
            let start = http.cursor % candidates.len();
            order.sort_by(|a, b| {
                let (left, right) =
                    (rank(&candidates[*a].1, candidates[*a].2), rank(&candidates[*b].1, candidates[*b].2));
                let distance = |index: usize| (index + candidates.len() - start) % candidates.len();
                left.0.cmp(&right.0).then(left.1.total_cmp(&right.1)).then(distance(*a).cmp(&distance(*b)))
            });
            order
        };
        let connecting: Vec<(String, u16)> = self
            .http
            .as_ref()?
            .conns
            .iter()
            .filter(|conn| !conn.is_ready())
            .filter_map(|conn| candidates.get(conn.address_index).map(|(_, host, port)| (host.clone(), *port)))
            .collect();
        let choice = ranked
            .iter()
            .copied()
            .find(|index| !connecting.contains(&(candidates[*index].1.clone(), candidates[*index].2)))
            .unwrap_or(ranked[0]);
        let (_, host, port) = candidates[choice].clone();
        let (connect_host, connect_port, socks) = match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { host: proxy_host, port: proxy_port, username, password }) => {
                let target = match parse_literal(&host, port) {
                    Some(SocketAddr::V4(v4)) => Socks5Target::Ipv4(v4.ip().octets(), port),
                    Some(SocketAddr::V6(v6)) => Socks5Target::Ipv6(v6.ip().octets(), port),
                    None => Socks5Target::Domain(host.clone(), port),
                };
                let auth = match (username, password) {
                    (Some(username), Some(password)) if !username.is_empty() => {
                        Some(Socks5Auth { username: username.clone(), password: password.clone() })
                    }
                    _ => None,
                };
                (proxy_host.clone(), *proxy_port, Some((target, auth)))
            }
            Some(ProxyConfig::Http { host: proxy_host, port: proxy_port, .. }) => {
                (proxy_host.clone(), *proxy_port, None)
            }
            _ => (host.clone(), port, None),
        };
        if !self.network_available {
            self.unavailable_probe_at = now.mono + super::UNAVAILABLE_PROBE_INTERVAL;
        }
        let mut named = None;
        let socket_address = match parse_literal(&connect_host, connect_port) {
            Some(address) => address,
            None => match self.resolve_cached(&connect_host, connect_port, resolver, now) {
                Resolution::Resolved(addresses) if !addresses.is_empty() => {
                    let key = (connect_host.clone(), connect_port);
                    let address = self.pick_named_address(&key, &addresses);
                    named = Some((key, address));
                    address
                }
                Resolution::Resolved(_) => {
                    self.note_http_resolve_failure(now);
                    return None;
                }
                Resolution::Pending => {
                    if let Some(http) = &mut self.http {
                        http.next_open_at = now.mono + super::RESOLVE_WAIT;
                    }
                    return None;
                }
            },
        };
        let token = self.http_free_token()?;
        let route = self.http_route(&host, port);
        match HttpConn::connect(registry, token, socket_address, route, socks, choice, now.mono) {
            Ok(conn) => {
                let http = self.http.as_mut()?;
                http.cursor = choice + 1;
                if let Some(named) = named {
                    http.named.push((conn.token(), named));
                }
                http.conns.push(conn);
                Some(http.conns.len() - 1)
            }
            Err(_) => {
                if let Some((key, address)) = named {
                    self.note_named_address_failed(key, address);
                }
                self.note_http_address(choice, false, now);
                self.note_http_open_failure(now);
                None
            }
        }
    }

    /// The address of a name to try: the first one that has not failed, or the one that failed longest
    /// ago once they all have.
    fn pick_named_address(&mut self, key: &(String, u16), addresses: &[SocketAddr]) -> SocketAddr {
        let failed = self.dns_failed.entry(key.clone()).or_default();
        failed.retain(|address| addresses.contains(address));
        if let Some(address) = addresses.iter().find(|address| !failed.contains(address)) {
            return *address;
        }
        failed.remove(0)
    }

    /// An address of a name could not be reached: the next connection tries the others first.
    fn note_named_address_failed(&mut self, key: (String, u16), address: SocketAddr) {
        let failed = self.dns_failed.entry(key).or_default();
        failed.retain(|other| *other != address);
        failed.push(address);
    }

    fn note_named_address_answered(&mut self, key: &(String, u16), address: SocketAddr) {
        if let Some(failed) = self.dns_failed.get_mut(key) {
            failed.retain(|other| *other != address);
        }
    }

    /// A route's name did not resolve: the next lookup waits as the TCP transport's does.
    pub(super) fn note_http_resolve_failure(&mut self, now: Now) {
        let jitter = self.next_jitter();
        if let Some(http) = &mut self.http {
            http.open_failures = http.open_failures.saturating_add(1);
            let delay =
                reconnect_delay(http.open_failures, jitter).clamp(super::RESOLVE_RETRY_MIN, super::RESOLVE_RETRY_MAX);
            http.next_open_at = http.next_open_at.max(now.mono + delay);
        }
    }

    pub(super) fn open_failures(&self) -> u32 {
        self.http.as_ref().map_or(0, |http| http.open_failures)
    }

    fn note_http_open_failure(&mut self, now: Now) {
        let jitter = self.next_jitter();
        let has_work = self.has_waiting_work();
        if let Some(http) = &mut self.http {
            http.open_failures = http.open_failures.saturating_add(1);
            let delay = if has_work {
                mtproto_core::transport::urgent_reconnect_delay(http.open_failures, jitter)
            } else {
                reconnect_delay(http.open_failures, jitter)
            };
            let cut = mtproto_core::transport::flap_delay(http.cut_in_a_row, jitter);
            http.next_open_at = http.next_open_at.max(now.mono + delay.max(cut).max(0.05));
        }
    }

    fn note_http_address(&mut self, candidate: usize, success: bool, now: Now) {
        let candidates = self.http_candidates();
        let Some((_, host, port)) = candidates.get(candidate).cloned() else {
            return;
        };
        if let Some(http) = &mut self.http {
            let health = http.health.entry((host, port)).or_default();
            if success {
                health.ok_at = now.mono;
            } else {
                health.error_at = now.mono;
            }
        }
    }

    /// A connection that takes a request now or as soon as it connects, opening one if needed.
    fn http_conn_for_request(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> Option<usize> {
        let http = self.http.as_ref()?;
        let proven =
            http.conns.iter().position(|conn| conn.is_ready() && conn.is_free() && http.proven.contains(&conn.token()));
        if proven.is_some() {
            return proven;
        }
        let ready = http.conns.iter().position(|conn| conn.is_ready() && conn.is_free());
        if ready.is_some() {
            return ready;
        }
        let connecting = http.conns.iter().position(|conn| !conn.is_ready() && conn.is_free());
        if connecting.is_some() {
            return connecting;
        }
        let pipelined = http.conns.iter().position(|conn| conn.takes_pipelined(HTTP_PIPELINE_DEPTH));
        if pipelined.is_some() {
            return pipelined;
        }
        self.open_http_conn(registry, now, resolver, callbacks)
    }

    /// Some HTTP route exists at all: an address without a secret, and no MTProxy in the way.
    pub(super) fn http_route_possible(&self) -> bool {
        !matches!(self.setup.proxy, Some(ProxyConfig::MtProxy { .. })) && !self.http_candidates().is_empty()
    }

    /// A request could go out now: a connection takes one, or one may be opened.
    pub(super) fn http_can_dispatch(&self, now: Now) -> bool {
        let Some(http) = &self.http else {
            return false;
        };
        if now.mono < http.hold_until || (http.route_check_needed && http.route_check_nonce.is_some()) {
            return false;
        }
        if http.conns.iter().any(|conn| conn.is_free() || conn.takes_pipelined(HTTP_PIPELINE_DEPTH)) {
            return true;
        }
        now.mono >= http.next_open_at
            && http.conns.len() < HTTP_MAX_CONNECTIONS
            && http.conns.iter().filter(|conn| !conn.is_ready()).count() < HTTP_MAX_CONNECTING
            && !matches!(self.setup.proxy, Some(ProxyConfig::MtProxy { .. }))
            && !self.http_candidates().is_empty()
    }

    fn http_response_timeout(&self) -> f64 {
        self.rpc.as_ref().and_then(|rpc| rpc.session().smoothed_rtt()).map_or(HTTP_RESPONSE_TIMEOUT_INITIAL, |rtt| {
            (rtt * 3.0 + 0.5).clamp(HTTP_RESPONSE_TIMEOUT_MIN, HTTP_RESPONSE_TIMEOUT_MAX)
        })
    }

    fn http_transfer_allowance(&self, bytes: usize) -> f64 {
        if bytes < 16 * 1024 {
            return 0.0;
        }
        let rate = self
            .http
            .as_ref()
            .and_then(|http| http.uplink_rate)
            .map_or(HTTP_UPLINK_INITIAL, |rate| (rate * 0.5).max(HTTP_UPLINK_MIN));
        (bytes as f64 / rate).min(HTTP_TRANSFER_ALLOWANCE_MAX)
    }

    /// When connection `index` has to have shown progress by, or is given up on.
    fn http_conn_deadline(&self, conn: &HttpConn, config: &EngineConfig) -> Option<f64> {
        if !conn.is_ready() {
            return Some(conn.started_at + config.connect_timeout);
        }
        let timeout = self.http_response_timeout();
        if let Some((received, started_at)) = conn.response_in_progress() {
            let stalled = conn.last_progress_at + timeout.max(FRAME_PROGRESS_GRACE / 2.0);
            let trickle = started_at + FRAME_PROGRESS_GRACE + received as f64 / FRAME_MIN_RATE;
            return Some(stalled.min(trickle.max(conn.last_progress_at)));
        }
        let (written_at, meta) = conn.head()?;
        let allowance = self.http_transfer_allowance(meta.bytes);
        let base = match written_at {
            Some(at) => (at + meta.max_wait).max(conn.last_progress_at),
            None => conn.last_progress_at.max(meta.queued_at),
        };
        let deadline = base + timeout + allowance;
        Some(match conn.head_in_progress() {
            Some(started) => deadline.min(started + timeout + FRAME_PROGRESS_GRACE),
            None => deadline,
        })
    }

    fn http_slot_target(&self) -> usize {
        let Some(rpc) = &self.rpc else {
            return 0;
        };
        let awaiting = rpc.session().is_awaiting_responses();
        let listening = self.setup.keep_connected && self.setup.role == SessionRole::Main;
        if awaiting {
            let unanswered = rpc.session().unanswered_query_count();
            (2 + unanswered / 8).min(HTTP_MAX_CONNECTIONS - 2)
        } else if listening {
            if self.setup.online { 2 } else { 1 }
        } else {
            0
        }
    }

    fn http_slot_wait(&self, now: Now) -> f64 {
        let period = if self.setup.online && self.setup.role == SessionRole::Main {
            HTTP_ONLINE_SLOT_WAIT
        } else {
            HTTP_SLOT_WAIT
        };
        let Some(http) = &self.http else {
            return period;
        };
        let parked: Vec<f64> = http
            .conns
            .iter()
            .filter_map(|conn| {
                conn.head()
                    .filter(|(_, meta)| meta.slot)
                    .map(|(written, meta)| written.unwrap_or(meta.queued_at) + meta.max_wait - now.mono)
            })
            .collect();
        staggered_wait(&parked, period)
    }

    pub(super) fn drive_http(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        config: &EngineConfig,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let wants = self.wants_connection(now);
        if !wants {
            if self.http.as_ref().is_some_and(|http| http.has_conns() || http.opened) || self.handshake.is_some() {
                self.close_http(registry, now);
            }
            self.pump_rpc_events(now, registry, callbacks);
            return;
        }
        self.expire_http_conns(registry, now, config, callbacks, rng);
        if self.handshake_started_at.is_some_and(|started| now.mono - started > super::HANDSHAKE_TIMEOUT) {
            callbacks.on_event(
                self.handle,
                crate::types::EngineEvent::AuthKeyCreationFailed { reason: "handshake timeout".into() },
            );
            self.log(callbacks, LogLevel::Info, "handshake timeout");
            match self.http.as_ref().and_then(|http| http.handshake_token) {
                Some(token) => {
                    self.fail_http_conn_token(token, DropReason::HandshakeTimeout, true, registry, now, callbacks)
                }
                None => self.note_http_handshake_failure(now),
            }
            self.handshake = None;
            self.handshake_started_at = None;
            self.pending_plain.clear();
            if let Some(http) = &mut self.http {
                http.handshake_token = None;
            }
        }
        if self.rpc.is_none() {
            self.drive_http_handshake(registry, now, resolver, callbacks, rng);
        } else {
            let ready = self.http.as_ref().is_some_and(HttpState::is_connected);
            if ready && self.http.as_ref().is_some_and(|http| !http.opened) {
                if let Some(http) = &mut self.http {
                    http.opened = true;
                }
                if let Some(rpc) = &mut self.rpc {
                    rpc.session_mut().set_http(true);
                    rpc.connection_opened(now);
                }
            }
            if !ready && self.http.as_ref().is_some_and(|http| http.conns.is_empty()) {
                self.open_http_conn(registry, now, resolver, callbacks);
            }
            if self.http.as_ref().is_some_and(|http| http.opened) {
                if let Some(rpc) = &mut self.rpc
                    && let Err(error) = rpc.handle_timeout(now)
                {
                    self.log(callbacks, LogLevel::Info, &format!("session timeout on HTTP: {error}"));
                }
                self.dispatch_http(registry, now, resolver, callbacks, rng);
            }
        }
        self.close_idle_http(registry, now);
        self.pump_rpc_events(now, registry, callbacks);
    }

    fn drive_http_handshake(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(handshake_config) = self.handshake_config() else {
            return;
        };
        if self.http.as_ref().is_some_and(|http| now.mono < http.hold_until) {
            return;
        }
        let token = match self.http.as_ref().and_then(|http| http.handshake_token) {
            Some(token) => token,
            None => {
                let Some(index) = self.http_conn_for_request(registry, now, resolver, callbacks) else {
                    return;
                };
                let token = self.http.as_ref().map(|http| http.conns[index].token()).expect("http");
                if let Some(http) = &mut self.http {
                    http.handshake_token = Some(token);
                }
                token
            }
        };
        let Some(index) = self.http.as_ref().and_then(|http| http.index(token)) else {
            if let Some(http) = &mut self.http {
                http.handshake_token = None;
            }
            return;
        };
        let ready = self.http.as_ref().is_some_and(|http| http.conns[index].is_ready());
        if ready && self.handshake.is_none() {
            let (handshake, packet) =
                mtproto_core::handshake::Handshake::start(handshake_config, now.unix + self.setup.time_difference, rng);
            self.handshake = Some(handshake);
            self.handshake_started_at = Some(now.mono);
            self.pending_plain.push_back(packet);
        }
        let free = self.http.as_ref().is_some_and(|http| http.conns[index].is_free());
        if free && let Some(packet) = self.pending_plain.pop_front() {
            let meta = RequestMeta {
                packet_seq: None,
                max_wait: 0.0,
                slot: false,
                queued_at: now.mono,
                bytes: 0,
                probe: false,
                generation: self.rpc_generation,
            };
            let result = self.http.as_mut().map(|http| http.conns[index].submit(registry, &packet, meta, now.mono));
            if let Some(Err(error)) = result {
                self.log(callbacks, LogLevel::Info, &format!("HTTP write failed: {error}"));
                self.fail_http_conn_token(token, DropReason::IoError, true, registry, now, callbacks);
            }
        }
    }

    fn dispatch_http(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        if self.http.as_ref().is_some_and(|http| now.mono < http.hold_until) {
            return;
        }
        self.check_http_route(registry, now, resolver, callbacks, rng);
        if self.http.as_ref().is_some_and(|http| http.route_check_needed) {
            return;
        }
        let send_wait = HttpWait { max_delay: 0, wait_after: 0, max_wait: (HTTP_SEND_WAIT * 1000.0) as i32 };
        let sending = |http: &HttpState| http.conns.iter().any(HttpConn::waits_on_queries);
        if !self.http.as_ref().is_some_and(sending) {
            let target = self.http_slot_target();
            let draining = self.rpc.as_ref().is_some_and(|rpc| rpc.session().is_draining());
            let mut parked = self.http.as_ref().map_or(0, |http| http.parked_long_polls(draining));
            while parked < target {
                let Some(index) = self.http_conn_for_request(registry, now, resolver, callbacks) else {
                    break;
                };
                let wait = self.http_slot_wait(now);
                let long_poll = HttpWait::long_poll((wait * 1000.0) as i32);
                let Some(transmit) =
                    self.rpc.as_mut().and_then(|rpc| rpc.poll_http_transmit(now, rng, long_poll, true, false))
                else {
                    break;
                };
                let meta = RequestMeta {
                    packet_seq: Some(transmit.packet_seq),
                    max_wait: wait,
                    slot: true,
                    queued_at: now.mono,
                    bytes: 0,
                    probe: false,
                    generation: self.rpc_generation,
                };
                if !self.submit_http(index, &transmit.data, meta, registry, now, callbacks) {
                    break;
                }
                parked += 1;
            }
        }
        let mut guard = 0;
        while self.rpc.as_mut().is_some_and(|rpc| rpc.wants_http_transmit(now)) && guard < HTTP_MAX_CONNECTIONS {
            guard += 1;
            let Some(index) = self.http_conn_for_request(registry, now, resolver, callbacks) else {
                break;
            };
            let carries_queries = self.rpc.as_ref().is_some_and(|rpc| rpc.session().has_queries_to_send());
            let (wait, max_wait) =
                if carries_queries { (send_wait, HTTP_SEND_WAIT) } else { (HttpWait::IMMEDIATE, 0.0) };
            let Some(transmit) = self.rpc.as_mut().and_then(|rpc| rpc.poll_http_transmit(now, rng, wait, false, true))
            else {
                break;
            };
            let meta = RequestMeta {
                packet_seq: Some(transmit.packet_seq),
                max_wait,
                slot: false,
                queued_at: now.mono,
                bytes: 0,
                probe: false,
                generation: self.rpc_generation,
            };
            if !self.submit_http(index, &transmit.data, meta, registry, now, callbacks) {
                break;
            }
        }
    }

    /// Asks the server for a res_pq on the route after a 404 nothing proved to be Telegram's.
    fn check_http_route(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        if !self.http.as_ref().is_some_and(|http| http.route_check_needed && http.route_check_nonce.is_none()) {
            return;
        }
        let Some(index) = self.http_conn_for_request(registry, now, resolver, callbacks) else {
            return;
        };
        let nonce: [u8; 16] = rng.array();
        let mut writer = mtproto_core::tl::Writer::with_capacity(24);
        mtproto_core::tl::TlWrite::write_to(&mtproto_core::tl::mtproto::ReqPqMulti { nonce }, &mut writer);
        let msg_id = mtproto_core::msg_id::msg_id_for_time(now.unix + self.time_difference()) & !3;
        let packet = mtproto_core::message::encode_plain_message(msg_id, &writer.into_inner());
        let meta = RequestMeta {
            packet_seq: None,
            max_wait: 0.0,
            slot: false,
            queued_at: now.mono,
            bytes: 0,
            probe: true,
            generation: self.rpc_generation,
        };
        if let Some(http) = &mut self.http {
            http.route_check_nonce = Some(nonce);
        }
        if !self.submit_http(index, &packet, meta, registry, now, callbacks)
            && let Some(http) = &mut self.http
        {
            http.route_check_nonce = None;
        }
    }

    fn submit_http(
        &mut self,
        index: usize,
        data: &[u8],
        meta: RequestMeta,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> bool {
        self.last_activity_at = now.mono;
        self.log(
            callbacks,
            LogLevel::Debug,
            &format!(
                "HTTP {} packet {:?} ({} bytes, wait {:.3}s) on connection {index}",
                if meta.slot { "long poll" } else { "send" },
                meta.packet_seq,
                data.len(),
                meta.max_wait
            ),
        );
        let Some(http) = &mut self.http else {
            return false;
        };
        let token = http.conns[index].token();
        match http.conns[index].submit(registry, data, meta, now.mono) {
            Ok(()) => true,
            Err(error) => {
                self.log(callbacks, LogLevel::Info, &format!("HTTP write failed: {error}"));
                self.fail_http_conn_token(token, DropReason::IoError, false, registry, now, callbacks);
                false
            }
        }
    }

    fn close_idle_http(&mut self, registry: &Registry, now: Now) {
        let target = self.http_slot_target();
        let Some(http) = &mut self.http else {
            return;
        };
        let mut spare = 0usize;
        let mut close = Vec::new();
        let mut order: Vec<usize> = (0..http.conns.len()).collect();
        order.sort_by(|a, b| http.conns[*b].idle_since.total_cmp(&http.conns[*a].idle_since));
        for index in order {
            let conn = &http.conns[index];
            if !conn.is_ready() || conn.in_flight_len() > 0 {
                continue;
            }
            let idle = now.mono - conn.idle_since;
            let surplus = spare >= HTTP_SPARE_IDLE + target && idle > HTTP_SPARE_IDLE_AFTER;
            if !conn.keep_alive || idle > HTTP_IDLE_CLOSE || surplus {
                close.push(index);
            } else {
                spare += 1;
            }
        }
        close.sort_unstable();
        for index in close.into_iter().rev() {
            let mut conn = http.conns.remove(index);
            http.more_readable.retain(|token| *token != conn.token());
            http.proven.retain(|token| *token != conn.token());
            http.named.retain(|(token, _)| *token != conn.token());
            self.reported_in += conn.bytes_in;
            self.reported_out += conn.bytes_out;
            conn.deregister(registry);
        }
    }

    fn expire_http_conns(
        &mut self,
        registry: &Registry,
        now: Now,
        config: &EngineConfig,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let _ = rng;
        let Some(http) = &mut self.http else {
            return;
        };
        for conn in http.conns.iter_mut().filter(|conn| conn.is_ready()) {
            conn.note_outbound_progress(now.mono);
        }
        let expired: Vec<(Token, DropReason)> = self
            .http
            .as_ref()
            .map(|http| {
                http.conns
                    .iter()
                    .filter_map(|conn| {
                        let deadline = self.http_conn_deadline(conn, config)?;
                        (now.mono >= deadline).then(|| {
                            let reason = if !conn.is_ready() {
                                DropReason::ConnectTimeout
                            } else if conn.response_in_progress().is_some() {
                                DropReason::ReadTimeout
                            } else {
                                DropReason::RequestTimeout
                            };
                            (conn.token(), reason)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (token, reason) in expired {
            self.log(callbacks, LogLevel::Info, &format!("HTTP {}", reason.name()));
            self.fail_http_conn_token(token, reason, true, registry, now, callbacks);
        }
    }

    /// Gives up on a connection: what it carried counts as lost, so its queries go again elsewhere.
    pub(super) fn fail_http_conn_token(
        &mut self,
        token: Token,
        reason: DropReason,
        report: bool,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) {
        let Some(http) = &mut self.http else {
            return;
        };
        let Some(index) = http.index(token) else {
            return;
        };
        let mut conn = http.conns.remove(index);
        http.more_readable.retain(|other| *other != token);
        let proven = http.proven.contains(&token);
        http.proven.retain(|other| *other != token);
        let handshake = http.handshake_token == Some(token);
        if handshake {
            http.handshake_token = None;
        }
        let lost = conn.lost_requests();
        let answered = conn.responses > 0;
        let handshake = handshake && !lost.is_empty();
        let named = http.named.iter().position(|(other, _)| *other == token).map(|at| http.named.remove(at).1);
        let age = now.mono - conn.started_at;
        let established = conn.established_at.is_some();
        let candidate = conn.address_index;
        self.reported_in += conn.bytes_in;
        self.reported_out += conn.bytes_out;
        conn.deregister(registry);
        if handshake {
            self.handshake = None;
            self.handshake_started_at = None;
            self.pending_plain.clear();
        }
        self.note_http_requests_lost(&lost, now);
        if handshake {
            self.note_http_handshake_failure(now);
        }
        if !answered
            && (!established || !lost.is_empty())
            && let Some((key, address)) = named
        {
            self.note_named_address_failed(key, address);
        }
        if !answered {
            if established
                && !lost.is_empty()
                && let Some(http) = &mut self.http
            {
                http.cut_in_a_row = http.cut_in_a_row.saturating_add(1);
            }
            self.note_http_address(candidate, false, now);
            self.note_http_open_failure(now);
        }
        if report {
            callbacks
                .on_event(self.handle, crate::types::EngineEvent::ConnectionDropped { reason, answered: proven, age });
        }
        self.pump_rpc_events(now, registry, callbacks);
    }

    /// Requests that will get no answer: their queries go again, and a lost route check is asked anew.
    fn note_http_requests_lost(&mut self, lost: &[RequestMeta], now: Now) {
        let generation = self.rpc_generation;
        if let Some(rpc) = &mut self.rpc {
            for meta in lost {
                if let Some(seq) = meta.packet_seq.filter(|_| meta.generation == generation) {
                    rpc.http_packet_lost(seq, now);
                }
            }
        }
        if lost.iter().any(|meta| meta.probe)
            && let Some(http) = &mut self.http
        {
            http.route_check_nonce = None;
        }
    }

    /// The route check's answer: only the server's res_pq to our nonce clears the route; anything else
    /// means something on the way answers instead, and the session backs off like a refused route.
    fn on_http_route_check(
        &mut self,
        response: &HttpResponse,
        rtt_sample: Option<f64>,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> Result<(), Option<DropReason>> {
        let Some(http) = &mut self.http else {
            return Err(None);
        };
        let nonce = http.route_check_nonce.take();
        let answered = response.transport_error().is_none()
            && nonce.is_some_and(|nonce| super::is_res_pq_for(&response.body, &nonce));
        if answered {
            http.route_checked = true;
            http.route_check_needed = false;
            if let (Some(sample), Some(rpc)) = (rtt_sample, &mut self.rpc) {
                rpc.session_mut().note_rtt_sample(sample);
            }
            return Ok(());
        }
        if !http.route_check_needed {
            return Err(None);
        }
        self.rejections = self.rejections.saturating_add(1);
        let delay = mtproto_core::transport::transport_flood_delay(self.rejections).min(super::REJECTION_MAX_DELAY);
        http.hold_until = http.hold_until.max(now.mono + delay);
        http.next_open_at = http.next_open_at.max(now.mono + delay);
        self.log(
            callbacks,
            LogLevel::Info,
            &format!(
                "HTTP route check answered with status {} and {} bytes that are not the server's",
                response.status,
                response.body.len()
            ),
        );
        Err(Some(DropReason::AddressRejected))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_http_io(
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
        let Some(index) = self.http.as_ref().and_then(|http| http.index(token)) else {
            return false;
        };
        let mut events = Vec::new();
        let mut failure: Option<HttpConnError> = None;
        let mut more = false;
        if let Some(http) = &mut self.http {
            http.more_readable.retain(|other| *other != token);
            let conn = &mut http.conns[index];
            if writable {
                match conn.handle_writable(registry, now.mono) {
                    Ok(true) => events.push(HttpIo::Connected),
                    Ok(false) => {}
                    Err(error) => failure = Some(error),
                }
            }
            if readable && failure.is_none() {
                match conn.read(registry, scratch, HTTP_READ_BUDGET, now.mono, &mut events) {
                    Ok(budget_spent) => {
                        if budget_spent {
                            http.more_readable.push(token);
                            more = true;
                        }
                    }
                    Err(error) => failure = Some(error),
                }
            }
            if conn.response_in_progress().is_some()
                && let Some(rpc) = &mut self.rpc
            {
                rpc.session_mut().note_http_receiving(now);
            }
        }
        let mut events = events.into_iter();
        while let Some(event) = events.next() {
            match event {
                HttpIo::Connected => self.on_http_connected(token, now),
                HttpIo::Response { meta, response, waited } => {
                    if let Err(reason) =
                        self.on_http_response(token, meta, response, waited, registry, now, callbacks, rng)
                    {
                        let unread: Vec<RequestMeta> = events
                            .filter_map(|event| match event {
                                HttpIo::Response { meta, .. } => Some(meta),
                                HttpIo::Connected => None,
                            })
                            .collect();
                        self.note_http_requests_lost(&unread, now);
                        let report = reason.is_some();
                        self.fail_http_conn_token(
                            token,
                            reason.unwrap_or(DropReason::SessionError),
                            report,
                            registry,
                            now,
                            callbacks,
                        );
                        return false;
                    }
                }
            }
        }
        if let Some(error) = failure {
            if self.http.as_ref().and_then(|http| http.index(token)).is_none() {
                return false;
            }
            let reason = match &error {
                HttpConnError::Closed => DropReason::Closed,
                HttpConnError::Io(_) => DropReason::IoError,
                HttpConnError::Http(_) | HttpConnError::Socks(_) => DropReason::Protocol,
            };
            let quiet = matches!(error, HttpConnError::Closed)
                && self.http.as_ref().and_then(|http| http.index(token)).is_some_and(|index| {
                    let conn = &self.http.as_ref().expect("http").conns[index];
                    conn.in_flight_len() == 0
                });
            if !quiet {
                self.log(callbacks, LogLevel::Info, &format!("HTTP connection closed: {error}"));
            }
            self.fail_http_conn_token(token, reason, !quiet, registry, now, callbacks);
            return false;
        }
        self.pump_rpc_events(now, registry, callbacks);
        more || self.http.as_ref().is_some_and(|http| !http.more_readable.is_empty())
    }

    /// A 2xx answer to an encrypted request that is not a packet under the session's key: a captive
    /// portal's page, a proxy's, an empty body. The server never answers so; the route is checked before
    /// anything else goes, backing off like a refused route.
    fn on_http_foreign_answer(
        &mut self,
        meta: RequestMeta,
        response: &HttpResponse,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> DropReason {
        if let (Some(seq), Some(rpc)) = (meta.packet_seq, &mut self.rpc) {
            rpc.http_packet_lost(seq, now);
        }
        self.rejections = self.rejections.saturating_add(1);
        let delay = mtproto_core::transport::transport_flood_delay(self.rejections).min(super::REJECTION_MAX_DELAY);
        if let Some(http) = &mut self.http {
            http.route_checked = false;
            http.route_check_needed = true;
            http.hold_until = http.hold_until.max(now.mono + delay);
            http.next_open_at = http.next_open_at.max(now.mono + delay);
        }
        self.log(
            callbacks,
            LogLevel::Info,
            &format!(
                "HTTP status {} with {} bytes that are not the server's; checking the route",
                response.status,
                response.body.len()
            ),
        );
        DropReason::Protocol
    }

    /// A key creation failed: the next starts after the reconnect delay, as over TCP.
    fn note_http_handshake_failure(&mut self, now: Now) {
        self.failures = self.failures.saturating_add(1);
        let delay = self.reconnect_delay();
        if let Some(http) = &mut self.http {
            http.hold_until = http.hold_until.max(now.mono + delay);
            http.next_open_at = http.next_open_at.max(now.mono + delay);
        }
    }

    /// Hosts the HTTP transport connects to: the proxy, or the datacenter's addresses on their HTTP
    /// ports.
    pub(super) fn http_connects_to(&self, host: &str, port: u16) -> bool {
        match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { host: proxy_host, port: proxy_port, .. })
            | Some(ProxyConfig::Http { host: proxy_host, port: proxy_port, .. }) => {
                proxy_host == host && *proxy_port == port
            }
            Some(ProxyConfig::MtProxy { .. }) => false,
            None => self
                .http_candidates()
                .iter()
                .any(|(_, candidate, candidate_port)| candidate == host && *candidate_port == port),
        }
    }

    /// The handshake failed a step: the next one starts over, on whichever connection is free.
    fn abandon_http_handshake(&mut self) {
        self.handshake = None;
        self.handshake_started_at = None;
        self.pending_plain.clear();
        if let Some(http) = &mut self.http {
            http.handshake_token = None;
        }
    }

    /// An error status for a plain request: no key is involved, so it is the route that refuses (a
    /// captive portal, a proxy's deny page) or the server that asks to back off.
    fn on_http_handshake_error(
        &mut self,
        code: i32,
        status: u16,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) -> DropReason {
        self.log(callbacks, LogLevel::Warning, &format!("HTTP status {status} on a plain request"));
        let in_handshake = self.handshake.is_some();
        if in_handshake {
            self.on_transport_error_with(code, false, now, callbacks);
            self.close_reason = None;
        }
        self.abandon_http_handshake();
        let flood = TransportErrorKind::from_code(code) == TransportErrorKind::Flood;
        if !flood {
            self.rejections = self.rejections.saturating_add(1);
            let delay = mtproto_core::transport::transport_flood_delay(self.rejections).min(super::REJECTION_MAX_DELAY);
            self.next_attempt_at = self.next_attempt_at.max(now.mono + delay);
        } else if !in_handshake {
            self.transport_floods += 1;
            self.next_attempt_at = self
                .next_attempt_at
                .max(now.mono + mtproto_core::transport::transport_flood_delay(self.transport_floods));
        }
        let next = self.next_attempt_at;
        if let Some(http) = &mut self.http {
            http.next_open_at = http.next_open_at.max(next);
            http.hold_until = http.hold_until.max(next);
        }
        if flood { DropReason::TransportFlood } else { DropReason::HandshakeFailed }
    }

    fn on_http_connected(&mut self, token: Token, now: Now) {
        let proxied = self.setup.proxy.is_some();
        let Some(http) = &mut self.http else {
            return;
        };
        let Some(index) = http.index(token) else {
            return;
        };
        let conn = &http.conns[index];
        let connect = conn.established_at.unwrap_or(now.mono) - conn.started_at;
        if !proxied
            && connect > 0.0
            && let Some(rpc) = &mut self.rpc
        {
            rpc.session_mut().note_rtt_sample(connect);
        }
    }

    /// Err(Some(reason)) closes the connection and reports it; Err(None) closes it quietly.
    #[allow(clippy::too_many_arguments)]
    fn on_http_response(
        &mut self,
        token: Token,
        meta: RequestMeta,
        response: HttpResponse,
        waited: f64,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> Result<(), Option<DropReason>> {
        self.log(
            callbacks,
            LogLevel::Debug,
            &format!(
                "HTTP response {} for packet {:?} after {:.1} ms, {} bytes",
                response.status,
                meta.packet_seq,
                waited * 1000.0,
                response.body.len()
            ),
        );
        let candidate = self
            .http
            .as_ref()
            .and_then(|http| http.index(token))
            .map(|index| self.http.as_ref().expect("http").conns[index].address_index);
        if meta.probe {
            let sample = (waited > 0.0 && meta.generation == self.rpc_generation).then_some(waited);
            return self.on_http_route_check(&response, sample, now, callbacks);
        }
        let current = meta.generation == self.rpc_generation;
        if let Some(code) = response.transport_error() {
            if let Some(seq) = meta.packet_seq.filter(|_| current)
                && let Some(rpc) = &mut self.rpc
            {
                rpc.http_packet_lost(seq, now);
            }
            if meta.packet_seq.is_none() {
                return Err(Some(self.on_http_handshake_error(code, response.status, now, callbacks)));
            }
            if !current && code == -404 {
                return Err(None);
            }
            if code == -404 {
                let checked = self.http.as_ref().is_some_and(|http| http.route_checked);
                if let Some(http) = &mut self.http {
                    http.route_checked = false;
                    if !checked {
                        http.route_check_needed = true;
                        http.hold_until = http.hold_until.max(now.mono + 0.05);
                    }
                }
                if !checked {
                    self.log(callbacks, LogLevel::Info, "HTTP 404 on an unchecked route; asking for res_pq first");
                    return Err(None);
                }
            }
            self.log(
                callbacks,
                LogLevel::Warning,
                &format!("HTTP status {} (transport error {code})", response.status),
            );
            let proven = self.http.as_ref().is_some_and(|http| http.proven.contains(&token));
            self.on_transport_error_with(code, proven, now, callbacks);
            let reason = self.close_reason.take();
            let dropped = match reason {
                Some(CloseReason::ServerRejected) => DropReason::KeyInvalid,
                Some(CloseReason::KeyRejectionUnconfirmed) => DropReason::KeyRejectedOnce,
                Some(CloseReason::TransportFlood) => DropReason::TransportFlood,
                Some(CloseReason::HandshakeFailed) => DropReason::HandshakeFailed,
                _ => DropReason::AddressRejected,
            };
            if let Some(candidate) = candidate {
                let reachable = matches!(
                    reason,
                    Some(CloseReason::ServerRejected)
                        | Some(CloseReason::KeyRejectionUnconfirmed)
                        | Some(CloseReason::TransportFlood)
                );
                self.note_http_address(candidate, reachable, now);
            }
            let next = self.next_attempt_at;
            if let Some(http) = &mut self.http {
                http.next_open_at = http.next_open_at.max(next);
                http.hold_until = http.hold_until.max(next);
            }
            if matches!(reason, Some(CloseReason::ServerRejected) | Some(CloseReason::KeyRejectionUnconfirmed)) {
                callbacks.on_event(
                    self.handle,
                    crate::types::EngineEvent::ConnectionDropped { reason: dropped, answered: false, age: 0.0 },
                );
                self.close_http(registry, now);
                return Err(None);
            }
            return Err(Some(dropped));
        }
        let body_key = read_auth_key_id(&response.body);
        if meta.packet_seq.is_some() && current {
            let ours = self.rpc.as_ref().is_some_and(|rpc| body_key == Some(rpc.session().auth_key_id()));
            if !ours {
                return Err(Some(self.on_http_foreign_answer(meta, &response, now, callbacks)));
            }
        }
        if meta.packet_seq.is_none() && body_key != Some(0) {
            let code = -i32::from(response.status);
            return Err(Some(self.on_http_handshake_error(code, response.status, now, callbacks)));
        }
        if let Some(seq) = meta.packet_seq.filter(|_| meta.generation == self.rpc_generation) {
            if let Some(rpc) = &mut self.rpc {
                rpc.session_mut().http_packet_delivered(seq, now);
                let sample = if waited >= meta.max_wait { waited - meta.max_wait } else { waited };
                if meta.max_wait <= HTTP_SEND_WAIT && sample > 0.0 {
                    rpc.session_mut().note_rtt_sample(sample);
                }
            }
            if meta.bytes >= 16 * 1024 && waited > 0.0 && !meta.slot {
                let sample = meta.bytes as f64 / waited;
                if let Some(http) = &mut self.http {
                    http.uplink_rate =
                        Some(http.uplink_rate.map_or(sample, |rate| rate * 0.7 + sample.min(rate * 4.0) * 0.3));
                }
            }
        } else if waited > 0.0
            && current
            && let Some(rpc) = &mut self.rpc
        {
            rpc.session_mut().note_rtt_sample(waited);
        }
        let body = response.body;
        if body.is_empty() {
            return Ok(());
        }
        if read_auth_key_id(&body) == Some(0) {
            if self.handshake.is_none() {
                return Ok(());
            }
            return match self.on_handshake_packet(&body, now, callbacks, rng) {
                Ok(installed) => {
                    if installed && let Some(http) = &mut self.http {
                        http.open_failures = 0;
                        http.cut_in_a_row = 0;
                        http.handshake_token = None;
                    }
                    Ok(())
                }
                Err(_) => {
                    self.close_reason = None;
                    self.abandon_http_handshake();
                    self.note_http_handshake_failure(now);
                    Err(Some(DropReason::HandshakeFailed))
                }
            };
        }
        let Some(rpc) = &mut self.rpc else {
            return Ok(());
        };
        if read_auth_key_id(&body) != Some(rpc.session().auth_key_id()) {
            return Ok(());
        }
        let fresh_before = rpc.session().fresh_packets();
        let result = rpc.handle_packet(&body, now, rng);
        let fresh = rpc.session().fresh_packets() != fresh_before;
        match result {
            Ok(()) => {
                self.transport_floods = 0;
                self.rejections = 0;
                self.timeout_fired = false;
                if !self.network_available {
                    self.network_available = true;
                    self.log(
                        callbacks,
                        LogLevel::Info,
                        "received a packet while marked offline; treating the network as available",
                    );
                }
                if fresh && let Some(http) = &mut self.http {
                    http.route_check_needed = false;
                    http.open_failures = 0;
                    http.cut_in_a_row = 0;
                    let first_on_conn = !http.proven.contains(&token);
                    let named = http.named.iter().find(|(other, _)| *other == token).map(|(_, named)| named.clone());
                    if first_on_conn {
                        http.proven.push(token);
                    }
                    let first = !http.answered;
                    http.answered = true;
                    if first_on_conn && let Some((key, address)) = &named {
                        self.note_named_address_answered(key, *address);
                    }
                    if first_on_conn && let Some(candidate) = candidate {
                        self.reset_failures();
                        self.key_rejections = 0;
                        self.note_http_address(candidate, true, now);
                        if first {
                            self.log(callbacks, LogLevel::Info, "HTTP transport answered");
                        }
                    }
                }
                Ok(())
            }
            Err(SessionError::ForeignSession) | Err(SessionError::TooOld) | Err(SessionError::EvenServerMsgId(_)) => {
                Ok(())
            }
            Err(error) => {
                self.log(callbacks, LogLevel::Warning, &format!("session error on HTTP: {error}"));
                self.pump_rpc_events(now, registry, callbacks);
                Err(Some(DropReason::SessionError))
            }
        }
    }

    pub(super) fn http_deadline(&self, now: Now, config: &EngineConfig) -> Option<f64> {
        let http = self.http.as_ref()?;
        let mut deadline = f64::INFINITY;
        for conn in &http.conns {
            if let Some(at) = self.http_conn_deadline(conn, config) {
                deadline = deadline.min(at.max(now.mono));
            }
            if conn.is_ready() && conn.is_free() {
                for at in [conn.idle_since + HTTP_IDLE_CLOSE + 0.01, conn.idle_since + HTTP_SPARE_IDLE_AFTER + 0.01] {
                    if at > now.mono {
                        deadline = deadline.min(at);
                    }
                }
            }
            if conn.is_ready() && conn.unacknowledged_out().is_some_and(|bytes| bytes > 0) {
                deadline = deadline.min(now.mono + 0.25);
            }
        }
        if http.conns.is_empty() && self.wants_connection(now) && self.http_route_possible() {
            deadline = deadline.min(http.next_open_at.max(http.hold_until).max(now.mono));
        } else if http.next_open_at > now.mono {
            deadline = deadline.min(http.next_open_at);
        }
        if http.hold_until > now.mono {
            deadline = deadline.min(http.hold_until);
        }
        if let Some(started) = self.handshake_started_at {
            deadline = deadline.min(started + super::HANDSHAKE_TIMEOUT + 0.01);
        }
        deadline.is_finite().then_some(deadline)
    }
}

/// The wait for a new long poll, between a quarter of the period and the period: its expiry lands as
/// far as it can from every parked poll's, counted around the period since each poll is renewed when
/// it expires; the longest on a tie. `parked` holds the seconds left on each.
fn staggered_wait(parked: &[f64], period: f64) -> f64 {
    let around = |wait: f64, left: f64| {
        let apart = (wait - left).rem_euclid(period);
        apart.min(period - apart)
    };
    let distance = |wait: f64| parked.iter().map(|left| around(wait, *left)).fold(f64::INFINITY, f64::min);
    let steps = ((period * 0.75) / STAGGER_STEP).floor() as usize;
    (0..=steps)
        .map(|step| period - step as f64 * STAGGER_STEP)
        .fold(period, |best, wait| if distance(wait) > distance(best) + 0.01 { wait } else { best })
}

const STAGGER_STEP: f64 = 0.25;

/// Auto: how long a fresh TCP connection may stay silent, or how many TCP connections in a row may
/// fail, before an HTTP route is tried alongside.
pub const AUTO_HTTP_AFTER_SILENCE: f64 = 2.5;
/// Auto, when another session already moved to HTTP: how long TCP gets before HTTP is tried too.
pub const AUTO_HTTP_AFTER_HINT: f64 = 0.3;
pub const AUTO_HTTP_AFTER_FAILURES: u32 = 2;
pub const AUTO_PROBE_TIMEOUT: f64 = 6.0;
pub const AUTO_PROBE_RETRY_BASE: f64 = 5.0;
pub const AUTO_PROBE_RETRY_MAX: f64 = 60.0;
/// Auto on HTTP: TCP is tried again at most this rarely (`SessionSetup::tcp_recheck_after` doubles
/// after every try that failed).
pub const AUTO_TCP_RECHECK_MAX: f64 = 900.0;

#[derive(Default)]
pub(super) struct AutoState {
    probe: Option<HttpConn>,
    probe_named: Option<NamedAddress>,
    probe_nonce: [u8; 16],
    probe_failures: u32,
    probe_retry_at: f64,
    probe_cursor: usize,
    /// The session moved to HTTP on its own and goes back to TCP once a TCP route answers.
    pub(super) on_http: bool,
    tcp_recheck_at: f64,
    tcp_recheck_failures: u32,
    /// TCP replaced HTTP then; it has to answer before the recheck counts as a success.
    back_on_tcp_at: Option<f64>,
}

impl AutoState {
    pub(super) fn probe_token(&self) -> Option<Token> {
        self.probe.as_ref().map(HttpConn::token)
    }

    /// A lookup the HTTP probe waits for came back: the probe may go at once.
    pub(super) fn note_lookup_done(&mut self, now: f64) {
        if self.probe_failures == 0 {
            self.probe_retry_at = self.probe_retry_at.min(now);
        }
    }

    #[cfg(test)]
    pub(super) fn describe(&self, now: f64) -> String {
        format!(
            "auto(on_http {} probe {} probe_failures {} probe_retry {:+.2} recheck {:+.2} recheck_failures {} back_on_tcp {:?})",
            self.on_http,
            self.probe.is_some(),
            self.probe_failures,
            self.probe_retry_at - now,
            self.tcp_recheck_at - now,
            self.tcp_recheck_failures,
            self.back_on_tcp_at.map(|at| at - now)
        )
    }
}

fn recheck_interval(base: f64, failures: u32) -> f64 {
    (base * f64::from(1u32 << failures.min(8))).min(AUTO_TCP_RECHECK_MAX.max(base))
}

impl SessionRuntime {
    fn probe_http_token(&self) -> Token {
        Token(self.token.0 + HTTP_FIRST_TOKEN_OFFSET + HTTP_MAX_CONNECTIONS)
    }

    /// Opens a connection to HTTP candidate `choice` on `token`, through the SOCKS5 proxy if one is set.
    fn connect_http_candidate(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        choice: usize,
        token: Token,
    ) -> Result<Option<HttpConn>, ()> {
        let candidates = self.http_candidates();
        let Some((_, host, port)) = candidates.get(choice).cloned() else {
            return Err(());
        };
        let (connect_host, connect_port, socks) = match &self.setup.proxy {
            Some(ProxyConfig::Socks5 { host: proxy_host, port: proxy_port, username, password }) => {
                let target = match parse_literal(&host, port) {
                    Some(SocketAddr::V4(v4)) => Socks5Target::Ipv4(v4.ip().octets(), port),
                    Some(SocketAddr::V6(v6)) => Socks5Target::Ipv6(v6.ip().octets(), port),
                    None => Socks5Target::Domain(host.clone(), port),
                };
                let auth = match (username, password) {
                    (Some(username), Some(password)) if !username.is_empty() => {
                        Some(Socks5Auth { username: username.clone(), password: password.clone() })
                    }
                    _ => None,
                };
                (proxy_host.clone(), *proxy_port, Some((target, auth)))
            }
            Some(ProxyConfig::Http { host: proxy_host, port: proxy_port, .. }) => {
                (proxy_host.clone(), *proxy_port, None)
            }
            Some(ProxyConfig::MtProxy { .. }) => return Err(()),
            None => (host.clone(), port, None),
        };
        let mut named = None;
        let socket_address = match parse_literal(&connect_host, connect_port) {
            Some(address) => address,
            None => match self.resolve_cached(&connect_host, connect_port, resolver, now) {
                Resolution::Resolved(addresses) if !addresses.is_empty() => {
                    let key = (connect_host.clone(), connect_port);
                    let address = self.pick_named_address(&key, &addresses);
                    named = Some((key, address));
                    address
                }
                Resolution::Resolved(_) => return Err(()),
                Resolution::Pending => return Ok(None),
            },
        };
        let route = self.http_route(&host, port);
        match HttpConn::connect(registry, token, socket_address, route, socks, choice, now.mono) {
            Ok(conn) => {
                self.auto.probe_named = named;
                Ok(Some(conn))
            }
            Err(_) => {
                if let Some((key, address)) = named {
                    self.note_named_address_failed(key, address);
                }
                Err(())
            }
        }
    }

    /// Auto on TCP: tries an HTTP route alongside once TCP gets nowhere.
    pub(super) fn maybe_probe_http(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        rng: &mut OsRandom,
    ) {
        if self.setup.transport != crate::types::TransportPreference::Auto
            || self.http.is_some()
            || self.auto.probe.is_some()
            || now.mono < self.auto.probe_retry_at
            || !self.wants_connection(now)
            || matches!(self.setup.proxy, Some(ProxyConfig::MtProxy { .. }))
        {
            return;
        }
        let silence = if self.hints.http_likely(now.mono) { AUTO_HTTP_AFTER_HINT } else { AUTO_HTTP_AFTER_SILENCE };
        let answering = self.connection.as_ref().is_some_and(|connection| connection.heard_from_server);
        let struggling = !answering
            && (self.failures >= AUTO_HTTP_AFTER_FAILURES
                || self.connection.as_ref().is_some_and(|connection| now.mono - connection.started_at >= silence));
        if !struggling {
            return;
        }
        let candidates = self.http_candidates().len();
        if candidates == 0 {
            return;
        }
        let choice = self.auto.probe_cursor % candidates;
        self.auto.probe_cursor = choice + 1;
        let token = self.probe_http_token();
        let mut conn = match self.connect_http_candidate(registry, now, resolver, choice, token) {
            Ok(Some(conn)) => conn,
            Ok(None) => {
                self.auto.probe_retry_at = now.mono + super::RESOLVE_WAIT;
                return;
            }
            Err(()) => {
                self.fail_http_probe(registry, now);
                return;
            }
        };
        let nonce: [u8; 16] = rng.array();
        let mut writer = mtproto_core::tl::Writer::with_capacity(24);
        mtproto_core::tl::TlWrite::write_to(&mtproto_core::tl::mtproto::ReqPqMulti { nonce }, &mut writer);
        let msg_id = mtproto_core::msg_id::msg_id_for_time(now.unix + self.time_difference()) & !3;
        let packet = mtproto_core::message::encode_plain_message(msg_id, &writer.into_inner());
        let meta = RequestMeta {
            packet_seq: None,
            max_wait: 0.0,
            slot: false,
            queued_at: now.mono,
            bytes: 0,
            probe: false,
            generation: self.rpc_generation,
        };
        if conn.submit(registry, &packet, meta, now.mono).is_err() {
            conn.deregister(registry);
            self.fail_http_probe(registry, now);
            return;
        }
        self.auto.probe_nonce = nonce;
        self.auto.probe = Some(conn);
    }

    fn fail_http_probe(&mut self, registry: &Registry, now: Now) {
        let named = self.auto.probe_named.take();
        if let Some(mut probe) = self.auto.probe.take() {
            if probe.responses == 0
                && let Some((key, address)) = named
            {
                self.note_named_address_failed(key, address);
            }
            self.reported_in += probe.bytes_in;
            self.reported_out += probe.bytes_out;
            probe.deregister(registry);
        }
        self.auto.probe_failures = self.auto.probe_failures.saturating_add(1);
        let backoff = AUTO_PROBE_RETRY_BASE * f64::from(1u32 << self.auto.probe_failures.saturating_sub(1).min(8));
        self.auto.probe_retry_at = now.mono + backoff.min(AUTO_PROBE_RETRY_MAX);
    }

    pub(super) fn cancel_http_probe(&mut self, registry: &Registry) {
        if let Some(mut probe) = self.auto.probe.take() {
            self.reported_in += probe.bytes_in;
            self.reported_out += probe.bytes_out;
            probe.deregister(registry);
        }
        self.auto.probe_failures = 0;
        self.auto.probe_retry_at = 0.0;
    }

    pub(super) fn expire_http_probe(&mut self, registry: &Registry, now: Now) {
        if self.auto.probe.as_ref().is_some_and(|probe| now.mono - probe.started_at > AUTO_PROBE_TIMEOUT) {
            self.fail_http_probe(registry, now);
        }
    }

    pub(super) fn auto_deadline(&self, now: Now) -> Option<f64> {
        if let Some(probe) = &self.auto.probe {
            return Some(probe.started_at + AUTO_PROBE_TIMEOUT + 0.01);
        }
        if self.setup.transport != crate::types::TransportPreference::Auto {
            return None;
        }
        if !self.auto.on_http && !self.http_route_possible() {
            return None;
        }
        if self.auto.on_http {
            return self.wants_connection(now).then(|| self.auto.tcp_recheck_at.max(self.racer_retry_at));
        }
        if self.http.is_none()
            && let Some(connection) = &self.connection
            && !connection.heard_from_server
        {
            let silence = if self.hints.http_likely(now.mono) { AUTO_HTTP_AFTER_HINT } else { AUTO_HTTP_AFTER_SILENCE };
            return Some((connection.started_at + silence).max(self.auto.probe_retry_at) + 0.01);
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_http_probe_io(
        &mut self,
        readable: bool,
        writable: bool,
        registry: &Registry,
        scratch: &mut [u8],
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) {
        let Some(probe) = &mut self.auto.probe else {
            return;
        };
        let mut events = Vec::new();
        let mut failed = false;
        if writable && probe.handle_writable(registry, now.mono).is_err() {
            failed = true;
        }
        if readable && !failed && probe.read(registry, scratch, HTTP_READ_BUDGET, now.mono, &mut events).is_err() {
            failed = true;
        }
        let nonce = self.auto.probe_nonce;
        for event in events {
            if let HttpIo::Response { response, .. } = event {
                if response.status == 200 && super::is_res_pq_for(&response.body, &nonce) {
                    self.adopt_http_probe(registry, now, callbacks);
                    return;
                }
                failed = true;
            }
        }
        if failed {
            self.fail_http_probe(registry, now);
        }
    }

    fn adopt_http_probe(&mut self, registry: &Registry, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        let Some(probe) = self.auto.probe.take() else {
            return;
        };
        self.log(callbacks, LogLevel::Info, "TCP gets no answer but HTTP does; moving to HTTP");
        if self.connection.is_some() {
            self.report_drop(DropReason::TransportSwitch, now, callbacks);
        }
        self.enter_http(registry, now);
        let named = self.auto.probe_named.take();
        if let Some(http) = &mut self.http {
            if let Some(named) = named {
                http.named.push((probe.token(), named));
            }
            http.conns.push(probe);
            http.route_checked = true;
        }
        self.auto.on_http = true;
        self.hints.note_http_needed(now.mono);
        self.auto.probe_failures = 0;
        self.auto.back_on_tcp_at = None;
        self.auto.tcp_recheck_at =
            now.mono + recheck_interval(self.setup.tcp_recheck_after, self.auto.tcp_recheck_failures);
        self.reset_failures();
        self.flaps = 0;
        self.next_attempt_at = now.mono;
    }

    /// Auto on HTTP: when due, races a fresh TCP connection whose answer to a plain req_pq moves the
    /// session back.
    pub(super) fn maybe_recheck_tcp(
        &mut self,
        registry: &Registry,
        now: Now,
        resolver: &mut dyn Resolve,
        rng: &mut OsRandom,
    ) {
        if !self.auto.on_http
            || self.racer.is_some()
            || now.mono < self.auto.tcp_recheck_at
            || !self.wants_connection(now)
        {
            return;
        }
        let next = self.best_address(None).unwrap_or(self.address_cursor);
        let super::Pick::Ready(index, socket_address, address) = self.pick_address_at(next, resolver, now) else {
            self.auto.tcp_recheck_at = now.mono + super::RESOLVE_RETRY_MAX;
            return;
        };
        let socks = self.tunnel_for(&address);
        let transport = mtproto_core::transport::TransportConfig {
            framing: self.setup.framing,
            dc_id: self.setup.obfuscation_dc_id,
            secret: self.setup.proxy_secret(&address),
            unix_time: (now.unix + self.time_difference()) as i32,
        };
        let token = self.free_token();
        match crate::connection::Connection::connect(
            registry,
            token,
            socket_address,
            &transport,
            socks,
            index,
            now.mono,
            rng,
        ) {
            Ok(racer) => {
                self.racer = Some(racer);
                self.racer_check = Some(super::RacerCheck { nonce: rng.array(), sent: false, promote_at: None });
                self.auto.tcp_recheck_at =
                    now.mono + recheck_interval(self.setup.tcp_recheck_after, self.auto.tcp_recheck_failures);
            }
            Err(_) => self.note_tcp_recheck_failed(now),
        }
    }

    pub(super) fn note_tcp_recheck_failed(&mut self, now: Now) {
        self.auto.tcp_recheck_failures = self.auto.tcp_recheck_failures.saturating_add(1);
        self.auto.tcp_recheck_at =
            now.mono + recheck_interval(self.setup.tcp_recheck_after, self.auto.tcp_recheck_failures);
    }

    /// The TCP recheck answered: the session leaves HTTP, and the verified connection takes over.
    pub(super) fn switch_back_to_tcp(&mut self, registry: &Registry, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        self.log(callbacks, LogLevel::Info, "a TCP route answers again; leaving HTTP");
        self.hints.note_tcp_answered(now.mono);
        self.leave_http(registry, now);
        self.auto.on_http = false;
        self.auto.back_on_tcp_at = Some(now.mono);
        self.reset_failures();
    }

    /// Auto back on TCP: a connection that answers settles it; one that fails first sends the session
    /// back to HTTP at once and makes the next recheck wait longer.
    pub(super) fn settle_back_on_tcp(&mut self, now: Now) {
        let Some(since) = self.auto.back_on_tcp_at else {
            return;
        };
        if self.connection.as_ref().is_some_and(|connection| connection.heard_from_server) {
            self.auto.back_on_tcp_at = None;
            self.auto.tcp_recheck_failures = 0;
            return;
        }
        if self.failures > 0 || now.mono - since > AUTO_HTTP_AFTER_SILENCE {
            self.auto.back_on_tcp_at = None;
            self.note_tcp_recheck_failed(now);
            self.auto.probe_retry_at = now.mono;
            self.auto.probe_failures = 0;
        }
    }

    /// A new network or route: whatever was learned about TCP there is void.
    pub(super) fn reset_auto(&mut self, registry: &Registry, now: Now, new_network: bool) {
        if new_network {
            self.hints.forget();
        }
        self.cancel_http_probe(registry);
        self.auto.tcp_recheck_failures = 0;
        self.auto.back_on_tcp_at = None;
        if self.auto.on_http {
            self.auto.on_http = false;
            self.leave_http(registry, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::staggered_wait;

    #[test]
    fn long_polls_are_spread_over_the_period() {
        assert_eq!(staggered_wait(&[], 10.0), 10.0);
        assert_eq!(staggered_wait(&[10.0], 10.0), 5.0);
        assert_eq!(staggered_wait(&[2.0], 10.0), 7.0);
        assert_eq!(staggered_wait(&[5.0], 10.0), 10.0);
        assert!(staggered_wait(&[25.0], 10.0) <= 10.0, "never longer than the period");
        let third = staggered_wait(&[5.0, 10.0], 10.0);
        assert!((third - 5.0).abs() > 1.0 && (third - 10.0).abs() > 1.0, "a third poll lands between: {third}");
    }
}
