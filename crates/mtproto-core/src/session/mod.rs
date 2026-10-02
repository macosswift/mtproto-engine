mod dedupe;
mod salts;

use std::collections::{HashMap, HashSet, VecDeque};

pub use dedupe::{DuplicateCheck, DuplicateChecker};
pub use salts::{SALT_SAFETY_MARGIN, SINGLE_SALT_LIFETIME, SaltState, ServerSalt};

use crate::auth_key::AuthKey;
use crate::crypto::{SecureRandom, Side, aes_ige_decrypt, message_key_v2};
use crate::message::{MessageError, MessageHeader, PaddingPolicy, decrypt_message, encrypt_message, read_auth_key_id};
use crate::msg_id::{MSG_ID_MAX_FUTURE_SECONDS, MSG_ID_MAX_PAST_SECONDS, msg_id_for_time, msg_id_time};
use crate::tl::mtproto::{self as tlm, ContainerMessage, FutureSalt, RpcResultBody, ServiceMessage};
use crate::tl::{Reader, TlError, Writer, ids};

pub const ACK_DELAY: f64 = 30.0;
pub const MAX_PENDING_ACKS: usize = 100;
pub const QUERY_DELAY: f64 = 0.001;
pub const FUTURE_SALTS_RETRY: f64 = 60.0;
pub const FUTURE_SALTS_COUNT: i32 = 64;
pub const MAX_IDS_PER_SERVICE_MESSAGE: usize = 8192;
pub const STATE_REQUEST_RETRY: f64 = 20.0;
pub const DEFAULT_CONTAINER_BYTES: usize = 1 << 15;
pub const DEFAULT_CONTAINER_QUERIES: usize = 1000;
pub const MAX_RECENT_QUICK_ACKS: usize = 256;
pub const MAX_QUEUED_ACKS: usize = 2 * MAX_IDS_PER_SERVICE_MESSAGE;
pub const MAX_QUEUED_SERVICE_REPLIES: usize = 64;
pub const MAX_PENDING_PINGS: usize = 16;
pub const MAX_TRACKED_SERVICE_CONTAINERS: usize = 64;
pub const RECENT_SENT_CAPACITY: usize = 1024;
pub const MAX_PROTOCOL_STRIKES: u32 = 3;
pub const MAX_ANSWER_REQUESTS: u32 = 3;
pub const MAX_NESTING_DEPTH: usize = 8;
pub const MAX_AWAITED_ANSWERS: usize = 1024;
pub const MAX_MESSAGES_PER_PACKET: usize = 4 * 1024;
pub const MAX_CONTAINER_MESSAGES_OUT: usize = 1024;
pub const CONTAINER_RESERVED_SLOTS: usize = 2;
pub const MAX_UNPACKED_PER_PACKET: usize = 64 * 1024 * 1024;
pub const CLOCK_JUMP_THRESHOLD: f64 = 1.0;
pub const RESPONSE_TIME_SKEW: i64 = 15i64 << 32;
pub const UNKNOWN_QUERIES_STUCK_AFTER: f64 = 60.0;
pub const RETRANSMIT_WINDOW: f64 = MSG_ID_MAX_PAST_SECONDS - 60.0;
pub const DROPPED_ANSWER_COUNTED_SIZE: usize = 16 * 1024;
pub const IMMEDIATE_ACK_SIZE: usize = 16 * 1024;
pub const PROBE_TIMEOUT_MIN: f64 = 1.0;
pub const PROBE_TIMEOUT_MAX: f64 = 8.0;
pub const PROBE_TIMEOUT_INITIAL: f64 = 4.0;
pub const PROBE_BACKOFF_MAX: f64 = 4.0;
pub const BACKLOG_SAMPLE_INTERVAL: f64 = 0.25;
pub const DROPPED_ANSWER_LIMIT: usize = 8 * 1024 * 1024;
pub const DROPPED_ANSWER_WINDOW: f64 = 10.0;
pub const RESPONSE_UNPACK_FAILED: &str = "RESPONSE_UNPACK_FAILED";
pub const PROTOCOL_ERROR_PREFIX: &str = "PROTOCOL_ERROR_BAD_MSG_";
pub const PROTOCOL_REJECTED: &str = "PROTOCOL_ERROR_REJECTED";
pub const MAX_QUERY_REJECTIONS: u32 = 12;
pub const MAX_SERVER_RESENDS: u32 = 8;
pub const TRANSMIT_GRACE_MIN_SIZE: usize = 4 * 1024;
pub const RESET_DRAIN_MIN: f64 = 1.0;
pub const RESET_DRAIN_MAX: f64 = 5.0;
pub const TRANSMIT_GRACE_RATE: f64 = 8.0 * 1024.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Now {
    pub mono: f64,
    pub unix: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueryId(pub u64);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryOptions {
    pub quick_ack: bool,
    pub invoke_after: Option<QueryId>,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub is_main: bool,
    pub padding: PaddingPolicy,
    pub max_container_bytes: usize,
    pub max_container_queries: usize,
    pub use_ping_delay_disconnect: bool,
    pub max_unpacked_bytes: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            is_main: true,
            padding: PaddingPolicy::default(),
            max_container_bytes: DEFAULT_CONTAINER_BYTES,
            max_container_queries: DEFAULT_CONTAINER_QUERIES,
            use_ping_delay_disconnect: true,
            max_unpacked_bytes: MAX_UNPACKED_PER_PACKET,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionEvent {
    Result { id: QueryId, body: Vec<u8>, response_msg_id: i64, original_size: usize },
    Error { id: QueryId, code: i32, message: String, response_msg_id: i64 },
    Acknowledged { id: QueryId },
    Update { body: Vec<u8>, msg_id: i64 },
    UpdatesLost,
    ServerSessionReset { unique_id: i64, first_msg_id: i64 },
    LocalSessionReset { previous_session_id: i64 },
    TimeDifferenceUpdated { difference: f64, forced: bool },
    SaltsUpdated { salts: Vec<ServerSalt> },
    Pong { rtt: f64 },
    DroppedAnswerTooLarge { total: usize },
    DestroyAuthKey { outcome: DestroyAuthKeyOutcome },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyAuthKeyOutcome {
    Ok,
    None,
    Fail,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("decryption failed: {0}")]
    Decrypt(#[from] MessageError),
    #[error("malformed packet: {0}")]
    Malformed(#[from] TlError),
    #[error("packet from foreign session")]
    ForeignSession,
    #[error("server msg_id {0:#x} has even parity")]
    EvenServerMsgId(i64),
    #[error("message is too old to be processed")]
    TooOld,
    #[error("ping timeout")]
    PingTimeout,
    #[error("read timeout")]
    ReadTimeout,
    #[error("probe timeout: no reply to a ping and the transport made no progress")]
    ProbeTimeout,
    #[error("server reported a fatal session error {0}")]
    BadMessage(i32),
    #[error("too many dropped answers")]
    TooManyDroppedAnswers,
    #[error("no state information received for unknown queries")]
    UnknownQueriesStuck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    NotFound,
    Removed,
    RemovedInFlight { msg_id: i64 },
}

#[derive(Debug, Clone)]
pub struct Transmit {
    pub data: Vec<u8>,
    pub quick_ack_token: Option<u32>,
    pub msg_id: i64,
    pub contains_queries: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryState {
    Pending,
    Sent,
    Unknown,
}

#[derive(Debug, Clone)]
struct Query {
    body: Vec<u8>,
    options: QueryOptions,
    state: QueryState,
    msg_id: i64,
    seq_no: i32,
    container_id: i64,
    invoke_after_msg_id: i64,
    acknowledged: bool,
    ack_reported: bool,
    sent_at: f64,
    connection_epoch: u64,
    protocol_strikes: u32,
    rejections: u32,
    server_resends: u32,
    may_have_arrived: bool,
    retransmit_refused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Salt,
    Other,
}

#[derive(Debug, Clone)]
enum ServiceRequest {
    StateRequest { msg_ids: Vec<i64>, sent_at: f64 },
    ResendRequest { msg_ids: Vec<i64>, sent_at: f64 },
}

impl ServiceRequest {
    fn sent_at(&self) -> f64 {
        match self {
            ServiceRequest::StateRequest { sent_at, .. } | ServiceRequest::ResendRequest { sent_at, .. } => *sent_at,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AwaitedAnswer {
    query: Option<QueryId>,
    requests: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Process,
    Replay,
    AckOnly,
}

impl Mode {
    fn combine(self, child: Mode) -> Mode {
        match (self, child) {
            (_, Mode::AckOnly) | (Mode::AckOnly, _) => Mode::AckOnly,
            (Mode::Replay, _) | (_, Mode::Replay) => Mode::Replay,
            _ => Mode::Process,
        }
    }
}

struct PacketContext {
    mode: Mode,
    budget: usize,
    messages: usize,
    deferred_resends: Vec<(QueryId, i64)>,
    updates_lost: bool,
    unknown_queries_stuck: bool,
    structure_error: Option<TlError>,
}

impl PacketContext {
    fn new(mode: Mode, budget: usize) -> Self {
        Self {
            mode,
            budget,
            messages: 0,
            deferred_resends: Vec::new(),
            updates_lost: false,
            unknown_queries_stuck: false,
            structure_error: None,
        }
    }
}

pub struct Session {
    config: SessionConfig,
    auth_key: AuthKey,
    session_id: i64,
    salts: SaltState,
    server_offset: f64,
    wall_offset: f64,
    time_difference: f64,
    time_synchronized: bool,
    last_msg_id: i64,
    seq_no: i32,

    queries: HashMap<QueryId, Query>,
    pending_queries: usize,
    unknown_queries: usize,
    pending: VecDeque<QueryId>,
    by_msg_id: HashMap<i64, QueryId>,
    containers: HashMap<i64, Vec<i64>>,
    quick_acks: VecDeque<(u32, Vec<QueryId>)>,

    to_ack: Vec<i64>,
    to_resend_answer: Vec<i64>,
    to_state_request: Vec<i64>,
    to_drop_answer: Vec<i64>,
    to_state_info_reply: Vec<(i64, Vec<u8>)>,
    to_pong: Vec<(i64, i64)>,
    to_retransmit: Vec<QueryId>,
    service_requests: HashMap<i64, ServiceRequest>,
    service_containers: VecDeque<(i64, Vec<i64>)>,
    future_salts_requests: VecDeque<i64>,
    awaited_answers: HashMap<i64, AwaitedAnswer>,
    resend_individually: HashSet<i64>,
    recent_sent: VecDeque<i64>,
    recent_unique_ids: VecDeque<i64>,
    force_send_at: Option<f64>,

    received: DuplicateChecker,
    updates: DuplicateChecker,

    connected: bool,
    connection_epoch: u64,
    connected_at: f64,
    online: bool,
    was_busy: bool,
    random_delay: f64,
    rtt: f64,
    rtt_var: f64,
    rtt_peak: f64,
    last_read_at: f64,
    last_pong_at: f64,
    last_ping_at: Option<f64>,
    last_ping_msg_id: i64,
    last_ping_container_id: i64,
    pending_pings: HashMap<i64, f64>,
    outbound_backlog: Option<usize>,
    outbound_progress_at: f64,
    backlog_sampled_at: f64,
    probe_episode: Option<f64>,
    probe_drained: bool,
    probe_backoff: f64,
    received_on_connection: bool,
    fresh_packets: u64,
    transmit_grace_until: f64,
    last_future_salts_at: Option<f64>,
    unknown_since: Option<f64>,
    dropped_answer_bytes: usize,
    dropped_answer_window_start: f64,

    need_destroy_auth_key: bool,
    sent_destroy_auth_key: bool,
    pending_reset: bool,
    drain_reset_at: Option<f64>,

    events: VecDeque<SessionEvent>,
}

impl Session {
    pub fn new(
        config: SessionConfig,
        auth_key: AuthKey,
        salts: &[ServerSalt],
        time_difference: f64,
        now: Now,
        rng: &mut impl SecureRandom,
    ) -> Self {
        let server_time = now.unix + time_difference;
        let random_delay = (rng.next_u32() % 5_000_000) as f64 * 1e-6;
        Self {
            config,
            auth_key,
            session_id: rng.next_u64() as i64,
            salts: SaltState::from_salts(salts, server_time),
            server_offset: server_time - now.mono,
            wall_offset: now.unix - now.mono,
            time_difference,
            time_synchronized: false,
            last_msg_id: 0,
            seq_no: 0,
            queries: HashMap::new(),
            pending_queries: 0,
            unknown_queries: 0,
            pending: VecDeque::new(),
            by_msg_id: HashMap::new(),
            containers: HashMap::new(),
            quick_acks: VecDeque::new(),
            to_ack: Vec::new(),
            to_resend_answer: Vec::new(),
            to_state_request: Vec::new(),
            to_drop_answer: Vec::new(),
            to_state_info_reply: Vec::new(),
            to_pong: Vec::new(),
            to_retransmit: Vec::new(),
            service_requests: HashMap::new(),
            service_containers: VecDeque::new(),
            future_salts_requests: VecDeque::new(),
            awaited_answers: HashMap::new(),
            resend_individually: HashSet::new(),
            recent_sent: VecDeque::new(),
            recent_unique_ids: VecDeque::new(),
            force_send_at: None,
            received: DuplicateChecker::new(1000),
            updates: DuplicateChecker::new(1000),
            connected: false,
            connection_epoch: 0,
            connected_at: now.mono,
            online: false,
            was_busy: false,
            random_delay,
            rtt: 0.0,
            rtt_var: 0.0,
            rtt_peak: 0.0,
            last_read_at: now.mono,
            last_pong_at: now.mono,
            last_ping_at: None,
            last_ping_msg_id: 0,
            last_ping_container_id: 0,
            pending_pings: HashMap::new(),
            outbound_backlog: None,
            outbound_progress_at: now.mono,
            backlog_sampled_at: now.mono,
            probe_episode: None,
            probe_drained: false,
            probe_backoff: 1.0,
            received_on_connection: false,
            fresh_packets: 0,
            transmit_grace_until: 0.0,
            last_future_salts_at: None,
            unknown_since: None,
            dropped_answer_bytes: 0,
            dropped_answer_window_start: now.mono,
            need_destroy_auth_key: false,
            sent_destroy_auth_key: false,
            pending_reset: false,
            drain_reset_at: None,
            events: VecDeque::new(),
        }
    }

    pub fn session_id(&self) -> i64 {
        self.session_id
    }

    pub fn auth_key(&self) -> &AuthKey {
        &self.auth_key
    }

    pub fn auth_key_id(&self) -> u64 {
        self.auth_key.id()
    }

    pub fn time_difference(&self) -> f64 {
        self.time_difference
    }

    pub fn salts(&self) -> Vec<ServerSalt> {
        self.salts.all()
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn has_queries(&self) -> bool {
        !self.queries.is_empty()
    }

    pub fn query_count(&self) -> usize {
        self.queries.len()
    }

    pub fn has_unanswered_queries(&self) -> bool {
        self.queries.len() > self.pending_queries
    }

    pub fn has_unknown_queries(&self) -> bool {
        self.unknown_queries > 0
    }

    fn awaits_old_session_answers(&self) -> bool {
        self.queries.len() > self.pending_queries + self.unknown_queries
    }

    fn finish_drain_reset(&mut self, now: Now, rng: &mut impl SecureRandom) -> bool {
        let Some(at) = self.drain_reset_at else {
            return false;
        };
        if now.mono < at && self.awaits_old_session_answers() {
            return false;
        }
        self.drain_reset_at = None;
        self.reset(rng);
        self.send_before(now.mono);
        true
    }

    fn count_transition(pending: &mut usize, unknown: &mut usize, from: Option<QueryState>, to: Option<QueryState>) {
        match from {
            Some(QueryState::Pending) => *pending -= 1,
            Some(QueryState::Unknown) => *unknown -= 1,
            _ => {}
        }
        match to {
            Some(QueryState::Pending) => *pending += 1,
            Some(QueryState::Unknown) => *unknown += 1,
            _ => {}
        }
    }

    #[cfg(debug_assertions)]
    fn debug_check_counts(&self) {
        let pending = self.queries.values().filter(|query| query.state == QueryState::Pending).count();
        let unknown = self.queries.values().filter(|query| query.state == QueryState::Unknown).count();
        assert_eq!(pending, self.pending_queries, "pending query count");
        assert_eq!(unknown, self.unknown_queries, "unknown query count");
    }

    #[cfg(not(debug_assertions))]
    fn debug_check_counts(&self) {}

    pub fn is_performing_service_tasks(&self) -> bool {
        self.has_unknown_queries() || !self.service_requests.is_empty() || !self.to_resend_answer.is_empty()
    }

    pub fn is_awaiting_responses(&self) -> bool {
        self.has_unanswered_queries()
            || !self.service_requests.is_empty()
            || !self.to_state_request.is_empty()
            || !self.to_resend_answer.is_empty()
    }

    pub fn query_msg_id(&self, id: QueryId) -> Option<i64> {
        self.queries.get(&id).filter(|query| query.state != QueryState::Pending).map(|query| query.msg_id)
    }

    pub fn contains(&self, id: QueryId) -> bool {
        self.queries.contains_key(&id)
    }

    pub fn set_online(&mut self, online: bool, now: Now) {
        let need_ping = online || !self.online;
        self.online = online;
        if need_ping {
            self.last_pong_at = now.mono - self.ping_disconnect_delay() + self.rtt_estimate();
            self.last_read_at = now.mono - self.read_disconnect_delay() + self.rtt_estimate();
        } else {
            self.last_pong_at = now.mono;
            self.last_read_at = now.mono;
        }
        self.last_ping_at = None;
        self.last_ping_msg_id = 0;
        self.last_ping_container_id = 0;
    }

    pub fn set_time_difference(&mut self, difference: f64) {
        self.time_difference = difference;
        self.server_offset = difference + self.wall_offset;
    }

    pub fn replace_auth_key(&mut self, auth_key: AuthKey, salts: &[ServerSalt], now: Now) {
        if auth_key.id() != self.auth_key.id() {
            self.auth_key = auth_key;
            self.salts = SaltState::from_salts(salts, self.server_time(now));
        }
    }

    pub fn merge_salts(&mut self, salts: &[ServerSalt], now: Now) {
        let server_time = self.server_time(now);
        let future: Vec<ServerSalt> = salts.iter().copied().filter(|salt| salt.valid_until > server_time).collect();
        if !future.is_empty() {
            self.salts.set_future(future, server_time);
        }
    }

    pub fn destroy_auth_key(&mut self, now: Now) {
        self.need_destroy_auth_key = true;
        self.sent_destroy_auth_key = false;
        self.send_before(now.mono);
    }

    pub fn request_destroy_auth_key(&mut self) {
        self.need_destroy_auth_key = true;
    }

    pub fn smoothed_rtt(&self) -> Option<f64> {
        (self.rtt > 0.0).then_some(self.rtt)
    }

    pub fn probe_timeout(&self) -> f64 {
        let base = if self.rtt == 0.0 {
            PROBE_TIMEOUT_INITIAL
        } else {
            ((self.rtt + 4.0 * self.rtt_var).max(self.rtt_peak * 1.5) + 0.25)
                .clamp(PROBE_TIMEOUT_MIN, PROBE_TIMEOUT_MAX)
        };
        base * self.probe_backoff
    }

    pub fn unanswered_ping_since(&self) -> Option<f64> {
        self.pending_pings.values().copied().filter(|sent| *sent >= self.last_read_at).reduce(f64::min)
    }

    pub fn wants_outbound_backlog(&self) -> bool {
        self.connected && self.unanswered_ping_since().is_some()
    }

    pub fn note_outbound_backlog(&mut self, backlog: Option<usize>, now: Now) {
        let episode = self.unanswered_ping_since();
        if episode != self.probe_episode {
            self.probe_episode = episode;
            self.probe_drained = backlog == Some(0);
            self.outbound_progress_at = now.mono;
        } else if !self.probe_drained {
            match (self.outbound_backlog, backlog) {
                (_, Some(0)) => {
                    self.probe_drained = true;
                    self.outbound_progress_at = now.mono;
                }
                (Some(previous), Some(current)) if current < previous => self.outbound_progress_at = now.mono,
                (None, Some(_)) => self.outbound_progress_at = now.mono,
                _ => {}
            }
        }
        self.outbound_backlog = backlog;
        self.backlog_sampled_at = now.mono;
    }

    fn probe_deadline(&self) -> Option<f64> {
        self.outbound_backlog?;
        let since = self.unanswered_ping_since()?;
        Some(since.max(self.outbound_progress_at) + self.probe_timeout())
    }

    pub fn fresh_packets(&self) -> u64 {
        self.fresh_packets
    }

    pub fn note_bytes_received(&mut self, now: Now) {
        if self.connected {
            self.last_read_at = self.last_read_at.max(now.mono);
        }
    }

    fn server_time(&self, now: Now) -> f64 {
        now.mono + self.server_offset
    }

    fn sync_wall_clock(&mut self, now: Now) {
        let wall_offset = now.unix - now.mono;
        if (wall_offset - self.wall_offset).abs() > CLOCK_JUMP_THRESHOLD {
            self.wall_offset = wall_offset;
            let difference = self.server_time(now) - now.unix;
            self.time_difference = difference;
            self.events.push_back(SessionEvent::TimeDifferenceUpdated { difference, forced: true });
        }
    }

    fn rtt_estimate(&self) -> f64 {
        (self.rtt * 1.5 + 1.0).max(2.0)
    }

    fn uses_fast_liveness(&self) -> bool {
        self.online || self.was_busy
    }

    pub fn read_disconnect_delay(&self) -> f64 {
        if self.uses_fast_liveness() { self.rtt_estimate() * 3.5 } else { 135.0 + self.random_delay }
    }

    pub fn ping_disconnect_delay(&self) -> f64 {
        if self.online && self.config.is_main { self.rtt_estimate() * 2.5 } else { 135.0 + self.random_delay }
    }

    fn ping_may_delay(&self) -> f64 {
        if self.uses_fast_liveness() { self.rtt_estimate() * 0.5 } else { 30.0 + self.random_delay }
    }

    fn ping_must_delay(&self) -> f64 {
        if self.uses_fast_liveness() { self.rtt_estimate() } else { 60.0 + self.random_delay }
    }

    fn liveness_at(&self) -> f64 {
        self.last_pong_at.max(self.last_read_at)
    }

    fn refresh_busy(&mut self, now: Now) {
        let busy = self.is_awaiting_responses();
        if busy && !self.was_busy {
            self.last_read_at = self.last_read_at.max(now.mono);
        }
        self.was_busy = busy;
    }

    fn next_msg_id(&mut self, now: Now, rng: &mut impl SecureRandom) -> i64 {
        let server_time = self.server_time(now);
        let random = rng.next_u32();
        let base = msg_id_for_time(server_time) ^ (random & ((1 << 22) - 1)) as i64;
        let mut id = base & !3;
        if id & 0xffff_ffff == 0 {
            id += 4;
        }
        if id <= self.last_msg_id {
            id = self.last_msg_id.saturating_add(8 * (((random >> 22) & 1023) as i64 + 1)) & !3;
        }
        self.last_msg_id = id;
        id
    }

    fn next_seq_no(&mut self, content_related: bool) -> i32 {
        let seq_no = self.seq_no;
        if content_related {
            self.seq_no += 2;
            seq_no | 1
        } else {
            seq_no
        }
    }

    fn send_before(&mut self, at: f64) {
        self.force_send_at = Some(match self.force_send_at {
            Some(existing) if existing <= at => existing,
            _ => at,
        });
    }

    pub fn send(&mut self, id: QueryId, body: Vec<u8>, options: QueryOptions, now: Now) {
        debug_assert!(body.len().is_multiple_of(4), "query body must be 4-byte aligned");
        if self.queries.contains_key(&id) {
            return;
        }
        self.queries.insert(
            id,
            Query {
                body,
                options,
                state: QueryState::Pending,
                msg_id: 0,
                seq_no: 0,
                container_id: 0,
                invoke_after_msg_id: 0,
                acknowledged: false,
                ack_reported: false,
                sent_at: 0.0,
                connection_epoch: 0,
                protocol_strikes: 0,
                rejections: 0,
                server_resends: 0,
                may_have_arrived: false,
                retransmit_refused: false,
            },
        );
        self.pending_queries += 1;
        self.pending.push_back(id);
        self.send_before(now.mono + QUERY_DELAY);
    }

    pub fn cancel(&mut self, id: QueryId) -> CancelOutcome {
        let Some(query) = self.queries.remove(&id) else {
            return CancelOutcome::NotFound;
        };
        Self::count_transition(&mut self.pending_queries, &mut self.unknown_queries, Some(query.state), None);
        self.to_retransmit.retain(|other| *other != id);
        match query.state {
            QueryState::Pending => {
                self.pending.retain(|pending| *pending != id);
                CancelOutcome::Removed
            }
            QueryState::Sent | QueryState::Unknown => {
                self.by_msg_id.remove(&query.msg_id);
                self.detach_from_container(query.container_id, query.msg_id);
                self.refresh_unknown_tracking();
                CancelOutcome::RemovedInFlight { msg_id: query.msg_id }
            }
        }
    }

    pub fn drop_answer(&mut self, msg_id: i64, now: Now) {
        if !self.to_drop_answer.contains(&msg_id) {
            self.to_drop_answer.push(msg_id);
        }
        self.send_before(now.mono);
    }

    pub fn connection_opened(&mut self, now: Now) {
        self.sync_wall_clock(now);
        self.connected = true;
        self.received_on_connection = false;
        self.connection_epoch += 1;
        self.connected_at = now.mono;
        self.last_read_at = now.mono;
        self.last_pong_at = now.mono;
        self.last_ping_at = None;
        self.last_ping_msg_id = 0;
        self.last_ping_container_id = 0;
        self.pending_pings.clear();
        self.quick_acks.clear();
        let server_time = self.server_time(now);
        let mut retransmit = Vec::new();
        let mut unknown = Vec::new();
        for (id, query) in &self.queries {
            if query.state != QueryState::Unknown {
                continue;
            }
            if !query.retransmit_refused && server_time - msg_id_time(query.msg_id) < RETRANSMIT_WINDOW {
                retransmit.push((query.msg_id, *id));
            } else {
                unknown.push(query.msg_id);
            }
        }
        retransmit.sort_unstable();
        for (_, id) in retransmit {
            if !self.to_retransmit.contains(&id) {
                self.to_retransmit.push(id);
            }
            self.send_before(now.mono);
        }
        if !unknown.is_empty() {
            self.to_state_request.extend(unknown);
            self.unknown_since.get_or_insert(now.mono);
            self.send_before(now.mono);
        }
        let queued: HashSet<i64> = self.to_resend_answer.iter().copied().collect();
        let awaited: Vec<i64> =
            self.awaited_answers.keys().copied().filter(|answer| !queued.contains(answer)).collect();
        self.to_resend_answer.extend(awaited);
        if !self.pending.is_empty() || !self.to_ack.is_empty() || !self.to_resend_answer.is_empty() {
            self.send_before(now.mono);
        }
        self.was_busy = false;
        self.refresh_busy(now);
    }

    pub fn connection_closed(&mut self) {
        if !self.connected {
            return;
        }
        self.connected = false;
        let epoch = self.connection_epoch;
        for query in self.queries.values_mut() {
            if query.state == QueryState::Sent && !query.acknowledged && query.connection_epoch == epoch {
                query.state = QueryState::Unknown;
                self.unknown_queries += 1;
                query.may_have_arrived = true;
            }
        }
        self.to_state_request.clear();
        self.service_requests.clear();
        self.service_containers.clear();
        self.future_salts_requests.clear();
        self.last_future_salts_at = None;
        self.quick_acks.clear();
        self.pending_pings.clear();
        self.to_pong.clear();
        self.to_retransmit.clear();
        self.to_resend_answer.clear();
        self.outbound_backlog = None;
        self.probe_episode = None;
        self.probe_drained = false;
        self.transmit_grace_until = 0.0;
    }

    pub fn connection_rejected(&mut self, now: Now) {
        if !self.connected {
            return;
        }
        let epoch = self.connection_epoch;
        let mut rejected: Vec<(i64, QueryId)> = self
            .queries
            .iter()
            .filter(|(_, query)| {
                query.state == QueryState::Sent
                    && !query.acknowledged
                    && !query.may_have_arrived
                    && query.connection_epoch == epoch
            })
            .map(|(id, query)| (query.msg_id, *id))
            .collect();
        rejected.sort_unstable();
        self.connection_closed();
        for (_, id) in rejected {
            self.resend_query(id, now);
        }
        self.refresh_unknown_tracking();
    }

    pub fn reset(&mut self, rng: &mut impl SecureRandom) {
        self.drain_reset_at = None;
        let previous_session_id = self.session_id;
        self.session_id = rng.next_u64() as i64;
        self.seq_no = 0;
        self.last_msg_id = 0;
        self.by_msg_id.clear();
        self.containers.clear();
        self.quick_acks.clear();
        self.to_ack.clear();
        self.to_resend_answer.clear();
        self.to_state_request.clear();
        self.to_drop_answer.clear();
        self.to_state_info_reply.clear();
        self.to_pong.clear();
        self.to_retransmit.clear();
        self.service_requests.clear();
        self.service_containers.clear();
        self.future_salts_requests.clear();
        self.awaited_answers.clear();
        self.resend_individually.clear();
        self.recent_sent.clear();
        self.recent_unique_ids.clear();
        self.pending_pings.clear();
        self.received.clear();
        self.updates.clear();
        self.unknown_since = None;
        self.last_ping_at = None;
        self.last_ping_msg_id = 0;
        self.last_ping_container_id = 0;
        self.last_future_salts_at = None;
        let mut resend: Vec<(i64, QueryId)> = self
            .queries
            .iter()
            .filter(|(_, query)| query.state != QueryState::Pending)
            .map(|(id, query)| (query.msg_id, *id))
            .collect();
        resend.sort_unstable();
        for (_, id) in resend.into_iter().rev() {
            self.requeue_front(id);
        }
        self.events.push_back(SessionEvent::LocalSessionReset { previous_session_id });
    }

    fn detach_from_container(&mut self, container_id: i64, msg_id: i64) {
        if container_id == 0 {
            return;
        }
        if let Some(children) = self.containers.get_mut(&container_id) {
            children.retain(|child| *child != msg_id);
            if children.is_empty() {
                self.containers.remove(&container_id);
            }
        }
    }

    fn release_query_message(&mut self, id: QueryId) -> Option<(i64, i64)> {
        let query = self.queries.get_mut(&id)?;
        if query.state == QueryState::Pending {
            return None;
        }
        let released = (query.msg_id, query.container_id);
        Self::count_transition(
            &mut self.pending_queries,
            &mut self.unknown_queries,
            Some(query.state),
            Some(QueryState::Pending),
        );
        query.state = QueryState::Pending;
        query.msg_id = 0;
        query.container_id = 0;
        query.invoke_after_msg_id = 0;
        query.acknowledged = false;
        query.may_have_arrived = false;
        query.retransmit_refused = false;
        self.by_msg_id.remove(&released.0);
        self.detach_from_container(released.1, released.0);
        self.to_retransmit.retain(|other| *other != id);
        Some(released)
    }

    fn requeue_front(&mut self, id: QueryId) {
        if self.release_query_message(id).is_some() {
            self.pending.push_front(id);
        }
    }

    fn resend_query(&mut self, id: QueryId, now: Now) {
        let Some(msg_id) =
            self.queries.get(&id).filter(|query| query.state != QueryState::Pending).map(|query| query.msg_id)
        else {
            return;
        };
        let position = self
            .pending
            .iter()
            .position(|other| self.queries.get(other).is_some_and(|other| other.msg_id > msg_id))
            .unwrap_or(self.pending.len());
        if self.release_query_message(id).is_some() {
            self.pending.insert(position.min(self.pending.len()), id);
            self.send_before(now.mono);
        }
    }

    fn was_sent_recently(&self, msg_id: i64, now: Now) -> bool {
        self.was_sent(msg_id) && msg_id_time(msg_id) >= self.server_time(now) - MSG_ID_MAX_PAST_SECONDS
    }

    fn was_sent(&self, msg_id: i64) -> bool {
        self.by_msg_id.contains_key(&msg_id)
            || self.containers.contains_key(&msg_id)
            || self.service_requests.contains_key(&msg_id)
            || self.pending_pings.contains_key(&msg_id)
            || self.future_salts_requests.contains(&msg_id)
            || self.service_containers.iter().any(|(container, _)| *container == msg_id)
            || self.recent_sent.contains(&msg_id)
    }

    fn remember_sent(&mut self, msg_id: i64) {
        self.recent_sent.push_back(msg_id);
        while self.recent_sent.len() > RECENT_SENT_CAPACITY {
            self.recent_sent.pop_front();
        }
    }

    fn affected_queries(&self, msg_id: i64) -> Vec<QueryId> {
        let mut targets = vec![msg_id];
        if let Some(children) = self.containers.get(&msg_id) {
            targets.extend(children.iter().copied());
        }
        targets.iter().filter_map(|target| self.by_msg_id.get(target).copied()).collect()
    }

    fn query_failed(&mut self, id: QueryId, kind: FailureKind, now: Now) {
        let Some(query) = self.queries.get_mut(&id).filter(|query| query.state != QueryState::Pending) else {
            return;
        };
        query.rejections += 1;
        if query.rejections > MAX_QUERY_REJECTIONS {
            let msg_id = query.msg_id;
            self.complete_query(id, msg_id);
            self.events.push_back(SessionEvent::Error {
                id,
                code: 500,
                message: PROTOCOL_REJECTED.to_string(),
                response_msg_id: 0,
            });
            return;
        }
        if !query.may_have_arrived {
            self.resend_query(id, now);
            return;
        }
        match kind {
            FailureKind::Salt => {
                if !self.to_retransmit.contains(&id) {
                    self.to_retransmit.push(id);
                }
            }
            FailureKind::Other => {
                if query.state != QueryState::Unknown {
                    self.unknown_queries += 1;
                }
                query.state = QueryState::Unknown;
                query.retransmit_refused = true;
                let msg_id = query.msg_id;
                if !self.to_state_request.contains(&msg_id) {
                    self.to_state_request.push(msg_id);
                }
                self.unknown_since.get_or_insert(now.mono);
            }
        }
        self.send_before(now.mono);
    }

    fn message_failed(&mut self, msg_id: i64, kind: FailureKind, now: Now) {
        if msg_id == self.last_ping_msg_id || msg_id == self.last_ping_container_id {
            self.last_ping_at = None;
            self.last_ping_msg_id = 0;
            self.last_ping_container_id = 0;
        }
        self.sent_destroy_auth_key = false;
        let mut targets = vec![msg_id];
        if let Some(children) = self.containers.remove(&msg_id) {
            targets.extend(children);
        }
        if let Some(position) = self.service_containers.iter().position(|(container, _)| *container == msg_id)
            && let Some((_, children)) = self.service_containers.remove(position)
        {
            targets.extend(children);
        }
        for target in targets {
            if let Some(id) = self.by_msg_id.get(&target).copied() {
                self.query_failed(id, kind, now);
            }
            if let Some(service) = self.service_requests.remove(&target) {
                match service {
                    ServiceRequest::StateRequest { msg_ids, .. } => {
                        self.to_state_request.extend(msg_ids);
                    }
                    ServiceRequest::ResendRequest { msg_ids, .. } => {
                        for id in msg_ids {
                            if !self.to_resend_answer.contains(&id) {
                                self.to_resend_answer.push(id);
                            }
                        }
                    }
                }
                self.send_before(now.mono);
            }
            if self.pending_pings.remove(&target).is_some() {
                self.last_ping_at = None;
            }
            if self.future_salts_requests.contains(&target) {
                self.last_future_salts_at = None;
            }
        }
    }

    fn strike_and_fail(&mut self, bad_msg_id: i64, code: i32, response_msg_id: i64) {
        for id in self.affected_queries(bad_msg_id) {
            let exhausted = match self.queries.get_mut(&id) {
                Some(query) => {
                    query.protocol_strikes += 1;
                    query.protocol_strikes >= MAX_PROTOCOL_STRIKES
                }
                None => false,
            };
            if exhausted && let Some(msg_id) = self.query_msg_id(id) {
                self.complete_query(id, msg_id);
                self.events.push_back(SessionEvent::Error {
                    id,
                    code: 500,
                    message: format!("{PROTOCOL_ERROR_PREFIX}{code}"),
                    response_msg_id,
                });
            }
        }
    }

    fn acknowledge(&mut self, msg_id: i64) {
        let mut targets = vec![msg_id];
        if let Some(children) = self.containers.get(&msg_id) {
            targets.extend(children.iter().copied());
        }
        for target in targets {
            if let Some(id) = self.by_msg_id.get(&target).copied() {
                self.mark_acknowledged(id);
            }
        }
    }

    fn mark_acknowledged(&mut self, id: QueryId) {
        if let Some(query) = self.queries.get_mut(&id) {
            if query.state == QueryState::Pending {
                return;
            }
            if query.state == QueryState::Unknown {
                query.state = QueryState::Sent;
                self.unknown_queries -= 1;
            }
            query.acknowledged = true;
            query.rejections = 0;
            if !query.ack_reported {
                query.ack_reported = true;
                self.events.push_back(SessionEvent::Acknowledged { id });
            }
        }
        self.refresh_unknown_tracking();
    }

    fn refresh_unknown_tracking(&mut self) {
        if !self.has_unknown_queries() {
            self.unknown_since = None;
        }
    }

    pub fn handle_quick_ack(&mut self, token: u32) {
        let token = token & 0x7fff_ffff;
        if let Some(position) = self.quick_acks.iter().position(|(stored, _)| *stored == token) {
            let (_, ids) = self.quick_acks.remove(position).expect("position is valid");
            for id in ids {
                self.mark_acknowledged(id);
            }
        }
    }

    fn schedule_ack(&mut self, msg_id: i64, now: Now) {
        if self.to_ack.is_empty() {
            self.send_before(now.mono + ACK_DELAY);
        }
        if self.to_ack.last() != Some(&msg_id) {
            self.to_ack.push(msg_id);
            if self.to_ack.len() > MAX_QUEUED_ACKS {
                let excess = self.to_ack.len() - MAX_QUEUED_ACKS;
                self.to_ack.drain(..excess);
            }
            if self.to_ack.len() >= MAX_PENDING_ACKS {
                self.send_before(now.mono);
            }
        }
    }

    pub fn force_ack(&mut self, now: Now) {
        if !self.to_ack.is_empty() {
            self.send_before(now.mono);
        }
    }

    pub fn progress_target(&self, head: &[u8]) -> Option<QueryId> {
        if head.len() < 24 + 48 || read_auth_key_id(head)? != self.auth_key.id() {
            return None;
        }
        let msg_key: [u8; 16] = head[8..24].try_into().ok()?;
        let material = message_key_v2(self.auth_key.bytes(), &msg_key, Side::Server);
        let usable = (head.len() - 24) / 16 * 16;
        let mut plain = head[24..24 + usable].to_vec();
        aes_ige_decrypt(&material.key, &material.iv, &mut plain).ok()?;
        let mut reader = Reader::new(&plain[32..]);
        let mut constructor = reader.read_u32().ok()?;
        if constructor == ids::MSG_CONTAINER {
            reader.read_i32().ok()?;
            reader.skip(16).ok()?;
            constructor = reader.read_u32().ok()?;
        }
        if constructor != ids::RPC_RESULT {
            return None;
        }
        let req_msg_id = reader.read_i64().ok()?;
        self.by_msg_id.get(&req_msg_id).copied()
    }

    pub fn handle_packet(&mut self, packet: &[u8], now: Now, rng: &mut impl SecureRandom) -> Result<(), SessionError> {
        let decrypted = decrypt_message(&self.auth_key, packet, Side::Server)?;
        let header = decrypted.header;
        if header.session_id != self.session_id {
            return Err(SessionError::ForeignSession);
        }
        if header.msg_id & 1 == 0 {
            return Err(SessionError::EvenServerMsgId(header.msg_id));
        }
        self.sync_wall_clock(now);
        let body = decrypted.body();
        let mode = match self.received.peek(header.msg_id) {
            DuplicateCheck::New => Mode::Process,
            DuplicateCheck::Duplicate => Mode::AckOnly,
            DuplicateCheck::TooOld => Mode::Replay,
        };
        let mut budget = self.config.max_unpacked_bytes;
        if mode != Mode::AckOnly {
            self.observe_server_time(header.msg_id, now);
            if !self.is_within_time_window(header.msg_id, now) {
                if !self.has_freshness_proof(body, 0, &mut budget, &mut 0, now) {
                    return Ok(());
                }
                self.reset_server_time(header.msg_id, now);
            }
            self.received.check(header.msg_id);
        }
        if mode == Mode::Process {
            self.last_read_at = now.mono;
            self.last_pong_at = now.mono;
            self.received_on_connection = true;
            self.fresh_packets += 1;
        }
        let mut context = PacketContext::new(mode, budget);
        self.process_message(&mut context, header.msg_id, header.seq_no, body, 0, now);
        self.finish_packet(context, now, rng)
    }

    fn finish_packet(
        &mut self,
        context: PacketContext,
        now: Now,
        rng: &mut impl SecureRandom,
    ) -> Result<(), SessionError> {
        if context.updates_lost {
            self.events.push_back(SessionEvent::UpdatesLost);
        }
        for (id, msg_id) in context.deferred_resends {
            if self.queries.get(&id).is_some_and(|query| query.state != QueryState::Pending && query.msg_id == msg_id) {
                self.resend_query(id, now);
            }
        }
        if self.pending_reset {
            self.pending_reset = false;
            self.reset(rng);
            self.send_before(now.mono);
        }
        self.finish_drain_reset(now, rng);
        if self.to_ack.len() >= MAX_PENDING_ACKS {
            self.send_before(now.mono);
        }
        self.refresh_busy(now);
        if let Some(error) = context.structure_error {
            return Err(SessionError::Malformed(error));
        }
        if context.unknown_queries_stuck {
            return Err(SessionError::UnknownQueriesStuck);
        }
        Ok(())
    }

    fn is_within_time_window(&self, msg_id: i64, now: Now) -> bool {
        if !self.time_synchronized {
            return true;
        }
        let server_time = self.server_time(now);
        let message_time = msg_id_time(msg_id);
        message_time >= server_time - MSG_ID_MAX_PAST_SECONDS && message_time <= server_time + MSG_ID_MAX_FUTURE_SECONDS
    }

    fn has_freshness_proof(
        &self,
        body: &[u8],
        depth: usize,
        budget: &mut usize,
        visited: &mut usize,
        now: Now,
    ) -> bool {
        *visited += 1;
        if depth > MAX_NESTING_DEPTH || *visited > MAX_MESSAGES_PER_PACKET {
            return false;
        }
        match ServiceMessage::parse(body) {
            Ok(ServiceMessage::Container(children)) => {
                children.iter().any(|child| self.has_freshness_proof(child.body, depth + 1, budget, visited, now))
            }
            Ok(ServiceMessage::GzipPacked(packed)) => tlm::gunzip_within(packed, budget)
                .map(|unpacked| self.has_freshness_proof(&unpacked, depth + 1, budget, visited, now))
                .unwrap_or(false),
            Ok(ServiceMessage::MsgCopy(inner)) => self.has_freshness_proof(inner.body, depth + 1, budget, visited, now),
            Ok(ServiceMessage::RpcResult { req_msg_id, .. }) => self.by_msg_id.contains_key(&req_msg_id),
            Ok(ServiceMessage::Pong { msg_id, ping_id }) => {
                self.pending_pings.contains_key(&msg_id) || self.pending_pings.contains_key(&ping_id)
            }
            Ok(ServiceMessage::BadMsgNotification { bad_msg_id, .. })
            | Ok(ServiceMessage::BadServerSalt { bad_msg_id, .. }) => self.was_sent_recently(bad_msg_id, now),
            Ok(ServiceMessage::MsgsStateInfo { req_msg_id, .. }) => self.service_requests.contains_key(&req_msg_id),
            Ok(ServiceMessage::FutureSalts { req_msg_id, .. }) => self.future_salts_requests.contains(&req_msg_id),
            Ok(ServiceMessage::MsgDetailedInfo { msg_id, .. }) => self.by_msg_id.contains_key(&msg_id),
            Ok(ServiceMessage::NewSessionCreated { first_msg_id, .. }) => self.was_sent_recently(first_msg_id, now),
            _ => false,
        }
    }

    fn observe_server_time(&mut self, msg_id: i64, now: Now) {
        let seconds = (msg_id >> 32) as f64;
        let offset = seconds - now.mono;
        if !self.time_synchronized || self.server_offset + 1e-4 < offset {
            self.time_synchronized = true;
            self.server_offset = offset;
            self.time_difference = seconds - now.unix;
            self.events
                .push_back(SessionEvent::TimeDifferenceUpdated { difference: self.time_difference, forced: false });
        }
    }

    fn reset_server_time(&mut self, msg_id: i64, now: Now) {
        let seconds = (msg_id >> 32) as f64;
        self.time_synchronized = false;
        self.server_offset = seconds - now.mono;
        self.time_difference = seconds - now.unix;
        self.events.push_back(SessionEvent::TimeDifferenceUpdated { difference: self.time_difference, forced: true });
    }

    fn note_awaited_answer(&mut self, msg_id: i64) {
        if self.awaited_answers.remove(&msg_id).is_none() {
            return;
        }
        self.to_resend_answer.retain(|id| *id != msg_id);
        let mut finished = Vec::new();
        for (request_id, request) in self.service_requests.iter_mut() {
            if let ServiceRequest::ResendRequest { msg_ids, .. } = request {
                msg_ids.retain(|id| *id != msg_id);
                if msg_ids.is_empty() {
                    finished.push(*request_id);
                }
            }
        }
        for request_id in finished {
            self.service_requests.remove(&request_id);
        }
    }

    fn process_message(
        &mut self,
        context: &mut PacketContext,
        msg_id: i64,
        seq_no: i32,
        body: &[u8],
        depth: usize,
        now: Now,
    ) {
        context.messages += 1;
        if context.messages > MAX_MESSAGES_PER_PACKET {
            return;
        }
        if seq_no & 1 == 1 {
            self.schedule_ack(msg_id, now);
            if body.len() >= IMMEDIATE_ACK_SIZE {
                self.send_before(now.mono);
            }
        }
        if context.mode != Mode::AckOnly {
            self.note_awaited_answer(msg_id);
        }
        if body.len() < 4 || depth > MAX_NESTING_DEPTH {
            return;
        }
        let message = match ServiceMessage::parse(body) {
            Ok(message) => message,
            Err(error) => {
                let constructor = u32::from_le_bytes(body[..4].try_into().expect("4 bytes"));
                if depth == 0 && constructor == ids::MSG_CONTAINER {
                    context.structure_error = Some(error);
                }
                return;
            }
        };
        if context.mode == Mode::AckOnly {
            match message {
                ServiceMessage::Container(children) => {
                    for child in children {
                        if child.msg_id & 1 == 1 {
                            self.process_message(context, child.msg_id, child.seqno, child.body, depth + 1, now);
                        }
                    }
                }
                ServiceMessage::GzipPacked(packed) => {
                    if let Ok(unpacked) = tlm::gunzip_within(packed, &mut context.budget) {
                        self.process_message(context, msg_id, seq_no & !1, &unpacked, depth + 1, now);
                    }
                }
                ServiceMessage::MsgCopy(inner) if inner.msg_id & 1 == 1 => {
                    self.process_message(context, inner.msg_id, inner.seqno, inner.body, depth + 1, now);
                }
                _ => {}
            }
            return;
        }
        if context.mode == Mode::Replay && !Self::replay_may_act(&message) {
            return;
        }
        match message {
            ServiceMessage::Container(children) => {
                for child in children {
                    self.process_child(context, child, depth + 1, now);
                }
            }
            ServiceMessage::MsgCopy(inner) => self.process_child(context, inner, depth + 1, now),
            ServiceMessage::GzipPacked(packed) => {
                if let Ok(unpacked) = tlm::gunzip_within(packed, &mut context.budget) {
                    self.process_message(context, msg_id, seq_no & !1, &unpacked, depth + 1, now);
                }
            }
            ServiceMessage::RpcResult { req_msg_id, result } => {
                self.on_rpc_result(context, msg_id, req_msg_id, result, body.len(), now);
            }
            ServiceMessage::Pong { msg_id: ping_msg_id, ping_id } => {
                self.on_pong(context, msg_id, ping_msg_id, ping_id, now);
            }
            ServiceMessage::Ping { ping_id } => {
                if self.to_pong.len() < MAX_QUEUED_SERVICE_REPLIES {
                    self.to_pong.push((msg_id, ping_id));
                }
                self.send_before(now.mono);
            }
            ServiceMessage::BadServerSalt { bad_msg_id, new_server_salt, .. } => {
                if !self.was_sent(bad_msg_id) {
                    return;
                }
                let server_time = self.server_time(now);
                self.salts.set_server_salt(new_server_salt, server_time);
                self.events.push_back(SessionEvent::SaltsUpdated { salts: self.salts.all() });
                self.last_future_salts_at = None;
                self.message_failed(bad_msg_id, FailureKind::Salt, now);
            }
            ServiceMessage::BadMsgNotification { bad_msg_id, error_code, .. } => {
                self.on_bad_msg_notification(msg_id, bad_msg_id, error_code, now)
            }
            ServiceMessage::NewSessionCreated { first_msg_id, unique_id, server_salt } => {
                self.on_new_session_created(context, unique_id, first_msg_id, server_salt, now)
            }
            ServiceMessage::MsgsAck(msg_ids) => {
                for acked in msg_ids {
                    self.acknowledge(acked);
                }
            }
            ServiceMessage::MsgDetailedInfo { msg_id: query_msg_id, answer_msg_id, status, .. } => {
                self.on_message_info(Some(query_msg_id), status, Some(answer_msg_id).filter(|id| *id != 0), now);
            }
            ServiceMessage::MsgNewDetailedInfo { answer_msg_id, .. } => {
                self.on_message_info(None, 0, Some(answer_msg_id).filter(|id| *id != 0), now);
            }
            ServiceMessage::MsgsStateInfo { req_msg_id, info } => match self.service_requests.remove(&req_msg_id) {
                Some(ServiceRequest::StateRequest { msg_ids, .. }) => self.on_state_info(&msg_ids, info, now),
                Some(ServiceRequest::ResendRequest { msg_ids, .. }) => self.on_answers_unavailable(&msg_ids, now),
                None => {}
            },
            ServiceMessage::MsgsAllInfo { msg_ids, info } => {
                self.on_state_info(&msg_ids, info, now);
            }
            ServiceMessage::MsgsStateReq(msg_ids) => {
                let info: Vec<u8> = msg_ids.iter().map(|id| self.received_state(*id)).collect();
                self.queue_state_info_reply(msg_id, info, now);
            }
            ServiceMessage::MsgResendReq(msg_ids) => self.on_server_resend_request(msg_id, &msg_ids, now),
            ServiceMessage::MsgResendAnsReq(msg_ids) => {
                self.queue_state_info_reply(msg_id, vec![1; msg_ids.len()], now);
            }
            ServiceMessage::FutureSalts { req_msg_id, salts, .. } => {
                if let Some(position) = self.future_salts_requests.iter().position(|request| *request == req_msg_id) {
                    self.future_salts_requests.remove(position);
                    self.on_future_salts(&salts, now);
                }
            }
            ServiceMessage::DestroySessionOk { .. } | ServiceMessage::DestroySessionNone { .. } => {}
            ServiceMessage::DestroyAuthKeyOk => self.on_destroy_auth_key(DestroyAuthKeyOutcome::Ok),
            ServiceMessage::DestroyAuthKeyNone => self.on_destroy_auth_key(DestroyAuthKeyOutcome::None),
            ServiceMessage::DestroyAuthKeyFail => self.on_destroy_auth_key(DestroyAuthKeyOutcome::Fail),
            ServiceMessage::HttpWait { .. } | ServiceMessage::Ignored { .. } => {}
            ServiceMessage::Other { body, .. } => {
                if context.mode == Mode::Replay {
                    context.updates_lost = true;
                    return;
                }
                match self.updates.check(msg_id) {
                    DuplicateCheck::New => self.events.push_back(SessionEvent::Update { body: body.to_vec(), msg_id }),
                    DuplicateCheck::Duplicate => {}
                    DuplicateCheck::TooOld => context.updates_lost = true,
                }
            }
        }
    }

    fn replay_may_act(message: &ServiceMessage<'_>) -> bool {
        matches!(
            message,
            ServiceMessage::Container(_)
                | ServiceMessage::MsgCopy(_)
                | ServiceMessage::GzipPacked(_)
                | ServiceMessage::RpcResult { .. }
                | ServiceMessage::Pong { .. }
                | ServiceMessage::MsgsStateInfo { .. }
                | ServiceMessage::FutureSalts { .. }
                | ServiceMessage::Other { .. }
        )
    }

    fn process_child(&mut self, context: &mut PacketContext, child: ContainerMessage<'_>, depth: usize, now: Now) {
        if child.msg_id & 1 == 0 {
            return;
        }
        let child_mode = match self.received.check(child.msg_id) {
            DuplicateCheck::New => Mode::Process,
            DuplicateCheck::Duplicate => Mode::AckOnly,
            DuplicateCheck::TooOld => Mode::Replay,
        };
        let parent_mode = context.mode;
        context.mode = parent_mode.combine(child_mode);
        self.process_message(context, child.msg_id, child.seqno, child.body, depth, now);
        context.mode = parent_mode;
    }

    fn received_state(&self, msg_id: i64) -> u8 {
        if self.received.contains(msg_id) {
            return 4;
        }
        match (self.received.oldest(), self.received.newest()) {
            (Some(oldest), _) if msg_id < oldest => 1,
            (_, Some(newest)) if msg_id > newest => 3,
            (Some(_), Some(_)) => 2,
            _ => 1,
        }
    }

    fn queue_state_info_reply(&mut self, req_msg_id: i64, info: Vec<u8>, now: Now) {
        if self.to_state_info_reply.len() < MAX_QUEUED_SERVICE_REPLIES {
            self.to_state_info_reply.push((req_msg_id, info));
        }
        self.send_before(now.mono);
    }

    fn on_server_resend_request(&mut self, request_msg_id: i64, msg_ids: &[i64], now: Now) {
        let mut any_unknown = false;
        let mut info = Vec::with_capacity(msg_ids.len());
        for msg_id in msg_ids {
            let known = self
                .by_msg_id
                .get(msg_id)
                .copied()
                .filter(|id| self.queries.get(id).is_some_and(|query| query.state != QueryState::Pending));
            match known {
                Some(id) => {
                    let allowed = self.queries.get_mut(&id).is_some_and(|query| {
                        query.server_resends += 1;
                        query.server_resends <= MAX_SERVER_RESENDS
                    });
                    if allowed && !self.to_retransmit.contains(&id) {
                        self.to_retransmit.push(id);
                    }
                    info.push(4);
                }
                None => {
                    any_unknown = true;
                    info.push(1);
                }
            }
        }
        if any_unknown {
            self.queue_state_info_reply(request_msg_id, info, now);
        }
        self.send_before(now.mono);
    }

    fn on_bad_msg_notification(&mut self, msg_id: i64, bad_msg_id: i64, error_code: i32, now: Now) {
        if !self.was_sent(bad_msg_id) {
            return;
        }
        match error_code {
            16 => {
                self.reset_server_time(msg_id, now);
                self.message_failed(bad_msg_id, FailureKind::Other, now);
            }
            17 => {
                self.reset_server_time(msg_id, now);
                self.message_failed(bad_msg_id, FailureKind::Other, now);
                if self.drain_reset_at.is_none() {
                    let grace = self.rtt_estimate().clamp(RESET_DRAIN_MIN, RESET_DRAIN_MAX);
                    self.drain_reset_at = Some(now.mono + grace);
                }
            }
            20 => self.message_failed(bad_msg_id, FailureKind::Other, now),
            32 | 33 => {
                self.message_failed(bad_msg_id, FailureKind::Other, now);
                self.pending_reset = true;
            }
            48 => {
                self.salts.invalidate_current();
                self.last_future_salts_at = None;
                self.message_failed(bad_msg_id, FailureKind::Salt, now);
            }
            _ => {
                self.strike_and_fail(bad_msg_id, error_code, msg_id);
                self.message_failed(bad_msg_id, FailureKind::Other, now);
            }
        }
    }

    fn on_pong(&mut self, context: &mut PacketContext, msg_id: i64, ping_msg_id: i64, ping_id: i64, now: Now) {
        self.last_pong_at = now.mono;
        let sent_at = self.pending_pings.remove(&ping_msg_id).or_else(|| self.pending_pings.remove(&ping_id));
        if let Some(sent_at) = sent_at {
            if msg_id < ping_msg_id.wrapping_sub(RESPONSE_TIME_SKEW) {
                self.reset_server_time(msg_id, now);
            }
            let rtt = (now.mono - sent_at).max(0.0);
            self.rtt_peak = rtt.max(self.rtt_peak * 0.9);
            if self.rtt == 0.0 {
                self.rtt = rtt;
                self.rtt_var = rtt / 2.0;
            } else {
                self.rtt_var = self.rtt_var * 0.75 + (self.rtt - rtt).abs() * 0.25;
                self.rtt = self.rtt * 0.7 + rtt * 0.3;
            }
            if rtt < self.probe_timeout() {
                self.probe_backoff = (self.probe_backoff * 0.5).max(1.0);
            }
            self.events.push_back(SessionEvent::Pong { rtt });
        }
        if ping_msg_id == self.last_ping_msg_id {
            self.last_ping_msg_id = 0;
        }
        if self.has_unknown_queries() && now.mono - self.connected_at > UNKNOWN_QUERIES_STUCK_AFTER {
            context.unknown_queries_stuck = true;
        }
    }

    fn on_destroy_auth_key(&mut self, outcome: DestroyAuthKeyOutcome) {
        if self.need_destroy_auth_key {
            self.events.push_back(SessionEvent::DestroyAuthKey { outcome });
        }
    }

    fn on_rpc_result(
        &mut self,
        context: &mut PacketContext,
        msg_id: i64,
        req_msg_id: i64,
        result: &[u8],
        size: usize,
        now: Now,
    ) {
        let Some(id) = self.by_msg_id.get(&req_msg_id).copied() else {
            if size > DROPPED_ANSWER_COUNTED_SIZE {
                if now.mono - self.dropped_answer_window_start > DROPPED_ANSWER_WINDOW {
                    self.dropped_answer_window_start = now.mono;
                    self.dropped_answer_bytes = 0;
                }
                self.dropped_answer_bytes += size;
                if self.dropped_answer_bytes > DROPPED_ANSWER_LIMIT {
                    let total = self.dropped_answer_bytes;
                    self.dropped_answer_bytes = 0;
                    self.events.push_back(SessionEvent::DroppedAnswerTooLarge { total });
                }
            }
            return;
        };
        if msg_id < req_msg_id.wrapping_sub(RESPONSE_TIME_SKEW) {
            self.reset_server_time(msg_id, now);
        }
        let event = match tlm::parse_rpc_result_limited(result, context.budget.min(tlm::MAX_UNPACKED_SIZE)) {
            Ok(RpcResultBody::Error(error)) => {
                let error = error.normalized();
                SessionEvent::Error { id, code: error.code, message: error.message, response_msg_id: msg_id }
            }
            Ok(RpcResultBody::Value(value)) => {
                SessionEvent::Result { id, body: value.to_vec(), response_msg_id: msg_id, original_size: size }
            }
            Ok(RpcResultBody::PackedValue(value)) => {
                context.budget = context.budget.saturating_sub(value.len());
                SessionEvent::Result { id, body: value, response_msg_id: msg_id, original_size: size }
            }
            Ok(RpcResultBody::DropAnswer(_)) => return,
            Err(error) => {
                context.budget = 0;
                SessionEvent::Error {
                    id,
                    code: 500,
                    message: format!("{RESPONSE_UNPACK_FAILED}: {error}"),
                    response_msg_id: msg_id,
                }
            }
        };
        self.complete_query(id, req_msg_id);
        self.events.push_back(event);
    }

    fn complete_query(&mut self, id: QueryId, msg_id: i64) {
        if let Some(query) = self.queries.remove(&id) {
            Self::count_transition(&mut self.pending_queries, &mut self.unknown_queries, Some(query.state), None);
            self.by_msg_id.remove(&msg_id);
            self.detach_from_container(query.container_id, msg_id);
            if !self.to_retransmit.is_empty() {
                self.to_retransmit.retain(|other| *other != id);
            }
            if !self.awaited_answers.is_empty() {
                self.awaited_answers.retain(|_, awaited| awaited.query != Some(id));
            }
        }
        self.refresh_unknown_tracking();
    }

    fn on_new_session_created(
        &mut self,
        context: &mut PacketContext,
        unique_id: i64,
        first_msg_id: i64,
        server_salt: i64,
        now: Now,
    ) {
        if context.mode == Mode::Replay || self.recent_unique_ids.contains(&unique_id) {
            return;
        }
        self.recent_unique_ids.push_back(unique_id);
        while self.recent_unique_ids.len() > 16 {
            self.recent_unique_ids.pop_front();
        }
        let server_time = self.server_time(now);
        if self.salts.current_value() != server_salt || !self.salts.has_valid_salt(server_time) {
            self.salts.set_server_salt(server_salt, server_time);
            self.last_future_salts_at = None;
            self.events.push_back(SessionEvent::SaltsUpdated { salts: self.salts.all() });
        }
        let mut first = first_msg_id;
        if let Some(query) = self.by_msg_id.get(&first_msg_id).and_then(|id| self.queries.get(id))
            && query.container_id != 0
        {
            first = query.container_id;
        }
        let mut resend: Vec<(i64, QueryId)> = self
            .queries
            .iter()
            .filter(|(_, query)| query.state != QueryState::Pending)
            .filter(|(_, query)| {
                let reference = if query.container_id != 0 { query.container_id } else { query.msg_id };
                reference < first
            })
            .map(|(id, query)| (query.msg_id, *id))
            .collect();
        resend.sort_unstable();
        context.deferred_resends.extend(resend.into_iter().map(|(msg_id, id)| (id, msg_id)));
        self.events.push_back(SessionEvent::ServerSessionReset { unique_id, first_msg_id });
    }

    fn on_message_info(&mut self, query_msg_id: Option<i64>, status: i32, answer_msg_id: Option<i64>, now: Now) {
        let mut answered_query = None;
        if let Some(query_msg_id) = query_msg_id {
            let Some(id) = self.by_msg_id.get(&query_msg_id).copied() else {
                if let Some(answer) = answer_msg_id {
                    self.schedule_ack(answer, now);
                }
                return;
            };
            match status & 7 {
                1..=3 => {
                    self.resend_query(id, now);
                    return;
                }
                0 if answer_msg_id.is_none() => {
                    self.resend_query(id, now);
                    return;
                }
                _ => {
                    self.mark_acknowledged(id);
                }
            }
            answered_query = Some(id);
        }
        if let Some(answer) = answer_msg_id {
            if self.received.contains(answer) {
                self.schedule_ack(answer, now);
            } else {
                self.request_answer(answer, answered_query, now);
            }
        }
    }

    fn request_answer(&mut self, answer: i64, query: Option<QueryId>, now: Now) {
        if !self.awaited_answers.contains_key(&answer) && self.awaited_answers.len() >= MAX_AWAITED_ANSWERS {
            return;
        }
        let entry = self.awaited_answers.entry(answer).or_insert(AwaitedAnswer { query, requests: 0 });
        if entry.query.is_none() {
            entry.query = query;
        }
        if self.to_resend_answer.is_empty() {
            self.send_before(now.mono + QUERY_DELAY);
        }
        if !self.to_resend_answer.contains(&answer) {
            self.to_resend_answer.push(answer);
            if self.to_resend_answer.len() > MAX_QUEUED_ACKS {
                let excess = self.to_resend_answer.len() - MAX_QUEUED_ACKS;
                self.to_resend_answer.drain(..excess);
            }
        }
    }

    fn on_answers_unavailable(&mut self, answers: &[i64], now: Now) {
        if answers.len() > 1 {
            for answer in answers {
                if self.awaited_answers.contains_key(answer) {
                    self.resend_individually.insert(*answer);
                    if !self.to_resend_answer.contains(answer) {
                        self.to_resend_answer.push(*answer);
                    }
                }
            }
            self.send_before(now.mono);
            return;
        }
        for answer in answers {
            self.resend_individually.remove(answer);
            if let Some(id) = self.awaited_answers.remove(answer).and_then(|awaited| awaited.query) {
                self.resend_query(id, now);
            }
        }
    }

    fn on_state_info(&mut self, msg_ids: &[i64], info: &[u8], now: Now) {
        if msg_ids.len() != info.len() {
            return;
        }
        for (msg_id, state) in msg_ids.iter().zip(info) {
            if let Some(id) = self.by_msg_id.get(msg_id).copied() {
                let stale = self
                    .queries
                    .get(&id)
                    .is_some_and(|query| query.state == QueryState::Sent && query.may_have_arrived);
                match state & 7 {
                    1..=3 if stale => {}
                    1..=3 => self.resend_query(id, now),
                    4 => self.mark_acknowledged(id),
                    _ => {}
                }
            }
        }
        self.refresh_unknown_tracking();
    }

    fn on_future_salts(&mut self, salts: &[FutureSalt], now: Now) {
        let converted: Vec<ServerSalt> = salts
            .iter()
            .map(|salt| ServerSalt {
                salt: salt.salt,
                valid_since: salt.valid_since as f64,
                valid_until: salt.valid_until as f64,
            })
            .collect();
        let server_time = self.server_time(now);
        self.salts.set_future(converted, server_time);
        self.events.push_back(SessionEvent::SaltsUpdated { salts: self.salts.all() });
    }

    fn may_ping(&self, now: Now) -> bool {
        match self.last_ping_at {
            None => true,
            Some(at) => at + self.ping_may_delay() < now.mono,
        }
    }

    fn must_ping(&self, now: Now) -> bool {
        match self.last_ping_at {
            None => true,
            Some(at) => at + self.ping_must_delay() < now.mono,
        }
    }

    fn must_flush(&mut self, now: Now) -> bool {
        if !self.connected {
            return false;
        }
        let server_time = self.server_time(now);
        let has_salt = self.salts.has_valid_salt(server_time);
        if has_salt {
            if self.force_send_at.is_some_and(|at| now.mono >= at) {
                return true;
            }
            if self.must_ping(now) {
                return true;
            }
            if self.need_destroy_auth_key && !self.sent_destroy_auth_key {
                return true;
            }
        } else {
            match self.last_future_salts_at {
                None => return true,
                Some(at) if at + FUTURE_SALTS_RETRY < now.mono => return true,
                _ => {}
            }
        }
        false
    }

    pub fn poll_timeout(&mut self, now: Now) -> Option<f64> {
        if !self.connected {
            return None;
        }
        let mut deadline = f64::INFINITY;
        let server_time = self.server_time(now);
        let has_salt = self.salts.has_valid_salt(server_time);
        if has_salt {
            if let Some(at) = self.force_send_at {
                deadline = deadline.min(at);
            }
            match self.last_ping_at {
                Some(at) => deadline = deadline.min(at + self.ping_must_delay()),
                None => deadline = deadline.min(now.mono),
            }
        } else {
            match self.last_future_salts_at {
                Some(at) => deadline = deadline.min(at + FUTURE_SALTS_RETRY),
                None => deadline = deadline.min(now.mono),
            }
        }
        if let Some(change) = self.salts.next_change_time() {
            deadline = deadline.min(now.mono + (change - server_time).max(0.0));
        }
        let grace = self.transmit_grace_until;
        deadline = deadline.min((self.liveness_at() + self.ping_disconnect_delay() + 0.002).max(grace));
        deadline = deadline.min((self.last_read_at + self.read_disconnect_delay() + 0.002).max(grace));
        if let Some(since) = self.unknown_since {
            deadline = deadline.min(since + STATE_REQUEST_RETRY);
        }
        if let Some(at) = self.drain_reset_at {
            deadline = deadline.min(at);
        }
        if let Some(at) = self.probe_deadline() {
            deadline = deadline.min((at + 0.002).max(grace)).min(self.backlog_sampled_at + BACKLOG_SAMPLE_INTERVAL);
        }
        for request in self.service_requests.values() {
            deadline = deadline.min(request.sent_at() + STATE_REQUEST_RETRY + 0.002);
        }
        deadline.is_finite().then_some(deadline)
    }

    pub fn handle_timeout(&mut self, now: Now) -> Result<(), SessionError> {
        if !self.connected {
            return Ok(());
        }
        self.sync_wall_clock(now);
        self.refresh_busy(now);
        let transmitting = now.mono < self.transmit_grace_until;
        if !transmitting && self.liveness_at() + self.ping_disconnect_delay() < now.mono {
            return Err(SessionError::PingTimeout);
        }
        if !transmitting && self.last_read_at + self.read_disconnect_delay() < now.mono {
            return Err(SessionError::ReadTimeout);
        }
        if !transmitting && self.probe_deadline().is_some_and(|at| at < now.mono) {
            if self.received_on_connection {
                self.probe_backoff = (self.probe_backoff * 2.0).min(PROBE_BACKOFF_MAX);
            }
            return Err(SessionError::ProbeTimeout);
        }
        self.expire_state_requests(now);
        if self.unknown_since.is_some_and(|since| since + STATE_REQUEST_RETRY < now.mono) {
            self.unknown_since = Some(now.mono);
            let unknown: Vec<i64> = self
                .queries
                .values()
                .filter(|query| query.state == QueryState::Unknown)
                .map(|query| query.msg_id)
                .collect();
            let already_requested: Vec<i64> = self
                .service_requests
                .values()
                .flat_map(|request| match request {
                    ServiceRequest::StateRequest { msg_ids, .. } => msg_ids.clone(),
                    ServiceRequest::ResendRequest { .. } => Vec::new(),
                })
                .collect();
            for msg_id in unknown {
                if !already_requested.contains(&msg_id) && !self.to_state_request.contains(&msg_id) {
                    self.to_state_request.push(msg_id);
                }
            }
            if !self.to_state_request.is_empty() {
                self.send_before(now.mono);
            }
        }
        self.expire_answer_requests(now);
        Ok(())
    }

    fn expire_state_requests(&mut self, now: Now) {
        let expired: Vec<i64> = self
            .service_requests
            .iter()
            .filter_map(|(request_id, request)| match request {
                ServiceRequest::StateRequest { sent_at, .. } if sent_at + STATE_REQUEST_RETRY < now.mono => {
                    Some(*request_id)
                }
                _ => None,
            })
            .collect();
        for request_id in expired {
            if let Some(ServiceRequest::StateRequest { msg_ids, .. }) = self.service_requests.remove(&request_id) {
                for msg_id in msg_ids {
                    let still_unknown = self
                        .by_msg_id
                        .get(&msg_id)
                        .and_then(|id| self.queries.get(id))
                        .is_some_and(|query| query.state == QueryState::Unknown);
                    if still_unknown && !self.to_state_request.contains(&msg_id) {
                        self.to_state_request.push(msg_id);
                    }
                }
                self.send_before(now.mono);
            }
        }
    }

    fn expire_answer_requests(&mut self, now: Now) {
        let expired: Vec<i64> = self
            .service_requests
            .iter()
            .filter_map(|(request_id, request)| match request {
                ServiceRequest::ResendRequest { sent_at, .. } if sent_at + STATE_REQUEST_RETRY < now.mono => {
                    Some(*request_id)
                }
                _ => None,
            })
            .collect();
        for request_id in expired {
            let Some(ServiceRequest::ResendRequest { msg_ids, .. }) = self.service_requests.remove(&request_id) else {
                continue;
            };
            for answer in msg_ids {
                let Some(awaited) = self.awaited_answers.get_mut(&answer) else {
                    continue;
                };
                awaited.requests += 1;
                if awaited.requests >= MAX_ANSWER_REQUESTS {
                    let query = awaited.query;
                    self.awaited_answers.remove(&answer);
                    if let Some(id) = query {
                        self.resend_query(id, now);
                    }
                } else if !self.to_resend_answer.contains(&answer) {
                    self.to_resend_answer.push(answer);
                    self.send_before(now.mono);
                }
            }
        }
    }

    pub fn poll_transmit(&mut self, now: Now, rng: &mut impl SecureRandom) -> Option<Transmit> {
        self.sync_wall_clock(now);
        self.finish_drain_reset(now, rng);
        if self.drain_reset_at.is_some() || !self.must_flush(now) {
            return None;
        }
        let transmit = self.flush_packet(now, rng);
        self.refresh_busy(now);
        transmit
    }

    fn query_wire_body(query: &Query) -> Vec<u8> {
        if query.invoke_after_msg_id == 0 {
            return query.body.clone();
        }
        let mut writer = Writer::with_capacity(query.body.len() + 12);
        tlm::write_invoke_after_msg(&mut writer, query.invoke_after_msg_id);
        writer.write_raw(&query.body);
        writer.into_inner()
    }

    fn push_service(
        &mut self,
        messages: &mut Vec<OutgoingMessage>,
        body: Vec<u8>,
        now: Now,
        rng: &mut impl SecureRandom,
    ) -> i64 {
        let msg_id = self.next_msg_id(now, rng);
        let seq_no = self.next_seq_no(false);
        messages.push(OutgoingMessage { msg_id, seq_no, body });
        msg_id
    }

    fn flush_packet(&mut self, now: Now, rng: &mut impl SecureRandom) -> Option<Transmit> {
        let server_time = self.server_time(now);
        let has_salt = self.salts.has_valid_salt(server_time);

        let mut messages: Vec<OutgoingMessage> = Vec::new();
        let mut query_messages: Vec<(QueryId, usize)> = Vec::new();
        let mut wants_quick_ack = false;
        let mut force_container = false;

        let mut total = 0usize;
        if has_salt && !self.to_retransmit.is_empty() {
            let epoch = self.connection_epoch;
            let mut deferred = Vec::new();
            for id in std::mem::take(&mut self.to_retransmit) {
                if !deferred.is_empty() {
                    deferred.push(id);
                    continue;
                }
                let Some(query) = self.queries.get_mut(&id).filter(|query| query.state != QueryState::Pending) else {
                    continue;
                };
                let body = Self::query_wire_body(query);
                if query_messages.len() >= self.config.max_container_queries
                    || (!query_messages.is_empty() && total + body.len() > self.config.max_container_bytes)
                {
                    deferred.push(id);
                    continue;
                }
                Self::count_transition(
                    &mut self.pending_queries,
                    &mut self.unknown_queries,
                    Some(query.state),
                    Some(QueryState::Sent),
                );
                query.state = QueryState::Sent;
                query.connection_epoch = epoch;
                query.may_have_arrived = true;
                total += body.len();
                wants_quick_ack |= query.options.quick_ack;
                query_messages.push((id, messages.len()));
                messages.push(OutgoingMessage { msg_id: query.msg_id, seq_no: query.seq_no, body });
                force_container = true;
            }
            self.to_retransmit = deferred;
            self.refresh_unknown_tracking();
        }

        if has_salt && self.to_retransmit.is_empty() {
            let mut sent_now: HashMap<QueryId, i64> = HashMap::new();
            while let Some(&id) = self.pending.front() {
                if query_messages.len() >= self.config.max_container_queries {
                    break;
                }
                let Some((body_len, invoke_after)) =
                    self.queries.get(&id).map(|query| (query.body.len(), query.options.invoke_after))
                else {
                    self.pending.pop_front();
                    continue;
                };
                if !query_messages.is_empty() && total + body_len > self.config.max_container_bytes {
                    break;
                }
                self.pending.pop_front();
                let dependency = invoke_after.and_then(|dependency| {
                    sent_now.get(&dependency).copied().or_else(|| self.query_msg_id(dependency))
                });
                let msg_id = self.next_msg_id(now, rng);
                let seq_no = self.next_seq_no(true);
                let epoch = self.connection_epoch;
                let query = self.queries.get_mut(&id).expect("query exists");
                query.invoke_after_msg_id = dependency.unwrap_or(0);
                let body = Self::query_wire_body(query);
                total += body.len();
                wants_quick_ack |= query.options.quick_ack;
                Self::count_transition(
                    &mut self.pending_queries,
                    &mut self.unknown_queries,
                    Some(query.state),
                    Some(QueryState::Sent),
                );
                query.state = QueryState::Sent;
                query.msg_id = msg_id;
                query.seq_no = seq_no;
                query.sent_at = now.mono;
                query.connection_epoch = epoch;
                query.acknowledged = false;
                self.by_msg_id.insert(msg_id, id);
                sent_now.insert(id, msg_id);
                query_messages.push((id, messages.len()));
                messages.push(OutgoingMessage { msg_id, seq_no, body });
            }
        }

        let mut ping_msg_id = 0;
        if has_salt && self.may_ping(now) {
            let msg_id = self.next_msg_id(now, rng);
            let seq_no = self.next_seq_no(false);
            let mut writer = Writer::with_capacity(20);
            if self.config.use_ping_delay_disconnect {
                tlm::write_ping_delay_disconnect(&mut writer, msg_id, (self.ping_disconnect_delay() + 2.0) as i32);
            } else {
                tlm::write_ping(&mut writer, msg_id);
            }
            self.last_ping_at = Some(now.mono);
            self.pending_pings.insert(msg_id, now.mono);
            if self.pending_pings.len() > MAX_PENDING_PINGS
                && let Some(oldest) = self.pending_pings.keys().min().copied()
            {
                self.pending_pings.remove(&oldest);
            }
            ping_msg_id = msg_id;
            messages.push(OutgoingMessage { msg_id, seq_no, body: writer.into_inner() });
        }

        if self.salts.needs_future_salts(server_time)
            && self.last_future_salts_at.is_none_or(|at| at + FUTURE_SALTS_RETRY < now.mono)
        {
            self.last_future_salts_at = Some(now.mono);
            let mut writer = Writer::with_capacity(8);
            tlm::write_get_future_salts(&mut writer, FUTURE_SALTS_COUNT);
            let msg_id = self.push_service(&mut messages, writer.into_inner(), now, rng);
            self.future_salts_requests.push_back(msg_id);
            while self.future_salts_requests.len() > 8 {
                self.future_salts_requests.pop_front();
            }
        }

        let mut state_request = None;
        if has_salt && !self.to_state_request.is_empty() {
            let queries = &self.queries;
            let by_msg_id = &self.by_msg_id;
            self.to_state_request.retain(|msg_id| {
                by_msg_id
                    .get(msg_id)
                    .and_then(|id| queries.get(id))
                    .is_none_or(|query| query.state == QueryState::Unknown)
            });
        }
        if has_salt && !self.to_state_request.is_empty() {
            let ids = take_tail(&mut self.to_state_request, MAX_IDS_PER_SERVICE_MESSAGE);
            let mut writer = Writer::new();
            tlm::write_msgs_state_req(&mut writer, &ids);
            let msg_id = self.push_service(&mut messages, writer.into_inner(), now, rng);
            state_request = Some((msg_id, ids));
        }

        let mut resend_requests: Vec<(i64, Vec<i64>)> = Vec::new();
        if has_salt && !self.to_resend_answer.is_empty() {
            let awaited = &self.awaited_answers;
            self.resend_individually.retain(|id| awaited.contains_key(id));
            let ids = take_tail(&mut self.to_resend_answer, MAX_IDS_PER_SERVICE_MESSAGE);
            let (single, batch): (Vec<i64>, Vec<i64>) =
                ids.into_iter().partition(|id| self.resend_individually.contains(id));
            if !batch.is_empty() {
                let mut writer = Writer::new();
                tlm::write_msg_resend_req(&mut writer, &batch);
                let msg_id = self.push_service(&mut messages, writer.into_inner(), now, rng);
                resend_requests.push((msg_id, batch));
            }
            for (index, id) in single.iter().enumerate() {
                if messages.len() + CONTAINER_RESERVED_SLOTS + 4 >= MAX_CONTAINER_MESSAGES_OUT {
                    self.to_resend_answer.extend_from_slice(&single[index..]);
                    break;
                }
                let mut writer = Writer::new();
                tlm::write_msg_resend_req(&mut writer, &[*id]);
                let msg_id = self.push_service(&mut messages, writer.into_inner(), now, rng);
                resend_requests.push((msg_id, vec![*id]));
            }
        }

        if has_salt {
            let room = MAX_CONTAINER_MESSAGES_OUT.saturating_sub(messages.len() + CONTAINER_RESERVED_SLOTS);
            let drops: Vec<i64> = self.to_drop_answer.drain(..room.min(self.to_drop_answer.len())).collect();
            for msg_id in drops {
                let mut writer = Writer::new();
                tlm::write_rpc_drop_answer(&mut writer, msg_id);
                self.push_service(&mut messages, writer.into_inner(), now, rng);
            }
            let room = MAX_CONTAINER_MESSAGES_OUT.saturating_sub(messages.len() + CONTAINER_RESERVED_SLOTS);
            let replies: Vec<(i64, Vec<u8>)> =
                self.to_state_info_reply.drain(..room.min(self.to_state_info_reply.len())).collect();
            for (req_msg_id, info) in replies {
                let mut writer = Writer::new();
                tlm::write_msgs_state_info(&mut writer, req_msg_id, &info);
                self.push_service(&mut messages, writer.into_inner(), now, rng);
            }
            let room = MAX_CONTAINER_MESSAGES_OUT.saturating_sub(messages.len() + CONTAINER_RESERVED_SLOTS);
            let pongs: Vec<(i64, i64)> = self.to_pong.drain(..room.min(self.to_pong.len())).collect();
            for (ping_msg_id, ping_id) in pongs {
                let mut writer = Writer::with_capacity(20);
                tlm::write_pong(&mut writer, ping_msg_id, ping_id);
                self.push_service(&mut messages, writer.into_inner(), now, rng);
            }
        }

        if has_salt && self.need_destroy_auth_key && !self.sent_destroy_auth_key {
            self.sent_destroy_auth_key = true;
            let mut writer = Writer::new();
            tlm::write_destroy_auth_key(&mut writer);
            self.push_service(&mut messages, writer.into_inner(), now, rng);
        }

        if !self.to_ack.is_empty() {
            let ids = take_tail(&mut self.to_ack, MAX_IDS_PER_SERVICE_MESSAGE);
            let mut writer = Writer::with_capacity(16 + ids.len() * 8);
            tlm::write_msgs_ack(&mut writer, &ids);
            self.push_service(&mut messages, writer.into_inner(), now, rng);
        }

        let nothing_left = self.pending.is_empty()
            && self.to_ack.is_empty()
            && self.to_state_request.is_empty()
            && self.to_resend_answer.is_empty()
            && self.to_drop_answer.is_empty()
            && self.to_state_info_reply.is_empty()
            && self.to_pong.is_empty()
            && self.to_retransmit.is_empty();
        if nothing_left {
            self.force_send_at = None;
        }

        if messages.is_empty() {
            return None;
        }

        for message in &messages {
            self.remember_sent(message.msg_id);
        }

        let (outer_msg_id, seq_no, body, container_id) = if messages.len() == 1 && !force_container {
            let message = messages.pop().expect("one message");
            (message.msg_id, message.seq_no, message.body, 0)
        } else {
            let container_id = self.next_msg_id(now, rng);
            let seq_no = self.next_seq_no(false);
            let refs: Vec<ContainerMessage<'_>> = messages
                .iter()
                .map(|message| ContainerMessage { msg_id: message.msg_id, seqno: message.seq_no, body: &message.body })
                .collect();
            let total: usize = messages.iter().map(|message| 16 + message.body.len()).sum();
            let mut writer = Writer::with_capacity(8 + total);
            tlm::write_container(&mut writer, &refs);
            (container_id, seq_no, writer.into_inner(), container_id)
        };
        self.remember_sent(outer_msg_id);

        if container_id != 0 {
            let children: Vec<i64> = query_messages.iter().map(|(_, index)| messages[*index].msg_id).collect();
            let mut moved = Vec::new();
            for (id, _) in &query_messages {
                if let Some(query) = self.queries.get_mut(id) {
                    if query.container_id != 0 && query.container_id != container_id {
                        moved.push((query.container_id, query.msg_id));
                    }
                    query.container_id = container_id;
                }
            }
            for (old_container, msg_id) in moved {
                self.detach_from_container(old_container, msg_id);
            }
            if !children.is_empty() {
                self.containers.insert(container_id, children);
            }
            let mut services = Vec::new();
            if let Some((msg_id, _)) = &state_request {
                services.push(*msg_id);
            }
            services.extend(resend_requests.iter().map(|(msg_id, _)| *msg_id));
            if ping_msg_id != 0 {
                services.push(ping_msg_id);
                self.last_ping_container_id = container_id;
            }
            if !services.is_empty() {
                self.service_containers.push_back((container_id, services));
                while self.service_containers.len() > MAX_TRACKED_SERVICE_CONTAINERS {
                    self.service_containers.pop_front();
                }
            }
        }
        if ping_msg_id != 0 {
            self.last_ping_msg_id = ping_msg_id;
        }
        if let Some((msg_id, ids)) = state_request {
            self.service_requests.insert(msg_id, ServiceRequest::StateRequest { msg_ids: ids, sent_at: now.mono });
        }
        for (msg_id, ids) in resend_requests {
            self.service_requests.insert(msg_id, ServiceRequest::ResendRequest { msg_ids: ids, sent_at: now.mono });
        }

        let header = MessageHeader {
            salt: self.salts.current_salt(server_time),
            session_id: self.session_id,
            msg_id: outer_msg_id,
            seq_no,
        };
        let packet = encrypt_message(&self.auth_key, &header, &body, Side::Client, self.config.padding, rng);
        if packet.data.len() >= TRANSMIT_GRACE_MIN_SIZE {
            let start = self.transmit_grace_until.max(now.mono);
            self.transmit_grace_until = start + packet.data.len() as f64 / TRANSMIT_GRACE_RATE;
        }
        let quick_ack_token = if wants_quick_ack {
            let token = packet.quick_ack_token & 0x7fff_ffff;
            let ids: Vec<QueryId> = query_messages
                .iter()
                .filter(|(id, _)| self.queries.get(id).is_some_and(|query| query.options.quick_ack))
                .map(|(id, _)| *id)
                .collect();
            self.quick_acks.push_back((token, ids));
            while self.quick_acks.len() > MAX_RECENT_QUICK_ACKS {
                self.quick_acks.pop_front();
            }
            Some(packet.quick_ack_token)
        } else {
            None
        };
        Some(Transmit {
            data: packet.data,
            quick_ack_token,
            msg_id: outer_msg_id,
            contains_queries: !query_messages.is_empty(),
        })
    }

    pub fn poll_event(&mut self) -> Option<SessionEvent> {
        self.debug_check_counts();
        self.events.pop_front()
    }

    pub fn drain_events(&mut self) -> Vec<SessionEvent> {
        self.events.drain(..).collect()
    }

    pub fn shrink(&mut self) {
        if self.queries.is_empty() {
            self.queries.shrink_to(16);
            self.by_msg_id.shrink_to(16);
            self.pending.shrink_to(16);
            self.containers.shrink_to(16);
        }
        if self.to_ack.is_empty() {
            self.to_ack.shrink_to(16);
        }
        if self.awaited_answers.is_empty() {
            self.awaited_answers.shrink_to(16);
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn footprint(&self) -> usize {
        self.queries.len()
            + self.pending.len()
            + self.by_msg_id.len()
            + self.containers.values().map(Vec::len).sum::<usize>()
            + self.quick_acks.len()
            + self.to_ack.len()
            + self.to_resend_answer.len()
            + self.to_state_request.len()
            + self.to_drop_answer.len()
            + self.to_state_info_reply.iter().map(|(_, info)| info.len() + 1).sum::<usize>()
            + self.to_pong.len()
            + self.to_retransmit.len()
            + self.service_requests.len()
            + self.service_containers.len()
            + self.future_salts_requests.len()
            + self.awaited_answers.len()
            + self.recent_sent.len()
            + self.recent_unique_ids.len()
            + self.received.len()
            + self.updates.len()
            + self.pending_pings.len()
            + self.events.len()
    }
}

struct OutgoingMessage {
    msg_id: i64,
    seq_no: i32,
    body: Vec<u8>,
}

fn take_tail(source: &mut Vec<i64>, limit: usize) -> Vec<i64> {
    if source.len() <= limit {
        return std::mem::take(source);
    }
    let split = source.len() - limit;
    source.split_off(split)
}

#[cfg(test)]
mod tests;
