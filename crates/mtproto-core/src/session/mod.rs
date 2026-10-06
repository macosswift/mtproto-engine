mod dedupe;
mod salts;

use std::collections::{HashMap, HashSet, VecDeque};

pub use dedupe::{DuplicateCheck, DuplicateChecker};
pub use salts::{SALT_SAFETY_MARGIN, SINGLE_SALT_LIFETIME, SaltState, ServerSalt};

use crate::auth_key::AuthKey;
use crate::crypto::{SecureRandom, Side, aes_ige_decrypt, message_key_v2};
use crate::message::{
    MessageError, MessageHeader, PaddingPolicy, decrypt_message, encrypt_message, encrypt_message_v1, read_auth_key_id,
};
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
/// How long the acknowledgement of a large answer waits for something to ride with, usually the
/// request for a download's next part: on a starved uplink a packet of its own costs as much as the
/// request, and the server keeps unacknowledged answers far longer than this.
pub const LARGE_ANSWER_ACK_DELAY: f64 = 1.0;
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
/// A call whose answer the server announced (so it executed the call) and then said it no longer has.
/// The call fails with this rather than going again under a new msg_id, which would execute it a second
/// time; the host decides what the caller hears (as with tdlib and MtProtoKit, the call may just wait).
/// An announced answer that does not come is asked for again on every new connection, on an announcement
/// while no request for it is out and, over HTTP, up to `MAX_EXPIRED_ANSWER_ASKS` times when a request
/// goes unanswered.
pub const ANSWER_LOST: &str = "PROTOCOL_ERROR_ANSWER_LOST";
/// HTTP: an announced answer whose re-send request expired with no sign of it is asked for again at most
/// this many times until the server announces it again (it does in every response while it holds it).
/// Over TCP a re-send request is not repeated: the server answers every one on the connection it came on
/// (re-sending the answer or saying it has none), and a new connection asks again.
pub const MAX_EXPIRED_ANSWER_ASKS: u32 = 3;
/// TCP: how long a re-send request waits for the server's reply before it is dropped (not repeated), in
/// case the reply was lost to us (an answer dropped as too old, a call cancelled meanwhile).
pub const TCP_ASK_BACKSTOP: f64 = 120.0;
pub const MAX_QUERY_REJECTIONS: u32 = 12;
pub const MAX_SERVER_RESENDS: u32 = 8;
pub const TRANSMIT_GRACE_MIN_SIZE: usize = 4 * 1024;
pub const RESET_DRAIN_MIN: f64 = 1.0;
pub const RESET_DRAIN_MAX: f64 = 5.0;
/// The uplink rate a large message is assumed to leave at until the session has measured one.
/// Below EDGE and GPRS uplinks: a wrong guess only delays noticing a dead connection.
pub const TRANSMIT_GRACE_RATE_INITIAL: f64 = 4.0 * 1024.0;
/// The slowest uplink rate the grace assumes, whatever was measured.
pub const TRANSMIT_GRACE_RATE_MIN: f64 = 2.0 * 1024.0;
/// The longest one large packet keeps the liveness checks waiting for the server to receive it.
pub const TRANSMIT_GRACE_MAX: f64 = 120.0;
/// A packet this large is an upload part rather than a container of calls.
pub const UPLOAD_PACKET_MIN: usize = 16 * 1024;
/// The longest a connection that has not answered yet is given before its liveness checks cut it.
pub const FRESH_ALLOWANCE_MAX: f64 = 16.0;
/// An uplink this many times slower than the best measured lately is more likely a dead connection
/// than a shared or degraded link, so an expired grace is not stretched that far.
pub const STRETCH_MAX_SLOWDOWN: f64 = 8.0;
/// How long a lowering of the uplink peak after a cut holds, unless another cut renews it.
pub const PEAK_LOWERING_LIFETIME: f64 = 120.0;
/// Bytes an uplink rate sample must cover: smaller deliveries measure jitter, not the uplink.
pub const UPLINK_SAMPLE_MIN_BYTES: u64 = 16 * 1024;
/// How long the kernel may hold unsent bytes without the peer acknowledging any before the transmit
/// grace stops covering for it. Receive windows open in bursts and weak links stall for seconds.
pub const SEND_QUEUE_STUCK_AFTER: f64 = 10.0;
/// HTTP: how long a re-send of an answer the server announced with msg_detailed_info waits, at
/// least, for that answer to arrive in a response another connection is still receiving.
pub const HTTP_ANSWER_HOLD_MIN: f64 = 1.0;
/// HTTP: the longest an announced answer is waited for while responses keep arriving.
pub const HTTP_ANSWER_HOLD_MAX: f64 = 30.0;
/// HTTP: the answers asked for in one request add up to at most this many announced bytes, one
/// always going: a response is lost whole, and on a link that drops connections every few seconds a
/// response carrying several large answers may never arrive.
pub const HTTP_ANSWER_REQUEST_BYTES: usize = 16 * 1024;
/// HTTP: packets tracked for loss; beyond it the oldest are forgotten (their queries then wait for
/// the usual state requests).
pub const MAX_TRACKED_HTTP_PACKETS: usize = 256;
/// HTTP: a response proves the server read the request, and it acknowledges the queries in it in
/// that response or soon after; one neither acknowledged nor answered this long after goes again.
pub const HTTP_ACK_GRACE: f64 = 3.0;
/// HTTP: acknowledgements wait this long for a request with queries to ride along with.
pub const HTTP_ACK_DELAY: f64 = 0.02;

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
    pub packet_seq: u64,
}

/// The `http_wait` an HTTP request carries: the server answers once something is queued for the
/// session, after `max_delay` ms at most (`wait_after` ms after the latest message), and otherwise
/// after `max_wait` ms with an empty packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpWait {
    pub max_delay: i32,
    pub wait_after: i32,
    pub max_wait: i32,
}

impl HttpWait {
    pub const IMMEDIATE: HttpWait = HttpWait { max_delay: 0, wait_after: 0, max_wait: 0 };

    pub fn long_poll(max_wait_ms: i32) -> Self {
        Self { max_delay: 0, wait_after: 0, max_wait: max_wait_ms }
    }
}

/// `auth.bindTempAuthKey` for this session's temporary key. Its body is made when it gets a msg_id:
/// the inner `bind_auth_key_inner`, encrypted with the permanent key under MTProto 1.0, has to carry
/// that msg_id, and this session's id.
#[derive(Clone)]
pub struct BindRequest {
    pub perm_key: AuthKey,
    pub nonce: i64,
    pub expires_at: i32,
}

impl core::fmt::Debug for BindRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BindRequest")
            .field("perm_key", &self.perm_key.id())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// What one HTTP request carried, to resend it promptly if the request is lost.
#[derive(Debug, Clone)]
struct HttpPacket {
    seq: u64,
    queries: Vec<(QueryId, i64)>,
    services: Vec<i64>,
    future_salts: Option<i64>,
    destroys_auth_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryState {
    Pending,
    Sent,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
    sent_at: f64,
    packet_seq: u64,
    /// The ping went out behind large packets the server had not received yet, so its round trip
    /// measures their transfer rather than the network.
    behind_large: bool,
}

/// A packet of at least `TRANSMIT_GRACE_MIN_SIZE` bytes the server has not yet shown to have received.
#[derive(Debug, Clone, Copy)]
struct LargePacket {
    seq: u64,
    bytes: usize,
    sent_at: f64,
    /// `Session::delivered` and `Session::delivered_at` when the packet was sent.
    delivered: u64,
    delivered_at: f64,
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
    /// The packet that carried the query under its current msg_id on this connection. None once the
    /// query is retransmitted, as its answer may then be for a transmission on an earlier connection.
    arrival_seq: Option<u64>,
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
    /// The msg_id of the latest message announcing it.
    announced_by: i64,
    /// HTTP: re-send requests repeated since the last announcement because the previous one expired.
    expired_asks: u32,
    /// The size the server announced.
    bytes: usize,
    /// HTTP: no re-send request before then; the answer may be in a response still arriving.
    hold_until: f64,
    announced_at: f64,
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
    quick_acks: VecDeque<(u32, Vec<QueryId>, u64)>,

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
    recent_sent: VecDeque<(i64, f64)>,
    recent_unique_ids: VecDeque<i64>,
    /// The msg_id of the last `new_session_created`: an answer announced before it is the old server
    /// session's, and the server saying it has none of it does not fail the call (the new session runs
    /// it, or it was sent again).
    server_session_since: i64,
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
    /// How long recent connections took to give their first answer, decaying like `rtt_peak`.
    first_answer_peak: f64,
    /// Connections in a row cut by a liveness check before they ever answered.
    silent_cuts: u32,
    /// How long other connections' uploads may hold up this connection's first exchange.
    uplink_queue: f64,
    /// The lowered peak and the time of the cut, applied when this connection closes: a liveness
    /// check cut it while its grace was refused a stretch, see `note_refused_stretch`.
    peak_after_close: Option<(f64, f64)>,
    last_read_at: f64,
    last_pong_at: f64,
    last_ping_at: Option<f64>,
    /// The disconnect delay the last ping gave the server: it closes the connection unless the next
    /// ping arrives within it.
    last_ping_delay: f64,
    last_ping_msg_id: i64,
    last_ping_container_id: i64,
    pending_pings: HashMap<i64, PendingPing>,
    outbound_backlog: Option<usize>,
    outbound_progress_at: f64,
    backlog_sampled_at: f64,
    probe_episode: Option<f64>,
    probe_drained: bool,
    probe_backoff: f64,
    received_on_connection: bool,
    fresh_packets: u64,
    transmit_grace_until: f64,
    /// Bytes per second large packets reached the server at.
    uplink_rate: Option<f64>,
    /// The fastest delivery measured lately, decaying with every sample.
    uplink_rate_peak: Option<f64>,
    /// A lower peak a refused stretch left behind, and when its cut came: see `note_refused_stretch`.
    lowered_peak: Option<(f64, f64)>,
    /// The rate before stretches on this connection pulled it down, given back if the connection is
    /// cut and closed before delivering: a stretch that ended in a cut measured nothing.
    rate_before_stretch: Option<Option<f64>>,
    packet_seq: u64,
    /// Large packets sent on this connection the server has not yet shown to have received, oldest first.
    unconfirmed_large: VecDeque<LargePacket>,
    /// Bytes of large packets the server has shown to have received, and when it last did.
    delivered: u64,
    delivered_at: f64,
    /// The host keeps a silent connection while a fresh one races it, until then.
    liveness_hold_until: f64,
    last_future_salts_at: Option<f64>,
    unknown_since: Option<f64>,
    dropped_answer_bytes: usize,
    dropped_answer_window_start: f64,

    need_destroy_auth_key: bool,
    sent_destroy_auth_key: bool,
    destroy_answered: bool,
    pending_reset: bool,
    drain_reset_at: Option<f64>,

    /// The transport is HTTP: every packet is a request carrying an `http_wait`, the server answers
    /// only in responses, there is no quick ack and no ping; the host times each request instead.
    http: bool,
    /// The longest an idle connection goes without a ping of its own: Telegram Web's fronts close a
    /// WebSocket after 91 s of silence.
    keepalive_cap: Option<f64>,
    http_packets: VecDeque<HttpPacket>,
    /// HTTP: queries whose request was answered, with when they must be acknowledged by.
    http_awaiting_ack: VecDeque<(QueryId, i64, f64)>,
    /// HTTP: response bytes arrived lately, so an announced answer may be among them.
    http_receiving_until: f64,

    bind: Option<(QueryId, BindRequest)>,
    /// The key is temporary and not bound yet: nothing but the bind query goes out.
    bind_gate: bool,

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
            server_session_since: 0,
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
            first_answer_peak: 0.0,
            silent_cuts: 0,
            uplink_queue: 0.0,
            peak_after_close: None,
            last_read_at: now.mono,
            last_pong_at: now.mono,
            last_ping_at: None,
            last_ping_delay: f64::INFINITY,
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
            uplink_rate: None,
            uplink_rate_peak: None,
            lowered_peak: None,
            rate_before_stretch: None,
            packet_seq: 0,
            unconfirmed_large: VecDeque::new(),
            delivered: 0,
            delivered_at: 0.0,
            liveness_hold_until: 0.0,
            last_future_salts_at: None,
            unknown_since: None,
            dropped_answer_bytes: 0,
            dropped_answer_window_start: now.mono,
            need_destroy_auth_key: false,
            sent_destroy_auth_key: false,
            destroy_answered: false,
            pending_reset: false,
            drain_reset_at: None,
            http: false,
            keepalive_cap: None,
            http_packets: VecDeque::new(),
            http_awaiting_ack: VecDeque::new(),
            http_receiving_until: 0.0,
            bind: None,
            bind_gate: false,
            events: VecDeque::new(),
        }
    }

    /// Switches between the stream transports and HTTP. The host calls `connection_closed` before a
    /// switch while a connection is open.
    pub fn set_http(&mut self, http: bool) {
        if self.http == http {
            return;
        }
        self.http = http;
        self.http_packets.clear();
        self.http_awaiting_ack.clear();
        self.quick_acks.clear();
        self.pending_pings.clear();
        self.unconfirmed_large.clear();
        self.transmit_grace_until = 0.0;
        self.last_ping_at = None;
        self.last_ping_msg_id = 0;
        self.last_ping_container_id = 0;
        self.last_ping_delay = f64::INFINITY;
    }

    /// Each query's state, for diagnostics.
    pub fn describe_queries(&self) -> String {
        self.queries
            .values()
            .map(|query| {
                format!(
                    "[{:?} ack {} arrived {} epoch {}/{} msg {:x}]",
                    query.state,
                    query.acknowledged,
                    query.may_have_arrived,
                    query.connection_epoch,
                    self.connection_epoch,
                    query.msg_id
                )
            })
            .collect()
    }

    pub fn is_http(&self) -> bool {
        self.http
    }

    /// HTTP: a response to the request that carried packet `seq` arrived, so the server read it.
    pub fn http_packet_delivered(&mut self, seq: u64, now: Now) {
        let Some(position) = self.http_packets.iter().position(|packet| packet.seq == seq) else {
            return;
        };
        let packet = self.http_packets.remove(position).expect("position is valid");
        for (id, msg_id) in packet.queries {
            if self
                .queries
                .get(&id)
                .is_some_and(|query| query.state == QueryState::Sent && query.msg_id == msg_id && !query.acknowledged)
            {
                self.http_awaiting_ack.push_back((id, msg_id, now.mono + HTTP_ACK_GRACE));
            }
        }
        while self.http_awaiting_ack.len() > MAX_AWAITED_ANSWERS {
            self.http_awaiting_ack.pop_front();
        }
    }

    /// HTTP: queries the server read but neither acknowledged nor answered in time go again under
    /// their msg_id; if they did arrive, the server answers the copy from its cache.
    fn resend_unacknowledged_http(&mut self, now: Now) {
        let server_time = self.server_time(now);
        let mut resend = Vec::new();
        while let Some(&(id, msg_id, due)) = self.http_awaiting_ack.front() {
            if due > now.mono {
                break;
            }
            self.http_awaiting_ack.pop_front();
            let Some(query) = self.queries.get_mut(&id) else {
                continue;
            };
            if query.state != QueryState::Sent || query.msg_id != msg_id || query.acknowledged {
                continue;
            }
            if query.retransmit_refused || server_time - msg_id_time(msg_id) >= RETRANSMIT_WINDOW {
                continue;
            }
            Self::count_transition(
                &mut self.pending_queries,
                &mut self.unknown_queries,
                Some(QueryState::Sent),
                Some(QueryState::Unknown),
            );
            query.state = QueryState::Unknown;
            query.may_have_arrived = true;
            resend.push((msg_id, id));
        }
        if resend.is_empty() {
            return;
        }
        resend.sort_unstable();
        for (_, id) in resend {
            if !self.to_retransmit.contains(&id) {
                self.to_retransmit.push(id);
            }
        }
        self.refresh_unknown_tracking();
        self.send_before(now.mono);
    }

    /// HTTP: the request that carried packet `seq` failed before its response came. What it carried
    /// may or may not have reached the server: queries go again under the same msg_id, which the
    /// server never executes twice, and service requests are asked again.
    pub fn http_packet_lost(&mut self, seq: u64, now: Now) {
        let Some(position) = self.http_packets.iter().position(|packet| packet.seq == seq) else {
            return;
        };
        let packet = self.http_packets.remove(position).expect("position is valid");
        if packet.destroys_auth_key {
            self.sent_destroy_auth_key = false;
        }
        let server_time = self.server_time(now);
        let mut retransmit = Vec::new();
        for (id, msg_id) in packet.queries {
            let Some(query) = self.queries.get_mut(&id) else {
                continue;
            };
            if query.state != QueryState::Sent || query.msg_id != msg_id || query.acknowledged {
                continue;
            }
            Self::count_transition(
                &mut self.pending_queries,
                &mut self.unknown_queries,
                Some(QueryState::Sent),
                Some(QueryState::Unknown),
            );
            query.state = QueryState::Unknown;
            query.may_have_arrived = true;
            if !query.retransmit_refused && server_time - msg_id_time(msg_id) < RETRANSMIT_WINDOW {
                retransmit.push((msg_id, id));
            } else if !self.to_state_request.contains(&msg_id) {
                self.to_state_request.push(msg_id);
                self.unknown_since.get_or_insert(now.mono);
            }
        }
        retransmit.sort_unstable();
        for (_, id) in retransmit {
            if !self.to_retransmit.contains(&id) {
                self.to_retransmit.push(id);
            }
        }
        for service in packet.services {
            match self.service_requests.remove(&service) {
                Some(ServiceRequest::StateRequest { msg_ids, .. }) => {
                    for msg_id in msg_ids {
                        if !self.to_state_request.contains(&msg_id) {
                            self.to_state_request.push(msg_id);
                        }
                    }
                }
                Some(ServiceRequest::ResendRequest { msg_ids, .. }) => {
                    for msg_id in msg_ids {
                        if self.awaited_answers.contains_key(&msg_id) && !self.to_resend_answer.contains(&msg_id) {
                            self.to_resend_answer.push(msg_id);
                        }
                    }
                }
                None => {}
            }
        }
        if let Some(request) = packet.future_salts
            && let Some(index) = self.future_salts_requests.iter().position(|pending| *pending == request)
        {
            self.future_salts_requests.remove(index);
            self.last_future_salts_at = None;
        }
        self.refresh_unknown_tracking();
        self.send_before(now.mono);
    }

    /// HTTP: response bytes are arriving; an answer the server announced may be among them.
    pub fn note_http_receiving(&mut self, now: Now) {
        self.http_receiving_until = self.http_receiving_until.max(now.mono + HTTP_ANSWER_HOLD_MIN / 2.0);
    }

    /// HTTP: a round trip of a request the server answered at once.
    pub fn note_rtt_sample(&mut self, rtt: f64) {
        let rtt = rtt.max(0.0);
        self.rtt_peak = rtt.max(self.rtt_peak * 0.9);
        if self.rtt == 0.0 {
            self.rtt = rtt;
            self.rtt_var = rtt / 2.0;
        } else {
            self.rtt_var = self.rtt_var * 0.75 + (self.rtt - rtt).abs() * 0.25;
            self.rtt = self.rtt * 0.7 + rtt * 0.3;
        }
    }

    /// When an answer announced over HTTP may be asked for again.
    fn answer_hold_until(&self, awaited: &AwaitedAnswer) -> f64 {
        if !self.http {
            return 0.0;
        }
        awaited.hold_until.max(self.http_receiving_until).min(awaited.announced_at + HTTP_ANSWER_HOLD_MAX)
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

    pub fn unanswered_query_count(&self) -> usize {
        self.queries.len() - self.pending_queries
    }

    pub fn has_unanswered_queries(&self) -> bool {
        self.queries.len() > self.pending_queries
    }

    pub fn has_unknown_queries(&self) -> bool {
        self.unknown_queries > 0
    }

    /// Answers may still come under the session about to be reset: for queries sent, and over HTTP
    /// also for queries whose request was lost but may have reached the server.
    fn awaits_old_session_answers(&self) -> bool {
        self.queries.len() > self.pending_queries + self.unknown_queries
            || (self.http
                && self
                    .queries
                    .values()
                    .any(|query| query.state == QueryState::Unknown && query.may_have_arrived && !query.acknowledged))
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

    /// The query went out at least once, so the server may have it.
    pub fn was_transmitted(&self, id: QueryId) -> bool {
        self.queries.get(&id).is_some_and(|query| query.state != QueryState::Pending || query.may_have_arrived)
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
            self.need_destroy_auth_key = false;
            self.sent_destroy_auth_key = false;
            self.destroy_answered = false;
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
        self.destroy_answered = false;
        self.send_before(now.mono);
    }

    /// `destroy_auth_key` was asked for and its answer has not come yet.
    pub fn is_destroying_auth_key(&self) -> bool {
        self.need_destroy_auth_key && !self.destroy_answered
    }

    pub fn request_destroy_auth_key(&mut self) {
        self.need_destroy_auth_key = true;
        self.sent_destroy_auth_key = false;
        self.destroy_answered = false;
    }

    pub fn smoothed_rtt(&self) -> Option<f64> {
        (self.rtt > 0.0).then_some(self.rtt)
    }

    /// The uplink rate the transmit grace assumes: half the measured rate, never below
    /// `TRANSMIT_GRACE_RATE_MIN`. Behind carrier proxies, satellite accelerators and bufferbloat the
    /// socket reports large packets sent long before they reach the server, and the server cannot
    /// answer before they do, so silence is no sign of a dead connection until they could have.
    pub fn transmit_grace_rate(&self) -> f64 {
        self.uplink_rate.map_or(TRANSMIT_GRACE_RATE_INITIAL, |rate| (rate * 0.5).max(TRANSMIT_GRACE_RATE_MIN))
    }

    /// Until when the oldest large packet the server has not received may still be on its way. Only
    /// a connection the server has answered on gets the grace: a silent fresh one may be blackholed.
    pub fn transmit_grace_until(&self) -> f64 {
        if self.received_on_connection { self.transmit_grace_until } else { 0.0 }
    }

    pub fn is_transmitting(&self, now: Now) -> bool {
        now.mono < self.transmit_grace_until()
    }

    pub fn uplink_rate(&self) -> Option<f64> {
        self.uplink_rate
    }

    /// The network changed: what was measured on the old one says nothing about the new one.
    pub fn forget_link_measurements(&mut self) {
        self.uplink_rate = None;
        self.uplink_rate_peak = None;
        self.lowered_peak = None;
        self.peak_after_close = None;
        self.rate_before_stretch = None;
        self.first_answer_peak = 0.0;
        self.silent_cuts = 0;
    }

    /// Bytes of upload-sized packets still crossing the uplink on a connection that answered and
    /// is within its transmit grace: what other connections' packets may queue behind.
    pub fn upload_backlog(&self, now: Now) -> u64 {
        if !self.is_transmitting(now) {
            return 0;
        }
        self.unconfirmed_large
            .iter()
            .filter(|packet| packet.bytes >= UPLOAD_PACKET_MIN)
            .map(|packet| packet.bytes as u64)
            .sum()
    }

    pub fn set_uplink_queue(&mut self, seconds: f64) {
        self.uplink_queue = seconds.clamp(0.0, FRESH_ALLOWANCE_MAX);
    }

    /// No ping, read or probe timeout until `at`: the host races a fresh connection against this
    /// silent one and drops whichever loses. 0 ends the hold.
    pub fn hold_liveness_until(&mut self, at: f64) {
        self.liveness_hold_until = at;
    }

    /// The server received packet `seq`. One connection is an ordered stream, so it received every
    /// packet before it too. Each delivery is a rate sample: bytes delivered since a packet was sent
    /// over the time since the delivery before it, which, unlike a round trip minus the smoothed
    /// one, cannot run ahead of the link.
    fn note_arrived(&mut self, seq: u64, now: Now) {
        let mut sample = None;
        while let Some(packet) = self.unconfirmed_large.front().copied().filter(|packet| packet.seq <= seq) {
            self.unconfirmed_large.pop_front();
            self.delivered += packet.bytes as u64;
            let bytes = self.delivered - packet.delivered;
            let elapsed = now.mono - packet.delivered_at;
            if bytes >= UPLINK_SAMPLE_MIN_BYTES && elapsed > 0.0 {
                sample = Some(bytes as f64 / elapsed);
            }
            self.delivered_at = now.mono;
        }
        if let Some(sample) = sample {
            self.rate_before_stretch = None;
            self.uplink_rate = Some(self.uplink_rate.map_or(sample, |rate| rate * 0.7 + sample.min(rate * 4.0) * 0.3));
            self.uplink_rate_peak = Some(self.uplink_rate_peak.map_or(sample, |peak| sample.max(peak * 0.95)));
            if self.lowered_peak.is_some_and(|(lowered, _)| sample > lowered) {
                self.lowered_peak = None;
            }
        }
        self.refresh_transmit_grace();
    }

    /// The oldest large packet outlived its grace and the connection is otherwise fine: the uplink is
    /// slower than assumed, or shared with other uploads. It cannot be faster than what could have
    /// crossed by now, so the grace stretches for the rest, up to `TRANSMIT_GRACE_MAX`, unless that is
    /// far slower than the uplink measured lately.
    fn stretch_expired_grace(&mut self, now: Now) {
        let Some(packet) = self.unconfirmed_large.front().copied() else {
            return;
        };
        if !self.received_on_connection || now.mono < self.transmit_grace_until {
            return;
        }
        let elapsed = now.mono - packet.sent_at.max(self.delivered_at);
        if elapsed <= 0.0 || elapsed >= TRANSMIT_GRACE_MAX {
            return;
        }
        let bound = packet.bytes as f64 / elapsed;
        if self.stretch_peak(now).is_some_and(|peak| bound < peak / STRETCH_MAX_SLOWDOWN) {
            return;
        }
        if self.uplink_rate.is_none_or(|rate| rate > bound) {
            self.rate_before_stretch.get_or_insert(self.uplink_rate);
            self.uplink_rate = Some(bound.max(TRANSMIT_GRACE_RATE_MIN));
            self.refresh_transmit_grace();
        }
    }

    /// The oldest unconfirmed packet started crossing the bottleneck when it was sent or when the one
    /// before it arrived, whichever came later; later packets queue behind it and get their grace as
    /// it arrives, so a dead connection is noticed within one packet's time.
    fn refresh_transmit_grace(&mut self) {
        self.transmit_grace_until = self.unconfirmed_large.front().map_or(0.0, |packet| {
            let transfer = packet.bytes as f64 / self.transmit_grace_rate() + self.rtt_estimate();
            packet.sent_at.max(self.delivered_at) + transfer.min(TRANSMIT_GRACE_MAX)
        });
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
        self.pending_pings.values().map(|ping| ping.sent_at).filter(|sent| *sent >= self.last_read_at).reduce(f64::min)
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

    /// The transmit grace holds the probe back while large packets may still be crossing the link,
    /// but not while the kernel keeps bytes the peer has stopped acknowledging.
    fn probe_held_until(&self, now: Now) -> f64 {
        if now.mono < self.liveness_hold_until {
            return self.liveness_hold_until;
        }
        if !self.is_transmitting(now) {
            return 0.0;
        }
        let grace = self.transmit_grace_until();
        if self.probe_drained { grace } else { grace.min(self.outbound_progress_at + SEND_QUEUE_STUCK_AFTER) }
    }

    /// How long a connection that has not answered yet is given before its liveness checks cut it:
    /// its first round trip also carries the connection setup behind proxies and the resent backlog,
    /// which the round-trip estimate of earlier connections does not cover. Half again as long as
    /// recent connections took to answer, and twice as long after each one cut silent in a row, as a
    /// link where no connection answers in time needs more of it.
    fn fresh_allowance(&self) -> f64 {
        (PROBE_TIMEOUT_INITIAL * f64::from(1u32 << self.silent_cuts.min(2)))
            .max(self.first_answer_peak * 1.5)
            .max(self.uplink_queue)
            .min(FRESH_ALLOWANCE_MAX)
    }

    fn note_silent_cut(&mut self, now: Now) {
        if !self.received_on_connection {
            self.silent_cuts = self.silent_cuts.saturating_add(1);
        }
        self.note_refused_stretch(now);
    }

    /// The peak a stretch is measured against: the sampled one, or a lowered one while it holds.
    fn stretch_peak(&self, now: Now) -> Option<f64> {
        let peak = self.uplink_rate_peak?;
        Some(match self.lowered_peak {
            Some((lowered, at)) if now.mono - at < PEAK_LOWERING_LIFETIME => peak.min(lowered),
            _ => peak,
        })
    }

    /// A liveness check cut a connection that answered while its oldest packet, an upload part, was
    /// refused a stretch, the uplink measured lately being far faster. If the connection then closes,
    /// the peak comes down 4× for `PEAK_LOWERING_LIFETIME`, so that a drop of up to 32× costs the
    /// resent part one cut. Behind a TCP-terminating hop nothing tells a slow live connection from a
    /// dead one, so a run of dead connections pays for it: at a 2 MB/s peak with 512 KB parts they
    /// are noticed after about 3, 16, 35 and 120 s, the cycle starting over once the lowering lapses;
    /// on a direct path the stuck kernel queue still cuts them within about 12 s. A packet arriving on
    /// the connection cancels the lowering, as does a delivery faster than the lowered peak, and only
    /// the first cut of a connection counts.
    fn note_refused_stretch(&mut self, now: Now) {
        let Some(packet) = self.unconfirmed_large.front() else {
            return;
        };
        let elapsed = now.mono - packet.sent_at.max(self.delivered_at);
        if !self.received_on_connection
            || elapsed <= 0.0
            || packet.bytes < UPLOAD_PACKET_MIN
            || self.peak_after_close.is_some()
        {
            return;
        }
        let bound = packet.bytes as f64 / elapsed;
        if let Some(peak) = self.stretch_peak(now)
            && bound < peak / STRETCH_MAX_SLOWDOWN
        {
            self.peak_after_close = Some((peak / 4.0, now.mono));
        }
    }

    fn fresh_hold_until(&self) -> f64 {
        if self.received_on_connection { 0.0 } else { self.connected_at + self.fresh_allowance() }
    }

    fn probe_deadline(&self) -> Option<f64> {
        self.outbound_backlog?;
        let since = self.unanswered_ping_since()?;
        let timeout = if self.received_on_connection {
            self.probe_timeout()
        } else {
            self.probe_timeout().max(self.fresh_allowance())
        };
        Some(since.max(self.outbound_progress_at) + timeout)
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
        let delay = if self.uses_fast_liveness() { self.rtt_estimate() } else { 60.0 + self.random_delay };
        self.keepalive_cap.map_or(delay, |cap| delay.min(cap))
    }

    /// Caps the time an idle connection goes without a ping (None: no cap).
    pub fn set_keepalive_cap(&mut self, cap: Option<f64>) {
        self.keepalive_cap = cap;
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
                arrival_seq: None,
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
                self.forget_awaited_answers_of(&[(query.msg_id, id)]);
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
        self.liveness_hold_until = 0.0;
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
        self.sent_destroy_auth_key = false;
        self.http_packets.clear();
        self.http_awaiting_ack.clear();
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
        self.unconfirmed_large.clear();
        self.liveness_hold_until = 0.0;
        if let Some(lowered) = self.peak_after_close.take() {
            self.lowered_peak = Some(lowered);
            if let Some(rate) = self.rate_before_stretch {
                self.uplink_rate = rate;
            }
        }
        self.rate_before_stretch = None;
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
        self.server_session_since = 0;
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
        self.sent_at(msg_id).is_some_and(|sent_at| now.mono - sent_at <= MSG_ID_MAX_PAST_SECONDS)
    }

    fn sent_at(&self, msg_id: i64) -> Option<f64> {
        if let Some(ping) = self.pending_pings.get(&msg_id) {
            return Some(ping.sent_at);
        }
        if let Some(request) = self.service_requests.get(&msg_id) {
            return Some(request.sent_at());
        }
        if let Some(query) = self.by_msg_id.get(&msg_id).and_then(|id| self.queries.get(id))
            && query.msg_id == msg_id
        {
            return Some(query.sent_at);
        }
        self.recent_sent.iter().rev().find(|(id, _)| *id == msg_id).map(|(_, sent_at)| *sent_at)
    }

    fn was_sent(&self, msg_id: i64) -> bool {
        self.by_msg_id.contains_key(&msg_id)
            || self.containers.contains_key(&msg_id)
            || self.service_requests.contains_key(&msg_id)
            || self.pending_pings.contains_key(&msg_id)
            || self.future_salts_requests.contains(&msg_id)
            || self.service_containers.iter().any(|(container, _)| *container == msg_id)
            || self.recent_sent.iter().any(|(id, _)| *id == msg_id)
    }

    fn remember_sent(&mut self, msg_id: i64, now: Now) {
        self.recent_sent.push_back((msg_id, now.mono));
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

    /// A large packet carrying a query sent under a fresh msg_id is confirmed by that answer anyway,
    /// and by any later quick ack, as one connection is an ordered stream. For such packets one quick
    /// ack at a time keeps a confirmation at receipt time coming while sparing the server a packet of
    /// its own per part, which on a lossy downlink holds up the answers queued behind it. A packet
    /// carrying only resent queries still asks, as their answers may be the ones to earlier copies, and
    /// so does one dropping an answer while large packets wait, as a cancelled query's answer confirms
    /// nothing.
    fn awaits_large_quick_ack(&self) -> bool {
        self.quick_acks.iter().any(|(_, _, seq)| self.unconfirmed_large.iter().any(|packet| packet.seq == *seq))
    }

    /// True when the token is one of ours: only the server holding the key can have computed it, so
    /// it shows the connection alive like any packet read.
    pub fn handle_quick_ack(&mut self, token: u32, now: Now) -> bool {
        let token = token & 0x7fff_ffff;
        let Some(position) = self.quick_acks.iter().position(|(stored, _, _)| *stored == token) else {
            return false;
        };
        let (_, ids, seq) = self.quick_acks.remove(position).expect("position is valid");
        for id in ids {
            self.mark_acknowledged(id);
        }
        if self.connected {
            self.last_read_at = self.last_read_at.max(now.mono);
        }
        self.note_arrived(seq, now);
        true
    }

    fn schedule_ack(&mut self, msg_id: i64, now: Now) {
        if self.http {
            self.send_before(now.mono + HTTP_ACK_DELAY);
        } else if self.to_ack.is_empty() {
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
        let mut mode = match self.received.peek(header.msg_id) {
            DuplicateCheck::New => Mode::Process,
            DuplicateCheck::Duplicate => Mode::AckOnly,
            DuplicateCheck::TooOld => Mode::Replay,
        };
        let budget = self.config.max_unpacked_bytes;
        let mut answers_awaited = false;
        match mode {
            Mode::Process => {
                self.observe_server_time(header.msg_id, now);
                if !self.is_within_time_window(header.msg_id, now) {
                    if self.has_freshness_proof(body, 0, &mut { budget }, &mut 0, now) {
                        self.reset_server_time(header.msg_id, now);
                    } else if self.awaited_answers.contains_key(&header.msg_id)
                        || self.answers_an_awaited_query(body, 0, &mut { budget }, &mut 0)
                    {
                        mode = Mode::Replay;
                        answers_awaited = true;
                    } else {
                        return Ok(());
                    }
                }
                self.received.check(header.msg_id);
            }
            Mode::Replay => {
                answers_awaited = self.awaited_answers.contains_key(&header.msg_id)
                    || self.answers_an_awaited_query(body, 0, &mut { budget }, &mut 0);
                if !self.is_within_time_window(header.msg_id, now) && !answers_awaited {
                    return Ok(());
                }
                self.received.check(header.msg_id);
            }
            Mode::AckOnly => {}
        }
        if mode == Mode::Process || answers_awaited {
            if !self.received_on_connection {
                let took = (now.mono - self.connected_at).max(0.0);
                self.first_answer_peak = took.max(self.first_answer_peak * 0.9);
                self.silent_cuts = 0;
            }
            self.peak_after_close = None;
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

    /// An answer whose msg_id can set the clock: one from this packet's own time, not an old answer
    /// taken as a replay or re-sent late inside a fresh container.
    fn answers_with_current_time(&self, context: &PacketContext, msg_id: i64, now: Now) -> bool {
        context.mode == Mode::Process && self.is_within_time_window(msg_id, now)
    }

    fn is_within_time_window(&self, msg_id: i64, now: Now) -> bool {
        if !self.time_synchronized {
            return true;
        }
        let server_time = self.server_time(now);
        let message_time = msg_id_time(msg_id);
        message_time >= server_time - MSG_ID_MAX_PAST_SECONDS && message_time <= server_time + MSG_ID_MAX_FUTURE_SECONDS
    }

    /// The packet carries the answer to a query this session still waits for. However old, it can only
    /// be the server's answer, held up somewhere (an outage longer than the time window), and is taken
    /// once like any other; its time says nothing about the server's clock.
    fn answers_an_awaited_query(&self, body: &[u8], depth: usize, budget: &mut usize, visited: &mut usize) -> bool {
        *visited += 1;
        if depth > MAX_NESTING_DEPTH || *visited > MAX_MESSAGES_PER_PACKET {
            return false;
        }
        match ServiceMessage::parse(body) {
            Ok(ServiceMessage::Container(children)) => {
                children.iter().any(|child| self.answers_an_awaited_query(child.body, depth + 1, budget, visited))
            }
            Ok(ServiceMessage::GzipPacked(packed)) => tlm::gunzip_within(packed, budget)
                .map(|unpacked| self.answers_an_awaited_query(&unpacked, depth + 1, budget, visited))
                .unwrap_or(false),
            Ok(ServiceMessage::MsgCopy(inner)) => self.answers_an_awaited_query(inner.body, depth + 1, budget, visited),
            Ok(ServiceMessage::RpcResult { req_msg_id, .. }) => self
                .by_msg_id
                .get(&req_msg_id)
                .and_then(|id| self.queries.get(id))
                .is_some_and(|query| query.msg_id == req_msg_id),
            _ => false,
        }
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
            Ok(ServiceMessage::RpcResult { req_msg_id, .. }) => self.was_sent_recently(req_msg_id, now),
            Ok(ServiceMessage::Pong { msg_id, ping_id }) => [msg_id, ping_id]
                .into_iter()
                .any(|id| self.pending_pings.contains_key(&id) && self.was_sent_recently(id, now)),
            Ok(ServiceMessage::BadMsgNotification { bad_msg_id, .. })
            | Ok(ServiceMessage::BadServerSalt { bad_msg_id, .. }) => self.was_sent_recently(bad_msg_id, now),
            Ok(ServiceMessage::MsgsStateInfo { req_msg_id, .. }) => {
                self.service_requests.contains_key(&req_msg_id) && self.was_sent_recently(req_msg_id, now)
            }
            Ok(ServiceMessage::FutureSalts { req_msg_id, .. }) => {
                self.future_salts_requests.contains(&req_msg_id) && self.was_sent_recently(req_msg_id, now)
            }
            Ok(ServiceMessage::MsgDetailedInfo { msg_id, .. }) => {
                self.by_msg_id.contains_key(&msg_id) && self.was_sent_recently(msg_id, now)
            }
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
        self.withdraw_asks_for(msg_id);
    }

    fn withdraw_asks_for(&mut self, answer: i64) {
        let mut finished = Vec::new();
        for (request_id, request) in self.service_requests.iter_mut() {
            if let ServiceRequest::ResendRequest { msg_ids, .. } = request {
                msg_ids.retain(|id| *id != answer);
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
                self.send_before(now.mono + LARGE_ANSWER_ACK_DELAY);
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
                self.on_new_session_created(context, msg_id, unique_id, first_msg_id, server_salt, now)
            }
            ServiceMessage::MsgsAck(msg_ids) => {
                for acked in msg_ids {
                    self.acknowledge(acked);
                }
            }
            ServiceMessage::MsgDetailedInfo { msg_id: query_msg_id, answer_msg_id, bytes, status } => {
                let answer = Some(answer_msg_id).filter(|id| *id != 0);
                self.on_message_info(msg_id, Some(query_msg_id), status, answer, bytes, now);
            }
            ServiceMessage::MsgNewDetailedInfo { answer_msg_id, bytes, .. } => {
                self.on_message_info(msg_id, None, 0, Some(answer_msg_id).filter(|id| *id != 0), bytes, now);
            }
            ServiceMessage::MsgsStateInfo { req_msg_id, info } => match self.service_requests.remove(&req_msg_id) {
                Some(ServiceRequest::StateRequest { msg_ids, .. }) => self.on_state_info(&msg_ids, info, now),
                Some(ServiceRequest::ResendRequest { msg_ids, .. }) => {
                    self.on_answers_unavailable(&msg_ids, info.len(), now)
                }
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
        let ping = self.pending_pings.remove(&ping_msg_id).or_else(|| self.pending_pings.remove(&ping_id));
        if let Some(ping) = ping {
            self.note_arrived(ping.packet_seq, now);
            let fresh = self.answers_with_current_time(context, msg_id, now);
            if fresh && msg_id < ping_msg_id.wrapping_sub(RESPONSE_TIME_SKEW) {
                self.reset_server_time(msg_id, now);
            }
            let rtt = (now.mono - ping.sent_at).max(0.0);
            if fresh && !ping.behind_large {
                self.rtt_peak = rtt.max(self.rtt_peak * 0.9);
                if self.rtt == 0.0 {
                    self.rtt = rtt;
                    self.rtt_var = rtt / 2.0;
                } else {
                    self.rtt_var = self.rtt_var * 0.75 + (self.rtt - rtt).abs() * 0.25;
                    self.rtt = self.rtt * 0.7 + rtt * 0.3;
                }
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
        if self.is_destroying_auth_key() {
            self.destroy_answered = true;
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
        if msg_id < req_msg_id.wrapping_sub(RESPONSE_TIME_SKEW) && self.answers_with_current_time(context, msg_id, now)
        {
            self.reset_server_time(msg_id, now);
        }
        if let Some(seq) = self
            .queries
            .get(&id)
            .filter(|query| query.msg_id == req_msg_id && query.connection_epoch == self.connection_epoch)
            .and_then(|query| query.arrival_seq)
        {
            self.note_arrived(seq, now);
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
                let gone: Vec<i64> = self
                    .awaited_answers
                    .iter()
                    .filter(|(_, awaited)| awaited.query == Some(id))
                    .map(|(answer, _)| *answer)
                    .collect();
                for answer in gone {
                    self.awaited_answers.remove(&answer);
                    self.to_resend_answer.retain(|id| *id != answer);
                    self.resend_individually.remove(&answer);
                    self.withdraw_asks_for(answer);
                }
            }
        }
        self.refresh_unknown_tracking();
    }

    fn on_new_session_created(
        &mut self,
        context: &mut PacketContext,
        notice_msg_id: i64,
        unique_id: i64,
        first_msg_id: i64,
        server_salt: i64,
        now: Now,
    ) {
        if context.mode == Mode::Replay || self.recent_unique_ids.contains(&unique_id) {
            return;
        }
        self.recent_unique_ids.push_back(unique_id);
        self.server_session_since = self.server_session_since.max(notice_msg_id);
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
        self.forget_awaited_answers_of(&resend);
        let old: Vec<i64> = self.awaited_answers.keys().copied().filter(|answer| *answer < notice_msg_id).collect();
        for answer in old {
            self.awaited_answers.remove(&answer);
            self.to_resend_answer.retain(|id| *id != answer);
            self.resend_individually.remove(&answer);
            self.withdraw_asks_for(answer);
        }
        context.deferred_resends.extend(resend.into_iter().map(|(msg_id, id)| (id, msg_id)));
        self.events.push_back(SessionEvent::ServerSessionReset { unique_id, first_msg_id });
    }

    fn on_message_info(
        &mut self,
        announcement: i64,
        query_msg_id: Option<i64>,
        status: i32,
        answer_msg_id: Option<i64>,
        bytes: i32,
        now: Now,
    ) {
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
                self.request_answer(answer, answered_query, announcement, usize::try_from(bytes).unwrap_or(0), now);
            }
        }
    }

    fn request_answer(&mut self, answer: i64, query: Option<QueryId>, announcement: i64, bytes: usize, now: Now) {
        if !self.awaited_answers.contains_key(&answer) && self.awaited_answers.len() >= MAX_AWAITED_ANSWERS {
            return;
        }
        let hold = if self.http { now.mono + HTTP_ANSWER_HOLD_MIN.max(self.rtt_estimate() * 1.5) } else { 0.0 };
        let announced_again = self.awaited_answers.contains_key(&answer);
        let entry = self.awaited_answers.entry(answer).or_insert(AwaitedAnswer {
            query,
            announced_by: announcement,
            expired_asks: 0,
            bytes,
            hold_until: hold,
            announced_at: now.mono,
        });
        if entry.query.is_none() {
            entry.query = query;
        }
        entry.bytes = bytes;
        entry.expired_asks = 0;
        entry.announced_by = entry.announced_by.max(announcement);
        let entry = *entry;
        if announced_again && self.is_answer_requested(answer) {
            return;
        }
        let due = if self.http { self.answer_hold_until(&entry) } else { now.mono + QUERY_DELAY };
        if self.to_resend_answer.is_empty() {
            self.send_before(due.max(now.mono + QUERY_DELAY));
        }
        if !self.to_resend_answer.contains(&answer) {
            self.to_resend_answer.push(answer);
            if self.to_resend_answer.len() > MAX_QUEUED_ACKS {
                let excess = self.to_resend_answer.len() - MAX_QUEUED_ACKS;
                self.to_resend_answer.drain(..excess);
            }
        }
    }

    /// HTTP: the answers at the tail of the queue whose announced sizes fit `HTTP_ANSWER_REQUEST_BYTES`,
    /// at least one.
    fn take_answers_for_http_request(&mut self) -> Vec<i64> {
        let mut bytes = 0usize;
        let mut count = 0;
        for id in self.to_resend_answer.iter().rev() {
            let size = self.awaited_answers.get(id).map_or(0, |awaited| awaited.bytes);
            if count > 0
                && (bytes.saturating_add(size) > HTTP_ANSWER_REQUEST_BYTES || count >= MAX_IDS_PER_SERVICE_MESSAGE)
            {
                break;
            }
            bytes = bytes.saturating_add(size);
            count += 1;
        }
        take_tail(&mut self.to_resend_answer, count)
    }

    /// A re-send request naming `answer` is out and has not expired yet; over HTTP, until the response
    /// to the request that carried it arrives, since the server re-sends the answer in some response.
    fn is_answer_requested(&self, answer: i64) -> bool {
        self.service_requests.iter().any(|(request_id, request)| match request {
            ServiceRequest::ResendRequest { msg_ids, .. } => {
                msg_ids.contains(&answer)
                    && (!self.http || self.http_packets.iter().any(|packet| packet.services.contains(request_id)))
            }
            ServiceRequest::StateRequest { .. } => false,
        })
    }

    /// The server executed the call whose answer `answer` is, and the answer cannot be had.
    fn give_up_answer(&mut self, answer: i64) {
        self.to_resend_answer.retain(|id| *id != answer);
        self.resend_individually.remove(&answer);
        self.withdraw_asks_for(answer);
        let Some(awaited) = self.awaited_answers.remove(&answer) else {
            return;
        };
        let Some(id) = awaited.query.filter(|_| awaited.announced_by >= self.server_session_since) else {
            return;
        };
        if self.awaited_answers.values().any(|awaited| awaited.query == Some(id)) {
            return;
        }
        let Some(msg_id) =
            self.queries.get(&id).filter(|query| query.state != QueryState::Pending).map(|query| query.msg_id)
        else {
            return;
        };
        self.complete_query(id, msg_id);
        self.events.push_back(SessionEvent::Error {
            id,
            code: 500,
            message: ANSWER_LOST.to_string(),
            response_msg_id: 0,
        });
    }

    /// The answers the old server session announced for queries that go again in the new one: they are
    /// gone with it, and a late reply about them must not touch the query sent again.
    fn forget_awaited_answers_of(&mut self, resent: &[(i64, QueryId)]) {
        let forgotten: Vec<i64> = self
            .awaited_answers
            .iter()
            .filter(|(_, awaited)| awaited.query.is_some_and(|id| resent.iter().any(|(_, other)| *other == id)))
            .map(|(answer, _)| *answer)
            .collect();
        for answer in forgotten {
            self.awaited_answers.remove(&answer);
            self.to_resend_answer.retain(|id| *id != answer);
            self.resend_individually.remove(&answer);
            self.withdraw_asks_for(answer);
        }
    }

    /// The server says it has none of `answers`, which a re-send request of `asked` answers named (some
    /// of them may have arrived since): a batch is asked for again one answer at a time first.
    fn on_answers_unavailable(&mut self, answers: &[i64], asked: usize, now: Now) {
        if answers.len() > 1 || asked > answers.len() {
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
            self.give_up_answer(*answer);
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

    /// A query the next packet would carry is large. A fresh connection then sends its first ping
    /// alone ahead of it, so the pong shows the path works within a round trip instead of after the
    /// transfer, and the grace cannot hide a blackholed connection.
    fn large_query_waiting(&self) -> bool {
        self.to_retransmit
            .iter()
            .chain(self.pending.iter())
            .take(self.config.max_container_queries.max(1))
            .any(|id| self.queries.get(id).is_some_and(|query| query.body.len() >= TRANSMIT_GRACE_MIN_SIZE))
    }

    /// Whether a ping may ride along with what goes out anyway. Except on the online main session,
    /// while answers keep arriving only once a quarter of the disconnect delay the server was given
    /// has passed: they show the connection alive, and on a starved uplink every byte counts. Never
    /// later than half that delay, so a ping that is due always may go.
    fn may_ping(&self, now: Now) -> bool {
        if self.http {
            return false;
        }
        let Some(at) = self.last_ping_at else {
            return true;
        };
        let every = self.ping_may_delay().min(self.last_ping_delay / 2.0);
        at + every < now.mono
            && (!self.reads_excuse_pings()
                || self.last_read_at + every < now.mono
                || at + self.server_ping_interval() / 2.0 < now.mono)
    }

    /// Answers arriving stand in for pings, except on the online main session: its disconnect delay
    /// is a few round trips, too short to leave room for a queue that builds up between two pings.
    fn reads_excuse_pings(&self) -> bool {
        !(self.online && self.config.is_main)
    }

    /// Half the disconnect delay the server was given with the last ping, or the one the next ping
    /// would give if that is shorter.
    fn server_ping_interval(&self) -> f64 {
        let given = (self.ping_disconnect_delay() + 2.0).min(self.last_ping_delay);
        (given / 2.0).max(self.ping_must_delay().min(self.last_ping_delay / 2.0))
    }

    fn must_ping(&self, now: Now) -> bool {
        !self.http && self.ping_due_at().is_none_or(|at| at < now.mono)
    }

    /// When a ping of its own must go out: after the ping-must delay, and no later than half the
    /// disconnect delay the server was given, after which the server would close the connection.
    /// Except on the online main session, answers arriving show the connection alive without one, so
    /// it also waits until reading has been quiet for the ping-may delay. None before the first ping.
    fn ping_due_at(&self) -> Option<f64> {
        let at = self.last_ping_at?;
        let every = self.ping_must_delay();
        let given = at + self.last_ping_delay / 2.0;
        if !self.reads_excuse_pings() {
            return Some((at + every).min(given));
        }
        let quiet = (self.last_read_at + self.ping_may_delay()).max(at + every);
        let server = at + self.server_ping_interval();
        Some(quiet.min(server).min(given))
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
            if self.is_destroying_auth_key() && !self.sent_destroy_auth_key {
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
        let mut transmit = f64::INFINITY;
        let server_time = self.server_time(now);
        let has_salt = self.salts.has_valid_salt(server_time);
        if has_salt {
            if let Some(at) = self.force_send_at {
                transmit = transmit.min(at);
            }
            if !self.http {
                match self.last_ping_at {
                    Some(_) => transmit = transmit.min(self.ping_due_at().unwrap_or(now.mono)),
                    None => transmit = transmit.min(now.mono),
                }
            }
        } else {
            match self.last_future_salts_at {
                Some(at) => transmit = transmit.min(at + FUTURE_SALTS_RETRY),
                None => transmit = transmit.min(now.mono),
            }
        }
        if let Some(change) = self.salts.next_change_time(server_time) {
            transmit = transmit.min(now.mono + (change - server_time));
        }
        let mut deadline = match self.drain_reset_at {
            Some(at) => transmit.max(at),
            None => transmit,
        };
        if !self.http {
            let grace = self.transmit_grace_until();
            let grace = grace.max(self.liveness_hold_until).max(self.fresh_hold_until());
            deadline = deadline.min((self.liveness_at() + self.ping_disconnect_delay() + 0.002).max(grace));
            deadline = deadline.min((self.last_read_at + self.read_disconnect_delay() + 0.002).max(grace));
        }
        if let Some(since) = self.unknown_since {
            deadline = deadline.min(since + STATE_REQUEST_RETRY);
        }
        if let Some(at) = self.drain_reset_at {
            deadline = deadline.min(at);
        }
        if let Some(&(_, _, due)) = self.http_awaiting_ack.front() {
            deadline = deadline.min(due);
        }
        if let Some(at) = self.probe_deadline() {
            deadline = deadline
                .min((at + 0.002).max(self.probe_held_until(now)))
                .min(self.backlog_sampled_at + BACKLOG_SAMPLE_INTERVAL);
        }
        for (request_id, request) in &self.service_requests {
            if self.ask_in_flight(*request_id) {
                if !self.http {
                    deadline = deadline.min(request.sent_at() + TCP_ASK_BACKSTOP + 0.002);
                }
                continue;
            }
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
        self.stretch_expired_grace(now);
        let transmitting = self.http
            || self.is_transmitting(now)
            || now.mono < self.liveness_hold_until
            || now.mono < self.fresh_hold_until();
        if !transmitting && self.liveness_at() + self.ping_disconnect_delay() < now.mono {
            self.note_silent_cut(now);
            return Err(SessionError::PingTimeout);
        }
        if !transmitting && self.last_read_at + self.read_disconnect_delay() < now.mono {
            self.note_silent_cut(now);
            return Err(SessionError::ReadTimeout);
        }
        if !self.http && now.mono >= self.probe_held_until(now) && self.probe_deadline().is_some_and(|at| at < now.mono)
        {
            if self.received_on_connection {
                self.probe_backoff = (self.probe_backoff * 2.0).min(PROBE_BACKOFF_MAX);
            }
            self.note_silent_cut(now);
            return Err(SessionError::ProbeTimeout);
        }
        if self.http {
            self.resend_unacknowledged_http(now);
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

    /// A re-send request still waiting for the server's reply does not expire after
    /// `STATE_REQUEST_RETRY`: over TCP until the reply, the connection's end or `TCP_ASK_BACKSTOP`, over
    /// HTTP while the response to the request that carried it is arriving.
    fn ask_in_flight(&self, request_id: i64) -> bool {
        matches!(self.service_requests.get(&request_id), Some(ServiceRequest::ResendRequest { .. }))
            && (!self.http || self.http_packets.iter().any(|packet| packet.services.contains(&request_id)))
    }

    fn expire_answer_requests(&mut self, now: Now) {
        let expired: Vec<i64> = self
            .service_requests
            .iter()
            .filter_map(|(request_id, request)| match request {
                ServiceRequest::ResendRequest { sent_at, .. }
                    if (sent_at + STATE_REQUEST_RETRY < now.mono && !self.ask_in_flight(*request_id))
                        || (!self.http && sent_at + TCP_ASK_BACKSTOP < now.mono) =>
                {
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
                let newer_ask_out = self.service_requests.values().any(|request| {
                    matches!(request, ServiceRequest::ResendRequest { msg_ids, .. } if msg_ids.contains(&answer))
                });
                if newer_ask_out || !self.http {
                    continue;
                }
                let Some(awaited) = self.awaited_answers.get_mut(&answer) else {
                    continue;
                };
                if awaited.expired_asks >= MAX_EXPIRED_ANSWER_ASKS {
                    continue;
                }
                awaited.expired_asks += 1;
                if !self.to_resend_answer.contains(&answer) {
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
        let transmit = self.flush_packet(now, rng, None, true);
        self.refresh_busy(now);
        transmit
    }

    /// HTTP: the next request, carrying `wait`. `force` makes one even with nothing else to send, to
    /// keep a long poll parked at the server; otherwise only when something is due.
    pub fn poll_http_transmit(
        &mut self,
        now: Now,
        rng: &mut impl SecureRandom,
        wait: HttpWait,
        force: bool,
        queries: bool,
    ) -> Option<Transmit> {
        debug_assert!(self.http, "HTTP requests on a stream transport");
        self.sync_wall_clock(now);
        self.finish_drain_reset(now, rng);
        let draining = self.drain_reset_at.is_some();
        if (draining && (queries || !force)) || !self.connected || (!force && !self.must_flush(now)) {
            return None;
        }
        let transmit = self.flush_packet(now, rng, Some(wait), queries);
        self.refresh_busy(now);
        transmit
    }

    /// Queries are waiting to go out, fresh or again, and may.
    pub fn has_queries_to_send(&self) -> bool {
        self.pending.iter().chain(self.to_retransmit.iter()).any(|id| !self.is_gated(*id))
    }

    /// The key is temporary and not bound yet: no query goes out until `start_bind`'s does and is
    /// answered.
    pub fn hold_until_bound(&mut self) {
        self.bind_gate = true;
    }

    pub fn is_bound(&self) -> bool {
        !self.bind_gate
    }

    pub fn bind_query(&self) -> Option<QueryId> {
        self.bind.as_ref().map(|(id, _)| *id)
    }

    /// Sends `auth.bindTempAuthKey` ahead of everything else and holds every other query until
    /// `finish_bind`.
    pub fn start_bind(&mut self, id: QueryId, request: BindRequest, now: Now) {
        if let Some((previous, _)) = self.bind.take() {
            self.cancel(previous);
        }
        self.cancel(id);
        self.queries.insert(
            id,
            Query {
                body: Vec::new(),
                options: QueryOptions::default(),
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
                arrival_seq: None,
            },
        );
        self.pending_queries += 1;
        self.pending.push_front(id);
        self.bind = Some((id, request));
        self.bind_gate = true;
        self.send_before(now.mono);
    }

    /// The bind query was answered: on success the other queries may go.
    pub fn finish_bind(&mut self, id: QueryId, bound: bool, now: Now) {
        if self.bind.as_ref().is_none_or(|(bind, _)| *bind != id) {
            return;
        }
        self.bind = None;
        if bound {
            self.bind_gate = false;
            if !self.pending.is_empty() || !self.to_retransmit.is_empty() {
                self.send_before(now.mono);
            }
        }
    }

    /// Held back by the bind gate: everything but the bind query while the key is not bound.
    /// A query that may not go yet: before the temporary key is bound only the bind may, and nothing
    /// goes while the key is being destroyed (as in tdlib, a destroying session sends no queries).
    fn is_gated(&self, id: QueryId) -> bool {
        (self.bind_gate && self.bind.as_ref().is_none_or(|(bind, _)| *bind != id)) || self.is_destroying_auth_key()
    }

    fn bind_body(&self, id: QueryId, msg_id: i64, rng: &mut impl SecureRandom) -> Option<Vec<u8>> {
        let (bind, request) = self.bind.as_ref()?;
        if *bind != id {
            return None;
        }
        let inner = tlm::BindAuthKeyInner {
            nonce: request.nonce,
            temp_auth_key_id: self.auth_key.id() as i64,
            perm_auth_key_id: request.perm_key.id() as i64,
            temp_session_id: self.session_id,
            expires_at: request.expires_at,
        };
        let mut writer = Writer::with_capacity(40);
        crate::tl::TlWrite::write_to(&inner, &mut writer);
        let header =
            MessageHeader { salt: rng.next_u64() as i64, session_id: rng.next_u64() as i64, msg_id, seq_no: 0 };
        let encrypted = encrypt_message_v1(&request.perm_key, &header, &writer.into_inner(), rng);
        let mut body = Writer::with_capacity(32 + encrypted.len());
        body.write_u32(ids::AUTH_BIND_TEMP_AUTH_KEY);
        body.write_i64(request.perm_key.id() as i64);
        body.write_i64(request.nonce);
        body.write_i32(request.expires_at);
        body.write_bytes(&encrypted);
        Some(body.into_inner())
    }

    /// A reset waits for the answers the old session may still get.
    pub fn is_draining(&self) -> bool {
        self.drain_reset_at.is_some()
    }

    /// HTTP: whether something is due to go out now; a drain reset that is due goes with the next
    /// transmit, which nothing else would ask for over HTTP.
    pub fn wants_http_transmit(&mut self, now: Now) -> bool {
        match self.drain_reset_at {
            Some(at) => now.mono >= at || !self.awaits_old_session_answers(),
            None => self.must_flush(now),
        }
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

    fn flush_packet(
        &mut self,
        now: Now,
        rng: &mut impl SecureRandom,
        http_wait: Option<HttpWait>,
        queries: bool,
    ) -> Option<Transmit> {
        let server_time = self.server_time(now);
        let has_salt = self.salts.has_valid_salt(server_time);

        let mut messages: Vec<OutgoingMessage> = Vec::new();
        let mut query_messages: Vec<(QueryId, usize)> = Vec::new();
        let mut wants_quick_ack = false;
        let mut force_container = false;
        self.packet_seq += 1;
        let packet_seq = self.packet_seq;
        let probe_first = has_salt && !self.received_on_connection && self.may_ping(now) && self.large_query_waiting();

        let mut total = 0usize;
        if queries && has_salt && !probe_first && !self.to_retransmit.is_empty() {
            let epoch = self.connection_epoch;
            let mut deferred = Vec::new();
            let mut held = Vec::new();
            for id in std::mem::take(&mut self.to_retransmit) {
                if self.is_gated(id) {
                    held.push(id);
                    continue;
                }
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
                query.arrival_seq = None;
                total += body.len();
                wants_quick_ack |= query.options.quick_ack;
                query_messages.push((id, messages.len()));
                messages.push(OutgoingMessage { msg_id: query.msg_id, seq_no: query.seq_no, body });
                force_container = true;
            }
            deferred.extend(held);
            self.to_retransmit = deferred;
            self.refresh_unknown_tracking();
        }

        if self.bind_gate
            && let Some((bind, _)) = &self.bind
            && let Some(position) = self.pending.iter().position(|id| id == bind)
            && position > 0
        {
            let id = self.pending.remove(position).expect("position is valid");
            self.pending.push_front(id);
        }
        if queries && has_salt && !probe_first && self.to_retransmit.iter().all(|id| self.is_gated(*id)) {
            let mut sent_now: HashMap<QueryId, i64> = HashMap::new();
            while let Some(&id) = self.pending.front() {
                if query_messages.len() >= self.config.max_container_queries {
                    break;
                }
                if self.is_gated(id) {
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
                let bind_body = self.bind_body(id, msg_id, rng);
                let query = self.queries.get_mut(&id).expect("query exists");
                if let Some(body) = bind_body {
                    query.body = body;
                }
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
                query.arrival_seq = Some(packet_seq);
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
                let delay = (self.ping_disconnect_delay() + 2.0) as i32;
                self.last_ping_delay = f64::from(delay);
                tlm::write_ping_delay_disconnect(&mut writer, msg_id, delay);
            } else {
                tlm::write_ping(&mut writer, msg_id);
            }
            self.last_ping_at = Some(now.mono);
            self.pending_pings.insert(msg_id, PendingPing { sent_at: now.mono, packet_seq, behind_large: false });
            if self.pending_pings.len() > MAX_PENDING_PINGS
                && let Some(oldest) = self.pending_pings.keys().min().copied()
            {
                self.pending_pings.remove(&oldest);
            }
            ping_msg_id = msg_id;
            messages.push(OutgoingMessage { msg_id, seq_no, body: writer.into_inner() });
        }

        let mut future_salts_msg_id = None;
        if self.salts.needs_future_salts(server_time)
            && self.last_future_salts_at.is_none_or(|at| at + FUTURE_SALTS_RETRY < now.mono)
        {
            self.last_future_salts_at = Some(now.mono);
            let mut writer = Writer::with_capacity(8);
            tlm::write_get_future_salts(&mut writer, FUTURE_SALTS_COUNT);
            let msg_id = self.push_service(&mut messages, writer.into_inner(), now, rng);
            future_salts_msg_id = Some(msg_id);
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
        let mut held_answers = Vec::new();
        if self.http && !self.to_resend_answer.is_empty() {
            let mut due = Vec::new();
            for id in std::mem::take(&mut self.to_resend_answer) {
                let hold = self.awaited_answers.get(&id).map_or(0.0, |awaited| self.answer_hold_until(awaited));
                if hold > now.mono { held_answers.push(id) } else { due.push(id) }
            }
            self.to_resend_answer = due;
        }
        if has_salt && !self.to_resend_answer.is_empty() {
            let awaited = &self.awaited_answers;
            self.resend_individually.retain(|id| awaited.contains_key(id));
            let ids = if self.http {
                self.take_answers_for_http_request()
            } else {
                take_tail(&mut self.to_resend_answer, MAX_IDS_PER_SERVICE_MESSAGE)
            };
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
            wants_quick_ack |= !drops.is_empty() && !self.unconfirmed_large.is_empty();
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

        let destroys_auth_key = has_salt && self.is_destroying_auth_key() && !self.sent_destroy_auth_key;
        if destroys_auth_key {
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

        if let Some(wait) = http_wait {
            let mut writer = Writer::with_capacity(16);
            tlm::write_http_wait(&mut writer, wait.max_delay, wait.wait_after, wait.max_wait);
            self.push_service(&mut messages, writer.into_inner(), now, rng);
        }

        let held_until = held_answers
            .iter()
            .filter_map(|id| self.awaited_answers.get(id))
            .map(|awaited| self.answer_hold_until(awaited))
            .reduce(f64::min);
        self.to_resend_answer.extend(held_answers);

        let pending_held = self.pending.iter().all(|id| self.is_gated(*id));
        let retransmit_held = self.to_retransmit.iter().all(|id| self.is_gated(*id));
        let nothing_left = pending_held
            && self.to_ack.is_empty()
            && self.to_state_request.is_empty()
            && self.to_resend_answer.is_empty()
            && self.to_drop_answer.is_empty()
            && self.to_state_info_reply.is_empty()
            && self.to_pong.is_empty()
            && retransmit_held;
        let only_held = held_until.is_some()
            && pending_held
            && self.to_ack.is_empty()
            && self.to_state_request.is_empty()
            && self.to_drop_answer.is_empty()
            && self.to_state_info_reply.is_empty()
            && self.to_pong.is_empty()
            && retransmit_held;
        if nothing_left {
            self.force_send_at = None;
        } else if only_held {
            self.force_send_at = held_until;
        }

        if messages.is_empty() {
            return None;
        }

        for message in &messages {
            self.remember_sent(message.msg_id, now);
        }

        let message_ids: Vec<i64> = messages.iter().map(|message| message.msg_id).collect();
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
        self.remember_sent(outer_msg_id, now);

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
        let mut service_ids: Vec<i64> = resend_requests.iter().map(|(msg_id, _)| *msg_id).collect();
        if let Some((msg_id, ids)) = state_request {
            service_ids.push(msg_id);
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
        if self.http {
            self.http_packets.push_back(HttpPacket {
                seq: packet_seq,
                queries: query_messages.iter().map(|(id, index)| (*id, message_ids[*index])).collect(),
                services: service_ids,
                future_salts: future_salts_msg_id,
                destroys_auth_key,
            });
            while self.http_packets.len() > MAX_TRACKED_HTTP_PACKETS {
                self.http_packets.pop_front();
            }
            return Some(Transmit {
                data: packet.data,
                quick_ack_token: None,
                msg_id: outer_msg_id,
                contains_queries: !query_messages.is_empty(),
                packet_seq,
            });
        }
        let large = packet.data.len() >= TRANSMIT_GRACE_MIN_SIZE;
        if large {
            if self.unconfirmed_large.is_empty() {
                self.delivered_at = now.mono;
            }
            self.unconfirmed_large.push_back(LargePacket {
                seq: packet_seq,
                bytes: packet.data.len(),
                sent_at: now.mono,
                delivered: self.delivered,
                delivered_at: self.delivered_at,
            });
            self.refresh_transmit_grace();
        }
        if let Some(ping) = self.pending_pings.get_mut(&ping_msg_id) {
            ping.behind_large = !self.unconfirmed_large.is_empty();
        }
        let answer_confirms = query_messages
            .iter()
            .any(|(id, _)| self.queries.get(id).is_some_and(|query| query.arrival_seq == Some(packet_seq)));
        let quick_ack_token = if wants_quick_ack || (large && (!answer_confirms || !self.awaits_large_quick_ack())) {
            let token = packet.quick_ack_token & 0x7fff_ffff;
            let ids: Vec<QueryId> = query_messages
                .iter()
                .filter(|(id, _)| self.queries.get(id).is_some_and(|query| query.options.quick_ack))
                .map(|(id, _)| *id)
                .collect();
            self.quick_acks.push_back((token, ids, packet_seq));
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
            packet_seq,
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
