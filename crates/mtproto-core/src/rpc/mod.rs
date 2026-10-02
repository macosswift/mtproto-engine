mod wrap;

use std::collections::{BTreeMap, HashMap, VecDeque};

pub use wrap::{
    ApiEnvironment, ClientProxy, INIT_CONNECTION, INPUT_CLIENT_PROXY, INVOKE_WITH_APNS_SECRET, INVOKE_WITH_RECAPTCHA,
    Verification, flood_wait_seconds, wrap_request,
};

use crate::crypto::SecureRandom;
use crate::msg_id::msg_id_time;
use crate::session::{
    CancelOutcome, DestroyAuthKeyOutcome, Now, PROTOCOL_ERROR_PREFIX, QueryId, QueryOptions, RESPONSE_UNPACK_FAILED,
    ServerSalt, Session, SessionError, SessionEvent, Transmit,
};

pub const SERVER_ERROR_RETRY_DELAY: f64 = 2.0;
pub const SERVER_ERROR_MAX_RETRY_DELAY: f64 = 16.0;
pub const LARGE_RESPONSE_THRESHOLD: u32 = 512 * 1024;
pub const MAX_CONNECTION_NOT_INITED_RETRIES: u32 = 5;
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const REQUEST_INVALID_SIZE: &str = "REQUEST_INVALID_SIZE";
pub const MIN_FLOOD_WAIT_SECONDS: i64 = 1;
pub const MAX_FLOOD_WAIT_SECONDS: i64 = 14 * 24 * 60 * 60;
pub const TEMPORARY_KEY_RETRY_DELAY: f64 = 1.0;
pub const TEMPORARY_KEY_MAX_RETRY_DELAY: f64 = 30.0;
pub const TEMPORARY_KEY_REPORT_INTERVAL: f64 = 30.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub u64);

impl From<RequestId> for QueryId {
    fn from(value: RequestId) -> Self {
        QueryId(value.0)
    }
}

impl From<QueryId> for RequestId {
    fn from(value: QueryId) -> Self {
        RequestId(value.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFlags {
    pub automatic_flood_wait: bool,
    pub report_flood_wait: bool,
    pub retry_server_errors: bool,
    pub quick_ack: bool,
    pub progress: bool,
    pub timeout_timer: bool,
    pub expected_response_size: u32,
    pub without_updates: bool,
    pub delegate_retry_decisions: bool,
}

impl Default for RequestFlags {
    fn default() -> Self {
        Self {
            automatic_flood_wait: true,
            report_flood_wait: false,
            retry_server_errors: true,
            quick_ack: false,
            progress: false,
            timeout_timer: false,
            expected_response_size: 0,
            without_updates: false,
            delegate_retry_decisions: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcRequest {
    pub id: RequestId,
    pub body: Vec<u8>,
    pub flags: RequestFlags,
    pub invoke_after: Option<RequestId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationKind {
    Apns { nonce: String },
    Recaptcha { method: String, site_key: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RpcEvent {
    Completed {
        id: RequestId,
        body: Vec<u8>,
        response_time: f64,
        duration: f64,
    },
    Failed {
        id: RequestId,
        code: i32,
        message: String,
        response_time: f64,
        duration: f64,
    },
    Acknowledged {
        id: RequestId,
    },
    FloodWaitReported {
        id: RequestId,
        message: String,
    },
    AuthorizationRequired {
        message: String,
    },
    SoftAuthReset {
        message: String,
    },
    AuthTokenRequired,
    TemporaryKeyRejected,
    InitHashStored {
        hash: String,
    },
    InitHashCleared,
    VerificationRequired {
        id: RequestId,
        kind: VerificationKind,
    },
    UpdatesReset,
    Update {
        body: Vec<u8>,
    },
    TimeDifferenceUpdated {
        difference: f64,
    },
    SaltsUpdated {
        salts: Vec<ServerSalt>,
    },
    Pong {
        rtt: f64,
    },
    ConnectionShouldReset,
    AuthKeyDestroyed {
        outcome: DestroyAuthKeyOutcome,
    },
    RetryDecisionRequired {
        id: RequestId,
        code: i32,
        message: String,
        flood_wait_seconds: i64,
        flood_wait_text: Option<String>,
        server_errors: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Main,
    Worker { requires_auth_token: bool },
    Cdn,
}

#[derive(Debug, Clone)]
struct RequestState {
    request: RpcRequest,
    seq: u64,
    wrapped_with_init: bool,
    in_session: bool,
    not_before: f64,
    server_errors: u32,
    not_inited_retries: u32,
    waiting_for_token: bool,
    waiting_for_dependency: Option<RequestId>,
    verification: Option<Verification>,
    pending_verification: bool,
    sent_at_unix: f64,
    flood_wait_seconds: i64,
    flood_wait_text: Option<String>,
    pending_decision: Option<PendingDecision>,
    rejected_key: Option<u64>,
    temporary_key_rejections: u32,
}

#[derive(Debug, Clone)]
struct PendingDecision {
    code: i32,
    message: String,
    delay: f64,
    response_time: f64,
}

pub struct RpcClient {
    session: Session,
    role: SessionRole,
    environment: Option<ApiEnvironment>,
    stored_init_hash: Option<String>,
    requests: HashMap<RequestId, RequestState>,
    order: BTreeMap<u64, RequestId>,
    parked: BTreeMap<u64, RequestId>,
    next_seq: u64,
    timeout_timer_in_session: usize,
    events: VecDeque<RpcEvent>,
    auth_token_ready: bool,
    temporary_key_reported: Option<(u64, f64)>,
}

impl RpcClient {
    pub fn new(
        session: Session,
        role: SessionRole,
        environment: Option<ApiEnvironment>,
        stored_init_hash: Option<String>,
    ) -> Self {
        Self {
            session,
            role,
            environment,
            stored_init_hash,
            requests: HashMap::new(),
            order: BTreeMap::new(),
            parked: BTreeMap::new(),
            next_seq: 0,
            timeout_timer_in_session: 0,
            events: VecDeque::new(),
            auth_token_ready: true,
            temporary_key_reported: None,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn environment(&self) -> Option<&ApiEnvironment> {
        self.environment.as_ref()
    }

    pub fn stored_init_hash(&self) -> Option<&str> {
        self.stored_init_hash.as_deref()
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn contains(&self, id: RequestId) -> bool {
        self.requests.contains_key(&id)
    }

    pub fn has_timeout_timer_requests(&self) -> bool {
        self.timeout_timer_in_session > 0
    }

    pub fn needs_initialization(&self) -> bool {
        match &self.environment {
            Some(environment) => self.stored_init_hash.as_deref() != Some(environment.init_hash.as_str()),
            None => false,
        }
    }

    pub fn set_stored_init_hash(&mut self, hash: Option<String>) {
        self.stored_init_hash = hash;
    }

    pub fn update_environment(&mut self, environment: ApiEnvironment, noop_request: Option<RpcRequest>, now: Now) {
        let changed =
            self.environment.as_ref().map(|current| current.init_hash.as_str()) != Some(environment.init_hash.as_str());
        self.environment = Some(environment);
        if changed && let Some(noop) = noop_request {
            self.send(noop, now);
        }
    }

    pub fn set_auth_token_ready(&mut self, ready: bool, now: Now) {
        self.auth_token_ready = ready;
        if ready {
            let waiting: Vec<RequestId> =
                self.requests.iter().filter(|(_, state)| state.waiting_for_token).map(|(id, _)| *id).collect();
            for id in waiting {
                if let Some(state) = self.requests.get_mut(&id) {
                    state.waiting_for_token = false;
                }
            }
            self.dispatch_ready(now);
        }
    }

    pub fn send(&mut self, request: RpcRequest, now: Now) {
        let id = request.id;
        if self.requests.contains_key(&id) {
            return;
        }
        if request.body.len() > MAX_REQUEST_BYTES || !request.body.len().is_multiple_of(4) || request.body.len() < 4 {
            self.events.push_back(RpcEvent::Failed {
                id,
                code: 400,
                message: REQUEST_INVALID_SIZE.to_string(),
                response_time: now.unix,
                duration: 0.0,
            });
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.requests.insert(
            id,
            RequestState {
                request,
                seq,
                wrapped_with_init: false,
                in_session: false,
                not_before: 0.0,
                server_errors: 0,
                not_inited_retries: 0,
                waiting_for_token: false,
                waiting_for_dependency: None,
                verification: None,
                pending_verification: false,
                sent_at_unix: now.unix,
                flood_wait_seconds: 0,
                flood_wait_text: None,
                pending_decision: None,
                rejected_key: None,
                temporary_key_rejections: 0,
            },
        );
        self.order.insert(seq, id);
        self.parked.insert(seq, id);
        self.dispatch_ready(now);
    }

    pub fn decide_retry(&mut self, id: RequestId, retry: bool, now: Now) {
        let Some(decision) = self.requests.get_mut(&id).and_then(|state| state.pending_decision.take()) else {
            return;
        };
        if retry {
            self.requeue(id, decision.delay, now);
            self.dispatch_ready(now);
        } else if let Some(state) = self.finish(id) {
            self.events.push_back(RpcEvent::Failed {
                id,
                code: decision.code,
                message: decision.message,
                response_time: decision.response_time,
                duration: (now.unix - state.sent_at_unix).max(0.0),
            });
        }
    }

    pub fn cancel(&mut self, id: RequestId, now: Now) -> bool {
        let Some(state) = self.remove_request(id) else {
            return false;
        };
        if state.in_session
            && let CancelOutcome::RemovedInFlight { msg_id } = self.session.cancel(id.into())
        {
            self.session.drop_answer(msg_id, now);
        }
        self.dispatch_ready(now);
        true
    }

    pub fn resolve_verification(&mut self, id: RequestId, verification: Verification, now: Now) {
        if let Some(state) = self.requests.get_mut(&id) {
            state.verification = Some(verification);
            state.pending_verification = false;
        }
        self.dispatch_ready(now);
    }

    pub fn fail_request(&mut self, id: RequestId, code: i32, message: &str, now: Now) {
        if let Some(state) = self.remove_request(id) {
            if state.in_session {
                self.session.cancel(id.into());
            }
            self.events.push_back(RpcEvent::Failed {
                id,
                code,
                message: message.to_string(),
                response_time: now.unix + self.session.time_difference(),
                duration: (now.unix - state.sent_at_unix).max(0.0),
            });
            self.dispatch_ready(now);
        }
    }

    pub fn destroy_auth_key(&mut self, now: Now) {
        self.session.destroy_auth_key(now);
    }

    pub fn invalidate_initialization(&mut self) {
        if self.stored_init_hash.take().is_some() {
            self.events.push_back(RpcEvent::InitHashCleared);
        }
    }

    fn is_ready(&self, state: &RequestState, now: Now) -> bool {
        if state.in_session || state.waiting_for_token || state.pending_verification || state.pending_decision.is_some()
        {
            return false;
        }
        let key_replaced = state.rejected_key.is_some_and(|key| key != self.session.auth_key_id());
        if state.not_before > now.mono && !key_replaced {
            return false;
        }
        if let Some(dependency) = state.waiting_for_dependency
            && self.requests.contains_key(&dependency)
        {
            return false;
        }
        if matches!(self.role, SessionRole::Worker { requires_auth_token: true }) && !self.auth_token_ready {
            return false;
        }
        true
    }

    fn dispatch_ready(&mut self, now: Now) {
        self.debug_check_bookkeeping();
        if self.parked.is_empty() {
            return;
        }
        let candidates: Vec<RequestId> = self.parked.values().copied().collect();
        let initialize = self.needs_initialization();
        for id in candidates {
            let ready = self.requests.get(&id).is_some_and(|state| self.is_ready(state, now));
            if !ready {
                continue;
            }
            let invoke_after = self
                .requests
                .get(&id)
                .and_then(|state| state.request.invoke_after)
                .filter(|dependency| self.requests.get(dependency).is_some_and(|other| other.in_session))
                .map(QueryId::from);
            let environment = self.environment.as_ref();
            let state = self.requests.get_mut(&id).expect("ready request exists");
            let without_updates = state.request.flags.without_updates
                || environment.is_some_and(|environment| environment.disable_updates);
            let body = wrap_request(
                &state.request.body,
                if initialize { environment } else { None },
                without_updates,
                state.verification.as_ref(),
            );
            state.wrapped_with_init = initialize;
            state.in_session = true;
            state.rejected_key = None;
            state.sent_at_unix = now.unix;
            if state.request.flags.timeout_timer {
                self.timeout_timer_in_session += 1;
            }
            self.parked.remove(&state.seq);
            let options = QueryOptions { quick_ack: state.request.flags.quick_ack, invoke_after };
            self.session.send(id.into(), body, options, now);
        }
    }

    fn leave_session(&mut self, id: RequestId) {
        if let Some(state) = self.requests.get_mut(&id) {
            if state.in_session {
                state.in_session = false;
                if state.request.flags.timeout_timer {
                    self.timeout_timer_in_session -= 1;
                }
            }
            self.parked.insert(state.seq, id);
        }
    }

    fn remove_request(&mut self, id: RequestId) -> Option<RequestState> {
        let state = self.requests.remove(&id)?;
        self.order.remove(&state.seq);
        self.parked.remove(&state.seq);
        if state.in_session && state.request.flags.timeout_timer {
            self.timeout_timer_in_session -= 1;
        }
        Some(state)
    }

    #[cfg(debug_assertions)]
    fn debug_check_bookkeeping(&self) {
        assert_eq!(self.order.len(), self.requests.len(), "every request is ordered");
        let mut parked = 0;
        let mut timeout_timer = 0;
        for (seq, id) in &self.order {
            let state = self.requests.get(id).expect("ordered request exists");
            assert_eq!(state.seq, *seq, "order key matches the request");
            assert_eq!(self.parked.contains_key(seq), !state.in_session, "parked iff not in session");
            parked += usize::from(!state.in_session);
            timeout_timer += usize::from(state.in_session && state.request.flags.timeout_timer);
        }
        assert_eq!(parked, self.parked.len(), "parked holds only live requests");
        assert_eq!(timeout_timer, self.timeout_timer_in_session, "timeout timer count");
    }

    #[cfg(not(debug_assertions))]
    fn debug_check_bookkeeping(&self) {}

    fn requeue(&mut self, id: RequestId, delay: f64, now: Now) {
        if let Some(state) = self.requests.get_mut(&id) {
            state.not_before = now.mono + delay.max(0.0);
        }
        self.leave_session(id);
    }

    fn finish(&mut self, id: RequestId) -> Option<RequestState> {
        self.remove_request(id)
    }

    fn handle_session_event(&mut self, event: SessionEvent, now: Now) {
        match event {
            SessionEvent::Result { id, body, response_msg_id, .. } => {
                let id = RequestId::from(id);
                if let Some(state) = self.finish(id) {
                    if state.wrapped_with_init
                        && let Some(environment) = &self.environment
                        && self.stored_init_hash.as_deref() != Some(environment.init_hash.as_str())
                    {
                        self.stored_init_hash = Some(environment.init_hash.clone());
                        self.events.push_back(RpcEvent::InitHashStored { hash: environment.init_hash.clone() });
                    }
                    self.events.push_back(RpcEvent::Completed {
                        id,
                        body,
                        response_time: msg_id_time(response_msg_id),
                        duration: (now.unix - state.sent_at_unix).max(0.0),
                    });
                }
            }
            SessionEvent::Error { id, code, message, response_msg_id } => {
                self.handle_error(RequestId::from(id), code, message, msg_id_time(response_msg_id), now)
            }
            SessionEvent::Acknowledged { id } => {
                let id = RequestId::from(id);
                if self.requests.get(&id).is_some_and(|state| state.request.flags.quick_ack) {
                    self.events.push_back(RpcEvent::Acknowledged { id });
                }
            }
            SessionEvent::Update { .. }
            | SessionEvent::ServerSessionReset { .. }
            | SessionEvent::LocalSessionReset { .. }
            | SessionEvent::UpdatesLost
                if self.role == SessionRole::Cdn => {}
            SessionEvent::Update { body, .. } => {
                if is_updates_too_long(&body) {
                    self.events.push_back(RpcEvent::UpdatesReset);
                }
                self.events.push_back(RpcEvent::Update { body });
            }
            SessionEvent::ServerSessionReset { .. }
            | SessionEvent::LocalSessionReset { .. }
            | SessionEvent::UpdatesLost => {
                self.events.push_back(RpcEvent::UpdatesReset);
            }
            SessionEvent::TimeDifferenceUpdated { difference, .. } => {
                self.events.push_back(RpcEvent::TimeDifferenceUpdated { difference });
            }
            SessionEvent::SaltsUpdated { salts } => {
                self.events.push_back(RpcEvent::SaltsUpdated { salts });
            }
            SessionEvent::Pong { rtt } => self.events.push_back(RpcEvent::Pong { rtt }),
            SessionEvent::DroppedAnswerTooLarge { .. } => self.events.push_back(RpcEvent::ConnectionShouldReset),
            SessionEvent::DestroyAuthKey { outcome } => self.events.push_back(RpcEvent::AuthKeyDestroyed { outcome }),
        }
    }

    fn handle_error(&mut self, id: RequestId, code: i32, message: String, response_time: f64, now: Now) {
        let Some(state) = self.requests.get(&id) else {
            return;
        };
        let flags = state.request.flags;
        let dependency = state.request.invoke_after;
        let is_main = self.role == SessionRole::Main;

        if is_local_terminal_error(&message) {
            self.surface(id, code, message, response_time, now);
            return;
        }
        if code == 401 && message == "AUTH_KEY_PERM_EMPTY" {
            self.park_for_temporary_key(id, now);
            return;
        }
        if code == 401 && !message.contains("SESSION_PASSWORD_NEEDED") {
            match self.role {
                SessionRole::Main => {
                    self.events.push_back(RpcEvent::AuthorizationRequired { message: message.clone() })
                }
                SessionRole::Worker { requires_auth_token: true } => {
                    self.events.push_back(RpcEvent::AuthTokenRequired);
                    if message.contains("SESSION_REVOKED") || message.contains("AUTH_KEY_UNREGISTERED") {
                        self.auth_token_ready = false;
                        if let Some(state) = self.requests.get_mut(&id) {
                            state.waiting_for_token = true;
                        }
                        self.leave_session(id);
                        return;
                    }
                }
                _ => {}
            }
        }
        if (message == "MSG_WAIT_TIMEOUT" || message == "MSG_WAIT_FAILED") && dependency.is_some() {
            if let Some(state) = self.requests.get_mut(&id) {
                state.waiting_for_dependency = dependency;
            }
            self.requeue(id, 0.0, now);
            return;
        }
        if is_server_error(code) {
            let state = self.requests.get_mut(&id).expect("request exists");
            state.server_errors += 1;
            if flags.delegate_retry_decisions {
                let server_errors = state.server_errors;
                let flood_wait_seconds = state.flood_wait_seconds;
                let flood_wait_text = state.flood_wait_text.clone();
                state.pending_decision = Some(PendingDecision {
                    code,
                    message: message.clone(),
                    delay: server_error_delay(server_errors),
                    response_time,
                });
                self.leave_session(id);
                self.events.push_back(RpcEvent::RetryDecisionRequired {
                    id,
                    code,
                    message,
                    flood_wait_seconds,
                    flood_wait_text,
                    server_errors,
                });
                return;
            }
            if flags.retry_server_errors {
                let delay = server_error_delay(state.server_errors);
                self.requeue(id, delay, now);
                return;
            }
        }
        let is_flood = (code == 420 && !message.contains("FROZEN_METHOD_INVALID"))
            || message.contains("FLOOD_WAIT_")
            || message.contains("FLOOD_PREMIUM_WAIT_");
        if is_flood && let Some(seconds) = flood_wait_seconds(&message) {
            let delay = seconds.clamp(MIN_FLOOD_WAIT_SECONDS, MAX_FLOOD_WAIT_SECONDS) as f64;
            if flags.delegate_retry_decisions {
                let state = self.requests.get_mut(&id).expect("request exists");
                state.flood_wait_seconds = seconds;
                state.flood_wait_text = Some(message.clone());
                state.pending_decision = Some(PendingDecision { code, message: message.clone(), delay, response_time });
                let server_errors = state.server_errors;
                self.leave_session(id);
                self.events.push_back(RpcEvent::RetryDecisionRequired {
                    id,
                    code,
                    message: message.clone(),
                    flood_wait_seconds: seconds,
                    flood_wait_text: Some(message),
                    server_errors,
                });
                return;
            }
            if flags.report_flood_wait {
                self.events.push_back(RpcEvent::FloodWaitReported { id, message: message.clone() });
            }
            if flags.automatic_flood_wait {
                self.requeue(id, delay, now);
                return;
            }
        }
        if code == 400 && (message.contains("CONNECTION_NOT_INITED") || message.contains("CONNECTION_LAYER_INVALID")) {
            let state = self.requests.get_mut(&id).expect("request exists");
            state.not_inited_retries += 1;
            if state.not_inited_retries <= MAX_CONNECTION_NOT_INITED_RETRIES {
                self.invalidate_initialization();
                self.requeue(id, 0.0, now);
                return;
            }
        }
        if code == 403 {
            if let Some(nonce) = message.strip_prefix("APNS_VERIFY_CHECK_") {
                let kind = VerificationKind::Apns { nonce: nonce.to_string() };
                self.park_for_verification(id, kind, now);
                return;
            }
            if let Some(rest) = message.strip_prefix("RECAPTCHA_CHECK_")
                && let Some((method, site_key)) = rest.split_once("__")
            {
                let kind = VerificationKind::Recaptcha { method: method.to_string(), site_key: site_key.to_string() };
                self.park_for_verification(id, kind, now);
                return;
            }
        }
        if code == 406 && is_main {
            self.events.push_back(RpcEvent::SoftAuthReset { message: message.clone() });
        }
        self.surface(id, code, message, response_time, now);
    }

    fn surface(&mut self, id: RequestId, code: i32, message: String, response_time: f64, now: Now) {
        if let Some(state) = self.finish(id) {
            self.events.push_back(RpcEvent::Failed {
                id,
                code,
                message,
                response_time,
                duration: (now.unix - state.sent_at_unix).max(0.0),
            });
        }
    }

    fn park_for_temporary_key(&mut self, id: RequestId, now: Now) {
        let key = self.session.auth_key_id();
        let report = match self.temporary_key_reported {
            Some((reported, at)) => reported != key || now.mono - at >= TEMPORARY_KEY_REPORT_INTERVAL,
            None => true,
        };
        if report {
            self.temporary_key_reported = Some((key, now.mono));
            self.events.push_back(RpcEvent::TemporaryKeyRejected);
        }
        if let Some(state) = self.requests.get_mut(&id) {
            let delay = (TEMPORARY_KEY_RETRY_DELAY * f64::from(1u32 << state.temporary_key_rejections.min(5)))
                .min(TEMPORARY_KEY_MAX_RETRY_DELAY);
            state.temporary_key_rejections += 1;
            state.rejected_key = Some(key);
            state.not_before = now.mono + delay;
        }
        self.leave_session(id);
    }

    fn park_for_verification(&mut self, id: RequestId, kind: VerificationKind, _now: Now) {
        if let Some(state) = self.requests.get_mut(&id) {
            state.pending_verification = true;
            state.verification = None;
        }
        self.leave_session(id);
        self.events.push_back(RpcEvent::VerificationRequired { id, kind });
    }

    fn pump_session_events(&mut self, now: Now) {
        while let Some(event) = self.session.poll_event() {
            self.handle_session_event(event, now);
        }
        self.dispatch_ready(now);
    }

    pub fn handle_packet(&mut self, packet: &[u8], now: Now, rng: &mut impl SecureRandom) -> Result<(), SessionError> {
        let result = self.session.handle_packet(packet, now, rng);
        self.pump_session_events(now);
        result
    }

    pub fn handle_quick_ack(&mut self, token: u32, now: Now) {
        self.session.handle_quick_ack(token);
        self.pump_session_events(now);
    }

    pub fn connection_opened(&mut self, now: Now) {
        self.session.connection_opened(now);
        self.dispatch_ready(now);
    }

    pub fn connection_closed(&mut self, now: Now) {
        self.session.connection_closed();
        self.pump_session_events(now);
    }

    pub fn connection_rejected(&mut self, now: Now) {
        self.session.connection_rejected(now);
        self.pump_session_events(now);
    }

    pub fn note_bytes_received(&mut self, now: Now) {
        self.session.note_bytes_received(now);
    }

    pub fn wants_outbound_backlog(&self) -> bool {
        self.session.wants_outbound_backlog()
    }

    pub fn note_outbound_backlog(&mut self, backlog: Option<usize>, now: Now) {
        self.session.note_outbound_backlog(backlog, now);
    }

    pub fn reset_session(&mut self, now: Now, rng: &mut impl SecureRandom) {
        self.session.reset(rng);
        self.pump_session_events(now);
    }

    pub fn poll_transmit(&mut self, now: Now, rng: &mut impl SecureRandom) -> Option<Transmit> {
        self.dispatch_ready(now);
        let transmit = self.session.poll_transmit(now, rng);
        self.pump_session_events(now);
        transmit
    }

    pub fn poll_timeout(&mut self, now: Now) -> Option<f64> {
        let mut deadline = self.session.poll_timeout(now).unwrap_or(f64::INFINITY);
        for state in self.parked.values().filter_map(|id| self.requests.get(id)) {
            if !state.in_session
                && state.not_before > now.mono
                && state.rejected_key.is_none_or(|key| key == self.session.auth_key_id())
                && !state.waiting_for_token
                && !state.pending_verification
                && state.pending_decision.is_none()
            {
                deadline = deadline.min(state.not_before);
            }
        }
        deadline.is_finite().then_some(deadline)
    }

    pub fn handle_timeout(&mut self, now: Now) -> Result<(), SessionError> {
        self.dispatch_ready(now);
        let result = self.session.handle_timeout(now);
        self.pump_session_events(now);
        result
    }

    pub fn progress_target(&self, head: &[u8]) -> Option<RequestId> {
        let id = RequestId::from(self.session.progress_target(head)?);
        self.requests.get(&id).is_some_and(|state| state.request.flags.progress).then_some(id)
    }

    pub fn poll_event(&mut self) -> Option<RpcEvent> {
        self.events.pop_front()
    }

    pub fn into_requests(mut self) -> Vec<RpcRequest> {
        let order = std::mem::take(&mut self.order);
        let mut requests = Vec::with_capacity(order.len());
        for id in order.into_values() {
            if let Some(state) = self.requests.remove(&id) {
                requests.push(state.request);
            }
        }
        requests
    }

    pub fn drain_events(&mut self) -> Vec<RpcEvent> {
        self.events.drain(..).collect()
    }
}

fn is_server_error(code: i32) -> bool {
    code == 500 || code == -500
}

fn server_error_delay(server_errors: u32) -> f64 {
    (SERVER_ERROR_RETRY_DELAY * f64::from(1u32 << server_errors.saturating_sub(1).min(3)))
        .min(SERVER_ERROR_MAX_RETRY_DELAY)
}

fn is_local_terminal_error(message: &str) -> bool {
    message.starts_with(RESPONSE_UNPACK_FAILED) || message.starts_with(PROTOCOL_ERROR_PREFIX)
}

fn is_updates_too_long(body: &[u8]) -> bool {
    body.len() >= 4 && u32::from_le_bytes(body[..4].try_into().expect("4")) == 0xe317af7e
}

#[cfg(test)]
mod tests;
