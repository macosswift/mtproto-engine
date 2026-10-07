//! Drives a `Session` (or the `RpcClient` around one) with fuzzer-chosen operations. Server packets are
//! sealed with the session's real key, so the fuzzer's bytes reach everything after decryption.

use std::collections::{BTreeMap, BTreeSet};

use mtproto_core::crypto::{SecureRandom, XorShiftRandom};
use mtproto_core::rpc::{RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, Verification};
use mtproto_core::session::{
    HttpWait, Now, QueryId, QueryOptions, ServerSalt, Session, SessionConfig, SessionError, SessionEvent, Transmit,
};
use mtproto_core::test_support::server_peer::{
    DecodedPacket, Outgoing, ServerPeer, future_salts, msgs_state_info, pong, rpc_result,
};

use mtproto_core::tl::ids;

use crate::{Cursor, Names, START, substitute, test_key};

pub const SALT: i64 = 101;
const MAX_OPS: usize = 96;
const MAX_FOOTPRINT: usize = 96 * 1024 * 1024;
const MAX_TRACKED_IDS: usize = 512;

pub trait Client {
    fn session(&self) -> &Session;
    fn handle_packet(&mut self, packet: &[u8], now: Now, rng: &mut XorShiftRandom) -> Result<(), SessionError>;
    fn handle_quick_ack(&mut self, token: u32, now: Now);
    fn poll_transmit(&mut self, now: Now, rng: &mut XorShiftRandom) -> Option<Transmit>;
    fn poll_http_transmit(
        &mut self,
        now: Now,
        rng: &mut XorShiftRandom,
        wait: HttpWait,
        force: bool,
    ) -> Option<Transmit>;
    fn http_packet_lost(&mut self, seq: u64, now: Now);
    fn handle_timeout(&mut self, now: Now) -> Result<(), SessionError>;
    fn poll_timeout(&mut self, now: Now) -> Option<f64>;
    fn connection_opened(&mut self, now: Now);
    fn connection_closed(&mut self, now: Now);
    fn send(&mut self, id: u64, body: Vec<u8>, cursor: &mut Cursor<'_>, now: Now);
    fn cancel(&mut self, id: u64, now: Now);
    /// A fuzzer-chosen host action; true when it asked to destroy the auth key.
    fn extra(&mut self, op: u8, cursor: &mut Cursor<'_>, now: Now, rng: &mut XorShiftRandom) -> bool;
    /// Drains events, noting the requests that got an answer or an error; returns how many there were.
    fn drain(&mut self, cursor: &mut Cursor<'_>, now: Now, resolved: &mut BTreeSet<u64>) -> usize;
}

impl Client for Session {
    fn session(&self) -> &Session {
        self
    }
    fn handle_packet(&mut self, packet: &[u8], now: Now, rng: &mut XorShiftRandom) -> Result<(), SessionError> {
        Session::handle_packet(self, packet, now, rng)
    }
    fn handle_quick_ack(&mut self, token: u32, now: Now) {
        Session::handle_quick_ack(self, token, now);
    }
    fn poll_transmit(&mut self, now: Now, rng: &mut XorShiftRandom) -> Option<Transmit> {
        Session::poll_transmit(self, now, rng)
    }
    fn poll_http_transmit(
        &mut self,
        now: Now,
        rng: &mut XorShiftRandom,
        wait: HttpWait,
        force: bool,
    ) -> Option<Transmit> {
        Session::poll_http_transmit(self, now, rng, wait, force, true)
    }
    fn http_packet_lost(&mut self, seq: u64, now: Now) {
        Session::http_packet_lost(self, seq, now);
    }
    fn handle_timeout(&mut self, now: Now) -> Result<(), SessionError> {
        Session::handle_timeout(self, now)
    }
    fn poll_timeout(&mut self, now: Now) -> Option<f64> {
        Session::poll_timeout(self, now)
    }
    fn connection_opened(&mut self, now: Now) {
        Session::connection_opened(self, now);
    }
    fn connection_closed(&mut self, _now: Now) {
        Session::connection_closed(self);
    }
    fn send(&mut self, id: u64, body: Vec<u8>, cursor: &mut Cursor<'_>, now: Now) {
        let flags = cursor.u8();
        let invoke_after = (flags & 2 != 0 && id > 1).then(|| QueryId(1 + cursor.below(id as usize - 1) as u64));
        Session::send(self, QueryId(id), body, QueryOptions { quick_ack: flags & 1 != 0, invoke_after }, now);
    }
    fn cancel(&mut self, id: u64, _now: Now) {
        let _ = Session::cancel(self, QueryId(id));
    }
    fn extra(&mut self, op: u8, cursor: &mut Cursor<'_>, now: Now, rng: &mut XorShiftRandom) -> bool {
        match op % 8 {
            0 => self.set_online(cursor.bool(), now),
            1 => self.note_outbound_backlog(cursor.bool().then(|| usize::from(cursor.u16()) * 64), now),
            2 => self.force_ack(now),
            3 => self.shrink(),
            4 => self.connection_rejected(now),
            5 => self.reset(rng),
            6 => self.note_rtt_sample(f64::from(cursor.u16()) / 1000.0),
            _ => {
                self.destroy_auth_key(now);
                return true;
            }
        }
        false
    }
    fn drain(&mut self, _cursor: &mut Cursor<'_>, _now: Now, resolved: &mut BTreeSet<u64>) -> usize {
        let events = self.drain_events();
        for event in &events {
            match event {
                SessionEvent::Result { id, body, .. } => {
                    assert!(body.len() <= 64 * 1024 * 1024, "result of {} bytes", body.len());
                    resolved.insert(id.0);
                }
                SessionEvent::Error { id, .. } => {
                    resolved.insert(id.0);
                }
                _ => {}
            }
        }
        events.len()
    }
}

impl Client for RpcClient {
    fn session(&self) -> &Session {
        RpcClient::session(self)
    }
    fn handle_packet(&mut self, packet: &[u8], now: Now, rng: &mut XorShiftRandom) -> Result<(), SessionError> {
        RpcClient::handle_packet(self, packet, now, rng)
    }
    fn handle_quick_ack(&mut self, token: u32, now: Now) {
        RpcClient::handle_quick_ack(self, token, now);
    }
    fn poll_transmit(&mut self, now: Now, rng: &mut XorShiftRandom) -> Option<Transmit> {
        RpcClient::poll_transmit(self, now, rng)
    }
    fn poll_http_transmit(
        &mut self,
        now: Now,
        rng: &mut XorShiftRandom,
        wait: HttpWait,
        force: bool,
    ) -> Option<Transmit> {
        RpcClient::poll_http_transmit(self, now, rng, wait, force, true)
    }
    fn http_packet_lost(&mut self, seq: u64, now: Now) {
        RpcClient::http_packet_lost(self, seq, now);
    }
    fn handle_timeout(&mut self, now: Now) -> Result<(), SessionError> {
        RpcClient::handle_timeout(self, now)
    }
    fn poll_timeout(&mut self, now: Now) -> Option<f64> {
        RpcClient::poll_timeout(self, now)
    }
    fn connection_opened(&mut self, now: Now) {
        RpcClient::connection_opened(self, now);
    }
    fn connection_closed(&mut self, now: Now) {
        RpcClient::connection_closed(self, now);
    }
    fn send(&mut self, id: u64, body: Vec<u8>, cursor: &mut Cursor<'_>, now: Now) {
        let bits = cursor.u16();
        let flags = RequestFlags {
            automatic_flood_wait: bits & 1 != 0,
            report_flood_wait: bits & 2 != 0,
            retry_server_errors: bits & 4 != 0,
            quick_ack: bits & 8 != 0,
            progress: bits & 16 != 0,
            timeout_timer: bits & 32 != 0,
            expected_response_size: if bits & 64 != 0 { 1 << 20 } else { 0 },
            without_updates: bits & 128 != 0,
            delegate_retry_decisions: bits & 256 != 0,
        };
        let invoke_after = (bits & 512 != 0 && id > 1).then(|| RequestId(1 + cursor.below(id as usize - 1) as u64));
        RpcClient::send(self, RpcRequest { id: RequestId(id), body, flags, invoke_after }, now);
    }
    fn cancel(&mut self, id: u64, now: Now) {
        let _ = RpcClient::cancel(self, RequestId(id), now);
    }
    fn extra(&mut self, op: u8, cursor: &mut Cursor<'_>, now: Now, rng: &mut XorShiftRandom) -> bool {
        match op % 6 {
            0 => {
                let id = RequestId(u64::from(cursor.u8()));
                let message = ["FLOOD_WAIT_3", "AUTH_KEY_UNREGISTERED", "PHONE_MIGRATE_2", "INTERNAL"][cursor.below(4)]
                    .to_string();
                let code = [420, 401, 303, 500, -503][cursor.below(5)];
                self.fail_request(id, code, &message, now)
            }
            1 => self.invalidate_initialization(),
            2 => self.reset_session(now, rng),
            3 => self.set_auth_token_ready(cursor.bool(), now),
            4 => self.note_outbound_backlog(cursor.bool().then(|| usize::from(cursor.u16()) * 64), now),
            _ => {
                self.destroy_auth_key(now);
                return true;
            }
        }
        false
    }
    fn drain(&mut self, cursor: &mut Cursor<'_>, now: Now, resolved: &mut BTreeSet<u64>) -> usize {
        let mut count = 0;
        while let Some(event) = self.poll_event() {
            count += 1;
            match event {
                RpcEvent::Completed { id, .. } | RpcEvent::Failed { id, .. } => {
                    resolved.insert(id.0);
                }
                RpcEvent::RetryDecisionRequired { id, .. } => self.decide_retry(id, cursor.bool(), now),
                RpcEvent::VerificationRequired { id, .. } => {
                    let verification = if cursor.bool() {
                        Verification::Recaptcha { token: "token".into() }
                    } else {
                        Verification::Apns { nonce: "nonce".into(), secret: "secret".into() }
                    };
                    self.resolve_verification(id, verification, now);
                }
                RpcEvent::AuthTokenRequired => self.set_auth_token_ready(cursor.bool(), now),
                RpcEvent::ConnectionShouldReset => {
                    self.connection_closed(now);
                    self.connection_opened(now);
                }
                _ => {}
            }
            assert!(count < 1_000_000, "rpc event storm");
        }
        count
    }
}

pub struct Peer {
    pub server: ServerPeer,
    pub names: Names,
    pub quick_ack_tokens: Vec<u32>,
    pub http_seqs: Vec<u64>,
    /// Query messages the server has read: msg_id to the query's id.
    pub queries_seen: BTreeMap<i64, u64>,
}

impl Peer {
    pub fn new() -> Self {
        let mut server = ServerPeer::new(test_key(), START);
        server.salt = SALT;
        Self {
            server,
            names: Names::default(),
            quick_ack_tokens: Vec::new(),
            http_seqs: Vec::new(),
            queries_seen: BTreeMap::new(),
        }
    }

    fn absorb(&mut self, transmit: &Transmit) {
        let packet = self.server.decode(&transmit.data);
        assert_eq!(packet.header.msg_id, transmit.msg_id, "transmit names the packet's msg_id");
        assert!(packet.header.msg_id & 3 == 0, "client msg_id {:#x} is not divisible by 4", packet.header.msg_id);
        self.names.packet_msg_ids.push(packet.header.msg_id);
        self.names.client_msg_ids.push(packet.header.msg_id);
        for message in packet.messages {
            assert!(message.msg_id & 3 == 0, "client msg_id {:#x} is not divisible by 4", message.msg_id);
            self.names.client_msg_ids.push(message.msg_id);
            if message.is_content_related() {
                self.names.query_msg_ids.push(message.msg_id);
            }
            if let Some(id) = query_id(&message.body) {
                self.queries_seen.insert(message.msg_id, id);
            }
            match message.constructor() {
                ids::PING | ids::PING_DELAY_DISCONNECT => {
                    self.names.ping_msg_ids.push(message.msg_id);
                    self.names.ping_ids.push(i64::from_le_bytes(message.body[4..12].try_into().expect("ping id")));
                }
                ids::GET_FUTURE_SALTS => self.names.future_salts_msg_ids.push(message.msg_id),
                ids::MSGS_STATE_REQ | ids::MSG_RESEND_REQ => self.names.state_request_msg_ids.push(message.msg_id),
                _ => {}
            }
        }
        if let Some(token) = transmit.quick_ack_token {
            self.quick_ack_tokens.push(token);
        }
        self.http_seqs.push(transmit.packet_seq);
        self.names.trim(MAX_TRACKED_IDS);
        let excess = self.quick_ack_tokens.len().saturating_sub(MAX_TRACKED_IDS);
        self.quick_ack_tokens.drain(..excess);
        let excess = self.http_seqs.len().saturating_sub(MAX_TRACKED_IDS);
        self.http_seqs.drain(..excess);
    }

    fn refresh_names(&mut self, session_id: i64) {
        self.names.session_id = session_id;
        self.names.salt = self.server.salt;
        self.names.server_time = self.server.server_time;
    }
}

impl Default for Peer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn new_session(config: SessionConfig, http: bool) -> (Session, XorShiftRandom, Now) {
    let mut rng = XorShiftRandom::new(5);
    let now = Now { mono: 100.0, unix: START };
    let salts = [
        ServerSalt { salt: SALT, valid_since: START - 100.0, valid_until: START + 1800.0 },
        ServerSalt { salt: SALT + 1, valid_since: START + 1800.0, valid_until: START + 3600.0 },
    ];
    let mut session = Session::new(config, test_key(), &salts, 0.0, now, &mut rng);
    session.set_http(http);
    session.connection_opened(now);
    (session, rng, now)
}

pub fn query_body(id: u64) -> Vec<u8> {
    let mut body = 0x1122_3344u32.to_le_bytes().to_vec();
    body.extend_from_slice(&(id as u32).to_le_bytes());
    body
}

/// Runs the fuzzer's operations against `client`, checking invariants that hold whatever the server
/// sends: the client's packets always decrypt and parse, msg_ids are proper, memory stays bounded,
/// and no operation makes the client transmit forever without new input.
/// Where `drive` left the client: the peer, the clock, and which requests are settled.
pub struct Run {
    pub peer: Peer,
    pub rng: XorShiftRandom,
    pub now: Now,
    pub sent: u64,
    pub cancelled: BTreeSet<u64>,
    pub resolved: BTreeSet<u64>,
    pub destroyed_key: bool,
}

pub fn drive<C: Client>(
    client: &mut C,
    http: bool,
    mut rng: XorShiftRandom,
    mut now: Now,
    cursor: &mut Cursor<'_>,
) -> Run {
    let mut peer = Peer::new();
    let mut next_query = 0u64;
    let mut cancelled = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    let mut destroyed_key = false;
    for _ in 0..3 {
        next_query += 1;
        client.send(next_query, query_body(next_query), &mut Cursor::new(&[]), now);
    }
    flush(client, &mut peer, http, &mut rng, now, false);
    let mut events = 0usize;
    for _ in 0..MAX_OPS {
        if cursor.is_empty() {
            break;
        }
        let op = cursor.u8();
        if trace() {
            eprintln!("op {} at {:.3} queries {}", op % 16, now.mono, client.session().describe_queries());
        }
        match op % 16 {
            0..=6 => {
                let packet = server_packet(client, &mut peer, cursor);
                let result = client.handle_packet(&packet, now, &mut rng);
                if trace() {
                    eprintln!("  delivered -> {result:?}");
                }
            }
            7 => {
                let step = match cursor.u8() % 8 {
                    0 => 0.001,
                    1 => 0.05,
                    2 => 0.5,
                    3 => 5.0,
                    4 => 30.0,
                    5 => 130.0,
                    6 => 700.0,
                    _ => f64::from(cursor.u16()),
                };
                now.mono += step;
                now.unix += step;
                peer.server.server_time += step;
                if cursor.u8() == 0xff {
                    now.unix += if cursor.bool() { 86_400.0 } else { -86_400.0 };
                }
                let _ = client.handle_timeout(now);
                if let Some(at) = client.poll_timeout(now) {
                    assert!(at.is_finite(), "timeout at {at}");
                }
            }
            8 => {
                next_query += 1;
                let mut body = query_body(next_query);
                body.extend(core::iter::repeat_n(0u8, usize::from(cursor.u8()) * 4));
                client.send(next_query, body, cursor, now);
            }
            9 => flush(client, &mut peer, http, &mut rng, now, cursor.bool()),
            10 => {
                client.connection_closed(now);
                client.connection_opened(now);
            }
            11 => {
                let id = 1 + cursor.below(next_query.max(1) as usize) as u64;
                client.cancel(id, now);
                cancelled.insert(id);
            }
            12 => {
                let token = if cursor.bool() || peer.quick_ack_tokens.is_empty() {
                    cursor.u32()
                } else {
                    peer.quick_ack_tokens[cursor.below(peer.quick_ack_tokens.len())]
                };
                client.handle_quick_ack(token, now);
            }
            13 => {
                let garbage = cursor.chunk().to_vec();
                assert!(client.handle_packet(&garbage, now, &mut rng).is_err(), "unsealed bytes were accepted");
            }
            14 if http && !peer.http_seqs.is_empty() => {
                let seq = peer.http_seqs[cursor.below(peer.http_seqs.len())];
                client.http_packet_lost(seq, now);
            }
            _ => {
                let extra = cursor.u8();
                destroyed_key |= client.extra(extra, cursor, now, &mut rng);
            }
        }
        events += client.drain(cursor, now, &mut resolved);
        assert!(events < 1_000_000, "event storm");
        let footprint = client.session().footprint();
        assert!(footprint < MAX_FOOTPRINT, "session footprint {footprint} bytes");
    }
    flush(client, &mut peer, http, &mut rng, now, false);
    client.drain(cursor, now, &mut resolved);
    Run { peer, rng, now, sent: next_query, cancelled, resolved, destroyed_key }
}

fn server_packet<C: Client>(client: &C, peer: &mut Peer, cursor: &mut Cursor<'_>) -> Vec<u8> {
    let control = cursor.u8();
    let session_id = client.session().session_id();
    let msg_id = match control & 7 {
        0..=2 => peer.server.next_msg_id(true),
        3 => peer.server.next_msg_id(false),
        4 => match peer.names.server_msg_ids.last() {
            Some(last) => *last,
            None => peer.server.next_msg_id(true),
        },
        5 => peer.server.next_msg_id(true) - (i64::from(cursor.u16()) << 32),
        6 => peer.server.next_msg_id(true) + (i64::from(cursor.u8()) << 32),
        _ => cursor.u64() as i64,
    };
    let seq_no = match (control >> 3) & 3 {
        0 => 1,
        1 => 0,
        2 => 2 * i32::from(cursor.u8()) + 1,
        _ => cursor.u32() as i32,
    };
    let mut body = cursor.chunk().to_vec();
    peer.refresh_names(session_id);
    substitute(&mut body, &peer.names);
    peer.server.session_id = if control & 0x40 != 0 && control & 0x80 != 0 { session_id ^ 1 } else { session_id };
    let salt = peer.server.salt;
    if control & 0x80 != 0 && control & 0x40 == 0 {
        peer.server.salt = salt ^ 0x55;
    }
    let packet = peer.server.seal(msg_id, seq_no, &body);
    peer.server.salt = salt;
    peer.server.session_id = session_id;
    peer.names.server_msg_ids.push(msg_id);
    packet
}

fn flush<C: Client>(client: &mut C, peer: &mut Peer, http: bool, rng: &mut XorShiftRandom, now: Now, force: bool) {
    let mut bytes = 0usize;
    for round in 0..256 {
        let transmit = if http {
            let wait = if force { HttpWait::long_poll(25_000) } else { HttpWait::IMMEDIATE };
            client.poll_http_transmit(now, rng, wait, force && round == 0)
        } else {
            client.poll_transmit(now, rng)
        };
        let Some(transmit) = transmit else {
            return;
        };
        bytes += transmit.data.len();
        assert!(bytes < 256 * 1024 * 1024, "over 256 MB in one flush");
        peer.absorb(&transmit);
    }
    let _ = rng.next_u32();
    panic!("the client keeps transmitting without new input");
}

/// After whatever the fuzzer did, an honest server takes over: it answers every query, ping, salt and
/// state request it is sent. Every request still open must then settle (answer or error) within
/// `rounds` half-second steps: a session that hostile input left unable to recover is a liveness bug.
pub fn honest_server(session: &mut Session, run: &mut Run, rounds: usize) {
    let outstanding = |run: &Run| -> Vec<u64> {
        (1..=run.sent).filter(|id| !run.cancelled.contains(id) && !run.resolved.contains(id)).collect()
    };
    let mut answered_at: BTreeMap<i64, f64> = BTreeMap::new();
    let mut replies: Vec<Outgoing> = Vec::new();
    for _ in 0..rounds {
        if outstanding(run).is_empty() {
            return;
        }
        if !session.is_connected() {
            session.connection_opened(run.now);
        }
        for (msg_id, id) in &run.peer.queries_seen {
            let due = answered_at.get(msg_id).is_none_or(|at| run.now.mono - at >= ANSWER_RESEND_AFTER);
            if due && !run.resolved.contains(id) && !run.cancelled.contains(id) {
                answered_at.insert(*msg_id, run.now.mono);
                replies.push(Outgoing::Content(rpc_result(*msg_id, &[1, 0, 0, 0])));
            }
        }
        for _ in 0..64 {
            let Some(transmit) = session.poll_transmit(run.now, &mut run.rng) else {
                break;
            };
            run.peer.absorb(&transmit);
            let packet = run.peer.server.decode(&transmit.data);
            if trace() {
                eprintln!("honest {:.1}: client sent {:x?}", run.now.mono, packet.constructors());
            }
            answer(&packet, &mut run.peer, &mut replies, &mut answered_at, run.now.mono);
        }
        if !replies.is_empty() {
            let packet = run.peer.server.encode(std::mem::take(&mut replies));
            let result = session.handle_packet(&packet, run.now, &mut run.rng);
            if trace() {
                eprintln!("honest {:.1}: replies -> {result:?}; {}", run.now.mono, session.describe_queries());
            }
            if result.is_err() {
                session.connection_closed();
                session.connection_opened(run.now);
            }
        }
        session.drain(&mut Cursor::new(&[]), run.now, &mut run.resolved);
        run.now.mono += 0.5;
        run.now.unix += 0.5;
        run.peer.server.server_time += 0.5;
        if session.handle_timeout(run.now).is_err() {
            session.connection_closed();
            session.connection_opened(run.now);
        }
        session.drain(&mut Cursor::new(&[]), run.now, &mut run.resolved);
    }
    let left = outstanding(run);
    assert!(
        left.is_empty(),
        "requests {left:?} never settled under an honest server; queries: {}",
        session.describe_queries()
    );
}

fn answer(
    packet: &DecodedPacket,
    peer: &mut Peer,
    replies: &mut Vec<Outgoing>,
    answered_at: &mut BTreeMap<i64, f64>,
    now_mono: f64,
) {
    let now = peer.server.server_time as i32;
    for message in &packet.messages {
        let body = &message.body;
        let word = |at: usize| body.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4")));
        if query_id(body).is_some() {
            answered_at.insert(message.msg_id, now_mono);
            replies.push(Outgoing::Content(rpc_result(message.msg_id, &[1, 0, 0, 0])));
            continue;
        }
        match word(0) {
            Some(ids::PING | ids::PING_DELAY_DISCONNECT) => {
                let ping_id = i64::from_le_bytes(body[4..12].try_into().expect("ping id"));
                replies.push(Outgoing::Service(pong(message.msg_id, ping_id)));
            }
            Some(ids::GET_FUTURE_SALTS) => replies.push(Outgoing::Content(future_salts(
                message.msg_id,
                now,
                &[(now - 60, now + 1800, SALT), (now + 1800, now + 3600, SALT + 1)],
            ))),
            Some(ids::MSGS_STATE_REQ) => {
                let count = body.get(8..12).map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().expect("4")));
                let info = vec![2u8; (count as usize).min(8192)];
                replies.push(Outgoing::Content(msgs_state_info(message.msg_id, &info)));
            }
            _ => {}
        }
    }
}

const QUERY: u32 = 0x1122_3344;

fn trace() -> bool {
    std::env::var_os("MTPROTO_FUZZ_TRACE").is_some()
}

/// Like a real server, the honest one answers again a query whose answer was not taken (a connection
/// dropped under it) until the client has it.
const ANSWER_RESEND_AFTER: f64 = 5.0;

fn query_id(body: &[u8]) -> Option<u64> {
    let word = |at: usize| body.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4")));
    if word(0) == Some(QUERY) {
        return word(4).map(u64::from);
    }
    (word(0) == Some(ids::INVOKE_AFTER_MSG) && word(12) == Some(QUERY)).then(|| word(16).map(u64::from)).flatten()
}
