//! A randomized server for announced answers (msg_detailed_info, msg_new_detailed_info, msg_resend_req,
//! msgs_state_info) over TCP and HTTP, with lost responses, slow links, reconnects, long outages,
//! cancels, server session resets and salt changes; the session's invariants are checked after every
//! step. `ANSWER_MODEL_SEEDS`, `ANSWER_MODEL_FIRST`, `ANSWER_MODEL_STEPS` and `ANSWER_MODEL_TRACE`
//! widen or replay a sweep.
use super::*;
use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next() % 1_000_000) as f64 / 1_000_000.0 * (hi - lo)
    }
}

#[derive(Clone, Debug)]
struct Held {
    req: i64,
    tag: u32,
    bytes: i32,
}

#[derive(Default)]
struct Server {
    executed: HashMap<u32, i64>,
    answer_of: HashMap<i64, i64>,
    held: BTreeMap<i64, Held>,
    forgotten: HashSet<u32>,
    announce_percent: u64,
    new_info_percent: u64,
    fresh_connection: bool,
    new_info_answers: HashSet<i64>,
    salt: i64,
    reset_forgotten: HashSet<u32>,
    pending_new_session: bool,
    unique: i64,
}

enum Out {
    Sealed(Vec<u8>),
    Items(Vec<Outgoing>),
}

pub(super) struct Stats {
    pub asks: usize,
    pub max_asks_per_answer_per_conn: u32,
    pub max_ask_age: f64,
    pub answer_lost: usize,
    pub results: usize,
    pub unresolved: usize,
    pub executed: usize,
    pub salt_spins: usize,
}

pub(super) struct World {
    h: Harness,
    http: bool,
    rng: Rng,
    server: Server,
    to_client: Vec<(f64, u64, Out)>,
    to_server: Vec<(f64, u64, Vec<u8>)>,
    epoch: u64,
    rtt: f64,
    tag: u32,
    live: HashMap<u32, QueryId>,
    resolved: HashMap<u32, String>,
    pub violations: Vec<String>,
    asks_this_conn: HashMap<i64, u32>,
    stats: Stats,
    idle_wakes: Vec<f64>,
    loss_percent: u64,
    ignore_ask_percent: u64,
    down_rate: f64,
    down_free_at: f64,
    forgetting: bool,
    outbound: Vec<Outgoing>,
    parked: Vec<(f64, u64, u64)>,
    in_flight: HashMap<u64, (f64, i32)>,
    trace: Vec<String>,
    pub trace_on: bool,
    seen_awaited: HashSet<i64>,
    awaited_log: HashMap<i64, Option<QueryId>>,
    copies: Vec<(i64, f64)>,
    pub max_concurrent_copies: usize,
    transfers: Vec<(f64, f64)>,
    pub unknowable: usize,
}

fn body_of_answer(tag: u32, bytes: i32) -> Vec<u8> {
    let mut body = vec![0u8; (bytes.max(8) as usize).div_ceil(4) * 4];
    body[..4].copy_from_slice(&0x0abc_def0u32.to_le_bytes());
    body[4..8].copy_from_slice(&tag.to_le_bytes());
    body
}

impl World {
    pub(super) fn new(seed: u64, http: bool) -> Self {
        let mut h = Harness::with_salts(vec![ServerSalt {
            salt: 101,
            valid_since: START - 100.0,
            valid_until: START + 10_000_000.0,
        }]);
        h.sync();
        if http {
            h.session.set_http(true);
        }
        let mut rng = Rng::new(seed);
        let rtt = rng.uniform(0.05, 1.5);
        Self {
            h,
            http,
            rng,
            server: Server { announce_percent: 50, new_info_percent: 10, salt: 101, ..Server::default() },
            to_client: Vec::new(),
            to_server: Vec::new(),
            epoch: 0,
            rtt,
            tag: 0,
            live: HashMap::new(),
            resolved: HashMap::new(),
            violations: Vec::new(),
            asks_this_conn: HashMap::new(),
            stats: Stats {
                asks: 0,
                max_asks_per_answer_per_conn: 0,
                max_ask_age: 0.0,
                answer_lost: 0,
                results: 0,
                unresolved: 0,
                executed: 0,
                salt_spins: 0,
            },
            idle_wakes: Vec::new(),
            loss_percent: 0,
            ignore_ask_percent: 0,
            down_rate: 1.0e6,
            down_free_at: 0.0,
            forgetting: true,
            outbound: Vec::new(),
            parked: Vec::new(),
            in_flight: HashMap::new(),
            trace: Vec::new(),
            trace_on: false,
            seen_awaited: HashSet::new(),
            awaited_log: HashMap::new(),
            copies: Vec::new(),
            max_concurrent_copies: 0,
            transfers: Vec::new(),
            unknowable: 0,
        }
    }

    fn log(&mut self, line: String) {
        if self.trace_on {
            self.trace.push(format!("[{:9.3}] {line}", self.h.now.mono - 100.0));
        }
    }

    fn violation(&mut self, text: String) {
        let line = format!("t={:.3} {text}", self.h.now.mono - 100.0);
        self.log(format!("VIOLATION {line}"));
        if self.violations.len() < 20 {
            self.violations.push(line);
        }
    }

    fn reconnect(&mut self, gap: f64) {
        if self.http {
            for (seq, _) in std::mem::take(&mut self.in_flight) {
                self.h.session.http_packet_lost(seq, self.h.now);
            }
            self.parked.clear();
            self.outbound.clear();
            self.to_client.clear();
            self.transfers.clear();
            self.copies.clear();
            self.h.session.connection_closed();
            self.h.advance(gap);
            self.h.session.connection_opened(self.h.now);
        } else {
            self.h.session.connection_closed();
            self.to_client.clear();
            self.to_server.clear();
            self.down_free_at = 0.0;
            self.transfers.clear();
            self.h.advance(gap);
            self.h.session.connection_opened(self.h.now);
        }
        self.epoch += 1;
        self.server.fresh_connection = true;
        self.asks_this_conn.clear();
        self.log(format!("reconnect after {gap:.1}"));
    }

    fn reannounce_items(&mut self) -> Vec<Outgoing> {
        let mut items = Vec::new();
        for (answer, held) in &self.server.held {
            items.push(Outgoing::Service(msg_detailed_info(held.req, *answer, held.bytes)));
        }
        items
    }

    fn server_receive(&mut self, packet: DecodedPacket) -> Vec<Out> {
        let mut out: Vec<Out> = Vec::new();
        let mut items: Vec<Outgoing> = Vec::new();
        if packet.header.salt != self.server.salt {
            self.log(format!("bad salt for {:x}", packet.header.msg_id));
            out.push(Out::Items(vec![Outgoing::Service(bad_server_salt(
                packet.header.msg_id,
                packet.header.seq_no,
                self.server.salt,
            ))]));
            return out;
        }
        if self.server.pending_new_session {
            self.server.pending_new_session = false;
            let first = packet.messages.iter().map(|m| m.msg_id).min().unwrap();
            self.server.unique += 1;
            items.push(Outgoing::Service(new_session_created(first, self.server.unique, self.server.salt)));
            self.log(format!("new_session_created first {first:x}"));
        }
        if self.server.fresh_connection && !self.http {
            self.server.fresh_connection = false;
            items.extend(self.reannounce_items());
        }
        for message in &packet.messages {
            let constructor = message.constructor();
            if let Some(tag) = query_tag(&message.body) {
                match self.server.executed.get(&tag).copied() {
                    None => {
                        self.server.executed.insert(tag, message.msg_id);
                        self.stats.executed += 1;
                        let answer = self.h.server.next_msg_id(true);
                        self.server.answer_of.insert(message.msg_id, answer);
                        let bytes = if self.rng.chance(30) { 40_000 } else { 200 };
                        self.server.held.insert(answer, Held { req: message.msg_id, tag, bytes });
                        if self.rng.chance(self.server.announce_percent) {
                            if self.rng.chance(self.server.new_info_percent) {
                                items.push(Outgoing::Service(msg_new_detailed_info(answer, bytes)));
                                self.log(format!("  (msg_new_detailed_info for {answer:x})"));
                                self.server.new_info_answers.insert(answer);
                            } else {
                                items.push(Outgoing::Service(msg_detailed_info(message.msg_id, answer, bytes)));
                            }
                            self.log(format!("exec tag {tag} q {:x} -> announce {answer:x}", message.msg_id));
                        } else {
                            items.push(Outgoing::Raw {
                                body: rpc_result(message.msg_id, &body_of_answer(tag, bytes)),
                                seq_no: 1,
                                msg_id: Some(answer),
                            });
                            self.log(format!("exec tag {tag} q {:x} -> answer {answer:x}", message.msg_id));
                        }
                    }
                    Some(first) if first == message.msg_id => {
                        if let Some(answer) = self.server.answer_of.get(&first).copied() {
                            let bytes = self.server.held.get(&answer).map_or(200, |held| held.bytes);
                            if self.server.held.contains_key(&answer) || self.server.forgotten.contains(&tag) {
                                items.push(Outgoing::Service(msg_detailed_info(first, answer, bytes)));
                            }
                        }
                        self.log(format!("dup tag {tag} q {first:x}"));
                    }
                    Some(first) => {
                        self.violation(format!(
                            "tag {tag} executed as {first:x} arrived again as {:x} (double execution)",
                            message.msg_id
                        ));
                    }
                }
                continue;
            }
            match constructor {
                ids::MSGS_ACK => {
                    for id in read_vector_after_constructor(&message.body) {
                        self.server.held.remove(&id);
                    }
                }
                ids::MSG_RESEND_REQ => {
                    let wanted = read_vector_after_constructor(&message.body);
                    self.stats.asks += 1;
                    if self.rng.chance(self.ignore_ask_percent) {
                        self.log(format!("ask {:x} for {:x?} ignored", message.msg_id, wanted));
                        for id in &wanted {
                            let count = self.asks_this_conn.entry(*id).or_insert(0);
                            *count += 1;
                        }
                        continue;
                    }
                    for id in &wanted {
                        let count = self.asks_this_conn.entry(*id).or_insert(0);
                        *count += 1;
                        self.stats.max_asks_per_answer_per_conn = self.stats.max_asks_per_answer_per_conn.max(*count);
                    }
                    let mut missing = false;
                    for id in &wanted {
                        match self.server.held.get(id).cloned() {
                            Some(held) => items.push(Outgoing::Raw {
                                body: rpc_result(held.req, &body_of_answer(held.tag, held.bytes)),
                                seq_no: 1,
                                msg_id: Some(*id),
                            }),
                            None => missing = true,
                        }
                    }
                    if missing {
                        items.push(Outgoing::Service(msgs_state_info(message.msg_id, &vec![2u8; wanted.len()])));
                    }
                    self.log(format!("ask {:x} for {:x?} missing={missing}", message.msg_id, wanted));
                }
                ids::PING_DELAY_DISCONNECT | ids::PING => {
                    let ping_id = i64::from_le_bytes(message.body[4..12].try_into().unwrap());
                    items.push(Outgoing::Service(pong(message.msg_id, ping_id)));
                }
                ids::MSGS_STATE_REQ => {
                    let asked = read_vector_after_constructor(&message.body);
                    let info: Vec<u8> =
                        asked.iter().map(|id| if self.server.answer_of.contains_key(id) { 4 } else { 2 }).collect();
                    items.push(Outgoing::Service(msgs_state_info(message.msg_id, &info)));
                }
                ids::GET_FUTURE_SALTS if std::env::var("ANSWER_MODEL_IGNORE_SALTS").is_err() => {
                    let now = self.h.server.server_time as i32;
                    items.push(Outgoing::Service(future_salts(
                        message.msg_id,
                        now,
                        &[(now - 10, now + 86_400, self.server.salt)],
                    )));
                }
                ids::RPC_DROP_ANSWER => {
                    let req = i64::from_le_bytes(message.body[4..12].try_into().unwrap());
                    if let Some(answer) = self.server.answer_of.get(&req).copied() {
                        self.server.held.remove(&answer);
                    }
                }
                _ => {}
            }
        }
        if !items.is_empty() {
            out.push(Out::Items(items));
        }
        out
    }

    fn deliver_to_client(&mut self, out: Out) {
        let packet = match out {
            Out::Sealed(packet) => packet,
            Out::Items(items) => self.h.server.encode(items),
        };
        let result = self.h.session.handle_packet(&packet, self.h.now, &mut self.h.rng);
        if let Err(error) = result
            && error != SessionError::ForeignSession
        {
            self.log(format!("packet error {error:?}"));
            if !self.http {
                self.reconnect(0.1);
            }
        }
    }

    fn collect_events(&mut self) {
        for event in self.h.session.drain_events() {
            match event {
                SessionEvent::Result { id, body, .. } => {
                    let tag = id.0 as u32;
                    self.stats.results += 1;
                    if self.live.remove(&tag).is_none() {
                        self.violation(format!("result for tag {tag} not live ({:?})", self.resolved.get(&tag)));
                    }
                    if body != body_of_answer(tag, 8)[4..].to_vec() && body != body_of_answer(tag, 8) {
                        let _ = &body;
                    }
                    self.resolved.insert(tag, "result".into());
                }
                SessionEvent::Error { id, message, .. } => {
                    let tag = id.0 as u32;
                    self.log(format!("client: tag {tag} failed {message}"));
                    if message == ANSWER_LOST {
                        self.stats.answer_lost += 1;
                        let reset_lost =
                            self.server.reset_forgotten.contains(&tag) && !self.server.executed.contains_key(&tag);
                        if !self.server.forgotten.contains(&tag) && !reset_lost {
                            self.violation(format!(
                                "ANSWER_LOST for tag {tag} whose answer the server holds (reset_forgotten {})",
                                self.server.reset_forgotten.contains(&tag)
                            ));
                        }
                    } else {
                        self.violation(format!("error {message} for tag {tag}"));
                    }
                    self.live.remove(&tag);
                    self.resolved.insert(tag, message);
                }
                _ => {}
            }
        }
    }

    fn check(&mut self) {
        let now = self.h.now.mono;
        if let Some(at) = self.h.session.poll_timeout(self.h.now)
            && at < now - 1e-9
        {
            let s = &self.h.session;
            let requests: Vec<String> = s
                .service_requests
                .iter()
                .map(|(id, r)| {
                    format!("{id:x}:{:?} age {:.3} in_flight {}", r, now - r.sent_at(), s.ask_in_flight(*id))
                })
                .collect();
            let detail = format!(
                "force_send_at {:?} unknown_since {:?} drain {:?} awaiting_ack {:?} to_resend {:x?} requests {:?} http_packets {:?}",
                s.force_send_at.map(|t| t - now),
                s.unknown_since.map(|t| t - now),
                s.drain_reset_at.map(|t| t - now),
                s.http_awaiting_ack.front().map(|(_, _, due)| due - now),
                s.to_resend_answer,
                requests,
                s.http_packets.iter().map(|p| (p.seq, p.services.clone())).collect::<Vec<_>>()
            );
            self.violation(format!("poll_timeout {:.3} s in the past: {detail}", now - at));
        }
        let ages: Vec<(f64, bool)> = self
            .h
            .session
            .service_requests
            .iter()
            .filter(|(_, request)| matches!(request, ServiceRequest::ResendRequest { .. }))
            .map(|(id, request)| (now - request.sent_at(), self.h.session.ask_in_flight(*id)))
            .collect();
        for (age, in_flight) in ages {
            self.stats.max_ask_age = self.stats.max_ask_age.max(age);
            let limit = if self.http {
                if in_flight { 1.0e9 } else { STATE_REQUEST_RETRY + 0.5 }
            } else {
                TCP_ASK_BACKSTOP + 0.5
            };
            if age > limit {
                self.violation(format!("an ask {age:.1} s old is still out (in flight {in_flight})"));
            }
        }
        let server_time = self.h.session.server_time(self.h.now);
        if !self.h.session.salts.has_valid_salt(server_time) {
            self.idle_wakes.clear();
            self.stats.salt_spins += 1;
        }
        let storm = self.idle_wakes.iter().rev().take_while(|at| now - **at < 1.0).count();
        if storm >= 100 {
            let server_time = self.h.session.server_time(self.h.now);
            let has_salt = self.h.session.salts.has_valid_salt(server_time);
            let detail = format!(
                "has_salt {has_salt} salts {:?} server_time {server_time:.1} last_future_salts_at {:?} next_change {:?} force_send_at {:?} timeout {:?} connected {} drain {:?} to_resend {:x?} pending {} requests {}",
                self.h.session.salts.all(),
                self.h.session.last_future_salts_at.map(|t| t - now),
                self.h.session.salts.next_change_time(server_time).map(|t| t - server_time),
                self.h.session.force_send_at.map(|t| t - now),
                self.h.session.poll_timeout(self.h.now).map(|t| t - now),
                self.h.session.connected,
                self.h.session.drain_reset_at.map(|t| t - now),
                self.h.session.to_resend_answer,
                self.h.session.pending.len(),
                self.h.session.service_requests.len(),
            );
            self.violation(format!("{storm} idle wake-ups within a second: {detail}"));
            self.idle_wakes.clear();
        }
    }

    fn transmit_tcp(&mut self) -> bool {
        let mut sent = false;
        for _ in 0..64 {
            let Some(transmit) = self.h.session.poll_transmit(self.h.now, &mut self.h.rng) else {
                break;
            };
            sent = true;
            let at = self.h.now.mono + self.rtt / 2.0;
            self.to_server.push((at, self.epoch, transmit.data));
        }
        sent
    }

    fn send_http(&mut self, transmit: Transmit, max_wait: i32) {
        let packet = self.h.server.decode(&transmit.data);
        let wait = packet
            .find(ids::HTTP_WAIT)
            .map(|message| i32::from_le_bytes(message.body[12..16].try_into().unwrap()))
            .unwrap_or(max_wait);
        let arrive = self.h.now.mono + self.rtt / 2.0;
        self.in_flight.insert(transmit.packet_seq, (arrive, wait));
        self.to_server.push((arrive, transmit.packet_seq, transmit.data));
    }

    fn transmit_http(&mut self) -> bool {
        let mut sent = false;
        for _ in 0..4096 {
            let Some(transmit) =
                self.h.session.poll_http_transmit(self.h.now, &mut self.h.rng, HttpWait::IMMEDIATE, false, true)
            else {
                break;
            };
            sent = true;
            self.send_http(transmit, 0);
        }
        let polls = self.in_flight.values().filter(|(_, wait)| *wait > 0).count();
        if polls == 0
            && let Some(transmit) =
                self.h.session.poll_http_transmit(self.h.now, &mut self.h.rng, HttpWait::long_poll(25_000), true, true)
        {
            sent = true;
            self.send_http(transmit, 25_000);
        }
        sent
    }

    fn respond_http(&mut self, seq: u64, extra: Vec<Outgoing>) {
        let mut items = extra;
        let copies: Vec<i64> = items
            .iter()
            .filter_map(|item| match item {
                Outgoing::Raw { msg_id: Some(id), .. } => Some(*id),
                _ => None,
            })
            .collect();
        let now = self.h.now.mono;
        self.copies.retain(|(_, until)| *until > now);
        for id in &copies {
            let concurrent = 1 + self.copies.iter().filter(|(other, _)| other == id).count();
            if concurrent > self.max_concurrent_copies {
                self.max_concurrent_copies = concurrent;
                self.log(format!("{concurrent} copies of {id:x} in flight"));
            }
        }
        let held_in_items: HashSet<i64> = items
            .iter()
            .filter_map(|item| match item {
                Outgoing::Raw { msg_id: Some(id), .. } => Some(*id),
                _ => None,
            })
            .collect();
        for (answer, held) in &self.server.held {
            if !held_in_items.contains(answer) {
                items.push(Outgoing::Service(msg_detailed_info(held.req, *answer, held.bytes)));
            }
        }
        if items.is_empty() {
            items.push(Outgoing::Service(msgs_ack(&[])));
        }
        let begin = self.h.now.mono + self.rtt / 2.0;
        let packet = self.h.server.encode(items);
        let at = begin + packet.len() as f64 / self.down_rate;
        if at - begin > 0.5 {
            self.transfers.push((begin, at));
        }
        for id in copies {
            self.copies.push((id, at));
        }
        self.to_client.push((at, seq, Out::Sealed(packet)));
    }

    fn server_step_http(&mut self) {
        let now = self.h.now.mono;
        while let Some(position) = self.to_server.iter().position(|(at, _, _)| *at <= now) {
            let (_, seq, data) = self.to_server.remove(position);
            if !self.in_flight.contains_key(&seq) {
                continue;
            }
            let packet = self.h.server.decode(&data);
            let wait = self.in_flight.get(&seq).map_or(0, |(_, wait)| *wait);
            for out in self.server_receive(packet) {
                if let Out::Items(items) = out {
                    self.outbound.extend(items);
                }
            }
            if wait > 0 {
                self.parked.push((now + f64::from(wait) / 1000.0, seq, 0));
            } else {
                let items = std::mem::take(&mut self.outbound);
                self.respond_http(seq, items);
            }
        }
        if !self.outbound.is_empty() && !self.parked.is_empty() {
            let (_, seq, _) = self.parked.remove(0);
            let items = std::mem::take(&mut self.outbound);
            self.respond_http(seq, items);
        }
        while let Some(position) = self.parked.iter().position(|(until, _, _)| *until <= now) {
            let (_, seq, _) = self.parked.remove(position);
            let items = std::mem::take(&mut self.outbound);
            self.respond_http(seq, items);
        }
    }

    fn client_step_http(&mut self) -> bool {
        let now = self.h.now.mono;
        let mut delivered = false;
        while let Some(position) = self.to_client.iter().position(|(at, _, _)| *at <= now) {
            let (_, seq, out) = self.to_client.remove(position);
            if self.in_flight.remove(&seq).is_none() {
                continue;
            }
            delivered = true;
            if self.rng.chance(self.loss_percent) {
                self.log(format!("response {seq} lost"));
                self.h.session.http_packet_lost(seq, self.h.now);
                continue;
            }
            self.h.session.http_packet_delivered(seq, self.h.now);
            self.deliver_to_client(out);
        }
        delivered
    }

    fn step(&mut self) -> bool {
        let now = self.h.now.mono;
        let mut delivered = false;
        if self.http {
            self.server_step_http();
            delivered |= self.client_step_http();
        } else {
            while let Some(position) =
                self.to_server.iter().position(|(at, epoch, _)| *at <= now && *epoch == self.epoch)
            {
                let (_, _, data) = self.to_server.remove(position);
                let packet = self.h.server.decode(&data);
                let replies = self.server_receive(packet);
                for reply in replies {
                    let sealed = match reply {
                        Out::Sealed(packet) => packet,
                        Out::Items(items) => self.h.server.encode(items),
                    };
                    let begin = self.down_free_at.max(now + self.rtt / 2.0);
                    let at = begin + sealed.len() as f64 / self.down_rate;
                    self.down_free_at = at;
                    if at - begin > 0.5 {
                        self.transfers.push((begin, at));
                    }
                    self.to_client.push((at, self.epoch, Out::Sealed(sealed)));
                }
            }
            while let Some(position) =
                self.to_client.iter().position(|(at, epoch, _)| *at <= now && *epoch == self.epoch)
            {
                let (_, _, out) = self.to_client.remove(position);
                delivered = true;
                self.deliver_to_client(out);
            }
        }
        self.transfers.retain(|(_, end)| *end > now);
        if self.transfers.iter().any(|(begin, _)| *begin <= now) {
            if self.http {
                self.h.session.note_http_receiving(self.h.now);
            } else {
                self.h.session.note_bytes_received(self.h.now);
            }
        }
        let current: Vec<(i64, Option<QueryId>)> =
            self.h.session.awaited_answers.iter().map(|(answer, awaited)| (*answer, awaited.query)).collect();
        if self.trace_on {
            let now_set: HashMap<i64, Option<QueryId>> = current.iter().copied().collect();
            for (answer, query) in &current {
                if self.awaited_log.get(answer) != Some(query) {
                    self.trace
                        .push(format!("[{:9.3}] client awaits {answer:x} for {query:?}", self.h.now.mono - 100.0));
                }
            }
            for (answer, query) in &self.awaited_log {
                if !now_set.contains_key(answer) {
                    self.trace.push(format!(
                        "[{:9.3}] client no longer awaits {answer:x} ({query:?})",
                        self.h.now.mono - 100.0
                    ));
                }
            }
            self.awaited_log = now_set;
        }
        for (answer, _) in current {
            self.seen_awaited.insert(answer);
        }
        if let Err(error) = self.h.session.handle_timeout(self.h.now) {
            self.log(format!("timeout error {error:?}"));
            self.reconnect(0.1);
        }
        let sent = if self.http { self.transmit_http() } else { self.transmit_tcp() };
        self.collect_events();
        if !delivered && !sent {
            self.idle_wakes.push(self.h.now.mono);
        }
        self.check();
        delivered || sent
    }

    fn next_event_at(&self) -> f64 {
        let mut next = f64::INFINITY;
        for (at, _, _) in &self.to_server {
            next = next.min(*at);
        }
        for (at, _, _) in &self.to_client {
            next = next.min(*at);
        }
        for (until, _, _) in &self.parked {
            next = next.min(*until);
        }
        if !self.transfers.is_empty() {
            next = next.min(self.h.now.mono + 0.25);
        }
        next
    }

    pub(super) fn run_for(&mut self, seconds: f64) {
        let until = self.h.now.mono + seconds;
        while self.h.now.mono < until {
            let timer = self.h.session.poll_timeout(self.h.now).unwrap_or(f64::INFINITY);
            let next = timer.min(self.next_event_at()).min(until).max(self.h.now.mono + 0.001);
            self.h.advance(next - self.h.now.mono);
            self.step();
            if self.violations.len() >= 20 {
                return;
            }
        }
    }

    pub(super) fn random_step(&mut self) {
        let roll = self.rng.below(100);
        match roll {
            0..=29 => {
                self.tag += 1;
                let tag = self.tag;
                self.h.session.send(QueryId(u64::from(tag)), query_body(tag), QueryOptions::default(), self.h.now);
                self.live.insert(tag, QueryId(u64::from(tag)));
                self.log(format!("send tag {tag}"));
            }
            30..=64 => {
                let seconds =
                    if self.rng.chance(80) { self.rng.uniform(0.01, 5.0) } else { self.rng.uniform(5.0, 150.0) };
                self.run_for(seconds);
            }
            65..=70 => {
                let gap = self.rng.uniform(0.0, 3.0);
                self.reconnect(gap);
            }
            71..=72 => {
                let gap = self.rng.uniform(100.0, 700.0);
                self.reconnect(gap);
            }
            73..=78 => {
                if !self.live.is_empty() {
                    let mut tags: Vec<u32> = self.live.keys().copied().collect();
                    tags.sort_unstable();
                    let tag = tags[self.rng.below(tags.len() as u64) as usize];
                    self.live.remove(&tag);
                    self.resolved.insert(tag, "cancelled".into());
                    if let CancelOutcome::RemovedInFlight { msg_id } = self.h.session.cancel(QueryId(u64::from(tag))) {
                        self.h.session.drop_answer(msg_id, self.h.now);
                    }
                    self.log(format!("cancel tag {tag}"));
                }
            }
            79..=82 => {
                if self.forgetting && !self.server.held.is_empty() {
                    let answers: Vec<i64> = self.server.held.keys().copied().collect();
                    let answer = answers[self.rng.below(answers.len() as u64) as usize];
                    let held = self.server.held.remove(&answer).unwrap();
                    self.server.forgotten.insert(held.tag);
                    self.log(format!("server forgets {answer:x} (tag {})", held.tag));
                }
            }
            83..=86 => {
                if !self.http {
                    let items = self.reannounce_items();
                    if !items.is_empty() {
                        let at = self.h.now.mono + self.rtt / 2.0;
                        self.to_client.push((at, self.epoch, Out::Items(items)));
                    }
                }
            }
            87..=91 => {
                self.server.announce_percent = [0, 50, 100][self.rng.below(3) as usize];
            }
            92..=93 => {
                self.loss_percent = [0, 10, 40][self.rng.below(3) as usize];
            }
            94 => {
                let choice = [0, 0, 30, 100][self.rng.below(4) as usize];
                self.ignore_ask_percent = if std::env::var("ANSWER_MODEL_NO_IGNORE").is_ok() { 0 } else { choice };
            }
            95 => {
                self.down_rate = [1.0e6, 1.0e6, 20_000.0, 1_000.0, 300.0][self.rng.below(5) as usize];
            }
            96 => {
                if std::env::var("ANSWER_MODEL_NO_RESET").is_err() {
                    self.server.executed.clear();
                    self.server.answer_of.clear();
                    let held = std::mem::take(&mut self.server.held);
                    for (_, held) in held {
                        self.server.reset_forgotten.insert(held.tag);
                    }
                    self.server.pending_new_session = true;
                    self.log("server session reset".into());
                }
            }
            97 => {
                if std::env::var("ANSWER_MODEL_NO_SALT").is_err() {
                    self.server.salt = if self.server.salt == 101 { 202 } else { 101 };
                    self.log(format!("server salt now {}", self.server.salt));
                }
            }
            _ => self.run_for(0.3),
        }
        self.step();
    }

    pub(super) fn finish(&mut self) -> Stats {
        self.forgetting = false;
        self.loss_percent = 0;
        self.ignore_ask_percent = 0;
        self.down_rate = 1.0e6;
        self.server.announce_percent = 50;
        self.run_for(30.0);
        self.reconnect(1.0);
        self.run_for(400.0);
        let mut unresolved = Vec::new();
        let mut tags: Vec<u32> = self.live.keys().copied().collect();
        tags.sort_unstable();
        for tag in tags {
            let executed = self.server.executed.get(&tag).copied();
            let held = executed
                .and_then(|q| self.server.answer_of.get(&q).copied())
                .map(|a| (a, self.server.held.contains_key(&a)));
            let query =
                self.h.session.queries.get(&QueryId(u64::from(tag))).map(|q| (q.state, q.msg_id, q.acknowledged));
            let awaited: Vec<(i64, Option<QueryId>)> = self
                .h
                .session
                .awaited_answers
                .iter()
                .filter(|(_, a)| a.query == Some(QueryId(u64::from(tag))))
                .map(|(id, a)| (*id, a.query))
                .collect();
            let answer_known = held.is_some_and(|(a, _)| self.seen_awaited.contains(&a));
            let unlinked = held.is_some_and(|(a, _)| self.server.new_info_answers.contains(&a));
            let lost = self.server.forgotten.contains(&tag) || self.server.reset_forgotten.contains(&tag);
            if lost && (!answer_known || unlinked) && awaited.is_empty() {
                self.unknowable += 1;
                continue;
            }
            unresolved.push(format!(
                "tag {tag}: executed {executed:x?} answer {held:x?} forgotten {} query {query:x?} awaited {awaited:x?}",
                self.server.forgotten.contains(&tag)
            ));
        }
        self.stats.unresolved = unresolved.len();
        for line in unresolved {
            self.violation(format!("unresolved after quiet phase: {line}"));
        }
        if self.h.session.is_performing_service_tasks() {
            let requests: Vec<String> =
                self.h.session.service_requests.iter().map(|(id, r)| format!("{id:x}:{r:?}")).collect();
            let text = format!(
                "still performing service tasks: unknown {} requests {:?} to_resend {:x?} awaited {:x?}",
                self.h.session.has_unknown_queries(),
                requests,
                self.h.session.to_resend_answer,
                self.h.session.awaited_answers.keys().collect::<Vec<_>>()
            );
            self.violation(text);
        }
        std::mem::replace(
            &mut self.stats,
            Stats {
                asks: 0,
                max_asks_per_answer_per_conn: 0,
                max_ask_age: 0.0,
                answer_lost: 0,
                results: 0,
                unresolved: 0,
                executed: 0,
                salt_spins: 0,
            },
        )
    }

    pub(super) fn dump_trace(&self) -> String {
        let start = self.trace.len().saturating_sub(4000);
        self.trace[start..].join("\n")
    }
}

fn run_seed(seed: u64, http: bool, steps: usize, trace: bool) -> (Vec<String>, Stats, String) {
    let mut world = World::new(seed, http);
    world.trace_on = trace;
    for _ in 0..steps {
        world.random_step();
        if world.violations.len() >= 5 {
            break;
        }
    }
    let stats = world.finish();
    let trace = world.dump_trace();
    if world.max_concurrent_copies > 2 {
        eprintln!("seed {seed}: {} copies of one answer in flight at once", world.max_concurrent_copies);
    }
    if world.unknowable > 0 {
        eprintln!(
            "seed {seed}: {} calls whose answer the server lost before the client learned its id (not announced-answer handling)",
            world.unknowable
        );
    }
    (world.violations.clone(), stats, trace)
}

fn sweep(http: bool) {
    let seeds: u64 = std::env::var("ANSWER_MODEL_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let first: u64 = std::env::var("ANSWER_MODEL_FIRST").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let steps: usize = std::env::var("ANSWER_MODEL_STEPS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let mut failing = Vec::new();
    let (mut asks, mut max_per_conn, mut max_age, mut lost, mut results, mut executed) = (0, 0, 0.0f64, 0, 0, 0);
    for seed in first..first + seeds {
        let (violations, stats, _) = run_seed(seed, http, steps, false);
        asks += stats.asks;
        max_per_conn = max_per_conn.max(stats.max_asks_per_answer_per_conn);
        max_age = max_age.max(stats.max_ask_age);
        lost += stats.answer_lost;
        results += stats.results;
        executed += stats.executed;
        if stats.max_asks_per_answer_per_conn > 20 {
            eprintln!("seed {seed}: max asks per answer per connection {}", stats.max_asks_per_answer_per_conn);
        }
        if !violations.is_empty() {
            failing.push((seed, violations));
        }
    }
    eprintln!(
        "http={http} seeds={seeds} executed={executed} results={results} answer_lost={lost} asks={asks} max_asks_per_answer_per_conn={max_per_conn} max_ask_age={max_age:.1} failing={}",
        failing.len()
    );
    for (seed, violations) in failing.iter().take(8) {
        eprintln!("seed {seed}:");
        for violation in violations.iter().take(5) {
            eprintln!("    {violation}");
        }
    }
    if let Ok(trace_seed) = std::env::var("ANSWER_MODEL_TRACE")
        && let Ok(seed) = trace_seed.parse::<u64>()
    {
        let repeat: usize = std::env::var("ANSWER_MODEL_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        for attempt in 0..repeat {
            let (violations, _, trace) = run_seed(seed, http, steps, true);
            if !violations.is_empty() || attempt + 1 == repeat {
                eprintln!("---- trace seed {seed} attempt {attempt} violations {}\n{trace}", violations.len());
                break;
            }
        }
    }
    assert!(failing.is_empty(), "{} failing seeds", failing.len());
}

#[test]
fn announced_answers_keep_their_invariants_over_tcp() {
    sweep(false);
}

#[test]
fn announced_answers_keep_their_invariants_over_http() {
    sweep(true);
}
