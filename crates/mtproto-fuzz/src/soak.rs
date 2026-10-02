use std::collections::{HashMap, HashSet, VecDeque};

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::session::{Now, QueryId, QueryOptions, ServerSalt, Session, SessionConfig, SessionEvent};
use mtproto_core::test_support::server_peer::{self as sp, ClientMessage, Outgoing, ServerPeer};
use mtproto_core::tl::{Reader, ids};

use crate::generate::Gen;
use crate::targets::CaseResult;

const QUERY: u32 = 0x5157_4b51;
const START: f64 = 1_727_000_000.0;
const SALT_PERIOD: f64 = 3600.0;
const MAX_IDLE_FOOTPRINT: usize = 256 * 1024;

struct Server {
    peer: ServerPeer,
    executed: HashMap<u64, u32>,
    answers: HashMap<i64, (i64, Vec<u8>)>,
    answer_order: VecDeque<i64>,
    unacked: HashMap<i64, Vec<u8>>,
    received: HashSet<i64>,
    last_header_msg_id: i64,
    salt_rejections: usize,
}

impl Server {
    fn salt_at(time: f64) -> i64 {
        let slot = (time / SALT_PERIOD).floor() as i64;
        slot.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64) | 1
    }

    fn salt_is_valid(&self, salt: i64) -> bool {
        let now = self.peer.server_time;
        salt == Self::salt_at(now) || salt == Self::salt_at(now - SALT_PERIOD / 2.0)
    }

    fn future_salts(&self, req_msg_id: i64) -> Vec<u8> {
        let now = self.peer.server_time;
        let base = (now / SALT_PERIOD).floor() * SALT_PERIOD;
        let salts: Vec<(i32, i32, i64)> = (0..8)
            .map(|index| {
                let since = base + index as f64 * SALT_PERIOD;
                (since as i32, (since + SALT_PERIOD) as i32, Self::salt_at(since))
            })
            .collect();
        sp::future_salts(req_msg_id, now as i32, &salts)
    }

    fn resend_unacked(&mut self) -> Vec<Vec<u8>> {
        let mut pending: Vec<(i64, Vec<u8>)> =
            self.unacked.iter().map(|(msg_id, body)| (*msg_id, body.clone())).collect();
        pending.sort_by_key(|(msg_id, _)| *msg_id);
        pending.into_iter().map(|(msg_id, body)| self.peer.seal(msg_id, 1, &body)).collect()
    }

    fn handle(&mut self, packet: &[u8], g: &mut Gen) -> Result<Vec<Vec<u8>>, String> {
        let decoded = self.peer.decode(packet);
        let header = decoded.header;
        if header.msg_id <= self.last_header_msg_id {
            return Err(format!(
                "client msg_id went backwards: {:#x} after {:#x}",
                header.msg_id, self.last_header_msg_id
            ));
        }
        self.last_header_msg_id = header.msg_id;
        self.peer.salt = Self::salt_at(self.peer.server_time);
        if !self.salt_is_valid(header.salt) {
            self.salt_rejections += 1;
            let body = sp::bad_server_salt(header.msg_id, header.seq_no, self.peer.salt);
            return Ok(vec![self.peer.encode(vec![Outgoing::Service(body)])]);
        }
        let mut replies = Vec::new();
        let mut redelivered = Vec::new();
        for message in decoded.messages {
            self.handle_message(&message, &mut replies, &mut redelivered, g)?;
        }
        let mut packets = Vec::new();
        for (msg_id, body) in redelivered {
            packets.push(self.peer.seal(msg_id, 1, &body));
        }
        if !replies.is_empty() {
            packets.push(self.peer.encode(replies));
        }
        Ok(packets)
    }

    fn handle_message(
        &mut self,
        message: &ClientMessage,
        replies: &mut Vec<Outgoing>,
        redelivered: &mut Vec<(i64, Vec<u8>)>,
        g: &mut Gen,
    ) -> CaseResult {
        let mut reader = Reader::new(&message.body);
        let constructor = reader.read_u32().map_err(|error| error.to_string())?;
        match constructor {
            QUERY => {
                if message.seq_no & 1 == 0 {
                    return Err("query sent as a service message".into());
                }
                if let Some((answer_id, body)) = self.answers.get(&message.msg_id) {
                    redelivered.push((*answer_id, body.clone()));
                    return Ok(());
                }
                if !self.received.insert(message.msg_id) {
                    return Ok(());
                }
                let tag = reader.read_u64().map_err(|error| error.to_string())?;
                *self.executed.entry(tag).or_insert(0) += 1;
                let body = sp::rpc_result(message.msg_id, &tag.to_le_bytes());
                let answer_id = self.peer.next_msg_id(true);
                self.answers.insert(message.msg_id, (answer_id, body.clone()));
                self.answer_order.push_back(message.msg_id);
                while self.answer_order.len() > 4096 {
                    if let Some(old) = self.answer_order.pop_front() {
                        self.answers.remove(&old);
                    }
                }
                self.unacked.insert(answer_id, body.clone());
                let _ = g;
                redelivered.push((answer_id, body));
            }
            ids::PING | ids::PING_DELAY_DISCONNECT => {
                let ping_id = reader.read_i64().map_err(|error| error.to_string())?;
                replies.push(Outgoing::Service(sp::pong(message.msg_id, ping_id)));
            }
            ids::GET_FUTURE_SALTS => replies.push(Outgoing::Service(self.future_salts(message.msg_id))),
            ids::MSGS_STATE_REQ => {
                let asked = sp::read_vector_after_constructor(&message.body);
                let info: Vec<u8> = asked
                    .iter()
                    .map(|id| if self.answers.contains_key(id) || self.received.contains(id) { 4 } else { 1 })
                    .collect();
                replies.push(Outgoing::Service(sp::msgs_state_info(message.msg_id, &info)));
            }
            ids::MSG_RESEND_ANS_REQ | ids::MSG_RESEND_REQ => {
                for asked in sp::read_vector_after_constructor(&message.body) {
                    if let Some(body) = self.unacked.get(&asked) {
                        redelivered.push((asked, body.clone()));
                    }
                }
            }
            ids::MSGS_ACK => {
                for acked in sp::read_vector_after_constructor(&message.body) {
                    self.unacked.remove(&acked);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

struct World {
    session: Session,
    server: Server,
    rng: XorShiftRandom,
    now: Now,
    connected: bool,
    fresh_connection: bool,
    issued: u64,
    completed: HashMap<u64, u32>,
}

impl World {
    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.peer.server_time += seconds;
    }

    fn exchange(&mut self, g: &mut Gen, lossy: bool) -> CaseResult {
        for _ in 0..64 {
            let _ = self.session.handle_timeout(self.now);
            let Some(transmit) = self.session.poll_transmit(self.now, &mut self.rng) else {
                return Ok(());
            };
            if !self.connected {
                continue;
            }
            if std::mem::take(&mut self.fresh_connection) {
                for packet in self.server.resend_unacked() {
                    let _ = self.session.handle_packet(&packet, self.now, &mut self.rng);
                }
            }
            if lossy && g.one_in(40) {
                if g.one_in(2) {
                    let _ = self.server.handle(&transmit.data, g)?;
                }
                self.reconnect(g);
                continue;
            }
            for packet in self.server.handle(&transmit.data, g)? {
                let _ = self.session.handle_packet(&packet, self.now, &mut self.rng);
            }
            self.collect()?;
        }
        Ok(())
    }

    fn reconnect(&mut self, g: &mut Gen) {
        self.session.connection_closed();
        if g.one_in(4) {
            self.advance(0.2 + g.below(5000) as f64 / 1000.0);
        }
        self.session.connection_opened(self.now);
        self.fresh_connection = true;
    }

    fn collect(&mut self) -> CaseResult {
        for event in self.session.drain_events() {
            match event {
                SessionEvent::Result { id, body, .. } => {
                    let tag =
                        u64::from_le_bytes(body.get(..8).and_then(|bytes| bytes.try_into().ok()).unwrap_or([0; 8]));
                    if tag != id.0 {
                        return Err(format!("query {} completed with the answer of {tag}", id.0));
                    }
                    *self.completed.entry(id.0).or_insert(0) += 1;
                }
                SessionEvent::Error { id, code, message, .. } => {
                    return Err(format!("query {} failed with {code} {message}", id.0));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn send(&mut self) {
        self.issued += 1;
        let mut body = QUERY.to_le_bytes().to_vec();
        body.extend_from_slice(&self.issued.to_le_bytes());
        self.session.send(QueryId(self.issued), body, QueryOptions::default(), self.now);
    }
}

pub fn soak_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let mut key_bytes = [0u8; 256];
    for (index, byte) in key_bytes.iter_mut().enumerate() {
        *byte = (seed as u8).wrapping_mul(31).wrapping_add(index as u8);
    }
    let key = AuthKey::new(key_bytes);
    let now = Now { mono: 1000.0, unix: START };
    let salts = [ServerSalt {
        salt: Server::salt_at(START),
        valid_since: START - SALT_PERIOD,
        valid_until: START + SALT_PERIOD / 2.0,
    }];
    let mut rng = XorShiftRandom::new(seed ^ 0x50a6);
    let mut session = Session::new(SessionConfig::default(), key.clone(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let mut peer = ServerPeer::new(key, START);
    peer.salt = Server::salt_at(START);
    let server = Server {
        peer,
        executed: HashMap::new(),
        answers: HashMap::new(),
        answer_order: VecDeque::new(),
        unacked: HashMap::new(),
        received: HashSet::new(),
        salt_rejections: 0,
        last_header_msg_id: 0,
    };
    let mut world = World {
        session,
        server,
        rng,
        now,
        connected: true,
        fresh_connection: false,
        issued: 0,
        completed: HashMap::new(),
    };
    let days = g.range(30, 90) as f64;
    let burst = if g.one_in(3) { 60 } else { 6 };
    let end = world.now.mono + days * 86_400.0;
    let mut peak_footprint = 0usize;
    while world.now.mono < end {
        match g.below(100) {
            0 => {
                world.session.connection_closed();
                world.connected = false;
                let hours = 1.0 + g.below(72) as f64;
                world.advance(hours * 3600.0);
                if g.one_in(4) {
                    world.now.unix += (g.below(7200) as f64) - 3600.0;
                }
                world.connected = true;
                world.session.connection_opened(world.now);
                world.fresh_connection = true;
            }
            1..=3 => world.reconnect(&mut g),
            4..=30 => world.advance(60.0 + g.below(3600) as f64),
            _ => {
                for _ in 0..g.range(1, burst) {
                    world.send();
                }
                world.advance(0.02 + g.below(2000) as f64 / 1000.0);
            }
        }
        world.exchange(&mut g, true)?;
        peak_footprint = peak_footprint.max(world.session.footprint());
    }
    for _ in 0..400 {
        world.advance(1.0);
        world.exchange(&mut g, false)?;
        if world.completed.len() as u64 == world.issued {
            break;
        }
    }
    for id in 1..=world.issued {
        match world.completed.get(&id).copied().unwrap_or(0) {
            1 => {}
            0 => return Err(format!("query {id} of {} never completed after {days} simulated days", world.issued)),
            count => return Err(format!("query {id} completed {count} times")),
        }
        match world.server.executed.get(&id).copied().unwrap_or(0) {
            1 => {}
            count => return Err(format!("query {id} executed {count} times on the server")),
        }
    }
    if std::env::var_os("MTPROTO_FUZZ_TRACE").is_some() {
        eprintln!(
            "soak: {days} days, {} queries, {} executed, {} salts handed out, peak footprint {peak_footprint}",
            world.issued,
            world.server.executed.len(),
            world.server.salt_rejections
        );
    }
    world.advance(600.0);
    world.exchange(&mut g, false)?;
    world.session.shrink();
    let idle = world.session.footprint();
    if idle > MAX_IDLE_FOOTPRINT {
        return Err(format!("idle footprint {idle} bytes after {days} days (peak {peak_footprint})"));
    }
    let next = msg_id_for_time(world.server.peer.server_time);
    if world.server.last_header_msg_id > next + (1i64 << 34) {
        return Err("client msg_ids ran ahead of the server clock".into());
    }
    Ok(())
}
