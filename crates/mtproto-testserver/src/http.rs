//! MTProto over HTTP/1.1 the way Telegram's servers speak it (probed on production DC2,
//! 2026-10-03): one encrypted packet per POST and per response, transport errors as HTTP status
//! codes, `http_wait` long polls where a new message goes to the newest parked request of the
//! session, unacknowledged small messages carried again in every response and large ones announced
//! by `msg_detailed_info`, keep-alive connections closed after about 90 s idle.

use std::collections::{HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{SecureRandom, XorShiftRandom};
use mtproto_core::message::read_auth_key_id;
use mtproto_core::test_support::ServerHandshake;
use mtproto_core::test_support::server_peer::{self as sp, ServerPeer};
use mtproto_core::tl::{Reader, ids};
use mtproto_core::transport::InputBuffer;

use super::{
    Delayed, HandshakeFault, RawHostile, Reaction, ServerOptions, Shared, chaos, process_packet, server_now, unix_now,
};

/// Unacknowledged answers up to this size go out again in full with every response; larger ones
/// are announced with `msg_detailed_info` (DC2 re-sent a 470-byte answer, announced a 3.4 KB one).
pub const INLINE_RESEND_MAX: usize = 1024;
pub const DEFAULT_MAX_WAIT_MS: i32 = 25_000;
pub const DEFAULT_IDLE_TIMEOUT: f64 = 90.0;
pub const DEFAULT_RESPONSE_LIMIT: usize = 1024 * 1024;
/// How long an answer takes to be ready over HTTP: the real servers execute queries apart from the
/// request that carried them, so a request answered at once carries only an acknowledgement.
pub const DEFAULT_PROCESSING_DELAY: f64 = 0.005;
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wait {
    max_delay: i32,
    wait_after: i32,
    max_wait: i32,
}

impl Default for Wait {
    fn default() -> Self {
        Wait { max_delay: 0, wait_after: 0, max_wait: DEFAULT_MAX_WAIT_MS }
    }
}

struct Request {
    body: Vec<u8>,
    keep_alive: bool,
}

pub(super) fn starts_like_http(head: &[u8]) -> bool {
    matches!(head, b"POST" | b"GET " | b"HEAD" | b"OPTI" | b"PUT ")
}

fn read_request(
    stream: &mut TcpStream,
    buffer: &mut InputBuffer,
    stop: &AtomicBool,
    idle: Duration,
) -> std::io::Result<Option<Request>> {
    let started = Instant::now();
    loop {
        let data = buffer.as_slice();
        if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_string();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or_default();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default();
            let _target = parts.next().unwrap_or_default();
            let version = parts.next().unwrap_or_default();
            let mut length = 0usize;
            let mut keep_alive = version == "HTTP/1.1";
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    return Err(std::io::Error::new(ErrorKind::InvalidData, "header"));
                };
                let value = value.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.parse().map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "length"))?;
                } else if name.eq_ignore_ascii_case("connection") {
                    keep_alive = !value.eq_ignore_ascii_case("close");
                }
            }
            if method != "POST" || length > MAX_REQUEST_BODY {
                return Err(std::io::Error::new(ErrorKind::InvalidData, "not a POST"));
            }
            if data.len() >= end + 4 + length {
                buffer.consume(end + 4);
                let body = buffer.take(length);
                return Ok(Some(Request { body, keep_alive }));
            }
        } else if data.len() > MAX_REQUEST_HEAD {
            return Err(std::io::Error::new(ErrorKind::InvalidData, "head"));
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut chunk = [0u8; 65536];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(read) => buffer.extend(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {
                if buffer.is_empty() && started.elapsed() >= idle {
                    return Ok(None);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let content_type = if status == 200 { "application/octet-stream" } else { "text/html" };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: {}\r\nContent-Type: {content_type}\r\nPragma: no-cache\r\nCache-control: no-store\r\nContent-Length: {}\r\n\r\n",
        if keep_alive { "keep-alive" } else { "close" },
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    stream.write_all(&out)
}

fn status_for(code: i32) -> (u16, &'static str) {
    match -code {
        404 => (404, "Not Found"),
        429 => (429, "Too Many Requests"),
        444 => (444, "No Response"),
        403 => (403, "Forbidden"),
        status @ 100..=599 => (status as u16, "Error"),
        _ => (500, "Internal Server Error"),
    }
}

fn error_page(status: u16) -> Vec<u8> {
    format!("<html>\r\n<head><title>{status}</title></head>\r\n<body><center><h1>{status}</h1></center></body>\r\n</html>\r\n")
        .into_bytes()
}

fn find_http_wait(key: &AuthKey, packet: &[u8]) -> (Wait, Vec<i64>) {
    let decoded = ServerPeer::new(key.clone(), unix_now()).decode(packet);
    let received =
        decoded.messages.iter().filter(|message| message.is_content_related()).map(|message| message.msg_id).collect();
    let wait = decoded
        .messages
        .iter()
        .find(|message| message.constructor() == ids::HTTP_WAIT)
        .and_then(|message| {
            let mut reader = Reader::new(&message.body[4..]);
            Some(Wait {
                max_delay: reader.read_i32().ok()?,
                wait_after: reader.read_i32().ok()?,
                max_wait: reader.read_i32().ok()?,
            })
        })
        .unwrap_or_default();
    (wait, received)
}

/// Queues a reply for the session: content messages stay unacknowledged until the client acks them
/// and go out with every response meanwhile; the others go out once.
pub(super) fn queue(shared: &mut Shared, session_id: i64, body: Vec<u8>, content: bool) {
    let Some(session) = shared.sessions.get_mut(&session_id) else {
        return;
    };
    session.peer.server_time = server_now(session.clock_offset);
    let msg_id = session.peer.next_msg_id(true);
    if content {
        if body.len() >= 12 && u32::from_le_bytes(body[..4].try_into().unwrap()) == ids::RPC_RESULT {
            let req_msg_id = i64::from_le_bytes(body[4..12].try_into().unwrap());
            session.answer_ids.insert(req_msg_id, msg_id);
        }
        session.unacked.push((msg_id, 1, body));
    } else {
        shared.http.outbox.entry(session_id).or_default().push((msg_id, 0, body));
    }
    let now = shared.clock();
    shared.http.changed_at.insert(session_id, now);
    shared.http.wake.notify_all();
}

const MAX_PENDING_HANDSHAKES: usize = 256;

#[derive(Default)]
pub(super) struct HttpShared {
    outbox: std::collections::HashMap<i64, Vec<(i64, i32, Vec<u8>)>>,
    sealed: std::collections::HashMap<i64, VecDeque<Vec<u8>>>,
    sent: std::collections::HashMap<i64, HashSet<i64>>,
    waiters: std::collections::HashMap<i64, Vec<u64>>,
    /// Content messages received and not acknowledged yet; an answer delivered acknowledges its query.
    acks: std::collections::HashMap<i64, Vec<i64>>,
    changed_at: std::collections::HashMap<i64, Instant>,
    delayed: Vec<Delayed>,
    /// Auth key handshakes by nonce, as the real server keeps them: each step may come on another
    /// connection.
    handshakes: std::collections::HashMap<[u8; 16], ServerHandshake>,
    next_waiter: u64,
    /// Wakes parked requests when something is queued for a session or a newer request left.
    wake: Arc<Condvar>,
}

#[derive(Debug, Default, Clone)]
pub struct HttpStats {
    pub requests: usize,
    pub long_polls: usize,
    pub empty_responses: usize,
    pub detailed_infos: usize,
    pub inline_resends: usize,
    pub idle_closes: usize,
    pub most_waiters: usize,
    pub status_errors: usize,
}

impl HttpShared {
    pub(super) fn wake_all(&self) {
        self.wake.notify_all();
    }
}

fn deliverable(shared: &Shared, session_id: i64) -> bool {
    if shared.http.outbox.get(&session_id).is_some_and(|outbox| !outbox.is_empty())
        || shared.http.sealed.get(&session_id).is_some_and(|sealed| !sealed.is_empty())
    {
        return true;
    }
    let sent = shared.http.sent.get(&session_id);
    shared
        .sessions
        .get(&session_id)
        .is_some_and(|session| session.unacked.iter().any(|(id, _, _)| sent.is_none_or(|sent| !sent.contains(id))))
}

/// Answers held for HTTP's processing delay that are due go to the session's queue; every transport
/// calls this, so a session that moved to TCP still gets them.
pub(super) fn release_delayed(shared: &mut Shared) {
    let now = shared.clock();
    let due: Vec<Delayed> = {
        let (due, later): (Vec<Delayed>, Vec<Delayed>) = shared.http.delayed.drain(..).partition(|item| item.at <= now);
        shared.http.delayed = later;
        due
    };
    for item in due {
        queue(shared, item.session_id, item.body, true);
    }
}

fn take_response(shared: &mut Shared, session_id: i64, limit: usize) -> Vec<u8> {
    if let Some(packet) = shared.http.sealed.get_mut(&session_id).and_then(VecDeque::pop_front) {
        return packet;
    }
    let mut acks = shared.http.acks.remove(&session_id).unwrap_or_default();
    let mut messages: Vec<(i64, i32, Vec<u8>)> = shared.http.outbox.remove(&session_id).unwrap_or_default();
    let mut size: usize = messages.iter().map(|(_, _, body)| body.len() + 16).sum();
    let sent = shared.http.sent.entry(session_id).or_default();
    let Some(session) = shared.sessions.get_mut(&session_id) else {
        return Vec::new();
    };
    session.peer.server_time = server_now(session.clock_offset);
    let unacked: HashSet<i64> = session.unacked.iter().map(|(id, _, _)| *id).collect();
    sent.retain(|id| unacked.contains(id));
    let mut included: HashSet<i64> = messages.iter().map(|(id, _, _)| *id).collect();
    let mut announcements = Vec::new();
    for (msg_id, seq, body) in &session.unacked {
        if !included.insert(*msg_id) {
            continue;
        }
        if sent.contains(msg_id) && body.len() > INLINE_RESEND_MAX {
            let req_msg_id = (body.len() >= 12 && u32::from_le_bytes(body[..4].try_into().unwrap()) == ids::RPC_RESULT)
                .then(|| i64::from_le_bytes(body[4..12].try_into().unwrap()));
            announcements.push(match req_msg_id {
                Some(request) => sp::msg_detailed_info(request, *msg_id, body.len() as i32),
                None => sp::msg_new_detailed_info(*msg_id, body.len() as i32),
            });
            shared.stats.http.detailed_infos += 1;
            continue;
        }
        if size + body.len() > limit && !messages.is_empty() {
            continue;
        }
        if sent.contains(msg_id) {
            shared.stats.http.inline_resends += 1;
        }
        size += body.len() + 16;
        messages.push((*msg_id, *seq, body.clone()));
        sent.insert(*msg_id);
    }
    for body in announcements {
        let msg_id = session.peer.next_msg_id(true);
        messages.push((msg_id, 0, body));
    }
    for (_, _, body) in &messages {
        if body.len() >= 12 && u32::from_le_bytes(body[..4].try_into().unwrap()) == ids::RPC_RESULT {
            let req_msg_id = i64::from_le_bytes(body[4..12].try_into().unwrap());
            acks.retain(|id| *id != req_msg_id);
        }
    }
    if !acks.is_empty() {
        messages.push((session.peer.next_msg_id(true), 0, sp::msgs_ack(&acks)));
    }
    if messages.is_empty() {
        shared.stats.http.empty_responses += 1;
        messages.push((session.peer.next_msg_id(true), 0, sp::msgs_ack(&[])));
    }
    if messages.len() == 1 {
        let (msg_id, seq, body) = messages.pop().unwrap();
        return session.peer.seal(msg_id, seq, &body);
    }
    let container_id = session.peer.next_msg_id(true);
    let body = sp::container(&messages);
    session.peer.seal(container_id, 0, &body)
}

/// Parks a request until something is due for its session and it is the newest parked one, or
/// until its `max_wait`, then returns the response body.
/// The client hung up while a request was parked: it must stop taking the session's messages.
fn peer_closed(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let closed = matches!(stream.peek(&mut byte), Ok(0));
    let _ = stream.set_nonblocking(false);
    closed
}

fn wait_for_response(
    shared: &Arc<Mutex<Shared>>,
    stream: &TcpStream,
    session_id: i64,
    wait: Wait,
    stop: &AtomicBool,
    limit: usize,
) -> Option<Vec<u8>> {
    let (me, started) = {
        let mut guard = shared.lock().unwrap();
        let started = guard.clock();
        guard.http.next_waiter += 1;
        let me = guard.http.next_waiter;
        let waiters = guard.http.waiters.entry(session_id).or_default();
        waiters.push(me);
        let count = waiters.len();
        guard.stats.http.most_waiters = guard.stats.http.most_waiters.max(count);
        if wait.max_wait > 0 {
            guard.stats.http.long_polls += 1;
        }
        (me, started)
    };
    let max_wait = Duration::from_millis(wait.max_wait.max(0) as u64);
    let mut first_ready: Option<Instant> = None;
    let mut last_peek = Instant::now();
    let mut guard = shared.lock().unwrap();
    let wake = guard.http.wake.clone();
    loop {
        release_delayed(&mut guard);
        let newest = guard.http.waiters.get(&session_id).and_then(|waiters| waiters.iter().max().copied()) == Some(me);
        let ready = deliverable(&guard, session_id);
        let now = guard.clock();
        let mut respond = now.duration_since(started) >= max_wait;
        let mut next = started + max_wait;
        if ready && newest {
            let first = *first_ready.get_or_insert(now);
            let last_change = guard.http.changed_at.get(&session_id).copied().unwrap_or(first);
            let delay_until = first + Duration::from_millis(wait.max_delay.max(0) as u64);
            let quiet_until = last_change + Duration::from_millis(wait.wait_after.max(0) as u64);
            respond |= now >= delay_until || now >= quiet_until;
            next = next.min(delay_until).min(quiet_until);
        }
        if let Some(due) = guard.http.delayed.iter().map(|item| item.at).min() {
            next = next.min(due);
        }
        if respond || stop.load(Ordering::Relaxed) {
            if let Some(waiters) = guard.http.waiters.get_mut(&session_id) {
                waiters.retain(|waiter| *waiter != me);
            }
            let body = take_response(&mut guard, session_id, limit);
            wake.notify_all();
            return if stop.load(Ordering::Relaxed) { None } else { Some(body) };
        }
        let timeout = next.saturating_duration_since(now).clamp(Duration::from_micros(200), Duration::from_millis(50));
        guard = wake.wait_timeout(guard, timeout).unwrap().0;
        if last_peek.elapsed() >= Duration::from_millis(50) {
            drop(guard);
            let closed = peer_closed(stream);
            last_peek = Instant::now();
            guard = shared.lock().unwrap();
            if closed {
                if let Some(waiters) = guard.http.waiters.get_mut(&session_id) {
                    waiters.retain(|waiter| *waiter != me);
                }
                wake.notify_all();
                return None;
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn serve_http(
    mut stream: TcpStream,
    mut buffer: InputBuffer,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    options: ServerOptions,
    seed: u64,
) -> std::io::Result<()> {
    let mut rng = XorShiftRandom::new(seed);
    let mut chaos_rng = XorShiftRandom::new(options.chaos.as_ref().map_or(1, |chaos| chaos.seed) ^ rng.next_u64());
    let kill_rate = options.chaos.as_ref().map_or(0.0, |chaos| chaos.rate(chaos::Fault::AdaptiveKillOnRetransmit));
    let mut resent_for = super::Delivered::default();
    let idle = Duration::from_secs_f64(options.http_idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));
    let limit = options.http_response_limit.unwrap_or(DEFAULT_RESPONSE_LIMIT);
    let processing_delay = options.http_processing_delay.unwrap_or(DEFAULT_PROCESSING_DELAY);
    loop {
        let request = match read_request(&mut stream, &mut buffer, &stop, idle) {
            Ok(Some(request)) => request,
            Ok(None) => {
                if buffer.is_empty() && !stop.load(Ordering::Relaxed) {
                    shared.lock().unwrap().stats.http.idle_closes += 1;
                }
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(_) => {
                let _ = write_response(&mut stream, 400, "Bad Request", &error_page(400), false);
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
        };
        let keep_alive = request.keep_alive;
        let packet = request.body;
        {
            let mut guard = shared.lock().unwrap();
            guard.stats.http.requests += 1;
        }
        let Some(auth_key_id) = read_auth_key_id(&packet) else {
            write_response(&mut stream, 400, "Bad Request", &error_page(400), false)?;
            return Ok(());
        };
        if auth_key_id == 0 {
            let starts = mtproto_core::message::decode_plain_message(&packet)
                .ok()
                .and_then(|message| message.body.get(..4).map(|head| u32::from_le_bytes(head.try_into().unwrap())))
                == Some(ids::REQ_PQ_MULTI);
            if starts {
                let fault = shared.lock().unwrap().handshake_faults.pop_front();
                match fault {
                    Some(HandshakeFault::TransportError(code)) => {
                        let (status, reason) = status_for(code);
                        let mut guard = shared.lock().unwrap();
                        guard.stats.transport_errors_sent += 1;
                        guard.stats.http.status_errors += 1;
                        drop(guard);
                        write_response(&mut stream, status, reason, &error_page(status), false)?;
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                    Some(HandshakeFault::Stall) => {
                        let started = Instant::now();
                        while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(60) {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        return Ok(());
                    }
                    None => {}
                }
            }
            let nonce: Option<[u8; 16]> = packet.get(24..40).map(|bytes| bytes.try_into().expect("16 bytes"));
            let mut handshake = nonce
                .and_then(|nonce| shared.lock().unwrap().http.handshakes.remove(&nonce))
                .unwrap_or_else(|| ServerHandshake::new(options.handshake.clone()));
            let reply = handshake.handle(&packet, &mut rng);
            {
                let mut guard = shared.lock().unwrap();
                if let Some(outcome) = handshake.outcome.clone() {
                    guard.stats.handshakes += 1;
                    super::register_key(&mut guard, &outcome, options.clock_offset);
                } else if let Some(nonce) = nonce {
                    if guard.http.handshakes.len() >= MAX_PENDING_HANDSHAKES {
                        guard.http.handshakes.clear();
                    }
                    guard.http.handshakes.insert(nonce, handshake);
                }
            }
            write_response(&mut stream, 200, "OK", &reply.unwrap_or_default(), keep_alive)?;
            continue;
        }
        if let Some(code) = options.reject_with {
            let (status, reason) = status_for(code);
            let mut guard = shared.lock().unwrap();
            guard.stats.transport_errors_sent += 1;
            guard.stats.http.status_errors += 1;
            drop(guard);
            write_response(&mut stream, status, reason, &error_page(status), keep_alive)?;
            continue;
        }
        let key = super::usable_key(&mut shared.lock().unwrap(), auth_key_id, options.clock_offset);
        let Some(key) = key else {
            shared.lock().unwrap().stats.http.status_errors += 1;
            write_response(&mut stream, 404, "Not Found", &error_page(404), keep_alive)?;
            continue;
        };
        let (wait, received) = find_http_wait(&key, &packet);
        let mut delayed = Vec::new();
        let reaction: Reaction = process_packet(
            &options,
            &shared,
            &mut resent_for,
            &mut chaos_rng,
            kill_rate,
            &mut delayed,
            &key,
            auth_key_id,
            &packet,
            None,
            true,
            seed,
        );
        if reaction.kill_now {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        let session_id = reaction.session_id;
        {
            let mut guard = shared.lock().unwrap();
            guard.http.delayed.extend(delayed);
            let kept: Vec<i64> = guard
                .sessions
                .get(&session_id)
                .map(|session| received.iter().copied().filter(|id| session.received.contains(id)).collect())
                .unwrap_or_default();
            guard.http.acks.entry(session_id).or_default().extend(kept);
            let ready_at = guard.clock() + Duration::from_secs_f64(processing_delay);
            for (body, content) in reaction.outgoing {
                let answer = body.len() >= 12 && u32::from_le_bytes(body[..4].try_into().unwrap()) == ids::RPC_RESULT;
                if content && answer && processing_delay > 0.0 {
                    guard.http.delayed.push(Delayed { at: ready_at, session_id, body });
                } else {
                    queue(&mut guard, session_id, body, content);
                }
            }
            if !reaction.resend.is_empty() {
                let outbox = guard.http.outbox.entry(session_id).or_default();
                for entry in reaction.resend {
                    if !outbox.iter().any(|(id, _, _)| *id == entry.0) {
                        outbox.push(entry);
                    }
                }
                let now = guard.clock();
                guard.http.changed_at.insert(session_id, now);
                guard.http.wake.notify_all();
            }
            let sealed = guard.http.sealed.entry(session_id).or_default();
            sealed.extend(reaction.sealed_extra);
        }
        if let Some(duration) = reaction.stall {
            std::thread::sleep(duration);
        }
        if let Some(code) = reaction.transport_error {
            let (status, reason) = status_for(code);
            let mut guard = shared.lock().unwrap();
            guard.stats.transport_errors_sent += 1;
            guard.stats.http.status_errors += 1;
            drop(guard);
            write_response(&mut stream, status, reason, &error_page(status), false)?;
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        if let Some(frame) = reaction.hostile_frames.into_iter().next() {
            write_response(&mut stream, 200, "OK", &frame, false)?;
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        if let Some(kind) = reaction.hostile_raw {
            let head: &[u8] = match kind {
                RawHostile::Oversized => b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n\x55\x55\x55\x55",
                RawHostile::Truncated => {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
                }
            };
            stream.write_all(head)?;
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        if let Some(mode) = reaction.trickle {
            let declared = if mode == 3 { 8u32 << 20 } else { 2u32 << 20 };
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").as_bytes())?;
            let started = Instant::now();
            while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(90) {
                std::thread::sleep(Duration::from_millis(300));
                if stream.write_all(&[0x55]).is_err() {
                    break;
                }
            }
            return Ok(());
        }
        if reaction.close_after {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        let Some(body) = wait_for_response(&shared, &stream, session_id, wait, &stop, limit) else {
            return Ok(());
        };
        let keep = keep_alive;
        if reaction.drip {
            let mut out =
                format!("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n", body.len())
                    .into_bytes();
            out.extend_from_slice(&body);
            {
                let mut guard = shared.lock().unwrap();
                guard.stats.dripped_packets += 1;
                guard.stats.dripped_bytes += body.len();
            }
            for chunk in out.chunks(1 + (chaos_rng.next_u64() % 48) as usize) {
                stream.write_all(chunk)?;
                std::thread::sleep(Duration::from_micros(500 + chaos_rng.next_u64() % 2500));
            }
        } else {
            write_response(&mut stream, 200, "OK", &body, keep)?;
        }
        if !keep {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
    }
}
