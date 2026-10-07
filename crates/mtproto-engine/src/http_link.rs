use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use mio::{Registry, Token};
use mtproto_core::transport::{
    HttpError, HttpResponse, HttpResponseReader, HttpRoute, InputBuffer, Socks5Auth, Socks5Error, Socks5Handshake,
    Socks5Progress, Socks5Target, write_post_head,
};

use crate::connection::WRITE_COMPACT_THRESHOLD;
use crate::host_stream::HostPipe;
use crate::pipe::Pipe;

/// Connections one session keeps to the HTTP endpoint at most; browsers allow six per host.
pub const HTTP_MAX_CONNECTIONS: usize = 6;
/// Tokens a session owns: its stream connection, the racer, then its HTTP connections.
pub const TOKENS_PER_SESSION: usize = 16;
pub const HTTP_FIRST_TOKEN_OFFSET: usize = 2;

#[derive(Debug)]
pub enum HttpConnError {
    Io(io::Error),
    Http(HttpError),
    Socks(Socks5Error),
    Closed,
}

impl core::fmt::Display for HttpConnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HttpConnError::Io(error) => write!(f, "io: {error}"),
            HttpConnError::Http(error) => write!(f, "http: {error}"),
            HttpConnError::Socks(error) => write!(f, "socks5: {error}"),
            HttpConnError::Closed => f.write_str("closed by peer"),
        }
    }
}

/// What a request was for, kept until its response comes or the connection fails.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RequestMeta {
    /// The session's packet sequence number; None for a plain handshake message.
    pub packet_seq: Option<u64>,
    /// The `max_wait` it carried, in seconds: the server may hold the response that long.
    pub max_wait: f64,
    /// A long poll kept parked for whatever the server has next.
    pub slot: bool,
    pub queued_at: f64,
    pub bytes: usize,
    /// A plain req_pq asking whether the route reaches Telegram at all.
    pub probe: bool,
    /// The session (key) the packet belongs to; answers for an earlier one are not accounted.
    pub generation: u64,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    meta: RequestMeta,
    /// `written_total` once the request's last byte is handed to the kernel.
    end_offset: u64,
    written_at: Option<f64>,
}

enum Phase {
    Connecting,
    Socks(Socks5Handshake),
    Ready,
}

pub enum HttpIo {
    Connected,
    Response { meta: RequestMeta, response: HttpResponse, waited: f64 },
}

/// One keep-alive HTTP/1.1 connection carrying one request at a time.
pub struct HttpConn {
    pipe: Pipe,
    token: Token,
    phase: Phase,
    pending_socks: Option<(Socks5Target, Option<Socks5Auth>)>,
    socks_out: Vec<u8>,
    route: HttpRoute,
    write_buffer: Vec<u8>,
    /// Its requests carry `Proxy-Authorization` or its SOCKS5 output a password: the buffers are wiped,
    /// not just cleared, and never left behind by a reallocation.
    secret: bool,
    write_offset: usize,
    writable_interest: bool,
    written_total: u64,
    acknowledged_out: u64,
    input: InputBuffer,
    reader: HttpResponseReader,
    in_flight: VecDeque<InFlight>,
    body_started_at: Option<f64>,
    head_started_at: Option<f64>,
    pub address_index: usize,
    pub started_at: f64,
    pub established_at: Option<f64>,
    /// Response bytes arrived or the peer acknowledged request bytes.
    pub last_progress_at: f64,
    pub idle_since: f64,
    pub responses: u32,
    /// Response bytes came on it, whole or not: the server, or something on the way, answered.
    pub heard: bool,
    pub keep_alive: bool,
    /// What it carries went again elsewhere after its answer ran late; it is kept until then for the
    /// late answer, rather than paying for a new connection on a slow link.
    pub hedged_at: Option<f64>,
    pub cellular: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl HttpConn {
    pub fn connect(
        registry: &Registry,
        token: Token,
        address: SocketAddr,
        route: HttpRoute,
        socks: Option<(Socks5Target, Option<Socks5Auth>)>,
        address_index: usize,
        now: f64,
    ) -> io::Result<Self> {
        let pipe = Pipe::connect(registry, token, address)?;
        Ok(Self::over(pipe, token, route, socks, address_index, now))
    }

    /// A connection over a stream the host opened, TLS included.
    pub fn over_host(pipe: HostPipe, token: Token, route: HttpRoute, address_index: usize, now: f64) -> Self {
        Self::over(Pipe::Host(pipe), token, route, None, address_index, now)
    }

    fn over(
        pipe: Pipe,
        token: Token,
        route: HttpRoute,
        socks: Option<(Socks5Target, Option<Socks5Auth>)>,
        address_index: usize,
        now: f64,
    ) -> Self {
        let secret = matches!(&route, HttpRoute::Forwarded { credentials: Some(_), .. })
            || socks.as_ref().is_some_and(|(_, auth)| auth.is_some());
        Self {
            secret,
            pipe,
            token,
            phase: Phase::Connecting,
            pending_socks: socks,
            socks_out: Vec::new(),
            route,
            write_buffer: Vec::new(),
            write_offset: 0,
            writable_interest: true,
            written_total: 0,
            acknowledged_out: 0,
            input: InputBuffer::new(),
            reader: HttpResponseReader::new(),
            in_flight: VecDeque::new(),
            body_started_at: None,
            head_started_at: None,
            address_index,
            started_at: now,
            established_at: None,
            last_progress_at: now,
            idle_since: now,
            responses: 0,
            heard: false,
            keep_alive: true,
            hedged_at: None,
            cellular: false,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    pub fn is_host_stream(&self) -> bool {
        self.pipe.is_host()
    }

    pub fn token(&self) -> Token {
        self.token
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.phase, Phase::Ready)
    }

    /// Can take a request, now or once it connects: nothing outstanding and still kept alive.
    pub fn is_free(&self) -> bool {
        self.in_flight.is_empty() && self.keep_alive
    }

    /// Its requests go again elsewhere; it keeps waiting for their answers, takes nothing new until
    /// they come, and is free again once they did.
    pub fn hedge(&mut self, now: f64) -> Vec<RequestMeta> {
        self.hedged_at = Some(now);
        self.in_flight.iter().map(|request| request.meta).collect()
    }

    /// Bytes of the uploads (requests from `upload_min` bytes on) it carries that were not answered.
    pub fn upload_bytes_in_flight(&self, upload_min: usize) -> usize {
        if self.hedged_at.is_some() {
            return 0;
        }
        self.in_flight.iter().map(|request| request.meta.bytes).filter(|bytes| *bytes >= upload_min).sum()
    }

    /// Some request it carries is of the kind `matches` picks.
    pub fn carries(&self, matches: impl Fn(&RequestMeta) -> bool) -> bool {
        self.in_flight.iter().any(|request| matches(&request.meta))
    }

    /// Uploads (requests from `upload_min` bytes on) it is sending or sent that were not answered.
    pub fn uploads_in_flight(&self, upload_min: usize) -> usize {
        if self.hedged_at.is_some() || !self.is_ready() {
            return 0;
        }
        self.in_flight.iter().filter(|request| request.meta.bytes >= upload_min).count()
    }

    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// A request may queue behind the ones already sent: each of them is answered at once, so the
    /// new one waits a round trip at most. Never behind a long poll, which holds the line.
    pub fn takes_pipelined(&self, depth: usize) -> bool {
        self.is_ready()
            && self.keep_alive
            && self.hedged_at.is_none()
            && self.in_flight.len() < depth
            && self.in_flight.iter().all(|request| request.meta.max_wait == 0.0)
            && matches!(self.route, HttpRoute::Direct { .. } | HttpRoute::Web { .. })
    }

    /// A request carrying queries is held at the server for their answers. Not on a hedged connection:
    /// its queries went again elsewhere.
    pub fn waits_on_queries(&self) -> bool {
        self.hedged_at.is_none()
            && self.in_flight.iter().any(|request| !request.meta.slot && request.meta.max_wait > 0.0)
    }

    pub fn has_slot(&self) -> bool {
        self.in_flight.iter().any(|request| request.meta.slot)
    }

    pub fn lost_requests(&mut self) -> Vec<RequestMeta> {
        self.in_flight.drain(..).map(|request| request.meta).collect()
    }

    /// The current response's first byte arrived then and its body is not being read yet: a head, or
    /// an error body thrown away, that trickles in still has to end in time.
    pub fn head_in_progress(&self) -> Option<f64> {
        self.head_started_at.filter(|_| self.reader.body_progress().is_none())
    }

    /// A response has started arriving: how many body bytes so far, and since when.
    pub fn response_in_progress(&self) -> Option<(usize, f64)> {
        let (_, received) = self.reader.body_progress()?;
        Some((received, self.body_started_at?))
    }

    /// The request at the head of the line: when its last byte was handed over, and what it was.
    pub fn head(&self) -> Option<(Option<f64>, RequestMeta)> {
        self.in_flight.front().map(|request| (request.written_at, request.meta))
    }

    pub fn deregister(&mut self, registry: &Registry) {
        self.pipe.close(registry);
    }

    pub fn submit(
        &mut self,
        registry: &Registry,
        body: &[u8],
        meta: RequestMeta,
        now: f64,
    ) -> Result<(), HttpConnError> {
        compact(&mut self.write_buffer, &mut self.write_offset);
        let unsent_before = self.write_buffer.len() - self.write_offset;
        if self.secret {
            let mut head = Vec::with_capacity(4096);
            write_post_head(&self.route, body.len(), &mut head);
            reserve_wiping(&mut self.write_buffer, head.len() + body.len());
            self.write_buffer.extend_from_slice(&head);
            mtproto_core::Zeroize::zeroize(&mut head);
        } else {
            write_post_head(&self.route, body.len(), &mut self.write_buffer);
        }
        self.write_buffer.extend_from_slice(body);
        let unsent = self.write_buffer.len() - self.write_offset;
        let end_offset = self.written_total + unsent as u64;
        let meta = RequestMeta { bytes: unsent - unsent_before, ..meta };
        self.in_flight.push_back(InFlight { meta, end_offset, written_at: None });
        self.flush(registry, now)
    }

    pub fn handle_writable(&mut self, registry: &Registry, now: f64) -> Result<bool, HttpConnError> {
        let mut became_ready = false;
        if matches!(self.phase, Phase::Connecting) {
            if !self.pipe.finish_connect().map_err(HttpConnError::Io)? {
                return Ok(false);
            }
            self.cellular = self.pipe.is_cellular();
            match self.pending_socks.take() {
                Some((target, auth)) => {
                    let (handshake, greeting) = Socks5Handshake::new(target, auth).map_err(HttpConnError::Socks)?;
                    self.socks_out = greeting;
                    self.phase = Phase::Socks(handshake);
                }
                None => {
                    self.phase = Phase::Ready;
                    self.established_at = Some(now);
                    became_ready = true;
                }
            }
        }
        self.flush(registry, now)?;
        Ok(became_ready)
    }

    pub fn flush(&mut self, registry: &Registry, now: f64) -> Result<(), HttpConnError> {
        match self.phase {
            Phase::Connecting => return Ok(()),
            Phase::Socks(_) => {
                while !self.socks_out.is_empty() {
                    match self.pipe.write(&self.socks_out) {
                        Ok(0) => return Err(HttpConnError::Closed),
                        Ok(written) => {
                            self.bytes_out += written as u64;
                            self.socks_out.drain(..written);
                            if self.socks_out.is_empty() && self.secret {
                                mtproto_core::Zeroize::zeroize(&mut self.socks_out);
                            }
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                        Err(error) => return Err(HttpConnError::Io(error)),
                    }
                }
            }
            Phase::Ready => {
                while self.write_offset < self.write_buffer.len() {
                    match self.pipe.write(&self.write_buffer[self.write_offset..]) {
                        Ok(0) => return Err(HttpConnError::Closed),
                        Ok(written) => {
                            self.write_offset += written;
                            self.bytes_out += written as u64;
                            self.written_total += written as u64;
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                        Err(error) => return Err(HttpConnError::Io(error)),
                    }
                }
                for request in self.in_flight.iter_mut() {
                    if request.written_at.is_none() && self.written_total >= request.end_offset {
                        request.written_at = Some(now);
                    }
                }
                if self.write_offset == self.write_buffer.len() {
                    if self.secret {
                        mtproto_core::Zeroize::zeroize(&mut self.write_buffer);
                    }
                    self.write_buffer.clear();
                    self.write_offset = 0;
                    if self.write_buffer.capacity() > 256 * 1024 {
                        self.write_buffer = Vec::new();
                    }
                }
            }
        }
        let needs_writable = match self.phase {
            Phase::Connecting => true,
            Phase::Socks(_) => !self.socks_out.is_empty(),
            Phase::Ready => self.write_offset < self.write_buffer.len(),
        };
        if needs_writable != self.writable_interest {
            self.pipe.set_writable_interest(registry, self.token, needs_writable).map_err(HttpConnError::Io)?;
            self.writable_interest = needs_writable;
        }
        Ok(())
    }

    /// The peer acknowledged request bytes it had not before: an upload is crossing.
    pub fn note_outbound_progress(&mut self, now: f64) {
        let Some(queued) = self.pipe.send_queue() else {
            return;
        };
        let acknowledged = self.written_total.saturating_sub(queued as u64);
        if acknowledged > self.acknowledged_out {
            let previous = self.acknowledged_out;
            self.acknowledged_out = acknowledged;
            if self.in_flight.iter().any(|request| request.end_offset > previous) {
                self.last_progress_at = now;
            }
        }
    }

    /// Bytes handed over for requests the peer has not acknowledged yet, where the kernel says.
    pub fn unacknowledged_out(&self) -> Option<u64> {
        self.pipe.send_queue().map(|queued| queued as u64 + (self.write_buffer.len() - self.write_offset) as u64)
    }

    /// Reads up to `budget` bytes. Ok(true) when the budget ran out with more possibly waiting.
    pub fn read(
        &mut self,
        registry: &Registry,
        scratch: &mut [u8],
        budget: usize,
        now: f64,
        out: &mut Vec<HttpIo>,
    ) -> Result<bool, HttpConnError> {
        let mut read_total = 0usize;
        loop {
            if read_total >= budget {
                return Ok(true);
            }
            let read = match self.pipe.read(scratch) {
                Ok(0) => {
                    if let Some(response) = self.reader.finish().map_err(HttpConnError::Http)? {
                        self.complete(response, now, out)?;
                    }
                    return Err(HttpConnError::Closed);
                }
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(HttpConnError::Io(error)),
            };
            read_total += read;
            self.bytes_in += read as u64;
            if matches!(self.phase, Phase::Connecting) && self.handle_writable(registry, now)? {
                out.push(HttpIo::Connected);
            }
            match &mut self.phase {
                Phase::Connecting => return Err(HttpConnError::Closed),
                Phase::Socks(handshake) => {
                    self.input.extend(&scratch[..read]);
                    loop {
                        match handshake.feed(&mut self.input).map_err(HttpConnError::Socks)? {
                            Socks5Progress::NeedMore => break,
                            Socks5Progress::Send(mut bytes) => {
                                reserve_wiping(&mut self.socks_out, bytes.len());
                                self.socks_out.extend_from_slice(&bytes);
                                mtproto_core::Zeroize::zeroize(&mut bytes);
                            }
                            Socks5Progress::Connected => {
                                self.phase = Phase::Ready;
                                self.established_at = Some(now);
                                out.push(HttpIo::Connected);
                                break;
                            }
                        }
                    }
                    self.flush(registry, now)?;
                    if !self.is_ready() {
                        continue;
                    }
                }
                Phase::Ready => self.input.extend(&scratch[..read]),
            }
            self.drain_responses(now, out)?;
        }
    }

    fn drain_responses(&mut self, now: f64, out: &mut Vec<HttpIo>) -> Result<(), HttpConnError> {
        if self.input.is_empty() {
            return Ok(());
        }
        self.last_progress_at = now;
        self.heard = true;
        self.head_started_at.get_or_insert(now);
        loop {
            if self.in_flight.is_empty() {
                return if self.input.is_empty() { Ok(()) } else { Err(HttpConnError::Http(HttpError::Unsolicited)) };
            }
            let was_in_response = self.reader.in_response();
            let response = self.reader.read(&mut self.input).map_err(HttpConnError::Http)?;
            if !was_in_response && self.reader.in_response() {
                self.body_started_at = Some(now);
            }
            match response {
                Some(response) => {
                    self.complete(response, now, out)?;
                    if !self.input.is_empty() {
                        self.head_started_at = Some(now);
                    }
                }
                None => return Ok(()),
            }
        }
    }

    fn complete(&mut self, response: HttpResponse, now: f64, out: &mut Vec<HttpIo>) -> Result<(), HttpConnError> {
        let Some(request) = self.in_flight.pop_front() else {
            return Err(HttpConnError::Http(HttpError::Unsolicited));
        };
        self.responses += 1;
        self.body_started_at = None;
        self.head_started_at = None;
        self.keep_alive &= response.keep_alive;
        if self.in_flight.is_empty() {
            self.idle_since = now;
            self.hedged_at = None;
        }
        let waited = now - request.written_at.unwrap_or(request.meta.queued_at);
        out.push(HttpIo::Response { meta: request.meta, response, waited });
        Ok(())
    }

    pub fn shrink(&mut self) {
        self.input.shrink_if_idle(16 * 1024);
        if self.write_buffer.is_empty() && self.write_buffer.capacity() > 64 * 1024 {
            if self.secret {
                mtproto_core::Zeroize::zeroize(&mut self.write_buffer);
            }
            self.write_buffer = Vec::new();
        }
    }
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        if self.secret {
            mtproto_core::Zeroize::zeroize(&mut self.write_buffer);
            mtproto_core::Zeroize::zeroize(&mut self.socks_out);
        }
    }
}

/// Room for `additional` bytes without a reallocation that would free the old block unwiped.
fn reserve_wiping(buffer: &mut Vec<u8>, additional: usize) {
    if buffer.capacity() - buffer.len() >= additional {
        return;
    }
    let mut bigger = Vec::with_capacity((buffer.len() + additional).max(buffer.capacity() * 2));
    bigger.extend_from_slice(buffer);
    mtproto_core::Zeroize::zeroize(buffer);
    *buffer = bigger;
}

fn compact(buffer: &mut Vec<u8>, offset: &mut usize) {
    if *offset == buffer.len() {
        buffer.clear();
        *offset = 0;
    } else if *offset >= WRITE_COMPACT_THRESHOLD && *offset * 2 >= buffer.len() {
        buffer.drain(..*offset);
        *offset = 0;
    }
}
