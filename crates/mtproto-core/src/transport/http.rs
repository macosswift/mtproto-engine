use base64::Engine as _;

use super::buffer::InputBuffer;
use super::codec::MAX_INBOUND_FRAME_LEN;

pub const MAX_HEAD_LEN: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_ERROR_BODY_LEN: usize = 64 * 1024;
pub const MAX_CHUNK_LINE_LEN: usize = 1024;
pub const API_PATH: &str = "/api";

#[derive(Clone, PartialEq, Eq)]
pub struct HttpCredentials {
    pub username: String,
    pub password: String,
}

impl core::fmt::Debug for HttpCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HttpCredentials(..)")
    }
}

impl Drop for HttpCredentials {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}

impl HttpCredentials {
    fn header_value(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))
    }
}

/// Where a POST goes: straight to the datacenter, to a forwarding proxy that is given the
/// datacenter's address in the request line, or to Telegram Web's endpoint on a web front (inside
/// TLS) at its own path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRoute {
    Direct { authority: String },
    Forwarded { authority: String, credentials: Option<HttpCredentials> },
    Web { host: String, path: String },
}

pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

pub fn write_post_head(route: &HttpRoute, body_len: usize, out: &mut Vec<u8>) {
    match route {
        HttpRoute::Direct { authority } => {
            out.extend_from_slice(b"POST ");
            out.extend_from_slice(API_PATH.as_bytes());
            out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
            out.extend_from_slice(authority.as_bytes());
            out.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
        }
        HttpRoute::Forwarded { authority, credentials } => {
            out.extend_from_slice(b"POST http://");
            out.extend_from_slice(authority.as_bytes());
            out.extend_from_slice(API_PATH.as_bytes());
            out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
            out.extend_from_slice(authority.as_bytes());
            out.extend_from_slice(b"\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n");
            if let Some(credentials) = credentials {
                out.extend_from_slice(b"Proxy-Authorization: ");
                out.extend_from_slice(credentials.header_value().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
        HttpRoute::Web { host, path } => {
            out.extend_from_slice(b"POST ");
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
        }
    }
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\nContent-Length: ");
    out.extend_from_slice(body_len.to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
}

pub fn encode_post(route: &HttpRoute, body: &[u8], out: &mut Vec<u8>) {
    write_post_head(route, body.len(), out);
    out.extend_from_slice(body);
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("malformed status line")]
    StatusLine,
    #[error("malformed header")]
    Header,
    #[error("response head is too large")]
    HeadTooLarge,
    #[error("too many headers")]
    TooManyHeaders,
    #[error("conflicting or invalid Content-Length")]
    ContentLength,
    #[error("unsupported Transfer-Encoding")]
    TransferEncoding,
    #[error("malformed chunk")]
    Chunk,
    #[error("body of {0} bytes is too large")]
    BodyTooLarge(u64),
    #[error("connection closed in the middle of a response")]
    Truncated,
    #[error("unexpected bytes with no request outstanding")]
    Unsolicited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub keep_alive: bool,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The transport error the status stands for, as the TCP transports send them in a 4-byte frame.
    pub fn transport_error(&self) -> Option<i32> {
        match self.status {
            200..=299 => (self.body.len() == 4)
                .then(|| i32::from_le_bytes(self.body[..4].try_into().expect("4")))
                .filter(|code| *code < 0),
            status => Some(-i32::from(status)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    Length(usize),
    Chunked,
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(usize),
    DataEnd,
    Trailers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Head,
    Body { framing: BodyFraming, chunk: ChunkState },
}

/// Reads HTTP/1.x responses off a byte stream, one per request sent, in order. Bounded: heads up to
/// `MAX_HEAD_LEN`, successful bodies up to the MTProto inbound frame cap, error bodies up to
/// `MAX_ERROR_BODY_LEN` (they are discarded as they arrive).
#[derive(Debug)]
pub struct HttpResponseReader {
    state: State,
    status: u16,
    keep_alive: bool,
    body: Vec<u8>,
    discard_body: bool,
    discarded: usize,
    max_body: usize,
    expected: Option<usize>,
}

impl Default for HttpResponseReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpResponseReader {
    pub fn new() -> Self {
        Self::with_max_body(MAX_INBOUND_FRAME_LEN)
    }

    pub fn with_max_body(max_body: usize) -> Self {
        Self {
            state: State::Head,
            status: 0,
            keep_alive: true,
            body: Vec::new(),
            discard_body: false,
            discarded: 0,
            max_body,
            expected: None,
        }
    }

    /// True while a response has started but is not complete.
    pub fn in_response(&self) -> bool {
        matches!(self.state, State::Body { .. })
    }

    /// The length a body announced and how much of it arrived, while one is being read.
    pub fn body_progress(&self) -> Option<(Option<usize>, usize)> {
        match self.state {
            State::Body { .. } if !self.discard_body => Some((self.expected, self.body.len())),
            _ => None,
        }
    }

    pub fn body_head(&self) -> &[u8] {
        &self.body
    }

    pub fn read(&mut self, input: &mut InputBuffer) -> Result<Option<HttpResponse>, HttpError> {
        loop {
            match self.state {
                State::Head => {
                    let data = input.as_slice();
                    let Some(end) = find_head_end(data) else {
                        if data.len() > MAX_HEAD_LEN {
                            return Err(HttpError::HeadTooLarge);
                        }
                        return Ok(None);
                    };
                    if end > MAX_HEAD_LEN {
                        return Err(HttpError::HeadTooLarge);
                    }
                    let head = parse_head(&data[..end])?;
                    input.consume(end + 4);
                    if (100..200).contains(&head.status) {
                        continue;
                    }
                    self.status = head.status;
                    self.keep_alive = head.keep_alive;
                    self.discard_body = !(200..300).contains(&head.status);
                    self.discarded = 0;
                    self.body = Vec::new();
                    let framing = if head.status == 204 || head.status == 304 {
                        BodyFraming::Length(0)
                    } else if head.chunked {
                        BodyFraming::Chunked
                    } else if let Some(length) = head.content_length {
                        let limit = if self.discard_body { MAX_ERROR_BODY_LEN } else { self.max_body };
                        if length > limit as u64 {
                            return Err(HttpError::BodyTooLarge(length));
                        }
                        BodyFraming::Length(length as usize)
                    } else {
                        self.keep_alive = false;
                        BodyFraming::UntilClose
                    };
                    self.expected = match framing {
                        BodyFraming::Length(length) => Some(length),
                        _ => None,
                    };
                    if let BodyFraming::Length(length) = framing
                        && !self.discard_body
                    {
                        self.body.reserve_exact(length.min(1 << 20));
                    }
                    self.state = State::Body { framing, chunk: ChunkState::Size };
                }
                State::Body { framing: BodyFraming::Length(length), .. } => {
                    let have = self.received();
                    let take = (length - have).min(input.len());
                    self.accept(&input.as_slice()[..take])?;
                    input.consume(take);
                    if self.received() < length {
                        return Ok(None);
                    }
                    return Ok(Some(self.finish_response()));
                }
                State::Body { framing: BodyFraming::UntilClose, .. } => {
                    let data = input.as_slice().to_vec();
                    input.consume(data.len());
                    self.accept(&data)?;
                    return Ok(None);
                }
                State::Body { framing: BodyFraming::Chunked, chunk } => match chunk {
                    ChunkState::Size => {
                        let Some(line) = take_line(input, MAX_CHUNK_LINE_LEN)? else {
                            return Ok(None);
                        };
                        let digits = line.split(|byte| *byte == b';').next().unwrap_or_default();
                        let digits = trim(digits);
                        if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_hexdigit) {
                            return Err(HttpError::Chunk);
                        }
                        let size =
                            usize::from_str_radix(core::str::from_utf8(digits).map_err(|_| HttpError::Chunk)?, 16)
                                .map_err(|_| HttpError::Chunk)?;
                        let limit = if self.discard_body { MAX_ERROR_BODY_LEN } else { self.max_body };
                        if self.received().saturating_add(size) > limit {
                            return Err(HttpError::BodyTooLarge((self.received() + size) as u64));
                        }
                        let next = if size == 0 { ChunkState::Trailers } else { ChunkState::Data(size) };
                        self.state = State::Body { framing: BodyFraming::Chunked, chunk: next };
                    }
                    ChunkState::Data(left) => {
                        if input.is_empty() {
                            return Ok(None);
                        }
                        let take = left.min(input.len());
                        self.accept(&input.as_slice()[..take])?;
                        input.consume(take);
                        let next = if take == left { ChunkState::DataEnd } else { ChunkState::Data(left - take) };
                        self.state = State::Body { framing: BodyFraming::Chunked, chunk: next };
                    }
                    ChunkState::DataEnd => {
                        let data = input.as_slice();
                        if data.first().is_some_and(|byte| *byte != b'\r')
                            || data.get(1).is_some_and(|byte| *byte != b'\n')
                        {
                            return Err(HttpError::Chunk);
                        }
                        if data.len() < 2 {
                            return Ok(None);
                        }
                        input.consume(2);
                        self.state = State::Body { framing: BodyFraming::Chunked, chunk: ChunkState::Size };
                    }
                    ChunkState::Trailers => {
                        let Some(line) = take_line(input, MAX_HEAD_LEN)? else {
                            return Ok(None);
                        };
                        if line.is_empty() {
                            return Ok(Some(self.finish_response()));
                        }
                    }
                },
            }
        }
    }

    /// The peer closed the stream: completes a response whose body runs until the close.
    pub fn finish(&mut self) -> Result<Option<HttpResponse>, HttpError> {
        match self.state {
            State::Head => Ok(None),
            State::Body { framing: BodyFraming::UntilClose, .. } => Ok(Some(self.finish_response())),
            State::Body { .. } => Err(HttpError::Truncated),
        }
    }

    fn received(&self) -> usize {
        if self.discard_body { self.discarded } else { self.body.len() }
    }

    fn accept(&mut self, data: &[u8]) -> Result<(), HttpError> {
        if self.discard_body {
            self.discarded += data.len();
            if self.discarded > MAX_ERROR_BODY_LEN {
                return Err(HttpError::BodyTooLarge(self.discarded as u64));
            }
            return Ok(());
        }
        if self.body.len() + data.len() > self.max_body {
            return Err(HttpError::BodyTooLarge((self.body.len() + data.len()) as u64));
        }
        self.body.extend_from_slice(data);
        Ok(())
    }

    fn finish_response(&mut self) -> HttpResponse {
        self.state = State::Head;
        self.expected = None;
        HttpResponse {
            status: self.status,
            keep_alive: self.keep_alive,
            body: if self.discard_body { Vec::new() } else { core::mem::take(&mut self.body) },
        }
    }
}

struct Head {
    status: u16,
    keep_alive: bool,
    content_length: Option<u64>,
    chunked: bool,
}

fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = value
        && (*first == b' ' || *first == b'\t')
    {
        value = rest;
    }
    while let [rest @ .., last] = value
        && (*last == b' ' || *last == b'\t')
    {
        value = rest;
    }
    value
}

fn take_line(input: &mut InputBuffer, limit: usize) -> Result<Option<Vec<u8>>, HttpError> {
    let data = input.as_slice();
    match data.windows(2).position(|window| window == b"\r\n") {
        Some(end) if end > limit => Err(HttpError::Chunk),
        Some(end) => {
            let line = data[..end].to_vec();
            input.consume(end + 2);
            Ok(Some(line))
        }
        None if data.len() > limit + 1 => Err(HttpError::Chunk),
        None => Ok(None),
    }
}

fn parse_head(head: &[u8]) -> Result<Head, HttpError> {
    let mut lines = head.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status_line = lines.next().ok_or(HttpError::StatusLine)?;
    let mut parts = status_line.splitn(3, |byte| *byte == b' ');
    let version = parts.next().ok_or(HttpError::StatusLine)?;
    let http10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return Err(HttpError::StatusLine),
    };
    let code = parts.next().ok_or(HttpError::StatusLine)?;
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(HttpError::StatusLine);
    }
    let status = code.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
    if !(100..=599).contains(&status) {
        return Err(HttpError::StatusLine);
    }
    let mut keep_alive = !http10;
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut count = 0usize;
    for line in lines {
        count += 1;
        if count > MAX_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }
        if line.first().is_some_and(|byte| *byte == b' ' || *byte == b'\t') {
            return Err(HttpError::Header);
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or(HttpError::Header)?;
        let name = &line[..colon];
        if name.is_empty() || name.iter().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
            return Err(HttpError::Header);
        }
        let value = trim(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
                return Err(HttpError::ContentLength);
            }
            let parsed = value.iter().fold(0u64, |acc, digit| acc * 10 + u64::from(digit - b'0'));
            if content_length.is_some_and(|previous| previous != parsed) {
                return Err(HttpError::ContentLength);
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if chunked || !trim(value).eq_ignore_ascii_case(b"chunked") {
                return Err(HttpError::TransferEncoding);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"connection") || name.eq_ignore_ascii_case(b"proxy-connection") {
            for token in value.split(|byte| *byte == b',').map(trim) {
                if token.eq_ignore_ascii_case(b"close") {
                    keep_alive = false;
                } else if token.eq_ignore_ascii_case(b"keep-alive") && http10 {
                    keep_alive = true;
                }
            }
        }
    }
    if chunked {
        content_length = None;
    }
    Ok(Head { status, keep_alive, content_length, chunked })
}

/// An HTTP CONNECT tunnel through a proxy; after it, the stream carries the TCP transports as is.
#[derive(Debug)]
pub struct HttpConnectHandshake {
    done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpConnectError {
    #[error("proxy refused the tunnel with HTTP {0}")]
    Refused(u16),
    #[error("proxy requires authentication")]
    AuthenticationRequired,
    #[error("malformed proxy response: {0}")]
    Malformed(HttpError),
}

impl HttpConnectHandshake {
    pub fn new(authority: &str, credentials: Option<&HttpCredentials>) -> (Self, Vec<u8>) {
        let mut request =
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n");
        if let Some(credentials) = credentials {
            request.push_str("Proxy-Authorization: ");
            request.push_str(&credentials.header_value());
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        (Self { done: false }, request.into_bytes())
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Ok(true) once the tunnel is up; the bytes left in `input` belong to the tunnel.
    pub fn feed(&mut self, input: &mut InputBuffer) -> Result<bool, HttpConnectError> {
        loop {
            let data = input.as_slice();
            let Some(end) = find_head_end(data) else {
                if data.len() > MAX_HEAD_LEN {
                    return Err(HttpConnectError::Malformed(HttpError::HeadTooLarge));
                }
                return Ok(false);
            };
            let head = parse_head(&data[..end]).map_err(HttpConnectError::Malformed)?;
            input.consume(end + 4);
            match head.status {
                100..=199 => continue,
                200..=299 => {
                    self.done = true;
                    return Ok(true);
                }
                407 => return Err(HttpConnectError::AuthenticationRequired),
                status => return Err(HttpConnectError::Refused(status)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(reader: &mut HttpResponseReader, bytes: &[u8], step: usize) -> Result<Vec<HttpResponse>, HttpError> {
        let mut input = InputBuffer::new();
        let mut out = Vec::new();
        for chunk in bytes.chunks(step.max(1)) {
            input.extend(chunk);
            while let Some(response) = reader.read(&mut input)? {
                out.push(response);
            }
        }
        Ok(out)
    }

    #[test]
    fn direct_and_forwarded_posts() {
        let mut out = Vec::new();
        encode_post(&HttpRoute::Direct { authority: authority("149.154.167.51", 80) }, b"abcd", &mut out);
        assert_eq!(
            out,
            b"POST /api HTTP/1.1\r\nHost: 149.154.167.51:80\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nabcd"
        );
        let mut out = Vec::new();
        let route = HttpRoute::Forwarded {
            authority: authority("2001:b28:f23d:f001::a", 80),
            credentials: Some(HttpCredentials { username: "user".into(), password: "pass".into() }),
        };
        encode_post(&route, b"", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("POST http://[2001:b28:f23d:f001::a]:80/api HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n"), "{text}");
        assert!(text.ends_with("Content-Length: 0\r\n\r\n"));
        let mut out = Vec::new();
        encode_post(&HttpRoute::Web { host: "venus.web.telegram.org".into(), path: "/apiw1".into() }, b"ab", &mut out);
        assert_eq!(
            out,
            b"POST /apiw1 HTTP/1.1\r\nHost: venus.web.telegram.org\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\nab"
        );
    }

    #[test]
    fn telegram_style_responses_in_any_chunking() {
        let mut wire = Vec::new();
        for body in [vec![1u8; 100], vec![2u8; 70_000], Vec::new()] {
            wire.extend_from_slice(
                format!(
                    "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nPragma: no-cache\r\nCache-control: no-store\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            wire.extend_from_slice(&body);
        }
        for step in [1, 2, 7, 100, 4096, usize::MAX] {
            let mut reader = HttpResponseReader::new();
            let responses = read_all(&mut reader, &wire, step).unwrap();
            assert_eq!(responses.len(), 3, "step {step}");
            assert_eq!(responses[0].body, vec![1u8; 100]);
            assert_eq!(responses[1].body.len(), 70_000);
            assert!(responses[2].body.is_empty());
            assert!(responses.iter().all(|response| response.status == 200 && response.keep_alive));
            assert!(!reader.in_response());
        }
    }

    #[test]
    fn status_codes_are_transport_errors_and_their_bodies_are_dropped() {
        let wire = b"HTTP/1.1 404 Not Found\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nServer: nginx/0.3.33\r\nContent-Length: 13\r\n\r\n<html></html>";
        let mut reader = HttpResponseReader::new();
        let responses = read_all(&mut reader, wire, 5).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].transport_error(), Some(-404));
        assert!(responses[0].body.is_empty());
        let ok = HttpResponse { status: 200, keep_alive: true, body: (-429i32).to_le_bytes().to_vec() };
        assert_eq!(ok.transport_error(), Some(-429), "a TCP-style code in a 200 body is honoured too");
        let ok = HttpResponse { status: 200, keep_alive: true, body: 5i32.to_le_bytes().to_vec() };
        assert_eq!(ok.transport_error(), None);
        let proxy = HttpResponse { status: 502, keep_alive: false, body: Vec::new() };
        assert_eq!(proxy.transport_error(), Some(-502));
    }

    #[test]
    fn chunked_bodies_with_extensions_and_trailers() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n4;name=v\r\nabcd\r\n3\r\nefg\r\n0\r\nX-Trailer: 1\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n0\r\n\r\n";
        for step in [1, 3, 64] {
            let mut reader = HttpResponseReader::new();
            let responses = read_all(&mut reader, wire, step).unwrap();
            assert_eq!(responses.len(), 2);
            assert_eq!(responses[0].body, b"abcdefg");
            assert!(responses[1].body.is_empty(), "chunked overrides Content-Length");
        }
    }

    #[test]
    fn informational_responses_are_skipped_and_http10_closes() {
        let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut reader = HttpResponseReader::new();
        let responses = read_all(&mut reader, wire, 1).unwrap();
        assert_eq!(responses, vec![HttpResponse { status: 200, keep_alive: false, body: b"ok".to_vec() }]);
        let wire = b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        assert!(read_all(&mut HttpResponseReader::new(), wire, 9).unwrap()[0].keep_alive);
        let wire = b"HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n";
        assert!(!read_all(&mut HttpResponseReader::new(), wire, 9).unwrap()[0].keep_alive);
    }

    #[test]
    fn bodies_without_length_run_until_close() {
        let wire = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let mut reader = HttpResponseReader::new();
        assert!(read_all(&mut reader, wire, 2).unwrap().is_empty());
        assert!(reader.in_response());
        let response = reader.finish().unwrap().unwrap();
        assert_eq!(response.body, b"hello");
        assert!(!response.keep_alive);
        let mut reader = HttpResponseReader::new();
        read_all(&mut reader, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", 4).unwrap();
        assert_eq!(reader.finish(), Err(HttpError::Truncated));
        assert_eq!(reader.body_progress(), Some((Some(10), 3)));
    }

    #[test]
    fn hostile_responses_are_bounded() {
        let cases: Vec<(Vec<u8>, HttpError)> = vec![
            (b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(), HttpError::StatusLine),
            (b"HTTP/1.1 2000 OK\r\n\r\n".to_vec(), HttpError::StatusLine),
            (b"HTTP/2 200\r\n\r\n".to_vec(), HttpError::StatusLine),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n".to_vec(), HttpError::ContentLength),
            (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".to_vec(), HttpError::ContentLength),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n".to_vec(),
                HttpError::BodyTooLarge(99_999_999_999),
            ),
            (b"HTTP/1.1 500 X\r\nContent-Length: 70000\r\n\r\n".to_vec(), HttpError::BodyTooLarge(70_000)),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec(), HttpError::TransferEncoding),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_vec(), HttpError::TransferEncoding),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
                HttpError::TransferEncoding,
            ),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(), HttpError::Chunk),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX".to_vec(), HttpError::Chunk),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffff\r\n".to_vec(),
                HttpError::BodyTooLarge(0x0fff_ffff),
            ),
            (b"HTTP/1.1 200 OK\r\n folded\r\n\r\n".to_vec(), HttpError::Header),
            (b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n".to_vec(), HttpError::Header),
        ];
        for (wire, expected) in cases {
            let mut reader = HttpResponseReader::new();
            assert_eq!(read_all(&mut reader, &wire, 3).unwrap_err(), expected, "{}", String::from_utf8_lossy(&wire));
        }
        let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge.extend(vec![b'a'; MAX_HEAD_LEN + 10]);
        assert_eq!(read_all(&mut HttpResponseReader::new(), &huge, 4096).unwrap_err(), HttpError::HeadTooLarge);
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for index in 0..=MAX_HEADERS {
            many.extend_from_slice(format!("X-{index}: 1\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(read_all(&mut HttpResponseReader::new(), &many, 4096).unwrap_err(), HttpError::TooManyHeaders);
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..80 {
            chunked.extend_from_slice(b"10000\r\n");
            chunked.extend(vec![0u8; 0x10000]);
            chunked.extend_from_slice(b"\r\n");
        }
        assert!(matches!(
            read_all(&mut HttpResponseReader::new(), &chunked, 1 << 20).unwrap_err(),
            HttpError::BodyTooLarge(_)
        ));
    }

    #[test]
    fn connect_tunnel() {
        let credentials = HttpCredentials { username: "a".into(), password: "b".into() };
        let (mut handshake, request) = HttpConnectHandshake::new(&authority("149.154.167.51", 443), Some(&credentials));
        assert_eq!(
            request,
            b"CONNECT 149.154.167.51:443 HTTP/1.1\r\nHost: 149.154.167.51:443\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic YTpi\r\n\r\n"
        );
        let mut input = InputBuffer::new();
        input.extend(b"HTTP/1.1 200 Connection established\r\n");
        assert_eq!(handshake.feed(&mut input), Ok(false));
        input.extend(b"\r\n\xef\x01");
        assert_eq!(handshake.feed(&mut input), Ok(true));
        assert!(handshake.is_done());
        assert_eq!(input.as_slice(), b"\xef\x01", "tunnel bytes are left in place");
        for (wire, expected) in [
            (&b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..], HttpConnectError::AuthenticationRequired),
            (b"HTTP/1.0 403 Forbidden\r\n\r\n", HttpConnectError::Refused(403)),
            (b"garbage\r\n\r\n", HttpConnectError::Malformed(HttpError::StatusLine)),
        ] {
            let (mut handshake, _) = HttpConnectHandshake::new("h:1", None);
            let mut input = InputBuffer::new();
            input.extend(wire);
            assert_eq!(handshake.feed(&mut input), Err(expected));
        }
    }
}
