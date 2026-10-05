use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use mio::{Registry, Token};
use mtproto_core::crypto::SecureRandom;
use mtproto_core::transport::{
    HttpConnectError, HttpConnectHandshake, HttpCredentials, Incoming, InputBuffer, Socks5Auth, Socks5Handshake,
    Socks5Progress, Socks5Target, TransportConfig, TransportError, TransportStream, WsDeframer, WsError, WsHandshake,
    encode_ws_frames,
};

use crate::host_stream::HostPipe;
use crate::pipe::Pipe;

/// How a connection reaches the datacenter through a proxy before the transport starts.
#[derive(Debug, Clone)]
pub enum Tunnel {
    Socks5(Socks5Target, Option<Socks5Auth>),
    HttpConnect { authority: String, credentials: Option<HttpCredentials> },
}

#[derive(Debug)]
pub enum ConnectionError {
    Io(io::Error),
    Transport(TransportError),
    Socks(mtproto_core::transport::Socks5Error),
    Proxy(HttpConnectError),
    WebSocket(WsError),
    Closed,
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnectionError::Io(error) => write!(f, "io: {error}"),
            ConnectionError::Transport(error) => write!(f, "transport: {error}"),
            ConnectionError::Socks(error) => write!(f, "socks5: {error}"),
            ConnectionError::Proxy(error) => write!(f, "http proxy: {error}"),
            ConnectionError::WebSocket(error) => write!(f, "websocket: {error}"),
            ConnectionError::Closed => f.write_str("closed by peer"),
        }
    }
}

enum Phase {
    Connecting,
    Socks { handshake: Socks5Handshake },
    HttpTunnel { handshake: HttpConnectHandshake },
    WebSocket { handshake: WsHandshake },
    Ready,
}

/// Telegram Web's WebSocket endpoint the stream goes to once the host's TLS stream is open.
#[derive(Debug, Clone)]
pub struct WebSocketTarget {
    pub host: String,
    pub path: String,
}

/// The stream is carried in WebSocket frames: masked client frames out, server frames in.
struct WebSocketLink {
    deframer: WsDeframer,
    input: InputBuffer,
    payload: Vec<u8>,
    mask_state: u64,
}

impl WebSocketLink {
    fn next_mask(state: &mut u64) -> [u8; 4] {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        (*state as u32).to_le_bytes()
    }
}

pub const WRITE_COMPACT_THRESHOLD: usize = 64 * 1024;

pub enum ChunkStatus {
    Data { became_ready: bool },
    WouldBlock,
    Eof,
}

pub struct Connection {
    pipe: Pipe,
    token: Token,
    phase: Phase,
    transport: TransportStream,
    socks_input: InputBuffer,
    pending_tunnel: Option<Tunnel>,
    pending_websocket: Option<(WebSocketTarget, [u8; 16])>,
    websocket: Option<WebSocketLink>,
    write_buffer: Vec<u8>,
    write_offset: usize,
    writable_interest: bool,
    pub address_index: usize,
    /// Where the socket goes: the address, or the proxy's.
    pub target: SocketAddr,
    pub started_at: f64,
    pub established_at: Option<f64>,
    pub last_progress_at: f64,
    pub received_packet: bool,
    /// Any packet of the server's arrived, a handshake step included.
    pub heard_from_server: bool,
    pub received_bytes: bool,
    pub cellular: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    written_total: u64,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        registry: &Registry,
        token: Token,
        address: SocketAddr,
        transport: &TransportConfig,
        tunnel: Option<Tunnel>,
        address_index: usize,
        now: f64,
        rng: &mut impl SecureRandom,
    ) -> io::Result<Self> {
        let pipe = Pipe::connect(registry, token, address)?;
        Ok(Self::over(pipe, token, address, transport, tunnel, None, address_index, now, rng))
    }

    /// A stream connection over the host's WEB proxy carrier.
    pub fn over_carrier(
        pipe: HostPipe,
        token: Token,
        transport: &TransportConfig,
        address_index: usize,
        now: f64,
        rng: &mut impl SecureRandom,
    ) -> Self {
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        Self::over(Pipe::Host(pipe), token, unspecified, transport, None, None, address_index, now, rng)
    }

    /// A stream connection over Telegram Web's WebSocket endpoint, in a TLS stream the host opened.
    pub fn over_websocket(
        pipe: HostPipe,
        token: Token,
        transport: &TransportConfig,
        target: WebSocketTarget,
        now: f64,
        rng: &mut impl SecureRandom,
    ) -> Self {
        let key: [u8; 16] = rng.array();
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        Self::over(Pipe::Host(pipe), token, unspecified, transport, None, Some((target, key)), usize::MAX, now, rng)
    }

    #[allow(clippy::too_many_arguments)]
    fn over(
        pipe: Pipe,
        token: Token,
        address: SocketAddr,
        transport: &TransportConfig,
        tunnel: Option<Tunnel>,
        websocket: Option<(WebSocketTarget, [u8; 16])>,
        address_index: usize,
        now: f64,
        rng: &mut impl SecureRandom,
    ) -> Self {
        Self {
            pipe,
            token,
            phase: Phase::Connecting,
            transport: TransportStream::new(transport, rng),
            socks_input: InputBuffer::new(),
            pending_tunnel: tunnel,
            pending_websocket: websocket,
            websocket: None,
            write_buffer: Vec::new(),
            write_offset: 0,
            writable_interest: true,
            address_index,
            target: address,
            started_at: now,
            established_at: None,
            last_progress_at: now,
            received_packet: false,
            heard_from_server: false,
            received_bytes: false,
            cellular: false,
            bytes_in: 0,
            bytes_out: 0,
            written_total: 0,
        }
    }

    pub fn token(&self) -> Token {
        self.token
    }

    /// Over a stream the host opened (Telegram Web's WebSocket, a WEB proxy carrier), not a socket of its
    /// own: it says nothing about TCP getting through.
    pub fn is_host_stream(&self) -> bool {
        self.pipe.is_host()
    }

    pub fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Ready) && self.transport.is_ready()
    }

    pub fn is_tcp_connected(&self) -> bool {
        !matches!(self.phase, Phase::Connecting)
    }

    pub fn deregister(&mut self, registry: &Registry) {
        self.pipe.close(registry);
    }

    pub fn handle_writable(&mut self, registry: &Registry, now: f64) -> Result<bool, ConnectionError> {
        let mut became_ready = false;
        if matches!(self.phase, Phase::Connecting) {
            if !self.pipe.finish_connect().map_err(ConnectionError::Io)? {
                return Ok(false);
            }
            self.cellular = self.pipe.is_cellular();
            if let Some((target, key)) = self.pending_websocket.take() {
                let (handshake, request) = WsHandshake::new(&target.host, &target.path, key);
                self.write_buffer.extend_from_slice(&request);
                self.phase = Phase::WebSocket { handshake };
                self.websocket = Some(WebSocketLink {
                    deframer: WsDeframer::new(),
                    input: InputBuffer::new(),
                    payload: Vec::new(),
                    mask_state: u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]])
                        | 1,
                });
            } else {
                match self.pending_tunnel.take() {
                    Some(Tunnel::Socks5(target, auth)) => {
                        let (handshake, greeting) =
                            Socks5Handshake::new(target, auth).map_err(ConnectionError::Socks)?;
                        self.write_buffer.extend_from_slice(&greeting);
                        self.phase = Phase::Socks { handshake };
                    }
                    Some(Tunnel::HttpConnect { authority, credentials }) => {
                        let (handshake, request) = HttpConnectHandshake::new(&authority, credentials.as_ref());
                        self.write_buffer.extend_from_slice(&request);
                        self.phase = Phase::HttpTunnel { handshake };
                    }
                    None => {
                        self.phase = Phase::Ready;
                        self.established_at = Some(now);
                        became_ready = true;
                    }
                }
            }
        }
        if matches!(self.phase, Phase::Ready) {
            self.move_transport_output();
        }
        self.flush(registry)?;
        Ok(became_ready)
    }

    fn move_transport_output(&mut self) {
        if self.transport.has_outgoing() {
            let data = self.transport.take_outgoing();
            self.compact_write_buffer();
            match &mut self.websocket {
                Some(link) => {
                    let state = &mut link.mask_state;
                    encode_ws_frames(&data, || WebSocketLink::next_mask(state), &mut self.write_buffer);
                }
                None => self.write_buffer.extend_from_slice(&data),
            }
        }
    }

    /// Bytes read off a WebSocket: the frames' payload goes to the transport.
    fn receive_websocket(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
        let Some(link) = &mut self.websocket else {
            return self.transport.receive(bytes).map_err(ConnectionError::Transport);
        };
        link.input.extend(bytes);
        link.payload.clear();
        let framing = link.deframer.feed(&mut link.input, &mut link.payload).map_err(ConnectionError::WebSocket);
        if link.payload.is_empty() {
            return framing;
        }
        let payload = std::mem::take(&mut link.payload);
        let result = self.transport.receive(&payload).map_err(ConnectionError::Transport);
        if let Some(link) = &mut self.websocket {
            link.payload = payload;
        }
        result.and(framing)
    }

    fn compact_write_buffer(&mut self) {
        compact_written_prefix(&mut self.write_buffer, &mut self.write_offset);
    }

    pub fn send_packet(
        &mut self,
        registry: &Registry,
        payload: &[u8],
        quick_ack: bool,
        rng: &mut impl SecureRandom,
    ) -> Result<(), ConnectionError> {
        self.transport.send_packet(payload, quick_ack, rng);
        if matches!(self.phase, Phase::Ready) {
            self.move_transport_output();
            self.flush(registry)?;
        }
        Ok(())
    }

    pub fn flush(&mut self, registry: &Registry) -> Result<(), ConnectionError> {
        while self.write_offset < self.write_buffer.len() {
            match self.pipe.write(&self.write_buffer[self.write_offset..]) {
                Ok(0) => return Err(ConnectionError::Closed),
                Ok(written) => {
                    self.write_offset += written;
                    self.bytes_out += written as u64;
                    self.written_total += written as u64;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::NotConnected && matches!(self.phase, Phase::Connecting) => {
                    break;
                }
                Err(error) => return Err(ConnectionError::Io(error)),
            }
        }
        if self.write_offset == self.write_buffer.len() {
            self.write_buffer.clear();
            self.write_offset = 0;
            if self.write_buffer.capacity() > 256 * 1024 {
                self.write_buffer = Vec::new();
            }
        }
        let needs_writable = self.write_offset < self.write_buffer.len() || matches!(self.phase, Phase::Connecting);
        if needs_writable != self.writable_interest {
            self.pipe.set_writable_interest(registry, self.token, needs_writable).map_err(ConnectionError::Io)?;
            self.writable_interest = needs_writable;
        }
        Ok(())
    }

    pub fn acknowledged_bytes(&self) -> Option<u64> {
        self.pipe.send_queue().map(|queued| self.written_total.saturating_sub(queued as u64))
    }

    /// Bytes the engine holds for this connection that the kernel has not taken yet.
    pub fn unsent_bytes(&self) -> usize {
        self.write_buffer.len() - self.write_offset
    }

    pub fn outbound_backlog(&self) -> Option<usize> {
        let unsent = self.write_buffer.len() - self.write_offset;
        self.pipe.send_queue().map(|queued| unsent + queued)
    }

    pub fn read_chunk(
        &mut self,
        registry: &Registry,
        scratch: &mut [u8],
        now: f64,
    ) -> Result<ChunkStatus, ConnectionError> {
        let read = loop {
            match self.pipe.read(scratch) {
                Ok(0) => return Ok(ChunkStatus::Eof),
                Ok(read) => break read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(ChunkStatus::WouldBlock),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(ConnectionError::Io(error)),
            }
        };
        self.bytes_in += read as u64;
        self.received_bytes = true;
        let mut became_ready = false;
        if matches!(self.phase, Phase::Connecting) {
            became_ready = self.handle_writable(registry, now)?;
        }
        match &mut self.phase {
            Phase::Connecting => {
                self.phase = Phase::Ready;
                self.established_at = Some(now);
                became_ready = true;
                self.transport.receive(&scratch[..read]).map_err(ConnectionError::Transport)?;
            }
            Phase::WebSocket { handshake } => {
                self.socks_input.extend(&scratch[..read]);
                if handshake.feed(&mut self.socks_input).map_err(ConnectionError::WebSocket)? {
                    let leftover = self.socks_input.as_slice().to_vec();
                    self.socks_input = InputBuffer::new();
                    self.phase = Phase::Ready;
                    self.established_at = Some(now);
                    became_ready = true;
                    if !leftover.is_empty() {
                        self.receive_websocket(&leftover)?;
                    }
                    self.move_transport_output();
                }
            }
            Phase::Socks { handshake } => {
                self.socks_input.extend(&scratch[..read]);
                loop {
                    match handshake.feed(&mut self.socks_input).map_err(ConnectionError::Socks)? {
                        Socks5Progress::NeedMore => break,
                        Socks5Progress::Send(bytes) => self.write_buffer.extend_from_slice(&bytes),
                        Socks5Progress::Connected => {
                            let leftover = self.socks_input.as_slice().to_vec();
                            self.socks_input = InputBuffer::new();
                            self.phase = Phase::Ready;
                            self.established_at = Some(now);
                            became_ready = true;
                            if !leftover.is_empty() {
                                self.transport.receive(&leftover).map_err(ConnectionError::Transport)?;
                            }
                            break;
                        }
                    }
                }
                if matches!(self.phase, Phase::Ready) {
                    self.move_transport_output();
                }
            }
            Phase::HttpTunnel { handshake } => {
                self.socks_input.extend(&scratch[..read]);
                if handshake.feed(&mut self.socks_input).map_err(ConnectionError::Proxy)? {
                    let leftover = self.socks_input.as_slice().to_vec();
                    self.socks_input = InputBuffer::new();
                    self.phase = Phase::Ready;
                    self.established_at = Some(now);
                    became_ready = true;
                    if !leftover.is_empty() {
                        self.transport.receive(&leftover).map_err(ConnectionError::Transport)?;
                    }
                    self.move_transport_output();
                }
            }
            Phase::Ready => {
                let was_ready = self.transport.is_ready();
                if self.websocket.is_some() {
                    self.receive_websocket(&scratch[..read])?;
                } else {
                    self.transport.receive(&scratch[..read]).map_err(ConnectionError::Transport)?;
                }
                if !was_ready && self.transport.is_ready() {
                    self.move_transport_output();
                }
            }
        }
        self.flush(registry)?;
        Ok(ChunkStatus::Data { became_ready })
    }

    pub fn next_incoming(&mut self) -> Result<Option<Incoming>, ConnectionError> {
        self.transport.next_incoming().map_err(ConnectionError::Transport)
    }

    pub fn buffered_input_len(&self) -> usize {
        self.transport.buffered_input_len()
    }

    pub fn pending_frame_head(&self) -> Option<(usize, &[u8])> {
        self.transport.pending_frame_head()
    }

    pub fn shrink(&mut self) {
        self.transport.shrink_buffers();
    }
}

fn compact_written_prefix(buffer: &mut Vec<u8>, offset: &mut usize) {
    if *offset == buffer.len() {
        buffer.clear();
        *offset = 0;
    } else if *offset >= WRITE_COMPACT_THRESHOLD && *offset * 2 >= buffer.len() {
        buffer.drain(..*offset);
        *offset = 0;
    }
}

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
pub(crate) fn kernel_send_queue(socket: &mio::net::TcpStream) -> Option<usize> {
    use std::os::fd::AsRawFd;
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    (result == 0 && value >= 0).then_some(value as usize)
}

#[cfg(not(target_vendor = "apple"))]
pub(crate) fn kernel_send_queue(_socket: &mio::net::TcpStream) -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_never_empty_write_buffer_stays_bounded() {
        let mut buffer = Vec::new();
        let mut offset = 0usize;
        let packet = vec![7u8; 512 * 1024];
        let mut written_total = 0usize;
        for round in 0..2048 {
            compact_written_prefix(&mut buffer, &mut offset);
            buffer.extend_from_slice(&packet);
            let unsent = buffer.len() - offset;
            let write = (unsent - 1).min(400 * 1024 + (round % 7) * 50 * 1024);
            offset += write;
            written_total += write;
            assert!(buffer.len() - offset >= 1, "the socket never fully drains in this test");
            assert!(buffer.capacity() <= 64 * 1024 * 1024, "round {round}: capacity {}", buffer.capacity());
        }
        assert!(written_total > 512 * 1024 * 1024, "the test pushed real volume through");
        assert!(buffer.capacity() <= 64 * 1024 * 1024);
        assert_eq!(&buffer[offset..], &vec![7u8; buffer.len() - offset][..], "unsent bytes are preserved in order");
    }

    #[test]
    fn compaction_keeps_unsent_bytes_in_order() {
        let mut buffer: Vec<u8> = (0..200_000u32).map(|value| value as u8).collect();
        let mut offset = 150_000usize;
        compact_written_prefix(&mut buffer, &mut offset);
        assert_eq!(offset, 0);
        assert_eq!(buffer.len(), 50_000);
        assert_eq!(buffer[0], 150_000u32 as u8);
        let mut small: Vec<u8> = vec![1; 1000];
        let mut small_offset = 10;
        compact_written_prefix(&mut small, &mut small_offset);
        assert_eq!((small.len(), small_offset), (1000, 10), "small prefixes are left alone");
    }
}
