use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use mtproto_core::crypto::SecureRandom;
use mtproto_core::transport::{
    Incoming, InputBuffer, Socks5Auth, Socks5Handshake, Socks5Progress, Socks5Target, TransportConfig, TransportError,
    TransportStream,
};

#[derive(Debug)]
pub enum ConnectionError {
    Io(io::Error),
    Transport(TransportError),
    Socks(mtproto_core::transport::Socks5Error),
    Closed,
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnectionError::Io(error) => write!(f, "io: {error}"),
            ConnectionError::Transport(error) => write!(f, "transport: {error}"),
            ConnectionError::Socks(error) => write!(f, "socks5: {error}"),
            ConnectionError::Closed => f.write_str("closed by peer"),
        }
    }
}

enum Phase {
    Connecting,
    Socks { handshake: Socks5Handshake },
    Ready,
}

pub const WRITE_COMPACT_THRESHOLD: usize = 64 * 1024;

pub enum ChunkStatus {
    Data { became_ready: bool },
    WouldBlock,
    Eof,
}

pub struct Connection {
    socket: TcpStream,
    token: Token,
    phase: Phase,
    transport: TransportStream,
    socks_input: InputBuffer,
    pending_socks: Option<(Socks5Target, Option<Socks5Auth>)>,
    write_buffer: Vec<u8>,
    write_offset: usize,
    writable_interest: bool,
    pub address_index: usize,
    pub started_at: f64,
    pub established_at: Option<f64>,
    pub last_progress_at: f64,
    pub received_packet: bool,
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
        socks: Option<(Socks5Target, Option<Socks5Auth>)>,
        address_index: usize,
        now: f64,
        rng: &mut impl SecureRandom,
    ) -> io::Result<Self> {
        let mut socket = TcpStream::connect(address)?;
        registry.register(&mut socket, token, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self {
            socket,
            token,
            phase: Phase::Connecting,
            transport: TransportStream::new(transport, rng),
            socks_input: InputBuffer::new(),
            pending_socks: socks,
            write_buffer: Vec::new(),
            write_offset: 0,
            writable_interest: true,
            address_index,
            started_at: now,
            established_at: None,
            last_progress_at: now,
            received_packet: false,
            received_bytes: false,
            cellular: false,
            bytes_in: 0,
            bytes_out: 0,
            written_total: 0,
        })
    }

    pub fn token(&self) -> Token {
        self.token
    }

    pub fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Ready) && self.transport.is_ready()
    }

    pub fn is_tcp_connected(&self) -> bool {
        !matches!(self.phase, Phase::Connecting)
    }

    pub fn deregister(&mut self, registry: &Registry) {
        let _ = registry.deregister(&mut self.socket);
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }

    pub fn handle_writable(&mut self, registry: &Registry, now: f64) -> Result<bool, ConnectionError> {
        let mut became_ready = false;
        if matches!(self.phase, Phase::Connecting) {
            if let Some(error) = self.socket.take_error().map_err(ConnectionError::Io)? {
                return Err(ConnectionError::Io(error));
            }
            match self.socket.peer_addr() {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotConnected => return Ok(false),
                Err(error) => return Err(ConnectionError::Io(error)),
            }
            let _ = self.socket.set_nodelay(true);
            self.cellular = self
                .socket
                .local_addr()
                .ok()
                .and_then(|address| crate::interface::interface_name_for(address.ip()))
                .is_some_and(|name| crate::interface::is_cellular_interface(&name));
            match self.pending_socks.take() {
                Some((target, auth)) => {
                    let (handshake, greeting) = Socks5Handshake::new(target, auth).map_err(ConnectionError::Socks)?;
                    self.write_buffer.extend_from_slice(&greeting);
                    self.phase = Phase::Socks { handshake };
                }
                None => {
                    self.phase = Phase::Ready;
                    self.established_at = Some(now);
                    became_ready = true;
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
            self.write_buffer.extend_from_slice(&data);
        }
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
            match self.socket.write(&self.write_buffer[self.write_offset..]) {
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
            let interest = if needs_writable { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
            registry.reregister(&mut self.socket, self.token, interest).map_err(ConnectionError::Io)?;
            self.writable_interest = needs_writable;
        }
        Ok(())
    }

    pub fn acknowledged_bytes(&self) -> Option<u64> {
        kernel_send_queue(&self.socket).map(|queued| self.written_total.saturating_sub(queued as u64))
    }

    pub fn outbound_backlog(&self) -> Option<usize> {
        let unsent = self.write_buffer.len() - self.write_offset;
        kernel_send_queue(&self.socket).map(|queued| unsent + queued)
    }

    pub fn read_chunk(
        &mut self,
        registry: &Registry,
        scratch: &mut [u8],
        now: f64,
    ) -> Result<ChunkStatus, ConnectionError> {
        let read = loop {
            match self.socket.read(scratch) {
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
            Phase::Ready => {
                let was_ready = self.transport.is_ready();
                self.transport.receive(&scratch[..read]).map_err(ConnectionError::Transport)?;
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
fn kernel_send_queue(socket: &mio::net::TcpStream) -> Option<usize> {
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
fn kernel_send_queue(_socket: &mio::net::TcpStream) -> Option<usize> {
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
