use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use mio::{Token, Waker};

/// A stream the host opened for the engine, by the number the engine gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

/// Where a host stream goes.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamTarget {
    /// A name the host looks up itself, or an address.
    pub host: String,
    pub port: u16,
    /// TLS with this server name. The certificate is not checked: TLS only makes the connection look
    /// like a browser's, and MTProto protects what it carries end to end.
    pub tls_server_name: Option<String>,
    /// The ALPN protocols TLS offers, in order.
    pub alpn: Vec<String>,
    /// The host's WEB proxy carrier rather than a network connection: `host` and `port` are the
    /// datacenter's, which the relay ignores (it reads the datacenter from the obfuscated stream).
    pub carrier: bool,
}

/// The host's side of host streams. The host may call the engine's `stream_*` functions from these
/// callbacks or from any thread later; it reports each stream's end with `stream_closed` unless the
/// engine closed it first.
pub trait StreamHost: Send + Sync {
    fn open(&self, stream: StreamId, target: &StreamTarget);
    /// Bytes to send in order; the host confirms them with `stream_sent` once the platform took them.
    fn write(&self, stream: StreamId, bytes: &[u8]);
    /// The engine is done with the stream; nothing more is reported for it.
    fn close(&self, stream: StreamId);
    /// The engine read enough of what was received for the host to receive more (see `stream_received`).
    fn resume(&self, stream: StreamId);
}

/// Bytes the engine hands the host without a confirmation before it waits.
pub const HOST_WRITE_WINDOW: usize = 1024 * 1024;
/// Received bytes the engine holds before it asks the host to stop receiving.
pub const HOST_READ_WINDOW: usize = 4 * 1024 * 1024;

/// How a worker learns that one of its host streams has news: the stream's token goes on the list and
/// the worker wakes.
pub(crate) struct WorkerSignal {
    waker: Arc<Waker>,
    ready: Mutex<Vec<Token>>,
}

impl WorkerSignal {
    pub(crate) fn new(waker: Arc<Waker>) -> Self {
        Self { waker, ready: Mutex::new(Vec::new()) }
    }

    fn raise(&self, token: Token) {
        if let Ok(mut ready) = self.ready.lock() {
            if ready.contains(&token) {
                return;
            }
            ready.push(token);
        }
        let _ = self.waker.wake();
    }

    pub(crate) fn take(&self) -> Vec<Token> {
        self.ready.lock().map(|mut ready| std::mem::take(&mut *ready)).unwrap_or_default()
    }
}

#[derive(Default)]
struct SlotState {
    connected: bool,
    /// The host reported the end: None for a clean one, or why it failed.
    ended: Option<Option<String>>,
    received: VecDeque<Vec<u8>>,
    offset: usize,
    received_bytes: usize,
    paused: bool,
    unconfirmed: usize,
    write_blocked: bool,
}

struct Slot {
    token: Token,
    signal: Arc<WorkerSignal>,
    /// The host that opened the stream carries it to its end, even when another host is set meanwhile.
    host: Arc<dyn StreamHost>,
    state: Mutex<SlotState>,
}

/// Every host stream of an engine, and the host that carries them.
#[derive(Default)]
pub(crate) struct HostStreams {
    host: RwLock<Option<Arc<dyn StreamHost>>>,
    next_id: AtomicU64,
    slots: Mutex<HashMap<StreamId, Arc<Slot>>>,
}

impl HostStreams {
    pub(crate) fn set_host(&self, host: Option<Arc<dyn StreamHost>>) {
        if let Ok(mut current) = self.host.write() {
            *current = host;
        }
    }

    pub(crate) fn available(&self) -> bool {
        self.host.read().is_ok_and(|host| host.is_some())
    }

    fn host(&self) -> Option<Arc<dyn StreamHost>> {
        self.host.read().ok().and_then(|host| host.clone())
    }

    fn slot(&self, stream: StreamId) -> Option<Arc<Slot>> {
        self.slots.lock().ok().and_then(|slots| slots.get(&stream).cloned())
    }

    /// Asks the host for a stream; its readiness is reported on `token` to `signal`'s worker.
    pub(crate) fn open(
        self: &Arc<Self>,
        target: &StreamTarget,
        token: Token,
        signal: &Arc<WorkerSignal>,
    ) -> io::Result<HostPipe> {
        let host = self.host().ok_or_else(|| io::Error::new(ErrorKind::Unsupported, "no stream host"))?;
        let id = StreamId(self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        let slot = Arc::new(Slot {
            token,
            signal: signal.clone(),
            host: host.clone(),
            state: Mutex::new(SlotState::default()),
        });
        self.slots.lock().map_err(|_| io::Error::other("poisoned"))?.insert(id, slot.clone());
        host.open(id, target);
        Ok(HostPipe { id, slot, streams: self.clone(), closed: false })
    }

    pub(crate) fn opened(&self, stream: StreamId) {
        self.update(stream, |state| {
            state.connected = true;
            true
        });
    }

    /// Whether the host may go on receiving; once it may not, it waits for `StreamHost::resume`.
    pub(crate) fn received(&self, stream: StreamId, bytes: &[u8]) -> bool {
        let mut more = true;
        self.update(stream, |state| {
            if state.ended.is_some() || bytes.is_empty() {
                return false;
            }
            state.received_bytes += bytes.len();
            state.received.push_back(bytes.to_vec());
            if state.received_bytes >= HOST_READ_WINDOW {
                state.paused = true;
                more = false;
            }
            true
        });
        more
    }

    pub(crate) fn sent(&self, stream: StreamId, count: usize) {
        self.update(stream, |state| {
            state.unconfirmed = state.unconfirmed.saturating_sub(count);
            std::mem::take(&mut state.write_blocked)
        });
    }

    pub(crate) fn closed(&self, stream: StreamId, error: Option<String>) {
        self.update(stream, |state| {
            if state.ended.is_none() {
                state.ended = Some(error);
            }
            true
        });
    }

    fn update(&self, stream: StreamId, change: impl FnOnce(&mut SlotState) -> bool) {
        let Some(slot) = self.slot(stream) else {
            return;
        };
        let notify = slot.state.lock().map(|mut state| change(&mut state)).unwrap_or(false);
        if notify {
            slot.signal.raise(slot.token);
        }
    }

    fn release(&self, stream: StreamId) {
        let removed = self.slots.lock().ok().and_then(|mut slots| slots.remove(&stream));
        if let Some(slot) = removed {
            slot.host.close(stream);
        }
    }
}

/// The engine's end of a host stream, read and written like a non-blocking socket.
pub(crate) struct HostPipe {
    id: StreamId,
    slot: Arc<Slot>,
    streams: Arc<HostStreams>,
    closed: bool,
}

impl HostPipe {
    /// Ok(false) while the host is still opening the stream.
    pub(crate) fn is_connected(&self) -> io::Result<bool> {
        let state = self.slot.state.lock().map_err(|_| io::Error::other("poisoned"))?;
        match &state.ended {
            Some(Some(error)) if !state.connected => Err(io::Error::new(ErrorKind::ConnectionRefused, error.clone())),
            Some(_) if !state.connected => Err(io::Error::from(ErrorKind::ConnectionRefused)),
            _ => Ok(state.connected),
        }
    }

    /// Bytes handed to the host that it has not confirmed yet.
    pub(crate) fn unconfirmed(&self) -> usize {
        self.slot.state.lock().map_or(0, |state| state.unconfirmed)
    }

    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.streams.release(self.id);
        }
    }
}

impl Drop for HostPipe {
    fn drop(&mut self) {
        self.close();
    }
}

impl io::Read for HostPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut resume = false;
        let result = {
            let mut state = self.slot.state.lock().map_err(|_| io::Error::other("poisoned"))?;
            let mut copied = 0;
            while copied < buffer.len() {
                let offset = state.offset;
                let Some(front) = state.received.front() else {
                    break;
                };
                let take = (front.len() - offset).min(buffer.len() - copied);
                buffer[copied..copied + take].copy_from_slice(&front[offset..offset + take]);
                copied += take;
                if offset + take == front.len() {
                    state.received.pop_front();
                    state.offset = 0;
                } else {
                    state.offset += take;
                }
            }
            state.received_bytes -= copied;
            if state.paused && state.received_bytes < HOST_READ_WINDOW / 2 {
                state.paused = false;
                resume = true;
            }
            if copied > 0 {
                Ok(copied)
            } else {
                match &state.ended {
                    Some(None) => Ok(0),
                    Some(Some(error)) => Err(io::Error::new(ErrorKind::ConnectionReset, error.clone())),
                    None => Err(io::Error::from(ErrorKind::WouldBlock)),
                }
            }
        };
        if resume && !self.closed {
            self.slot.host.resume(self.id);
        }
        result
    }
}

impl io::Write for HostPipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let take = {
            let mut state = self.slot.state.lock().map_err(|_| io::Error::other("poisoned"))?;
            if let Some(ended) = &state.ended {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    ended.clone().unwrap_or_else(|| "closed by the peer".into()),
                ));
            }
            if !state.connected {
                return Err(io::Error::from(ErrorKind::NotConnected));
            }
            let room = HOST_WRITE_WINDOW.saturating_sub(state.unconfirmed);
            if room == 0 {
                state.write_blocked = true;
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            let take = room.min(bytes.len());
            state.unconfirmed += take;
            take
        };
        self.slot.host.write(self.id, &bytes[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[derive(Default)]
    struct RecordingHost {
        written: Mutex<Vec<u8>>,
        resumed: Mutex<Vec<StreamId>>,
        closed: Mutex<Vec<StreamId>>,
    }

    impl StreamHost for RecordingHost {
        fn open(&self, _stream: StreamId, _target: &StreamTarget) {}

        fn write(&self, _stream: StreamId, bytes: &[u8]) {
            self.written.lock().unwrap().extend_from_slice(bytes);
        }

        fn close(&self, stream: StreamId) {
            self.closed.lock().unwrap().push(stream);
        }

        fn resume(&self, stream: StreamId) {
            self.resumed.lock().unwrap().push(stream);
        }
    }

    fn signal(poll: &mio::Poll) -> Arc<WorkerSignal> {
        Arc::new(WorkerSignal::new(Arc::new(Waker::new(poll.registry(), Token(usize::MAX)).unwrap())))
    }

    fn open(streams: &Arc<HostStreams>, signal: &Arc<WorkerSignal>) -> HostPipe {
        let target =
            StreamTarget { host: "example".into(), port: 443, tls_server_name: None, alpn: Vec::new(), carrier: false };
        streams.open(&target, Token(7), signal).unwrap()
    }

    #[test]
    fn writes_wait_for_the_host_to_take_a_window() {
        let poll = mio::Poll::new().unwrap();
        let host = Arc::new(RecordingHost::default());
        let streams = Arc::new(HostStreams::default());
        streams.set_host(Some(host.clone()));
        let signal = signal(&poll);
        let mut pipe = open(&streams, &signal);
        let stream = StreamId(1);
        assert_eq!(pipe.write(b"early").unwrap_err().kind(), ErrorKind::NotConnected);
        assert!(!pipe.is_connected().unwrap());
        streams.opened(stream);
        assert_eq!(signal.take(), vec![Token(7)], "opening is news for the worker");
        assert!(pipe.is_connected().unwrap());
        let big = vec![1u8; HOST_WRITE_WINDOW + 100];
        assert_eq!(pipe.write(&big).unwrap(), HOST_WRITE_WINDOW, "a write takes at most the window");
        assert_eq!(pipe.write(b"more").unwrap_err().kind(), ErrorKind::WouldBlock);
        assert_eq!(pipe.unconfirmed(), HOST_WRITE_WINDOW);
        assert!(signal.take().is_empty());
        streams.sent(stream, 4096);
        assert_eq!(signal.take(), vec![Token(7)], "a refused write is told when there is room again");
        assert_eq!(pipe.write(b"more").unwrap(), 4);
        streams.sent(stream, 1);
        assert!(signal.take().is_empty(), "room without a refused write is no news");
        assert_eq!(host.written.lock().unwrap().len(), HOST_WRITE_WINDOW + 4);
    }

    #[test]
    fn receiving_pauses_at_the_window_and_resumes_once_read() {
        let poll = mio::Poll::new().unwrap();
        let host = Arc::new(RecordingHost::default());
        let streams = Arc::new(HostStreams::default());
        streams.set_host(Some(host.clone()));
        let signal = signal(&poll);
        let mut pipe = open(&streams, &signal);
        let stream = StreamId(1);
        streams.opened(stream);
        let chunk = vec![9u8; 256 * 1024];
        let mut accepted = 0;
        while streams.received(stream, &chunk) {
            accepted += 1;
        }
        assert_eq!((accepted + 1) * chunk.len(), HOST_READ_WINDOW);
        assert_eq!(signal.take(), vec![Token(7)]);
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut read = 0;
        while host.resumed.lock().unwrap().is_empty() {
            read += pipe.read(&mut buffer).unwrap();
        }
        assert!(read > HOST_READ_WINDOW / 2 && read <= HOST_READ_WINDOW / 2 + buffer.len(), "{read}");
        while read < HOST_READ_WINDOW {
            read += pipe.read(&mut buffer).unwrap();
        }
        assert_eq!(pipe.read(&mut buffer).unwrap_err().kind(), ErrorKind::WouldBlock);
        assert_eq!(host.resumed.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_end_comes_after_the_data_and_closing_tells_the_host_once() {
        let poll = mio::Poll::new().unwrap();
        let host = Arc::new(RecordingHost::default());
        let streams = Arc::new(HostStreams::default());
        streams.set_host(Some(host.clone()));
        let signal = signal(&poll);
        let mut pipe = open(&streams, &signal);
        let stream = StreamId(1);
        streams.opened(stream);
        streams.received(stream, b"last words");
        streams.closed(stream, None);
        let mut buffer = [0u8; 64];
        assert_eq!(pipe.read(&mut buffer).unwrap(), 10);
        assert_eq!(pipe.read(&mut buffer).unwrap(), 0, "a clean end reads as EOF");
        assert_eq!(pipe.write(b"x").unwrap_err().kind(), ErrorKind::BrokenPipe);
        assert!(host.closed.lock().unwrap().is_empty());
        pipe.close();
        drop(pipe);
        assert_eq!(*host.closed.lock().unwrap(), vec![stream]);
        streams.received(stream, b"late");
        streams.closed(stream, Some("late".into()));

        let mut failed = open(&streams, &signal);
        streams.closed(StreamId(2), Some("unreachable".into()));
        assert_eq!(failed.is_connected().unwrap_err().kind(), ErrorKind::ConnectionRefused);
        assert_eq!(failed.read(&mut buffer).unwrap_err().kind(), ErrorKind::ConnectionReset);
    }
}
