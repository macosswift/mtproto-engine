#![deny(unsafe_code)]

mod clock;
mod connection;
mod host_stream;
mod http_link;
mod interface;
mod pipe;
mod resolver;
mod route_hints;
mod session_runtime;
mod types;
mod uploads;
mod worker;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use mio::{Poll, Waker};
pub use mtproto_core;
use mtproto_core::rpc::{ApiEnvironment, RequestId, RpcRequest, SessionRole, Verification};

pub use clock::{monotonic_seconds, now, unix_seconds};
pub use host_stream::{HOST_READ_WINDOW, HOST_WRITE_WINDOW, StreamHost, StreamId, StreamTarget};
#[cfg(feature = "fuzzing")]
pub use route_hints::{NETWORKS_REMEMBERED, RouteHints};
pub use types::{
    AuthKeyMaterial, BoundTemporaryKey, ConnectionState, DcAddress, DropReason, EngineCallbacks, EngineConfig,
    EngineEvent, KeyGeneration, LogLevel, PfsSetup, ProxyConfig, SecretBytes, SessionHandle, SessionSetup,
    TransportPreference, WebEndpoint,
};
use uploads::Uploads;
use worker::{Command, WAKER_TOKEN, Worker};

struct WorkerHandle {
    sender: Mutex<Sender<Command>>,
    waker: Arc<Waker>,
    wake_pending: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl WorkerHandle {
    fn notify(&self) {
        if !self.wake_pending.swap(true, Ordering::SeqCst) {
            let _ = self.waker.wake();
        }
    }
}

struct EngineInner {
    workers: Vec<WorkerHandle>,
    next_session: AtomicU64,
    next_request: AtomicU64,
    round_robin: AtomicUsize,
    hints: Arc<route_hints::RouteHints>,
    streams: Arc<host_stream::HostStreams>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

const WORKER_BITS: u64 = 8;

impl Engine {
    pub fn new(config: EngineConfig, callbacks: Arc<dyn EngineCallbacks>) -> io::Result<Self> {
        let count = config.worker_threads.clamp(1, 16);
        let hints = Arc::new(route_hints::RouteHints::default());
        let streams = Arc::new(host_stream::HostStreams::default());
        let mut inner = EngineInner {
            workers: Vec::with_capacity(count),
            next_session: AtomicU64::new(1),
            next_request: AtomicU64::new(1),
            round_robin: AtomicUsize::new(0),
            hints: hints.clone(),
            streams: streams.clone(),
        };
        let uploads = Arc::new(Uploads::default());
        for index in 0..count {
            let poll = Poll::new()?;
            let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN)?);
            let wake_pending = Arc::new(AtomicBool::new(false));
            let (sender, receiver) = channel();
            let worker = Worker::new(
                poll,
                receiver,
                sender.clone(),
                waker.clone(),
                wake_pending.clone(),
                callbacks.clone(),
                config.clone(),
            )
            .sharing_uploads(uploads.clone())
            .sharing_route_hints(hints.clone())
            .sharing_host_streams(streams.clone(), Arc::new(host_stream::WorkerSignal::new(waker.clone())));
            let thread = std::thread::Builder::new()
                .name(if index == 0 { "mtproto-main".into() } else { format!("mtproto-worker-{index}") })
                .stack_size(512 * 1024)
                .spawn(move || worker.run())?;
            inner.workers.push(WorkerHandle {
                sender: Mutex::new(sender),
                waker,
                wake_pending,
                thread: Mutex::new(Some(thread)),
            });
        }
        Ok(Self { inner: Arc::new(inner) })
    }

    pub fn worker_count(&self) -> usize {
        self.inner.workers.len()
    }

    pub fn next_request_id(&self) -> RequestId {
        RequestId(self.inner.next_request.fetch_add(1, Ordering::Relaxed))
    }

    fn worker_for(&self, handle: SessionHandle) -> &WorkerHandle {
        let index = (handle.0 & ((1 << WORKER_BITS) - 1)) as usize;
        &self.inner.workers[index.min(self.inner.workers.len() - 1)]
    }

    fn post(&self, handle: SessionHandle, command: Command) {
        let worker = self.worker_for(handle);
        let sent = worker.sender.lock().is_ok_and(|sender| sender.send(command).is_ok());
        if sent {
            worker.notify();
        }
    }

    fn broadcast(&self, make: impl Fn() -> Command) {
        for worker in &self.inner.workers {
            let sent = worker.sender.lock().is_ok_and(|sender| sender.send(make()).is_ok());
            if sent {
                worker.notify();
            }
        }
    }

    pub fn create_session(&self, mut setup: SessionSetup) -> SessionHandle {
        if !setup.time_difference.is_finite() {
            setup.time_difference = 0.0;
        }
        let count = self.inner.workers.len();
        let worker = if count == 1 || setup.role == SessionRole::Main {
            0
        } else {
            1 + self.inner.round_robin.fetch_add(1, Ordering::Relaxed) % (count - 1)
        };
        let serial = self.inner.next_session.fetch_add(1, Ordering::Relaxed);
        let handle = SessionHandle((serial << WORKER_BITS) | worker as u64);
        self.post(handle, Command::Create { handle, setup: Box::new(setup) });
        handle
    }

    pub fn destroy_session(&self, handle: SessionHandle) {
        self.post(handle, Command::Destroy(handle));
    }

    pub fn send(&self, handle: SessionHandle, request: RpcRequest) {
        self.post(handle, Command::Send(handle, request));
    }

    pub fn cancel(&self, handle: SessionHandle, id: RequestId) {
        self.post(handle, Command::Cancel(handle, id));
    }

    pub fn set_paused(&self, handle: SessionHandle, paused: bool) {
        self.post(handle, Command::SetPaused(handle, paused));
    }

    pub fn set_online(&self, handle: SessionHandle, online: bool) {
        self.post(handle, Command::SetOnline(handle, online));
    }

    pub fn set_auth_key(&self, handle: SessionHandle, material: Option<AuthKeyMaterial>) {
        self.post(handle, Command::SetAuthKey(handle, material));
    }

    pub fn set_addresses(&self, handle: SessionHandle, addresses: Vec<DcAddress>) {
        self.post(handle, Command::SetAddresses(handle, addresses));
    }

    pub fn set_proxy(&self, handle: SessionHandle, proxy: Option<ProxyConfig>) {
        self.post(handle, Command::SetProxy(handle, proxy));
    }

    /// Which transports the session may use, and the port HTTP goes to (None: each address's own).
    pub fn set_transport(&self, handle: SessionHandle, transport: TransportPreference, http_port: Option<u16>) {
        self.post(handle, Command::SetTransport(handle, transport, http_port));
    }

    /// The engine makes and binds temporary keys itself from now on; the session's key is the
    /// permanent key.
    /// False, and PFS stays off, without a public key to make temporary keys with.
    pub fn enable_pfs(&self, handle: SessionHandle, setup: PfsSetup) -> bool {
        if setup.public_keys.is_empty() {
            return false;
        }
        self.post(handle, Command::EnablePfs(handle, Box::new(setup)));
        true
    }

    /// A temporary key already bound to the session's permanent key, made by another session or kept
    /// from an earlier run: the session takes it instead of making one whenever it needs a new key.
    pub fn offer_temporary_key(&self, handle: SessionHandle, key: BoundTemporaryKey) {
        self.post(handle, Command::OfferTemporaryKey(handle, Box::new(key)));
    }

    /// With PFS and the permanent key from the host: whether this session may make the permanent key
    /// itself while it has none.
    pub fn allow_permanent_key(&self, handle: SessionHandle, allowed: bool) {
        self.post(handle, Command::AllowPermanentKey(handle, allowed));
    }

    pub fn update_environment(&self, handle: SessionHandle, environment: ApiEnvironment, noop: Option<RpcRequest>) {
        self.post(handle, Command::UpdateEnvironment(handle, Box::new(environment), noop));
    }

    pub fn set_auth_token_ready(&self, handle: SessionHandle, ready: bool) {
        self.post(handle, Command::SetAuthTokenReady(handle, ready));
    }

    pub fn resolve_verification(&self, handle: SessionHandle, id: RequestId, verification: Verification) {
        self.post(handle, Command::ResolveVerification(handle, id, verification));
    }

    pub fn fail_request(&self, handle: SessionHandle, id: RequestId, code: i32, message: String) {
        self.post(handle, Command::FailRequest(handle, id, code, message));
    }

    pub fn decide_retry(&self, handle: SessionHandle, id: RequestId, retry: bool) {
        self.post(handle, Command::DecideRetry(handle, id, retry));
    }

    pub fn set_obfuscation_dc_id(&self, handle: SessionHandle, dc_id: i16) {
        self.post(handle, Command::SetObfuscationDcId(handle, dc_id));
    }

    pub fn invalidate_initialization(&self, handle: SessionHandle) {
        self.post(handle, Command::InvalidateInitialization(handle));
    }

    /// A difference that is not a finite number is ignored: the session would compute no salt valid
    /// and send nothing until a salt request came back, a minute later.
    pub fn set_time_difference(&self, handle: SessionHandle, difference: f64) {
        if difference.is_finite() {
            self.post(handle, Command::SetTimeDifference(handle, difference));
        }
    }

    pub fn destroy_auth_key(&self, handle: SessionHandle) {
        self.post(handle, Command::DestroyAuthKey(handle));
    }

    pub fn set_network_available(&self, available: bool) {
        self.broadcast(|| Command::SetNetworkAvailable(available));
    }

    pub fn reset_connections(&self) {
        self.broadcast(|| Command::ResetConnections);
    }

    /// The network the device is on now, as an opaque key the host derives (a salted hash of what
    /// identifies the network); empty when unknown. What sessions learn about TCP and HTTP is kept per
    /// key, so a network known to block TCP gets HTTP early from the first connection.
    pub fn set_network(&self, key: &[u8]) {
        if self.inner.hints.set_network(key, clock::unix_seconds()) {
            for worker in &self.inner.workers {
                worker.notify();
            }
        }
    }

    /// What `EngineEvent::RouteMemory` reported in an earlier run.
    pub fn set_route_memory(&self, memory: &[u8]) {
        self.inner.hints.load(memory, clock::unix_seconds());
    }

    /// The memory of named networks now, as `EngineEvent::RouteMemory` reports it.
    pub fn route_memory(&self) -> Vec<u8> {
        self.inner.hints.export(clock::unix_seconds())
    }

    /// The host that opens streams the engine cannot open itself (TLS to Telegram Web's fronts with
    /// the platform's TLS). Without one, routes that need it are not tried.
    pub fn set_stream_host(&self, host: Option<Arc<dyn StreamHost>>) {
        self.inner.streams.set_host(host);
    }

    /// The host's stream is open (its TLS handshake done): bytes may go both ways.
    pub fn stream_opened(&self, stream: StreamId) {
        self.inner.streams.opened(stream);
    }

    /// Bytes the host's stream received. False when the engine holds `HOST_READ_WINDOW` bytes
    /// already: the host stops receiving on the stream until `StreamHost::resume`.
    pub fn stream_received(&self, stream: StreamId, bytes: &[u8]) -> bool {
        self.inner.streams.received(stream, bytes)
    }

    /// The platform took `count` more bytes of what the engine wrote on the stream.
    pub fn stream_sent(&self, stream: StreamId, count: usize) {
        self.inner.streams.sent(stream, count);
    }

    /// The host's stream ended: cleanly (None) or with an error. Before `stream_opened`, it could not
    /// be opened.
    pub fn stream_closed(&self, stream: StreamId, error: Option<String>) {
        self.inner.streams.closed(stream, error);
    }

    /// Telegram Web's HTTPS endpoint the session may use as one more HTTP route (None: none).
    pub fn set_web_endpoint(&self, handle: SessionHandle, endpoint: Option<WebEndpoint>) {
        self.post(handle, Command::SetWebEndpoint(handle, endpoint.map(Box::new)));
    }

    /// Telegram Web's own endpoint for the session's datacenter and role (`WebEndpoint::telegram`).
    pub fn use_telegram_web(&self, handle: SessionHandle, test: bool) {
        self.post(handle, Command::UseTelegramWeb(handle, test));
    }

    pub fn shutdown(&self) {
        self.broadcast(|| Command::Shutdown);
        for worker in &self.inner.workers {
            if let Ok(mut thread) = worker.thread.lock()
                && let Some(thread) = thread.take()
                && thread.thread().id() != std::thread::current().id()
            {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for EngineInner {
    fn drop(&mut self) {
        for worker in &self.workers {
            if let Ok(sender) = worker.sender.lock() {
                let _ = sender.send(Command::Shutdown);
                let _ = worker.waker.wake();
            }
        }
        for worker in &self.workers {
            if let Ok(mut thread) = worker.thread.lock()
                && let Some(thread) = thread.take()
                && thread.thread().id() != std::thread::current().id()
            {
                let _ = thread.join();
            }
        }
    }
}
