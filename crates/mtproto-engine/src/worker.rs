use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use mio::{Events, Poll, Token, Waker};
use mtproto_core::crypto::OsRandom;
use mtproto_core::rpc::{ApiEnvironment, RequestId, RpcRequest, Verification};

use crate::clock;
use crate::resolver::resolve_blocking;
use crate::session_runtime::{Resolution, Resolve, SessionRuntime};
use crate::types::{
    AuthKeyMaterial, DcAddress, EngineCallbacks, EngineConfig, EngineEvent, ProxyConfig, SessionHandle, SessionSetup,
};

pub const WAKER_TOKEN: Token = Token(usize::MAX);
const MAX_POLL_WAIT: f64 = 60.0;
const SHRINK_INTERVAL: f64 = 30.0;

pub enum Command {
    Create { handle: SessionHandle, setup: Box<SessionSetup> },
    Destroy(SessionHandle),
    Send(SessionHandle, RpcRequest),
    Cancel(SessionHandle, RequestId),
    SetPaused(SessionHandle, bool),
    SetOnline(SessionHandle, bool),
    SetAuthKey(SessionHandle, Option<AuthKeyMaterial>),
    SetAddresses(SessionHandle, Vec<DcAddress>),
    SetObfuscationDcId(SessionHandle, i16),
    SetProxy(SessionHandle, Option<ProxyConfig>),
    UpdateEnvironment(SessionHandle, Box<ApiEnvironment>, Option<RpcRequest>),
    SetAuthTokenReady(SessionHandle, bool),
    ResolveVerification(SessionHandle, RequestId, Verification),
    FailRequest(SessionHandle, RequestId, i32, String),
    DecideRetry(SessionHandle, RequestId, bool),
    InvalidateInitialization(SessionHandle),
    SetTimeDifference(SessionHandle, f64),
    DestroyAuthKey(SessionHandle),
    SetNetworkAvailable(bool),
    ResetConnections,
    Resolved { host: String, port: u16, addresses: Vec<std::net::SocketAddr> },
    Shutdown,
}

struct ThreadResolver {
    sender: Sender<Command>,
    waker: Arc<Waker>,
    in_flight: HashMap<(String, u16), (Vec<SessionHandle>, f64)>,
}

impl Resolve for ThreadResolver {
    fn resolve(&mut self, session: SessionHandle, host: &str, port: u16) -> Resolution {
        let key = (host.to_string(), port);
        let now = clock::monotonic_seconds();
        if let Some((waiting, started_at)) = self.in_flight.get_mut(&key) {
            if !waiting.contains(&session) {
                waiting.push(session);
            }
            if now - *started_at < crate::session_runtime::RESOLVE_WAIT {
                return Resolution::Pending;
            }
            *started_at = now;
        }
        let sender = self.sender.clone();
        let waker = self.waker.clone();
        let host = host.to_string();
        let lookup_host = host.clone();
        let spawned = std::thread::Builder::new().name("mtproto-resolver".into()).spawn(move || {
            let addresses = resolve_blocking(&lookup_host, port);
            let _ = sender.send(Command::Resolved { host: lookup_host, port, addresses });
            let _ = waker.wake();
        });
        if spawned.is_err() {
            return Resolution::Resolved(Vec::new());
        }
        self.in_flight.entry((host, port)).or_insert_with(|| (vec![session], now));
        Resolution::Pending
    }
}

pub struct Worker {
    poll: Poll,
    receiver: Receiver<Command>,
    wake_pending: Arc<AtomicBool>,
    resolver: ThreadResolver,
    sessions: HashMap<SessionHandle, SessionRuntime>,
    tokens: HashMap<Token, SessionHandle>,
    next_token: usize,
    callbacks: Arc<dyn EngineCallbacks>,
    config: EngineConfig,
    rng: OsRandom,
    scratch: Vec<u8>,
    network_available: bool,
    last_shrink: f64,
    more_readable: VecDeque<SessionHandle>,
}

impl Worker {
    pub fn new(
        poll: Poll,
        receiver: Receiver<Command>,
        sender: Sender<Command>,
        waker: Arc<Waker>,
        wake_pending: Arc<AtomicBool>,
        callbacks: Arc<dyn EngineCallbacks>,
        config: EngineConfig,
    ) -> Self {
        Self {
            poll,
            receiver,
            wake_pending,
            resolver: ThreadResolver { sender, waker, in_flight: HashMap::new() },
            sessions: HashMap::new(),
            tokens: HashMap::new(),
            next_token: 1,
            callbacks,
            config,
            rng: OsRandom::new(),
            scratch: vec![0u8; 256 * 1024],
            network_available: true,
            last_shrink: clock::monotonic_seconds(),
            more_readable: VecDeque::new(),
        }
    }

    pub fn run(mut self) {
        let mut events = Events::with_capacity(512);
        loop {
            let now = clock::now();
            let mut deadline = now.mono + MAX_POLL_WAIT;
            for session in self.sessions.values_mut() {
                if let Some(at) = session.next_deadline(now, &self.config) {
                    deadline = deadline.min(at);
                }
            }
            let wait =
                if self.more_readable.is_empty() { (deadline - now.mono).clamp(0.0, MAX_POLL_WAIT) } else { 0.0 };
            if let Err(error) = self.poll.poll(&mut events, Some(Duration::from_secs_f64(wait)))
                && error.kind() != std::io::ErrorKind::Interrupted
            {
                self.callbacks.on_log(crate::types::LogLevel::Error, &format!("[MTProtoEngine] poll failed: {error}"));
                std::thread::sleep(Duration::from_millis(50));
            }
            let now = clock::now();
            let mut carried: VecDeque<SessionHandle> = std::mem::take(&mut self.more_readable);
            for event in events.iter() {
                if event.token() == WAKER_TOKEN {
                    continue;
                }
                let Some(handle) = self.tokens.get(&event.token()).copied() else {
                    continue;
                };
                if let Some(session) = self.sessions.get_mut(&handle) {
                    let readable = event.is_readable() || event.is_read_closed() || event.is_error();
                    let writable = event.is_writable() || event.is_write_closed();
                    if readable {
                        carried.retain(|other| *other != handle);
                    }
                    let more = session.handle_io(
                        event.token(),
                        readable,
                        writable,
                        self.poll.registry(),
                        &mut self.scratch,
                        now,
                        &self.callbacks,
                        &mut self.rng,
                    );
                    if more {
                        self.more_readable.push_back(handle);
                    }
                }
            }
            for handle in carried {
                if let Some(session) = self.sessions.get_mut(&handle)
                    && let Some(token) = session.active_token()
                    && session.handle_io(
                        token,
                        true,
                        false,
                        self.poll.registry(),
                        &mut self.scratch,
                        now,
                        &self.callbacks,
                        &mut self.rng,
                    )
                {
                    self.more_readable.push_back(handle);
                }
            }
            self.wake_pending.store(false, Ordering::SeqCst);
            if !self.drain_commands(now) {
                self.shutdown(now);
                return;
            }
            for session in self.sessions.values_mut() {
                session.drive(
                    self.poll.registry(),
                    now,
                    &mut self.resolver,
                    &self.config,
                    &self.callbacks,
                    &mut self.rng,
                );
            }
            if now.mono - self.last_shrink > SHRINK_INTERVAL {
                self.last_shrink = now.mono;
                for session in self.sessions.values_mut() {
                    session.shrink();
                }
                if self.sessions.is_empty() && self.scratch.capacity() > 64 * 1024 {
                    self.scratch = vec![0u8; 64 * 1024];
                } else if !self.sessions.is_empty() && self.scratch.len() < 256 * 1024 {
                    self.scratch = vec![0u8; 256 * 1024];
                }
            }
        }
    }

    fn shutdown(&mut self, now: mtproto_core::session::Now) {
        for session in self.sessions.values_mut() {
            session.shutdown(self.poll.registry(), now);
        }
        self.sessions.clear();
        self.tokens.clear();
    }

    fn drain_commands(&mut self, now: mtproto_core::session::Now) -> bool {
        while let Ok(command) = self.receiver.try_recv() {
            match command {
                Command::Shutdown => return false,
                Command::Create { handle, setup } => {
                    let token = Token(self.next_token);
                    self.next_token += 2;
                    let mut runtime = SessionRuntime::new(handle, *setup, token, now, &mut self.rng);
                    runtime.set_network_available(self.network_available, now, self.poll.registry());
                    self.tokens.insert(token, handle);
                    self.tokens.insert(runtime.race_token(), handle);
                    self.sessions.insert(handle, runtime);
                }
                Command::Destroy(handle) => {
                    if let Some(mut session) = self.sessions.remove(&handle) {
                        session.shutdown(self.poll.registry(), now);
                        self.tokens.remove(&session.token());
                        self.tokens.remove(&session.race_token());
                        self.callbacks.on_event(handle, EngineEvent::Closed);
                    }
                }
                Command::Send(handle, request) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.send(request, now);
                    } else {
                        self.callbacks.on_event(
                            handle,
                            EngineEvent::Rpc(mtproto_core::rpc::RpcEvent::Failed {
                                id: request.id,
                                code: -1,
                                message: "SESSION_CLOSED".into(),
                                response_time: now.unix,
                                duration: 0.0,
                            }),
                        );
                    }
                }
                Command::Cancel(handle, id) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.cancel(id, now, self.poll.registry(), &self.callbacks);
                    }
                }
                Command::SetPaused(handle, paused) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_paused(paused, now, self.poll.registry());
                    }
                }
                Command::SetOnline(handle, online) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_online(online, now);
                    }
                }
                Command::SetAuthKey(handle, material) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_auth_key(material, now, self.poll.registry(), &mut self.rng);
                    }
                }
                Command::SetAddresses(handle, addresses) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_addresses(addresses, now, self.poll.registry());
                    }
                }
                Command::SetObfuscationDcId(handle, dc_id) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_obfuscation_dc_id(dc_id, now, self.poll.registry());
                    }
                }
                Command::SetProxy(handle, proxy) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_proxy(proxy, now, self.poll.registry());
                    }
                }
                Command::UpdateEnvironment(handle, environment, noop) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.update_environment(*environment, noop, now);
                    }
                }
                Command::SetAuthTokenReady(handle, ready) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_auth_token_ready(ready, now);
                    }
                }
                Command::ResolveVerification(handle, id, verification) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.resolve_verification(id, verification, now);
                    }
                }
                Command::FailRequest(handle, id, code, message) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.fail_request(id, code, &message, now, &self.callbacks);
                    }
                }
                Command::DecideRetry(handle, id, retry) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.decide_retry(id, retry, now, &self.callbacks);
                    }
                }
                Command::InvalidateInitialization(handle) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.invalidate_initialization();
                    }
                }
                Command::DestroyAuthKey(handle) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.destroy_auth_key(now);
                    }
                }
                Command::SetTimeDifference(handle, difference) => {
                    if let Some(session) = self.sessions.get_mut(&handle) {
                        session.set_time_difference(difference);
                    }
                }
                Command::SetNetworkAvailable(available) => {
                    self.network_available = available;
                    for session in self.sessions.values_mut() {
                        session.set_network_available(available, now, self.poll.registry());
                    }
                }
                Command::ResetConnections => {
                    for session in self.sessions.values_mut() {
                        session.reset_connection(now, self.poll.registry());
                    }
                }
                Command::Resolved { host, port, addresses } => {
                    let waiting = self
                        .resolver
                        .in_flight
                        .remove(&(host.clone(), port))
                        .map(|(waiting, _)| waiting)
                        .unwrap_or_default();
                    for handle in waiting {
                        if let Some(session) = self.sessions.get_mut(&handle) {
                            session.on_resolved(&host, port, addresses.clone(), now);
                        }
                    }
                }
            }
        }
        true
    }
}
