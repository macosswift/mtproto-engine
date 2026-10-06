use std::sync::Arc;

use mio::{Registry, Token};
use mtproto_core::crypto::{OsRandom, SecureRandom};
use mtproto_core::session::Now;
use mtproto_core::transport::{Incoming, TransportConfig};

use super::SessionRuntime;
use super::http::{Probe, ProbeKind, ProbeLink};
use crate::connection::{ChunkStatus, Connection, WebSocketTarget};
use crate::host_stream::StreamTarget;
use crate::types::{DropReason, EngineCallbacks, LogLevel};

/// On Telegram Web's WebSocket endpoint an idle connection pings at least this often: the fronts close
/// a WebSocket after 91 s without traffic.
pub const WEBSOCKET_KEEPALIVE: f64 = 45.0;
/// Connections to the WebSocket endpoint that may fail in a row before the session tries TCP again.
pub const WEBSOCKET_MAX_FAILURES: u32 = 2;
/// Bytes a probe may buffer without its answer.
const PROBE_MAX_BUFFERED: usize = 64 * 1024;

impl SessionRuntime {
    /// Telegram Web's WebSocket endpoint can be tried: a web endpoint with a WebSocket path, and a host
    /// to open the stream.
    pub(super) fn websocket_possible(&self) -> bool {
        self.web_endpoint().is_some_and(|web| !web.ws_path.is_empty())
    }

    /// A stream connection to Telegram Web's WebSocket endpoint over a TLS stream the host opens.
    fn open_websocket(&self, token: Token, now: Now, rng: &mut OsRandom) -> Option<Connection> {
        let web = self.web_endpoint().filter(|web| !web.ws_path.is_empty())?;
        let (streams, signal) = self.host_streams.as_ref()?;
        let target = StreamTarget {
            host: web.address.clone().unwrap_or_else(|| web.host.clone()),
            port: web.port,
            tls_server_name: Some(web.host.clone()),
            alpn: vec!["http/1.1".into()],
            carrier: false,
        };
        let pipe = streams.open(&target, token, signal).ok()?;
        let transport = TransportConfig {
            framing: self.setup.framing,
            dc_id: self.setup.obfuscation_dc_id,
            secret: None,
            unix_time: (now.unix + self.time_difference()) as i32,
        };
        let websocket = WebSocketTarget { host: web.authority(), path: web.ws_path.clone() };
        Some(Connection::over_websocket(pipe, token, &transport, websocket, now.mono, rng))
    }

    /// Auto: a plain req_pq over the WebSocket endpoint, beside the HTTP probes.
    /// False when the probe could not even start.
    pub(super) fn start_websocket_probe(&mut self, registry: &Registry, now: Now, rng: &mut OsRandom) -> bool {
        let token = self.probe_token(ProbeKind::WebSocket);
        let Some(mut connection) = self.open_websocket(token, now, rng) else {
            return false;
        };
        let nonce: [u8; 16] = rng.array();
        let packet = self.plain_req_pq(nonce, now);
        if connection.send_packet(registry, &packet, false, rng).is_err() {
            connection.deregister(registry);
            return false;
        }
        self.auto.probes.push(Probe::new(
            ProbeKind::WebSocket,
            ProbeLink::Stream(Box::new(connection)),
            nonce,
            now.mono,
        ));
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_websocket_probe_io(
        &mut self,
        token: Token,
        readable: bool,
        registry: &Registry,
        scratch: &mut [u8],
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(probe) = self.auto.probes.iter_mut().find(|probe| probe.token() == token) else {
            return;
        };
        let nonce = probe.nonce;
        let ProbeLink::Stream(connection) = &mut probe.link else {
            return;
        };
        let mut failed = connection.handle_writable(registry, now.mono).is_err();
        let connected = connection.is_tcp_connected();
        probe.note_connected(connected, now.mono);
        let ProbeLink::Stream(connection) = &mut probe.link else {
            return;
        };
        let mut verified = false;
        while readable && !failed && !verified {
            match connection.read_chunk(registry, scratch, now.mono) {
                Ok(ChunkStatus::Data { .. }) => {}
                Ok(ChunkStatus::WouldBlock) => break,
                Ok(ChunkStatus::Eof) | Err(_) => failed = true,
            }
            match connection.next_incoming() {
                Ok(Some(Incoming::Packet(packet))) if super::is_res_pq_for(&packet, &nonce) => verified = true,
                Ok(Some(_)) | Err(_) => failed = true,
                Ok(None) => failed |= connection.buffered_input_len() > PROBE_MAX_BUFFERED,
            }
        }
        if verified {
            self.adopt_websocket_probe(token, registry, now, callbacks, rng);
        } else if failed {
            self.fail_http_probe(token, registry, now);
        }
    }

    /// The WebSocket probe answered while TCP did not: the stream transport moves to the endpoint, on
    /// the connection that proved it.
    pub(super) fn adopt_websocket_probe(
        &mut self,
        token: Token,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(at) = self.auto.probes.iter().position(|probe| probe.token() == token) else {
            return;
        };
        if !self.may_adopt_probe(now) {
            self.cancel_http_probe(registry);
            return;
        }
        let probe = self.auto.probes.remove(at);
        self.end_round_for_websocket(registry);
        let ProbeLink::Stream(mut connection) = probe.link else {
            return;
        };
        self.log(
            callbacks,
            LogLevel::Info,
            "TCP gets no answer but Telegram Web's WebSocket endpoint does; moving the stream there",
        );
        self.drop_racer(registry);
        if let Some(mut old) = self.connection.take() {
            self.report_drop(DropReason::TransportSwitch, now, callbacks);
            self.account_usage(&old);
            old.deregister(registry);
        }
        if let Some(rpc) = &mut self.rpc {
            rpc.connection_closed(now);
        }
        self.handshake = None;
        self.handshake_started_at = None;
        self.pending_plain.clear();
        self.progress = None;
        self.frame_watch = None;
        self.suspect_since = None;
        connection.heard_from_server = true;
        self.connection = Some(*connection);
        self.auto.on_websocket = true;
        self.note_route_http_needed(now);
        self.note_websocket_adopted(now);
        self.reset_failures();
        self.flaps = 0;
        self.apply_keepalive();
        self.on_established(now, callbacks, rng);
    }

    /// On the WebSocket endpoint: every new stream connection goes there.
    pub(super) fn start_websocket_connection(&mut self, registry: &Registry, now: Now, rng: &mut OsRandom) {
        let _ = registry;
        match self.open_websocket(self.free_token(), now, rng) {
            Some(connection) => self.connection = Some(connection),
            None => {
                self.auto.on_websocket = false;
                self.apply_keepalive();
                self.next_attempt_at = now.mono;
            }
        }
    }

    /// The WebSocket endpoint failed `WEBSOCKET_MAX_FAILURES` times in a row: TCP gets its turn again,
    /// and the probes after it if it stays silent, HTTPS first: a front can answer a probe and still cut
    /// every session.
    pub(super) fn settle_websocket(&mut self, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        if self.auto.on_websocket && self.failures >= WEBSOCKET_MAX_FAILURES {
            self.auto.on_websocket = false;
            self.apply_keepalive();
            self.next_attempt_at = self.next_attempt_at.min(now.mono + 0.05);
            self.note_probes_failed(now);
            self.demote_websocket(now);
            self.log(callbacks, LogLevel::Info, "Telegram Web's WebSocket endpoint keeps failing; trying TCP again");
        }
    }

    /// The TCP recheck answered: the stream transport goes back to TCP on the verified connection.
    pub(super) fn leave_websocket_for_tcp(&mut self, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        self.log(callbacks, LogLevel::Info, "a TCP route answers again; leaving the WebSocket endpoint");
        self.note_route_tcp_answered(now);
        self.auto.on_websocket = false;
        self.note_left_websocket(now);
        self.reset_failures();
        self.apply_keepalive();
    }

    pub(super) fn apply_keepalive(&mut self) {
        let cap = self.auto.on_websocket.then_some(WEBSOCKET_KEEPALIVE);
        if let Some(rpc) = &mut self.rpc {
            rpc.session_mut().set_keepalive_cap(cap);
        }
    }
}
