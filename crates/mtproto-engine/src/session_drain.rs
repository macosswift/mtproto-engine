//! `mt_session_drain`: the host moves a session's requests to another session (a live engine switch)
//! without running any of them twice.
//!
//! Every request that never reached the server is released at once (`RpcEvent::Released`, not run).
//! A request the server may have is kept: the session keeps or reopens its connection, sends it again
//! only under its own msg_id (the server never runs a msg_id twice), and completes it when its answer
//! comes. The session sends no request it had not sent before; pings, acknowledgements and the service
//! messages that ask about its requests still go. A request that would have to go under a new msg_id
//! leaves instead: as never run when the server said it did not get it, as possibly run otherwise
//! (`Session::hand_back`). So does every request still kept when the session would change keys (a
//! temporary key rotation, the server forgetting the key): their answers could never arrive. At the
//! deadline, extended in `DRAIN_EXTENSION` steps up to `DRAIN_MAX` while answers keep arriving, every
//! request left is released, as possibly run if it ever went out, and the session closes
//! (`EngineEvent::Closed`). It closes as soon as nothing is left.

use std::sync::Arc;

use mio::Registry;
use mtproto_core::rpc::RpcEvent;
use mtproto_core::session::Now;

use super::SessionRuntime;
use crate::types::{EngineCallbacks, EngineEvent, LogLevel};

/// Each extension of the deadline while answers keep arriving.
pub const DRAIN_EXTENSION: f64 = 5.0;
/// The longest a drain lasts, whatever the host asked and however many answers arrive.
pub const DRAIN_MAX: f64 = 30.0;

#[derive(Debug, Clone, Copy)]
pub(super) struct DrainState {
    started_at: f64,
    deadline: f64,
    last_answer_at: Option<f64>,
}

impl SessionRuntime {
    /// Starts handing the session's requests back to the host; `deadline` seconds from now at the
    /// latest (extended while answers arrive, up to `DRAIN_MAX`). A second call changes nothing.
    pub fn drain(&mut self, deadline: f64, now: Now, registry: &Registry, callbacks: &Arc<dyn EngineCallbacks>) {
        if self.drain.is_some() || self.closed {
            return;
        }
        let seconds = if deadline.is_nan() { 0.0 } else { deadline.clamp(0.0, DRAIN_MAX) };
        self.drain = Some(DrainState { started_at: now.mono, deadline: now.mono + seconds, last_answer_at: None });
        let queued: Vec<_> = self.queued.drain(..).collect();
        release_pending(&mut self.undelivered, queued, now);
        if let Some(rpc) = &mut self.rpc {
            rpc.start_handover(now);
        }
        let held = self.rpc.as_ref().map_or(0, |rpc| rpc.held_request_count());
        self.log(
            callbacks,
            LogLevel::Info,
            &format!("draining for another session: {held} requests wait for their answers, at most {seconds:.1} s"),
        );
        self.pump_rpc_events(now, registry, callbacks);
        self.drive_drain(now, registry, callbacks);
    }

    pub(super) fn is_draining(&self) -> bool {
        self.drain.is_some()
    }

    /// An answer to a kept request arrived: the deadline may be extended.
    pub(super) fn note_drain_answer(&mut self, now: Now) {
        if let Some(drain) = &mut self.drain {
            drain.last_answer_at = Some(now.mono);
        }
    }

    /// Requests the session would send under a new session (a new key) leave instead, as possibly run
    /// when they ever went out: `retire_rpc` while draining.
    pub(super) fn release_retired(&mut self, pending: Vec<mtproto_core::rpc::PendingRequest>, now: Now) {
        release_pending(&mut self.undelivered, pending, now);
    }

    /// Ends the drain when nothing is left or the deadline passed. True once the session is closed.
    pub(super) fn drive_drain(&mut self, now: Now, registry: &Registry, callbacks: &Arc<dyn EngineCallbacks>) -> bool {
        let Some(mut drain) = self.drain else {
            return false;
        };
        if self.closed {
            if !self.undelivered.is_empty() {
                self.pump_rpc_events(now, registry, callbacks);
            }
            return true;
        }
        let held = self.rpc.as_ref().map_or(0, |rpc| rpc.held_request_count()) + self.queued.len();
        if held > 0 {
            let limit = drain.started_at + DRAIN_MAX;
            while now.mono >= drain.deadline
                && drain.deadline < limit
                && drain.last_answer_at.is_some_and(|at| at > drain.deadline - DRAIN_EXTENSION)
            {
                drain.deadline = (drain.deadline + DRAIN_EXTENSION).min(limit);
            }
            self.drain = Some(drain);
            if now.mono < drain.deadline {
                return false;
            }
            self.log(callbacks, LogLevel::Info, &format!("drain deadline: {held} requests leave unanswered"));
        }
        self.finish_drain(now, registry, callbacks);
        true
    }

    /// The session's key has to change while it drains: the answers of the requests it kept could
    /// never arrive under another one, so they leave now.
    pub(super) fn end_drain_for_new_key(
        &mut self,
        now: Now,
        registry: &Registry,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) {
        self.log(callbacks, LogLevel::Info, "the key would change while draining; the requests kept leave now");
        self.finish_drain(now, registry, callbacks);
    }

    fn finish_drain(&mut self, now: Now, registry: &Registry, callbacks: &Arc<dyn EngineCallbacks>) {
        if let Some(rpc) = &mut self.rpc {
            rpc.release_all(now);
        }
        let queued: Vec<_> = self.queued.drain(..).collect();
        self.release_retired(queued, now);
        self.pump_rpc_events(now, registry, callbacks);
        self.closed = true;
        self.cancel_http_probe(registry);
        self.close_connection(registry, now, false);
        callbacks.on_event(self.handle, EngineEvent::Closed);
    }

    pub(super) fn drain_deadline(&self) -> Option<f64> {
        if self.closed {
            return None;
        }
        self.drain.map(|drain| drain.deadline)
    }
}

/// Releases requests the client no longer holds, in their order, each with what is left of its own
/// wait (none when it may have run).
fn release_pending(undelivered: &mut Vec<RpcEvent>, pending: Vec<mtproto_core::rpc::PendingRequest>, now: Now) {
    for pending in pending {
        let may_have_run = pending.may_have_run();
        let retry_after = if may_have_run { 0.0 } else { pending.retry_after(now) };
        undelivered.push(RpcEvent::Released { id: pending.id(), may_have_run, retry_after });
    }
}
