//! Handing a client's requests back to the host for another session without running any twice.
//!
//! After `start_handover` the client puts no request into its session. A request is released
//! (`RpcEvent::Released`) as soon as it is not out under a msg_id whose answer may still come: it never
//! went out, or the server said it never ran it, or the server answered it with an error the host chose
//! to retry (the old session would send it again under a new msg_id just the same) — released as not
//! run — or an earlier copy of it may have run but is gone (a new server session, a local reset) —
//! released as possibly run. A request chained
//! with `invoke_after` to one still waiting stays until that one is answered or released, so the host
//! sends the chain on in its order. A request the server may have run waits for its answer under its
//! own msg_id; `release_all` lets every remaining one go, as possibly run.

use super::{RequestId, RequestState, RpcClient, RpcEvent};
use crate::session::{Now, QueryId};

impl RequestState {
    /// An earlier copy of the request may have reached the server (`RequestState::reached_server`).
    pub(super) fn may_have_run_before(&self) -> bool {
        self.reached_server
    }

    /// How long the host should wait before sending the request again: what is left of a flood wait
    /// or a server error's delay. A wait for a key or a token belongs to this session alone.
    pub(super) fn retry_after(&self, now: Now) -> f64 {
        if self.rejected_key.is_some() || self.waiting_for_token {
            return 0.0;
        }
        (self.not_before - now.mono).max(0.0)
    }
}

impl RpcClient {
    /// The client's requests go to another session from now on; it cannot be undone.
    pub fn start_handover(&mut self, now: Now) {
        if self.handover {
            return;
        }
        self.handover = true;
        self.session.hand_over();
        self.release_handed_over(now);
    }

    pub fn is_handing_over(&self) -> bool {
        self.handover
    }

    /// Requests that still wait while the client hands over.
    pub fn held_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Lets every request still held go: those the server may have run as possibly run, the others as
    /// never sent. Nothing is left afterwards.
    pub fn release_all(&mut self, now: Now) {
        self.handover = true;
        self.session.hand_over();
        let ids: Vec<RequestId> = self.order.values().copied().collect();
        for id in ids {
            let Some(state) = self.requests.get(&id) else {
                continue;
            };
            let sent = state.in_session && self.session.may_have_run(QueryId::from(id));
            let may_have_run = sent || state.may_have_run_before() || state.pending_decision.is_some();
            self.release(id, may_have_run, now);
        }
    }

    /// Releases every request moving cannot run twice, in submission order, so that a request chained
    /// to one released in the same pass follows it.
    pub(super) fn release_handed_over(&mut self, now: Now) {
        if self.requests.is_empty() {
            return;
        }
        let ids: Vec<RequestId> = self.order.values().copied().collect();
        for id in ids {
            let Some(state) = self.requests.get(&id) else {
                continue;
            };
            if state.pending_decision.is_some() {
                continue;
            }
            if state.in_session && self.session.was_transmitted(QueryId::from(id)) {
                continue;
            }
            if state.request.invoke_after.is_some_and(|dependency| self.requests.contains_key(&dependency)) {
                continue;
            }
            let may_have_run =
                state.may_have_run_before() || (state.in_session && self.session.may_have_run(QueryId::from(id)));
            self.release(id, may_have_run, now);
        }
    }

    /// A request routed to this client after it began handing over goes straight back.
    pub(super) fn release_new(&mut self, state: RequestState, now: Now) {
        let may_have_run = state.may_have_run_before();
        self.push_released(&state, may_have_run, now);
    }

    fn release(&mut self, id: RequestId, may_have_run: bool, now: Now) {
        if self.requests.get(&id).is_some_and(|state| state.in_session) {
            self.session.cancel(QueryId::from(id));
        }
        let Some(state) = self.remove_request(id) else {
            return;
        };
        self.push_released(&state, may_have_run, now);
    }

    /// The session gave a query back (see `Session::hand_back`).
    pub(super) fn on_query_released(&mut self, id: RequestId, may_have_run: bool, now: Now) {
        let Some(state) = self.remove_request(id) else {
            return;
        };
        let may_have_run = may_have_run || state.may_have_run_before();
        self.push_released(&state, may_have_run, now);
    }

    /// `retry_after` is what is left of the request's own wait, none when it may have run.
    fn push_released(&mut self, state: &RequestState, may_have_run: bool, now: Now) {
        let retry_after = if may_have_run { 0.0 } else { state.retry_after(now) };
        self.events.push_back(RpcEvent::Released { id: state.request.id, may_have_run, retry_after });
    }
}
