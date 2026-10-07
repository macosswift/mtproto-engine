//! Handing a session's queries over to another session without running any of them twice.
//!
//! Once `hand_over` is called the session sends no query it has not sent yet. A query it did send
//! goes out again only under the msg_id it has, which the server never runs twice, and waits for its
//! answer. A query that would get a new msg_id leaves the session instead, as `SessionEvent::Released`:
//! with `may_have_run` false when the server said it never ran it (`msgs_state_info` "not received",
//! `bad_msg_notification`, `bad_server_salt` for the only copy that went out), true when it may have
//! (a `new_session_created` that covers it, a local session reset, `msgs_state_info` status 1 "nothing
//! known", which a server that forgot an old msg_id also answers). Once a copy may have run, the query
//! stays possibly run (`Query::maybe_ran_before`), also when it went back to the queue before the
//! handover. The host sends a released query on another session, or gives up on it.

use super::{QueryId, QueryState, Session, SessionEvent};

impl Session {
    /// The session hands its queries over from now on; it cannot be undone.
    pub fn hand_over(&mut self) {
        self.handover = true;
    }

    pub fn is_handing_over(&self) -> bool {
        self.handover
    }

    /// Removes a query that would otherwise go out under a new msg_id, and reports it released.
    /// The bind query stays: it is the session's own and never runs a host call.
    pub(super) fn hand_back(&mut self, id: QueryId, may_have_run: bool) -> bool {
        if self.bind.as_ref().is_some_and(|(bind, _)| *bind == id) {
            return false;
        }
        let Some(query) = self.queries.remove(&id) else {
            return false;
        };
        let may_have_run = may_have_run || query.maybe_ran_before;
        Self::count_transition(&mut self.pending_queries, &mut self.unknown_queries, Some(query.state), None);
        match query.state {
            QueryState::Pending => self.pending.retain(|pending| *pending != id),
            QueryState::Sent | QueryState::Unknown => {
                if self.by_msg_id.get(&query.msg_id) == Some(&id) {
                    self.by_msg_id.remove(&query.msg_id);
                }
                self.detach_from_container(query.container_id, query.msg_id);
                self.forget_awaited_answers_of(&[(query.msg_id, id)]);
            }
        }
        self.to_retransmit.retain(|other| *other != id);
        self.refresh_unknown_tracking();
        self.events.push_back(SessionEvent::Released { id, may_have_run });
        true
    }
}
