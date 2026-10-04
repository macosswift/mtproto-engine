use std::sync::Mutex;

/// How long a session's finding that TCP does not get through, and HTTP does, is trusted by the others.
pub const HTTP_HINT_LIFETIME: f64 = 600.0;

/// What the engine's sessions learned about the network: once one of them proved that only HTTP gets
/// through, the others try HTTP at once instead of waiting out their own TCP silence.
#[derive(Debug, Default)]
pub struct RouteHints {
    inner: Mutex<Hints>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Hints {
    http_needed_at: Option<f64>,
    tcp_answered_at: Option<f64>,
}

impl RouteHints {
    pub fn note_http_needed(&self, now: f64) {
        if let Ok(mut hints) = self.inner.lock() {
            hints.http_needed_at = Some(now);
        }
    }

    pub fn note_tcp_answered(&self, now: f64) {
        if let Ok(mut hints) = self.inner.lock() {
            hints.tcp_answered_at = Some(now);
        }
    }

    /// Another session moved to HTTP lately, and no TCP connection answered since.
    pub fn http_likely(&self, now: f64) -> bool {
        self.inner.lock().is_ok_and(|hints| {
            hints.http_needed_at.is_some_and(|at| now - at < HTTP_HINT_LIFETIME)
                && hints.tcp_answered_at.is_none_or(|tcp| tcp < hints.http_needed_at.unwrap_or(0.0))
        })
    }

    /// A new network: nothing learned on the old one holds.
    pub fn forget(&self) {
        if let Ok(mut hints) = self.inner.lock() {
            *hints = Hints::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hint_holds_until_tcp_answers_or_it_ages_out() {
        let hints = RouteHints::default();
        assert!(!hints.http_likely(10.0));
        hints.note_http_needed(10.0);
        assert!(hints.http_likely(11.0));
        assert!(!hints.http_likely(10.0 + HTTP_HINT_LIFETIME + 1.0));
        hints.note_tcp_answered(12.0);
        assert!(!hints.http_likely(13.0));
        hints.note_http_needed(14.0);
        assert!(hints.http_likely(15.0));
        hints.forget();
        assert!(!hints.http_likely(15.0));
    }
}
