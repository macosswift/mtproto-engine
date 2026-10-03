use std::sync::atomic::{AtomicU64, Ordering};

use mtproto_core::session::{FRESH_ALLOWANCE_MAX, TRANSMIT_GRACE_RATE_INITIAL};

/// What the engine's sessions are uploading over connections that answered, handed to the kernel
/// but not confirmed by the server, and the uplink rate measured last: behind a first-in, first-out
/// bottleneck a fresh connection's first exchange queues behind it. Where the bottleneck shares the
/// link fairly it does not, and the estimate only lengthens the fresh allowance.
#[derive(Debug, Default)]
pub struct Uploads {
    bytes: AtomicU64,
    rate: AtomicU64,
}

impl Uploads {
    pub fn change(&self, from: u64, to: u64) {
        if to > from {
            self.bytes.fetch_add(to - from, Ordering::Relaxed);
        } else if from > to {
            self.bytes.fetch_sub(from - to, Ordering::Relaxed);
        }
    }

    /// The uplink rate the uploading sessions measured last; 0 when they have not, or the network
    /// changed since.
    pub fn note_rate(&self, rate: f64) {
        self.rate.store(rate.to_bits(), Ordering::Relaxed);
    }

    /// How long the other sessions' uploads may hold up a first exchange, for a session uploading
    /// `own` bytes itself: half again what they need at the measured rate, at most
    /// `FRESH_ALLOWANCE_MAX`.
    pub fn queue_seconds(&self, own: u64) -> f64 {
        let others = self.bytes.load(Ordering::Relaxed).saturating_sub(own);
        if others == 0 {
            return 0.0;
        }
        let rate = f64::from_bits(self.rate.load(Ordering::Relaxed));
        let rate = if rate > 0.0 { rate } else { TRANSMIT_GRACE_RATE_INITIAL };
        (others as f64 / rate * 1.5).min(FRESH_ALLOWANCE_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_upload_on_a_fast_uplink_holds_nobody_up() {
        let uploads = Uploads::default();
        assert_eq!(uploads.queue_seconds(0), 0.0);
        uploads.change(0, 1024 * 1024);
        uploads.note_rate(2.0 * 1024.0 * 1024.0);
        assert_eq!(uploads.queue_seconds(0), 0.75);
        assert_eq!(uploads.queue_seconds(1024 * 1024), 0.0, "a session does not wait for its own upload");
        uploads.note_rate(16.0 * 1024.0);
        assert_eq!(uploads.queue_seconds(0), FRESH_ALLOWANCE_MAX);
        uploads.change(1024 * 1024, 0);
        assert_eq!(uploads.queue_seconds(0), 0.0);
    }
}
