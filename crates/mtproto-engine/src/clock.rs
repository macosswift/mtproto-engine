use std::time::{SystemTime, UNIX_EPOCH};

use mtproto_core::session::Now;

#[allow(unsafe_code)]
pub fn monotonic_seconds() -> f64 {
    let mut spec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut spec) };
    if result != 0 {
        return std::time::Instant::now().elapsed().as_secs_f64();
    }
    spec.tv_sec as f64 + spec.tv_nsec as f64 * 1e-9
}

pub fn unix_seconds() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs_f64()).unwrap_or(0.0)
}

pub fn now() -> Now {
    Now { mono: monotonic_seconds(), unix: unix_seconds() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_is_monotonic() {
        let a = monotonic_seconds();
        let b = monotonic_seconds();
        assert!(b >= a);
        assert!(unix_seconds() > 1_600_000_000.0);
    }
}
