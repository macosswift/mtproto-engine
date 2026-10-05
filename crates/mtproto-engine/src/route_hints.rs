use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// How long a session's finding that TCP does not get through, and HTTP does, is trusted by the others
/// on a network the host does not name.
pub const HTTP_HINT_LIFETIME: f64 = 600.0;
/// How long the same finding is remembered for a network the host names: sessions on it try HTTP early
/// until then, or until a TCP connection there answers.
pub const HTTP_MEMORY_LIFETIME: f64 = 7.0 * 86_400.0;
/// Named networks remembered at most; the least recently seen goes first.
pub const NETWORKS_REMEMBERED: usize = 64;
/// A finding dated later than this ahead of the clock is not trusted: the clock was ahead when it was
/// made, or the memory is corrupt.
const FUTURE_TOLERANCE: f64 = 60.0;
/// A finding that still holds is stored again once it is this old, so the memory keeps a network that
/// keeps blocking TCP.
const REFRESH_AFTER: f64 = 3600.0;
const MAX_KEY_LENGTH: usize = 64;
const MEMORY_FORMAT: u8 = 1;
const ENTRY_LENGTH_AFTER_KEY: usize = 24;

/// What the engine's sessions learned about the network, in Unix seconds: once one of them proved that
/// only HTTP gets through, the others try HTTP at once instead of waiting out their own TCP silence.
/// With the host naming networks (`set_network`), the finding is kept per network across runs (the host
/// stores `export` and gives it back with `load`), so a session on a network known to block TCP tries
/// HTTP early from its first connection.
#[derive(Debug, Default)]
pub struct RouteHints {
    inner: Mutex<State>,
    /// Held while a change is taken and reported, so the host stores the memory in the order it changed.
    reporting: Mutex<()>,
    /// A change waits to be reported: workers check it without taking the locks.
    pending: AtomicBool,
}

#[derive(Debug, Default)]
struct State {
    network: Option<Vec<u8>>,
    unnamed: Record,
    named: HashMap<Vec<u8>, Record>,
    changed: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Record {
    http_needed_at: Option<f64>,
    tcp_answered_at: Option<f64>,
    seen_at: f64,
}

impl Record {
    fn http_likely(&self, now: f64, lifetime: f64) -> bool {
        self.http_needed_at.is_some_and(|at| now - at < lifetime && at - now <= FUTURE_TOLERANCE)
            && self.tcp_answered_at.is_none_or(|tcp| tcp < self.http_needed_at.unwrap_or(0.0))
    }
}

impl State {
    fn current(&mut self) -> &mut Record {
        match &self.network {
            Some(key) => self.named.entry(key.clone()).or_default(),
            None => &mut self.unnamed,
        }
    }

    fn peek(&self) -> Option<&Record> {
        match &self.network {
            Some(key) => self.named.get(key),
            None => Some(&self.unnamed),
        }
    }

    fn lifetime(&self) -> f64 {
        if self.network.is_some() { HTTP_MEMORY_LIFETIME } else { HTTP_HINT_LIFETIME }
    }

    fn prune(&mut self, now: f64) {
        let current = self.network.clone();
        self.named.retain(|key, record| Some(key) == current.as_ref() || record.http_likely(now, HTTP_MEMORY_LIFETIME));
        while self.named.len() > NETWORKS_REMEMBERED {
            let Some(oldest) = self
                .named
                .iter()
                .filter(|(key, _)| Some(*key) != current.as_ref())
                .min_by(|a, b| a.1.seen_at.total_cmp(&b.1.seen_at))
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.named.remove(&oldest);
        }
    }
}

impl RouteHints {
    pub fn note_http_needed(&self, now: f64) {
        if let Ok(mut state) = self.inner.lock() {
            let named = state.network.is_some();
            let lifetime = state.lifetime();
            let record = state.current();
            let news =
                !record.http_likely(now, lifetime) || record.http_needed_at.is_some_and(|at| now - at >= REFRESH_AFTER);
            if news || !named {
                record.http_needed_at = Some(now);
                record.tcp_answered_at = None;
            }
            record.seen_at = now;
            if named && news {
                state.changed = true;
                self.pending.store(true, Ordering::Release);
            }
        }
    }

    /// A TCP connection answered: whatever was found about TCP on this network no longer holds, however
    /// the clock moved since.
    pub fn note_tcp_answered(&self, now: f64) {
        if let Ok(mut state) = self.inner.lock() {
            let named = state.network.is_some();
            let record = state.current();
            let flips = record.http_needed_at.is_some();
            record.http_needed_at = None;
            record.tcp_answered_at = Some(now);
            record.seen_at = now;
            if named && flips {
                state.changed = true;
                self.pending.store(true, Ordering::Release);
            }
        }
    }

    /// TCP did not get through lately on this network, and no TCP connection answered since.
    pub fn http_likely(&self, now: f64) -> bool {
        self.inner
            .lock()
            .is_ok_and(|state| state.peek().is_some_and(|record| record.http_likely(now, state.lifetime())))
    }

    /// A new network the host does not name: nothing learned on the old one holds. Named networks keep
    /// their own records.
    pub fn forget(&self) {
        if let Ok(mut state) = self.inner.lock()
            && state.network.is_none()
        {
            state.unnamed = Record::default();
        }
    }

    /// The network the device is on now, as an opaque key from the host (a hash; empty when unknown).
    /// True when the network changed: sessions then have to look at what is known about it.
    pub fn set_network(&self, key: &[u8], now: f64) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        let key = (!key.is_empty()).then(|| key[..key.len().min(MAX_KEY_LENGTH)].to_vec());
        if state.network == key {
            return false;
        }
        state.network = key;
        state.unnamed = Record::default();
        if state.network.is_some() {
            state.current().seen_at = now;
            state.prune(now);
        }
        true
    }

    /// Takes the memory back from an earlier run; anything malformed is ignored.
    pub fn load(&self, memory: &[u8], now: f64) {
        let Some(entries) = parse(memory) else {
            return;
        };
        if let Ok(mut state) = self.inner.lock() {
            for (key, record) in entries {
                if record.seen_at - now > FUTURE_TOLERANCE {
                    continue;
                }
                let known = state.named.get(&key).copied().unwrap_or_default();
                if record.seen_at >= known.seen_at {
                    state.named.insert(key, record);
                }
            }
            state.prune(now);
        }
    }

    /// The memory of named networks, for the host to store.
    pub fn export(&self, now: f64) -> Vec<u8> {
        self.inner.lock().map_or_else(
            |_| Vec::new(),
            |mut state| {
                state.prune(now);
                serialize(&state.named, now)
            },
        )
    }

    /// Hands `report` the memory when a named network's finding changed since the last call. Reports
    /// from several threads reach `report` in the order the memory changed.
    pub fn report_change(&self, now: f64, report: impl FnOnce(Vec<u8>)) {
        if !self.pending.load(Ordering::Acquire) {
            return;
        }
        let Ok(_reporting) = self.reporting.lock() else {
            return;
        };
        let memory = {
            let Ok(mut state) = self.inner.lock() else {
                return;
            };
            if !state.changed {
                return;
            }
            state.changed = false;
            self.pending.store(false, Ordering::Release);
            state.prune(now);
            serialize(&state.named, now)
        };
        report(memory);
    }

    #[cfg(test)]
    fn take_change(&self, now: f64) -> Option<Vec<u8>> {
        let mut taken = None;
        self.report_change(now, |memory| taken = Some(memory));
        taken
    }
}

fn time_bits(value: Option<f64>) -> [u8; 8] {
    value.unwrap_or(0.0).to_le_bytes()
}

fn time_from(bytes: &[u8]) -> Option<f64> {
    let value = f64::from_le_bytes(bytes.try_into().ok()?);
    (value.is_finite() && value > 0.0).then_some(value)
}

/// Only networks where TCP is known not to get through are worth storing.
fn serialize(named: &HashMap<Vec<u8>, Record>, now: f64) -> Vec<u8> {
    let mut entries: Vec<_> =
        named.iter().filter(|(_, record)| record.http_likely(now, HTTP_MEMORY_LIFETIME)).collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = vec![MEMORY_FORMAT, entries.len().min(usize::from(u8::MAX)) as u8];
    for (key, record) in entries.into_iter().take(usize::from(u8::MAX)) {
        out.push(key.len() as u8);
        out.extend_from_slice(key);
        out.extend_from_slice(&time_bits(record.http_needed_at));
        out.extend_from_slice(&time_bits(record.tcp_answered_at));
        out.extend_from_slice(&time_bits(Some(record.seen_at)));
    }
    out
}

fn parse(memory: &[u8]) -> Option<Vec<(Vec<u8>, Record)>> {
    let (&format, rest) = memory.split_first()?;
    if format != MEMORY_FORMAT {
        return None;
    }
    let (&count, mut rest) = rest.split_first()?;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (&length, after) = rest.split_first()?;
        let length = usize::from(length);
        if length == 0 || length > MAX_KEY_LENGTH || after.len() < length + ENTRY_LENGTH_AFTER_KEY {
            return None;
        }
        let key = after[..length].to_vec();
        let times = &after[length..length + ENTRY_LENGTH_AFTER_KEY];
        entries.push((
            key,
            Record {
                http_needed_at: time_from(&times[0..8]),
                tcp_answered_at: time_from(&times[8..16]),
                seen_at: time_from(&times[16..24]).unwrap_or(0.0),
            },
        ));
        rest = &after[length + ENTRY_LENGTH_AFTER_KEY..];
    }
    rest.is_empty().then_some(entries)
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

    #[test]
    fn a_named_network_remembers_for_days_and_across_runs() {
        let now = 1_800_000_000.0;
        let hints = RouteHints::default();
        hints.set_network(b"office", now);
        hints.note_http_needed(now);
        let stored = hints.take_change(now).expect("the finding changed");
        assert!(hints.take_change(now).is_none());

        let next_run = RouteHints::default();
        next_run.load(&stored, now + 86_400.0);
        next_run.set_network(b"office", now + 86_400.0);
        assert!(next_run.http_likely(now + 86_400.0), "known to block TCP");
        assert!(!next_run.http_likely(now + HTTP_MEMORY_LIFETIME + 1.0));
        next_run.set_network(b"home", now + 86_400.0);
        assert!(!next_run.http_likely(now + 86_400.0), "another network knows nothing");
        next_run.set_network(b"office", now + 86_401.0);
        next_run.forget();
        assert!(next_run.http_likely(now + 86_401.0), "a network change keeps a named network's memory");
        next_run.note_tcp_answered(now + 86_402.0);
        assert!(!next_run.http_likely(now + 86_402.0));
        assert!(next_run.take_change(now + 86_402.0).is_some(), "TCP answering there is a change to store");
        next_run.note_tcp_answered(now + 86_403.0);
        assert!(next_run.take_change(now + 86_403.0).is_none(), "every later TCP answer is not");
    }

    #[test]
    fn a_finding_from_a_clock_that_ran_ahead_does_not_stick() {
        let now = 1_800_000_000.0;
        let ahead = RouteHints::default();
        ahead.set_network(b"office", now + 3600.0);
        ahead.note_http_needed(now + 3600.0);
        let stored = ahead.export(now + 3600.0);

        let hints = RouteHints::default();
        hints.load(&stored, now);
        hints.set_network(b"office", now);
        assert!(!hints.http_likely(now), "a finding an hour ahead of the clock is not trusted");

        let stepped_back = RouteHints::default();
        stepped_back.set_network(b"office", now);
        stepped_back.note_http_needed(now);
        assert!(stepped_back.take_change(now).is_some());
        stepped_back.note_tcp_answered(now - 5.0);
        assert!(!stepped_back.http_likely(now - 5.0), "TCP answering clears it even after the clock stepped back");
        assert!(stepped_back.take_change(now - 5.0).is_some());
        for second in 0..10 {
            stepped_back.note_tcp_answered(now + f64::from(second));
        }
        assert!(stepped_back.take_change(now + 10.0).is_none(), "later answers change nothing");
    }

    #[test]
    fn sessions_moving_to_http_one_after_another_store_the_memory_once() {
        let now = 1_800_000_000.0;
        let hints = RouteHints::default();
        hints.set_network(b"office", now);
        hints.note_http_needed(now);
        assert!(hints.take_change(now).is_some());
        for session in 1..5 {
            hints.note_http_needed(now + f64::from(session));
        }
        assert!(hints.take_change(now + 5.0).is_none(), "the finding already held");
        hints.note_http_needed(now + REFRESH_AFTER + 1.0);
        assert!(hints.take_change(now + REFRESH_AFTER + 1.0).is_some(), "an old finding is stored again");
    }

    #[test]
    fn memory_is_bounded_and_malformed_memory_is_ignored() {
        let now = 1_800_000_000.0;
        let hints = RouteHints::default();
        for index in 0..(NETWORKS_REMEMBERED + 20) {
            hints.set_network(format!("net{index}").as_bytes(), now + index as f64);
            hints.note_http_needed(now + index as f64);
        }
        let stored = hints.export(now + 200.0);
        let entries = parse(&stored).expect("well formed");
        assert!(entries.len() <= NETWORKS_REMEMBERED);
        assert!(entries.iter().any(|(key, _)| key == b"net83"), "the newest are kept");

        let loaded = RouteHints::default();
        for garbage in [&[][..], &[2, 0][..], &[1, 1, 0][..], &[1, 1, 70][..], &stored[..stored.len() - 1]] {
            loaded.load(garbage, now);
        }
        assert!(loaded.export(now).len() == 2, "nothing was taken from malformed memory");
    }
}
