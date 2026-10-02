#[derive(Debug, Clone, Default)]
pub struct MsgIdGenerator {
    last: i64,
}

impl MsgIdGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last(&self) -> i64 {
        self.last
    }

    pub fn next(&mut self, server_unix_time: f64) -> i64 {
        let candidate = msg_id_for_time(server_unix_time);
        let id = if candidate <= self.last { self.last.saturating_add(4) & !3 } else { candidate };
        self.last = id;
        id
    }

    pub fn reset_floor(&mut self, floor: i64) {
        if floor > self.last {
            self.last = floor & !3;
        }
    }
}

pub const MAX_MSG_ID_SECONDS: f64 = (i32::MAX - 1) as f64;

pub fn msg_id_for_time(unix_time: f64) -> i64 {
    let clamped = unix_time.clamp(0.0, MAX_MSG_ID_SECONDS);
    let seconds = clamped.floor();
    let fraction = ((clamped - seconds) * 4_294_967_296.0) as u64 & 0xffff_fffc;
    ((seconds as i64) << 32) | fraction as i64
}

pub fn msg_id_time(msg_id: i64) -> f64 {
    (msg_id >> 32) as f64 + ((msg_id as u64 & 0xffff_ffff) as f64) / 4_294_967_296.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgIdTimeCheck {
    Ok,
    TooOld,
    TooNew,
}

pub const MSG_ID_MAX_PAST_SECONDS: f64 = 300.0;
pub const MSG_ID_MAX_FUTURE_SECONDS: f64 = 30.0;

pub fn check_server_msg_id_time(msg_id: i64, server_now: f64) -> MsgIdTimeCheck {
    let time = msg_id_time(msg_id);
    if time < server_now - MSG_ID_MAX_PAST_SECONDS {
        MsgIdTimeCheck::TooOld
    } else if time > server_now + MSG_ID_MAX_FUTURE_SECONDS {
        MsgIdTimeCheck::TooNew
    } else {
        MsgIdTimeCheck::Ok
    }
}

#[derive(Debug, Clone, Default)]
pub struct SeqNoGenerator {
    content_messages: i32,
}

impl SeqNoGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&mut self, content_related: bool) -> i32 {
        let seq_no = self.content_messages * 2 + i32::from(content_related);
        if content_related {
            self.content_messages += 1;
        }
        seq_no
    }

    pub fn content_messages(&self) -> i32 {
        self.content_messages
    }

    pub fn reset(&mut self) {
        self.content_messages = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ids_are_divisible_by_four_and_monotonic() {
        let mut generator = MsgIdGenerator::new();
        let first = generator.next(1_700_000_000.25);
        assert_eq!(first % 4, 0);
        assert_eq!(first >> 32, 1_700_000_000);
        let second = generator.next(1_700_000_000.25);
        assert_eq!(second, first + 4);
        let third = generator.next(1_600_000_000.0);
        assert_eq!(third, second + 4);
    }

    #[test]
    fn time_roundtrip() {
        let id = msg_id_for_time(1_234_567_890.5);
        assert!((msg_id_time(id) - 1_234_567_890.5).abs() < 1e-6);
    }

    #[test]
    fn server_time_window() {
        let now = 1_700_000_000.0;
        assert_eq!(check_server_msg_id_time(msg_id_for_time(now) | 1, now), MsgIdTimeCheck::Ok);
        assert_eq!(check_server_msg_id_time(msg_id_for_time(now - 301.0), now), MsgIdTimeCheck::TooOld);
        assert_eq!(check_server_msg_id_time(msg_id_for_time(now + 31.0), now), MsgIdTimeCheck::TooNew);
        assert_eq!(check_server_msg_id_time(msg_id_for_time(now - 299.0), now), MsgIdTimeCheck::Ok);
    }

    #[test]
    fn seqno_rules() {
        let mut seq = SeqNoGenerator::new();
        assert_eq!(seq.next(false), 0);
        assert_eq!(seq.next(true), 1);
        assert_eq!(seq.next(true), 3);
        assert_eq!(seq.next(false), 4);
        assert_eq!(seq.next(true), 5);
        assert_eq!(seq.content_messages(), 3);
        seq.reset();
        assert_eq!(seq.next(true), 1);
    }

    #[test]
    fn floor_moves_forward_only() {
        let mut generator = MsgIdGenerator::new();
        generator.reset_floor(1001);
        assert_eq!(generator.last(), 1000);
        generator.reset_floor(10);
        assert_eq!(generator.last(), 1000);
    }

    proptest! {
        #[test]
        fn strictly_increasing_for_any_clock(times in proptest::collection::vec(0.0f64..2.0e9, 1..200)) {
            let mut generator = MsgIdGenerator::new();
            let mut previous = 0i64;
            for time in times {
                let id = generator.next(time);
                prop_assert!(id > previous);
                prop_assert_eq!(id % 4, 0);
                previous = id;
            }
        }
    }
}
