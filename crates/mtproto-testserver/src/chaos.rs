use mtproto_core::crypto::{SecureRandom, XorShiftRandom};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fault {
    DropBeforeExecution,
    DropAfterExecution,
    RotateSalt,
    ExpireSalt,
    ResendRequest,
    UnknownSibling,
    FloodWait,
    InternalError,
    TransportFlood,
    SlowAnswer,
    DuplicateAnswer,
    GzipAnswer,
    MsgCopy,
    ServerPing,
    AckNoise,
    Stall,
    NewSession,
    HostileGarbage,
    HostileBadMsgKey,
    HostileForeignSession,
    HostileEvenMsgId,
    HostileFanOut,
    HostileGzipBomb,
    HostileHugeVector,
    HostileSaltsFlood,
    HostileReplay,
    HostileSaltStorm,
    HostileUnknownResults,
    HostileDeepNest,
    HostileTransportCode,
    HostileOversized,
    HostileTruncated,
    HostileQuickAckNoise,
    HostileSaltLoop,
    HostileTimeLoop,
    HostileResendLoop,
    AdaptiveReconnectAmbush,
    AdaptiveKillOnRetransmit,
    AdaptiveTimeWarp,
    AdaptiveLazyRedelivery,
    AdaptiveSlowDrip,
    AdaptiveTrickle,
}

impl Fault {
    pub const ALL: [Fault; 17] = [
        Fault::DropBeforeExecution,
        Fault::DropAfterExecution,
        Fault::RotateSalt,
        Fault::ExpireSalt,
        Fault::ResendRequest,
        Fault::UnknownSibling,
        Fault::FloodWait,
        Fault::InternalError,
        Fault::TransportFlood,
        Fault::SlowAnswer,
        Fault::DuplicateAnswer,
        Fault::GzipAnswer,
        Fault::MsgCopy,
        Fault::ServerPing,
        Fault::AckNoise,
        Fault::Stall,
        Fault::NewSession,
    ];

    pub const LOOPS: [Fault; 3] = [Fault::HostileSaltLoop, Fault::HostileTimeLoop, Fault::HostileResendLoop];

    pub const ADAPTIVE: [Fault; 5] = [
        Fault::AdaptiveReconnectAmbush,
        Fault::AdaptiveKillOnRetransmit,
        Fault::AdaptiveTimeWarp,
        Fault::AdaptiveLazyRedelivery,
        Fault::AdaptiveSlowDrip,
    ];

    pub const PER_CONNECTION: [Fault; 2] = [Fault::AdaptiveReconnectAmbush, Fault::AdaptiveKillOnRetransmit];

    pub const HOSTILE: [Fault; 16] = [
        Fault::HostileGarbage,
        Fault::HostileBadMsgKey,
        Fault::HostileForeignSession,
        Fault::HostileEvenMsgId,
        Fault::HostileFanOut,
        Fault::HostileGzipBomb,
        Fault::HostileHugeVector,
        Fault::HostileSaltsFlood,
        Fault::HostileReplay,
        Fault::HostileSaltStorm,
        Fault::HostileUnknownResults,
        Fault::HostileDeepNest,
        Fault::HostileTransportCode,
        Fault::HostileOversized,
        Fault::HostileTruncated,
        Fault::HostileQuickAckNoise,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Fault::DropBeforeExecution => "drop-before",
            Fault::DropAfterExecution => "drop-after",
            Fault::RotateSalt => "rotate-salt",
            Fault::ExpireSalt => "expire-salt",
            Fault::ResendRequest => "resend-req",
            Fault::UnknownSibling => "unknown-sibling",
            Fault::FloodWait => "flood-wait",
            Fault::InternalError => "internal-error",
            Fault::TransportFlood => "transport-flood",
            Fault::SlowAnswer => "slow-answer",
            Fault::DuplicateAnswer => "duplicate-answer",
            Fault::GzipAnswer => "gzip-answer",
            Fault::MsgCopy => "msg-copy",
            Fault::ServerPing => "server-ping",
            Fault::AckNoise => "ack-noise",
            Fault::Stall => "stall",
            Fault::NewSession => "new-session",
            Fault::HostileGarbage => "x-garbage",
            Fault::HostileBadMsgKey => "x-bad-msg-key",
            Fault::HostileForeignSession => "x-foreign-session",
            Fault::HostileEvenMsgId => "x-even-msg-id",
            Fault::HostileFanOut => "x-fan-out",
            Fault::HostileGzipBomb => "x-gzip-bomb",
            Fault::HostileHugeVector => "x-huge-vector",
            Fault::HostileSaltsFlood => "x-salts-flood",
            Fault::HostileReplay => "x-replay",
            Fault::HostileSaltStorm => "x-salt-storm",
            Fault::HostileUnknownResults => "x-unknown-results",
            Fault::HostileDeepNest => "x-deep-nest",
            Fault::HostileTransportCode => "x-transport-code",
            Fault::HostileOversized => "x-oversized",
            Fault::HostileTruncated => "x-truncated",
            Fault::HostileQuickAckNoise => "x-quick-ack-noise",
            Fault::HostileSaltLoop => "x-salt-loop",
            Fault::HostileTimeLoop => "x-time-loop",
            Fault::HostileResendLoop => "x-resend-loop",
            Fault::AdaptiveReconnectAmbush => "a-reconnect-ambush",
            Fault::AdaptiveKillOnRetransmit => "a-kill-on-retransmit",
            Fault::AdaptiveTimeWarp => "a-time-warp",
            Fault::AdaptiveLazyRedelivery => "a-lazy-redelivery",
            Fault::AdaptiveSlowDrip => "a-slow-drip",
            Fault::AdaptiveTrickle => "a-trickle",
        }
    }

    pub fn by_name(name: &str) -> Option<Fault> {
        Fault::ALL
            .into_iter()
            .chain(Fault::HOSTILE)
            .chain(Fault::LOOPS)
            .chain(Fault::ADAPTIVE)
            .chain([Fault::AdaptiveTrickle])
            .find(|fault| fault.name() == name)
    }

    pub fn closes_connection(self) -> bool {
        matches!(
            self,
            Fault::HostileGarbage
                | Fault::HostileBadMsgKey
                | Fault::HostileTransportCode
                | Fault::HostileOversized
                | Fault::HostileTruncated
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChaosConfig {
    pub seed: u64,
    pub faults: Vec<(Fault, f64)>,
}

impl ChaosConfig {
    pub fn only(seed: u64, fault: Fault, rate: f64) -> Self {
        Self { seed, faults: vec![(fault, rate)] }
    }

    pub fn mixed(seed: u64, rate_each: f64) -> Self {
        Self {
            seed,
            faults: Fault::ALL
                .into_iter()
                .filter(|fault| *fault != Fault::NewSession)
                .map(|fault| (fault, rate_each))
                .collect(),
        }
    }

    pub fn hostile(seed: u64, rate_each: f64) -> Self {
        Self { seed, faults: Fault::HOSTILE.into_iter().map(|fault| (fault, rate_each)).collect() }
    }

    pub fn apocalypse(seed: u64, rate_each: f64, with_hostile: bool) -> Self {
        let mut faults: Vec<(Fault, f64)> = Fault::ALL
            .into_iter()
            .filter(|fault| *fault != Fault::NewSession)
            .chain(Fault::ADAPTIVE)
            .map(|fault| (fault, rate_each))
            .collect();
        if with_hostile {
            faults.extend(Fault::HOSTILE.into_iter().map(|fault| (fault, rate_each)));
        }
        for (fault, rate) in &mut faults {
            if Fault::PER_CONNECTION.contains(fault) {
                *rate = (*rate * 100.0).min(0.25);
            }
        }
        Self { seed, faults }
    }

    pub fn rate(&self, fault: Fault) -> f64 {
        self.faults.iter().filter(|(candidate, _)| *candidate == fault).map(|(_, rate)| *rate).sum()
    }

    pub fn chance(rng: &mut XorShiftRandom, rate: f64) -> bool {
        rate > 0.0 && ((rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < rate
    }

    pub fn roll(&self, rng: &mut XorShiftRandom) -> Option<Fault> {
        let sample = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let mut cumulative = 0.0;
        for (fault, rate) in &self.faults {
            if Fault::PER_CONNECTION.contains(fault) {
                continue;
            }
            cumulative += rate;
            if sample < cumulative {
                return Some(*fault);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_respected_and_names_round_trip() {
        let config = ChaosConfig::mixed(1, 0.01);
        let mut rng = XorShiftRandom::new(9);
        let mut hits = 0;
        for _ in 0..100_000 {
            if config.roll(&mut rng).is_some() {
                hits += 1;
            }
        }
        let expected = 100_000.0 * 0.01 * (Fault::ALL.len() - 1) as f64;
        assert!((hits as f64 - expected).abs() < expected * 0.1, "{hits} vs {expected}");
        for fault in Fault::ALL.into_iter().chain(Fault::HOSTILE).chain(Fault::LOOPS).chain(Fault::ADAPTIVE) {
            assert_eq!(Fault::by_name(fault.name()), Some(fault));
        }
        let connection_level = ChaosConfig::only(3, Fault::AdaptiveReconnectAmbush, 1.0);
        assert_eq!(connection_level.roll(&mut rng), None, "per-connection faults are not rolled per request");
        assert_eq!(connection_level.rate(Fault::AdaptiveReconnectAmbush), 1.0);
    }
}
