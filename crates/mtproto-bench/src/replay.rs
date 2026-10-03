//! Replays failures recorded in the field by TelegramCore's `NetworkTelemetry` against the test
//! server, to reproduce them locally.
//!
//! Records are grouped by failure class, session role and API method. Each group becomes a case: a
//! simulated network derived from what the records saw (latency, jitter, cellular link, reconnect
//! cadence, outages, proxy) and a set of candidate server faults for the failure class. Every
//! candidate runs on each engine with the client's own telemetry switched on, and the failure
//! classes the run records decide whether it reproduced the field failure.
//!
//! A timeline cannot tell a network that drops connections from a client that reconnects because of
//! what the server sent, so the two are separate hypotheses: the network-only candidate runs the
//! measured link with its reconnect cadence and outage, and each server-fault candidate runs the
//! measured link without them.

use std::collections::BTreeMap;
use std::time::Duration;

use mtproto_netsim::Profile;
use mtproto_testserver::api::FileSpec;
use mtproto_testserver::chaos::{ChaosConfig, Fault};

use crate::cluster::{self, ClusterResult, ClusterScenario, ProxyKind};
use crate::json::{self, Value};

/// A connection the engine gave up on shortly before a failure.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedDrop {
    /// Seconds before the failure.
    pub ago: f64,
    pub reason: String,
    pub answered: bool,
    /// Seconds the connection lived.
    pub age: f64,
}

/// One `NetworkFailureRecord`, with the fields replay uses.
#[derive(Debug, Clone, PartialEq)]
pub struct FailureRecord {
    pub failure: String,
    pub role: String,
    pub method: String,
    pub engine: String,
    pub code: i64,
    pub error: String,
    pub duration: f64,
    pub retries: u64,
    pub flood_wait: u64,
    pub expected_bytes: u64,
    pub request_bytes: u64,
    pub cellular: Option<bool>,
    pub via_proxy: bool,
    /// Whether the user was online, which makes the main session give up on a silent connection
    /// within a few round trips instead of minutes.
    pub user_online: Option<bool>,
    /// Connection states before the failure, oldest first, as (seconds before the failure, state).
    pub connection: Vec<(f64, String)>,
    /// Seconds since the network was created.
    pub uptime: f64,
    /// Connections of the same role the engine gave up on shortly before, oldest first.
    pub drops: Vec<RecordedDrop>,
    pub since_online: Option<f64>,
    /// Estimated requests in flight when the failure was recorded.
    pub in_flight: Option<u64>,
    pub latency_p50: Option<f64>,
    pub latency_p90: Option<f64>,
    /// Bytes per second recent uploads and downloads moved at, rounded up to a power of two.
    pub uplink_rate: Option<f64>,
    pub downlink_rate: Option<f64>,
}

impl FailureRecord {
    fn from_value(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        let number = |key: &str| value.get(key).and_then(Value::as_f64);
        let failure = text("failure")?;
        let connection = value
            .get("connection")
            .and_then(Value::as_array)
            .map(|events| {
                events
                    .iter()
                    .filter_map(|event| Some((event.get("ago")?.as_f64()?, event.get("state")?.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            failure,
            role: text("role").unwrap_or_else(|| "main".into()),
            method: text("method").unwrap_or_else(|| "unknown".into()),
            engine: text("engine").unwrap_or_default(),
            code: number("code").unwrap_or(0.0) as i64,
            error: text("error").unwrap_or_default(),
            duration: number("duration").unwrap_or(0.0),
            retries: number("retries").unwrap_or(0.0) as u64,
            flood_wait: number("flood_wait").unwrap_or(0.0) as u64,
            expected_bytes: number("expected_bytes").unwrap_or(0.0) as u64,
            request_bytes: number("request_bytes").unwrap_or(0.0) as u64,
            cellular: match value.get("cellular") {
                Some(Value::Bool(cellular)) => Some(*cellular),
                _ => None,
            },
            via_proxy: matches!(value.get("via_proxy"), Some(Value::Bool(true))),
            user_online: match value.get("user_online") {
                Some(Value::Bool(online)) => Some(*online),
                _ => None,
            },
            connection,
            uptime: number("uptime").unwrap_or(0.0),
            drops: value
                .get("drops")
                .and_then(Value::as_array)
                .map(|drops| {
                    drops
                        .iter()
                        .filter_map(|drop| {
                            Some(RecordedDrop {
                                ago: drop.get("ago")?.as_f64()?,
                                reason: drop.get("reason")?.as_str()?.to_string(),
                                answered: matches!(drop.get("answered"), Some(Value::Bool(true))),
                                age: drop.get("age").and_then(Value::as_f64).unwrap_or(0.0),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            since_online: number("since_online"),
            in_flight: number("in_flight").map(|value| value as u64),
            latency_p50: number("latency_p50"),
            latency_p90: number("latency_p90"),
            uplink_rate: number("uplink_rate"),
            downlink_rate: number("downlink_rate"),
        })
    }
}

/// Reads records from `failures.jsonl` (one record per line), a JSON array of records, a reported
/// chunk (`{"records": [...]}`) or an array of reported chunks or app log events.
pub fn load_records(text: &str) -> Vec<FailureRecord> {
    fn collect(value: &Value, out: &mut Vec<FailureRecord>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    collect(item, out);
                }
            }
            Value::Object(_) => {
                if let Some(records) = value.get("records") {
                    collect(records, out);
                } else if let Some(data) = value.get("data") {
                    collect(data, out);
                } else if let Some(record) = FailureRecord::from_value(value) {
                    out.push(record);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(value) = json::parse(text.trim()) {
        collect(&value, &mut out);
        return out;
    }
    let mut skipped = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match json::parse(line) {
            Some(value) => collect(&value, &mut out),
            None => skipped += 1,
        }
    }
    if skipped > 0 {
        eprintln!("skipped {skipped} lines that are not JSON");
    }
    out
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(values[values.len() / 2])
}

fn is_connected(state: &str) -> bool {
    state == "online" || state == "updating"
}

/// What the connection timelines of a group of records say about the link.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkHistory {
    /// Median seconds between losing the connection and losing it again.
    pub reconnect_interval: Option<f64>,
    /// Median seconds from starting to connect to being connected.
    pub connect_time: Option<f64>,
    /// Median seconds the connection had been down when the request failed.
    pub down_at_failure: Option<f64>,
    pub proxy_issues: bool,
}

/// Spans off the connection shorter than this are status blips, not disconnects.
const DISCONNECT_MIN: f64 = 0.5;

pub fn link_history(records: &[&FailureRecord]) -> LinkHistory {
    let mut intervals = Vec::new();
    let mut connect_times = Vec::new();
    let mut down = Vec::new();
    let mut proxy_issues = false;
    for record in records {
        let events: Vec<(f64, &str)> = record.connection.iter().map(|(ago, state)| (-ago, state.as_str())).collect();
        proxy_issues |= events.iter().any(|(_, state)| *state == "connecting_proxy_issues");
        let mut disconnects = Vec::new();
        let mut index = 0;
        while index < events.len() {
            let (time, state) = events[index];
            let was_connected = index > 0 && is_connected(events[index - 1].1);
            if was_connected && !is_connected(state) {
                let back = events[index..].iter().find(|(_, state)| is_connected(state)).map(|(at, _)| *at);
                if back.is_none_or(|back| back - time >= DISCONNECT_MIN) {
                    disconnects.push(time);
                }
            }
            if state == "connecting" || state == "connecting_proxy_issues" {
                let started = time;
                let mut end = index + 1;
                while end < events.len() && !is_connected(events[end].1) && events[end].1 != "waiting_network" {
                    end += 1;
                }
                if end < events.len() && is_connected(events[end].1) {
                    connect_times.push(events[end].0 - started);
                }
                index = end.max(index + 1);
                continue;
            }
            index += 1;
        }
        intervals.extend(disconnects.windows(2).map(|pair| pair[1] - pair[0]));
        if let Some(since) = record.since_online
            && since > 0.0
        {
            down.push(since);
        }
    }
    LinkHistory {
        reconnect_interval: median(intervals),
        connect_time: median(connect_times),
        down_at_failure: (down.len() * 2 > records.len()).then(|| median(down)).flatten(),
        proxy_issues,
    }
}

/// A simulated link that matches what the records measured.
pub fn derive_profile(name: &str, records: &[&FailureRecord], history: &LinkHistory) -> Profile {
    let p50 = median(records.iter().filter_map(|record| record.latency_p50).collect());
    let p90 = median(records.iter().filter_map(|record| record.latency_p90).collect());
    let cellular = records.iter().filter(|record| record.cellular == Some(true)).count() * 2 > records.len();
    let mut profile = Profile::perfect();
    profile.name = name.to_string();
    let one_way = p50.map(|p50| p50 / 2.0).unwrap_or(if cellular { 0.075 } else { 0.025 }).clamp(0.001, 1.5);
    profile.latency = Duration::from_secs_f64(one_way);
    if let (Some(p50), Some(p90)) = (p50, p90) {
        profile.jitter = Duration::from_secs_f64(((p90 - p50) / 2.0).clamp(0.0, 1.0));
    }
    if cellular {
        profile.bandwidth = Some(1_500_000 / 8);
        profile.max_chunk = 1400;
        profile.stall_probability = 0.01;
        profile.stall = Duration::from_millis(400);
    } else {
        profile.bandwidth = Some(20_000_000 / 8);
        profile.max_chunk = 16 * 1024;
    }
    if let Some(interval) = history.reconnect_interval {
        let interval = interval.clamp(2.0, 120.0);
        profile.reset_after = Some((Duration::from_secs_f64(interval * 0.5), Duration::from_secs_f64(interval * 1.5)));
    }
    if let Some(connect_time) = history.connect_time {
        profile.connect_delay = Duration::from_secs_f64(connect_time.clamp(0.0, 5.0));
    }
    if history.proxy_issues {
        profile.refuse_probability = 0.3;
    }
    let measured =
        |rates: Vec<f64>| median(rates).map(|rate| (rate / std::f64::consts::SQRT_2).max(LINK_RATE_MIN) as u64);
    if let Some(rate) = measured(records.iter().filter_map(|record| record.downlink_rate).collect()) {
        profile.bandwidth = Some(rate);
        profile.max_chunk = profile.max_chunk.min(1400);
    }
    if let Some(rate) = measured(records.iter().filter_map(|record| record.uplink_rate).collect()) {
        profile.uplink = Some(rate);
    } else if let Some(bound) = median(records.iter().filter_map(stalled_upload_bound).collect()) {
        let link = profile.uplink.or(profile.bandwidth).unwrap_or(u64::MAX);
        profile.uplink = Some(link.min(bound.max(LINK_RATE_MIN) as u64));
    }
    profile
}

/// The slowest link replay derives from measured rates.
const LINK_RATE_MIN: f64 = 2048.0;

/// An upload part that stalled or never finished did not cross the link in the time it was given, so
/// the uplink was slower than its size over that time. Parts are powers of two plus a few bytes of
/// request, so the part is half its power-of-two bucket.
fn stalled_upload_bound(record: &&FailureRecord) -> Option<f64> {
    let stuck = matches!(record.failure.as_str(), "stalled" | "abandoned" | "slow");
    (stuck && record.method.starts_with("upload.save") && record.request_bytes >= 16 * 1024 && record.duration > 0.0)
        .then(|| record.request_bytes as f64 / 2.0 / record.duration)
}

fn is_timeout(error: &str) -> bool {
    error == "Timeout" || error.ends_with(" timeout")
}

/// Server faults that can produce a failure class. Every case also runs with the network alone.
pub fn candidate_faults(failure: &str, code: i64, error: &str) -> Vec<Vec<(Fault, f64)>> {
    match failure {
        "flood" => vec![vec![(Fault::FloodWait, 0.05)], vec![(Fault::TransportFlood, 0.01)]],
        "server" if code == -503 || is_timeout(error) => {
            vec![
                vec![(Fault::Stall, 0.02)],
                vec![(Fault::DropBeforeExecution, 0.01)],
                vec![(Fault::DropAfterExecution, 0.01)],
            ]
        }
        "server" => vec![vec![(Fault::InternalError, 0.05)]],
        "parse" => vec![
            vec![(Fault::HostileUnknownResults, 0.01)],
            vec![(Fault::HostileTruncated, 0.01)],
            vec![(Fault::GzipAnswer, 0.05)],
        ],
        "slow" => vec![vec![(Fault::SlowAnswer, 0.02)], vec![(Fault::AdaptiveSlowDrip, 0.01)]],
        "stalled" | "abandoned" => vec![
            vec![(Fault::RotateSalt, 0.01)],
            vec![(Fault::TransportFlood, 0.01)],
            vec![(Fault::AdaptiveTimeWarp, 0.01)],
            vec![(Fault::DropAfterExecution, 0.01)],
            vec![(Fault::Stall, 0.02)],
            vec![(Fault::NewSession, 0.01)],
            vec![(Fault::MsgCopy, 0.01)],
        ],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct ReplayCase {
    pub name: String,
    pub failure: String,
    pub role: String,
    pub method: String,
    pub records: usize,
    pub engines_seen: Vec<String>,
    pub sample_error: String,
    pub profile: Profile,
    pub outage: Option<(f64, f64)>,
    pub proxy: bool,
    /// The user was online in most of the records.
    pub user_online: bool,
    /// Why the engine gave up on connections before these failures, most frequent first.
    pub drops: Vec<(String, usize)>,
    pub expected_bytes: u64,
    /// The largest request, rounded up to a power of two: an upload's part size.
    pub request_bytes: u64,
    /// Requests kept in flight, from the records' estimates.
    pub concurrency: usize,
    pub candidates: Vec<Vec<(Fault, f64)>>,
}

/// Groups records into cases, the most frequent first.
pub fn cases(records: &[FailureRecord]) -> Vec<ReplayCase> {
    let mut groups: BTreeMap<(String, String, String), Vec<&FailureRecord>> = BTreeMap::new();
    for record in records {
        groups.entry((record.failure.clone(), record.role.clone(), record.method.clone())).or_default().push(record);
    }
    let mut result: Vec<ReplayCase> = groups
        .into_iter()
        .map(|((failure, role, method), group)| {
            let name = format!("replay/{failure}/{role}/{method}");
            let history = link_history(&group);
            let profile = derive_profile(&name, &group, &history);
            let outage = history.down_at_failure.map(|down| (3.0, down.clamp(1.0, 30.0)));
            let mut engines_seen: Vec<String> = group.iter().map(|record| record.engine.clone()).collect();
            engines_seen.sort();
            engines_seen.dedup();
            let first = group[0];
            let mut candidates: Vec<Vec<(Fault, f64)>> = Vec::new();
            for record in &group {
                for candidate in candidate_faults(&failure, record.code, &record.error) {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            ReplayCase {
                name,
                candidates,
                failure,
                role,
                method,
                records: group.len(),
                engines_seen,
                sample_error: if first.error.is_empty() {
                    first.code.to_string()
                } else {
                    format!("{} {}", first.code, first.error)
                },
                profile,
                outage,
                proxy: group.iter().filter(|record| record.via_proxy).count() * 2 > group.len(),
                user_online: group.iter().filter(|record| record.user_online == Some(true)).count() * 2 > group.len(),
                drops: drop_counts(&group),
                expected_bytes: group.iter().map(|record| record.expected_bytes).max().unwrap_or(0),
                request_bytes: group.iter().map(|record| record.request_bytes).max().unwrap_or(0),
                concurrency: median(
                    group.iter().filter_map(|record| record.in_flight.map(|value| value as f64)).collect(),
                )
                .map(|value| (value as usize).clamp(8, 256))
                .unwrap_or(32),
            }
        })
        .collect();
    result.sort_by(|lhs, rhs| rhs.records.cmp(&lhs.records).then(lhs.name.cmp(&rhs.name)));
    result
}

fn faults_label(faults: &[(Fault, f64)]) -> String {
    if faults.is_empty() {
        "network only".into()
    } else {
        faults.iter().map(|(fault, rate)| format!("{} {rate}", fault.name())).collect::<Vec<_>>().join(", ")
    }
}

/// How long a candidate runs: long enough for the measured outage, two reconnect cycles and a stall.
fn run_seconds(case: &ReplayCase, stalled_after: f64) -> f64 {
    let outage_end = case.outage.map_or(0.0, |(at, length)| at + length);
    let resets = case.profile.reset_after.map_or(0.0, |(_, max)| max.as_secs_f64() * 2.0);
    (outage_end + resets + stalled_after + 5.0).max(20.0)
}

/// Bytes the measured link carries in `seconds` one way.
fn link_budget(profile: &Profile, upstream: bool, seconds: f64) -> u64 {
    let rate = if upstream { profile.uplink.or(profile.bandwidth) } else { profile.bandwidth };
    (rate.unwrap_or(2_500_000) as f64 * seconds) as u64
}

/// TelegramCore uploads a file over 10 MB in 512 KB `saveBigFilePart` parts; a smaller file already
/// in memory goes in `saveFilePart` parts whatever the hints.
const BIG_UPLOAD_MIN: u64 = 10 * 1024 * 1024 + 512 * 1024;
const SMALL_UPLOAD_MAX: u64 = 10 * 1024 * 1024;
/// Parts of 128 KB (a streamed file) or 256 KB (`useLargerParts`) rather than 16 KB (a file in memory),
/// after the power-of-two rounding of the request around them; both replay as 256 KB parts, the only
/// large size the bench can make TelegramCore use below 10 MB.
const LARGE_PART_MIN: u64 = 128 * 1024;
/// Two 256 KB parts and a tail, for links too slow for a big upload within the run.
const LARGE_UPLOAD: u64 = 2 * 256 * 1024 + 4096;
const TRANSFER_FILES_MAX: u64 = 64;

/// The bench scenario for one candidate of a case. Calls run for a fixed time rather than a fixed
/// number, and transfers are sized to keep the measured link busy as long, so that its outage and
/// reconnects happen while requests are waiting. Uploads replay as uploads, in big parts when the
/// failures were; downloads use files on the main DC, the one the faults are injected on.
pub fn scenario(case: &ReplayCase, faults: &[(Fault, f64)], seed: u64, dump: &str) -> ClusterScenario {
    let upload = case.method.starts_with("upload.save");
    let media = !upload && (case.role == "media" || case.role == "cdn");
    let stalled_after = if upload || media { 20.0 } else { 6.0 };
    let seconds = run_seconds(case, stalled_after);
    let big = case.method == "upload.saveBigFilePart";
    let budget = link_budget(&case.profile, true, seconds);
    let large_parts = upload && (if big { budget / 2 < BIG_UPLOAD_MIN } else { case.request_bytes >= LARGE_PART_MIN });
    let mut scenario = if upload {
        let (size, count) = if large_parts {
            ((budget / 2).clamp(LARGE_UPLOAD, SMALL_UPLOAD_MAX), 2)
        } else if big {
            ((budget / 2).min(64 * 1024 * 1024), 2)
        } else {
            let size = (budget / 8).clamp(64 * 1024, 512 * 1024);
            (size, (budget / size).clamp(2, TRANSFER_FILES_MAX))
        };
        let uploads = (0..count as i64)
            .map(|index| FileSpec { id: 9100 + index, datacenter_id: cluster::MAIN_DC, size, cdn: false })
            .collect();
        cluster::scenario(&case.name, "tc-upload", "perfect", uploads, 1)
    } else if media {
        let size = (case.expected_bytes.max(128 * 1024) * 4).min(8 * 1024 * 1024);
        let count = (link_budget(&case.profile, false, seconds) / size).clamp(4, TRANSFER_FILES_MAX);
        let files: Vec<FileSpec> = (0..count as i64)
            .map(|index| FileSpec { id: 9000 + index, datacenter_id: cluster::MAIN_DC, size, cdn: false })
            .collect();
        cluster::scenario(&case.name, "tc-download", "perfect", files, 2)
    } else {
        let mut scenario = cluster::scenario(&case.name, "tc-torture", "perfect", Vec::new(), case.concurrency);
        scenario.requests = 0;
        scenario.duration = seconds;
        scenario
    };
    scenario.deadline = seconds * 3.0 + 60.0;
    scenario.stall_exit = stalled_after * 2.0 + 10.0;
    let mut profile = case.profile.clone();
    if faults.is_empty() {
        scenario.outage = case.outage;
    } else {
        profile.reset_after = None;
    }
    scenario.custom_profile = Some(profile);
    if case.proxy && !media && !upload {
        scenario.proxy = Some(ProxyKind::Socks5);
        scenario.routes = vec![cluster::Route::Measured];
    }
    if !faults.is_empty() {
        scenario.chaos = Some(ChaosConfig { seed, faults: faults.to_vec() });
    }
    if case.user_online {
        scenario.env.push(("TC_BENCH_ONLINE".into(), "1".into()));
    }
    if large_parts {
        scenario.env.push(("TC_BENCH_UPLOAD_LARGE_PARTS".into(), "1".into()));
        scenario.stall_exit = scenario.stall_exit.max(150.0);
        let uplink = case.profile.uplink.or(case.profile.bandwidth).unwrap_or(u64::MAX).max(1) as f64;
        let bytes: u64 = scenario.files.iter().map(|file| file.size).sum();
        scenario.deadline = scenario.deadline.max(bytes as f64 / uplink * 2.0 + 60.0);
    }
    scenario.env.extend([
        ("TC_BENCH_TELEMETRY".into(), "1".into()),
        ("TC_BENCH_STALLED_AFTER".into(), stalled_after.to_string()),
        ("TC_BENCH_WATCH_EVERY".into(), "1".into()),
        ("TC_BENCH_TELEMETRY_DUMP".into(), dump.into()),
    ]);
    scenario
}

pub struct ReplayArgs {
    pub records: String,
    pub binary: String,
    pub engines: Vec<String>,
    pub max_cases: usize,
    pub rounds: usize,
    pub only: Option<String>,
    pub plan_only: bool,
}

impl ReplayArgs {
    pub fn parse(arguments: &[String]) -> Self {
        let mut args = Self {
            records: String::new(),
            binary: String::new(),
            engines: vec!["rust".into(), "mtprotokit".into()],
            max_cases: 5,
            rounds: 1,
            only: None,
            plan_only: false,
        };
        let mut iter = arguments.iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--records" => args.records = iter.next().cloned().expect("records path"),
                "--telegramcore" => args.binary = iter.next().cloned().expect("telegramcore path"),
                "--engines" => args.engines = iter.next().expect("engines").split(',').map(str::to_string).collect(),
                "--max-cases" => args.max_cases = iter.next().and_then(|v| v.parse().ok()).expect("max cases"),
                "--rounds" => args.rounds = iter.next().and_then(|v| v.parse().ok()).expect("rounds"),
                "--only" => args.only = iter.next().cloned(),
                "--plan" => args.plan_only = true,
                other => panic!("unknown argument {other}"),
            }
        }
        assert!(!args.records.is_empty(), "--records PATH");
        assert!(args.plan_only || !args.binary.is_empty(), "--telegramcore PATH");
        args
    }
}

/// Drops by reason, each counted once although every failure in the window after it lists it: a
/// drop an earlier record listed has the same reason and age there, at the same uptime give or take
/// the whole-second uptime. Each earlier drop stands for one drop of a later record, so drops one
/// record lists twice (sessions cut together) both count. Records carry no source, so identical
/// drops of different users at the same uptime count once.
fn drop_counts(group: &[&FailureRecord]) -> Vec<(String, usize)> {
    let mut seen: Vec<(f64, &RecordedDrop)> = Vec::new();
    for record in group {
        let earlier = seen.len();
        let mut claimed = vec![false; earlier];
        for drop in &record.drops {
            let at = record.uptime - drop.ago;
            let matched = (0..earlier).find(|&index| {
                let (time, other) = seen[index];
                !claimed[index]
                    && other.reason == drop.reason
                    && other.answered == drop.answered
                    && other.age == drop.age
                    && (time - at).abs() < 1.01
            });
            match matched {
                Some(index) => claimed[index] = true,
                None => seen.push((at, drop)),
            }
        }
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, drop) in seen {
        let key = if drop.answered { drop.reason.clone() } else { format!("{} (unanswered)", drop.reason) };
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts
}

fn describe(case: &ReplayCase) -> String {
    let profile = &case.profile;
    format!(
        "{}: {} records of `{}` ({}), engines {:?}, {} in flight\n  link: one-way latency {} ms ±{} ms, bandwidth {}{}, chunk {} B, stalls {:.0}%, resets {}, connect delay {} ms, refuse {:.0}%{}{}{}",
        case.name,
        case.records,
        case.method,
        case.sample_error,
        case.engines_seen,
        case.concurrency,
        profile.latency.as_millis(),
        profile.jitter.as_millis(),
        profile.bandwidth.map(|bytes| format!("{} kbit/s", bytes * 8 / 1000)).unwrap_or_else(|| "unlimited".into()),
        profile.uplink.map(|bytes| format!(" ({} kbit/s up)", bytes * 8 / 1000)).unwrap_or_default(),
        profile.max_chunk,
        profile.stall_probability * 100.0,
        profile
            .reset_after
            .map(|(min, max)| format!("every {:.0}–{:.0} s", min.as_secs_f64(), max.as_secs_f64()))
            .unwrap_or_else(|| "never".into()),
        profile.connect_delay.as_millis(),
        profile.refuse_probability * 100.0,
        case.outage.map(|(at, length)| format!(", outage {length:.0} s at {at:.0} s")).unwrap_or_default(),
        if case.proxy { ", via SOCKS5 proxy" } else { "" },
        if case.user_online { ", user online" } else { "" }
    ) + &if case.drops.is_empty() {
        String::new()
    } else {
        format!(
            "\n  engine dropped connections: {}",
            case.drops.iter().map(|(reason, count)| format!("{reason} ×{count}")).collect::<Vec<_>>().join(", ")
        )
    }
}

pub struct CandidateResult {
    pub faults: String,
    pub engine: String,
    pub reproduced: bool,
    pub classes: BTreeMap<String, usize>,
    pub result: ClusterResult,
}

/// A stall or an abandonment reproduces only when requests failed or never finished: on a link as
/// slow as the records measured, requests that finish late are recorded as stalled too.
fn stuck(case: &ReplayCase) -> bool {
    matches!(case.failure.as_str(), "stalled" | "abandoned")
}

fn unfinished(result: &ClusterResult) -> bool {
    result.report.as_ref().is_none_or(|report| result.issued > report.completed)
}

/// Whether a run recorded the case's failure class on the case's role.
pub fn reproduced(case: &ReplayCase, local: &[FailureRecord]) -> bool {
    local.iter().any(|record| {
        let same_class = record.failure == case.failure
            || (case.failure == "abandoned" && record.failure == "stalled")
            || (case.failure == "stalled" && record.failure == "abandoned");
        let media = |role: &str| role == "media" || role == "cdn";
        same_class && (record.role == case.role || case.role == "worker" || (media(&record.role) && media(&case.role)))
    })
}

pub fn run(args: ReplayArgs) {
    let text = std::fs::read_to_string(&args.records).expect("read records");
    let records = load_records(&text);
    let mut all = cases(&records);
    if let Some(filter) = &args.only {
        all.retain(|case| case.name.contains(filter.as_str()));
    }
    all.truncate(args.max_cases);
    eprintln!("{} records, {} cases", records.len(), all.len());
    let mut out = String::new();
    for (case_index, case) in all.iter().enumerate() {
        out.push_str(&format!("\n### {}\n\n", describe(case)));
        if args.plan_only {
            for faults in std::iter::once(Vec::new()).chain(case.candidates.iter().cloned()) {
                out.push_str(&format!("- candidate: {}\n", faults_label(&faults)));
            }
            continue;
        }
        out.push_str("| Candidate | Engine | Reproduced | Local failures | Done/Issued | Failed or hung | p50 ms | p99 ms | Conns |\n");
        out.push_str("|---|---|---|---|---|---|---|---|---|\n");
        for (candidate_index, faults) in std::iter::once(Vec::new()).chain(case.candidates.iter().cloned()).enumerate()
        {
            for round in 0..args.rounds {
                for engine in &args.engines {
                    let seed = 7000 + case_index as u64 * 101 + candidate_index as u64 * 7 + round as u64;
                    let dump = std::env::temp_dir().join(format!("replay-{}-{seed}-{engine}.json", std::process::id()));
                    let dump = dump.to_string_lossy().to_string();
                    let _ = std::fs::remove_file(&dump);
                    eprintln!(
                        "[{}/{}] {} — {} — tc-{engine}",
                        case_index + 1,
                        all.len(),
                        case.name,
                        faults_label(&faults)
                    );
                    let result = cluster::run(&scenario(case, &faults, seed, &dump), &args.binary, engine, seed);
                    let local = std::fs::read_to_string(&dump).map(|text| load_records(&text)).unwrap_or_default();
                    let _ = std::fs::remove_file(&dump);
                    let mut classes = BTreeMap::new();
                    for record in &local {
                        *classes.entry(record.failure.clone()).or_insert(0) += 1;
                    }
                    let row = CandidateResult {
                        faults: faults_label(&faults),
                        engine: engine.clone(),
                        reproduced: reproduced(case, &local) && (!stuck(case) || unfinished(&result)),
                        classes,
                        result,
                    };
                    let line = markdown_row(&row);
                    eprintln!("{line}");
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
    }
    println!("{out}");
}

fn markdown_row(row: &CandidateResult) -> String {
    let classes = if row.classes.is_empty() {
        "none".to_string()
    } else {
        row.classes.iter().map(|(class, count)| format!("{class} {count}")).collect::<Vec<_>>().join(", ")
    };
    match &row.result.report {
        Some(report) => format!(
            "| {} | tc-{} | {} | {} | {}/{} | {} | {:.1} | {:.1} | {} |",
            row.faults,
            row.engine,
            if row.reproduced { "yes" } else { "no" },
            classes,
            report.completed,
            row.result.issued,
            row.result.issued.saturating_sub(report.completed),
            report.latency.p50,
            report.latency.p99,
            row.result.connections
        ),
        None => format!(
            "| {} | tc-{} | {} | {} | no report ({}) | | | | {} |",
            row.faults,
            row.engine,
            if row.reproduced { "yes" } else { "no" },
            classes,
            row.result.error.clone().unwrap_or_default(),
            row.result.connections
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STALLED: &str = r#"{"app":"12.1","cellular":false,"code":0,"connection":[{"ago":40.5,"state":"connecting"},{"ago":40.1,"state":"online"},{"ago":30.0,"state":"connecting"},{"ago":29.0,"state":"online"},{"ago":19.5,"state":"connecting"},{"ago":18.0,"state":"online"}],"datacenter":2,"duration":61.2,"engine":"mtProtoKit","error":"","expected_bytes":0,"failure":"stalled","flood_wait":0,"hour":1759993200,"latency_p50":0.08,"latency_p90":0.2,"latency_samples":64,"in_flight":256,"layer":214,"method":"messages.getHistory","request_bytes":64,"retries":0,"role":"main","schema":1,"sequence":7,"server_errors":0,"since_online":0,"system":"macos-15.4.0","uptime":900,"via_proxy":false}"#;

    #[test]
    fn loads_every_container() {
        let line = STALLED;
        assert_eq!(load_records(line).len(), 1);
        assert_eq!(load_records(&format!("{line}\n{line}\n\n")).len(), 2);
        assert_eq!(load_records(&format!("[{line},{line},{line}]")).len(), 3);
        assert_eq!(
            load_records(&format!("{{\"schema\":1,\"report_id\":\"ab\",\"offset\":0,\"records\":[{line}]}}")).len(),
            1
        );
        assert_eq!(
            load_records(&format!(
                "[{{\"type\":\"network_telemetry_failures\",\"data\":{{\"records\":[{line},{line}]}}}}]"
            ))
            .len(),
            2
        );
        assert!(load_records("not json").is_empty());
    }

    #[test]
    fn parses_record_fields() {
        let record = &load_records(STALLED)[0];
        assert_eq!(record.failure, "stalled");
        assert_eq!(record.method, "messages.getHistory");
        assert_eq!(record.engine, "mtProtoKit");
        assert_eq!(record.cellular, Some(false));
        assert_eq!(record.connection.len(), 6);
        assert_eq!(record.connection[0], (40.5, "connecting".to_string()));
        assert_eq!(record.latency_p90, Some(0.2));
        assert_eq!(record.in_flight, Some(256));
    }

    #[test]
    fn derives_link_from_timeline() {
        let records = load_records(STALLED);
        let refs: Vec<&FailureRecord> = records.iter().collect();
        let history = link_history(&refs);
        assert_eq!(history.reconnect_interval.map(|value| (value * 10.0).round() / 10.0), Some(10.5));
        assert_eq!(history.connect_time.map(|value| (value * 10.0).round() / 10.0), Some(1.0));
        assert_eq!(history.down_at_failure, None);
        let profile = derive_profile("x", &refs, &history);
        assert_eq!(profile.latency, Duration::from_millis(40));
        assert_eq!(profile.jitter, Duration::from_millis(60));
        assert_eq!(profile.bandwidth, Some(2_500_000));
        let (min, max) = profile.reset_after.expect("resets");
        assert!((min.as_secs_f64() - 5.25).abs() < 0.01 && (max.as_secs_f64() - 15.75).abs() < 0.01);
        assert_eq!(profile.connect_delay, Duration::from_secs(1));
    }

    #[test]
    fn cellular_records_get_a_mobile_link_and_outages_follow_downtime() {
        let mut record = load_records(STALLED).remove(0);
        record.cellular = Some(true);
        record.since_online = Some(12.0);
        record.connection = vec![(14.0, "online".into()), (12.0, "connecting".into())];
        let cases = cases(&[record.clone(), record]);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].records, 2);
        assert_eq!(cases[0].profile.max_chunk, 1400);
        assert_eq!(cases[0].outage, Some((3.0, 12.0)));
        assert!(cases[0].profile.reset_after.is_none());
    }

    #[test]
    fn groups_by_class_role_and_method() {
        let base = load_records(STALLED).remove(0);
        let mut flood = base.clone();
        flood.failure = "flood".into();
        flood.code = 420;
        let mut media = base.clone();
        media.role = "media".into();
        media.method = "upload.getFile".into();
        media.expected_bytes = 524288;
        let all = cases(&[base.clone(), base.clone(), flood, media]);
        let names: Vec<&str> = all.iter().map(|case| case.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "replay/stalled/main/messages.getHistory",
                "replay/flood/main/messages.getHistory",
                "replay/stalled/media/upload.getFile"
            ]
        );
        assert!(all[1].candidates.iter().any(|faults| faults.contains(&(Fault::FloodWait, 0.05))));
        assert_eq!(all[0].concurrency, 256);
        let calls = scenario(&all[0], &[], 1, "/tmp/x.json");
        assert_eq!(calls.requests, 0, "calls run for a time, not a count");
        assert!(calls.duration >= 20.0);
        let media_scenario = scenario(&all[2], &[], 1, "/tmp/x.json");
        assert_eq!(media_scenario.workload, "tc-download");
        assert_eq!(media_scenario.files[0].size, 524288 * 4);
        assert_eq!(media_scenario.files[0].datacenter_id, cluster::MAIN_DC, "faults are injected on the main DC");
        assert!(media_scenario.env.iter().any(|(key, value)| key == "TC_BENCH_TELEMETRY" && value == "1"));
    }

    #[test]
    fn fault_candidates_run_without_the_measured_reconnects() {
        let mut record = load_records(STALLED).remove(0);
        record.since_online = Some(5.0);
        let case = cases(&[record]).remove(0);
        assert!(case.profile.reset_after.is_some());
        let network = scenario(&case, &[], 1, "/tmp/x.json");
        assert!(network.custom_profile.as_ref().is_some_and(|profile| profile.reset_after.is_some()));
        assert_eq!(network.outage, Some((3.0, 5.0)));
        let fault = scenario(&case, &[(Fault::RotateSalt, 0.01)], 1, "/tmp/x.json");
        assert!(fault.custom_profile.as_ref().is_some_and(|profile| profile.reset_after.is_none()));
        assert_eq!(fault.outage, None);
        assert_eq!(fault.custom_profile.as_ref().map(|profile| profile.latency), Some(case.profile.latency));
    }

    #[test]
    fn proxied_records_route_the_measured_link_through_the_proxy() {
        let mut record = load_records(STALLED).remove(0);
        record.via_proxy = true;
        let case = cases(&[record]).remove(0);
        let proxied = scenario(&case, &[], 1, "/tmp/x.json");
        assert_eq!(proxied.proxy, Some(ProxyKind::Socks5));
        assert_eq!(proxied.routes, vec![cluster::Route::Measured]);
    }

    #[test]
    fn records_of_an_online_user_replay_online() {
        let offline = load_records(STALLED).remove(0);
        assert_eq!(offline.user_online, None);
        let online = load_records(&STALLED.replace("\"uptime\"", "\"user_online\":true,\"uptime\"")).remove(0);
        assert_eq!(online.user_online, Some(true));
        let flag = |records: &[FailureRecord]| {
            scenario(&cases(records).remove(0), &[], 1, "/tmp/x.json")
                .env
                .iter()
                .any(|(key, value)| key == "TC_BENCH_ONLINE" && value == "1")
        };
        assert!(flag(&[online.clone(), online.clone(), offline.clone()]));
        assert!(!flag(&[online, offline.clone(), offline]));
    }

    #[test]
    fn a_case_says_why_the_engine_dropped_connections() {
        let first = STALLED.replace(
            "\"uptime\":900",
            "\"drops\":[{\"ago\":9.0,\"reason\":\"probe_timeout\",\"answered\":true,\"age\":30.0},{\"ago\":4.0,\"reason\":\"racer_won\",\"answered\":false,\"age\":2.0}],\"uptime\":900",
        );
        let later = STALLED.replace(
            "\"uptime\":900",
            "\"drops\":[{\"ago\":14.5,\"reason\":\"probe_timeout\",\"answered\":true,\"age\":30.0},{\"ago\":1.0,\"reason\":\"probe_timeout\",\"answered\":true,\"age\":12.0}],\"uptime\":905",
        );
        let records = load_records(&format!("[{first},{later}]"));
        assert_eq!(
            records[0].drops[1],
            RecordedDrop { ago: 4.0, reason: "racer_won".into(), answered: false, age: 2.0 }
        );
        let case = cases(&records).remove(0);
        assert_eq!(case.drops, vec![("probe_timeout".into(), 2), ("racer_won (unanswered)".into(), 1)]);
        assert!(describe(&case).contains("engine dropped connections: probe_timeout ×2, racer_won (unanswered) ×1"));
        let together = STALLED.replace(
            "\"uptime\":900",
            "\"drops\":[{\"ago\":3.0,\"reason\":\"connect_timeout\",\"answered\":false,\"age\":10.001},{\"ago\":3.0,\"reason\":\"connect_timeout\",\"answered\":false,\"age\":10.001}],\"uptime\":900",
        );
        let case = cases(&load_records(&together)).remove(0);
        assert_eq!(case.drops, vec![("connect_timeout (unanswered)".into(), 2)], "two sessions cut together");
    }

    #[test]
    fn uploads_replay_as_uploads() {
        let mut record = load_records(STALLED).remove(0);
        record.role = "media".into();
        record.method = "upload.saveBigFilePart".into();
        let case = cases(&[record]).remove(0);
        let upload = scenario(&case, &[], 1, "/tmp/x.json");
        assert_eq!(upload.workload, "tc-upload");
        assert!(upload.files.iter().all(|file| file.datacenter_id == cluster::MAIN_DC));
        assert!(upload.files.iter().all(|file| file.size >= BIG_UPLOAD_MIN), "a fast link replays real big parts");
        let mut slow = case.clone();
        slow.profile.bandwidth = Some(8_000);
        let slow = scenario(&slow, &[], 1, "/tmp/x.json");
        assert!(
            slow.env.iter().any(|(key, value)| key == "TC_BENCH_UPLOAD_LARGE_PARTS" && value == "1"),
            "a slow link replays 256 KB parts"
        );
        assert!(slow.files.iter().all(|file| file.size >= LARGE_UPLOAD && file.size <= SMALL_UPLOAD_MAX));
        let mut small = case.clone();
        small.method = "upload.saveFilePart".into();
        let small = scenario(&small, &[], 1, "/tmp/x.json");
        assert!(small.files.iter().all(|file| file.size <= 512 * 1024));
    }

    #[test]
    fn transfers_keep_the_measured_link_busy_for_the_whole_run() {
        let mut record = load_records(STALLED).remove(0);
        record.role = "media".into();
        record.method = "upload.getFile".into();
        record.expected_bytes = 131072;
        let case = cases(&[record]).remove(0);
        let download = scenario(&case, &[], 1, "/tmp/x.json");
        let seconds = run_seconds(&case, 20.0);
        let bytes: u64 = download.files.iter().map(|file| file.size).sum();
        let rate = case.profile.bandwidth.expect("measured") as f64;
        assert!(
            bytes as f64 >= (rate * seconds).min(64.0 * 512.0 * 1024.0),
            "{bytes} bytes for {seconds} s at {rate} B/s"
        );
        let mut upload = case.clone();
        upload.method = "upload.saveFilePart".into();
        let upload = scenario(&upload, &[], 1, "/tmp/x.json");
        assert!(upload.files.len() > 2, "{} uploads", upload.files.len());
    }

    #[test]
    fn connecting_through_updating_counts_as_connect_time_and_cdn_matches_media() {
        let mut record = load_records(STALLED).remove(0);
        record.connection = vec![
            (30.0, "online".into()),
            (20.0, "connecting".into()),
            (18.5, "updating".into()),
            (17.0, "online".into()),
            (10.0, "connecting".into()),
            (9.0, "updating".into()),
            (8.0, "online".into()),
        ];
        let history = link_history(&[&record]);
        let connect = history.connect_time.expect("both reconnects went through updating");
        assert!((1.0..=1.5).contains(&connect), "{connect}");
        record.role = "cdn".into();
        record.method = "upload.getCdnFile".into();
        let case = cases(&[record.clone()]).remove(0);
        let mut local = record;
        local.role = "media".into();
        assert!(reproduced(&case, &[local]));
    }

    #[test]
    fn status_blips_are_not_disconnects_and_one_offline_record_is_no_outage() {
        let mut record = load_records(STALLED).remove(0);
        record.connection = vec![
            (30.0, "online".into()),
            (29.999, "waiting_network".into()),
            (29.998, "connecting".into()),
            (29.997, "online".into()),
            (10.0, "waiting_network".into()),
            (9.999, "online".into()),
        ];
        let history = link_history(&[&record]);
        assert_eq!(history.reconnect_interval, None);
        let mut offline = load_records(STALLED).remove(0);
        offline.since_online = Some(25.0);
        let mut records = vec![offline];
        records.extend((0..19).map(|_| load_records(STALLED).remove(0)));
        assert_eq!(cases(&records)[0].outage, None);
    }

    #[test]
    fn timeouts_and_mixed_server_errors_get_every_candidate() {
        let mut timeout = load_records(STALLED).remove(0);
        timeout.failure = "server".into();
        timeout.code = 500;
        timeout.error = "read timeout".into();
        let mut internal = timeout.clone();
        internal.error = "INTERNAL".into();
        let case = cases(&[timeout, internal]).remove(0);
        assert!(case.candidates.contains(&vec![(Fault::Stall, 0.02)]));
        assert!(case.candidates.contains(&vec![(Fault::InternalError, 0.05)]));
    }

    #[test]
    fn a_damaged_jsonl_line_is_skipped() {
        let text = format!("{STALLED}\n{STALLED}\n{{\"failure\":\"sta\n");
        assert_eq!(load_records(&text).len(), 2);
    }

    #[test]
    fn semantic_errors_replay_only_the_network() {
        assert!(candidate_faults("client", 400, "PEER_ID_INVALID").is_empty());
        assert!(candidate_faults("auth", 401, "AUTH_KEY_UNREGISTERED").is_empty());
        assert_eq!(candidate_faults("server", -503, "Timeout").len(), 3);
        assert_eq!(candidate_faults("server", 500, "INTERNAL").len(), 1);
    }

    #[test]
    fn stalled_and_abandoned_count_as_each_other() {
        let base = load_records(STALLED).remove(0);
        let case = cases(std::slice::from_ref(&base)).remove(0);
        let mut local = base.clone();
        local.failure = "abandoned".into();
        assert!(reproduced(&case, &[local.clone()]));
        local.failure = "flood".into();
        assert!(!reproduced(&case, &[local]));
    }

    #[test]
    fn reported_rates_size_the_link_and_a_stalled_part_bounds_the_uplink() {
        let mut record = load_records(STALLED).remove(0);
        record.uplink_rate = Some(8192.0);
        record.downlink_rate = Some(65536.0);
        let case = cases(&[record.clone()]).remove(0);
        assert_eq!(case.profile.uplink, Some(5792), "the middle of the 4–8 KB/s bucket");
        assert_eq!(case.profile.bandwidth, Some(46340));

        let mut part = load_records(STALLED).remove(0);
        part.role = "media".into();
        part.method = "upload.saveFilePart".into();
        part.request_bytes = 524288;
        part.duration = 21.0;
        let case = cases(&[part]).remove(0);
        let uplink = case.profile.uplink.expect("bounded");
        assert!((12_000..13_000).contains(&uplink), "a 256 KB part stuck for 21 s: {uplink}");
        let upload = scenario(&case, &[], 1, "/tmp/x.json");
        assert!(
            upload.env.iter().any(|(key, value)| key == "TC_BENCH_UPLOAD_LARGE_PARTS" && value == "1"),
            "a large saveFilePart replays in large parts"
        );
        assert!(upload.stall_exit >= 150.0);
        let bytes: u64 = upload.files.iter().map(|file| file.size).sum();
        assert!(upload.deadline >= bytes as f64 / uplink as f64, "an engine that can finish has the time to");
    }
}
