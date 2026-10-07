use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::crypto::{SecureRandom, XorShiftRandom};
use mtproto_netsim::{NetSim, Profile};
use mtproto_testserver::api::{ApiWorld, CdnFault, FileSpec, WorldOptions};
use mtproto_testserver::chaos::{ChaosConfig, Fault};
use mtproto_testserver::{SERVER_SALT, ServerOptions, TestServer, random_key};

use crate::args::hex;
use crate::report::ClientReport;

pub const MAIN_DC: i32 = 2;
const FILE_DC: i32 = 4;
const CDN_DC: i32 = 203;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Dead,
    Sim(&'static str),
    /// The scenario's `custom_profile`.
    Measured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    FakeTls,
    Socks5,
}

const FAKE_TLS_SECRET: &str = "ee3131313131313131313131313131313177772e6578616d706c652e636f6d";
const DEAD_ADDRESS: (&str, u16) = ("192.0.2.1", 443);

#[derive(Debug, Clone)]
pub struct ClusterScenario {
    pub name: String,
    pub workload: String,
    pub profile: String,
    pub files: Vec<FileSpec>,
    pub reupload: bool,
    pub cdn_fault: CdnFault,
    pub concurrency: usize,
    pub requests: usize,
    pub rate: f64,
    pub deadline: f64,
    pub cancel_fraction: f64,
    pub outage: Option<(f64, f64)>,
    pub chaos: Option<ChaosConfig>,
    pub stall_exit: f64,
    pub routes: Vec<Route>,
    pub inject: Option<(f64, Vec<Route>)>,
    pub proxy: Option<ProxyKind>,
    pub duration: f64,
    pub switch_engine_at: Vec<f64>,
    /// Replaces the named `profile` on every simulated link.
    pub custom_profile: Option<Profile>,
    /// Extra environment for the client process.
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct ClusterResult {
    pub scenario: String,
    pub engine: String,
    pub report: Option<ClientReport>,
    pub verify_failures: usize,
    pub cancellations: usize,
    pub cpu_seconds: f64,
    pub max_rss_mb: f64,
    pub connections: u64,
    pub useful_bytes: u64,
    pub served_bytes: u64,
    pub part_requests: usize,
    pub repeated_parts: usize,
    pub imports: usize,
    pub reuploads: usize,
    pub redirects: usize,
    pub invalid_ranges: usize,
    pub longest_gap: f64,
    pub recovery: Option<f64>,
    pub issued: usize,
    pub double_completions: usize,
    pub duplicate_executions: usize,
    pub chaos_injected: usize,
    pub client_packets: usize,
    pub client_bytes: usize,
    pub loop_rejections: usize,
    pub stalled: bool,
    pub engine_switched: bool,
    pub upload_parts: usize,
    /// Upload parts the server received more than once.
    pub upload_duplicates: usize,
    /// Upload parts with wrong bytes or in the wrong place.
    pub upload_bad_parts: usize,
    /// Uploads the client reported done that the server does not hold completely.
    pub upload_incomplete: usize,
    /// The largest upload part the server received.
    pub upload_largest_part: usize,
    /// Failure records the client's `NetworkTelemetry` wrote, by class, when the run dumped them.
    pub telemetry: Vec<(String, usize)>,
    /// Connections the engine gave up on, by `role/reason`, when the run dumped its telemetry.
    pub drops: Vec<(String, usize)>,
    pub exit: String,
    pub error: Option<String>,
}

fn files(seed: u64, count: usize, datacenter_id: i32, min: u64, max: u64, cdn: bool, first_id: i64) -> Vec<FileSpec> {
    let mut rng = XorShiftRandom::new(seed);
    (0..count)
        .map(|index| FileSpec {
            id: first_id + index as i64,
            datacenter_id,
            size: min + rng.next_u64() % (max - min + 1),
            cdn,
        })
        .collect()
}

pub fn scenario(
    name: &str,
    workload: &str,
    profile: &str,
    files: Vec<FileSpec>,
    concurrency: usize,
) -> ClusterScenario {
    ClusterScenario {
        name: name.into(),
        workload: workload.into(),
        profile: profile.into(),
        files,
        reupload: true,
        cdn_fault: CdnFault::None,
        concurrency,
        requests: 0,
        rate: 20.0,
        deadline: 180.0,
        cancel_fraction: 0.0,
        outage: None,
        chaos: None,
        stall_exit: 0.0,
        routes: Vec::new(),
        inject: None,
        proxy: None,
        duration: 10.0,
        switch_engine_at: Vec::new(),
        custom_profile: None,
        env: Vec::new(),
    }
}

/// Weak and slow networks as users meet them, each with small calls, calls during downloads and
/// during an upload, downloads and uploads sized to the link so that every run moves for a
/// comparable time, an upload in 256 KB parts, which take most of a minute each on the slowest
/// links, two such uploads sharing the uplink, and calls and downloads after pauses longer than a
/// carrier NAT remembers an idle connection. Profiles are (name, downlink bytes/s, uplink
/// bytes/s, round trip s); small uploads go in 16 KB parts three at a time, so they are bound by the
/// round trip as much as by the uplink.
pub fn weak_suite(quick: bool) -> Vec<ClusterScenario> {
    let profiles: [(&'static str, u64, u64, f64); 12] = [
        ("gprs", 6_000, 6_000, 1.0),
        ("edge", 8_000, 8_000, 0.9),
        ("edge-flaky", 8_000, 8_000, 0.9),
        ("3g", 187_500, 187_500, 0.3),
        ("satellite", 500_000, 500_000, 0.6),
        ("lossy-heavy", 250_000, 250_000, 0.2),
        ("train", 125_000, 125_000, 0.24),
        ("handover", 1_250_000, 1_250_000, 0.08),
        ("uplink-starved", 1_000_000, 8_000, 0.12),
        ("blackholes", 1_250_000, 1_250_000, 0.08),
        ("bufferbloat", 500_000, 32_000, 0.08),
        ("bufferbloat-down", 125_000, 64_000, 0.08),
    ];
    let seconds = if quick { 12.0 } else { 30.0 };
    let mut scenarios = Vec::new();
    for (index, (profile, down, up, rtt)) in profiles.into_iter().enumerate() {
        let index = index as u64;
        let mut rpc = scenario(&format!("weak/{profile}/rpc"), "tc-steady", profile, Vec::new(), 8);
        rpc.rate = 4.0;
        rpc.duration =
            Profile::by_name(profile).map_or(seconds, |profile| seconds.max(longest_quiet_spell(&profile) + 4.0));
        rpc.deadline = rpc.duration + 150.0;
        rpc.stall_exit = 45.0;
        scenarios.push(online(&rpc));
        scenarios.push(rpc);

        let photo = (down * 2).clamp(16_000, 1_500_000);
        let count = if quick { 4 } else { 10 };
        let mut loaded = scenario(
            &format!("weak/{profile}/rpc-under-load"),
            "tc-mixed",
            profile,
            files(200 + index, count, MAIN_DC, photo / 2, photo, false, 60_000 + index as i64 * 100),
            2,
        );
        loaded.rate = 4.0;
        loaded.deadline = 300.0;
        loaded.stall_exit = 60.0;
        scenarios.push(online(&loaded));
        scenarios.push(loaded);

        let mut photos = scenario(
            &format!("weak/{profile}/photos"),
            "tc-download",
            profile,
            files(300 + index, count, MAIN_DC, photo / 2, photo, false, 70_000 + index as i64 * 100),
            4,
        );
        photos.deadline = 300.0;
        photos.stall_exit = 60.0;
        scenarios.push(photos);

        let upload_rate = (up as f64).min(3.0 * 16_384.0 / rtt);
        let upload_size = ((upload_rate * if quick { 8.0 } else { 20.0 }) as u64).clamp(64 * 1024, 4 * 1024 * 1024);
        let uploads = (0..2)
            .map(|file| FileSpec {
                id: 80_000 + index as i64 * 10 + file,
                datacenter_id: MAIN_DC,
                size: upload_size,
                cdn: false,
            })
            .collect();
        let mut upload = scenario(&format!("weak/{profile}/upload"), "tc-upload", profile, uploads, 1);
        upload.deadline = 300.0;
        upload.stall_exit = 60.0;
        scenarios.push(upload);

        let sending =
            vec![FileSpec { id: 82_000 + index as i64, datacenter_id: MAIN_DC, size: upload_size, cdn: false }];
        let mut chatting =
            scenario(&format!("weak/{profile}/rpc-during-upload"), "tc-mixed-upload", profile, sending, 1);
        chatting.rate = 2.0;
        chatting.deadline = 300.0;
        chatting.stall_exit = 60.0;
        scenarios.push(online(&chatting));
        scenarios.push(chatting);

        let large =
            vec![FileSpec { id: 85_000 + index as i64, datacenter_id: MAIN_DC, size: LARGE_UPLOAD, cdn: false }];
        let mut large_upload = scenario(&format!("weak/{profile}/large-parts"), "tc-upload", profile, large, 1);
        large_upload.deadline = 420.0;
        large_upload.stall_exit = 150.0;
        large_upload.env = vec![("TC_BENCH_UPLOAD_LARGE_PARTS".into(), "1".into())];
        scenarios.push(large_upload);

        let shared = (0..2)
            .map(|file| FileSpec {
                id: 86_000 + index as i64 * 10 + file,
                datacenter_id: MAIN_DC,
                size: LARGE_UPLOAD / 2,
                cdn: false,
            })
            .collect();
        let mut shared_upload = scenario(&format!("weak/{profile}/shared-uplink"), "tc-upload", profile, shared, 2);
        shared_upload.deadline = 420.0;
        shared_upload.stall_exit = 150.0;
        shared_upload.env = vec![("TC_BENCH_UPLOAD_LARGE_PARTS".into(), "1".into())];
        scenarios.push(shared_upload);
    }
    let pauses = files(400, if quick { 6 } else { 10 }, MAIN_DC, 32_000, 64_000, false, 90_000);
    let mut after_pauses = scenario("weak/nat/after-pauses", "tc-idle", "nat", pauses, 1);
    after_pauses.rate = 1.0 / 45.0;
    after_pauses.duration = if quick { 240.0 } else { 420.0 };
    after_pauses.deadline = after_pauses.duration + 120.0;
    after_pauses.stall_exit = 90.0;
    scenarios.push(after_pauses);
    scenarios
}

/// The same run with the user online, as while the app is in front: the main session then pings
/// every round trip and gives up on silence after a few, where an offline one waits minutes.
fn online(scenario: &ClusterScenario) -> ClusterScenario {
    let mut online = scenario.clone();
    online.name = format!("{}-online", scenario.name);
    online.env.push(("TC_BENCH_ONLINE".into(), "1".into()));
    online
}

/// Two 256 KB parts and a tail.
const LARGE_UPLOAD: u64 = 2 * 256 * 1024 + 4096;
/// The smallest part a large-part upload must have sent.
const LARGE_PART_MIN: usize = 128 * 1024;

/// How long a run must last for every periodic event of the profile to have struck at least once.
pub fn longest_quiet_spell(profile: &Profile) -> f64 {
    let tunnel = profile.tunnel.map_or(0.0, |tunnel| (tunnel.every_max + tunnel.length).as_secs_f64());
    let reset = profile.reset_after.map_or(0.0, |(_, latest)| latest.as_secs_f64());
    let blackhole = profile.blackhole.map_or(0.0, |blackhole| (blackhole.after_max + blackhole.duration).as_secs_f64());
    tunnel.max(reset).max(blackhole)
}

pub fn weak_markdown(results: &[ClusterResult]) -> String {
    let mut out = String::new();
    out.push_str("| Scenario | Engine | Done/Issued | Failed or hung | Bad data | p50 ms | p95 ms | p99 ms | KB/s | Re-sent parts | Conns | Longest gap s | CPU s | Telemetry | Process |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for result in results {
        let mut telemetry = if result.telemetry.is_empty() {
            "none".to_string()
        } else {
            result.telemetry.iter().map(|(class, count)| format!("{class} {count}")).collect::<Vec<_>>().join(", ")
        };
        if !result.drops.is_empty() {
            telemetry.push_str("; drops ");
            telemetry.push_str(
                &result.drops.iter().map(|(reason, count)| format!("{reason} {count}")).collect::<Vec<_>>().join(", "),
            );
        }
        let Some(report) = &result.report else {
            out.push_str(&format!(
                "| {} | {} | no report ({}) | | | | | | | | {} | | {:.1} | {} | {} |\n",
                result.scenario,
                result.engine,
                result.error.clone().unwrap_or_default(),
                result.connections,
                result.cpu_seconds,
                telemetry,
                result.exit
            ));
            continue;
        };
        let rate = report.transfer_rate() / 1024.0;
        out.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {:.0} | {:.0} | {:.0} | {:.1} | {} | {} | {:.1} | {:.1} | {} | {} |\n",
            result.scenario,
            result.engine,
            report.completed,
            result.issued,
            report.failed + result.issued.saturating_sub(report.completed + report.failed),
            result.verify_failures + result.upload_bad_parts + result.upload_incomplete,
            report.latency.p50,
            report.latency.p95,
            report.latency.p99,
            rate,
            result.upload_duplicates + result.repeated_parts,
            result.connections,
            result.longest_gap,
            result.cpu_seconds,
            telemetry,
            result.exit
        ));
    }
    out
}

/// Fewer latency samples per run make a p95 little more than the slowest one or two.
const P95_SAMPLES_MIN: f64 = 20.0;

/// Where the Rust engine did worse than MtProtoKit on the same scenario: more failed or hung
/// requests, any bad data, more failure records with as many failed requests, a p95 latency 25%
/// and 100 ms worse when both had `P95_SAMPLES_MIN` calls a run, 20% less throughput, or half as
/// much CPU again and a second more, which is what a worker spinning on a timer looks like. Averages
/// over rounds.
pub fn weak_spots(results: &[ClusterResult]) -> String {
    #[derive(Default)]
    struct Totals {
        runs: f64,
        reporting: f64,
        completed: f64,
        /// Completed calls. In runs that mix calls and files the p95 is over the calls only; a run of
        /// files alone has none, and its p95 is not compared.
        samples: f64,
        failed: f64,
        bad: f64,
        p95: f64,
        rate: f64,
        records: f64,
        cpu: f64,
    }
    let mut by_scenario: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Totals>> =
        std::collections::BTreeMap::new();
    for result in results {
        let totals = by_scenario.entry(result.scenario.clone()).or_default().entry(result.engine.clone()).or_default();
        totals.runs += 1.0;
        totals.cpu += result.cpu_seconds;
        totals.bad += (result.verify_failures + result.upload_bad_parts + result.upload_incomplete) as f64;
        totals.records +=
            result.telemetry.iter().filter(|(class, _)| class != "client").map(|(_, count)| *count as f64).sum::<f64>();
        match &result.report {
            Some(report) => {
                totals.reporting += 1.0;
                totals.completed += report.completed as f64;
                totals.samples += report.completed.saturating_sub(report.transfers_done.unwrap_or(0)) as f64;
                totals.failed +=
                    (report.failed + result.issued.saturating_sub(report.completed + report.failed)) as f64;
                totals.p95 += report.latency.p95;
                totals.rate += report.transfer_rate();
            }
            None => totals.failed += result.issued.max(1) as f64,
        }
    }
    let mut worse = Vec::new();
    let mut better = 0;
    let mut compared = 0;
    for (scenario, engines) in &by_scenario {
        let (Some(rust), Some(baseline)) = (engines.get("tc-rust"), engines.get("tc-mtprotokit")) else {
            continue;
        };
        compared += 1;
        let average = |totals: &Totals, value: f64| value / totals.runs.max(1.0);
        let mut reasons = Vec::new();
        if average(rust, rust.failed) > average(baseline, baseline.failed) {
            reasons.push(format!(
                "failed or hung {:.1} vs {:.1}",
                average(rust, rust.failed),
                average(baseline, baseline.failed)
            ));
        }
        if rust.bad > 0.0 {
            reasons.push(format!("bad data {:.0}", rust.bad));
        }
        if average(rust, rust.failed) == average(baseline, baseline.failed)
            && average(rust, rust.records) > average(baseline, baseline.records)
        {
            reasons.push(format!(
                "failure records {:.1} vs {:.1}",
                average(rust, rust.records),
                average(baseline, baseline.records)
            ));
        }
        let reported = |totals: &Totals, value: f64| value / totals.reporting.max(1.0);
        let (rust_p95, baseline_p95) = (reported(rust, rust.p95), reported(baseline, baseline.p95));
        if reported(baseline, baseline.samples) >= P95_SAMPLES_MIN
            && reported(rust, rust.samples) >= P95_SAMPLES_MIN
            && rust_p95 > baseline_p95 * 1.25
            && rust_p95 - baseline_p95 > 100.0
        {
            reasons.push(format!("p95 {rust_p95:.0} ms vs {baseline_p95:.0} ms"));
        }
        let (rust_rate, baseline_rate) = (reported(rust, rust.rate), reported(baseline, baseline.rate));
        if baseline_rate > 0.0 && rust_rate < baseline_rate * 0.8 {
            reasons.push(format!("throughput {:.1} vs {:.1} KB/s", rust_rate / 1024.0, baseline_rate / 1024.0));
        }
        let (rust_cpu, baseline_cpu) = (average(rust, rust.cpu), average(baseline, baseline.cpu));
        if rust_cpu > baseline_cpu * 1.5 && rust_cpu - baseline_cpu > 1.0 {
            reasons.push(format!("CPU {rust_cpu:.1} s vs {baseline_cpu:.1} s"));
        }
        if reasons.is_empty() {
            better += 1;
        } else {
            worse.push(format!("- `{scenario}`: {}", reasons.join("; ")));
        }
    }
    let mut out = format!(
        "\n### Weak spots: Rust worse than MtProtoKit in {} of {compared} scenarios ({better} not worse)\n\n",
        worse.len()
    );
    for line in worse {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

pub fn resilience_suite() -> Vec<ClusterScenario> {
    let steady = |name: &str, profile: &str, routes: Vec<Route>| {
        let mut scenario = scenario(name, "tc-steady", profile, Vec::new(), 8);
        scenario.rate = 10.0;
        scenario.duration = 20.0;
        scenario.deadline = 120.0;
        scenario.stall_exit = 60.0;
        scenario.routes = routes;
        scenario
    };
    let mut scenarios = vec![
        steady("resilience/edge", "edge", vec![Route::Sim("edge")]),
        steady("resilience/edge-flaky", "edge-flaky", vec![Route::Sim("edge-flaky")]),
        steady("resilience/route-syn-drop-first", "perfect", vec![Route::Sim("perfect"), Route::Dead]),
        steady("resilience/route-dpi-reset-first", "perfect", vec![Route::Sim("perfect"), Route::Sim("dpi-reset")]),
        steady(
            "resilience/route-dpi-blackhole-first",
            "perfect",
            vec![Route::Sim("perfect"), Route::Sim("dpi-blackhole")],
        ),
        steady("resilience/route-dpi-half", "perfect", vec![Route::Sim("dpi-half")]),
        steady(
            "resilience/route-only-last-works",
            "perfect",
            vec![Route::Sim("perfect"), Route::Sim("dpi-reset"), Route::Sim("dpi-blackhole"), Route::Dead],
        ),
    ];
    let mut backup = steady("resilience/backup-arrives-5s", "perfect", vec![Route::Sim("dpi-blackhole")]);
    backup.inject = Some((5.0, vec![Route::Sim("perfect"), Route::Sim("dpi-blackhole")]));
    scenarios.push(backup);
    let mut backlog = steady("resilience/backlog-outage-20s", "perfect", vec![Route::Sim("perfect")]);
    backlog.rate = 20.0;
    backlog.duration = 30.0;
    backlog.outage = Some((3.0, 20.0));
    scenarios.push(backlog);
    for (name, kind, profile) in [
        ("resilience/proxy-tls-flaky", ProxyKind::FakeTls, "flaky"),
        ("resilience/proxy-tls-edge", ProxyKind::FakeTls, "edge"),
        ("resilience/proxy-tls-dpi-half", ProxyKind::FakeTls, "dpi-half"),
        ("resilience/proxy-socks5-flaky", ProxyKind::Socks5, "flaky"),
    ] {
        let mut proxied = steady(name, profile, vec![Route::Sim(profile)]);
        proxied.proxy = Some(kind);
        scenarios.push(proxied);
    }
    let mut edge_download = scenario(
        "resilience/edge-photos",
        "tc-download",
        "edge",
        files(31, 4, MAIN_DC, 60_000, 200_000, false, 4_000),
        2,
    );
    edge_download.routes = vec![Route::Sim("edge")];
    edge_download.deadline = 240.0;
    scenarios.push(edge_download);
    scenarios
}

pub fn torture_suite(quick: bool) -> Vec<ClusterScenario> {
    let scale = |full: usize, quick_value: usize| if quick { quick_value } else { full };
    let torture = |name: &str, profile: &str, requests: usize, chaos: Option<ChaosConfig>| {
        let mut scenario = scenario(name, "tc-torture", profile, Vec::new(), 256);
        scenario.requests = requests;
        scenario.deadline = if quick { 120.0 } else { 900.0 };
        scenario.stall_exit = if quick { 10.0 } else { 120.0 };
        scenario.chaos = chaos;
        scenario
    };
    let mut scenarios = Vec::new();
    for fault in Fault::ALL {
        let requests = if fault == Fault::ExpireSalt { scale(500_000, 30_000) } else { scale(50_000, 3_000) };
        scenarios.push(torture(
            &format!("torture/{}", fault.name()),
            "perfect",
            requests,
            Some(ChaosConfig::only(17, fault, 0.01)),
        ));
    }
    scenarios.push(torture(
        "torture/all-faults",
        "perfect",
        scale(1_000_000, 30_000),
        Some(ChaosConfig::mixed(23, 0.0005)),
    ));
    scenarios.push(torture(
        "torture/all-faults-flaky",
        "flaky",
        scale(100_000, 5_000),
        Some(ChaosConfig::mixed(29, 0.0005)),
    ));
    for (index, fault) in Fault::ADAPTIVE.into_iter().enumerate() {
        let mut chaos = ChaosConfig::only(31 + index as u64, fault, 0.01);
        match fault {
            Fault::AdaptiveReconnectAmbush => chaos.faults = vec![(fault, 0.3)],
            Fault::AdaptiveKillOnRetransmit => {
                chaos.faults =
                    vec![(fault, 0.5), (Fault::DropAfterExecution, 0.002), (Fault::DropBeforeExecution, 0.002)]
            }
            _ => {}
        }
        scenarios.push(torture(&format!("torture/{}", fault.name()), "perfect", scale(50_000, 3_000), Some(chaos)));
    }
    let mut trickle = torture(
        "torture/a-trickle",
        "perfect",
        scale(10_000, 2_000),
        Some(ChaosConfig::only(37, Fault::AdaptiveTrickle, 0.002)),
    );
    trickle.deadline = if quick { 300.0 } else { 1800.0 };
    trickle.stall_exit = 60.0;
    scenarios.push(trickle);
    scenarios.push(torture(
        "torture/apocalypse",
        "flaky",
        scale(100_000, 5_000),
        Some(ChaosConfig::apocalypse(41, 0.001, false)),
    ));
    scenarios.push(torture(
        "torture/apocalypse-hostile",
        "flaky",
        scale(100_000, 5_000),
        Some(ChaosConfig::apocalypse(43, 0.0005, true)),
    ));
    if !quick {
        scenarios.push(torture("torture/million-clean", "perfect", 1_000_000, None));
    }
    scenarios
}

pub fn killswitch_suite() -> Vec<ClusterScenario> {
    let switched = |mut scenario: ClusterScenario, at: &[f64]| {
        scenario.switch_engine_at = at.to_vec();
        scenario.deadline = 120.0;
        scenario.stall_exit = 20.0;
        scenario
    };
    let mut burst = scenario("killswitch/burst", "tc-torture", "perfect", Vec::new(), 256);
    burst.requests = 50_000;
    let mut faults = scenario("killswitch/faults-flaky", "tc-torture", "flaky", Vec::new(), 256);
    faults.requests = 5_000;
    faults.chaos = Some(ChaosConfig::mixed(29, 0.0005));
    let mut outage = scenario(
        "killswitch/during-outage",
        "tc-mixed",
        "broadband",
        files(9, 300, MAIN_DC, 40_000, 400_000, false, 1_000),
        8,
    );
    outage.outage = Some((3.0, 6.0));
    outage.rate = 10.0;
    let big = |name: &str, seed: u64, cdn: bool| {
        scenario(name, "tc-download", "wan", files(seed, 2, FILE_DC, 40 << 20, 80 << 20, cdn, 4_000), 1)
    };
    let mut flap_burst = scenario("killswitch/flap-burst", "tc-torture", "perfect", Vec::new(), 256);
    flap_burst.requests = 50_000;
    let mut flap_faults = scenario("killswitch/flap-faults-flaky", "tc-torture", "flaky", Vec::new(), 256);
    flap_faults.requests = 5_000;
    flap_faults.chaos = Some(ChaosConfig::mixed(31, 0.0005));
    vec![
        switched(burst, &[0.15]),
        switched(faults, &[2.0]),
        switched(big("killswitch/bigfile-wan", 14, false), &[1.5]),
        switched(big("killswitch/bigfile-cdn-wan", 15, true), &[1.5]),
        switched(
            scenario(
                "killswitch/photos-lossy",
                "tc-download",
                "lossy",
                files(5, 20, MAIN_DC, 40_000, 400_000, false, 1_000),
                8,
            ),
            &[1.0],
        ),
        switched(outage, &[5.0]),
        switched(flap_burst, &[0.1, 0.2, 0.3, 0.4, 0.5, 0.6]),
        switched(flap_faults, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]),
    ]
}

pub fn hostile_suite(quick: bool) -> Vec<ClusterScenario> {
    let scale = |full: usize, quick_value: usize| if quick { quick_value } else { full };
    let hostile = |name: String, requests: usize, chaos: ChaosConfig| {
        let mut scenario = scenario(&name, "tc-torture", "perfect", Vec::new(), 64);
        scenario.requests = requests;
        scenario.deadline = if quick { 120.0 } else { 600.0 };
        scenario.stall_exit = if quick { 15.0 } else { 60.0 };
        scenario.chaos = Some(chaos);
        scenario
    };
    let mut scenarios: Vec<ClusterScenario> = Fault::HOSTILE
        .into_iter()
        .enumerate()
        .map(|(index, fault)| {
            hostile(
                format!("hostile/{}", fault.name()),
                scale(20_000, 2_000),
                ChaosConfig::only(41 + index as u64, fault, 0.005),
            )
        })
        .collect();
    scenarios.push(hostile("hostile/all".into(), scale(100_000, 10_000), ChaosConfig::hostile(97, 0.0005)));
    for (index, fault) in Fault::LOOPS.into_iter().enumerate() {
        let mut scenario = hostile(
            format!("loop/{}", fault.name()),
            scale(2_000, 400),
            ChaosConfig::only(71 + index as u64, fault, 0.005),
        );
        scenario.deadline = 60.0;
        scenario.stall_exit = 30.0;
        scenarios.push(scenario);
    }
    scenarios
}

pub fn suite(quick: bool) -> Vec<ClusterScenario> {
    let scale = |full: usize, quick_value: usize| if quick { quick_value } else { full };
    let photos = |seed: u64, count: usize| files(seed, count, MAIN_DC, 40_000, 400_000, false, 1_000);
    let videos = |seed: u64, count: usize| files(seed, count, FILE_DC, 4 << 20, 16 << 20, false, 2_000);
    let cdn_videos = |seed: u64, count: usize| files(seed, count, FILE_DC, 3 << 20, 10 << 20, true, 3_000);
    let big_files = |seed: u64, count: usize, cdn: bool| files(seed, count, FILE_DC, 40 << 20, 80 << 20, cdn, 4_000);
    let mut mixed_files = photos(11, scale(40, 20));
    mixed_files.extend(videos(12, scale(3, 2)));
    mixed_files.extend(cdn_videos(13, scale(2, 1)));

    let mut scenarios = vec![
        scenario("tc/photos/perfect", "tc-download", "perfect", photos(1, scale(2000, 600)), 8),
        scenario("tc/videos-dc4/perfect", "tc-download", "perfect", videos(2, scale(8, 4)), 3),
        scenario("tc/cdn/perfect", "tc-download", "perfect", cdn_videos(3, scale(6, 3)), 3),
        scenario("tc/mixed/broadband", "tc-mixed", "broadband", mixed_files.clone(), 8),
        scenario("tc/mixed/3g", "tc-mixed", "3g", photos(4, scale(16, 8)), 4),
        scenario("tc/photos/lossy", "tc-download", "lossy", photos(5, scale(40, 20)), 8),
        scenario("tc/videos-dc4/flaky", "tc-download", "flaky", videos(6, scale(3, 2)), 3),
        scenario("tc/cdn/flaky", "tc-download", "flaky", cdn_videos(7, scale(3, 2)), 3),
        scenario("tc/bigfile/wan", "tc-download", "wan", big_files(14, scale(3, 2), false), 1),
        scenario("tc/bigfile-cdn/wan", "tc-download", "wan", big_files(15, scale(3, 2), true), 1),
        scenario("tc/mixed/blackholes", "tc-mixed", "blackholes", mixed_files.clone(), 8),
    ];
    for (index, fault) in CdnFault::ALL.into_iter().enumerate() {
        let mut hostile_cdn = scenario(
            &format!("tc/cdn-hostile/{}", fault.name()),
            "tc-download",
            "broadband",
            cdn_videos(20 + index as u64, 2),
            2,
        );
        hostile_cdn.cdn_fault = fault;
        hostile_cdn.deadline = 60.0;
        scenarios.push(hostile_cdn);
    }
    let mut scroll = scenario("tc/scroll/broadband", "tc-scroll", "broadband", photos(8, scale(200, 100)), 12);
    scroll.cancel_fraction = 0.5;
    scenarios.push(scroll);
    let mut outage = scenario("tc/mixed/outage-6s", "tc-mixed", "broadband", photos(9, 300), 8);
    outage.outage = Some((3.0, 6.0));
    outage.rate = 10.0;
    scenarios.push(outage);
    let mut small = scenario("tc/small/perfect", "tc-small", "perfect", Vec::new(), 64);
    small.requests = scale(50_000, 10_000);
    scenarios.push(small);
    scenarios
}

fn key_object(keys: &[(&str, &mtproto_engine::mtproto_core::auth_key::AuthKey)]) -> String {
    let entries: Vec<String> = keys.iter().map(|(name, key)| format!("\"{name}\":\"{}\"", hex(key.bytes()))).collect();
    format!("{{{}}}", entries.join(","))
}

#[allow(unsafe_code)]
fn wait_with_usage(pid: u32) -> (f64, f64, String) {
    let mut status = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::wait4(pid as i32, &mut status, 0, &mut usage) };
    let cpu = usage.ru_utime.tv_sec as f64
        + usage.ru_utime.tv_usec as f64 * 1e-6
        + usage.ru_stime.tv_sec as f64
        + usage.ru_stime.tv_usec as f64 * 1e-6;
    let exit = if libc::WIFSIGNALED(status) {
        format!("signal {}", libc::WTERMSIG(status))
    } else {
        format!("exit {}", libc::WEXITSTATUS(status))
    };
    (cpu, usage.ru_maxrss as f64 / (1024.0 * 1024.0), exit)
}

fn extra_number(output: &str, field: &str) -> usize {
    let needle = format!("\"{field}\":");
    output
        .rfind(&needle)
        .and_then(|start| {
            let rest = &output[start + needle.len()..];
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse().ok()
        })
        .unwrap_or(0)
}

pub fn run(scenario: &ClusterScenario, binary: &str, engine: &str, seed: u64) -> ClusterResult {
    let world = Arc::new(ApiWorld::new(
        WorldOptions {
            main_datacenter_id: MAIN_DC,
            cdn_datacenter_id: CDN_DC,
            reupload_needed: scenario.reupload,
            cdn_fault: scenario.cdn_fault,
            ..WorldOptions::default()
        },
        &scenario.files,
        seed,
    ));
    let main_keys = [random_key(seed * 10 + 1), random_key(seed * 10 + 2), random_key(seed * 10 + 3)];
    let file_keys = [random_key(seed * 10 + 4), random_key(seed * 10 + 5), random_key(seed * 10 + 6)];
    let cdn_key = random_key(seed * 10 + 7);
    for key in &main_keys {
        world.register_key(key.id(), 0xa2);
    }
    for key in &file_keys {
        world.register_key(key.id(), 0xa4);
    }
    world.register_key(cdn_key.id(), 0xcd);
    let start_server = |datacenter_id: i32, keys: Vec<mtproto_engine::mtproto_core::auth_key::AuthKey>| {
        TestServer::start(
            keys,
            ServerOptions {
                datacenter_id,
                api: Some(world.clone()),
                chaos: scenario.chaos.clone().filter(|_| datacenter_id == MAIN_DC),
                secret: (datacenter_id == MAIN_DC && scenario.proxy == Some(ProxyKind::FakeTls))
                    .then(|| crate::args::unhex(FAKE_TLS_SECRET)),
                socks5: datacenter_id == MAIN_DC && scenario.proxy == Some(ProxyKind::Socks5),
                validate_msg_id_time: true,
                ..ServerOptions::default()
            },
        )
    };
    let main_server = start_server(MAIN_DC, main_keys.to_vec());
    let file_server = start_server(FILE_DC, file_keys.to_vec());
    let cdn_server = start_server(CDN_DC, vec![cdn_key.clone()]);
    let profile = scenario
        .custom_profile
        .clone()
        .unwrap_or_else(|| Profile::by_name(&scenario.profile).unwrap_or_else(Profile::perfect));
    let mut sims: Vec<NetSim> = [&main_server, &file_server, &cdn_server]
        .iter()
        .enumerate()
        .map(|(index, server)| NetSim::start(server.address, profile.clone(), seed + index as u64).expect("netsim"))
        .collect();
    let route_address = |route: Route, sims: &mut Vec<NetSim>| -> String {
        match route {
            Route::Dead => format!("{{\"host\":\"{}\",\"port\":{}}}", DEAD_ADDRESS.0, DEAD_ADDRESS.1),
            Route::Sim(_) | Route::Measured => {
                let profile = match route {
                    Route::Sim(name) => Profile::by_name(name).unwrap_or_else(Profile::perfect),
                    _ => profile.clone(),
                };
                let sim = NetSim::start(main_server.address, profile, seed + 100 + sims.len() as u64).expect("netsim");
                let address = format!("{{\"host\":\"{}\",\"port\":{}}}", sim.address.ip(), sim.address.port());
                sims.push(sim);
                address
            }
        }
    };
    let main_routes: Option<Vec<String>> = (!scenario.routes.is_empty())
        .then(|| scenario.routes.iter().map(|route| route_address(*route, &mut sims)).collect());
    let inject = scenario.inject.as_ref().map(|(after, routes)| {
        let addresses: Vec<String> = routes.iter().map(|route| route_address(*route, &mut sims)).collect();
        format!("[{{\"dc\":{MAIN_DC},\"after\":{after},\"addresses\":[{}]}}]", addresses.join(","))
    });
    let proxy = scenario.proxy.map(|kind| {
        let sim = sims.last().expect("proxy route");
        let (name, secret) = match kind {
            ProxyKind::FakeTls => ("mtp", FAKE_TLS_SECRET),
            ProxyKind::Socks5 => ("socks5", ""),
        };
        format!(
            "{{\"kind\":\"{name}\",\"host\":\"{}\",\"port\":{},\"secret\":\"{secret}\"}}",
            sim.address.ip(),
            sim.address.port()
        )
    });

    let datacenter = |id: i32, sim: &NetSim, cdn: bool, keys: String| {
        let addresses = match (&main_routes, id == MAIN_DC) {
            (Some(routes), true) => routes.join(","),
            _ => format!("{{\"host\":\"{}\",\"port\":{}}}", sim.address.ip(), sim.address.port()),
        };
        format!("{{\"id\":{id},\"addresses\":[{addresses}],\"cdn\":{cdn},\"salt\":{SERVER_SALT},\"keys\":{keys}}}")
    };
    let datacenters = [
        datacenter(
            MAIN_DC,
            &sims[0],
            false,
            key_object(&[("persistent", &main_keys[0]), ("main", &main_keys[1]), ("media", &main_keys[2])]),
        ),
        datacenter(
            FILE_DC,
            &sims[1],
            false,
            key_object(&[("persistent", &file_keys[0]), ("main", &file_keys[1]), ("media", &file_keys[2])]),
        ),
        datacenter(CDN_DC, &sims[2], true, key_object(&[("persistent", &cdn_key)])),
    ];
    let files: Vec<String> = scenario
        .files
        .iter()
        .map(|file| {
            format!("{{\"id\":{},\"dc\":{},\"size\":{},\"cdn\":{}}}", file.id, file.datacenter_id, file.size, file.cdn)
        })
        .collect();
    let config = format!(
        "{{\"main_datacenter_id\":{MAIN_DC},\"datacenters\":[{}],\"files\":[{}],\"inject\":{},\"proxy\":{}}}",
        datacenters.join(","),
        files.join(","),
        inject.unwrap_or_else(|| "[]".into()),
        proxy.unwrap_or_else(|| "null".into())
    );
    let config_path = std::env::temp_dir().join(format!("tc-bench-{}-{seed}-{engine}.json", std::process::id()));
    std::fs::write(&config_path, config).expect("write config");

    if let Some((_, path)) = scenario.env.iter().find(|(key, _)| key == "TC_BENCH_TELEMETRY_DUMP") {
        let _ = std::fs::remove_file(path);
    }
    let label = format!("tc-{engine}");
    let switch_times = scenario.switch_engine_at.iter().map(|time| time.to_string()).collect::<Vec<_>>().join(",");
    let switch_times = if switch_times.is_empty() { "0".to_string() } else { switch_times };
    let started = Instant::now();
    let child = Command::new(binary)
        .args([
            "--config",
            config_path.to_str().expect("utf8 path"),
            "--engine",
            engine,
            "--engine-label",
            &label,
            "--workload",
            &scenario.workload,
            "--concurrency",
            &scenario.concurrency.to_string(),
            "--requests",
            &scenario.requests.to_string(),
            "--rate",
            &scenario.rate.to_string(),
            "--deadline",
            &std::env::var("TC_BENCH_DEADLINE").unwrap_or_else(|_| scenario.deadline.to_string()),
            "--cancel-fraction",
            &scenario.cancel_fraction.to_string(),
            "--seed",
            &seed.to_string(),
            "--trickle",
            &std::env::var("TC_BENCH_TRICKLE").unwrap_or_else(|_| "0".into()),
            "--stall-exit",
            &scenario.stall_exit.to_string(),
            "--duration",
            &scenario.duration.to_string(),
            "--switch-engine-at",
            &switch_times,
            "--switch-engine-to",
            "other",
        ])
        .envs(scenario.env.iter().map(|(key, value)| (key.as_str(), value.as_str())))
        .stdout(Stdio::piped())
        .stderr(if std::env::var_os("TC_BENCH_STDERR").is_some() { Stdio::inherit() } else { Stdio::null() })
        .spawn();
    let mut result = ClusterResult {
        scenario: scenario.name.clone(),
        engine: label,
        report: None,
        verify_failures: 0,
        cancellations: 0,
        cpu_seconds: 0.0,
        max_rss_mb: 0.0,
        connections: 0,
        useful_bytes: scenario.files.iter().map(|file| file.size).sum(),
        served_bytes: 0,
        part_requests: 0,
        repeated_parts: 0,
        imports: 0,
        reuploads: 0,
        redirects: 0,
        invalid_ranges: 0,
        longest_gap: 0.0,
        recovery: None,
        issued: 0,
        double_completions: 0,
        duplicate_executions: 0,
        chaos_injected: 0,
        client_packets: 0,
        client_bytes: 0,
        loop_rejections: 0,
        stalled: false,
        engine_switched: false,
        upload_parts: 0,
        upload_duplicates: 0,
        upload_bad_parts: 0,
        upload_incomplete: 0,
        upload_largest_part: 0,
        telemetry: Vec::new(),
        drops: Vec::new(),
        exit: String::new(),
        error: None,
    };
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            result.error = Some(error.to_string());
            return result;
        }
    };
    let mut stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    if let Some((at, duration)) = scenario.outage {
        let elapsed = started.elapsed().as_secs_f64();
        if at > elapsed {
            std::thread::sleep(Duration::from_secs_f64(at - elapsed));
        }
        for sim in &sims {
            sim.outage(Duration::from_secs_f64(duration));
        }
    }
    let (cpu_seconds, max_rss_mb, exit) = wait_with_usage(child.id());
    result.exit = exit;
    let output = reader.join().unwrap_or_default();
    if std::env::var_os("TC_BENCH_STDERR").is_some() {
        for line in output.lines().filter(|line| !line.starts_with('{')) {
            eprintln!("{line}");
        }
    }
    let _ = std::fs::remove_file(&config_path);
    let line = output.lines().rev().find(|line| line.starts_with('{')).unwrap_or("");
    result.report = ClientReport::from_json(line);
    result.verify_failures = extra_number(line, "verify_failures");
    result.cancellations = extra_number(line, "cancellations");
    result.double_completions = extra_number(line, "double_completions");
    result.stalled = extra_number(line, "stalled") == 1;
    result.engine_switched = extra_number(line, "engine_switched") == 1;
    result.issued = extra_number(line, "issued");
    main_server.with_stats(|stats| {
        result.duplicate_executions = stats.duplicate_executions;
        if std::env::var_os("TC_BENCH_DUPLICATES").is_some() {
            for record in &stats.duplicate_records {
                eprintln!("duplicate: {record}");
            }
        }
        if std::env::var_os("TC_BENCH_STATS").is_some() {
            eprintln!(
                "server: packets {} bytes {} pings {} state_requests {} retransmissions {} in_container {} duplicate_msg_ids {} redelivered {} future_salts {} sessions {} bad_msgs {} chaos {:?} dripped {} packets {} bytes calls_per_packet {:?} lone {:x?}",
                stats.client_packets,
                stats.client_bytes,
                stats.pings,
                stats.state_requests,
                stats.retransmissions,
                stats.retransmissions_in_container,
                stats.duplicate_msg_ids,
                stats.redelivered_answers,
                stats.future_salts_requests,
                stats.session_ids.len(),
                stats.bad_msgs_sent,
                stats.chaos_injected,
                stats.dripped_packets,
                stats.dripped_bytes,
                {
                    let mut histogram: Vec<_> = stats.calls_per_packet.iter().map(|(k, v)| (*k, *v)).collect();
                    histogram.sort();
                    histogram
                },
                {
                    let mut lone: Vec<_> = stats.lone_messages.iter().map(|(k, v)| (*k, *v)).collect();
                    lone.sort();
                    lone
                }
            );
        }
        result.chaos_injected = stats.chaos_injected.values().sum();
        result.client_packets = stats.client_packets;
        result.client_bytes = stats.client_bytes;
        result.loop_rejections = stats.loop_rejections;
    });
    result.cpu_seconds = cpu_seconds;
    result.max_rss_mb = max_rss_mb;
    result.connections = sims.iter().map(|sim| sim.stats().connections).sum();
    if std::env::var_os("TC_BENCH_STDERR").is_some() {
        let per_dc: Vec<u64> = sims.iter().map(|sim| sim.stats().connections).collect();
        eprintln!("connections per datacenter [main, file, cdn]: {per_dc:?}");
    }
    let stats = world.stats();
    result.served_bytes = stats.bytes_served;
    result.part_requests = stats.get_file + stats.get_cdn_file;
    result.repeated_parts =
        stats.file_requests.values().chain(stats.cdn_requests.values()).map(|count| count.saturating_sub(1)).sum();
    result.imports = stats.imports;
    result.reuploads = stats.reuploads;
    result.redirects = stats.cdn_redirects;
    result.invalid_ranges = stats.invalid_ranges;
    result.upload_parts = stats.upload_parts;
    result.upload_duplicates = stats.upload_duplicates;
    result.upload_bad_parts = stats.upload_bad_parts;
    result.upload_largest_part = stats.upload_largest_part;
    if scenario.env.iter().any(|(key, value)| key == "TC_BENCH_UPLOAD_LARGE_PARTS" && value == "1")
        && result.upload_largest_part < LARGE_PART_MIN
    {
        result.exit = format!("{} (parts of {} bytes at most)", result.exit, result.upload_largest_part);
    }
    if let Some((_, path)) = scenario.env.iter().find(|(key, _)| key == "TC_BENCH_TELEMETRY_DUMP") {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut classes: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        let counts = crate::json::parse(text.trim()).and_then(|value| match value.get("failure_counts") {
            Some(crate::json::Value::Object(entries)) => Some(entries.clone()),
            _ => None,
        });
        match counts {
            Some(entries) => {
                for (class, count) in entries {
                    classes.insert(class, count.as_f64().unwrap_or(0.0) as usize);
                }
            }
            None => {
                for record in crate::replay::load_records(&text) {
                    *classes.entry(record.failure).or_insert(0) += 1;
                }
            }
        }
        classes.retain(|_, count| *count > 0);
        result.telemetry = classes.into_iter().collect();
        if let Some(crate::json::Value::Object(entries)) =
            crate::json::parse(text.trim()).as_ref().and_then(|value| value.get("drop_counts"))
        {
            result.drops = entries
                .iter()
                .map(|(key, count)| (key.clone(), count.as_f64().unwrap_or(0.0) as usize))
                .filter(|(_, count)| *count > 0)
                .collect();
        }
    }
    if matches!(scenario.workload.as_str(), "tc-upload" | "tc-mixed-upload")
        && let Some(report) = &result.report
    {
        let uploaded = world.uploaded_files();
        let held = scenario
            .files
            .iter()
            .filter(|spec| {
                uploaded.iter().any(|file| file.complete && file.bytes == spec.size && file.tag == Some(spec.id as u64))
            })
            .count();
        result.upload_incomplete = report.transfers_done.unwrap_or(report.completed).saturating_sub(held);
    }
    if let Some(report) = &result.report
        && std::env::var_os("TC_BENCH_STATS").is_some()
    {
        let mut slowest: Vec<(f64, f64)> =
            report.requests.iter().filter_map(|(sent, done)| done.map(|done| (done - sent, *sent))).collect();
        slowest.sort_by(|lhs, rhs| rhs.0.total_cmp(&lhs.0));
        let slowest: Vec<String> =
            slowest.iter().take(6).map(|(took, sent)| format!("{:.0} ms at {sent:.2} s", took * 1000.0)).collect();
        eprintln!("slowest: {}", slowest.join(", "));
    }
    if let Some(report) = &result.report {
        let mut completions: Vec<f64> = report.requests.iter().filter_map(|(_, done)| *done).collect();
        completions.sort_by(f64::total_cmp);
        result.longest_gap = completions.windows(2).map(|w| w[1] - w[0]).fold(0.0, f64::max);
        result.recovery = scenario.outage.and_then(|(at, duration)| {
            completions.iter().find(|done| **done > at + duration).map(|done| done - at - duration)
        });
    } else {
        result.error = Some("no report".into());
    }
    drop(sims);
    drop(main_server);
    drop(file_server);
    drop(cdn_server);
    result
}

pub fn markdown(results: &[ClusterResult]) -> String {
    let mut out = String::new();
    out.push_str("| Scenario | Engine | Done/Issued | Failed | Bad data | p50 ms | p99 ms | MB/s | CPU s | Peak RSS MB | Served/needed | Part reqs | Re-fetched parts | Conns | Imports | Reuploads | Longest gap s | Recovery s |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for result in results {
        let Some(report) = &result.report else {
            out.push_str(&format!(
                "| {} | {} | error: {} |{}\n",
                result.scenario,
                result.engine,
                result.error.clone().unwrap_or_default(),
                " |".repeat(15)
            ));
            continue;
        };
        let amplification = if result.useful_bytes > 0 {
            format!("{:.2}", result.served_bytes as f64 / result.useful_bytes as f64)
        } else {
            "-".into()
        };
        out.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {:.1} | {:.1} | {:.1} | {:.2} | {:.1} | {} | {} | {} | {} | {} | {} | {:.2} | {} |\n",
            result.scenario,
            result.engine,
            report.completed,
            report.requests.len(),
            report.failed,
            result.verify_failures,
            report.latency.p50,
            report.latency.p99,
            report.throughput_mbps,
            result.cpu_seconds,
            result.max_rss_mb,
            amplification,
            result.part_requests,
            result.repeated_parts,
            result.connections,
            result.imports,
            result.reuploads,
            result.longest_gap,
            result.recovery.map(|v| format!("{v:.2}")).unwrap_or_else(|| "-".into()),
        ));
    }
    out
}

pub fn torture_markdown(results: &[ClusterResult]) -> String {
    let mut out = String::new();
    out.push_str("| Scenario | Engine | Done/Issued | Failed or hung | Wrong results | Double completions | Duplicate executions | Faults injected | p50 ms | p99 ms | req/s | CPU s | Peak RSS MB | Conns | Client packets | Client MB | Loop rejections | Process |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for result in results {
        let Some(report) = &result.report else {
            out.push_str(&format!(
                "| {} | {} | no report ({}) | | | | | {} | | | | {:.2} | {:.1} | {} | {} | {:.1} | {} | {} |\n",
                result.scenario,
                result.engine,
                result.error.clone().unwrap_or_default(),
                result.chaos_injected,
                result.cpu_seconds,
                result.max_rss_mb,
                result.connections,
                result.client_packets,
                result.client_bytes as f64 / 1e6,
                result.loop_rejections,
                result.exit
            ));
            continue;
        };
        let rate = if report.elapsed > 0.0 { report.completed as f64 / report.elapsed } else { 0.0 };
        out.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {} | {} | {} | {:.2} | {:.1} | {:.0} | {:.2} | {:.1} | {} | {} | {:.1} | {} | {} |\n",
            result.scenario,
            result.engine,
            report.completed,
            result.issued,
            result.issued.saturating_sub(report.completed),
            result.verify_failures,
            result.double_completions,
            result.duplicate_executions,
            result.chaos_injected,
            report.latency.p50,
            report.latency.p99,
            rate,
            result.cpu_seconds,
            result.max_rss_mb,
            result.connections,
            result.client_packets,
            result.client_bytes as f64 / 1e6,
            result.loop_rejections,
            match (result.stalled, result.engine_switched) {
                (true, true) => format!("{} (stalled, switched)", result.exit),
                (true, false) => format!("{} (stalled)", result.exit),
                (false, true) => format!("{} (switched)", result.exit),
                (false, false) => result.exit.clone(),
            },
        ));
    }
    out
}

pub fn resilience_markdown(results: &[ClusterResult]) -> String {
    let mut out = String::new();
    out.push_str("| Scenario | Engine | Done/Issued | Failed or hung | First reply s | p50 ms | p99 ms | Longest gap s | Recovery s | Duplicate executions | CPU s | Peak RSS MB | Conns | Process |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for result in results {
        let Some(report) = &result.report else {
            out.push_str(&format!(
                "| {} | {} | no report ({}) |{}\n",
                result.scenario,
                result.engine,
                result.error.clone().unwrap_or_default(),
                " |".repeat(11)
            ));
            continue;
        };
        let first = report.requests.iter().filter_map(|(_, done)| *done).fold(f64::INFINITY, f64::min);
        out.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {:.1} | {:.1} | {:.2} | {} | {} | {:.2} | {:.1} | {} | {} |\n",
            result.scenario,
            result.engine,
            report.completed,
            report.requests.len(),
            report.requests.len().saturating_sub(report.completed),
            if first.is_finite() { format!("{first:.2}") } else { "-".into() },
            report.latency.p50,
            report.latency.p99,
            result.longest_gap,
            result.recovery.map(|v| format!("{v:.2}")).unwrap_or_else(|| "-".into()),
            result.duplicate_executions,
            result.cpu_seconds,
            result.max_rss_mb,
            result.connections,
            if result.stalled { format!("{} (stalled)", result.exit) } else { result.exit.clone() },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(engine: &str, cpu_seconds: f64) -> ClusterResult {
        ClusterResult {
            scenario: "weak/edge/rpc".into(),
            engine: engine.into(),
            report: Some(ClientReport { completed: 40, elapsed: 30.0, ..ClientReport::default() }),
            issued: 40,
            cpu_seconds,
            ..ClusterResult::default()
        }
    }

    #[test]
    fn a_worker_spinning_on_a_timer_is_a_weak_spot() {
        let spinning = weak_spots(&[run("tc-rust", 6.0), run("tc-mtprotokit", 2.0)]);
        assert!(spinning.contains("CPU 6.0 s vs 2.0 s"), "{spinning}");
        let noise = weak_spots(&[run("tc-rust", 2.6), run("tc-mtprotokit", 2.0)]);
        assert!(noise.contains("in 0 of 1"), "{noise}");
    }

    #[test]
    fn weak_calls_last_until_every_periodic_event_has_struck() {
        for scenario in weak_suite(true).iter().filter(|scenario| scenario.workload == "tc-steady") {
            let profile = Profile::by_name(&scenario.profile).expect("profile");
            assert!(scenario.duration >= longest_quiet_spell(&profile), "{}", scenario.name);
            assert!(scenario.deadline > scenario.duration, "{}", scenario.name);
        }
        let train = weak_suite(true).into_iter().find(|scenario| scenario.name == "weak/train/rpc").expect("train");
        assert!(train.duration >= 26.0);
    }
}
