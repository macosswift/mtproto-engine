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

const MAIN_DC: i32 = 2;
const FILE_DC: i32 = 4;
const CDN_DC: i32 = 203;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Dead,
    Sim(&'static str),
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
}

#[derive(Debug, Clone)]
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

fn scenario(name: &str, workload: &str, profile: &str, files: Vec<FileSpec>, concurrency: usize) -> ClusterScenario {
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
    }
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
            scenario("killswitch/photos-lossy", "tc-download", "lossy", files(5, 20, MAIN_DC, 40_000, 400_000, false, 1_000), 8),
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
    let profile = Profile::by_name(&scenario.profile).unwrap_or_else(Profile::perfect);
    let mut sims: Vec<NetSim> = [&main_server, &file_server, &cdn_server]
        .iter()
        .enumerate()
        .map(|(index, server)| NetSim::start(server.address, profile.clone(), seed + index as u64).expect("netsim"))
        .collect();
    let route_address = |route: Route, sims: &mut Vec<NetSim>| -> String {
        match route {
            Route::Dead => format!("{{\"host\":\"{}\",\"port\":{}}}", DEAD_ADDRESS.0, DEAD_ADDRESS.1),
            Route::Sim(name) => {
                let profile = Profile::by_name(name).unwrap_or_else(Profile::perfect);
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

    let label = format!("tc-{engine}");
    let switch_times =
        scenario.switch_engine_at.iter().map(|time| time.to_string()).collect::<Vec<_>>().join(",");
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
                "server: packets {} bytes {} pings {} state_requests {} retransmissions {} in_container {} duplicate_msg_ids {} redelivered {} future_salts {} sessions {} bad_msgs {} chaos {:?} dripped {} packets {} bytes calls_per_packet {:?}",
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
