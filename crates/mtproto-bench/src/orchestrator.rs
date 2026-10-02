use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mtproto_netsim::{NetSim, Profile};
use mtproto_testserver::{SERVER_SALT, ServerOptions, TestServer, random_key};

use crate::args::{ClientArgs, hex};
use crate::report::ClientReport;

#[derive(Debug, Clone)]
pub struct EngineBinary {
    pub label: String,
    pub path: String,
    pub prefix: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub args: ClientArgs,
    pub profile: String,
    pub secret: Option<String>,
    pub outage: Option<(f64, f64)>,
    pub real_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub scenario: String,
    pub engine: String,
    pub report: Option<ClientReport>,
    pub issued: usize,
    pub cpu_seconds: f64,
    pub max_rss_mb: f64,
    pub server_executions: Option<usize>,
    pub connections: u64,
    pub recovery: Option<f64>,
    pub longest_gap: f64,
    pub error: Option<String>,
}

fn base(workload: &str) -> ClientArgs {
    ClientArgs { workload: workload.into(), ..ClientArgs::default() }
}

fn scenario(name: &str, args: ClientArgs, profile: &str) -> Scenario {
    Scenario { name: name.into(), args, profile: profile.into(), secret: None, outage: None, real_address: None }
}

const FAKE_TLS_SECRET: &str = "ee3131313131313131313131313131313177772e6578616d706c652e636f6d";

pub fn suite(name: &str, include_real: bool) -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    let quick = name == "quick";
    let scale = |full: u64, quick_value: u64| if quick { quick_value } else { full };

    scenarios.push(scenario(
        "latency/perfect",
        ClientArgs { requests: scale(1000, 200) as usize, ..base("latency") },
        "perfect",
    ));
    scenarios.push(scenario(
        "small-pipelined/perfect",
        ClientArgs { requests: scale(20_000, 3000) as usize, concurrency: 128, ..base("small") },
        "perfect",
    ));
    scenarios.push(scenario(
        "media/perfect",
        ClientArgs { total_bytes: scale(512, 128) * 1024 * 1024, ..base("media") },
        "perfect",
    ));
    scenarios.push(scenario(
        "mixed/perfect",
        ClientArgs { total_bytes: scale(256, 96) * 1024 * 1024, rate: 20.0, ..base("mixed") },
        "perfect",
    ));
    scenarios.push(scenario(
        "media/broadband",
        ClientArgs { total_bytes: scale(48, 16) * 1024 * 1024, ..base("media") },
        "broadband",
    ));
    scenarios.push(scenario(
        "mixed/3g",
        ClientArgs {
            total_bytes: scale(4, 2) * 1024 * 1024,
            part_size: 128 * 1024,
            rate: 4.0,
            deadline: 180.0,
            ..base("mixed")
        },
        "3g",
    ));
    scenarios.push(scenario(
        "mixed/lossy",
        ClientArgs {
            total_bytes: scale(16, 6) * 1024 * 1024,
            part_size: 256 * 1024,
            rate: 10.0,
            deadline: 180.0,
            ..base("mixed")
        },
        "lossy",
    ));
    scenarios.push(scenario(
        "steady/flaky",
        ClientArgs { rate: 10.0, duration: scale(30, 15) as f64, deadline: 120.0, ..base("steady") },
        "flaky",
    ));
    scenarios.push(scenario(
        "media/flaky",
        ClientArgs { total_bytes: scale(32, 12) * 1024 * 1024, deadline: 180.0, ..base("media") },
        "flaky",
    ));
    scenarios.push(scenario(
        "steady/blackholes",
        ClientArgs { rate: 10.0, duration: scale(30, 15) as f64, deadline: 180.0, ..base("steady") },
        "blackholes",
    ));
    let mut outage = scenario(
        "steady/outage-8s",
        ClientArgs { rate: 10.0, duration: 20.0, deadline: 90.0, ..base("steady") },
        "perfect",
    );
    outage.outage = Some((5.0, 8.0));
    scenarios.push(outage);
    let mut proxy_media = scenario(
        "media/fake-tls-proxy",
        ClientArgs { total_bytes: scale(256, 64) * 1024 * 1024, ..base("media") },
        "perfect",
    );
    proxy_media.secret = Some(FAKE_TLS_SECRET.into());
    scenarios.push(proxy_media);
    let mut proxy_flaky = scenario(
        "steady/fake-tls-proxy-flaky",
        ClientArgs { rate: 10.0, duration: scale(30, 15) as f64, deadline: 120.0, ..base("steady") },
        "flaky",
    );
    proxy_flaky.secret = Some(FAKE_TLS_SECRET.into());
    scenarios.push(proxy_flaky);

    if !quick {
        scenarios.push(scenario(
            "media/many-sessions",
            ClientArgs {
                total_bytes: 64 * 1024 * 1024,
                part_size: 64 * 1024,
                sessions: 32,
                session_concurrency: 2,
                ..base("media")
            },
            "perfect",
        ));
        scenarios.push(scenario(
            "soak/flaky-120s",
            ClientArgs { rate: 20.0, duration: 120.0, deadline: 240.0, ..base("steady") },
            "flaky",
        ));
    }

    if include_real {
        for (profile, requests) in [("perfect", 12), ("3g", 12), ("flaky", 40)] {
            let mut real = scenario(
                &format!("real-config/{profile}"),
                ClientArgs { mode: "real".into(), requests, concurrency: 2, deadline: 120.0, ..base("real-config") },
                profile,
            );
            real.real_address = Some("149.154.167.51:443".into());
            scenarios.push(real);
        }
    }
    scenarios
}

#[allow(unsafe_code)]
fn wait_with_usage(pid: u32) -> (f64, f64) {
    let mut status = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::wait4(pid as i32, &mut status, 0, &mut usage) };
    let cpu = usage.ru_utime.tv_sec as f64
        + usage.ru_utime.tv_usec as f64 * 1e-6
        + usage.ru_stime.tv_sec as f64
        + usage.ru_stime.tv_usec as f64 * 1e-6;
    (cpu, usage.ru_maxrss as f64 / (1024.0 * 1024.0))
}

pub fn run(scenario: &Scenario, engine: &EngineBinary, seed: u64) -> RunResult {
    let key = random_key(seed);
    let server = if scenario.real_address.is_none() {
        Some(TestServer::start(
            vec![key.clone()],
            ServerOptions { secret: scenario.secret.as_deref().map(crate::args::unhex), ..ServerOptions::default() },
        ))
    } else {
        None
    };
    let upstream: SocketAddr = match (&server, &scenario.real_address) {
        (Some(server), _) => server.address,
        (None, Some(address)) => address.parse().expect("address"),
        (None, None) => unreachable!(),
    };
    let profile = Profile::by_name(&scenario.profile).unwrap_or_else(Profile::perfect);
    let sim = NetSim::start(upstream, profile, seed).expect("netsim");
    let mut args = scenario.args.clone();
    args.engine_label = engine.label.clone();
    args.address = sim.address.to_string();
    args.secret = scenario.secret.clone();
    if server.is_some() {
        args.key_hex = Some(hex(key.bytes()));
        args.salt = SERVER_SALT;
    }
    let started = Instant::now();
    let mut child = match Command::new(&engine.path)
        .args(&engine.prefix)
        .args(args.to_arguments())
        .stdout(Stdio::piped())
        .stderr(if std::env::var_os("BENCH_STDERR").is_some() { Stdio::inherit() } else { Stdio::null() })
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return RunResult {
                scenario: scenario.name.clone(),
                engine: engine.label.clone(),
                report: None,
                issued: 0,
                cpu_seconds: 0.0,
                max_rss_mb: 0.0,
                server_executions: None,
                connections: 0,
                recovery: None,
                longest_gap: 0.0,
                error: Some(error.to_string()),
            };
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
        sim.outage(Duration::from_secs_f64(duration));
    }
    let (cpu_seconds, max_rss_mb) = wait_with_usage(child.id());
    let output = reader.join().unwrap_or_default();
    let report = output.lines().rev().find(|line| line.starts_with('{')).and_then(ClientReport::from_json);
    let server_executions = server.as_ref().map(|server| server.with_stats(|stats| stats.executions.values().sum()));
    let issued = report.as_ref().map(|report| report.requests.len()).unwrap_or(0);
    let (recovery, longest_gap) =
        report.as_ref().map(|report| recovery_metrics(report, scenario.outage)).unwrap_or((None, 0.0));
    RunResult {
        scenario: scenario.name.clone(),
        engine: engine.label.clone(),
        error: if report.is_none() { Some("no report".into()) } else { None },
        report,
        issued,
        cpu_seconds,
        max_rss_mb,
        server_executions,
        connections: sim.stats().connections,
        recovery,
        longest_gap,
    }
}

fn recovery_metrics(report: &ClientReport, outage: Option<(f64, f64)>) -> (Option<f64>, f64) {
    let mut completions: Vec<f64> = report.requests.iter().filter_map(|(_, done)| *done).collect();
    completions.sort_by(f64::total_cmp);
    let longest_gap = completions.windows(2).map(|w| w[1] - w[0]).fold(0.0, f64::max);
    let recovery = outage.and_then(|(at, duration)| {
        let end = at + duration;
        completions.iter().find(|done| **done > end).map(|done| done - end)
    });
    (recovery, longest_gap)
}

fn format_option(value: Option<f64>, precision: usize) -> String {
    value.map(|v| format!("{v:.precision$}")).unwrap_or_else(|| "-".into())
}

pub fn markdown(results: &[RunResult]) -> String {
    let mut out = String::new();
    out.push_str("| Scenario | Engine | Done/Issued | Failed | p50 ms | p99 ms | max ms | MB/s | CPU s | Peak RSS MB | Server exec | Dup | Conns | Longest gap s | Recovery s |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for result in results {
        let Some(report) = &result.report else {
            out.push_str(&format!(
                "| {} | {} | error: {} |  |  |  |  |  |  |  |  |  |  |  |  |\n",
                result.scenario,
                result.engine,
                result.error.clone().unwrap_or_default()
            ));
            continue;
        };
        let duplicates = result
            .server_executions
            .map(|executions| executions.saturating_sub(result.issued).to_string())
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "| {} | {} | {}/{} | {} | {:.2} | {:.2} | {:.1} | {:.1} | {:.2} | {:.1} | {} | {} | {} | {:.2} | {} |\n",
            result.scenario,
            result.engine,
            report.completed,
            result.issued,
            report.failed,
            report.latency.p50,
            report.latency.p99,
            report.latency.max,
            report.throughput_mbps,
            result.cpu_seconds,
            result.max_rss_mb,
            result.server_executions.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            duplicates,
            result.connections,
            result.longest_gap,
            format_option(result.recovery, 2),
        ));
    }
    out
}

pub fn json(results: &[RunResult]) -> String {
    let rows: Vec<String> = results
        .iter()
        .map(|result| {
            format!(
                "{{\"scenario\":\"{}\",\"engine\":\"{}\",\"issued\":{},\"cpu_seconds\":{:.4},\"max_rss_mb\":{:.2},\"server_executions\":{},\"connections\":{},\"longest_gap\":{:.4},\"recovery\":{},\"report\":{}}}",
                result.scenario,
                result.engine,
                result.issued,
                result.cpu_seconds,
                result.max_rss_mb,
                result.server_executions.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                result.connections,
                result.longest_gap,
                result.recovery.map(|v| format!("{v:.4}")).unwrap_or_else(|| "null".into()),
                result.report.as_ref().map(|r| r.to_json()).unwrap_or_else(|| "null".into())
            )
        })
        .collect();
    format!("[{}]", rows.join(",\n"))
}
