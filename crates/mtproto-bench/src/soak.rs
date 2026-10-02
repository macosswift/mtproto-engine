use std::collections::HashMap;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
};
use mtproto_testserver::chaos::{ChaosConfig, Fault};
use mtproto_testserver::{ServerOptions, TestServer, call, parse_result, random_key};

struct Forwarder {
    sender: Mutex<Sender<(SessionHandle, EngineEvent)>>,
}

impl EngineCallbacks for Forwarder {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        if let Ok(sender) = self.sender.lock() {
            let _ = sender.send((session, event));
        }
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, _message: &str) {}
}

#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub minute: f64,
    pub rss_mb: f64,
    pub heap_mb: f64,
    pub threads: usize,
    pub descriptors: usize,
    pub completed: u64,
    pub outstanding: usize,
}

fn rss_mb() -> f64 {
    let output = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output();
    output
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse::<f64>().ok())
        .map_or(0.0, |kilobytes| kilobytes / 1024.0)
}

fn threads() -> usize {
    let output = std::process::Command::new("ps").args(["-M", "-p", &std::process::id().to_string()]).output();
    output.ok().map_or(0, |output| String::from_utf8_lossy(&output.stdout).lines().count().saturating_sub(1))
}

fn descriptors() -> usize {
    std::fs::read_dir("/dev/fd").map_or(0, |entries| entries.count())
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: 0x5a17, valid_since: now - 60.0, valid_until: now + 86_400.0 }]
}

type Outstanding = HashMap<u64, (Instant, u64)>;

struct Slot {
    handle: SessionHandle,
    role: SessionRole,
    outstanding: HashMap<u64, (Instant, u64)>,
}

pub fn serve() {
    use std::io::{BufRead, Write};
    let key = random_key(4242);
    let mut chaos = ChaosConfig::mixed(4242, 0.0002);
    chaos.faults.extend(Fault::HOSTILE.into_iter().map(|fault| (fault, 0.0001)));
    let server = TestServer::start(vec![key], ServerOptions { chaos: Some(chaos), ..ServerOptions::default() });
    println!("PORT {}", server.address.port());
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    while std::io::stdin().lock().read_line(&mut line).is_ok_and(|read| read > 0) {
        line.clear();
    }
    let (duplicates, injected) =
        server.with_stats(|stats| (stats.duplicate_executions, stats.chaos_injected.values().sum::<usize>()));
    println!("STATS {duplicates} {injected}");
    let _ = std::io::stdout().flush();
}

struct ServerProcess {
    child: std::process::Child,
    address: std::net::SocketAddr,
}

impl ServerProcess {
    fn spawn() -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
            .arg("serve")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("server process");
        let mut reader = std::io::BufReader::new(child.stdout.as_mut().expect("stdout"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("port line");
        let port: u16 = line.trim().strip_prefix("PORT ").and_then(|port| port.parse().ok()).expect("port");
        Self { child, address: std::net::SocketAddr::from(([127, 0, 0, 1], port)) }
    }

    fn finish(mut self) -> (usize, usize) {
        use std::io::Read;
        drop(self.child.stdin.take());
        let mut output = String::new();
        if let Some(stdout) = self.child.stdout.as_mut() {
            let _ = stdout.read_to_string(&mut output);
        }
        let _ = self.child.wait();
        let numbers: Vec<usize> = output
            .lines()
            .find_map(|line| line.strip_prefix("STATS "))
            .map(|rest| rest.split_whitespace().filter_map(|value| value.parse().ok()).collect())
            .unwrap_or_default();
        (numbers.first().copied().unwrap_or(usize::MAX), numbers.get(1).copied().unwrap_or(0))
    }
}

pub fn run(minutes: f64, out: Option<String>) {
    let key = random_key(4242);
    let server = ServerProcess::spawn();
    let (sender, receiver) = channel();
    let engine = Engine::new(
        EngineConfig { worker_threads: 2, ..EngineConfig::default() },
        Arc::new(Forwarder { sender: Mutex::new(sender) }),
    )
    .expect("engine");
    let setup = |role: SessionRole| {
        let mut setup = SessionSetup::new(
            2,
            role,
            vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
        );
        setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
        setup.keep_connected = matches!(role, SessionRole::Main);
        setup.idle_disconnect_after = (!matches!(role, SessionRole::Main)).then_some(5.0);
        setup
    };
    let roles = [
        SessionRole::Main,
        SessionRole::Worker { requires_auth_token: false },
        SessionRole::Worker { requires_auth_token: false },
        SessionRole::Cdn,
    ];
    let mut slots: Vec<Slot> = roles
        .iter()
        .map(|role| Slot { handle: engine.create_session(setup(*role)), role: *role, outstanding: HashMap::new() })
        .collect();
    let started = Instant::now();
    let end = started + Duration::from_secs_f64(minutes * 60.0);
    let mut next_id = 1u64;
    let mut completed = 0u64;
    let mut wrong = 0u64;
    let mut failed = 0u64;
    let mut slowest = 0f64;
    let mut samples = Vec::new();
    let mut next_sample = started;
    let mut next_network_flap = started + Duration::from_secs(30);
    let mut next_reset = started + Duration::from_secs(45);
    let mut next_churn = started + Duration::from_secs(60);
    let mut retired: Vec<(SessionHandle, Outstanding)> = Vec::new();
    let mut cursor = 0usize;
    while Instant::now() < end {
        for slot in slots.iter_mut() {
            let target = if matches!(slot.role, SessionRole::Main) { 24 } else { 8 };
            while slot.outstanding.len() < target {
                let id = next_id;
                next_id += 1;
                let payload = id.to_le_bytes();
                let tag = 100 + (id % 500) as u32;
                engine.send(
                    slot.handle,
                    RpcRequest {
                        id: RequestId(id),
                        body: call(tag, &payload),
                        flags: RequestFlags::default(),
                        invoke_after: None,
                    },
                );
                slot.outstanding.insert(id, (Instant::now(), u64::from(tag)));
            }
        }
        let deadline = Instant::now() + Duration::from_millis(50);
        while let Ok((handle, event)) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            let (id, body) = match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, body, .. }) => (id, Some(body)),
                EngineEvent::Rpc(RpcEvent::Failed { id, .. }) => (id, None),
                _ => continue,
            };
            let owner = slots
                .iter_mut()
                .map(|slot| (slot.handle, &mut slot.outstanding))
                .chain(retired.iter_mut().map(|(handle, outstanding)| (*handle, outstanding)))
                .find(|(owner, _)| *owner == handle);
            let Some((_, outstanding)) = owner else {
                continue;
            };
            let Some((sent_at, tag)) = outstanding.remove(&id.0) else {
                wrong += 1;
                continue;
            };
            slowest = slowest.max(sent_at.elapsed().as_secs_f64());
            match body {
                Some(body) => {
                    let valid = parse_result(&body).is_some_and(|(result_tag, payload)| {
                        u64::from(result_tag) == tag && payload == id.0.to_le_bytes()
                    });
                    if valid {
                        completed += 1;
                    } else {
                        wrong += 1;
                    }
                }
                None => failed += 1,
            }
        }
        retired.retain(|(handle, outstanding)| {
            if outstanding.is_empty() {
                engine.destroy_session(*handle);
                false
            } else {
                true
            }
        });
        let now = Instant::now();
        if now >= next_network_flap {
            engine.set_network_available(false);
            std::thread::sleep(Duration::from_millis(500 + (cursor as u64 % 3) * 700));
            engine.set_network_available(true);
            next_network_flap = now + Duration::from_secs(30);
        }
        if now >= next_reset {
            engine.reset_connections();
            next_reset = now + Duration::from_secs(45);
        }
        if now >= next_churn {
            cursor = (cursor % (slots.len() - 1)) + 1;
            let role = slots[cursor].role;
            let replacement = Slot { handle: engine.create_session(setup(role)), role, outstanding: HashMap::new() };
            let old = std::mem::replace(&mut slots[cursor], replacement);
            retired.push((old.handle, old.outstanding));
            next_churn = now + Duration::from_secs(60);
        }
        if now >= next_sample {
            let outstanding = slots.iter().map(|slot| slot.outstanding.len()).sum::<usize>()
                + retired.iter().map(|(_, outstanding)| outstanding.len()).sum::<usize>();
            let sample = Sample {
                minute: started.elapsed().as_secs_f64() / 60.0,
                rss_mb: rss_mb(),
                heap_mb: crate::heap::live_bytes() as f64 / (1024.0 * 1024.0),
                threads: threads(),
                descriptors: descriptors(),
                completed,
                outstanding,
            };
            eprintln!(
                "{:6.1} min  rss {:6.1} MB  heap {:6.2} MB  threads {:3}  fds {:3}  completed {:9}  outstanding {:4}  failed {}  wrong {}  slowest {:.1} s",
                sample.minute,
                sample.rss_mb,
                sample.heap_mb,
                sample.threads,
                sample.descriptors,
                sample.completed,
                sample.outstanding,
                failed,
                wrong,
                slowest
            );
            samples.push(sample);
            next_sample = now + Duration::from_secs(10);
        }
    }
    let drain = Instant::now() + Duration::from_secs(60);
    let mut remaining = usize::MAX;
    while Instant::now() < drain {
        if let Ok((handle, EngineEvent::Rpc(RpcEvent::Completed { id, .. }))) =
            receiver.recv_timeout(Duration::from_millis(100))
        {
            for slot in slots.iter_mut() {
                if slot.handle == handle && slot.outstanding.remove(&id.0).is_some() {
                    completed += 1;
                }
            }
            for (owner, outstanding) in retired.iter_mut() {
                if *owner == handle && outstanding.remove(&id.0).is_some() {
                    completed += 1;
                }
            }
        }
        remaining = slots.iter().map(|slot| slot.outstanding.len()).sum::<usize>()
            + retired.iter().map(|(_, outstanding)| outstanding.len()).sum::<usize>();
        if remaining == 0 {
            break;
        }
    }
    engine.shutdown();
    let (duplicates, injected) = server.finish();
    let baseline = samples.iter().find(|sample| sample.minute >= 1.0).or(samples.first()).copied();
    let last = samples.last().copied();
    let mut report = String::new();
    report.push_str("| Minutes | Requests completed | Wrong results | Failed | Never completed | Duplicate executions | Faults injected | Slowest s | RSS at 1 min MB | RSS at end MB | Live heap at 1 min MB | Live heap at end MB | Threads start/end | Descriptors start/end |\n");
    report.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    if let (Some(baseline), Some(last)) = (baseline, last) {
        report.push_str(&format!(
            "| {:.1} | {} | {} | {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.2} | {:.2} | {}/{} | {}/{} |\n",
            last.minute,
            completed,
            wrong,
            failed,
            remaining,
            duplicates,
            injected,
            slowest,
            baseline.rss_mb,
            last.rss_mb,
            baseline.heap_mb,
            last.heap_mb,
            baseline.threads,
            last.threads,
            baseline.descriptors,
            last.descriptors
        ));
    }
    println!("{report}");
    if let Some(path) = out {
        let mut series = String::from("minute,rss_mb,heap_mb,threads,descriptors,completed,outstanding\n");
        for sample in &samples {
            series.push_str(&format!(
                "{:.2},{:.1},{:.3},{},{},{},{}\n",
                sample.minute,
                sample.rss_mb,
                sample.heap_mb,
                sample.threads,
                sample.descriptors,
                sample.completed,
                sample.outstanding
            ));
        }
        std::fs::write(format!("{path}.md"), &report).expect("write report");
        std::fs::write(format!("{path}.csv"), series).expect("write series");
    }
}
