mod args;
mod client;
mod cluster;
mod heap;
mod json;
mod orchestrator;
mod report;
mod soak;

use args::ClientArgs;
use orchestrator::EngineBinary;

#[global_allocator]
static GLOBAL: heap::CountingAlloc = heap::CountingAlloc;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("client") => {
            let args = ClientArgs::parse(&arguments[2..]);
            let report = client::run(args);
            println!("{}", report.to_json());
        }
        Some("run") => {
            let mut mtprotokit: Option<String> = None;
            let mut suite_name = "quick".to_string();
            let mut include_real = false;
            let mut out: Option<String> = None;
            let mut only: Option<String> = None;
            let mut repeat = 1usize;
            let mut iter = arguments[2..].iter();
            while let Some(flag) = iter.next() {
                match flag.as_str() {
                    "--mtprotokit" => mtprotokit = iter.next().cloned(),
                    "--suite" => suite_name = iter.next().cloned().expect("suite"),
                    "--real" => include_real = true,
                    "--out" => out = iter.next().cloned(),
                    "--only" => only = iter.next().cloned(),
                    "--repeat" => repeat = iter.next().and_then(|v| v.parse().ok()).expect("repeat"),
                    other => panic!("unknown argument {other}"),
                }
            }
            let mut engines =
                vec![EngineBinary { label: "rust".into(), path: arguments[0].clone(), prefix: vec!["client".into()] }];
            if let Some(path) = mtprotokit {
                engines.push(EngineBinary { label: "mtprotokit".into(), path, prefix: Vec::new() });
            }
            let mut results = Vec::new();
            let scenarios = orchestrator::suite(&suite_name, include_real);
            for (index, scenario) in scenarios.iter().enumerate() {
                if let Some(filter) = &only
                    && !scenario.name.contains(filter.as_str())
                {
                    continue;
                }
                for round in 0..repeat {
                    for engine in &engines {
                        eprintln!(
                            "[{}/{}] {} — {} (round {})",
                            index + 1,
                            scenarios.len(),
                            scenario.name,
                            engine.label,
                            round + 1
                        );
                        let result = orchestrator::run(scenario, engine, 1000 + index as u64 * 7 + round as u64);
                        eprintln!(
                            "{}",
                            orchestrator::markdown(std::slice::from_ref(&result)).lines().nth(2).unwrap_or("")
                        );
                        results.push(result);
                    }
                }
            }
            let table = orchestrator::markdown(&results);
            println!("{table}");
            if let Some(path) = out {
                std::fs::write(format!("{path}.md"), &table).expect("write markdown");
                std::fs::write(format!("{path}.json"), orchestrator::json(&results)).expect("write json");
            }
        }
        Some("serve") => soak::serve(),
        Some("proxy") => {
            let mut profile = "perfect".to_string();
            let mut bind = "127.0.0.1:1080".to_string();
            let mut outage_every: Option<f64> = None;
            let mut outage_for = 8.0;
            let mut iter = arguments[2..].iter();
            while let Some(flag) = iter.next() {
                match flag.as_str() {
                    "--profile" => profile = iter.next().cloned().expect("profile"),
                    "--bind" => bind = iter.next().cloned().expect("bind"),
                    "--outage-every" => outage_every = iter.next().and_then(|v| v.parse().ok()),
                    "--outage-for" => outage_for = iter.next().and_then(|v| v.parse().ok()).expect("seconds"),
                    other => panic!("unknown argument {other}"),
                }
            }
            let sim = mtproto_netsim::NetSim::start_socks5(
                mtproto_netsim::Profile::by_name(&profile).expect("profile"),
                0x50c5,
                &bind,
            )
            .expect("proxy");
            eprintln!("SOCKS5 {} profile {profile}", sim.address);
            let started = std::time::Instant::now();
            let mut next_outage = outage_every.map(|every| started + std::time::Duration::from_secs_f64(every));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if let Some(at) = next_outage
                    && std::time::Instant::now() >= at
                {
                    sim.outage(std::time::Duration::from_secs_f64(outage_for));
                    next_outage = outage_every.map(|every| at + std::time::Duration::from_secs_f64(every));
                }
                if started.elapsed().as_secs().is_multiple_of(10) {
                    let stats = sim.stats();
                    eprintln!(
                        "{:6.0} s  conns {}  refused {}  resets {}  up {} KB  down {} KB",
                        started.elapsed().as_secs_f64(),
                        stats.connections,
                        stats.refused,
                        stats.resets,
                        stats.bytes_up / 1024,
                        stats.bytes_down / 1024
                    );
                }
            }
        }
        Some("soak") => {
            let mut minutes = 10.0;
            let mut out: Option<String> = None;
            let mut iter = arguments[2..].iter();
            while let Some(flag) = iter.next() {
                match flag.as_str() {
                    "--minutes" => minutes = iter.next().and_then(|v| v.parse().ok()).expect("minutes"),
                    "--out" => out = iter.next().cloned(),
                    other => panic!("unknown argument {other}"),
                }
            }
            soak::run(minutes, out);
        }
        Some("tc") => {
            let mut binary: Option<String> = None;
            let mut quick = true;
            let mut torture = false;
            let mut resilience = false;
            let mut jobs = 1usize;
            let mut out: Option<String> = None;
            let mut only: Option<String> = None;
            let mut repeat = 1usize;
            let mut hostile = false;
            let mut killswitch = false;
            let mut engines = vec!["rust".to_string(), "mtprotokit".to_string()];
            let mut iter = arguments[2..].iter();
            while let Some(flag) = iter.next() {
                match flag.as_str() {
                    "--telegramcore" => binary = iter.next().cloned(),
                    "--suite" => {
                        let name = iter.next().cloned().unwrap_or_default();
                        hostile = name.starts_with("hostile");
                        killswitch = name == "killswitch";
                        torture = name.starts_with("torture") || hostile || killswitch;
                        resilience = name == "resilience";
                        quick = if torture { name.ends_with("quick") } else { !name.ends_with("full") };
                    }
                    "--jobs" => jobs = iter.next().and_then(|v| v.parse().ok()).expect("jobs"),
                    "--out" => out = iter.next().cloned(),
                    "--only" => only = iter.next().cloned(),
                    "--repeat" => repeat = iter.next().and_then(|v| v.parse().ok()).expect("repeat"),
                    "--engines" => {
                        engines = iter.next().expect("engines").split(',').map(str::to_string).collect();
                    }
                    other => panic!("unknown argument {other}"),
                }
            }
            let binary = binary.expect("--telegramcore PATH");
            let scenarios = if resilience {
                cluster::resilience_suite()
            } else if killswitch {
                cluster::killswitch_suite()
            } else if hostile {
                cluster::hostile_suite(quick)
            } else if torture {
                cluster::torture_suite(quick)
            } else {
                cluster::suite(quick)
            };
            let render = |results: &[cluster::ClusterResult]| {
                if resilience {
                    cluster::resilience_markdown(results)
                } else if torture {
                    cluster::torture_markdown(results)
                } else {
                    cluster::markdown(results)
                }
            };
            let mut work = Vec::new();
            for (index, scenario) in scenarios.iter().enumerate() {
                if let Some(filter) = &only
                    && !scenario.name.contains(filter.as_str())
                {
                    continue;
                }
                for round in 0..repeat {
                    for engine in &engines {
                        work.push((work.len(), index, round, scenario.clone(), engine.clone()));
                    }
                }
            }
            let total = scenarios.len();
            let queue = std::sync::Mutex::new(work.into_iter());
            let collected = std::sync::Mutex::new(Vec::new());
            std::thread::scope(|scope| {
                for _ in 0..jobs.max(1) {
                    scope.spawn(|| {
                        loop {
                            let next = queue.lock().unwrap().next();
                            let Some((order, index, round, scenario, engine)) = next else {
                                break;
                            };
                            eprintln!(
                                "[{}/{}] {} — tc-{} (round {})",
                                index + 1,
                                total,
                                scenario.name,
                                engine,
                                round + 1
                            );
                            let result =
                                cluster::run(&scenario, &binary, &engine, 5000 + index as u64 * 11 + round as u64);
                            let row = render(std::slice::from_ref(&result));
                            eprintln!("{}", row.lines().nth(2).unwrap_or(""));
                            collected.lock().unwrap().push((order, result));
                        }
                    });
                }
            });
            let mut collected = collected.into_inner().unwrap();
            collected.sort_by_key(|(order, _)| *order);
            let results: Vec<cluster::ClusterResult> = collected.into_iter().map(|(_, result)| result).collect();
            let table = render(&results);
            println!("{table}");
            if let Some(path) = out {
                std::fs::write(format!("{path}.md"), &table).expect("write markdown");
            }
        }
        _ => {
            eprintln!(
                "usage: mtproto-bench client <args> | mtproto-bench tc --telegramcore PATH [--suite quick|full] [--only NAME] [--repeat N] [--engines rust,mtprotokit] [--out PREFIX] | mtproto-bench run [--mtprotokit PATH] [--suite quick|full] [--real] [--only NAME] [--repeat N] [--out PREFIX]"
            );
            std::process::exit(2);
        }
    }
}
