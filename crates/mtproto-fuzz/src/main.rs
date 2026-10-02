use std::time::Duration;

use mtproto_fuzz::alloc::{TrackingAlloc, is_tracking};
use mtproto_fuzz::driver::{Limits, install_panic_hook, run_target};
use mtproto_fuzz::targets::{TARGETS, Target, find};

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

fn usage() -> ! {
    eprintln!(
        "usage: mtproto-fuzz [--target NAME]... [--cases N] [--seed S] [--jobs J] [--case-ms MS] [--case-mb MB] [--hang-s S] [--list]"
    );
    std::process::exit(2);
}

fn main() {
    let mut targets: Vec<&'static Target> = Vec::new();
    let mut cases = 10_000u64;
    let mut seed = 1u64;
    let mut jobs = std::thread::available_parallelism().map(usize::from).unwrap_or(4);
    let mut limits = Limits::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--target" => {
                let name = value();
                targets.push(find(&name).unwrap_or_else(|| {
                    eprintln!("unknown target {name}");
                    usage()
                }));
            }
            "--cases" => cases = value().parse().unwrap_or_else(|_| usage()),
            "--seed" => seed = value().parse().unwrap_or_else(|_| usage()),
            "--jobs" => jobs = value().parse().unwrap_or_else(|_| usage()),
            "--case-ms" => limits.case_time = Duration::from_millis(value().parse().unwrap_or_else(|_| usage())),
            "--case-mb" => limits.case_bytes = value().parse::<usize>().unwrap_or_else(|_| usage()) * 1024 * 1024,
            "--hang-s" => limits.hang = Duration::from_secs(value().parse().unwrap_or_else(|_| usage())),
            "--list" => {
                for target in TARGETS {
                    println!("{:<10} {}", target.name, target.about);
                }
                return;
            }
            _ => usage(),
        }
    }
    if targets.is_empty() {
        targets = TARGETS.iter().collect();
    }
    install_panic_hook();
    let _ = mtproto_fuzz::generate::gzip_bomb();
    println!(
        "{:<10} {:>10} {:>6} {:>12} {:>20} {:>10} {:>20} {:>10}",
        "target", "cases", "fail", "slowest ms", "slowest seed", "peak MB", "peak seed", "cases/s"
    );
    let mut failures = Vec::new();
    for target in targets {
        let report = run_target(target, seed, cases, jobs, limits);
        let rate = report.cases as f64 / report.elapsed.as_secs_f64().max(1e-9);
        println!(
            "{:<10} {:>10} {:>6} {:>12.1} {:>20} {:>10.1} {:>20} {:>10.0}",
            report.target,
            report.cases,
            report.failures.len(),
            report.slowest.1.as_secs_f64() * 1000.0,
            report.slowest.0,
            report.peak.1 as f64 / (1024.0 * 1024.0),
            report.peak.0,
            rate
        );
        failures.extend(report.failures);
    }
    if !is_tracking() {
        println!("memory tracking is not active");
    }
    if failures.is_empty() {
        println!("no failures");
        return;
    }
    println!();
    for failure in failures.iter().take(40) {
        println!(
            "{:?} {} seed {}: {}  (--target {} --seed {} --cases 1)",
            failure.kind, failure.target, failure.seed, failure.detail, failure.target, failure.seed
        );
    }
    std::process::exit(1);
}
