use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::alloc;
use crate::targets::Target;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub case_time: Duration,
    pub case_bytes: usize,
    pub hang: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { case_time: Duration::from_secs(10), case_bytes: 256 * 1024 * 1024, hang: Duration::from_secs(120) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Panic,
    Invariant,
    Slow,
    Memory,
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub target: &'static str,
    pub seed: u64,
    pub kind: FailureKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct TargetReport {
    pub target: &'static str,
    pub cases: u64,
    pub failures: Vec<Failure>,
    pub slowest: (u64, Duration),
    pub peak: (u64, usize),
    pub elapsed: Duration,
}

thread_local! {
    static PANIC_MESSAGE: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|text| text.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into());
        let location = info.location().map(|location| location.to_string()).unwrap_or_default();
        PANIC_MESSAGE.with(|message| *message.borrow_mut() = Some(format!("{payload} at {location}")));
    }));
}

pub fn run_case(target: &Target, seed: u64, limits: &Limits) -> (Option<Failure>, Duration, usize) {
    alloc::reset_peak();
    let started = Instant::now();
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| (target.run)(seed)));
    let elapsed = started.elapsed();
    let peak = alloc::peak_since_reset();
    let failure = |kind, detail| Some(Failure { target: target.name, seed, kind, detail });
    let failure = match outcome {
        Err(_) => failure(
            FailureKind::Panic,
            PANIC_MESSAGE.with(|message| message.borrow_mut().take()).unwrap_or_else(|| "panic".into()),
        ),
        Ok(Err(detail)) => failure(FailureKind::Invariant, detail),
        Ok(Ok(())) if elapsed > limits.case_time => failure(FailureKind::Slow, format!("{} ms", elapsed.as_millis())),
        Ok(Ok(())) if peak > limits.case_bytes => {
            failure(FailureKind::Memory, format!("{} MB peak", peak / (1024 * 1024)))
        }
        Ok(Ok(())) => None,
    };
    (failure, elapsed, peak)
}

type WorkerResult = (Vec<Failure>, (u64, Duration), (u64, usize));

struct Slot {
    started_ms: AtomicU64,
    seed: AtomicU64,
}

pub fn run_target(target: &'static Target, base_seed: u64, cases: u64, jobs: usize, limits: Limits) -> TargetReport {
    let jobs = jobs.max(1) as u64;
    let origin = Instant::now();
    let slots: Arc<Vec<Slot>> =
        Arc::new((0..jobs).map(|_| Slot { started_ms: AtomicU64::new(0), seed: AtomicU64::new(0) }).collect());
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let slots = slots.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                let now = origin.elapsed().as_millis() as u64;
                for slot in slots.iter() {
                    let started = slot.started_ms.load(Ordering::Relaxed);
                    if started != 0 && now.saturating_sub(started) > limits.hang.as_millis() as u64 {
                        let seed = slot.seed.load(Ordering::Relaxed);
                        eprintln!(
                            "HANG: target {} seed {seed} has run for {} s; reproduce with --target {} --seed {seed} --cases 1",
                            target.name,
                            (now - started) / 1000,
                            target.name
                        );
                        std::process::exit(3);
                    }
                }
            }
        })
    };
    let results: Vec<WorkerResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..jobs)
            .map(|job| {
                let slots = slots.clone();
                scope.spawn(move || {
                    let mut failures = Vec::new();
                    let mut slowest = (0, Duration::ZERO);
                    let mut peak = (0, 0usize);
                    let mut index = job;
                    while index < cases {
                        let seed = base_seed.wrapping_add(index);
                        slots[job as usize].seed.store(seed, Ordering::Relaxed);
                        slots[job as usize]
                            .started_ms
                            .store(origin.elapsed().as_millis() as u64 + 1, Ordering::Relaxed);
                        let (failure, elapsed, bytes) = run_case(target, seed, &limits);
                        slots[job as usize].started_ms.store(0, Ordering::Relaxed);
                        if let Some(failure) = failure
                            && failures.len() < 64
                        {
                            failures.push(failure);
                        }
                        if elapsed > slowest.1 {
                            slowest = (seed, elapsed);
                        }
                        if bytes > peak.1 {
                            peak = (seed, bytes);
                        }
                        index += jobs;
                    }
                    (failures, slowest, peak)
                })
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().expect("fuzz worker")).collect()
    });
    done.store(true, Ordering::Relaxed);
    let _ = watchdog.join();
    let mut report = TargetReport {
        target: target.name,
        cases,
        failures: Vec::new(),
        slowest: (0, Duration::ZERO),
        peak: (0, 0),
        elapsed: origin.elapsed(),
    };
    for (failures, slowest, peak) in results {
        report.failures.extend(failures);
        if slowest.1 > report.slowest.1 {
            report.slowest = slowest;
        }
        if peak.1 > report.peak.1 {
            report.peak = peak;
        }
    }
    report.failures.sort_by_key(|failure| failure.seed);
    report
}
