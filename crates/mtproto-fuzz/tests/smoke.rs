use std::time::Duration;

use mtproto_fuzz::alloc::TrackingAlloc;
use mtproto_fuzz::driver::{Limits, install_panic_hook, run_target};
use mtproto_fuzz::targets::TARGETS;

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

#[test]
fn every_target_survives_a_short_run() {
    install_panic_hook();
    let limits = Limits { case_time: Duration::from_secs(120), hang: Duration::from_secs(300), ..Limits::default() };
    for target in TARGETS {
        let cases = match target.name {
            "session" | "rpc" => 24,
            "handshake" => 150,
            _ => 1500,
        };
        let report = run_target(target, 7, cases, 4, limits);
        assert!(report.failures.is_empty(), "{}: {:#?}", target.name, report.failures);
    }
}
