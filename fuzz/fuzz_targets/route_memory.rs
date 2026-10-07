#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_engine::{NETWORKS_REMEMBERED, RouteHints};

const NOW: f64 = 1_800_000_000.0;

/// The stored memory always loads back to the same memory, whatever it was built from. `stepped_back`:
/// the clock went back during the run; a record then seen "in the future" is stored as is and refused
/// on load (crashes.md, fix-03), so stability is only checked while the clock has not gone back.
fn check_export(hints: &RouteHints, now: f64, stepped_back: bool) {
    let exported = hints.export(now);
    assert!(exported.len() >= 2);
    assert_eq!(exported[0], 1, "format");
    let count = usize::from(exported[1]);
    assert!(count <= NETWORKS_REMEMBERED, "{count} networks stored");
    if stepped_back {
        return;
    }
    let reloaded = RouteHints::default();
    reloaded.load(&exported, now);
    assert_eq!(reloaded.export(now), exported, "export → load → export is stable");
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let hints = RouteHints::default();
    let mut now = NOW;
    let memory = cursor.chunk().to_vec();
    hints.load(&memory, now);
    check_export(&hints, now, false);
    let mut stepped_back = false;
    let mut generation = hints.generation();
    for _ in 0..256 {
        if cursor.is_empty() {
            break;
        }
        let datacenter = i32::from(cursor.u8() % 6);
        match cursor.u8() % 9 {
            0 => {
                let length = usize::from(cursor.u8() % 80);
                let key = cursor.bytes(length).to_vec();
                let changed = hints.set_network(&key, now);
                if changed {
                    assert!(hints.generation() > generation);
                    generation = hints.generation();
                }
            }
            1 => hints.note_http_needed_for(datacenter, generation, now),
            2 => hints.note_tcp_answered_for(datacenter, generation, now),
            3 => {
                let datacenter = datacenter.max(1);
                hints.note_tcp_answered_for(datacenter, generation, now);
                assert!(!hints.http_likely_for(datacenter, now), "HTTP is likely for a datacenter whose TCP answered");
            }
            4 => {
                let step = match cursor.u8() % 6 {
                    0 => 1.0,
                    1 => 59.0,
                    2 => 3601.0,
                    3 => 86_400.0,
                    4 => {
                        stepped_back = true;
                        -120.0
                    }
                    _ => f64::from(cursor.u32()),
                };
                now += step;
            }
            5 => hints.forget(),
            6 => {
                let memory = cursor.chunk().to_vec();
                hints.load(&memory, now);
            }
            7 => {
                let mut reported = None;
                hints.report_change(now, |memory| reported = Some(memory));
                if let Some(memory) = reported
                    && !stepped_back
                {
                    let reloaded = RouteHints::default();
                    reloaded.load(&memory, now);
                    assert_eq!(reloaded.export(now), memory, "a reported memory reloads as is");
                }
            }
            _ => check_export(&hints, now, stepped_back),
        }
    }
    check_export(&hints, now, stepped_back);
});
