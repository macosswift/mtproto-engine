#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_core::session::{SALT_SAFETY_MARGIN, SaltState, ServerSalt};
use mtproto_core::tl::mtproto::ServiceMessage;

fn time(cursor: &mut Cursor<'_>, base: f64) -> f64 {
    match cursor.u8() % 8 {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => f64::NEG_INFINITY,
        3 => base + f64::from(cursor.u16()),
        4 => base - f64::from(cursor.u16()),
        5 => f64::from(cursor.u32() as i32),
        _ => base + f64::from(cursor.u8()) * 600.0,
    }
}

fn salt(cursor: &mut Cursor<'_>, base: f64) -> ServerSalt {
    ServerSalt { salt: cursor.u64() as i64, valid_since: time(cursor, base), valid_until: time(cursor, base) }
}

/// `stored_nan`: a stored salt ended in NaN. Such a salt is neither valid nor asks for future salts
/// (crashes.md, fix-01); the liveness check is skipped for it so the campaign keeps going.
fn check(state: &mut SaltState, now: f64, stored_nan: bool) {
    let all = state.all();
    assert!(all.windows(2).all(|pair| pair[0].valid_since.total_cmp(&pair[1].valid_since).is_le()));
    if let Some(at) = state.next_change_time(now) {
        assert!(at > now, "next change {at} is not after {now}");
        assert!(at.is_finite());
    }
    let valid = state.has_valid_salt(now);
    let needs = state.needs_future_salts(now);
    assert!(valid || needs || stored_nan, "an invalid salt always asks for future salts");
    let current = state.current_salt(now);
    assert_eq!(current, state.current_value());
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let mut now = 1_727_000_000.0;
    if cursor.u8() & 1 == 0 {
        if let Ok(ServiceMessage::FutureSalts { now: server_now, salts, .. }) = ServiceMessage::parse(cursor.rest()) {
            let salts: Vec<ServerSalt> = salts
                .iter()
                .map(|salt| ServerSalt {
                    salt: salt.salt,
                    valid_since: f64::from(salt.valid_since),
                    valid_until: f64::from(salt.valid_until),
                })
                .collect();
            let mut state = SaltState::empty();
            state.set_future(salts.clone(), f64::from(server_now));
            check(&mut state, f64::from(server_now), false);
            let usable = salts.iter().filter(|salt| salt.valid_until > salt.valid_since).count();
            assert!(state.all().len() <= usable + 1);
        }
        return;
    }
    let count = usize::from(cursor.u8() % 8);
    let initial: Vec<ServerSalt> = (0..count).map(|_| salt(&mut cursor, now)).collect();
    let stored_nan = initial.iter().any(|salt| salt.valid_until.is_nan());
    let mut state = SaltState::from_salts(&initial, now);
    for _ in 0..64 {
        if cursor.is_empty() {
            break;
        }
        match cursor.u8() % 6 {
            0 => {
                let count = usize::from(cursor.u8() % 70);
                let salts: Vec<ServerSalt> = (0..count).map(|_| salt(&mut cursor, now)).collect();
                state.set_future(salts, now);
            }
            1 => {
                let value = cursor.u64() as i64;
                state.set_server_salt(value, now);
                assert_eq!(state.current_salt(now), value);
                assert!(state.has_valid_salt(now), "a fresh server salt is valid");
                assert!(state.needs_future_salts(now), "and future salts are asked for");
            }
            2 => state.invalidate_current(),
            3 => now += f64::from(cursor.u16()),
            4 => now += SALT_SAFETY_MARGIN * f64::from(cursor.u8()),
            _ => {
                if let Some(at) = state.next_change_time(now) {
                    let before = state.current_value();
                    state.current_salt(at - 1e-3);
                    assert_eq!(state.current_value(), before, "nothing changes before next_change_time");
                    now = at;
                }
            }
        }
        check(&mut state, now, stored_nan);
    }
});
