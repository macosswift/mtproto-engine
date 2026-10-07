#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_cargo_fuzz::peer::{drive, new_session};
use mtproto_core::session::SessionConfig;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let setup = cursor.u8();
    let http = setup & 1 != 0;
    let config = SessionConfig {
        is_main: setup & 2 == 0,
        use_ping_delay_disconnect: setup & 4 == 0,
        max_unpacked_bytes: if setup & 8 != 0 { 4096 } else { SessionConfig::default().max_unpacked_bytes },
        ..SessionConfig::default()
    };
    let (mut session, rng, now) = new_session(config, http);
    drive(&mut session, http, rng, now, &mut cursor);
});
