#![no_main]

//! The session target's hostile operations, then an honest server: every request still open must
//! settle. Catches states hostile input (or a host call) leaves the session unable to leave.

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_cargo_fuzz::peer::{drive, honest_server, new_session};
use mtproto_core::session::SessionConfig;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let setup = cursor.u8();
    let config = SessionConfig {
        is_main: setup & 2 == 0,
        use_ping_delay_disconnect: setup & 4 == 0,
        ..SessionConfig::default()
    };
    let (mut session, rng, now) = new_session(config, false);
    let mut run = drive(&mut session, false, rng, now, &mut cursor);
    if !run.destroyed_key {
        honest_server(&mut session, &mut run, 900);
    }
});
