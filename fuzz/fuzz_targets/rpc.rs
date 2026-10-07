#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_cargo_fuzz::peer::{drive, new_session};
use mtproto_core::rpc::{ApiEnvironment, RpcClient, SessionRole};
use mtproto_core::session::SessionConfig;

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "h".into(),
        disable_updates: false,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let setup = cursor.u8();
    let http = setup & 1 != 0;
    let role = match (setup >> 1) & 3 {
        0 => SessionRole::Main,
        1 => SessionRole::Cdn,
        2 => SessionRole::Worker { requires_auth_token: true },
        _ => SessionRole::Worker { requires_auth_token: false },
    };
    let (session, rng, now) = new_session(SessionConfig::default(), http);
    let environment = (setup & 8 == 0).then(environment);
    let stored = (setup & 16 != 0).then(|| "h".to_string());
    let mut client = RpcClient::new(session, role, environment, stored);
    drive(&mut client, http, rng, now, &mut cursor);
});
