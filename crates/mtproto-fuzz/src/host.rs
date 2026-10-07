//! The RPC client driven by a broken or hostile host: strings TL cannot carry, init params larger than a
//! frame, verifications of any size, non-finite clocks, calls on unknown requests. Whatever the host
//! gives may fail a request but must never panic: a release build aborts the whole app on a panic.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{
    ApiEnvironment, ClientProxy, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole, Verification,
};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_error, rpc_result};
use mtproto_core::tl::ids;
use mtproto_core::transport::{Framing, encode_frame};

use crate::generate::Gen;
use crate::targets::CaseResult;

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5566_7788;

fn length(g: &mut Gen, huge: &mut bool) -> usize {
    if !*huge && g.one_in(40) {
        *huge = true;
        return if g.one_in(2) { 1 << 24 } else { (1 << 24) - 1 };
    }
    *g.pick(&[0, 1, 3, 253, 254, 255, 256, 4096, 70_000])
}

fn text(g: &mut Gen, huge: &mut bool) -> String {
    let length = length(g, huge);
    let fill = *g.pick(&["a", "\0", "é", "\u{fffd}"]);
    fill.repeat(length / fill.len())
}

fn environment(g: &mut Gen) -> ApiEnvironment {
    let mut huge = false;
    ApiEnvironment {
        layer: if g.one_in(4) { g.i32() } else { 230 },
        api_id: g.i32(),
        device_model: text(g, &mut huge),
        system_version: text(g, &mut huge),
        app_version: text(g, &mut huge),
        system_lang_code: text(g, &mut huge),
        lang_pack: text(g, &mut huge),
        lang_code: text(g, &mut huge),
        proxy: g.one_in(3).then(|| ClientProxy { address: text(g, &mut huge), port: g.i32() }),
        params: g.one_in(3).then(|| {
            let size = if !huge && g.one_in(30) { 17 << 20 } else { g.below(64 * 1024) };
            vec![0x42; size]
        }),
        init_hash: text(g, &mut false),
        disable_updates: g.one_in(4),
    }
}

fn verification(g: &mut Gen) -> Verification {
    let mut huge = false;
    if g.one_in(2) {
        Verification::Recaptcha { token: text(g, &mut huge) }
    } else {
        Verification::Apns { nonce: text(g, &mut huge), secret: text(g, &mut huge) }
    }
}

fn time_difference(g: &mut Gen) -> f64 {
    *g.pick(&[0.0, -3600.0, 86_400.0, 1e300, -1e300, f64::INFINITY, f64::NEG_INFINITY, f64::NAN])
}

pub fn host_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let mut rng = XorShiftRandom::new(seed ^ 0x4057);
    let key = AuthKey::new(core::array::from_fn(|i| (i as u8) ^ (seed as u8)));
    let mut now = Now { mono: 100.0, unix: START };
    let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
    let mut session =
        Session::new(SessionConfig::default(), key.clone(), &salts, time_difference(&mut g), now, &mut rng);
    session.connection_opened(now);
    let role = match g.below(3) {
        0 => SessionRole::Main,
        1 => SessionRole::Cdn,
        _ => SessionRole::Worker { requires_auth_token: g.one_in(2) },
    };
    let mut client = RpcClient::new(session, role, Some(environment(&mut g)), None);
    let mut server = ServerPeer::new(key, START);
    server.salt = 5;
    let mut next = 0u64;
    for _ in 0..g.range(4, 40) {
        match g.below(12) {
            0..=2 => {
                next += 1;
                let invoke_after = g.one_in(4).then(|| RequestId(g.below(next as usize + 2) as u64));
                let body = [CALL.to_le_bytes(), (next as u32).to_le_bytes()].concat();
                let flags = RequestFlags { delegate_retry_decisions: g.one_in(3), ..RequestFlags::default() };
                client.send(RpcRequest { id: RequestId(next), body, flags, invoke_after }, now);
            }
            3 => {
                let noop = g.one_in(2).then(|| {
                    next += 1;
                    RpcRequest {
                        id: RequestId(next),
                        body: [CALL.to_le_bytes(), 0u32.to_le_bytes()].concat(),
                        flags: RequestFlags::default(),
                        invoke_after: None,
                    }
                });
                client.update_environment(environment(&mut g), noop, now);
            }
            4 => client.resolve_verification(RequestId(g.below(next as usize + 2) as u64), verification(&mut g), now),
            5 => client.session_mut().set_time_difference(time_difference(&mut g)),
            6 => {
                let id = RequestId(g.below(next as usize + 2) as u64);
                match g.below(3) {
                    0 => {
                        client.cancel(id, now);
                    }
                    1 => client.fail_request(id, g.i32(), "HOST", now),
                    _ => client.decide_retry(id, g.one_in(2), now),
                }
            }
            7 => client.invalidate_initialization(),
            8 => {
                client.connection_closed(now);
                client.connection_opened(now);
            }
            9 => {
                let step = *g.pick(&[0.01, 1.0, 30.0, 400.0]);
                now.mono += step;
                now.unix += step;
                server.server_time += step;
                let _ = client.handle_timeout(now);
                let _ = client.poll_timeout(now);
            }
            _ => {
                for _ in 0..8 {
                    let Some(transmit) = client.poll_transmit(now, &mut rng) else {
                        break;
                    };
                    let mut framed = Vec::new();
                    encode_frame(Framing::Intermediate, &transmit.data, false, &mut rng, &mut framed);
                    let packet = server.decode(&transmit.data);
                    let mut replies = Vec::new();
                    for message in &packet.messages {
                        let query = matches!(
                            message.constructor(),
                            CALL | ids::INVOKE_WITH_LAYER
                                | ids::INVOKE_WITHOUT_UPDATES
                                | mtproto_core::rpc::INVOKE_WITH_RECAPTCHA
                                | mtproto_core::rpc::INVOKE_WITH_APNS_SECRET
                                | ids::INVOKE_AFTER_MSG
                        );
                        if !query {
                            continue;
                        }
                        replies.push(Outgoing::Content(match g.below(6) {
                            0 => rpc_error(message.msg_id, 403, "RECAPTCHA_CHECK_login__6Lc"),
                            1 => rpc_error(message.msg_id, 403, "APNS_VERIFY_CHECK_nonce"),
                            2 => rpc_error(message.msg_id, 400, "CONNECTION_NOT_INITED"),
                            3 => rpc_error(message.msg_id, 500, "INTERNAL"),
                            _ => rpc_result(message.msg_id, &ids::BOOL_TRUE.to_le_bytes()),
                        }));
                    }
                    if !replies.is_empty() {
                        let reply = server.encode(replies);
                        let _ = client.handle_packet(&reply, now, &mut rng);
                    }
                }
            }
        }
        for event in client.drain_events() {
            if let RpcEvent::VerificationRequired { id, .. } = event {
                client.resolve_verification(id, verification(&mut g), now);
            }
        }
        if client.request_count() > next as usize {
            return Err(format!("{} requests tracked, {next} sent", client.request_count()));
        }
    }
    Ok(())
}
