//! A CDN datacenter is untrusted and serves only upload.getCdnFile. A 403 APNS_VERIFY_CHECK_ or
//! RECAPTCHA_CHECK_ from it must not start the host's verification UI with a nonce or site key the CDN
//! chose, nor make the client send the resulting token to the CDN: it fails the request like any error.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_error};

const START: f64 = 1_727_000_000.0;

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1)))
}

fn events_after_error(role: SessionRole, message: &str) -> Vec<RpcEvent> {
    let mut rng = XorShiftRandom::new(5);
    let mut now = Now { mono: 10.0, unix: START };
    let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
    let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let mut client = RpcClient::new(session, role, None, None);
    let mut server = ServerPeer::new(key(), START);
    server.salt = 5;
    let body = [0xe0b4_c3b5u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    client.send(RpcRequest { id: RequestId(1), body, flags: RequestFlags::default(), invoke_after: None }, now);
    now.mono += 0.01;
    let transmit = client.poll_transmit(now, &mut rng).expect("the call");
    let packet = server.decode(&transmit.data);
    let call = packet.messages.iter().find(|m| m.body.len() == 8).expect("call sent").msg_id;
    let reply = server.encode(vec![Outgoing::Content(rpc_error(call, 403, message))]);
    client.handle_packet(&reply, now, &mut rng).unwrap();
    client.drain_events()
}

#[test]
fn verification_requests_from_a_cdn_fail_the_call() {
    for message in ["APNS_VERIFY_CHECK_cdnchosen", "RECAPTCHA_CHECK_login__cdn-site-key"] {
        let events = events_after_error(SessionRole::Cdn, message);
        assert!(
            !events.iter().any(|event| matches!(event, RpcEvent::VerificationRequired { .. })),
            "{message}: {events:?}"
        );
        assert!(
            events.iter().any(|event| matches!(event, RpcEvent::Failed { code: 403, .. })),
            "{message}: {events:?}"
        );
        let events = events_after_error(SessionRole::Main, message);
        assert!(events.iter().any(|event| matches!(event, RpcEvent::VerificationRequired { .. })), "{message}");
    }
}
