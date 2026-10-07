//! Request ids above `BIND_QUERY_ID_BASE` belong to the client's own `auth.bindTempAuthKey`. A host
//! request with such an id was silently cancelled by the next bind (or dropped as a duplicate of the
//! bind in flight) and never answered; it must be refused at once instead.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{
    BIND_QUERY_ID_BASE, REQUEST_ID_INVALID, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole,
};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_result};
use mtproto_core::tl::ids;

const START: f64 = 1_727_000_000.0;

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(seed)))
}

fn request(id: u64) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: [0x5566_7788u32.to_le_bytes(), 1u32.to_le_bytes()].concat(),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn refused(events: &[RpcEvent], id: u64) -> bool {
    events.iter().any(|event| {
        matches!(event, RpcEvent::Failed { id: failed, code: 400, message, .. }
            if failed.0 == id && message == REQUEST_ID_INVALID)
    })
}

#[test]
fn host_requests_in_the_bind_id_range_are_refused_and_the_bind_still_works() {
    let mut rng = XorShiftRandom::new(3);
    let mut now = Now { mono: 10.0, unix: START };
    let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
    let mut session = Session::new(SessionConfig::default(), key(3), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let mut client = RpcClient::new(session, SessionRole::Main, None, None);
    let mut server = ServerPeer::new(key(3), START);
    server.salt = 5;
    client.hold_until_bound();

    let first_bind = BIND_QUERY_ID_BASE + 1;
    client.send(request(first_bind), now);
    let bind = client.bind_temporary_key(key(9), START as i32 + 86_400, now, &mut rng);
    assert_eq!(bind.0, first_bind, "the host picked the id of the next bind");
    client.send(request(u64::MAX), now);
    let events = client.drain_events();
    assert!(refused(&events, first_bind), "{events:?}");
    assert!(refused(&events, u64::MAX), "{events:?}");
    assert!(!client.contains(RequestId(first_bind)), "nothing is left waiting for an answer that never comes");

    now.mono += 0.01;
    let transmit = client.poll_transmit(now, &mut rng).expect("the bind");
    let packet = server.decode(&transmit.data);
    let sent = packet.messages.iter().find(|m| m.constructor() == ids::AUTH_BIND_TEMP_AUTH_KEY).expect("bind sent");
    let reply = server.encode(vec![Outgoing::Content(rpc_result(sent.msg_id, &ids::BOOL_TRUE.to_le_bytes()))]);
    client.handle_packet(&reply, now, &mut rng).unwrap();
    assert!(client.drain_events().contains(&RpcEvent::TemporaryKeyBound));

    client.send(request(BIND_QUERY_ID_BASE), now);
    assert!(client.contains(RequestId(BIND_QUERY_ID_BASE)), "ids up to the base stay the host's");
}
