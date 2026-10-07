//! A CDN must not be able to substitute replies to queries sent to other DCs. Pending queries live in
//! the session that sent them, under its key: a packet the CDN seals with its own key is refused by the
//! master's session even when it copies the master's session id and query msg_id, and the CDN's own
//! session drops an answer to a query it never sent.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::message::MessageError;
use mtproto_core::rpc::{RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig, SessionError};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_result};

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5566_7788;

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)))
}

fn client(role: SessionRole, key: AuthKey, rng: &mut XorShiftRandom, now: Now) -> RpcClient {
    let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
    let mut session = Session::new(SessionConfig::default(), key, &salts, 0.0, now, rng);
    session.connection_opened(now);
    RpcClient::new(session, role, None, None)
}

fn sent_query(client: &mut RpcClient, peer: &mut ServerPeer, tag: u32, now: Now, rng: &mut XorShiftRandom) -> i64 {
    let body = [CALL.to_le_bytes(), tag.to_le_bytes()].concat();
    client.send(
        RpcRequest { id: RequestId(1), body: body.clone(), flags: RequestFlags::default(), invoke_after: None },
        now,
    );
    let transmit = client.poll_transmit(now, rng).expect("the query goes out");
    let packet = peer.decode(&transmit.data);
    packet.messages.iter().find(|message| message.body == body).expect("the query").msg_id
}

fn completions(events: &[RpcEvent]) -> Vec<(RequestId, Vec<u8>)> {
    events
        .iter()
        .filter_map(|event| match event {
            RpcEvent::Completed { id, body, .. } => Some((*id, body.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_cdn_cannot_answer_a_query_the_master_session_sent() {
    let now = Now { mono: 10.0, unix: START };
    let mut master_rng = XorShiftRandom::new(50);
    let mut cdn_rng = XorShiftRandom::new(51);
    let mut master = client(SessionRole::Main, key(1), &mut master_rng, now);
    let mut cdn = client(SessionRole::Cdn, key(2), &mut cdn_rng, now);
    let mut master_server = ServerPeer::new(key(1), START);
    let mut cdn_server = ServerPeer::new(key(2), START);
    let master_query = sent_query(&mut master, &mut master_server, 1, now, &mut master_rng);
    let cdn_query = sent_query(&mut cdn, &mut cdn_server, 2, now, &mut cdn_rng);
    assert_ne!(master_query, cdn_query);
    let cdn_session_id = cdn_server.session_id;

    let forged = cdn_server.encode(vec![Outgoing::Content(rpc_result(master_query, b"forged!!"))]);
    assert!(matches!(
        master.handle_packet(&forged, now, &mut master_rng),
        Err(SessionError::Decrypt(MessageError::AuthKeyMismatch { .. }))
    ));
    cdn_server.session_id = master_server.session_id;
    let forged = cdn_server.encode(vec![Outgoing::Content(rpc_result(master_query, b"forged!!"))]);
    assert!(matches!(
        master.handle_packet(&forged, now, &mut master_rng),
        Err(SessionError::Decrypt(MessageError::AuthKeyMismatch { .. }))
    ));
    assert_eq!(completions(&master.drain_events()), Vec::new());
    assert!(master.contains(RequestId(1)), "the master's query is still waiting for the master's answer");

    cdn_server.session_id = cdn_session_id;
    let misdirected = cdn_server.encode(vec![Outgoing::Content(rpc_result(master_query, b"forged!!"))]);
    cdn.handle_packet(&misdirected, now, &mut cdn_rng).unwrap();
    assert_eq!(completions(&cdn.drain_events()), Vec::new(), "an answer to a query the CDN session never sent");
    assert!(cdn.contains(RequestId(1)));

    let own = cdn_server.encode(vec![Outgoing::Content(rpc_result(cdn_query, b"cdn-part"))]);
    cdn.handle_packet(&own, now, &mut cdn_rng).unwrap();
    assert_eq!(completions(&cdn.drain_events()), vec![(RequestId(1), b"cdn-part".to_vec())]);
    assert!(master.contains(RequestId(1)));

    let genuine = master_server.encode(vec![Outgoing::Content(rpc_result(master_query, b"master!!"))]);
    master.handle_packet(&genuine, now, &mut master_rng).unwrap();
    assert_eq!(completions(&master.drain_events()), vec![(RequestId(1), b"master!!".to_vec())]);
}
