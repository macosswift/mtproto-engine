//! Seed inputs that reach deep states at once: valid service messages naming the client's own
//! msg_ids through placeholders, valid handshake answers, well-formed HTTP and WebSocket streams.

use mtproto_core::tl::mtproto::{ContainerMessage, FutureSalt, gzip, write_container, write_pong, write_rpc_result};
use mtproto_core::tl::{Writer, ids};

use crate::{
    ANY_CLIENT_MSG, CLIENT_PACKET, CLIENT_QUERY, FUTURE_SALTS_MSG, PING_ID, PING_MSG, SERVER_MSG, STATE_REQUEST_MSG,
    placeholder,
};

fn tl(build: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut writer = Writer::new();
    build(&mut writer);
    writer.into_inner()
}

fn rpc_error(code: i32, message: &str) -> Vec<u8> {
    tl(|w| {
        w.write_u32(ids::RPC_ERROR);
        w.write_i32(code);
        w.write_bytes(message.as_bytes());
    })
}

fn result_for(query: u8, result: &[u8]) -> Vec<u8> {
    tl(|w| write_rpc_result(w, placeholder(CLIENT_QUERY, query), result))
}

fn vector_of(constructor: u32, ids_: &[i64]) -> Vec<u8> {
    tl(|w| {
        w.write_u32(constructor);
        w.write_u32(ids::VECTOR);
        w.write_i32(ids_.len() as i32);
        for id in ids_ {
            w.write_i64(*id);
        }
    })
}

/// Service message bodies a server sends, each naming live client state.
pub fn service_bodies() -> Vec<Vec<u8>> {
    let value = vec![0x15, 0xc4, 0xb5, 0x1c, 0, 0, 0, 0];
    let mut bodies = vec![
        result_for(0, &value),
        result_for(1, &rpc_error(420, "FLOOD_WAIT_3")),
        result_for(2, &rpc_error(303, "PHONE_MIGRATE_4")),
        result_for(0, &rpc_error(500, "INTERNAL")),
        result_for(1, &rpc_error(-503, "Timeout")),
        result_for(2, &rpc_error(401, "AUTH_KEY_UNREGISTERED")),
        result_for(0, &rpc_error(400, "CONNECTION_NOT_INITED")),
        result_for(1, &rpc_error(403, "RECAPTCHA_CHECK_signin__abc")),
        result_for(2, &rpc_error(400, "CONNECTION_LAYER_INVALID")),
        result_for(0, &rpc_error(406, "AUTH_KEY_PERM_EMPTY")),
        result_for(1, &tl(|w| w.write_u32(ids::RPC_ANSWER_UNKNOWN))),
        result_for(2, &tl(|w| w.write_u32(ids::RPC_ANSWER_DROPPED_RUNNING))),
        result_for(
            0,
            &tl(|w| {
                w.write_u32(ids::RPC_ANSWER_DROPPED);
                w.write_i64(placeholder(CLIENT_QUERY, 0));
                w.write_i32(1);
                w.write_i32(64);
            }),
        ),
        result_for(
            0,
            &tl(|w| {
                w.write_u32(ids::GZIP_PACKED);
                w.write_bytes(&gzip(&vec![7u8; 4096]));
            }),
        ),
        vector_of(ids::MSGS_ACK, &[placeholder(CLIENT_QUERY, 0), placeholder(CLIENT_QUERY, 1)]),
        tl(|w| write_pong(w, placeholder(PING_MSG, 0), placeholder(PING_ID, 0))),
        tl(|w| {
            w.write_u32(ids::BAD_SERVER_SALT);
            w.write_i64(placeholder(CLIENT_PACKET, 0));
            w.write_i32(1);
            w.write_i32(48);
            w.write_i64(0x0102_0304);
        }),
        tl(|w| {
            w.write_u32(ids::NEW_SESSION_CREATED);
            w.write_i64(placeholder(ANY_CLIENT_MSG, 2));
            w.write_i64(0x4242);
            w.write_i64(0x0506_0708);
        }),
        tl(|w| {
            w.write_u32(ids::MSG_DETAILED_INFO);
            w.write_i64(placeholder(CLIENT_QUERY, 0));
            w.write_i64(placeholder(SERVER_MSG, 0) | 1);
            w.write_i32(100_000);
            w.write_i32(0);
        }),
        tl(|w| {
            w.write_u32(ids::MSG_NEW_DETAILED_INFO);
            w.write_i64(placeholder(SERVER_MSG, 1));
            w.write_i32(64);
            w.write_i32(0);
        }),
        tl(|w| {
            w.write_u32(ids::MSGS_STATE_INFO);
            w.write_i64(placeholder(STATE_REQUEST_MSG, 0));
            w.write_bytes(&[1, 2, 4, 8]);
        }),
        tl(|w| {
            w.write_u32(ids::MSGS_ALL_INFO);
            w.write_u32(ids::VECTOR);
            w.write_i32(2);
            w.write_i64(placeholder(CLIENT_QUERY, 0));
            w.write_i64(placeholder(CLIENT_QUERY, 1));
            w.write_bytes(&[4, 0x24]);
        }),
        vector_of(ids::MSGS_STATE_REQ, &[placeholder(SERVER_MSG, 0), 5]),
        vector_of(ids::MSG_RESEND_REQ, &[placeholder(SERVER_MSG, 0)]),
        vector_of(ids::MSG_RESEND_ANS_REQ, &[placeholder(SERVER_MSG, 0)]),
        tl(|w| {
            w.write_u32(ids::FUTURE_SALTS);
            w.write_i64(placeholder(FUTURE_SALTS_MSG, 0));
            w.write_i32(1_727_000_000);
            let salts = [
                FutureSalt { valid_since: 1_727_000_000 - 100, valid_until: 1_727_001_800, salt: 11 },
                FutureSalt { valid_since: 1_727_001_800, valid_until: 1_727_003_600, salt: 12 },
            ];
            w.write_i32(salts.len() as i32);
            for salt in salts {
                w.write_u32(ids::FUTURE_SALT);
                w.write_i32(salt.valid_since);
                w.write_i32(salt.valid_until);
                w.write_i64(salt.salt);
            }
        }),
        tl(|w| {
            w.write_u32(ids::PING);
            w.write_i64(77);
        }),
        tl(|w| {
            w.write_u32(ids::DESTROY_AUTH_KEY_OK);
        }),
        tl(|w| {
            w.write_u32(ids::DESTROY_SESSION_OK);
            w.write_i64(1);
        }),
        tl(|w| {
            w.write_u32(0x7419_8a3a);
            w.write_i32(5);
        }),
    ];
    for code in [16, 17, 18, 19, 20, 32, 33, 34, 35, 48, 64] {
        bodies.push(tl(|w| {
            w.write_u32(ids::BAD_MSG_NOTIFICATION);
            w.write_i64(placeholder(CLIENT_QUERY, 0));
            w.write_i32(1);
            w.write_i32(code);
        }));
    }
    let children: Vec<Vec<u8>> = vec![
        vector_of(ids::MSGS_ACK, &[placeholder(CLIENT_QUERY, 1)]),
        result_for(1, &value),
        tl(|w| {
            w.write_u32(0x7419_8a3a);
        }),
    ];
    let container = tl(|w| {
        let messages: Vec<ContainerMessage<'_>> = children
            .iter()
            .enumerate()
            .map(|(index, body)| ContainerMessage {
                msg_id: placeholder(crate::FRESH_SERVER_MSG, 0) + index as i64 * 4,
                seqno: if index == 0 { 0 } else { 2 * index as i32 + 1 },
                body,
            })
            .collect();
        write_container(w, &messages);
    });
    bodies.push(container);
    bodies.push(tl(|w| {
        w.write_u32(ids::GZIP_PACKED);
        w.write_bytes(&gzip(&result_for(0, &value)));
    }));
    bodies.push(tl(|w| {
        w.write_u32(ids::MSG_COPY);
        w.write_u32(ids::MESSAGE);
        w.write_i64(placeholder(crate::FRESH_SERVER_MSG, 1));
        w.write_i32(3);
        let inner = result_for(2, &value);
        w.write_i32(inner.len() as i32);
        w.write_raw(&inner);
    }));
    bodies
}

fn deliver(out: &mut Vec<u8>, control: u8, body: &[u8]) {
    out.push(0);
    out.push(control);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
}

/// Op streams for the session and rpc targets: flush, answer, advance, reconnect.
pub fn session_streams() -> Vec<Vec<u8>> {
    let bodies = service_bodies();
    let mut seeds = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        for setup in [0u8, 1] {
            let mut seed = vec![setup];
            seed.extend_from_slice(&[9, 0]);
            deliver(&mut seed, 0, body);
            seed.extend_from_slice(&[9, 0]);
            seed.extend_from_slice(&[7, 3, 0]);
            seed.extend_from_slice(&[9, 0]);
            deliver(&mut seed, 0, &bodies[(index * 7 + 3) % bodies.len()]);
            seed.extend_from_slice(&[7, 5, 0]);
            seed.extend_from_slice(&[10, 9, 0]);
            deliver(&mut seed, 0x08, body);
            seed.extend_from_slice(&[7, 6, 0, 9, 0]);
            seeds.push(seed);
        }
    }
    let mut everything = vec![0u8, 9, 0];
    for body in &bodies {
        deliver(&mut everything, 0, body);
        everything.extend_from_slice(&[7, 2, 0, 9, 0, 8, 0, 0]);
    }
    seeds.push(everything);
    seeds
}

pub fn http_responses() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for wire in [
        &b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 4\r\n\r\nabcd"[..],
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\nabcd\r\n0\r\nT: 1\r\n\r\n",
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\n\r\nuntil close",
        b"HTTP/1.1 200 Connection established\r\n\r\n\xef",
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
    ] {
        for connect in [0u8, 1] {
            let mut seed = vec![0u8, 0, connect];
            seed.extend_from_slice(&(wire.len() as u16).to_le_bytes());
            seed.extend_from_slice(wire);
            seed.extend_from_slice(&[3, 7, 1]);
            seeds.push(seed);
        }
    }
    seeds.push(vec![1, 0, 1, 0, 0, 0, 0, 5, 0, b'h', b'e', b'l', b'l', b'o', 2, 1]);
    seeds
}

pub fn handshake_stages() -> Vec<Vec<u8>> {
    vec![
        vec![0u8, 1],
        vec![1, 6, 0],
        vec![1, 2, 0, 0, 0],
        vec![2, 0],
        vec![2, 1, 1, 0],
        vec![2, 1, 1, 1, 0],
        vec![2, 1, 2],
        vec![2, 0x10, 3],
    ]
}

pub fn websocket_streams() -> Vec<Vec<u8>> {
    vec![
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 3, 0, 0x82, 1, 9, 5],
        vec![1, 6, 0, 0x82, 2, 1, 2, 0x89, 0, 3],
        vec![2, 0, 3, 0, 1, 2, 3, 2, 1, 0, 9, 16, 0, 1, 0, 7, 4],
    ]
}

pub fn route_memories() -> Vec<Vec<u8>> {
    let now = 1_800_000_000.0f64;
    let mut memory = vec![1u8, 1, 6];
    memory.extend_from_slice(b"office");
    memory.extend_from_slice(&(now - 10.0).to_le_bytes());
    memory.extend_from_slice(&0f64.to_le_bytes());
    memory.extend_from_slice(&(now - 10.0).to_le_bytes());
    let mut seed = (memory.len() as u16).to_le_bytes().to_vec();
    seed.extend_from_slice(&memory);
    seed.extend_from_slice(&[0, 0, 6]);
    seed.extend_from_slice(b"office");
    seed.extend_from_slice(&[2, 1, 2, 3, 0, 7, 4, 4, 2, 8, 3, 7]);
    vec![seed]
}

pub fn socks5_replies() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for (target, auth, reply) in [
        (vec![0u8, 149, 154, 167, 51, 0xbb, 1], false, vec![5u8, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 80]),
        (vec![2u8, 3, 0, b'a', b'b', b'c', 0xbb, 1], true, vec![5, 2, 1, 0, 5, 0, 0, 3, 3, b'x', b'y', b'z', 0, 80]),
        (vec![1u8; 19], false, vec![5, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ] {
        let mut seed = target;
        if auth {
            seed.extend_from_slice(&[1, 1, 0, b'u', 1, 0, b'p']);
        } else {
            seed.push(0);
        }
        seed.extend_from_slice(&(reply.len() as u16).to_le_bytes());
        seed.extend_from_slice(&reply);
        seed.push(1);
        seeds.push(seed);
    }
    seeds
}

pub fn service_messages() -> Vec<Vec<u8>> {
    service_bodies()
}
