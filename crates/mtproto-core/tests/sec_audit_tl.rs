//! TL and RPC parsing under "impossible" inputs: everything the server, a CDN or a hostile peer can put
//! inside an encrypted message is bounded, never panics and never allocates from a declared size alone.

use std::io::Write;
use std::time::{Duration, Instant};

use mtproto_core::rpc::{ApiEnvironment, ClientProxy, Verification, flood_wait_seconds, wrap_request};
use mtproto_core::tl::mtproto::{
    INVALID_UTF8_ERROR_MESSAGE, MAX_CONTAINER_MESSAGES, MAX_UNPACKED_SIZE, MAX_VECTOR_ITEMS, RpcError, RpcResultBody,
    ServiceMessage, gunzip, gunzip_within, gzip, parse_rpc_result, parse_rpc_result_limited,
};
use mtproto_core::tl::{Reader, TlError, Writer, ids};

fn body(constructor: u32, fill: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(constructor);
    fill(&mut writer);
    writer.into_inner()
}

fn deflate_member(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn bytes_lengths_beyond_the_buffer_fail_without_moving_the_reader() {
    for data in [
        vec![254u8, 0xff, 0xff, 0xff],
        vec![254u8, 4, 0, 0, 1, 2, 3],
        vec![253u8],
        vec![255u8, 1, 2, 3, 4, 5, 6, 7],
        vec![254u8, 1, 0],
    ] {
        let mut reader = Reader::new(&data);
        assert!(reader.read_bytes().is_err(), "{data:?}");
        assert_eq!(reader.position(), 0, "{data:?}");
    }
}

#[test]
fn vector_counts_never_allocate_from_the_declared_count() {
    for count in [i32::MAX, MAX_VECTOR_ITEMS as i32, MAX_VECTOR_ITEMS as i32 + 1, -1, i32::MIN] {
        for constructor in [ids::MSGS_ACK, ids::MSG_RESEND_REQ, ids::MSGS_STATE_REQ, ids::MSGS_ALL_INFO] {
            let message = body(constructor, |w| {
                w.write_u32(ids::VECTOR);
                w.write_i32(count);
                w.write_i64(1);
            });
            let started = Instant::now();
            assert!(ServiceMessage::parse(&message).is_err(), "{constructor:#x} count {count}");
            assert!(started.elapsed() < Duration::from_millis(50));
        }
        let salts = body(ids::FUTURE_SALTS, |w| {
            w.write_i64(1);
            w.write_i32(2);
            w.write_i32(count);
        });
        assert!(ServiceMessage::parse(&salts).is_err(), "future_salts count {count}");
        let container = body(ids::MSG_CONTAINER, |w| w.write_i32(count));
        assert!(ServiceMessage::parse(&container).is_err(), "container count {count}");
    }
}

#[test]
fn container_children_are_bounded_aligned_and_inside_the_container() {
    let full = body(ids::MSG_CONTAINER, |w| {
        w.write_i32(MAX_CONTAINER_MESSAGES as i32);
        for index in 0..MAX_CONTAINER_MESSAGES {
            w.write_i64(index as i64 * 4 + 1);
            w.write_i32(1);
            w.write_i32(4);
            w.write_u32(0x1234_5678);
        }
    });
    match ServiceMessage::parse(&full).unwrap() {
        ServiceMessage::Container(children) => assert_eq!(children.len(), MAX_CONTAINER_MESSAGES),
        other => panic!("{other:?}"),
    }
    for length in [i32::MIN, -4, 3, 5, i32::MAX, 1 << 24] {
        let message = body(ids::MSG_CONTAINER, |w| {
            w.write_i32(1);
            w.write_i64(1);
            w.write_i32(1);
            w.write_i32(length);
            w.write_raw(&[0u8; 64]);
        });
        assert!(ServiceMessage::parse(&message).is_err(), "child length {length}");
        let copy = body(ids::MSG_COPY, |w| {
            w.write_u32(ids::MESSAGE);
            w.write_i64(1);
            w.write_i32(1);
            w.write_i32(length);
            w.write_raw(&[0u8; 64]);
        });
        assert!(ServiceMessage::parse(&copy).is_err(), "msg_copy length {length}");
    }
}

#[test]
fn rpc_errors_with_hostile_codes_and_texts_are_normalised() {
    for code in [i32::MIN, i32::MAX, 0, 10_000, -10_000, 1_000_000] {
        let error = RpcError { code, message: String::new() }.normalized();
        assert_eq!(error.code, 500, "{code}");
    }
    let message = body(ids::RPC_ERROR, |w| {
        w.write_i32(400);
        w.write_bytes(b"NUL\0INSIDE\xff");
    });
    match parse_rpc_result(&message).unwrap() {
        RpcResultBody::Error(error) => assert_eq!(error.message, INVALID_UTF8_ERROR_MESSAGE),
        other => panic!("{other:?}"),
    }
    let message = body(ids::RPC_ERROR, |w| {
        w.write_i32(400);
        w.write_bytes(b"NUL\0INSIDE");
    });
    match parse_rpc_result(&message).unwrap() {
        RpcResultBody::Error(error) => {
            assert_eq!(error.message, "NUL\0INSIDE", "a NUL is kept; the C side gets a length")
        }
        other => panic!("{other:?}"),
    }
    for truncated in [vec![], ids::RPC_ERROR.to_le_bytes().to_vec(), body(ids::RPC_ERROR, |w| w.write_i32(400))] {
        assert!(parse_rpc_result(&truncated).is_err());
    }
    let huge = "9".repeat(1 << 20);
    assert_eq!(flood_wait_seconds(&format!("FLOOD_WAIT_{huge}")), None, "an overflowing wait is not a wait");
    assert_eq!(flood_wait_seconds("FLOOD_WAIT_"), None);
    assert_eq!(flood_wait_seconds("FLOOD_WAIT_٣"), None, "only ASCII digits");
    assert_eq!(flood_wait_seconds("FLOOD_PREMIUM_WAIT_7 FLOOD_WAIT_9"), Some(7));
}

#[test]
fn gzip_members_after_the_first_and_lying_trailers_stay_within_the_limit() {
    let first = deflate_member(&[b'a'; 1000]);
    let mut concatenated = first.clone();
    concatenated.extend_from_slice(&deflate_member(&vec![b'b'; 1 << 20]));
    let unpacked = gunzip(&concatenated, 4 << 20).unwrap_or_default();
    assert!(unpacked.len() <= 1 << 20, "only the declared size of the last member bounds the output");

    let mut lying = deflate_member(&vec![0u8; 8 << 20]);
    let trailer = lying.len() - 4;
    lying[trailer..].copy_from_slice(&(MAX_UNPACKED_SIZE as u32).to_le_bytes());
    let mut budget = 1 << 20;
    assert!(gunzip_within(&lying, &mut budget).is_err());
    assert!(budget < 1 << 20, "a refused unpack is charged");

    let mut header_bomb = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 0xff];
    header_bomb.extend(std::iter::repeat_n(b'n', 2 << 20));
    header_bomb.push(0);
    header_bomb.extend_from_slice(&first[10..]);
    let started = Instant::now();
    let _ = gunzip(&header_bomb, 1 << 20);
    assert!(started.elapsed() < Duration::from_secs(2));

    let zlib_bomb = {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&vec![0u8; 64 << 20]).unwrap();
        encoder.finish().unwrap()
    };
    assert!(matches!(gunzip(&zlib_bomb, 1 << 20), Err(TlError::Gzip(_))), "a zlib stream is bounded by the limit too");
}

#[test]
fn gzip_inside_gzip_is_unpacked_once_and_bounded() {
    let inner = gzip(&vec![7u8; 1 << 20]);
    let mut packed = Writer::new();
    packed.write_u32(ids::GZIP_PACKED);
    packed.write_bytes(&inner);
    let outer = gzip(packed.as_slice());
    let result = body(ids::GZIP_PACKED, |w| w.write_bytes(&outer));
    match parse_rpc_result_limited(&result, 64 * 1024).unwrap() {
        RpcResultBody::PackedValue(value) => {
            assert_eq!(value, packed.into_inner(), "only one level is unpacked for the host");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn deeply_nested_service_messages_parse_one_level_at_a_time() {
    let mut message = body(ids::PING, |w| w.write_i64(1));
    for depth in 0..2000 {
        message = if depth % 2 == 0 {
            body(ids::MSG_CONTAINER, |w| {
                w.write_i32(1);
                w.write_i64(1);
                w.write_i32(1);
                w.write_i32(message.len() as i32);
                w.write_raw(&message);
            })
        } else {
            body(ids::MSG_COPY, |w| {
                w.write_i64(1);
                w.write_i32(1);
                w.write_i32(message.len() as i32);
                w.write_raw(&message);
            })
        };
    }
    let started = Instant::now();
    assert!(ServiceMessage::parse(&message).is_ok(), "a parse looks at one level only, so depth cannot recurse");
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[test]
fn wrapped_requests_carry_the_host_strings_verbatim_as_tl_bytes() {
    let environment = ApiEnvironment {
        layer: i32::MIN,
        api_id: -1,
        device_model: "\0".repeat(300),
        system_version: "é".repeat(200),
        app_version: String::new(),
        system_lang_code: "x".repeat(253),
        lang_pack: "y".repeat(254),
        lang_code: "z".repeat(255),
        proxy: Some(ClientProxy { address: "p".repeat(1000), port: -1 }),
        params: Some(vec![1, 2, 3, 4]),
        init_hash: String::new(),
        disable_updates: true,
    };
    let verification = Verification::Apns { nonce: "n".repeat(70_000), secret: String::new() };
    let wrapped = wrap_request(&[9, 9, 9, 9], Some(&environment), true, Some(&verification));
    assert_eq!(wrapped.len() % 4, 0);
    let mut reader = Reader::new(&wrapped);
    assert_eq!(reader.read_u32().unwrap(), mtproto_core::rpc::INVOKE_WITH_APNS_SECRET);
    assert_eq!(reader.read_bytes().unwrap().len(), 70_000);
    assert_eq!(reader.read_bytes().unwrap().len(), 0);
    assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITHOUT_UPDATES);
    assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITH_LAYER);
    assert_eq!(reader.read_i32().unwrap(), i32::MIN);
    assert_eq!(reader.read_u32().unwrap(), mtproto_core::rpc::INIT_CONNECTION);
    assert_eq!(reader.read_i32().unwrap(), 3);
    assert_eq!(reader.read_i32().unwrap(), -1);
    for expected in [300, 400, 0, 253, 254, 255] {
        assert_eq!(reader.read_bytes().unwrap().len(), expected);
    }
    assert_eq!(reader.read_u32().unwrap(), mtproto_core::rpc::INPUT_CLIENT_PROXY);
    assert_eq!(reader.read_bytes().unwrap().len(), 1000);
    assert_eq!(reader.read_i32().unwrap(), -1);
    assert_eq!(reader.rest(), &[1, 2, 3, 4, 9, 9, 9, 9]);
}

#[test]
fn every_service_parser_survives_structured_garbage() {
    let constructors = [
        ids::RPC_RESULT,
        ids::MSG_CONTAINER,
        ids::GZIP_PACKED,
        ids::PONG,
        ids::BAD_MSG_NOTIFICATION,
        ids::BAD_SERVER_SALT,
        ids::NEW_SESSION_CREATED,
        ids::MSGS_ACK,
        ids::MSG_DETAILED_INFO,
        ids::MSG_NEW_DETAILED_INFO,
        ids::MSG_RESEND_REQ,
        ids::MSG_RESEND_ANS_REQ,
        ids::MSGS_STATE_REQ,
        ids::MSGS_STATE_INFO,
        ids::MSGS_ALL_INFO,
        ids::FUTURE_SALTS,
        ids::MSG_COPY,
        ids::HTTP_WAIT,
        ids::PING,
        ids::RPC_ERROR,
        ids::RPC_ANSWER_DROPPED,
    ];
    let words = [0u32, 1, 3, 4, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, ids::VECTOR, ids::FUTURE_SALT, ids::MESSAGE];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let constructor = constructors[(next() % constructors.len() as u64) as usize];
        let mut writer = Writer::new();
        writer.write_u32(constructor);
        for _ in 0..(next() % 12) {
            match next() % 4 {
                0 => writer.write_u32(words[(next() % words.len() as u64) as usize]),
                1 => writer.write_i64(next() as i64),
                2 => writer.write_bytes(&vec![0xab; (next() % 300) as usize]),
                _ => writer.write_raw(&[0xfe, 0xff, 0xff, 0xff]),
            }
        }
        let data = writer.into_inner();
        for cut in [data.len(), data.len().saturating_sub(1), data.len() / 2] {
            let _ = ServiceMessage::parse(&data[..cut]);
            let _ = parse_rpc_result_limited(&data[..cut], 4096);
        }
    }
}
