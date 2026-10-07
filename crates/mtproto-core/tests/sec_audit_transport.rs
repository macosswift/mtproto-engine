use mtproto_core::crypto::{AesCtr, XorShiftRandom, sha256_parts};
use mtproto_core::transport::{
    FrameDecoder, Framing, HttpConnectHandshake, HttpResponseReader, Incoming, InputBuffer, OBFUSCATED_HEADER_LEN,
    ProxySecret, Socks5Handshake, Socks5Progress, Socks5Target, TransportConfig, TransportError, TransportStream,
    WsDeframer, WsError, WsHandshake, accept_for, accept_obfuscated_header, encode_frame, server_hello_for_tests,
};
use proptest::prelude::*;

const FRAMINGS: [Framing; 3] = [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate];

fn client(framing: Framing, secret: Option<ProxySecret>, seed: u64) -> (TransportStream, Vec<u8>, XorShiftRandom) {
    let config = TransportConfig { framing, dc_id: 2, secret, unix_time: 1_700_000_000 };
    let mut rng = XorShiftRandom::new(seed);
    let mut stream = TransportStream::new(&config, &mut rng);
    stream.send_packet(&[0x11; 40], false, &mut rng);
    let wire = stream.take_outgoing();
    (stream, wire, rng)
}

/// What anyone who sees the first 64 bytes of the connection can compute: the server-to-client key
/// stream, keyed from the reversed init (and the proxy secret, when they know it).
fn observer_server_stream(header: &[u8], secret: Option<&[u8; 16]>) -> AesCtr {
    let mut reversed: [u8; OBFUSCATED_HEADER_LEN] = header[..OBFUSCATED_HEADER_LEN].try_into().unwrap();
    reversed.reverse();
    let key: [u8; 32] = match secret {
        Some(secret) => sha256_parts(&[&reversed[8..40], secret]),
        None => reversed[8..40].try_into().unwrap(),
    };
    AesCtr::new(&key, &reversed[40..56].try_into().unwrap())
}

fn error_frame(framing: Framing, code: i32) -> Vec<u8> {
    let mut frame = Vec::new();
    encode_frame(framing, &code.to_le_bytes(), false, &mut XorShiftRandom::new(1), &mut frame);
    frame
}

/// Obfuscated2 hides the stream from passive filters only: its keys travel in the clear, so anyone on
/// the path, and any proxy carrying the connection, can write transport frames the client takes for
/// the server's. Transport errors (-404, -429, -444) and quick acks are therefore never evidence on
/// their own; the engine has to treat them as hints.
#[test]
fn an_on_path_observer_can_forge_transport_errors_on_obfuscated2() {
    for framing in FRAMINGS {
        for code in [-404i32, -429, -444] {
            let (mut stream, wire, _) = client(framing, None, 7 + code.unsigned_abs() as u64);
            let mut forged = error_frame(framing, code);
            observer_server_stream(&wire, None).apply(&mut forged);
            stream.receive(&forged).unwrap();
            assert_eq!(stream.next_incoming().unwrap(), Some(Incoming::TransportError(code)), "{framing:?}");
        }
    }
    let secret = ProxySecret::from_binary(&[0x42; 16], false).unwrap();
    let (mut stream, wire, _) = client(Framing::Intermediate, Some(secret.clone()), 11);
    let mut forged = error_frame(Framing::Intermediate, -404);
    observer_server_stream(&wire, Some(&secret.proxy_key())).apply(&mut forged);
    stream.receive(&forged).unwrap();
    assert_eq!(stream.next_incoming().unwrap(), Some(Incoming::TransportError(-404)), "the proxy knows the secret");
}

#[test]
fn without_the_proxy_secret_forged_frames_do_not_decode_as_the_forger_meant() {
    let mut wrong = 0;
    for seed in 0..200u64 {
        let secret = ProxySecret::from_binary(&[&[0xdd][..], &[seed as u8; 16][..]].concat(), false).unwrap();
        let (mut stream, wire, _) = client(Framing::PaddedIntermediate, Some(secret), 1000 + seed);
        let mut forged = error_frame(Framing::PaddedIntermediate, -404);
        observer_server_stream(&wire, None).apply(&mut forged);
        stream.receive(&forged).unwrap();
        match stream.next_incoming() {
            Ok(Some(Incoming::TransportError(-404))) => panic!("seed {seed}: forged without the secret"),
            _ => wrong += 1,
        }
    }
    assert_eq!(wrong, 200);
}

#[test]
fn fake_tls_server_hello_is_bound_to_this_connection() {
    let secret = ProxySecret::from_link("ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d", false).unwrap();
    let key = secret.proxy_key();
    let (mut first, first_hello, mut rng) = client(Framing::Intermediate, Some(secret.clone()), 21);
    let (mut second, _, _) = client(Framing::Intermediate, Some(secret.clone()), 22);
    let reply = server_hello_for_tests(&first_hello, &key, &mut rng);

    assert!(matches!(
        second.receive(&reply),
        Err(TransportError::Tls(mtproto_core::transport::TlsHelloError::HashMismatch))
    ));
    assert!(!second.is_ready(), "a hello made for another connection is a replay");

    let other = ProxySecret::from_binary(&[&[0xee][..], &[1u8; 16][..], b"example.com"].concat(), false).unwrap();
    let forged = server_hello_for_tests(&first_hello, &other.proxy_key(), &mut rng);
    let (mut third, _, _) = client(Framing::Intermediate, Some(secret.clone()), 21);
    assert!(third.receive(&forged).is_err(), "a hello signed with another secret");

    for byte in &reply[..reply.len() - 1] {
        first.receive(&[*byte]).unwrap();
        assert!(!first.is_ready(), "a truncated hello is waited for, not taken");
    }
    first.receive(&reply[reply.len() - 1..]).unwrap();
    assert!(first.is_ready());
    assert!(first.has_outgoing(), "frames queued behind the hello go out once it is verified");
    assert!(
        matches!(first.receive(b"\x15\x03\x03\x00\x02\x02\x28"), Err(TransportError::InvalidTlsRecord)),
        "an alert or any record but application data ends the stream"
    );
}

fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

#[test]
fn websocket_upgrade_rejects_hostile_answers() {
    let key = [9u8; 16];
    let accept = accept_for(&base64_of(&key));
    let cases: Vec<(Vec<u8>, WsError)> = vec![
        (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), WsError::Refused(200)),
        (b"HTTP/1.1 101 OK\r\nSec-WebSocket-Protocol: binary\r\n\r\n".to_vec(), WsError::BadAccept),
        (format!("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes(), WsError::NoBinaryProtocol),
        (b"HTTP/1.1 101 \xff\xfe\r\n\r\n".to_vec(), WsError::Malformed),
        (b"SSH-2.0-x 101\r\n\r\n".to_vec(), WsError::Malformed),
        (b"HTTP/1.1 101 OK\r\nno-colon\r\n\r\n".to_vec(), WsError::Malformed),
        (b"HTTP/1.1 999999 OK\r\n\r\n".to_vec(), WsError::Malformed),
    ];
    for (wire, expected) in cases {
        let (mut handshake, _) = WsHandshake::new("h", "/apiws", key);
        let mut input = InputBuffer::new();
        input.extend(&wire);
        assert_eq!(handshake.feed(&mut input), Err(expected), "{}", String::from_utf8_lossy(&wire));
    }
    let (mut handshake, _) = WsHandshake::new("h", "/apiws", key);
    let mut input = InputBuffer::new();
    input.extend(&vec![b'a'; 17 * 1024]);
    assert_eq!(handshake.feed(&mut input), Err(WsError::Malformed), "an endless head is cut");
}

fn base64_of(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[(value >> (18 - 6 * index)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn websocket_frames_beyond_the_rules_end_the_stream() {
    let mut huge_ping = vec![0x89, 126];
    huge_ping.extend_from_slice(&200u16.to_be_bytes());
    let mut top_bit_length = vec![0x82, 127];
    top_bit_length.extend_from_slice(&(1u64 << 63).to_be_bytes());
    for (wire, expected) in [
        (huge_ping, WsError::FrameTooLong(200)),
        (top_bit_length, WsError::FrameTooLong(1 << 63)),
        (vec![0x83, 0], WsError::UnexpectedOpcode(3)),
        (vec![0x8f, 0], WsError::UnexpectedOpcode(0xf)),
        (ws_frame(0x8, b""), WsError::Closed),
    ] {
        let mut input = InputBuffer::new();
        input.extend(&wire);
        assert_eq!(WsDeframer::new().feed(&mut input, &mut Vec::new()), Err(expected));
    }
}

#[derive(Debug, Clone)]
enum WsPiece {
    Data(bool, Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

fn ws_piece() -> impl Strategy<Value = WsPiece> {
    prop_oneof![
        (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..70_000)).prop_map(|(c, d)| WsPiece::Data(c, d)),
        proptest::collection::vec(any::<u8>(), 0..=125).prop_map(WsPiece::Ping),
        proptest::collection::vec(any::<u8>(), 0..=125).prop_map(WsPiece::Pong),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn websocket_stream_is_the_data_frames_whatever_the_split(pieces in proptest::collection::vec(ws_piece(), 0..8), cuts in proptest::collection::vec(1usize..5000, 1..40)) {
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for piece in &pieces {
            match piece {
                WsPiece::Data(continuation, data) => {
                    wire.extend(ws_frame(if *continuation { 0 } else { 2 }, data));
                    expected.extend_from_slice(data);
                }
                WsPiece::Ping(data) => wire.extend(ws_frame(9, data)),
                WsPiece::Pong(data) => wire.extend(ws_frame(10, data)),
            }
        }
        let mut deframer = WsDeframer::new();
        let mut input = InputBuffer::new();
        let mut out = Vec::new();
        let mut at = 0;
        let mut cut = cuts.iter().cycle();
        while at < wire.len() {
            let end = (at + cut.next().unwrap()).min(wire.len());
            input.extend(&wire[at..end]);
            deframer.feed(&mut input, &mut out).unwrap();
            at = end;
        }
        prop_assert_eq!(out, expected);
        prop_assert!(input.is_empty());
    }

    #[test]
    fn websocket_deframer_never_panics(data in proptest::collection::vec(any::<u8>(), 0..600), step in 1usize..64) {
        let mut deframer = WsDeframer::new();
        let mut input = InputBuffer::new();
        let mut out = Vec::new();
        for chunk in data.chunks(step) {
            input.extend(chunk);
            if deframer.feed(&mut input, &mut out).is_err() {
                break;
            }
        }
        prop_assert!(out.len() <= data.len());
    }

    #[test]
    fn handshakes_and_http_never_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000), step in 1usize..300, prefix in 0usize..4) {
        let heads: [&[u8]; 4] = [b"", b"HTTP/1.1 101 OK\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", b"HTTP/1.1 100 Continue\r\n\r\n"];
        let mut wire = heads[prefix].to_vec();
        wire.extend_from_slice(&data);

        let mut reader = HttpResponseReader::new();
        let mut input = InputBuffer::new();
        for chunk in wire.chunks(step) {
            input.extend(chunk);
            match reader.read(&mut input) {
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = reader.finish();

        let (mut connect, _) = HttpConnectHandshake::new("h:1", None);
        let mut input = InputBuffer::new();
        for chunk in wire.chunks(step) {
            input.extend(chunk);
            if !matches!(connect.feed(&mut input), Ok(false)) {
                break;
            }
        }

        let (mut ws, _) = WsHandshake::new("h", "/apiws", [3; 16]);
        let mut input = InputBuffer::new();
        for chunk in wire.chunks(step) {
            input.extend(chunk);
            if !matches!(ws.feed(&mut input), Ok(false)) {
                break;
            }
        }

        let (mut socks, _) = Socks5Handshake::new(Socks5Target::Ipv4([1, 2, 3, 4], 443), None).unwrap();
        let mut input = InputBuffer::new();
        'outer: for chunk in data.chunks(step) {
            input.extend(chunk);
            loop {
                match socks.feed(&mut input) {
                    Ok(Socks5Progress::Send(_)) => continue,
                    Ok(Socks5Progress::NeedMore) => break,
                    Ok(Socks5Progress::Connected) | Err(_) => break 'outer,
                }
            }
        }
    }

    #[test]
    fn short_frames_never_become_packets_and_long_ones_never_errors(framing in prop::sample::select(FRAMINGS.to_vec()), words in 1usize..64, fill in any::<u32>()) {
        let payload: Vec<u8> = (0..words).flat_map(|_| fill.to_le_bytes()).collect();
        let mut wire = Vec::new();
        encode_frame(framing, &payload, false, &mut XorShiftRandom::new(fill as u64), &mut wire);
        let framed = if framing == Framing::Abridged { payload.len() } else { wire.len() - 4 };
        let mut input = InputBuffer::new();
        input.extend(&wire);
        let decoded = FrameDecoder::new(framing).decode(&mut input);
        let short = if framing == Framing::PaddedIntermediate { 24 } else { 16 };
        match decoded {
            Ok(Some(Incoming::Packet(_))) => prop_assert!(framed >= short),
            Ok(Some(Incoming::TransportError(_))) | Ok(Some(Incoming::Nop)) => prop_assert!(framed < short),
            Ok(Some(Incoming::QuickAck(_))) => prop_assert!(framed < short && fill == u32::MAX),
            other => prop_assert!(false, "{:?}", other),
        }
    }
}

#[test]
fn obfuscated_inits_never_look_like_another_protocol() {
    let mut rng = XorShiftRandom::new(99);
    for round in 0..2000u32 {
        let framing = FRAMINGS[round as usize % 3];
        let config = TransportConfig { framing, dc_id: -(round as i16 % 5) - 1, secret: None, unix_time: 0 };
        let mut stream = TransportStream::new(&config, &mut rng);
        stream.send_packet(&[0; 8], false, &mut rng);
        let wire = stream.take_outgoing();
        let first = u32::from_le_bytes(wire[..4].try_into().unwrap());
        assert_ne!(wire[0], 0xef);
        assert!(![0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee, 0x02010316].contains(&first));
        assert_ne!(u32::from_le_bytes(wire[4..8].try_into().unwrap()), 0);
        let accepted = accept_obfuscated_header(&wire[..64].try_into().unwrap(), None).unwrap();
        assert_eq!((accepted.framing, accepted.dc_id), (framing, config.dc_id));
    }
}
