//! Transport and message rows of the security table: packets decode the same wherever they sit in the
//! stream, a broken stream stays broken, WebSocket streams are obfuscated and binary, and a message that
//! fails a check is dropped whole.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{Side, XorShiftRandom, aes_ige_encrypt, message_key_v2, sha256_parts};
use mtproto_core::message::{MessageError, MessageHeader, PaddingPolicy, decrypt_message, encrypt_message};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::session::{
    Now, QueryId, QueryOptions, ServerSalt, Session, SessionConfig, SessionError, SessionEvent,
};
use mtproto_core::test_support::server_peer::{
    DecodedPacket, Outgoing, ServerPeer, container, msgs_ack, new_session_created, read_vector_after_constructor,
    rpc_result, update,
};
use mtproto_core::tl::ids;
use mtproto_core::transport::{
    FrameDecoder, Framing, Incoming, InputBuffer, ProxySecret, TransportConfig, TransportError, TransportStream,
    WsDeframer, WsError, WsHandshake, accept_for, accept_obfuscated_header, encode_frame, encode_ws_frames,
    server_hello_for_tests,
};

const START: f64 = 1_727_000_000.0;

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(seed)))
}

fn server_packet(auth_key: &AuthKey, body: &[u8], rng: &mut XorShiftRandom) -> Vec<u8> {
    let header = MessageHeader { salt: 7, session_id: 11, msg_id: msg_id_for_time(START) | 1, seq_no: 1 };
    encrypt_message(auth_key, &header, body, Side::Server, PaddingPolicy::default(), rng).data
}

#[test]
fn frames_decode_to_the_same_packet_at_every_byte_offset() {
    let auth_key = key(3);
    let mut rng = XorShiftRandom::new(18);
    let body: Vec<u8> = (0..92u32).flat_map(|word| word.wrapping_mul(0x0101_0101).to_le_bytes()).collect();
    let packet = server_packet(&auth_key, &body, &mut rng);
    for framing in [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate] {
        let decoder = FrameDecoder::new(framing);
        for offset in 0..16usize {
            let mut frame = Vec::new();
            encode_frame(framing, &packet, false, &mut rng, &mut frame);
            let mut buffer = InputBuffer::new();
            buffer.extend(&vec![0xa5u8; offset]);
            buffer.extend(&frame);
            buffer.consume(offset);
            let Ok(Some(Incoming::Packet(decoded))) = decoder.decode(&mut buffer) else {
                panic!("{framing:?} at offset {offset}");
            };
            assert_eq!(decoded, packet, "{framing:?} at offset {offset}");
            assert!(buffer.is_empty());
            let message = decrypt_message(&auth_key, &decoded[..], Side::Server).expect("decrypts");
            assert_eq!(message.body(), &body[..], "{framing:?} at offset {offset}");
        }
    }
    let decoder = FrameDecoder::new(Framing::Intermediate);
    for junk in 1..4usize {
        let mut payload = packet.clone();
        payload.extend(std::iter::repeat_n(0x5au8, junk));
        let mut buffer = InputBuffer::new();
        buffer.extend(&(payload.len() as u32).to_le_bytes());
        buffer.extend(&payload);
        let Ok(Some(Incoming::Packet(decoded))) = decoder.decode(&mut buffer) else {
            panic!("{junk} trailing bytes");
        };
        assert_eq!(decoded.len() % 4, 0, "{junk} trailing bytes leave the packet unaligned");
        assert_eq!(decoded, packet);
    }
}

#[test]
fn a_broken_stream_stays_broken_and_hides_the_frames_behind_it() {
    let mut rng = XorShiftRandom::new(19);
    let mut valid = Vec::new();
    encode_frame(Framing::Intermediate, &[7u8; 88], false, &mut rng, &mut valid);
    let decoder = FrameDecoder::with_max_len(Framing::Intermediate, 1024);
    let mut buffer = InputBuffer::new();
    buffer.extend(&4096u32.to_le_bytes());
    buffer.extend(&valid);
    let length = buffer.len();
    for _ in 0..3 {
        assert_eq!(decoder.decode(&mut buffer), Err(TransportError::InvalidLength(4096)));
        assert_eq!(buffer.len(), length, "the broken header was skipped");
    }

    let mut valid = Vec::new();
    encode_frame(Framing::Abridged, &[7u8; 88], false, &mut rng, &mut valid);
    let decoder = FrameDecoder::new(Framing::Abridged);
    let mut buffer = InputBuffer::new();
    buffer.extend(&[0]);
    buffer.extend(&valid);
    for _ in 0..3 {
        assert_eq!(decoder.decode(&mut buffer), Err(TransportError::InvalidMarker(0)));
    }

    let mut wire = vec![0x88, 0x02, 0x03, 0xe8];
    wire.extend_from_slice(&[0x82, 3, b'a', b'b', b'c']);
    let mut deframer = WsDeframer::new();
    let mut input = InputBuffer::new();
    input.extend(&wire);
    let mut out = Vec::new();
    for _ in 0..3 {
        assert_eq!(deframer.feed(&mut input, &mut out), Err(WsError::Closed));
        assert!(out.is_empty(), "bytes behind the close frame reached the stream");
    }

    let mut raw = vec![0xee];
    raw.extend_from_slice(&[0x42; 16]);
    raw.extend_from_slice(b"example.com");
    let secret = ProxySecret::from_binary(&raw, true).expect("fake TLS secret");
    let proxy_key = secret.proxy_key();
    let config =
        TransportConfig { framing: Framing::Abridged, dc_id: 2, secret: Some(secret), unix_time: 1_700_000_000 };
    let mut stream = TransportStream::new(&config, &mut rng);
    let hello = stream.take_outgoing();
    stream.receive(&server_hello_for_tests(&hello, &proxy_key, &mut rng)).expect("server hello");
    assert!(stream.is_ready());
    assert_eq!(stream.receive(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]), Err(TransportError::InvalidTlsRecord));
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x40];
    record.extend_from_slice(&[0x33; 0x40]);
    for _ in 0..3 {
        assert_eq!(stream.receive(&record), Err(TransportError::InvalidTlsRecord));
        assert_eq!(stream.next_incoming(), Ok(None), "a record behind the broken one was decoded");
    }
}

fn unmask_client_frames(wire: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();
    let mut at = 0;
    while at < wire.len() {
        assert_eq!(wire[at], 0x82, "a masked binary frame with FIN");
        assert_ne!(wire[at + 1] & 0x80, 0, "client frames are masked");
        let (length, header) = match wire[at + 1] & 0x7f {
            126 => (usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]])), 4),
            127 => (u64::from_be_bytes(wire[at + 2..at + 10].try_into().unwrap()) as usize, 10),
            short => (usize::from(short), 2),
        };
        let mask = &wire[at + header..at + header + 4];
        let start = at + header + 4;
        stream.extend(wire[start..start + length].iter().enumerate().map(|(index, byte)| byte ^ mask[index & 3]));
        at = start + length;
    }
    stream
}

#[test]
fn websocket_streams_are_obfuscated_binary_and_end_on_any_close() {
    let (mut handshake, request) = WsHandshake::new("venus.web.telegram.org", "/apiws", [9u8; 16]);
    let request = String::from_utf8(request).unwrap();
    assert!(request.contains("\r\nSec-WebSocket-Protocol: binary\r\n"), "{request}");
    let key = request.split("\r\n").find_map(|line| line.strip_prefix("Sec-WebSocket-Key: ")).expect("key").to_string();
    let response = |protocol: Option<&str>| {
        let mut head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n",
            accept_for(&key)
        );
        if let Some(protocol) = protocol {
            head.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
        }
        head.push_str("\r\n");
        head
    };
    for (protocol, expected) in [(None, Err(WsError::NoBinaryProtocol)), (Some("chat"), Err(WsError::NoBinaryProtocol))]
    {
        let (mut other, _) = WsHandshake::new("venus.web.telegram.org", "/apiws", [9u8; 16]);
        let mut input = InputBuffer::new();
        input.extend(response(protocol).as_bytes());
        assert_eq!(other.feed(&mut input), expected, "{protocol:?}");
    }
    let mut input = InputBuffer::new();
    input.extend(response(Some("binary")).as_bytes());
    assert_eq!(handshake.feed(&mut input), Ok(true));

    let mut rng = XorShiftRandom::new(20);
    let payload: Vec<u8> = (0..66u32).flat_map(|word| (word | 0x6d74_7000).to_le_bytes()).collect();
    for framing in [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate] {
        let config = TransportConfig { framing, dc_id: 2, secret: None, unix_time: 0 };
        let mut client = TransportStream::new(&config, &mut rng);
        client.send_packet(&payload, false, &mut rng);
        let mut wire = Vec::new();
        let mut masks = 0u32;
        encode_ws_frames(
            &client.take_outgoing(),
            || {
                masks += 1;
                masks.to_be_bytes()
            },
            &mut wire,
        );
        let stream = unmask_client_frames(&wire);
        assert!(stream.len() > 64);
        assert_ne!(stream[0], 0xef, "{framing:?}: plain abridged prefix");
        assert!(
            ![[0xee; 4], [0xdd; 4]].contains(&<[u8; 4]>::try_from(&stream[..4]).unwrap()),
            "{framing:?}: plain intermediate prefix"
        );
        assert!(
            !stream.windows(payload.len()).any(|window| window == payload.as_slice()),
            "{framing:?}: the packet travels in the clear"
        );
        let header: [u8; 64] = stream[..64].try_into().unwrap();
        let mut server = accept_obfuscated_header(&header, None).expect("an obfuscated header");
        assert_eq!(server.framing, framing);
        assert_eq!(server.dc_id, 2);
        let mut rest = stream[64..].to_vec();
        server.decryptor.apply(&mut rest);
        let mut input = InputBuffer::new();
        input.extend(&rest);
        let decoded = FrameDecoder::new(framing).decode_client_frame(&mut input).expect("frame").expect("whole");
        assert_eq!(decoded.0, payload);
    }

    for close in
        [vec![0x88, 0x07, 0x03, 0xe8, b'b', b'y', b'e', b'!', b'!'], vec![0x88, 0x02, 0x03, 0xe9], vec![0x88, 0x00]]
    {
        let mut wire = vec![0x82, 4, 1, 2, 3, 4];
        wire.extend_from_slice(&close);
        let mut deframer = WsDeframer::new();
        let mut input = InputBuffer::new();
        input.extend(&wire);
        let mut out = Vec::new();
        assert_eq!(deframer.feed(&mut input, &mut out), Err(WsError::Closed), "{close:?}");
        assert_eq!(out, [1, 2, 3, 4], "{close:?}: the bytes before the close frame are kept");
    }
}

struct Rig {
    session: Session,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
    query: i64,
}

impl Rig {
    fn new() -> Self {
        let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 7200.0 }];
        let mut rng = XorShiftRandom::new(21);
        let now = Now { mono: 100.0, unix: START };
        let mut session = Session::new(SessionConfig::default(), key(5), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        session.send(QueryId(1), vec![0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0], QueryOptions::default(), now);
        let mut server = ServerPeer::new(key(5), START);
        server.salt = 101;
        let transmit = session.poll_transmit(now, &mut rng).expect("the query");
        let query = server
            .decode(&transmit.data)
            .messages
            .iter()
            .find(|message| message.constructor() == 0x1122_3344)
            .expect("query sent")
            .msg_id;
        let mut rig = Self { session, server, rng, now, query };
        let sync = rig.server.encode(vec![Outgoing::Service(msgs_ack(&[query]))]);
        rig.session.handle_packet(&sync, rig.now, &mut rig.rng).expect("a genuine packet");
        rig.session.drain_events();
        rig
    }

    fn feed(&mut self, packet: &[u8]) -> Result<(), SessionError> {
        self.session.handle_packet(packet, self.now, &mut self.rng)
    }

    fn assert_untouched(&mut self, what: &str) {
        let events = self.session.drain_events();
        assert!(events.is_empty(), "{what}: {events:?}");
        assert_eq!(self.session.time_difference(), 0.0, "{what} moved the clock");
        assert!(self.session.has_unanswered_queries(), "{what} completed the query");
        assert_eq!(self.session.salts().first().map(|salt| salt.salt), Some(101), "{what} changed the salt");
    }

    fn loaded_body(&self) -> Vec<u8> {
        container(&[
            (msg_id_for_time(START) | 1, 1, rpc_result(self.query, &[9, 9, 9, 9])),
            (msg_id_for_time(START) | 5, 3, update(0x0bad_0003, &[0; 4])),
            (msg_id_for_time(START) | 9, 4, new_session_created(self.query - 4, 0x5151, 0x0666)),
        ])
    }

    fn forge(&self, declared: i32, body: &[u8], padding: usize, msg_id: i64) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&101i64.to_le_bytes());
        plaintext.extend_from_slice(&self.session.session_id().to_le_bytes());
        plaintext.extend_from_slice(&msg_id.to_le_bytes());
        plaintext.extend_from_slice(&1i32.to_le_bytes());
        plaintext.extend_from_slice(&declared.to_le_bytes());
        plaintext.extend_from_slice(body);
        let unpadded = plaintext.len();
        plaintext.resize(unpadded + padding, 0x77);
        assert_eq!(plaintext.len() % 16, 0);
        let auth_key = key(5);
        let large = sha256_parts(&[&auth_key.bytes()[96..128], &plaintext]);
        let msg_key: [u8; 16] = large[8..24].try_into().unwrap();
        let material = message_key_v2(auth_key.bytes(), &msg_key, Side::Server);
        aes_ige_encrypt(&material.key, &material.iv, &mut plaintext).unwrap();
        let mut packet = auth_key.id().to_le_bytes().to_vec();
        packet.extend_from_slice(&msg_key);
        packet.extend_from_slice(&plaintext);
        packet
    }

    fn acks_after_delay(&mut self) -> Vec<i64> {
        self.now.mono += 31.0;
        self.now.unix += 31.0;
        self.server.server_time += 31.0;
        let mut packets: Vec<DecodedPacket> = Vec::new();
        while let Some(transmit) = self.session.poll_transmit(self.now, &mut self.rng) {
            packets.push(self.server.decode(&transmit.data));
            assert!(packets.len() < 50, "flush loop");
        }
        packets
            .iter()
            .flat_map(|packet| packet.messages.iter())
            .filter(|message| message.constructor() == ids::MSGS_ACK)
            .flat_map(|message| read_vector_after_constructor(&message.body))
            .collect()
    }
}

#[test]
fn a_message_failing_any_check_is_dropped_whole() {
    let mut rig = Rig::new();
    let body = rig.loaded_body();
    let mut dropped = Vec::new();

    let id = msg_id_for_time(START) | 0x101;
    let mut tampered = rig.server.seal(id, 1, &body);
    let middle = 24 + (tampered.len() - 24) / 2;
    tampered[middle] ^= 0x04;
    assert_eq!(rig.feed(&tampered), Err(SessionError::Decrypt(MessageError::MsgKeyMismatch)));
    rig.assert_untouched("a tampered packet");
    dropped.push(id);

    let id = msg_id_for_time(START) | 0x201;
    let mut stranger = ServerPeer::new(key(6), START);
    stranger.session_id = rig.session.session_id();
    let packet = stranger.seal(id, 1, &body);
    assert!(matches!(rig.feed(&packet), Err(SessionError::Decrypt(MessageError::AuthKeyMismatch { .. }))));
    rig.assert_untouched("a packet under another key");
    dropped.push(id);

    let reused = msg_id_for_time(START) | 0x301;
    let own = rig.server.session_id;
    rig.server.session_id = own.wrapping_add(1);
    let foreign = rig.server.seal(reused, 1, &body);
    rig.server.session_id = own;
    assert_eq!(rig.feed(&foreign), Err(SessionError::ForeignSession));
    rig.assert_untouched("a packet of another session");

    let even = msg_id_for_time(START) | 0x400;
    let packet = rig.server.seal(even, 1, &body);
    assert_eq!(rig.feed(&packet), Err(SessionError::EvenServerMsgId(even)));
    rig.assert_untouched("a packet with an even msg_id");

    let id = msg_id_for_time(START) | 0x501;
    let padding = (16 - (32 + body.len()) % 16) % 16 + 1040;
    let padded = rig.forge(body.len() as i32, &body, padding, id);
    assert_eq!(rig.feed(&padded), Err(SessionError::Decrypt(MessageError::InvalidPadding(padding))));
    rig.assert_untouched("a packet with too much padding");
    dropped.push(id);

    let id = msg_id_for_time(START) | 0x601;
    let padding = (16 - (32 + body.len()) % 16) % 16 + 16;
    let unaligned = rig.forge(body.len() as i32 - 2, &body, padding, id);
    assert!(matches!(rig.feed(&unaligned), Err(SessionError::Decrypt(MessageError::InvalidLength { .. }))));
    let beyond = rig.forge(body.len() as i32 + 64, &body, padding, id);
    assert!(matches!(rig.feed(&beyond), Err(SessionError::Decrypt(MessageError::InvalidLength { .. }))));
    rig.assert_untouched("a packet with a broken length");
    dropped.push(id);

    let stale = msg_id_for_time(START - 400.0) | 1;
    let quiet = container(&[
        (stale - 8, 1, update(0x0bad_0004, &[0; 4])),
        (stale - 4, 2, new_session_created(0x1000, 0x5252, 0x0777)),
    ]);
    let packet = rig.server.seal(stale, 1, &quiet);
    assert_eq!(rig.feed(&packet), Ok(()));
    rig.assert_untouched("a packet outside the time window");
    dropped.extend([stale, stale - 8, stale - 4]);

    let genuine = rig.server.seal(reused, 1, &rpc_result(rig.query, &[1, 2, 3, 4]));
    assert_eq!(rig.feed(&genuine), Ok(()));
    let events = rig.session.drain_events();
    assert!(
        events.iter().any(|event| matches!(event, SessionEvent::Result { body, .. } if body == &[1, 2, 3, 4])),
        "the genuine answer under a msg_id a dropped packet carried is taken: {events:?}"
    );
    assert!(!events.iter().any(|event| matches!(event, SessionEvent::Update { .. })), "{events:?}");
    let acked = rig.acks_after_delay();
    assert!(acked.contains(&reused), "{acked:?}");
    for id in dropped {
        assert!(!acked.contains(&id), "a dropped message {id:#x} was acknowledged: {acked:?}");
    }
}
