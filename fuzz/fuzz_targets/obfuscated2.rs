#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::transport::{
    FrameDecoder, Framing, Incoming, InputBuffer, MAX_INBOUND_FRAME_LEN, ProxySecret, TlsRecordReader, TlsRecordWriter,
    TransportConfig, TransportStream, accept_obfuscated_header, encode_frame, server_hello_for_tests,
    verify_client_hello_for_tests,
};

fn secret(cursor: &mut Cursor<'_>) -> Option<ProxySecret> {
    match cursor.u8() % 5 {
        0 | 1 => None,
        2 => ProxySecret::from_binary(cursor.bytes(16), false).ok(),
        3 => {
            let mut raw = vec![0xdd];
            raw.extend_from_slice(cursor.bytes(16));
            ProxySecret::from_binary(&raw, false).ok()
        }
        _ => {
            let mut raw = vec![0xee];
            raw.extend_from_slice(cursor.bytes(16));
            let domain = usize::from(cursor.u8());
            raw.extend_from_slice(cursor.bytes(domain));
            ProxySecret::from_binary(&raw, cursor.bool()).ok()
        }
    }
}

fn payload(cursor: &mut Cursor<'_>) -> Vec<u8> {
    let blocks = usize::from(cursor.u8() % 64);
    let mut payload = vec![0u8; 24 + blocks * 16];
    payload[..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let fill = cursor.bytes(payload.len() - 8);
    payload[8..8 + fill.len()].copy_from_slice(fill);
    payload
}

/// A client stream and a server built on accept_obfuscated_header carry each other's frames intact,
/// with every proxy secret kind, through any chunking of the wire.
fn roundtrip(cursor: &mut Cursor<'_>) {
    let framing = [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate][cursor.below(3)];
    let dc_id = cursor.u16() as i16;
    let secret = secret(cursor);
    let config = TransportConfig { framing, dc_id, secret: secret.clone(), unix_time: cursor.u32() as i32 };
    let mut rng = XorShiftRandom::new(u64::from(cursor.u32()) | 1);
    let mut client = TransportStream::new(&config, &mut rng);
    let emulate_tls = secret.as_ref().is_some_and(ProxySecret::emulate_tls);
    let key = secret.as_ref().map(ProxySecret::proxy_key);
    let mut sent = Vec::new();
    for _ in 0..(1 + cursor.u8() % 6) {
        let packet = payload(cursor);
        let quick_ack = cursor.bool();
        client.send_packet(&packet, quick_ack, &mut rng);
        sent.push((packet, quick_ack));
    }
    let mut wire = client.take_outgoing();
    if emulate_tls {
        let key = key.as_ref().expect("tls has a key");
        assert_eq!(verify_client_hello_for_tests(&wire, key), Some(config.unix_time), "hello proves the secret");
        assert!(!client.is_ready());
        let response = server_hello_for_tests(&wire, key, &mut rng);
        let mut start = 0;
        for end in split_points(cursor, response.len()) {
            client.receive(&response[start..end]).expect("a valid server hello");
            start = end;
        }
        assert!(client.is_ready());
        wire = client.take_outgoing();
        assert_eq!(&wire[..6], b"\x14\x03\x03\x00\x01\x01");
        let mut records = InputBuffer::new();
        records.extend(&wire[6..]);
        let mut reader = TlsRecordReader::new();
        let mut unwrapped = Vec::new();
        while reader.read(&mut records, &mut unwrapped).expect("own records") {}
        assert!(records.is_empty());
        wire = unwrapped;
    }
    let header: [u8; 64] = wire[..64].try_into().expect("header");
    let mut server = accept_obfuscated_header(&header, key.as_ref()).expect("own header is accepted");
    assert_eq!(server.framing, config.effective_framing());
    assert_eq!(server.dc_id, dc_id);
    let mut rest = wire[64..].to_vec();
    server.decryptor.apply(&mut rest);
    let decoder = FrameDecoder::new(server.framing);
    let mut input = InputBuffer::new();
    input.extend(&rest);
    for (packet, quick_ack) in &sent {
        assert_eq!(decoder.decode_client_frame(&mut input).expect("frame"), Some((packet.clone(), *quick_ack)));
    }
    assert!(input.is_empty());

    let mut reply = Vec::new();
    let mut expected = Vec::new();
    for (packet, _) in &sent {
        encode_frame(server.framing, packet, false, &mut rng, &mut reply);
        expected.push(Incoming::Packet(packet.clone()));
        if cursor.bool() {
            let token = cursor.u32() & 0x7fff_ffff;
            let word = 0x8000_0000 | token;
            match server.framing {
                Framing::Abridged => reply.extend_from_slice(&word.to_be_bytes()),
                _ => reply.extend_from_slice(&word.to_le_bytes()),
            }
            expected.push(Incoming::QuickAck(token));
        }
    }
    server.encryptor.apply(&mut reply);
    let reply = if emulate_tls {
        let mut out = Vec::new();
        TlsRecordWriter::new().write(&reply, &mut out);
        out[6..].to_vec()
    } else {
        reply
    };
    let mut received = Vec::new();
    let mut start = 0;
    for end in split_points(cursor, reply.len()) {
        client.receive(&reply[start..end]).expect("server bytes");
        start = end;
        while let Some(incoming) = client.next_incoming().expect("server frames") {
            received.push(incoming);
        }
    }
    assert_eq!(received, expected);
    assert_eq!(client.buffered_input_len(), 0);
}

/// Hostile bytes after the client's header: never a panic, frames stay within the inbound cap.
fn hostile(cursor: &mut Cursor<'_>) {
    let framing = [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate][cursor.below(3)];
    let secret = secret(cursor);
    let config = TransportConfig { framing, dc_id: 2, secret, unix_time: 0 };
    let mut rng = XorShiftRandom::new(9);
    let mut client = TransportStream::new(&config, &mut rng);
    let wire = cursor.chunk().to_vec();
    let mut start = 0;
    for end in split_points(cursor, wire.len()) {
        if client.receive(&wire[start..end]).is_err() {
            return;
        }
        start = end;
        loop {
            match client.next_incoming() {
                Ok(Some(Incoming::Packet(packet))) => assert!(packet.len() <= MAX_INBOUND_FRAME_LEN),
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
        let _ = client.pending_frame_len();
        let _ = client.pending_frame_head();
    }
    let header: Option<[u8; 64]> = wire.get(..64).and_then(|head| head.try_into().ok());
    if let Some(header) = header
        && let Some(server) = accept_obfuscated_header(&header, None)
    {
        assert!(matches!(server.framing, Framing::Abridged | Framing::Intermediate | Framing::PaddedIntermediate));
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    if cursor.u8() & 1 == 0 {
        roundtrip(&mut cursor);
    } else {
        hostile(&mut cursor);
    }
});
