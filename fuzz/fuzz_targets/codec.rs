#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::transport::{
    FrameDecoder, Framing, Incoming, InputBuffer, SHORT_FRAME_LEN, SHORT_PADDED_FRAME_LEN, encode_frame,
    trim_padded_payload,
};

const MAX_LEN: usize = 1 << 16;

fn framing(byte: u8) -> Framing {
    [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate][usize::from(byte % 3)]
}

/// Hostile server bytes: every frame decoded is within limits, and the decoder never waits on
/// more than one frame's worth of buffered input.
fn hostile(cursor: &mut Cursor<'_>) {
    let framing = framing(cursor.u8());
    let client_side = cursor.bool();
    let decoder = FrameDecoder::with_max_len(framing, MAX_LEN);
    let wire = cursor.chunk().to_vec();
    let points = split_points(cursor, wire.len());
    let mut input = InputBuffer::new();
    let mut start = 0;
    for end in points {
        input.extend(&wire[start..end]);
        start = end;
        loop {
            let before = input.len();
            if client_side {
                match decoder.decode_client_frame(&mut input) {
                    Ok(Some((payload, _))) => assert!(payload.len() <= MAX_LEN && !payload.is_empty()),
                    Ok(None) => break,
                    Err(_) => return,
                }
            } else {
                let pending = decoder.pending_frame_len(&input);
                match decoder.decode(&mut input) {
                    Ok(Some(incoming)) => {
                        let consumed = before - input.len();
                        assert!(consumed > 0);
                        if let Some(pending) = pending {
                            assert_eq!(pending, consumed, "pending_frame_len names the frame decode takes");
                        }
                        if let Incoming::Packet(packet) = incoming {
                            let short = if framing == Framing::PaddedIntermediate {
                                SHORT_PADDED_FRAME_LEN
                            } else {
                                SHORT_FRAME_LEN
                            };
                            assert!(packet.len() <= MAX_LEN);
                            if framing == Framing::PaddedIntermediate {
                                assert!(packet.len() >= 20, "padded packet of {} bytes", packet.len());
                            } else {
                                assert!(packet.len() >= short && packet.len().is_multiple_of(4));
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
        }
        assert!(input.len() <= MAX_LEN + 4, "decoder waits on {} bytes", input.len());
    }
}

/// Frames made by encode_frame decode to their payloads, whatever the chunking: client frames (with
/// quick-ack requests) on the server side, and server frames (never flagged) on the client side.
fn roundtrip(cursor: &mut Cursor<'_>) {
    let framing = framing(cursor.u8());
    let mut rng = XorShiftRandom::new(u64::from(cursor.u32()));
    let mut to_server = Vec::new();
    let mut to_client = Vec::new();
    let mut sent = Vec::new();
    while !cursor.is_empty() && sent.len() < 64 {
        let quick_ack = cursor.bool();
        let length = usize::from(cursor.u16()) % 4096 / 4 * 4;
        let mut payload = vec![0u8; length.max(24)];
        payload[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        let fill = cursor.bytes(payload.len() - 8);
        payload[8..8 + fill.len()].copy_from_slice(fill);
        if framing == Framing::PaddedIntermediate {
            payload.truncate(24 + (payload.len() - 24) / 16 * 16);
        }
        encode_frame(framing, &payload, quick_ack, &mut rng, &mut to_server);
        encode_frame(framing, &payload, false, &mut rng, &mut to_client);
        sent.push((payload, quick_ack));
    }
    let decoder = FrameDecoder::new(framing);
    let mut as_server = Vec::new();
    let mut input = InputBuffer::new();
    let mut start = 0;
    for end in split_points(cursor, to_server.len()) {
        input.extend(&to_server[start..end]);
        start = end;
        while let Some(frame) = decoder.decode_client_frame(&mut input).expect("own frames decode") {
            as_server.push(frame);
        }
    }
    assert_eq!(as_server, sent);
    assert!(input.is_empty());
    let mut as_client = Vec::new();
    let mut start = 0;
    for end in split_points(cursor, to_client.len()) {
        input.extend(&to_client[start..end]);
        start = end;
        while let Some(incoming) = decoder.decode(&mut input).expect("own frames decode") {
            as_client.push(incoming);
        }
    }
    let expected: Vec<Incoming> = sent.iter().map(|(payload, _)| Incoming::Packet(payload.clone())).collect();
    assert_eq!(as_client, expected);
    assert!(input.is_empty());
    if framing == Framing::PaddedIntermediate {
        for (payload, _) in &sent {
            assert_eq!(trim_padded_payload(payload), payload.len());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    if cursor.u8() & 1 == 0 {
        hostile(&mut cursor);
    } else {
        roundtrip(&mut cursor);
    }
});
