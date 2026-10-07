#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::transport::{
    InputBuffer, MAX_HEAD_LEN, WS_MAX_INBOUND_FRAME, WsDeframer, WsError, WsHandshake, accept_for, encode_ws_frames,
};

fn server_frame(opcode: u8, fin: bool, payload: &[u8], long_form: bool, out: &mut Vec<u8>) {
    out.push(if fin { 0x80 } else { 0 } | opcode);
    if payload.len() < 126 && !long_form {
        out.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
}

fn upgrade_response(key: [u8; 16]) -> Vec<u8> {
    let encoded = {
        let (_, request) = WsHandshake::new("h", "/apiws", key);
        let text = String::from_utf8(request).expect("ascii");
        let line = text.lines().find(|line| line.starts_with("Sec-WebSocket-Key: ")).expect("key").to_string();
        line["Sec-WebSocket-Key: ".len()..].to_string()
    };
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        accept_for(&encoded)
    )
    .into_bytes()
}

fn run_deframer(wire: &[u8], points: &[usize]) -> (Vec<u8>, Result<(), WsError>, usize) {
    let mut deframer = WsDeframer::new();
    let mut input = InputBuffer::new();
    let mut out = Vec::new();
    let mut start = 0;
    for &end in points {
        input.extend(&wire[start..end]);
        start = end;
        if let Err(error) = deframer.feed(&mut input, &mut out) {
            return (out, Err(error), input.len());
        }
        assert!(input.len() <= 10 + 125, "deframer holds {} bytes back", input.len());
    }
    (out, Ok(()), input.len())
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match cursor.u8() % 3 {
        0 => {
            let key: [u8; 16] = core::array::from_fn(|_| cursor.u8());
            let (mut handshake, _) = WsHandshake::new("venus.web.telegram.org", "/apiws", key);
            let mut wire = if cursor.bool() { upgrade_response(key) } else { Vec::new() };
            wire.extend_from_slice(cursor.chunk());
            let points = split_points(&mut cursor, wire.len());
            let mut input = InputBuffer::new();
            let mut start = 0;
            for end in points {
                input.extend(&wire[start..end]);
                start = end;
                match handshake.feed(&mut input) {
                    Ok(true) => {
                        let rest = input.as_slice().to_vec();
                        let points: Vec<usize> = (1..=rest.len()).collect();
                        let _ = run_deframer(&rest, &points);
                        return;
                    }
                    Ok(false) => assert!(input.len() <= MAX_HEAD_LEN, "unbounded head"),
                    Err(_) => return,
                }
            }
        }
        1 => {
            let wire = cursor.chunk().to_vec();
            let points = split_points(&mut cursor, wire.len());
            let (out, _, _) = run_deframer(&wire, &points);
            assert!(out.len() <= wire.len());
        }
        _ => {
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            while !cursor.is_empty() && wire.len() < 1 << 20 {
                let kind = cursor.u8();
                let payload = cursor.chunk().to_vec();
                match kind % 4 {
                    0 | 1 => {
                        server_frame(
                            if kind & 4 != 0 { 0x0 } else { 0x2 },
                            kind & 8 != 0,
                            &payload,
                            kind & 16 != 0,
                            &mut wire,
                        );
                        expected.extend_from_slice(&payload);
                    }
                    2 => server_frame(0x9, true, &payload[..payload.len().min(125)], false, &mut wire),
                    _ => server_frame(0xa, true, &payload[..payload.len().min(125)], false, &mut wire),
                }
            }
            let points = split_points(&mut cursor, wire.len());
            let (out, result, left) = run_deframer(&wire, &points);
            assert_eq!(result, Ok(()));
            assert_eq!(out, expected, "the stream survives any chunking");
            assert_eq!(left, 0);
            let mut client = Vec::new();
            let mut mask = 0u8;
            encode_ws_frames(
                &expected,
                || {
                    mask = mask.wrapping_add(1);
                    [mask, 7, 3, 1]
                },
                &mut client,
            );
            let frames = expected.len().div_ceil(64 * 1024);
            assert_eq!(usize::from(mask), frames % 256);
            let framing: usize = expected
                .chunks(64 * 1024)
                .map(|chunk| match chunk.len() {
                    0..126 => 6,
                    126..=65535 => 8,
                    _ => 14,
                })
                .sum();
            assert_eq!(client.len(), expected.len() + framing);
            assert!(expected.len() as u64 <= WS_MAX_INBOUND_FRAME);
        }
    }
});
