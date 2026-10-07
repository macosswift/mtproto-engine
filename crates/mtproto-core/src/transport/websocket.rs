use base64::Engine;
use sha1::{Digest, Sha1};

use super::InputBuffer;
use super::http::MAX_HEAD_LEN;

const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xa;
/// The most one outgoing frame carries; longer writes are split.
pub const WS_MAX_FRAME_PAYLOAD: usize = 64 * 1024;
/// The most one incoming frame may announce.
pub const WS_MAX_INBOUND_FRAME: u64 = 16 * 1024 * 1024;
/// The most a control frame may carry (RFC 6455 5.5); a longer one is not buffered.
pub const WS_MAX_CONTROL_PAYLOAD: u64 = 125;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WsError {
    #[error("upgrade refused with HTTP {0}")]
    Refused(u16),
    #[error("malformed upgrade response")]
    Malformed,
    #[error("upgrade response does not prove the key")]
    BadAccept,
    #[error("upgrade response without the binary subprotocol")]
    NoBinaryProtocol,
    #[error("server frame is masked")]
    MaskedServerFrame,
    #[error("frame of {0} bytes")]
    FrameTooLong(u64),
    #[error("unexpected frame opcode {0:#x}")]
    UnexpectedOpcode(u8),
    #[error("closed by the server")]
    Closed,
}

/// The client side of the WebSocket upgrade to Telegram Web's MTProto endpoint (`/apiws`). The server
/// insists on the `binary` subprotocol and answers nothing else.
#[derive(Debug)]
pub struct WsHandshake {
    accept: String,
}

impl WsHandshake {
    pub fn new(host: &str, path: &str, key: [u8; 16]) -> (Self, Vec<u8>) {
        let key = base64::engine::general_purpose::STANDARD.encode(key);
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
        );
        (Self { accept: accept_for(&key) }, request.into_bytes())
    }

    /// Ok(true) once the upgrade is done; what is left in `input` is frames.
    pub fn feed(&mut self, input: &mut InputBuffer) -> Result<bool, WsError> {
        let data = input.as_slice();
        let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
            return if data.len() > MAX_HEAD_LEN { Err(WsError::Malformed) } else { Ok(false) };
        };
        if end > MAX_HEAD_LEN {
            return Err(WsError::Malformed);
        }
        let head = std::str::from_utf8(&data[..end]).map_err(|_| WsError::Malformed)?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status: u16 = parts.next().and_then(|code| code.parse().ok()).ok_or(WsError::Malformed)?;
        if !version.starts_with("HTTP/1.") {
            return Err(WsError::Malformed);
        }
        if status != 101 {
            return Err(WsError::Refused(status));
        }
        let mut accepted = false;
        let mut binary = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(WsError::Malformed);
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accepted = value == self.accept;
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                binary = value.eq_ignore_ascii_case("binary");
            }
        }
        if !accepted {
            return Err(WsError::BadAccept);
        }
        if !binary {
            return Err(WsError::NoBinaryProtocol);
        }
        input.consume(end + 4);
        Ok(true)
    }
}

pub fn accept_for(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(ACCEPT_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Wraps `payload` in masked binary frames of at most `WS_MAX_FRAME_PAYLOAD` bytes, as a client must
/// send them. Empty payloads send nothing: an empty frame makes Telegram's server drop the connection.
pub fn encode_ws_frames(payload: &[u8], mut next_mask: impl FnMut() -> [u8; 4], out: &mut Vec<u8>) {
    for chunk in payload.chunks(WS_MAX_FRAME_PAYLOAD) {
        let mask = next_mask();
        out.push(0x80 | OPCODE_BINARY);
        let length = chunk.len();
        if length < 126 {
            out.push(0x80 | length as u8);
        } else if length <= usize::from(u16::MAX) {
            out.push(0x80 | 126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        let start = out.len();
        out.extend_from_slice(chunk);
        for (index, byte) in out[start..].iter_mut().enumerate() {
            *byte ^= mask[index & 3];
        }
    }
}

/// Server frames to the byte stream they carry. Binary and continuation frames carry the stream;
/// pings are left unanswered (a pong makes Telegram's server drop the connection), a close or a text
/// frame ends it.
#[derive(Debug, Default)]
pub struct WsDeframer {
    /// Payload bytes of the current frame still to come.
    remaining: u64,
}

impl WsDeframer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Moves every payload byte available in `input` to `out`.
    pub fn feed(&mut self, input: &mut InputBuffer, out: &mut Vec<u8>) -> Result<(), WsError> {
        loop {
            if self.remaining > 0 {
                let available = input.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
                if available == 0 {
                    return Ok(());
                }
                out.extend_from_slice(&input.as_slice()[..available]);
                input.consume(available);
                self.remaining -= available as u64;
                continue;
            }
            let data = input.as_slice();
            if data.len() < 2 {
                return Ok(());
            }
            let opcode = data[0] & 0x0f;
            if data[1] & 0x80 != 0 {
                return Err(WsError::MaskedServerFrame);
            }
            let (length, header) = match data[1] & 0x7f {
                126 => {
                    if data.len() < 4 {
                        return Ok(());
                    }
                    (u64::from(u16::from_be_bytes([data[2], data[3]])), 4)
                }
                127 => {
                    if data.len() < 10 {
                        return Ok(());
                    }
                    (u64::from_be_bytes(data[2..10].try_into().expect("8 bytes")), 10)
                }
                short => (u64::from(short), 2),
            };
            if length > WS_MAX_INBOUND_FRAME {
                return Err(WsError::FrameTooLong(length));
            }
            match opcode {
                OPCODE_BINARY | OPCODE_CONTINUATION => {
                    input.consume(header);
                    self.remaining = length;
                }
                OPCODE_PING | OPCODE_PONG if length > WS_MAX_CONTROL_PAYLOAD => {
                    return Err(WsError::FrameTooLong(length));
                }
                OPCODE_PING | OPCODE_PONG => {
                    let total = header + length as usize;
                    if data.len() < total {
                        return Ok(());
                    }
                    input.consume(total);
                }
                OPCODE_CLOSE => return Err(WsError::Closed),
                other => {
                    let _ = OPCODE_TEXT;
                    return Err(WsError::UnexpectedOpcode(other));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
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
    fn the_accept_value_of_the_rfc_example() {
        assert_eq!(accept_for("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn upgrade_request_and_response() {
        let (mut handshake, request) = WsHandshake::new("venus.web.telegram.org", "/apiws", [7u8; 16]);
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("GET /apiws HTTP/1.1\r\nHost: venus.web.telegram.org\r\n"), "{text}");
        assert!(text.contains("\r\nSec-WebSocket-Protocol: binary\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let mut input = InputBuffer::new();
        input.extend(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
        assert_eq!(handshake.feed(&mut input), Ok(false));
        input.extend(
            format!("Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: binary\r\n\r\n", accept_for(&key)).as_bytes(),
        );
        input.extend(&[0x82, 1, 9]);
        assert_eq!(handshake.feed(&mut input), Ok(true));
        assert_eq!(input.as_slice(), &[0x82, 1, 9], "frames after the head stay");

        let (mut refused, _) = WsHandshake::new("h", "/apiws", [1u8; 16]);
        let mut input = InputBuffer::new();
        input.extend(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(refused.feed(&mut input), Err(WsError::Refused(404)));

        let (mut forged, _) = WsHandshake::new("h", "/apiws", [1u8; 16]);
        let mut input = InputBuffer::new();
        input.extend(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: AAAA\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        );
        assert_eq!(forged.feed(&mut input), Err(WsError::BadAccept), "a middlebox answering 101 to anything");
    }

    #[test]
    fn an_oversized_upgrade_head_is_refused_even_when_it_arrives_whole() {
        let (mut handshake, _) = WsHandshake::new("h", "/apiws", [2u8; 16]);
        let mut input = InputBuffer::new();
        input.extend(b"HTTP/1.1 101 Switching Protocols\r\n");
        for index in 0..4096 {
            input.extend(format!("X-{index}: v\r\n").as_bytes());
        }
        input.extend(b"\r\n");
        assert_eq!(handshake.feed(&mut input), Err(WsError::Malformed));
    }

    #[test]
    fn client_frames_are_masked_binary_and_split() {
        let payload: Vec<u8> = (0..(WS_MAX_FRAME_PAYLOAD + 300)).map(|index| index as u8).collect();
        let mut out = Vec::new();
        let mut masks = 0u8;
        encode_ws_frames(
            &payload,
            || {
                masks += 1;
                [masks, 2, 3, 4]
            },
            &mut out,
        );
        assert_eq!(masks, 2, "two frames");
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x80 | 127);
        let first = u64::from_be_bytes(out[2..10].try_into().unwrap()) as usize;
        assert_eq!(first, WS_MAX_FRAME_PAYLOAD);
        let mask = [out[10], out[11], out[12], out[13]];
        let unmasked: Vec<u8> = out[14..14 + first].iter().enumerate().map(|(i, b)| b ^ mask[i & 3]).collect();
        assert_eq!(unmasked, payload[..first]);
        let second = &out[14 + first..];
        assert_eq!(second[0], 0x82);
        assert_eq!(second[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([second[2], second[3]]), 300);
        let mut empty = Vec::new();
        encode_ws_frames(&[], || [0; 4], &mut empty);
        assert!(empty.is_empty(), "never an empty frame");
    }

    #[test]
    fn server_frames_become_a_stream_whatever_the_chunking() {
        let mut wire = Vec::new();
        wire.extend(server_frame(OPCODE_BINARY, b"hello "));
        wire.extend(server_frame(OPCODE_PING, b"p"));
        wire.extend(server_frame(OPCODE_BINARY, &vec![5u8; 70_000]));
        wire.extend(server_frame(OPCODE_BINARY, &vec![6u8; 300]));
        for step in [1usize, 3, 7, 1000, wire.len()] {
            let mut deframer = WsDeframer::new();
            let mut input = InputBuffer::new();
            let mut out = Vec::new();
            for chunk in wire.chunks(step) {
                input.extend(chunk);
                deframer.feed(&mut input, &mut out).unwrap();
            }
            let mut expected = b"hello ".to_vec();
            expected.extend(vec![5u8; 70_000]);
            expected.extend(vec![6u8; 300]);
            assert_eq!(out, expected, "step {step}");
            assert!(input.is_empty());
        }
    }

    #[test]
    fn close_text_masked_and_huge_frames_end_the_stream() {
        for (wire, error) in [
            (server_frame(OPCODE_CLOSE, &[3, 232]), WsError::Closed),
            (server_frame(OPCODE_TEXT, b"x"), WsError::UnexpectedOpcode(OPCODE_TEXT)),
            (vec![0x82, 0x81, 1, 2, 3, 4, 0], WsError::MaskedServerFrame),
            (
                {
                    let mut frame = vec![0x82, 127];
                    frame.extend_from_slice(&(WS_MAX_INBOUND_FRAME + 1).to_be_bytes());
                    frame
                },
                WsError::FrameTooLong(WS_MAX_INBOUND_FRAME + 1),
            ),
            (server_frame(OPCODE_PING, &[0; 126]), WsError::FrameTooLong(126)),
            (
                {
                    let mut frame = vec![0x89, 127];
                    frame.extend_from_slice(&(2u64 << 20).to_be_bytes());
                    frame
                },
                WsError::FrameTooLong(2 << 20),
            ),
        ] {
            let mut input = InputBuffer::new();
            input.extend(&wire);
            assert_eq!(WsDeframer::new().feed(&mut input, &mut Vec::new()), Err(error));
        }
    }
}
