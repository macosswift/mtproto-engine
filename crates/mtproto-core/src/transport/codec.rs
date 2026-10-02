use super::TransportError;
use super::buffer::InputBuffer;
use crate::crypto::SecureRandom;

pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const QUICK_ACK_BIT: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framing {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl Framing {
    pub fn tag(self) -> u32 {
        match self {
            Framing::Abridged => 0xefefefef,
            Framing::Intermediate => 0xeeeeeeee,
            Framing::PaddedIntermediate => 0xdddddddd,
        }
    }

    pub fn plain_prefix(self) -> &'static [u8] {
        match self {
            Framing::Abridged => &[0xef],
            Framing::Intermediate => &[0xee, 0xee, 0xee, 0xee],
            Framing::PaddedIntermediate => &[0xdd, 0xdd, 0xdd, 0xdd],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Packet(Vec<u8>),
    QuickAck(u32),
    TransportError(i32),
    Nop,
}

pub fn encode_frame(framing: Framing, payload: &[u8], quick_ack: bool, rng: &mut impl SecureRandom, out: &mut Vec<u8>) {
    assert!(payload.len().is_multiple_of(4), "payload must be 4-byte aligned");
    assert!(payload.len() < MAX_FRAME_LEN, "payload too large");
    match framing {
        Framing::Abridged => {
            let quarter = payload.len() / 4;
            let ack = if quick_ack { 0x80 } else { 0 };
            if quarter < 0x7f {
                out.push(quarter as u8 | ack);
            } else {
                out.push(0x7f | ack);
                out.extend_from_slice(&(quarter as u32).to_le_bytes()[..3]);
            }
            out.extend_from_slice(payload);
        }
        Framing::Intermediate => {
            let mut length = payload.len() as u32;
            if quick_ack {
                length |= QUICK_ACK_BIT;
            }
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(payload);
        }
        Framing::PaddedIntermediate => {
            let padding = (rng.next_u32() % 16) as usize;
            let mut length = (payload.len() + padding) as u32;
            if quick_ack {
                length |= QUICK_ACK_BIT;
            }
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(payload);
            let start = out.len();
            out.resize(start + padding, 0);
            rng.fill(&mut out[start..]);
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameDecoder {
    framing: Framing,
    max_len: usize,
}

impl FrameDecoder {
    pub fn new(framing: Framing) -> Self {
        Self { framing, max_len: MAX_FRAME_LEN }
    }

    pub fn with_max_len(framing: Framing, max_len: usize) -> Self {
        Self { framing, max_len }
    }

    pub fn framing(&self) -> Framing {
        self.framing
    }

    pub fn pending_frame(&self, buffer: &InputBuffer) -> Option<(usize, usize)> {
        let data = buffer.as_slice();
        match self.framing {
            Framing::Abridged => {
                let first = *data.first()?;
                if first & 0x80 != 0 {
                    return None;
                }
                if first < 0x7f {
                    Some((1, first as usize * 4))
                } else if data.len() >= 4 {
                    Some((4, u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize * 4))
                } else {
                    None
                }
            }
            Framing::Intermediate | Framing::PaddedIntermediate => {
                if data.len() < 4 {
                    return None;
                }
                let word = u32::from_le_bytes(data[..4].try_into().expect("4"));
                if word & QUICK_ACK_BIT != 0 { None } else { Some((4, word as usize)) }
            }
        }
    }

    pub fn pending_frame_len(&self, buffer: &InputBuffer) -> Option<usize> {
        let data = buffer.as_slice();
        match self.framing {
            Framing::Abridged => {
                let first = *data.first()?;
                if first & 0x80 != 0 {
                    return Some(4);
                }
                if first < 0x7f {
                    Some(1 + first as usize * 4)
                } else if data.len() >= 4 {
                    Some(4 + (u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize) * 4)
                } else {
                    None
                }
            }
            Framing::Intermediate | Framing::PaddedIntermediate => {
                if data.len() < 4 {
                    return None;
                }
                let word = u32::from_le_bytes(data[..4].try_into().expect("4"));
                if word & QUICK_ACK_BIT != 0 { Some(4) } else { Some(4 + word as usize) }
            }
        }
    }

    pub fn decode(&self, buffer: &mut InputBuffer) -> Result<Option<Incoming>, TransportError> {
        let data = buffer.as_slice();
        match self.framing {
            Framing::Abridged => {
                let Some(&first) = data.first() else {
                    return Ok(None);
                };
                if first & 0x80 != 0 {
                    if data.len() < 4 {
                        return Ok(None);
                    }
                    let token = u32::from_be_bytes(data[..4].try_into().expect("4")) & !QUICK_ACK_BIT;
                    buffer.consume(4);
                    return Ok(Some(Incoming::QuickAck(token)));
                }
                let (header, length) = if first < 0x7f {
                    if first == 0 {
                        return Err(TransportError::InvalidMarker(first));
                    }
                    (1usize, first as usize * 4)
                } else {
                    if data.len() < 4 {
                        return Ok(None);
                    }
                    let quarter = u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize;
                    if quarter == 0 {
                        return Err(TransportError::InvalidLength(0));
                    }
                    (4usize, quarter * 4)
                };
                if length > self.max_len {
                    return Err(TransportError::InvalidLength(length as u64));
                }
                if data.len() < header + length {
                    return Ok(None);
                }
                buffer.consume(header);
                let payload = buffer.take(length);
                Ok(Some(classify(payload, false)))
            }
            Framing::Intermediate | Framing::PaddedIntermediate => {
                if data.len() < 4 {
                    return Ok(None);
                }
                let word = u32::from_le_bytes(data[..4].try_into().expect("4"));
                if word & QUICK_ACK_BIT != 0 {
                    buffer.consume(4);
                    return Ok(Some(Incoming::QuickAck(word & !QUICK_ACK_BIT)));
                }
                let length = word as usize;
                if length < 4 || length > self.max_len {
                    return Err(TransportError::InvalidLength(length as u64));
                }
                if data.len() < 4 + length {
                    return Ok(None);
                }
                buffer.consume(4);
                let payload = buffer.take(length);
                Ok(Some(classify(payload, self.framing == Framing::PaddedIntermediate)))
            }
        }
    }
}

impl FrameDecoder {
    pub fn decode_client_frame(&self, buffer: &mut InputBuffer) -> Result<Option<(Vec<u8>, bool)>, TransportError> {
        let data = buffer.as_slice();
        match self.framing {
            Framing::Abridged => {
                let Some(&first) = data.first() else {
                    return Ok(None);
                };
                let quick_ack = first & 0x80 != 0;
                let marker = first & 0x7f;
                let (header, length) = if marker < 0x7f {
                    (1usize, marker as usize * 4)
                } else {
                    if data.len() < 4 {
                        return Ok(None);
                    }
                    (4usize, u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize * 4)
                };
                if length == 0 || length > self.max_len {
                    return Err(TransportError::InvalidLength(length as u64));
                }
                if data.len() < header + length {
                    return Ok(None);
                }
                buffer.consume(header);
                Ok(Some((buffer.take(length), quick_ack)))
            }
            Framing::Intermediate | Framing::PaddedIntermediate => {
                if data.len() < 4 {
                    return Ok(None);
                }
                let word = u32::from_le_bytes(data[..4].try_into().expect("4"));
                let quick_ack = word & QUICK_ACK_BIT != 0;
                let length = (word & !QUICK_ACK_BIT) as usize;
                if length < 4 || length > self.max_len {
                    return Err(TransportError::InvalidLength(length as u64));
                }
                if data.len() < 4 + length {
                    return Ok(None);
                }
                buffer.consume(4);
                let mut payload = buffer.take(length);
                if self.framing == Framing::PaddedIntermediate {
                    let trimmed = trim_padded_payload(&payload);
                    payload.truncate(trimmed);
                }
                Ok(Some((payload, quick_ack)))
            }
        }
    }
}

pub const SHORT_FRAME_LEN: usize = 16;
pub const SHORT_PADDED_FRAME_LEN: usize = 24;

fn classify(mut payload: Vec<u8>, padded: bool) -> Incoming {
    let short_limit = if padded { SHORT_PADDED_FRAME_LEN } else { SHORT_FRAME_LEN };
    if payload.len() < short_limit {
        if payload.len() < 4 {
            return Incoming::Nop;
        }
        let header = u32::from_le_bytes(payload[..4].try_into().expect("4"));
        if header == 0xffff_ffff && payload.len() >= 8 {
            let word = u32::from_le_bytes(payload[4..8].try_into().expect("4"));
            return Incoming::QuickAck(word & !QUICK_ACK_BIT);
        }
        return match header as i32 {
            0 => Incoming::Nop,
            code => Incoming::TransportError(code),
        };
    }
    if padded {
        let trimmed = trim_padded_payload(&payload);
        payload.truncate(trimmed);
    } else if !payload.len().is_multiple_of(4) {
        let aligned = payload.len() & !3;
        payload.truncate(aligned);
    }
    Incoming::Packet(payload)
}

pub fn trim_padded_payload(payload: &[u8]) -> usize {
    if payload.len() < 8 {
        return payload.len() & !3;
    }
    let auth_key_id = u64::from_le_bytes(payload[..8].try_into().expect("8"));
    if auth_key_id == 0 {
        if payload.len() >= 20 {
            let declared = u32::from_le_bytes(payload[16..20].try_into().expect("4")) as usize;
            if declared <= payload.len() - 20 {
                return 20 + declared;
            }
        }
        return payload.len() & !3;
    }
    if payload.len() < 24 {
        return payload.len() & !3;
    }
    24 + (payload.len() - 24) / 16 * 16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;
    use proptest::prelude::*;

    fn roundtrip(framing: Framing, payload: &[u8], quick_ack: bool) -> Vec<u8> {
        let mut rng = XorShiftRandom::new(payload.len() as u64);
        let mut out = Vec::new();
        encode_frame(framing, payload, quick_ack, &mut rng, &mut out);
        out
    }

    #[test]
    fn abridged_short_and_long_headers() {
        let short = roundtrip(Framing::Abridged, &[0u8; 8], false);
        assert_eq!(short[0], 2);
        assert_eq!(short.len(), 9);
        let long = roundtrip(Framing::Abridged, &[0u8; 127 * 4], false);
        assert_eq!(&long[..4], &[0x7f, 127, 0, 0]);
        let ack = roundtrip(Framing::Abridged, &[0u8; 8], true);
        assert_eq!(ack[0], 0x82);
        let long_ack = roundtrip(Framing::Abridged, &[0u8; 1024], true);
        assert_eq!(&long_ack[..4], &[0xff, 0, 1, 0]);
    }

    #[test]
    fn intermediate_header() {
        let frame = roundtrip(Framing::Intermediate, &[1u8; 12], true);
        assert_eq!(&frame[..4], &(12u32 | 0x8000_0000).to_le_bytes());
        assert_eq!(frame.len(), 16);
    }

    #[test]
    fn abridged_quick_ack_is_big_endian() {
        let mut buffer = InputBuffer::new();
        buffer.extend(&[0x81, 0x02, 0x03, 0x04]);
        let decoder = FrameDecoder::new(Framing::Abridged);
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::QuickAck(0x01020304)));
        assert!(buffer.is_empty());
    }

    #[test]
    fn intermediate_quick_ack_and_error() {
        let decoder = FrameDecoder::new(Framing::Intermediate);
        let mut buffer = InputBuffer::new();
        buffer.extend(&(0x8123_4567u32).to_le_bytes());
        buffer.extend(&4u32.to_le_bytes());
        buffer.extend(&(-404i32).to_le_bytes());
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::QuickAck(0x0123_4567)));
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::TransportError(-404)));
        assert_eq!(decoder.decode(&mut buffer).unwrap(), None);
    }

    #[test]
    fn abridged_transport_error() {
        let decoder = FrameDecoder::new(Framing::Abridged);
        let mut buffer = InputBuffer::new();
        buffer.extend(&[1]);
        buffer.extend(&(-429i32).to_le_bytes());
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::TransportError(-429)));
    }

    #[test]
    fn padded_error_and_ffff_quick_ack() {
        let decoder = FrameDecoder::new(Framing::PaddedIntermediate);
        let mut buffer = InputBuffer::new();
        let mut error = (-444i32).to_le_bytes().to_vec();
        error.extend_from_slice(&[9u8; 7]);
        buffer.extend(&(error.len() as u32).to_le_bytes());
        buffer.extend(&error);
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::TransportError(-444)));
        let mut ack = 0xffff_ffffu32.to_le_bytes().to_vec();
        ack.extend_from_slice(&0x8000_00ffu32.to_le_bytes());
        buffer.extend(&(ack.len() as u32).to_le_bytes());
        buffer.extend(&ack);
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::QuickAck(0xff)));
    }

    #[test]
    fn short_frames_follow_tdlib_classification() {
        let decoder = FrameDecoder::new(Framing::Intermediate);
        let frame = |payload: &[u8]| {
            let mut buffer = InputBuffer::new();
            buffer.extend(&(payload.len() as u32).to_le_bytes());
            buffer.extend(payload);
            decoder.decode(&mut buffer).unwrap().unwrap()
        };
        assert_eq!(frame(&0u32.to_le_bytes()), Incoming::Nop);
        assert_eq!(frame(&[0u8; 12]), Incoming::Nop);
        assert_eq!(frame(&(-444i32).to_le_bytes()), Incoming::TransportError(-444));
        assert_eq!(frame(&(-403i32).to_le_bytes()), Incoming::TransportError(-403));
        assert_eq!(frame(&(-1234i32).to_le_bytes()), Incoming::TransportError(-1234));
        assert_eq!(frame(&7i32.to_le_bytes()), Incoming::TransportError(7));
        let mut with_slack = (-429i32).to_le_bytes().to_vec();
        with_slack.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(frame(&with_slack), Incoming::TransportError(-429));
        let mut http_ack = 0xffff_ffffu32.to_le_bytes().to_vec();
        http_ack.extend_from_slice(&0x8000_0042u32.to_le_bytes());
        assert_eq!(frame(&http_ack), Incoming::QuickAck(0x42));
    }

    #[test]
    fn long_frames_are_packets_even_with_suspicious_prefixes() {
        let decoder = FrameDecoder::new(Framing::Intermediate);
        for prefix in [0xffff_ffffu32, 0, (-404i32) as u32] {
            let mut payload = prefix.to_le_bytes().to_vec();
            payload.resize(24 + 48, 9);
            let mut buffer = InputBuffer::new();
            buffer.extend(&(payload.len() as u32).to_le_bytes());
            buffer.extend(&payload);
            assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::Packet(payload)));
        }
    }

    #[test]
    fn abridged_nop_and_long_quick_ack() {
        let decoder = FrameDecoder::new(Framing::Abridged);
        let mut buffer = InputBuffer::new();
        buffer.extend(&[1, 0, 0, 0, 0]);
        buffer.extend(&[0xff, 0xee, 0xdd, 0xcc]);
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::Nop));
        assert_eq!(decoder.decode(&mut buffer).unwrap(), Some(Incoming::QuickAck(0x7feeddcc)));
        assert!(buffer.is_empty());
    }

    #[test]
    fn rejects_bad_lengths() {
        let decoder = FrameDecoder::with_max_len(Framing::Intermediate, 1024);
        let mut buffer = InputBuffer::new();
        buffer.extend(&2048u32.to_le_bytes());
        assert_eq!(decoder.decode(&mut buffer), Err(TransportError::InvalidLength(2048)));
        let mut buffer = InputBuffer::new();
        buffer.extend(&0u32.to_le_bytes());
        assert!(decoder.decode(&mut buffer).is_err());
        let decoder = FrameDecoder::new(Framing::Abridged);
        let mut buffer = InputBuffer::new();
        buffer.extend(&[0]);
        assert!(decoder.decode(&mut buffer).is_err());
        let mut buffer = InputBuffer::new();
        buffer.extend(&[0x7f, 0, 0, 0]);
        assert!(decoder.decode(&mut buffer).is_err());
    }

    #[test]
    fn padded_trim_uses_inner_structure() {
        let mut encrypted = vec![1u8; 24 + 64];
        encrypted.extend_from_slice(&[0u8; 13]);
        assert_eq!(trim_padded_payload(&encrypted), 24 + 64);
        let mut plain = vec![0u8; 8];
        plain.extend_from_slice(&5i64.to_le_bytes());
        plain.extend_from_slice(&8u32.to_le_bytes());
        plain.extend_from_slice(&[7u8; 8]);
        plain.extend_from_slice(&[3u8; 11]);
        assert_eq!(trim_padded_payload(&plain), 28);
    }

    #[test]
    fn server_side_decoding_keeps_quick_ack_requests() {
        let mut rng = XorShiftRandom::new(1);
        for framing in [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate] {
            let mut wire = Vec::new();
            let payload = vec![0u8; 20].into_iter().chain(4u32.to_le_bytes()).chain([1u8; 4]).collect::<Vec<u8>>();
            let mut plain = vec![0u8; 16];
            plain.extend_from_slice(&4u32.to_le_bytes());
            plain.extend_from_slice(&[1u8; 4]);
            let _ = payload;
            encode_frame(framing, &plain, true, &mut rng, &mut wire);
            encode_frame(framing, &plain, false, &mut rng, &mut wire);
            let decoder = FrameDecoder::new(framing);
            let mut buffer = InputBuffer::new();
            buffer.extend(&wire);
            assert_eq!(decoder.decode_client_frame(&mut buffer).unwrap(), Some((plain.clone(), true)));
            assert_eq!(decoder.decode_client_frame(&mut buffer).unwrap(), Some((plain.clone(), false)));
            assert!(buffer.is_empty());
        }
    }

    proptest! {
        #[test]
        fn decode_any_split(words in proptest::collection::vec(proptest::collection::vec(any::<u32>(), 2..300), 1..6), framing in prop::sample::select(vec![Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate]), split in 1usize..64, quick in any::<bool>()) {
            let mut rng = XorShiftRandom::new(7);
            let mut wire = Vec::new();
            let mut payloads = Vec::new();
            for packet in &words {
                let mut payload: Vec<u8> = 1u64.to_le_bytes().to_vec();
                payload.extend(vec![0u8; 16]);
                payload.extend(packet.iter().flat_map(|w| w.to_le_bytes()));
                let aligned = 24 + (payload.len() - 24) / 16 * 16;
                payload.truncate(aligned.max(24 + 16));
                payload.resize(aligned.max(24 + 16), 0);
                encode_frame(framing, &payload, quick, &mut rng, &mut wire);
                payloads.push(payload);
            }
            let decoder = FrameDecoder::new(framing);
            let mut buffer = InputBuffer::new();
            let mut decoded = Vec::new();
            for chunk in wire.chunks(split) {
                buffer.extend(chunk);
                while let Some((payload, quick_ack)) = decoder.decode_client_frame(&mut buffer).unwrap() {
                    prop_assert_eq!(quick_ack, quick);
                    decoded.push(payload);
                }
            }
            prop_assert_eq!(&decoded, &payloads);
            prop_assert!(buffer.is_empty());

            let mut downstream = Vec::new();
            for payload in &payloads {
                encode_frame(framing, payload, false, &mut rng, &mut downstream);
            }
            let mut buffer = InputBuffer::new();
            let mut received = Vec::new();
            for chunk in downstream.chunks(split) {
                buffer.extend(chunk);
                while let Some(item) = decoder.decode(&mut buffer).unwrap() {
                    if let Incoming::Packet(p) = item {
                        received.push(p);
                    }
                }
            }
            prop_assert_eq!(received, payloads);
        }

        #[test]
        fn decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..300), framing in prop::sample::select(vec![Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate])) {
            let decoder = FrameDecoder::with_max_len(framing, 4096);
            let mut buffer = InputBuffer::new();
            buffer.extend(&data);
            for _ in 0..64 {
                match decoder.decode(&mut buffer) {
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
        }
    }
}
