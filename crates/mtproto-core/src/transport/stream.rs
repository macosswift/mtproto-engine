use super::TransportError;
use super::buffer::InputBuffer;
use super::codec::{FrameDecoder, Framing, Incoming, encode_frame};
use super::obfuscation::obfuscated_init;
use super::proxy_secret::ProxySecret;
use super::tls::{TlsRecordReader, TlsRecordWriter, client_hello, verify_server_hello};
use crate::crypto::{AesCtr, SecureRandom};

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub framing: Framing,
    pub dc_id: i16,
    pub secret: Option<ProxySecret>,
    pub unix_time: i32,
}

impl TransportConfig {
    pub fn effective_framing(&self) -> Framing {
        match &self.secret {
            Some(secret) if secret.use_random_padding() => Framing::PaddedIntermediate,
            _ => self.framing,
        }
    }
}

enum TlsState {
    Disabled,
    WaitingForServerHello { client_random: [u8; 32], secret: [u8; 16] },
    Established,
}

pub struct TransportStream {
    decoder: FrameDecoder,
    encryptor: AesCtr,
    decryptor: AesCtr,
    pending_header: Option<[u8; 64]>,
    tls: TlsState,
    tls_writer: Option<TlsRecordWriter>,
    tls_reader: Option<TlsRecordReader>,
    raw_input: InputBuffer,
    decrypted_input: InputBuffer,
    queued_frames: Vec<u8>,
    outgoing: Vec<u8>,
    scratch: Vec<u8>,
    framing: Framing,
}

impl TransportStream {
    pub fn new(config: &TransportConfig, rng: &mut impl SecureRandom) -> Self {
        let framing = config.effective_framing();
        let emulate_tls = config.secret.as_ref().is_some_and(ProxySecret::emulate_tls);
        let proxy_key = config.secret.as_ref().map(ProxySecret::proxy_key);
        let init = obfuscated_init(framing, config.dc_id, proxy_key.as_ref(), emulate_tls, rng);
        let mut outgoing = Vec::new();
        let tls = if emulate_tls {
            let secret = config.secret.as_ref().expect("tls requires a secret");
            let key = secret.proxy_key();
            let hello = client_hello(secret.domain().unwrap_or_default(), &key, config.unix_time, rng);
            let client_random: [u8; 32] = hello[11..43].try_into().expect("32");
            outgoing.extend_from_slice(&hello);
            TlsState::WaitingForServerHello { client_random, secret: key }
        } else {
            TlsState::Disabled
        };
        Self {
            decoder: FrameDecoder::new(framing),
            encryptor: init.encryptor,
            decryptor: init.decryptor,
            pending_header: Some(init.header),
            tls_writer: emulate_tls.then(TlsRecordWriter::new),
            tls_reader: emulate_tls.then(TlsRecordReader::new),
            tls,
            raw_input: InputBuffer::new(),
            decrypted_input: InputBuffer::new(),
            queued_frames: Vec::new(),
            outgoing,
            scratch: Vec::new(),
            framing,
        }
    }

    pub fn framing(&self) -> Framing {
        self.framing
    }

    pub fn is_ready(&self) -> bool {
        !matches!(self.tls, TlsState::WaitingForServerHello { .. })
    }

    pub fn send_packet(&mut self, payload: &[u8], quick_ack: bool, rng: &mut impl SecureRandom) {
        let start = self.queued_frames.len();
        encode_frame(self.framing, payload, quick_ack, rng, &mut self.queued_frames);
        let _ = start;
        if self.is_ready() {
            self.flush_frames();
        }
    }

    fn flush_frames(&mut self) {
        if self.queued_frames.is_empty() {
            return;
        }
        let mut frames = core::mem::take(&mut self.queued_frames);
        self.encryptor.apply(&mut frames);
        let mut chunk = Vec::with_capacity(frames.len() + 64);
        if let Some(header) = self.pending_header.take() {
            chunk.extend_from_slice(&header);
        }
        chunk.extend_from_slice(&frames);
        match &mut self.tls_writer {
            Some(writer) => writer.write(&chunk, &mut self.outgoing),
            None => self.outgoing.extend_from_slice(&chunk),
        }
        frames.clear();
        self.queued_frames = frames;
    }

    pub fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    pub fn outgoing(&self) -> &[u8] {
        &self.outgoing
    }

    pub fn consume_outgoing(&mut self, count: usize) {
        self.outgoing.drain(..count);
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<(), TransportError> {
        match &self.tls {
            TlsState::Disabled => {
                let start = self.scratch.len();
                self.scratch.extend_from_slice(data);
                self.decryptor.apply(&mut self.scratch[start..]);
                self.decrypted_input.extend(&self.scratch);
                self.scratch.clear();
                Ok(())
            }
            TlsState::WaitingForServerHello { client_random, secret } => {
                self.raw_input.extend(data);
                let (client_random, secret) = (*client_random, *secret);
                if verify_server_hello(&mut self.raw_input, &client_random, &secret)? {
                    self.tls = TlsState::Established;
                    self.flush_frames();
                    self.drain_tls_records()?;
                }
                Ok(())
            }
            TlsState::Established => {
                self.raw_input.extend(data);
                self.drain_tls_records()
            }
        }
    }

    fn drain_tls_records(&mut self) -> Result<(), TransportError> {
        let reader = self.tls_reader.as_mut().expect("tls reader");
        self.scratch.clear();
        while reader.read(&mut self.raw_input, &mut self.scratch)? {}
        if !self.scratch.is_empty() {
            self.decryptor.apply(&mut self.scratch);
            self.decrypted_input.extend(&self.scratch);
            self.scratch.clear();
        }
        Ok(())
    }

    pub fn next_incoming(&mut self) -> Result<Option<Incoming>, TransportError> {
        self.decoder.decode(&mut self.decrypted_input)
    }

    pub fn buffered_input_len(&self) -> usize {
        self.decrypted_input.len() + self.raw_input.len()
    }

    pub fn pending_frame_len(&self) -> Option<usize> {
        self.decoder.pending_frame_len(&self.decrypted_input)
    }

    pub fn pending_frame_head(&self) -> Option<(usize, &[u8])> {
        let (header, payload) = self.decoder.pending_frame(&self.decrypted_input)?;
        let data = self.decrypted_input.as_slice();
        if data.len() < header {
            return None;
        }
        let available = &data[header..data.len().min(header + payload)];
        Some((payload, available))
    }

    pub fn shrink_buffers(&mut self) {
        self.raw_input.shrink_if_idle(16 * 1024);
        self.decrypted_input.shrink_if_idle(16 * 1024);
        if self.scratch.capacity() > 64 * 1024 {
            self.scratch = Vec::new();
        }
        if self.outgoing.is_empty() && self.outgoing.capacity() > 64 * 1024 {
            self.outgoing = Vec::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;
    use crate::transport::obfuscation::accept_obfuscated_header;
    use crate::transport::tls::{server_hello_for_tests, verify_client_hello_for_tests};

    fn encrypted_payload(seed: u8, blocks: usize) -> Vec<u8> {
        let mut payload = vec![seed; 8];
        payload.extend(vec![seed.wrapping_add(1); 16 + blocks * 16]);
        payload
    }

    fn server_roundtrip(config: TransportConfig) {
        let mut rng = XorShiftRandom::new(42);
        let mut client = TransportStream::new(&config, &mut rng);
        let first = encrypted_payload(1, 2);
        let second = encrypted_payload(2, 200);
        client.send_packet(&first, false, &mut rng);
        client.send_packet(&second, true, &mut rng);

        let mut wire = client.take_outgoing();
        let emulate_tls = config.secret.as_ref().is_some_and(ProxySecret::emulate_tls);
        let key = config.secret.as_ref().map(ProxySecret::proxy_key);
        if emulate_tls {
            assert_eq!(wire.len(), 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]])));
            assert!(wire.len() >= super::super::tls::MIN_CLIENT_HELLO_LEN);
            assert_eq!(verify_client_hello_for_tests(&wire, key.as_ref().unwrap()), Some(config.unix_time));
            assert!(!client.is_ready());
            let response = server_hello_for_tests(&wire, key.as_ref().unwrap(), &mut rng);
            for chunk in response.chunks(7) {
                client.receive(chunk).unwrap();
            }
            assert!(client.is_ready());
            wire = client.take_outgoing();
            assert_eq!(&wire[..6], b"\x14\x03\x03\x00\x01\x01");
            let mut records = InputBuffer::new();
            records.extend(&wire[6..]);
            let mut reader = TlsRecordReader::new();
            let mut unwrapped = Vec::new();
            while reader.read(&mut records, &mut unwrapped).unwrap() {}
            wire = unwrapped;
        }

        let header: [u8; 64] = wire[..64].try_into().unwrap();
        let mut server = accept_obfuscated_header(&header, key.as_ref()).expect("header");
        assert_eq!(server.framing, config.effective_framing());
        assert_eq!(server.dc_id, config.dc_id);
        let mut rest = wire[64..].to_vec();
        server.decryptor.apply(&mut rest);
        let decoder = FrameDecoder::new(server.framing);
        let mut input = InputBuffer::new();
        input.extend(&rest);
        assert_eq!(decoder.decode_client_frame(&mut input).unwrap(), Some((first.clone(), false)));
        assert_eq!(decoder.decode_client_frame(&mut input).unwrap(), Some((second.clone(), true)));

        let mut reply = Vec::new();
        encode_frame(server.framing, &second, false, &mut rng, &mut reply);
        let mut quick_ack = Vec::new();
        match server.framing {
            Framing::Abridged => quick_ack.extend_from_slice(&0x8000_1234u32.to_be_bytes()),
            _ => quick_ack.extend_from_slice(&0x8000_1234u32.to_le_bytes()),
        }
        reply.extend_from_slice(&quick_ack);
        server.encryptor.apply(&mut reply);
        let reply = if emulate_tls {
            let mut writer = TlsRecordWriter::new();
            let mut out = Vec::new();
            writer.write(&reply, &mut out);
            out[6..].to_vec()
        } else {
            reply
        };
        for chunk in reply.chunks(5) {
            client.receive(chunk).unwrap();
        }
        assert_eq!(client.next_incoming().unwrap(), Some(Incoming::Packet(second)));
        assert_eq!(client.next_incoming().unwrap(), Some(Incoming::QuickAck(0x1234)));
        assert_eq!(client.next_incoming().unwrap(), None);
    }

    #[test]
    fn plain_obfuscated_abridged() {
        server_roundtrip(TransportConfig { framing: Framing::Abridged, dc_id: 2, secret: None, unix_time: 0 });
    }

    #[test]
    fn plain_obfuscated_intermediate_media_dc() {
        server_roundtrip(TransportConfig { framing: Framing::Intermediate, dc_id: -4, secret: None, unix_time: 0 });
    }

    #[test]
    fn mtproxy_simple_secret() {
        server_roundtrip(TransportConfig {
            framing: Framing::Abridged,
            dc_id: 10002,
            secret: Some(ProxySecret::from_link("00112233445566778899aabbccddeeff", false).unwrap()),
            unix_time: 0,
        });
    }

    #[test]
    fn mtproxy_padded_secret() {
        server_roundtrip(TransportConfig {
            framing: Framing::Abridged,
            dc_id: 5,
            secret: Some(ProxySecret::from_link("dd00112233445566778899aabbccddeeff", false).unwrap()),
            unix_time: 0,
        });
    }

    #[test]
    fn mtproxy_fake_tls_secret() {
        let mut raw = vec![0xee];
        raw.extend_from_slice(&[0x31; 16]);
        raw.extend_from_slice(b"telegram.org");
        server_roundtrip(TransportConfig {
            framing: Framing::Abridged,
            dc_id: 1,
            secret: Some(ProxySecret::from_binary(&raw, false).unwrap()),
            unix_time: 1_727_000_000,
        });
    }
}
