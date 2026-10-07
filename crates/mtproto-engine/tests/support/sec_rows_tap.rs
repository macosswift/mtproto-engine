//! A passive tap between the engine and a test server: bytes pass unchanged both ways, and the client's
//! frames are read on the side (without a proxy secret the obfuscation keys travel in the clear), so a
//! test can decrypt them with the keys it knows and see what went to the server, under which key and salt.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtproto_core::auth_key::AuthKey;
use mtproto_core::message::read_auth_key_id;
use mtproto_core::test_support::server_peer::ServerPeer;
use mtproto_core::tl::mtproto::gunzip;
use mtproto_core::tl::{Reader, ids};
use mtproto_core::transport::{FrameDecoder, InputBuffer, accept_obfuscated_header};

pub struct Tap {
    pub address: SocketAddr,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl Tap {
    pub fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accept_frames = frames.clone();
        let accept_stop = stop.clone();
        std::thread::spawn(move || {
            while !accept_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let frames = accept_frames.clone();
                        let stop = accept_stop.clone();
                        std::thread::spawn(move || {
                            let _ = relay(stream, upstream, frames, stop);
                        });
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Self { address, frames, stop }
    }

    /// Every frame the client sent so far, in the order the tap read them.
    pub fn client_frames(&self) -> Vec<Vec<u8>> {
        self.frames.lock().unwrap().clone()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn relay(
    mut client: TcpStream,
    upstream: SocketAddr,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut header = [0u8; 64];
    client.read_exact(&mut header)?;
    let Some(observed) = accept_obfuscated_header(&header, None) else {
        return Ok(());
    };
    let mut server = TcpStream::connect(upstream)?;
    server.set_nodelay(true)?;
    client.set_nodelay(true)?;
    server.write_all(&header)?;

    let mut server_reader = server.try_clone()?;
    let mut client_writer = client.try_clone()?;
    let down_stop = stop.clone();
    server_reader.set_read_timeout(Some(Duration::from_millis(20)))?;
    let down = std::thread::spawn(move || {
        let mut chunk = [0u8; 16384];
        while !down_stop.load(Ordering::Relaxed) {
            match server_reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    if client_writer.write_all(&chunk[..read]).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        let _ = client_writer.shutdown(Shutdown::Both);
    });

    let mut decryptor = observed.decryptor;
    let decoder = FrameDecoder::new(observed.framing);
    let mut buffer = InputBuffer::new();
    let mut chunk = [0u8; 16384];
    client.set_read_timeout(Some(Duration::from_millis(20)))?;
    while !stop.load(Ordering::Relaxed) {
        match client.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if server.write_all(&chunk[..read]).is_err() {
                    break;
                }
                let mut data = chunk[..read].to_vec();
                decryptor.apply(&mut data);
                buffer.extend(&data);
                while let Ok(Some((payload, _))) = decoder.decode_client_frame(&mut buffer) {
                    frames.lock().unwrap().push(payload);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    let _ = server.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    let _ = down.join();
    Ok(())
}

/// One encrypted client packet, opened with a key the test knew.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Opened {
    pub key_id: u64,
    pub salt: i64,
    pub session_id: i64,
    /// Each message's body, gzip unpacked, and whether it was content-related (odd seqno).
    pub messages: Vec<(Vec<u8>, bool)>,
}

/// Opens the encrypted packets among `frames` whose key is in `keys`; plain handshake packets and
/// packets under other keys are left out.
pub fn open(frames: &[Vec<u8>], keys: &[AuthKey]) -> Vec<Opened> {
    let mut opened = Vec::new();
    for frame in frames {
        let Some(key_id) = read_auth_key_id(frame).filter(|id| *id != 0) else {
            continue;
        };
        let Some(key) = keys.iter().find(|key| key.id() == key_id) else {
            continue;
        };
        let packet = ServerPeer::new(key.clone(), 0.0).decode(frame);
        let messages =
            packet.messages.iter().map(|message| (unpacked(&message.body), message.is_content_related())).collect();
        opened.push(Opened { key_id, salt: packet.header.salt, session_id: packet.header.session_id, messages });
    }
    opened
}

/// How many encrypted packets among `frames` went under a key not in `keys`.
#[allow(dead_code)]
pub fn under_other_keys(frames: &[Vec<u8>], keys: &[AuthKey]) -> usize {
    frames
        .iter()
        .filter_map(|frame| read_auth_key_id(frame))
        .filter(|id| *id != 0 && !keys.iter().any(|key| key.id() == *id))
        .count()
}

fn unpacked(body: &[u8]) -> Vec<u8> {
    if body.len() < 4 || u32::from_le_bytes(body[..4].try_into().unwrap()) != ids::GZIP_PACKED {
        return body.to_vec();
    }
    let mut reader = Reader::new(&body[4..]);
    let packed = reader.read_bytes().expect("gzip_packed bytes");
    gunzip(packed, 16 << 20).expect("gzip_packed unpacks")
}
