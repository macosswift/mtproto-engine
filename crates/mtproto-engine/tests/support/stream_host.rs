//! A stream host for tests, standing in for the app's: each stream is a thread with a TCP connection
//! and, when asked for, TLS without a certificate check (rustls), reporting to the engine as the app's
//! host does.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mtproto_engine::{Engine, StreamHost, StreamId, StreamTarget};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

enum Op {
    Write(Vec<u8>),
    Resume,
    Close,
}

/// Where the host reports: the engine itself, or its C ABI.
pub trait StreamSink: Send + Sync {
    fn opened(&self, stream: StreamId);
    fn received(&self, stream: StreamId, bytes: &[u8]) -> bool;
    fn sent(&self, stream: StreamId, count: usize);
    fn closed(&self, stream: StreamId, error: Option<String>);
}

impl StreamSink for Engine {
    fn opened(&self, stream: StreamId) {
        self.stream_opened(stream);
    }

    fn received(&self, stream: StreamId, bytes: &[u8]) -> bool {
        self.stream_received(stream, bytes)
    }

    fn sent(&self, stream: StreamId, count: usize) {
        self.stream_sent(stream, count);
    }

    fn closed(&self, stream: StreamId, error: Option<String>) {
        self.stream_closed(stream, error);
    }
}

#[derive(Default)]
pub struct TestStreamHost {
    sink: OnceLock<Arc<dyn StreamSink>>,
    streams: Mutex<HashMap<StreamId, Sender<Op>>>,
    pub targets: Mutex<Vec<StreamTarget>>,
    /// Opens fail at once, as when the platform cannot reach the host.
    pub refuse: AtomicBool,
    /// The most a single `write` carried, and how often the engine let a paused stream receive again.
    pub largest_write: AtomicUsize,
    pub pauses: AtomicUsize,
    pub closed_by_engine: AtomicUsize,
    /// Where carrier streams go (the WEB proxy relay); without one they are refused.
    pub carrier_relay: Mutex<Option<std::net::SocketAddr>>,
}

impl TestStreamHost {
    #[allow(dead_code)]
    pub fn attach(self: &Arc<Self>, engine: &Engine) {
        self.attach_sink(Arc::new(engine.clone()));
        engine.set_stream_host(Some(self.clone()));
    }

    pub fn attach_sink(&self, sink: Arc<dyn StreamSink>) {
        let _ = self.sink.set(sink);
    }

    fn sink(&self) -> Arc<dyn StreamSink> {
        self.sink.get().expect("attached").clone()
    }

    #[allow(dead_code)]
    pub fn open_streams(&self) -> usize {
        self.streams.lock().unwrap().len()
    }
}

impl StreamHost for TestStreamHost {
    fn open(&self, stream: StreamId, target: &StreamTarget) {
        self.targets.lock().unwrap().push(target.clone());
        let sink = self.sink();
        if self.refuse.load(Ordering::Relaxed) {
            sink.closed(stream, Some("refused".into()));
            return;
        }
        let mut target = target.clone();
        if target.carrier {
            let Some(relay) = *self.carrier_relay.lock().unwrap() else {
                sink.closed(stream, Some("no carrier".into()));
                return;
            };
            target.host = relay.ip().to_string();
            target.port = relay.port();
        }
        let (sender, receiver) = channel();
        self.streams.lock().unwrap().insert(stream, sender);
        std::thread::spawn(move || {
            if let Some(end) = run(sink.as_ref(), stream, &target, receiver) {
                sink.closed(stream, end);
            }
        });
    }

    fn write(&self, stream: StreamId, bytes: &[u8]) {
        self.largest_write.fetch_max(bytes.len(), Ordering::Relaxed);
        if let Some(sender) = self.streams.lock().unwrap().get(&stream) {
            let _ = sender.send(Op::Write(bytes.to_vec()));
        }
    }

    fn close(&self, stream: StreamId) {
        self.closed_by_engine.fetch_add(1, Ordering::Relaxed);
        if let Some(sender) = self.streams.lock().unwrap().remove(&stream) {
            let _ = sender.send(Op::Close);
        }
    }

    fn resume(&self, stream: StreamId) {
        self.pauses.fetch_add(1, Ordering::Relaxed);
        if let Some(sender) = self.streams.lock().unwrap().get(&stream) {
            let _ = sender.send(Op::Resume);
        }
    }
}

/// Some(end) to report to the engine; None when the engine closed the stream. Reads and writes never
/// block each other, as with the platform's streams.
fn run(
    sink: &dyn StreamSink,
    stream: StreamId,
    target: &StreamTarget,
    receiver: Receiver<Op>,
) -> Option<Option<String>> {
    let address = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(mut addresses) => addresses.next(),
        Err(error) => return Some(Some(error.to_string())),
    };
    let Some(address) = address else {
        return Some(Some("no address".into()));
    };
    let mut socket = match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
        Ok(socket) => socket,
        Err(error) => return Some(Some(error.to_string())),
    };
    let _ = socket.set_nodelay(true);
    if let Err(error) = socket.set_nonblocking(true) {
        return Some(Some(error.to_string()));
    }
    let mut tls = match &target.tls_server_name {
        Some(name) => {
            let mut config = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider())))
                .with_no_client_auth();
            config.alpn_protocols = target.alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
            let name = ServerName::try_from(name.clone()).expect("server name");
            Some(ClientConnection::new(Arc::new(config), name).expect("client"))
        }
        None => None,
    };
    let mut opened = tls.is_none();
    if opened {
        sink.opened(stream);
    }
    let mut paused = false;
    let mut pending: Vec<u8> = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let mut progress = false;
        loop {
            match receiver.try_recv() {
                Ok(Op::Write(bytes)) => pending.extend_from_slice(&bytes),
                Ok(Op::Resume) => paused = false,
                Ok(Op::Close) | Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => break,
            }
        }
        if !pending.is_empty() && opened {
            let taken = match &mut tls {
                Some(connection) => connection.writer().write(&pending),
                None => match socket.write(&pending) {
                    Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
                    other => other,
                },
            };
            match taken {
                Ok(0) => {}
                Ok(taken) => {
                    progress = true;
                    pending.drain(..taken);
                    sink.sent(stream, taken);
                }
                Err(error) => return Some(Some(error.to_string())),
            }
        }
        if let Some(connection) = &mut tls {
            while connection.wants_write() {
                match connection.write_tls(&mut socket) {
                    Ok(_) => progress = true,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Some(Some(error.to_string())),
                }
            }
        }
        if !paused {
            match &mut tls {
                Some(connection) => match connection.read_tls(&mut socket) {
                    Ok(0) => return Some(None),
                    Ok(_) => {
                        progress = true;
                        if let Err(error) = connection.process_new_packets() {
                            return Some(Some(error.to_string()));
                        }
                        if !opened && !connection.is_handshaking() {
                            opened = true;
                            sink.opened(stream);
                        }
                        loop {
                            match connection.reader().read(&mut buffer) {
                                Ok(0) => return Some(None),
                                Ok(read) => {
                                    if !sink.received(stream, &buffer[..read]) {
                                        paused = true;
                                    }
                                }
                                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                                Err(error) => return Some(Some(error.to_string())),
                            }
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Some(Some(error.to_string())),
                },
                None => match socket.read(&mut buffer) {
                    Ok(0) => return Some(None),
                    Ok(read) => {
                        progress = true;
                        if !sink.received(stream, &buffer[..read]) {
                            paused = true;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Some(Some(error.to_string())),
                },
            }
        }
        if !progress {
            std::thread::sleep(Duration::from_micros(500));
        }
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
