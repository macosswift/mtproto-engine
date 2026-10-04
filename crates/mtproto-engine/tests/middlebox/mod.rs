#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Info {
    pub plain: bool,
    pub plain_index: usize,
    pub encrypted_index: usize,
    pub connection: usize,
}

pub enum Action {
    Forward,
    Respond(u16, Vec<u8>),
    Hold,
}

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicUsize,
    pub plain: AtomicUsize,
    pub encrypted: AtomicUsize,
}

type Policy = Arc<dyn Fn(Info) -> Action + Send + Sync>;
type Message = (Vec<u8>, Vec<u8>);

fn read_message(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Message> {
    let mut scratch = vec![0u8; 65536];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower.strip_prefix("content-length:").map(|value| value.trim().to_string())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                let head_bytes = buffer[..end + 4].to_vec();
                let body = buffer[end + 4..end + 4 + length].to_vec();
                buffer.drain(..end + 4 + length);
                return Some((head_bytes, body));
            }
        }
        let read = stream.read(&mut scratch).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
}

pub fn start(upstream: SocketAddr, policy: Policy) -> (u16, Arc<Stats>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let counters = stats.clone();
    let order = Arc::new(Mutex::new(()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            let connection = counters.connections.fetch_add(1, Ordering::SeqCst);
            let counters = counters.clone();
            let policy = policy.clone();
            let order = order.clone();
            std::thread::spawn(move || {
                let mut upstream_stream: Option<TcpStream> = None;
                let mut client_buffer = Vec::new();
                let mut upstream_buffer = Vec::new();
                loop {
                    let Some((head, body)) = read_message(&mut client, &mut client_buffer) else { return };
                    let plain = body.len() >= 8 && body[..8] == [0u8; 8];
                    let info = {
                        let _guard = order.lock().unwrap();
                        if plain {
                            Info {
                                plain,
                                plain_index: counters.plain.fetch_add(1, Ordering::SeqCst),
                                encrypted_index: counters.encrypted.load(Ordering::SeqCst),
                                connection,
                            }
                        } else {
                            Info {
                                plain,
                                plain_index: counters.plain.load(Ordering::SeqCst),
                                encrypted_index: counters.encrypted.fetch_add(1, Ordering::SeqCst),
                                connection,
                            }
                        }
                    };
                    match policy(info) {
                        Action::Hold => loop {
                            std::thread::sleep(Duration::from_secs(1));
                            let mut probe = [0u8; 1];
                            client.set_nonblocking(true).ok();
                            if let Ok(0) = client.peek(&mut probe) {
                                return;
                            }
                            client.set_nonblocking(false).ok();
                        },
                        Action::Respond(status, payload) => {
                            let head = format!(
                                "HTTP/1.1 {status} X\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                payload.len()
                            );
                            if client.write_all(head.as_bytes()).is_err() || client.write_all(&payload).is_err() {
                                return;
                            }
                        }
                        Action::Forward => {
                            if upstream_stream.is_none() {
                                let Ok(stream) = TcpStream::connect(upstream) else { return };
                                upstream_stream = Some(stream);
                            }
                            let up = upstream_stream.as_mut().unwrap();
                            if up.write_all(&head).is_err() || up.write_all(&body).is_err() {
                                return;
                            }
                            let Some((response_head, response_body)) = read_message(up, &mut upstream_buffer) else {
                                return;
                            };
                            if client.write_all(&response_head).is_err() || client.write_all(&response_body).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, stats)
}

fn try_read_message(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<Option<Message>, ()> {
    let mut scratch = vec![0u8; 65536];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                let head_bytes = buffer[..end + 4].to_vec();
                let body = buffer[end + 4..end + 4 + length].to_vec();
                buffer.drain(..end + 4 + length);
                return Ok(Some((head_bytes, body)));
            }
        }
        match stream.read(&mut scratch) {
            Ok(0) => return Err(()),
            Ok(read) => buffer.extend_from_slice(&scratch[..read]),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(_) => return Err(()),
        }
    }
}

/// Forwards, but holds each response a moment; the first time a second request comes in behind
/// one still unanswered on the same connection, both are answered with 429 in a single write.
pub fn start_pipeline_flood(upstream: SocketAddr) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let paired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = paired.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            let flag = flag.clone();
            std::thread::spawn(move || {
                let mut up: Option<TcpStream> = None;
                let mut client_buffer = Vec::new();
                let mut upstream_buffer = Vec::new();
                loop {
                    client.set_read_timeout(None).ok();
                    let Ok(Some((head, body))) = try_read_message(&mut client, &mut client_buffer) else { return };
                    let plain = body.len() >= 8 && body[..8] == [0u8; 8];
                    if !flag.load(Ordering::SeqCst) && !plain {
                        client.set_read_timeout(Some(Duration::from_millis(250))).ok();
                        match try_read_message(&mut client, &mut client_buffer) {
                            Ok(Some(_second)) => {
                                flag.store(true, Ordering::SeqCst);
                                let one = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                                let both = format!("{one}{one}");
                                let _ = client.write_all(both.as_bytes());
                                continue;
                            }
                            Ok(None) => {}
                            Err(()) => return,
                        }
                        client.set_read_timeout(None).ok();
                    }
                    if up.is_none() {
                        let Ok(stream) = TcpStream::connect(upstream) else { return };
                        up = Some(stream);
                    }
                    let stream = up.as_mut().unwrap();
                    if stream.write_all(&head).is_err() || stream.write_all(&body).is_err() {
                        return;
                    }
                    let Some((response_head, response_body)) = read_message(stream, &mut upstream_buffer) else {
                        return;
                    };
                    if client.write_all(&response_head).is_err() || client.write_all(&response_body).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, paired)
}
