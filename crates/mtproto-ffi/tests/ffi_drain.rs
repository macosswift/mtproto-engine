//! `mt_session_drain` through the C ABI: `MTEventKindReleased` (36) with `MTReleasedMayHaveRun`, then
//! `MTEventKindClosed` (26).

use std::ffi::c_void;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[derive(Debug, Clone, Copy, PartialEq)]
struct Seen {
    kind: u32,
    request: u64,
    flags: u32,
    value1: f64,
}

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Seen>>,
    condvar: Condvar,
}

unsafe extern "C" fn on_event(context: *mut c_void, _session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const Sink) };
    let event = unsafe { &*event };
    if !event.payload.is_null() {
        unsafe { mt_buffer_free(event.payload) };
    }
    sink.events.lock().unwrap().push(Seen {
        kind: event.kind,
        request: event.request_id,
        flags: event.flags,
        value1: event.value1,
    });
    sink.condvar.notify_all();
}

impl Sink {
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[Seen]) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        while !predicate(&events) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
        true
    }
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

const KIND_COMPLETED: u32 = 1;
const KIND_CLOSED: u32 = 26;
const KIND_RELEASED: u32 = 36;

#[test]
fn a_drained_session_releases_its_requests_then_closes() {
    let key = random_key(91);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(1, sink as *const Sink as *mut c_void, Some(on_event), None) };
    assert!(!engine.is_null());
    let host = server.address.ip().to_string();
    let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&[]) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    let setup = MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: 2,
        role: 0,
        framing: 0,
        addresses: &address,
        address_count: 1,
        proxy: MTProxy {
            kind: 0,
            host: string(""),
            port: 0,
            username: string(""),
            password: string(""),
            secret: bytes(&[]),
        },
        auth_key: bytes(key.bytes()),
        salts: &salt,
        salt_count: 1,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 0,
        public_keys_pem: std::ptr::null(),
        public_key_count: 0,
        temp_key_expires_in: 0,
        environment: std::ptr::null(),
        time_difference: 0.0,
        online: 0,
        paused: 0,
        keep_connected: 1,
        idle_disconnect_after: 0.0,
        request_timeout: 5.0,
        pfs_lifetime: 0,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: std::ptr::null(),
    };
    let session = unsafe { mt_session_create(engine, &setup) };
    assert_ne!(session, 0);
    let send = |tag: u32| {
        let id = unsafe { mt_engine_next_request_id(engine) };
        let body = call(tag, &id.to_le_bytes());
        let request = MTRequest { id, body: bytes(&body), flags: 0, expected_response_size: 0, invoke_after: 0 };
        unsafe { mt_session_send(engine, session, &request) };
        id
    };
    let warmup = send(7);
    assert!(sink.wait(Duration::from_secs(10), |events| {
        events.iter().any(|e| e.kind == KIND_COMPLETED && e.request == warmup)
    }));
    let never = send(TAG_NEVER);
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.with_stats(|stats| stats.executions.get(&TAG_NEVER).copied().unwrap_or(0)) == 0
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    unsafe { mt_session_drain(engine, session, 0.5) };
    let late = send(7);
    assert!(sink.wait(Duration::from_secs(10), |events| events.iter().any(|e| e.kind == KIND_CLOSED)));
    let events = sink.events.lock().unwrap().clone();
    let released: Vec<Seen> = events.iter().copied().filter(|e| e.kind == KIND_RELEASED).collect();
    assert!(
        released.contains(&Seen { kind: KIND_RELEASED, request: never, flags: RELEASED_MAY_HAVE_RUN, value1: 0.0 }),
        "{released:?}"
    );
    assert!(released.contains(&Seen { kind: KIND_RELEASED, request: late, flags: 0, value1: 0.0 }), "{released:?}");
    let closed_index = events.iter().position(|e| e.kind == KIND_CLOSED).unwrap();
    let never_index = events.iter().position(|e| e.kind == KIND_RELEASED && e.request == never).unwrap();
    assert!(never_index < closed_index, "every release comes before Closed");
    unsafe { mt_session_destroy(engine, session) };
    unsafe { mt_engine_destroy(engine) };
    assert_eq!(server.with_stats(|stats| stats.executions.get(&TAG_NEVER).copied().unwrap_or(0)), 1);
}

#[test]
fn the_header_declares_the_drain_abi() {
    let header = include_str!("../include/mtproto_engine.h");
    assert!(header.contains("MTEventKindReleased = 36,"));
    assert!(header.contains("MTReleasedMayHaveRun = 1 << 0,"));
    assert!(header.contains("void mt_session_drain(MTEngine *engine, MTSessionHandle session, double deadline);"));
    assert_eq!(RELEASED_MAY_HAVE_RUN, 1);
    assert_eq!(mt_engine_abi_version(), 5);
}
