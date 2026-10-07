//! A time difference that is not a finite number (NaN, ±infinity) from the host must not stall the
//! session: with a NaN offset no salt is ever valid, queries are held, and only the get_future_salts
//! retry a minute later brought the clock back.

use std::ffi::c_void;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[derive(Default)]
struct Sink {
    completed: Mutex<Vec<u64>>,
    condvar: Condvar,
}

unsafe extern "C" fn record(context: *mut c_void, _session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const Sink) };
    let event = unsafe { &*event };
    if !event.payload.is_null() {
        unsafe { mt_buffer_free(event.payload) };
    }
    if event.kind == 1 {
        sink.completed.lock().unwrap().push(event.request_id);
        sink.condvar.notify_all();
    }
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

const NO_STRING: MTString = MTString { data: std::ptr::null(), length: 0 };

fn completes(sink: &Sink, id: u64, seconds: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut completed = sink.completed.lock().unwrap();
    while !completed.contains(&id) {
        if Instant::now() >= deadline {
            return false;
        }
        completed = sink.condvar.wait_timeout(completed, Duration::from_millis(50)).unwrap().0;
    }
    true
}

fn send(engine: *mut MTEngine, session: u64, tag: u32) -> u64 {
    let id = unsafe { mt_engine_next_request_id(engine) };
    let body = call(tag, &[tag as u8; 3]);
    let request = MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
    unsafe { mt_session_send(engine, session, &request) };
    id
}

#[test]
fn non_finite_time_differences_from_the_host_do_not_stall_the_session() {
    let key = random_key(4646);
    let server =
        TestServer::start(vec![key.clone()], ServerOptions { validate_msg_id_time: true, ..ServerOptions::default() });
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(record), None) };
    let host = server.address.ip().to_string();
    let address = MTAddress {
        host: MTString { data: host.as_ptr(), length: host.len() },
        port: server.address.port(),
        secret: bytes(&[]),
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    for difference in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let setup = MTSessionSetup {
            datacenter_id: 2,
            obfuscation_dc_id: 2,
            role: 0,
            framing: 1,
            addresses: &address,
            address_count: 1,
            proxy: MTProxy {
                kind: 0,
                host: NO_STRING,
                port: 0,
                username: NO_STRING,
                password: NO_STRING,
                secret: bytes(&[]),
            },
            auth_key: bytes(key.bytes()),
            salts: &salt,
            salt_count: 1,
            has_init_hash: 0,
            init_hash: NO_STRING,
            generate_key: 0,
            public_keys_pem: std::ptr::null(),
            public_key_count: 0,
            temp_key_expires_in: 0,
            environment: std::ptr::null(),
            time_difference: difference,
            online: 1,
            paused: 0,
            keep_connected: 1,
            idle_disconnect_after: 0.0,
            request_timeout: 30.0,
            pfs_lifetime: 0,
            pfs_make_permanent_key: 0,
            pfs_temporary_key: std::ptr::null(),
        };
        let session = unsafe { mt_session_create(engine, &setup) };
        let first = send(engine, session, 1);
        assert!(completes(sink, first, 15), "created with {difference}");
        unsafe { mt_session_set_time_difference(engine, session, difference) };
        let second = send(engine, session, 2);
        assert!(completes(sink, second, 15), "set to {difference}");
        unsafe { mt_session_destroy(engine, session) };
    }
    unsafe { mt_engine_destroy(engine) };
}
