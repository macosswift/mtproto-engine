//! Hostile and "impossible" inputs on the C boundary: null and dangling-length pointers, invalid
//! UTF-8, unknown handles, non-finite numbers, callbacks that call back into the engine, and events
//! racing `mt_engine_destroy`. None of them may crash the process, deadlock, or leave the engine unusable.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

type Recorded = (u64, u32, u64, i32, Vec<u8>, String);

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Recorded>>,
    condvar: Condvar,
    engine: AtomicPtr<MTEngine>,
    chain_left: AtomicUsize,
    chain_session: AtomicU64,
    destroyed: AtomicBool,
    after_destroy: AtomicUsize,
    in_callback: AtomicUsize,
}

unsafe extern "C" fn record(context: *mut c_void, session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const Sink) };
    sink.in_callback.fetch_add(1, Ordering::SeqCst);
    if sink.destroyed.load(Ordering::SeqCst) {
        sink.after_destroy.fetch_add(1, Ordering::SeqCst);
    }
    let event = unsafe { &*event };
    let payload = if event.payload.is_null() {
        Vec::new()
    } else {
        let data =
            unsafe { std::slice::from_raw_parts(mt_buffer_data(event.payload), mt_buffer_length(event.payload)) }
                .to_vec();
        unsafe { mt_buffer_free(event.payload) };
        data
    };
    let text = if event.text.data.is_null() {
        String::new()
    } else {
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(event.text.data, event.text.length) }).into_owned()
    };
    if event.kind == 1 {
        reenter(sink, session);
    }
    sink.events.lock().unwrap().push((session, event.kind, event.request_id, event.code, payload, text));
    sink.condvar.notify_all();
    sink.in_callback.fetch_sub(1, Ordering::SeqCst);
}

/// From inside the completion callback: the next call of a chain, plus calls that must neither
/// deadlock nor disturb the engine.
fn reenter(sink: &Sink, session: u64) {
    let engine = sink.engine.load(Ordering::SeqCst);
    if engine.is_null() || session != sink.chain_session.load(Ordering::SeqCst) {
        return;
    }
    let left = sink.chain_left.load(Ordering::SeqCst);
    if left == 0 || sink.chain_left.compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    unsafe {
        let id = mt_engine_next_request_id(engine);
        let body = call(9000 + left as u32, &[1, 2, 3]);
        let request = MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
        mt_session_send(engine, session, &request);
        mt_session_cancel(engine, session, u64::MAX - 7);
        mt_session_set_online(engine, session, 1);
        mt_session_set_paused(engine, session, 0);
        mt_engine_set_network_available(engine, 1);
        mt_engine_set_network(engine, bytes(b"reentrant"));
    }
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

const NO_STRING: MTString = MTString { data: std::ptr::null(), length: 0 };

fn no_proxy() -> MTProxy {
    MTProxy { kind: 0, host: NO_STRING, port: 0, username: NO_STRING, password: NO_STRING, secret: bytes(&[]) }
}

fn unix_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
}

struct Owned {
    host: String,
    address: MTAddress,
    salt: MTSaltEntry,
}

fn setup_for(owned: &Owned, key: &[u8], time_difference: f64) -> MTSessionSetup {
    MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: 2,
        role: 0,
        framing: 1,
        addresses: &owned.address,
        address_count: 1,
        proxy: no_proxy(),
        auth_key: bytes(key),
        salts: &owned.salt,
        salt_count: 1,
        has_init_hash: 0,
        init_hash: NO_STRING,
        generate_key: 0,
        public_keys_pem: std::ptr::null(),
        public_key_count: 0,
        temp_key_expires_in: 0,
        environment: std::ptr::null(),
        time_difference,
        online: 1,
        paused: 0,
        keep_connected: 1,
        idle_disconnect_after: 0.0,
        request_timeout: 10.0,
        pfs_lifetime: 0,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: std::ptr::null(),
    }
}

fn owned_for(server: &TestServer) -> Box<Owned> {
    let mut owned = Box::new(Owned {
        host: server.address.ip().to_string(),
        address: MTAddress { host: NO_STRING, port: server.address.port(), secret: bytes(&[]) },
        salt: MTSaltEntry { salt: SERVER_SALT, valid_since: unix_now() - 60.0, valid_until: unix_now() + 3600.0 },
    });
    owned.address.host = MTString { data: owned.host.as_ptr(), length: owned.host.len() };
    owned
}

fn send_call(engine: *mut MTEngine, session: u64, tag: u32) -> u64 {
    let id = unsafe { mt_engine_next_request_id(engine) };
    let body = call(tag, &[tag as u8; 5]);
    let request = MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
    unsafe { mt_session_send(engine, session, &request) };
    id
}

fn wait_for(sink: &Sink, seconds: u64, done: impl Fn(&[Recorded]) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut events = sink.events.lock().unwrap();
    while !done(&events) {
        if Instant::now() >= deadline {
            return false;
        }
        events = sink.condvar.wait_timeout(events, Duration::from_millis(50)).unwrap().0;
    }
    true
}

fn completed(events: &[Recorded], id: u64) -> bool {
    events.iter().any(|event| event.1 == 1 && event.2 == id)
}

#[test]
fn null_and_dangling_inputs_on_every_entry_point_are_ignored() {
    let engine: *mut MTEngine = std::ptr::null_mut();
    let dangling = MTBytes { data: std::ptr::null(), length: 4096 };
    let dangling_text = MTString { data: std::ptr::null(), length: 4096 };
    unsafe {
        assert_eq!(mt_engine_next_request_id(engine), 0);
        mt_engine_set_network_available(engine, 1);
        mt_engine_reset_connections(engine);
        mt_engine_set_network(engine, dangling);
        mt_engine_set_route_memory(engine, dangling);
        mt_engine_set_stream_host(engine, std::ptr::null());
        mt_stream_opened(engine, 1);
        assert_eq!(mt_stream_received(engine, 1, dangling), 0);
        mt_stream_sent(engine, 1, usize::MAX);
        mt_stream_closed(engine, 1, dangling_text);
        assert_eq!(mt_session_create(engine, std::ptr::null()), 0);
        mt_session_destroy(engine, 1);
        mt_session_send(engine, 1, std::ptr::null());
        mt_session_cancel(engine, 1, 1);
        mt_session_set_paused(engine, 1, 1);
        mt_session_set_online(engine, 1, 1);
        mt_session_set_auth_key(engine, 1, dangling, std::ptr::null(), 99, 1, dangling_text);
        mt_session_set_addresses(engine, 1, std::ptr::null(), 99);
        mt_session_set_obfuscation_dc_id(engine, 1, -1);
        mt_session_set_proxy(engine, 1, std::ptr::null());
        mt_session_set_transport(engine, 1, 200, 0);
        mt_session_set_web_endpoint(engine, 1, std::ptr::null());
        mt_session_use_telegram_web(engine, 1, 1);
        assert_eq!(mt_session_enable_pfs(engine, 1, 86_400, std::ptr::null(), 99, 1, std::ptr::null()), 0);
        mt_session_offer_temporary_key(engine, 1, std::ptr::null());
        mt_session_allow_permanent_key(engine, 1, 1);
        mt_session_update_environment(engine, 1, std::ptr::null(), std::ptr::null());
        mt_session_set_auth_token_ready(engine, 1, 1);
        mt_session_resolve_apns(engine, 1, 1, dangling_text, dangling_text);
        mt_session_resolve_recaptcha(engine, 1, 1, dangling_text);
        mt_session_fail_request(engine, 1, 1, 400, dangling_text);
        mt_session_decide_retry(engine, 1, 1, 1);
        mt_session_invalidate_initialization(engine, 1);
        mt_session_set_time_difference(engine, 1, f64::NAN);
        mt_session_destroy_auth_key(engine, 1);
        mt_engine_destroy(engine);
    }
}

#[test]
fn hostile_session_setups_and_unknown_handles_leave_the_engine_usable() {
    let key = random_key(4242);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(u32::MAX, sink as *const Sink as *mut c_void, Some(record), None) };
    assert!(!engine.is_null(), "an absurd worker count is clamped");

    let invalid_utf8 = [0xffu8, 0xfe, 0x00, 0xc3, 0x28];
    let bad_text = MTString { data: invalid_utf8.as_ptr(), length: invalid_utf8.len() };
    let dangling = MTBytes { data: std::ptr::null(), length: 1 << 20 };
    let dangling_text = MTString { data: std::ptr::null(), length: 1 << 20 };
    let short_key = vec![7u8; 255];
    let long_key = vec![7u8; 257];
    let garbage_pem = [bad_text, dangling_text, string("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")];
    let nan_salt = MTSaltEntry { salt: 1, valid_since: f64::NAN, valid_until: f64::INFINITY };
    let address = MTAddress { host: bad_text, port: 0, secret: dangling };
    let environment = MTEnvironment {
        layer: i32::MIN,
        api_id: -1,
        device_model: bad_text,
        system_version: dangling_text,
        app_version: bad_text,
        system_lang_code: NO_STRING,
        lang_pack: bad_text,
        lang_code: dangling_text,
        has_proxy: 1,
        proxy_address: bad_text,
        proxy_port: -5,
        has_params: 1,
        params: dangling,
        init_hash: bad_text,
        disable_updates: 7,
    };
    let temporary = MTTemporaryKey {
        key: bytes(&short_key),
        expires_at: i32::MIN,
        bound_to: -1,
        salts: &nan_salt,
        salt_count: 1,
        has_init_hash: 1,
        init_hash: bad_text,
    };
    let mut handles = Vec::new();
    for (index, auth_key) in [bytes(&short_key), bytes(&long_key), dangling, bytes(&[])].into_iter().enumerate() {
        let setup = MTSessionSetup {
            datacenter_id: [i32::MIN, -1, 0, i32::MAX][index],
            obfuscation_dc_id: [i16::MIN, -1, 0, i16::MAX][index],
            role: [0, 1, 3, 250][index],
            framing: [0, 1, 2, 250][index],
            addresses: if index == 3 { std::ptr::null() } else { &address },
            address_count: if index == 3 { 1000 } else { 1 },
            proxy: MTProxy {
                kind: [1, 2, 3, 250][index],
                host: bad_text,
                port: 0,
                username: dangling_text,
                password: bad_text,
                secret: bytes(&invalid_utf8),
            },
            auth_key,
            salts: if index == 3 { std::ptr::null() } else { &nan_salt },
            salt_count: if index == 3 { 77 } else { 1 },
            has_init_hash: 1,
            init_hash: bad_text,
            generate_key: (index % 2) as u8,
            public_keys_pem: garbage_pem.as_ptr(),
            public_key_count: garbage_pem.len(),
            temp_key_expires_in: [i32::MIN, -1, 0, i32::MAX][index],
            environment: &environment,
            time_difference: [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1e300][index],
            online: 200,
            paused: 0,
            keep_connected: 9,
            idle_disconnect_after: [f64::NAN, -1.0, f64::INFINITY, 1e-300][index],
            request_timeout: [f64::NAN, -1.0, f64::INFINITY, 1e-300][index],
            pfs_lifetime: [i32::MIN, -1, 1, i32::MAX][index],
            pfs_make_permanent_key: 1,
            pfs_temporary_key: &temporary,
        };
        let handle = unsafe { mt_session_create(engine, &setup) };
        assert_ne!(handle, 0);
        handles.push(handle);
    }
    for &handle in &handles {
        unsafe {
            mt_session_set_time_difference(engine, handle, f64::NAN);
            mt_session_set_auth_key(engine, handle, dangling, std::ptr::null(), 5, 1, bad_text);
            mt_session_offer_temporary_key(engine, handle, &temporary);
            assert_eq!(
                mt_session_enable_pfs(engine, handle, 60, garbage_pem.as_ptr(), garbage_pem.len(), 1, &temporary),
                0,
                "no key in the list parses"
            );
            mt_session_set_addresses(engine, handle, &address, 1);
            mt_session_resolve_recaptcha(engine, handle, 1, bad_text);
            mt_session_fail_request(engine, handle, 1, i32::MIN, bad_text);
            mt_session_update_environment(engine, handle, &environment, std::ptr::null());
        }
        send_call(engine, handle, 1);
    }
    for handle in [0u64, u64::MAX, 0xff, 1 << 63] {
        let id = send_call(engine, handle, 2);
        unsafe {
            mt_session_destroy(engine, handle);
            mt_session_cancel(engine, handle, id);
        }
    }
    unsafe {
        mt_engine_set_route_memory(engine, bytes(&invalid_utf8));
        mt_engine_set_route_memory(engine, bytes(&[1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        mt_engine_set_network(engine, bytes(&vec![0x5au8; 1 << 20]));
        mt_stream_received(engine, 12345, bytes(&invalid_utf8));
        mt_stream_sent(engine, 12345, usize::MAX);
        mt_stream_closed(engine, 12345, bad_text);
    }
    for &handle in &handles {
        unsafe {
            mt_session_destroy(engine, handle);
            mt_session_destroy(engine, handle);
        }
    }
    let closed_late = send_call(engine, handles[0], 3);
    assert!(
        wait_for(sink, 10, |events| events
            .iter()
            .any(|event| event.1 == 2 && event.2 == closed_late && event.5 == "SESSION_CLOSED")),
        "a call to a destroyed session fails at once"
    );

    let owned = owned_for(&server);
    let setup = setup_for(&owned, key.bytes(), 0.0);
    let session = unsafe { mt_session_create(engine, &setup) };
    let id = send_call(engine, session, 7);
    assert!(wait_for(sink, 15, |events| completed(events, id)), "the engine still works after all of it");
    unsafe {
        mt_session_destroy(engine, session);
        mt_engine_destroy(engine);
    }
}

#[test]
fn completion_callbacks_may_call_back_into_the_engine() {
    let key = random_key(4343);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(3, sink as *const Sink as *mut c_void, Some(record), None) };
    sink.engine.store(engine, Ordering::SeqCst);
    let owned = owned_for(&server);
    let setup = setup_for(&owned, key.bytes(), 0.0);
    let session = unsafe { mt_session_create(engine, &setup) };
    sink.chain_session.store(session, Ordering::SeqCst);
    sink.chain_left.store(30, Ordering::SeqCst);
    send_call(engine, session, 1);
    assert!(
        wait_for(sink, 30, |events| events.iter().filter(|event| event.1 == 1).count() >= 31),
        "each completion sent the next call from inside its callback"
    );
    sink.engine.store(std::ptr::null_mut(), Ordering::SeqCst);
    unsafe {
        mt_session_destroy(engine, session);
        mt_engine_destroy(engine);
    }
}

#[test]
fn no_event_reaches_the_host_once_engine_destroy_returned() {
    let key = random_key(4444);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    for round in 0..4 {
        let sink: &'static Sink = Box::leak(Box::default());
        let engine = unsafe { mt_engine_create(4, sink as *const Sink as *mut c_void, Some(record), None) };
        let owned = owned_for(&server);
        let mut sessions = Vec::new();
        for role in [0u8, 1, 1, 1] {
            let mut setup = setup_for(&owned, key.bytes(), 0.0);
            setup.role = role;
            sessions.push(unsafe { mt_session_create(engine, &setup) });
        }
        for tag in 0..200u32 {
            send_call(engine, sessions[tag as usize % sessions.len()], tag);
        }
        std::thread::sleep(Duration::from_millis(20 + 40 * round));
        unsafe { mt_engine_destroy(engine) };
        sink.destroyed.store(true, Ordering::SeqCst);
        assert_eq!(sink.in_callback.load(Ordering::SeqCst), 0, "no callback runs once destroy returned");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(sink.after_destroy.load(Ordering::SeqCst), 0, "round {round}: an event arrived after destroy");
    }
}

#[test]
fn many_threads_share_one_engine() {
    let key = random_key(4545);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(4, sink as *const Sink as *mut c_void, Some(record), None) };
    let owned = owned_for(&server);
    let setup = setup_for(&owned, key.bytes(), 0.0);
    let session = unsafe { mt_session_create(engine, &setup) };
    let address = engine as usize;
    let ids: Vec<u64> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8u32)
            .map(|thread| {
                scope.spawn(move || {
                    let engine = address as *mut MTEngine;
                    (0..25u32).map(|tag| send_call(engine, session, thread * 100 + tag)).collect::<Vec<_>>()
                })
            })
            .collect();
        workers.into_iter().flat_map(|worker| worker.join().unwrap()).collect()
    });
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "request ids are unique across threads");
    assert!(wait_for(sink, 30, |events| ids.iter().all(|id| completed(events, *id))), "every call completes");
    unsafe {
        mt_session_destroy(engine, session);
        mt_engine_destroy(engine);
    }
}

#[derive(Default)]
struct DestroyingSink {
    engine: AtomicPtr<MTEngine>,
    destroyed_in_callback: AtomicBool,
    events_after: AtomicUsize,
    done: Mutex<bool>,
    condvar: Condvar,
}

unsafe extern "C" fn destroy_on_completion(context: *mut c_void, _session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const DestroyingSink) };
    let event = unsafe { &*event };
    if !event.payload.is_null() {
        unsafe { mt_buffer_free(event.payload) };
    }
    if sink.destroyed_in_callback.load(Ordering::SeqCst) {
        sink.events_after.fetch_add(1, Ordering::SeqCst);
        return;
    }
    if event.kind == 1 {
        let engine = sink.engine.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !engine.is_null() {
            unsafe { mt_engine_destroy(engine) };
            sink.destroyed_in_callback.store(true, Ordering::SeqCst);
            *sink.done.lock().unwrap() = true;
            sink.condvar.notify_all();
        }
    }
}

#[test]
fn the_engine_may_be_destroyed_from_inside_its_own_callback() {
    let key = random_key(4747);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static DestroyingSink = Box::leak(Box::default());
    let engine =
        unsafe { mt_engine_create(3, sink as *const DestroyingSink as *mut c_void, Some(destroy_on_completion), None) };
    sink.engine.store(engine, Ordering::SeqCst);
    let owned = owned_for(&server);
    let mut sessions = Vec::new();
    for role in [0u8, 1, 1] {
        let mut setup = setup_for(&owned, key.bytes(), 0.0);
        setup.role = role;
        sessions.push(unsafe { mt_session_create(engine, &setup) });
    }
    for tag in 0..60u32 {
        send_call(engine, sessions[tag as usize % sessions.len()], tag);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut done = sink.done.lock().unwrap();
    while !*done && Instant::now() < deadline {
        done = sink.condvar.wait_timeout(done, Duration::from_millis(50)).unwrap().0;
    }
    assert!(*done, "destroy called from a callback returned");
    drop(done);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(sink.events_after.load(Ordering::SeqCst), 0, "no event after the destroy returned");
}
