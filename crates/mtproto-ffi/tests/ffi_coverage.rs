//! The C ABI entry points and event kinds no other test crossed (found with `cargo llvm-cov`): every
//! host control reaches the session and changes what it does, and every event the host can get comes
//! out with its fields where the header says.

use std::ffi::c_void;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[derive(Clone, Debug)]
struct Recorded {
    session: u64,
    kind: u32,
    request_id: u64,
    code: i32,
    flags: u32,
    text: String,
    text2: String,
    payload: Vec<u8>,
    value1: f64,
    integer1: i64,
    integer2: i64,
    salts: Vec<(i64, f64, f64)>,
}

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Recorded>>,
    logs: Mutex<Vec<(i32, String)>>,
    condvar: Condvar,
}

impl Sink {
    fn wait(&self, seconds: u64, predicate: impl Fn(&[Recorded]) -> bool) -> Vec<Recorded> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut events = self.events.lock().unwrap();
        while !predicate(&events) && Instant::now() < deadline {
            events = self.condvar.wait_timeout(events, Duration::from_millis(20)).unwrap().0;
        }
        events.clone()
    }

    fn find(&self, seconds: u64, matches: impl Fn(&Recorded) -> bool) -> Option<Recorded> {
        self.wait(seconds, |events| events.iter().any(&matches)).into_iter().find(|event| matches(event))
    }
}

fn text_of(value: MTString) -> String {
    if value.data.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(value.data, value.length) }).into_owned()
}

unsafe extern "C" fn on_event(context: *mut c_void, session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const Sink) };
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
    let salts = if event.salts.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(event.salts, event.salt_count) }
            .iter()
            .map(|salt| (salt.salt, salt.valid_since, salt.valid_until))
            .collect()
    };
    sink.events.lock().unwrap().push(Recorded {
        session,
        kind: event.kind,
        request_id: event.request_id,
        code: event.code,
        flags: event.flags,
        text: text_of(event.text),
        text2: text_of(event.text2),
        payload,
        value1: event.value1,
        integer1: event.integer1,
        integer2: event.integer2,
        salts,
    });
    sink.condvar.notify_all();
}

unsafe extern "C" fn on_log(context: *mut c_void, level: i32, message: MTString) {
    let sink = unsafe { &*(context as *const Sink) };
    sink.logs.lock().unwrap().push((level, text_of(message)));
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn no_proxy() -> MTProxy {
    MTProxy { kind: 0, host: string(""), port: 0, username: string(""), password: string(""), secret: bytes(&[]) }
}

/// jsonObject with no values, as `initConnection.params`.
const JSON_EMPTY_OBJECT: [u8; 12] = [0x9d, 0xd4, 0xc1, 0x99, 0x15, 0xc4, 0xb5, 0x1c, 0, 0, 0, 0];

fn environment(init_hash: &str) -> MTEnvironment {
    MTEnvironment {
        layer: 230,
        api_id: 9,
        device_model: string("Mac"),
        system_version: string("26"),
        app_version: string("1"),
        system_lang_code: string("en"),
        lang_pack: string("macos"),
        lang_code: string("en"),
        has_proxy: 1,
        proxy_address: string("proxy.example"),
        proxy_port: 443,
        has_params: 1,
        params: bytes(&JSON_EMPTY_OBJECT),
        init_hash: string(init_hash),
        disable_updates: 0,
    }
}

const COMPLETED: u32 = 1;
const FAILED: u32 = 2;
const FLOOD_WAIT_REPORTED: u32 = 5;
const AUTHORIZATION_REQUIRED: u32 = 6;
const AUTH_TOKEN_REQUIRED: u32 = 8;
const INIT_HASH_STORED: u32 = 10;
const UPDATES_RESET: u32 = 13;
const UPDATE: u32 = 14;
const TIME_DIFFERENCE: u32 = 15;
const SALTS_UPDATED: u32 = 16;
const CONNECTION_STATE: u32 = 18;
const AUTH_KEY_REQUIRED: u32 = 19;
const AUTH_KEY_INVALID: u32 = 20;
const AUTH_KEY_CREATED: u32 = 21;
const AUTH_KEY_CREATION_FAILED: u32 = 22;
const TRANSPORT_FLOOD: u32 = 23;
const NETWORK_USAGE: u32 = 24;
const RETRY_DECISION: u32 = 27;
const AUTH_KEY_DESTROYED: u32 = 28;
const CONNECTION_DROPPED: u32 = 29;
const TEMPORARY_KEY_BOUND: u32 = 30;
const TEMPORARY_KEY_IN_USE: u32 = 33;

struct Rig {
    engine: *mut MTEngine,
    sink: &'static Sink,
}

impl Rig {
    fn new() -> Self {
        let sink: &'static Sink = Box::leak(Box::default());
        let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(on_event), Some(on_log)) };
        assert!(!engine.is_null());
        Self { engine, sink }
    }

    fn session(&self, server: &TestServer, key: Option<&[u8]>, role: u8, generate_key: u8, pems: &[MTString]) -> u64 {
        let host = server.address.ip().to_string();
        let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&[]) };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
        let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
        let environment = environment("hash");
        let setup = MTSessionSetup {
            datacenter_id: 2,
            obfuscation_dc_id: 2,
            role,
            framing: 1,
            addresses: &address,
            address_count: 1,
            proxy: no_proxy(),
            auth_key: bytes(key.unwrap_or(&[])),
            salts: &salt,
            salt_count: 1,
            has_init_hash: 1,
            init_hash: string("old"),
            generate_key,
            public_keys_pem: pems.as_ptr(),
            public_key_count: pems.len(),
            temp_key_expires_in: 0,
            environment: &environment,
            time_difference: 0.0,
            online: 1,
            paused: 0,
            keep_connected: 1,
            idle_disconnect_after: 0.0,
            request_timeout: 10.0,
            pfs_lifetime: 0,
            pfs_make_permanent_key: 0,
            pfs_temporary_key: std::ptr::null(),
        };
        let session = unsafe { mt_session_create(self.engine, &setup) };
        assert_ne!(session, 0);
        session
    }

    fn send(&self, session: u64, tag: u32, payload: &[u8], flags: u32) -> u64 {
        let id = unsafe { mt_engine_next_request_id(self.engine) };
        let body = call(tag, payload);
        let request = MTRequest { id, body: bytes(&body), flags, expected_response_size: 0, invoke_after: 0 };
        unsafe { mt_session_send(self.engine, session, &request) };
        id
    }

    fn completed(&self, id: u64, seconds: u64) -> bool {
        self.sink.find(seconds, |event| event.kind == COMPLETED && event.request_id == id).is_some()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        unsafe { mt_engine_destroy(self.engine) };
    }
}

const AUTOMATIC_FLOOD_WAIT: u32 = 1;
const REPORT_FLOOD_WAIT: u32 = 2;
const RETRY_SERVER_ERRORS: u32 = 4;
const DELEGATE_RETRY: u32 = 128;

#[test]
fn every_entry_point_ignores_a_null_engine() {
    let null = std::ptr::null_mut();
    let none = MTString { data: std::ptr::null(), length: 0 };
    let nothing = MTBytes { data: std::ptr::null(), length: 0 };
    unsafe {
        assert_eq!(mt_engine_next_request_id(null), 0);
        mt_engine_set_network_available(null, 1);
        mt_engine_set_network(null, nothing);
        mt_engine_set_route_memory(null, nothing);
        mt_engine_set_stream_host(null, std::ptr::null());
        mt_stream_opened(null, 1);
        assert_eq!(mt_stream_received(null, 1, nothing), 0, "nothing more may be received");
        mt_stream_sent(null, 1, 10);
        mt_stream_closed(null, 1, none);
        mt_session_set_web_endpoint(null, 1, std::ptr::null());
        mt_session_use_telegram_web(null, 1, 0);
        mt_engine_reset_connections(null);
        mt_session_destroy(null, 1);
        mt_session_cancel(null, 1, 1);
        mt_session_set_paused(null, 1, 1);
        mt_session_set_online(null, 1, 1);
        mt_session_set_auth_key(null, 1, nothing, std::ptr::null(), 0, 0, none);
        mt_session_set_addresses(null, 1, std::ptr::null(), 0);
        mt_session_set_obfuscation_dc_id(null, 1, 2);
        mt_session_set_proxy(null, 1, std::ptr::null());
        assert_eq!(mt_session_enable_pfs(null, 1, 3600, std::ptr::null(), 0, 0, std::ptr::null()), 0);
        mt_session_offer_temporary_key(null, 1, std::ptr::null());
        mt_session_allow_permanent_key(null, 1, 1);
        mt_session_set_transport(null, 1, 1, 80);
        mt_session_update_environment(null, 1, std::ptr::null(), std::ptr::null());
        mt_session_set_auth_token_ready(null, 1, 1);
        mt_session_resolve_apns(null, 1, 1, none, none);
        mt_session_resolve_recaptcha(null, 1, 1, none);
        mt_session_fail_request(null, 1, 1, 400, none);
        mt_session_decide_retry(null, 1, 1, 1);
        mt_session_invalidate_initialization(null, 1);
        mt_session_set_time_difference(null, 1, 0.0);
        mt_session_destroy_auth_key(null, 1);
    }
}

#[test]
fn null_arguments_to_a_live_engine_are_ignored() {
    let rig = Rig::new();
    let server = TestServer::start(vec![random_key(3)], ServerOptions::default());
    let key = random_key(3);
    let session = rig.session(&server, Some(key.bytes()), 0, 0, &[]);
    unsafe {
        mt_session_send(rig.engine, session, std::ptr::null());
        mt_session_update_environment(rig.engine, session, std::ptr::null(), std::ptr::null());
        mt_session_offer_temporary_key(rig.engine, session, std::ptr::null());
        assert_eq!(
            mt_session_enable_pfs(rig.engine, session, 3600, std::ptr::null(), 0, 0, std::ptr::null()),
            0,
            "PFS needs a public key to make temporary keys with"
        );
        mt_session_set_web_endpoint(rig.engine, session, std::ptr::null());
    }
    let id = rig.send(session, 1, &[7], 0);
    assert!(rig.completed(id, 10), "null arguments changed nothing");
    unsafe { mt_session_set_auth_key(rig.engine, session, bytes(&[1, 2, 3]), std::ptr::null(), 0, 0, string("")) };
    assert!(
        rig.sink.find(10, |event| event.session == session && event.kind == AUTH_KEY_REQUIRED).is_some(),
        "a key of the wrong length is no key: the session asks the host for one"
    );
    let waiting = rig.send(session, 2, &[8], 0);
    assert!(!rig.completed(waiting, 1), "nothing goes out without a key");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    unsafe { mt_session_set_auth_key(rig.engine, session, bytes(key.bytes()), &salt, 1, 1, string("hash")) };
    assert!(rig.completed(waiting, 10), "the host's key lets the call through");
}

#[test]
fn host_controls_change_what_the_session_does() {
    let key = random_key(41);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let rig = Rig::new();
    let session = rig.session(&server, Some(key.bytes()), 0, 0, &[]);

    let first = rig.send(session, 1, &[1], 0);
    assert!(rig.completed(first, 10));
    let stored = rig.sink.find(5, |event| event.kind == INIT_HASH_STORED).expect("init hash stored");
    assert_eq!(stored.text, "hash");
    let inits = server.with_stats(|stats| stats.init_connections);

    let updated = environment("hash2");
    unsafe { mt_session_update_environment(rig.engine, session, &updated, std::ptr::null()) };
    let second = rig.send(session, 2, &[2], 0);
    assert!(rig.completed(second, 10));
    assert!(rig.sink.find(5, |event| event.kind == INIT_HASH_STORED && event.text == "hash2").is_some());
    assert_eq!(server.with_stats(|stats| stats.init_connections), inits + 1, "a new environment is sent again");

    unsafe { mt_session_invalidate_initialization(rig.engine, session) };
    let third = rig.send(session, 3, &[3], 0);
    assert!(rig.completed(third, 10));
    assert_eq!(server.with_stats(|stats| stats.init_connections), inits + 2, "and again once invalidated");

    unsafe { mt_session_set_paused(rig.engine, session, 1) };
    std::thread::sleep(Duration::from_millis(200));
    let paused = rig.send(session, 4, &[4], 0);
    assert!(!rig.completed(paused, 1), "a paused session sends nothing");
    unsafe { mt_session_set_paused(rig.engine, session, 0) };
    assert!(rig.completed(paused, 10), "and resumes when unpaused");

    let never = rig.send(session, TAG_NEVER, &[], 0);
    std::thread::sleep(Duration::from_millis(200));
    unsafe { mt_session_fail_request(rig.engine, session, never, 400, string("HOST_GAVE_UP")) };
    let failed = rig.sink.find(5, |event| event.kind == FAILED && event.request_id == never).expect("failed");
    assert_eq!((failed.code, failed.text.as_str()), (400, "HOST_GAVE_UP"));

    let cancelled = rig.send(session, TAG_NEVER, &[], 0);
    unsafe { mt_session_cancel(rig.engine, session, cancelled) };
    unsafe { mt_session_set_online(rig.engine, session, 0) };
    unsafe { mt_session_set_online(rig.engine, session, 1) };
    unsafe { mt_session_set_auth_token_ready(rig.engine, session, 1) };
    unsafe { mt_session_resolve_apns(rig.engine, session, 999, string("nonce"), string("secret")) };
    unsafe { mt_session_resolve_recaptcha(rig.engine, session, 999, string("token")) };
    unsafe { mt_session_set_time_difference(rig.engine, session, 0.0) };
    unsafe { mt_session_decide_retry(rig.engine, session, 999, 1) };
    let after = rig.send(session, 5, &[5], 0);
    assert!(rig.completed(after, 10), "controls about unknown requests change nothing");
    let events = rig.sink.wait(0, |_| true);
    assert!(!events.iter().any(|event| event.request_id == cancelled), "a cancelled request reports nothing");
    unsafe { mt_session_destroy(rig.engine, session) };
}

#[test]
fn rpc_events_cross_the_c_abi_with_their_fields() {
    let key = random_key(42);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let rig = Rig::new();
    let session = rig.session(&server, Some(key.bytes()), 0, 0, &[]);

    let update = rig.send(session, TAG_UPDATE_PUSH, &[], 0);
    assert!(rig.completed(update, 10));
    let pushed = rig.sink.find(5, |event| event.kind == UPDATE).expect("update");
    assert_eq!(&pushed.payload[..4], &0x74ae4240u32.to_le_bytes(), "the update body is the payload");

    let flood = rig.send(session, TAG_FLOOD_ONCE, &[], AUTOMATIC_FLOOD_WAIT | REPORT_FLOOD_WAIT);
    let reported = rig.sink.find(10, |event| event.kind == FLOOD_WAIT_REPORTED).expect("reported");
    assert_eq!((reported.request_id, reported.text.as_str()), (flood, "FLOOD_WAIT_1"));
    assert!(rig.completed(flood, 15), "then waited out automatically");

    let delegated = rig.send(session, TAG_SERVER_ERROR_ONCE, &[], DELEGATE_RETRY | RETRY_SERVER_ERRORS);
    let question = rig.sink.find(10, |event| event.kind == RETRY_DECISION).expect("retry question");
    assert_eq!(question.request_id, delegated);
    assert_eq!((question.code, question.text.as_str()), (500, "INTERNAL_SERVER_ERROR"));
    assert_eq!(question.integer2, 1, "one server error so far");
    assert!(question.text2.is_empty(), "no flood wait text");
    unsafe { mt_session_decide_retry(rig.engine, session, delegated, 1) };
    assert!(rig.completed(delegated, 15), "retried on the host's word");

    let salted = rig.send(session, TAG_BAD_SALT_ONCE, &[], 0);
    assert!(rig.completed(salted, 10));
    let changed = rig
        .sink
        .find(5, |event| event.kind == SALTS_UPDATED && event.salts.iter().any(|salt| salt.0 == SERVER_SALT + 1))
        .expect("the salt the server changed to reaches the host");
    assert!(changed.salts.iter().all(|(_, since, until)| until > since), "{:?}", changed.salts);

    let flooded = rig.send(session, TAG_TRANSPORT_ERROR_ONCE, &(-429i32).to_le_bytes(), 0);
    assert!(rig.sink.find(10, |event| event.kind == TRANSPORT_FLOOD).is_some());
    assert!(rig.completed(flooded, 15));

    let dropped = rig.send(session, TAG_DROP_CONNECTION_ONCE, &[], 0);
    assert!(rig.completed(dropped, 15));
    let drop = rig.sink.find(5, |event| event.kind == CONNECTION_DROPPED).expect("dropped");
    assert!(!drop.text.is_empty(), "the reason has a name");
    assert!(drop.value1 >= 0.0);

    let fresh = rig.send(session, TAG_NEW_SESSION, &[], 0);
    assert!(rig.completed(fresh, 10));
    assert!(rig.sink.find(5, |event| event.kind == UPDATES_RESET).is_some(), "a new server session resets updates");

    let unauthorized = rig.send(session, TAG_UNAUTHORIZED, &[], 0);
    let required = rig.sink.find(10, |event| event.kind == AUTHORIZATION_REQUIRED).expect("authorization");
    assert_eq!(required.text, "AUTH_KEY_UNREGISTERED");
    let failed = rig.sink.find(5, |event| event.kind == FAILED && event.request_id == unauthorized).expect("failed");
    assert_eq!(failed.code, 401);

    let usage = rig.sink.find(10, |event| event.kind == NETWORK_USAGE).expect("usage");
    assert!(usage.integer1 > 0 && usage.integer2 > 0, "bytes both ways: {usage:?}");
    let state = rig.sink.find(5, |event| event.kind == CONNECTION_STATE && event.flags & 2 != 0).expect("connected");
    assert!(state.flags & 1 != 0, "the network is available while connected");
    assert!(rig.sink.logs.lock().unwrap().iter().all(|(level, _)| (0..=3).contains(level)));

    unsafe { mt_session_destroy_auth_key(rig.engine, session) };
    let destroyed = rig.sink.find(10, |event| event.kind == AUTH_KEY_DESTROYED).expect("destroyed");
    assert!((0..=2).contains(&destroyed.code));
    assert!(server.with_stats(|stats| stats.destroyed_keys.contains(&key.id())));
}

#[test]
fn a_worker_without_an_auth_token_asks_the_host_for_one() {
    let key = random_key(43);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let rig = Rig::new();
    let worker = rig.session(&server, Some(key.bytes()), 2, 0, &[]);
    let id = rig.send(worker, TAG_UNAUTHORIZED, &[], 0);
    let asked = rig.sink.find(10, |event| event.session == worker && event.kind == AUTH_TOKEN_REQUIRED);
    assert!(asked.is_some());
    assert!(
        rig.sink.find(1, |event| event.kind == FAILED && event.request_id == id).is_none(),
        "the request waits for the token instead of failing"
    );
    unsafe { mt_session_fail_request(rig.engine, worker, id, 401, string("NO_TOKEN")) };
    let failed = rig.sink.find(5, |event| event.kind == FAILED && event.request_id == id).expect("failed");
    assert_eq!(failed.text, "NO_TOKEN");
}

#[test]
fn routing_controls_move_the_session() {
    let key = random_key(44);
    let first = TestServer::start(vec![key.clone()], ServerOptions::default());
    let second = TestServer::start(vec![key.clone()], ServerOptions::default());
    let rig = Rig::new();
    let session = rig.session(&first, Some(key.bytes()), 0, 0, &[]);
    let id = rig.send(session, 7, &[], 0);
    assert!(rig.completed(id, 10));

    unsafe { mt_session_set_obfuscation_dc_id(rig.engine, session, -7) };
    unsafe { mt_engine_reset_connections(rig.engine) };
    let id = rig.send(session, 8, &[], 0);
    assert!(rig.completed(id, 10));
    assert!(first.with_stats(|stats| stats.obfuscation_dc_ids.contains(&-7)), "the next connection says DC -7");

    let host = second.address.ip().to_string();
    let addresses = [MTAddress { host: string(&host), port: second.address.port(), secret: bytes(&[]) }];
    unsafe { mt_session_set_addresses(rig.engine, session, addresses.as_ptr(), addresses.len()) };
    unsafe { mt_engine_reset_connections(rig.engine) };
    let id = rig.send(session, 9, &[], 0);
    assert!(rig.completed(id, 10));
    assert_eq!(second.executions(9), 1, "the call ran on the new address");
    assert_eq!(first.executions(9), 0);

    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = closed.local_addr().unwrap().port();
    drop(closed);
    for kind in [1u8, 2, 3, 4] {
        let secret = [0x11u8; 16];
        let proxy = MTProxy {
            kind,
            host: string("127.0.0.1"),
            port: dead_port,
            username: string(if kind == 3 { "user" } else { "" }),
            password: string(if kind == 3 { "pass" } else { "" }),
            secret: bytes(if kind == 2 || kind == 4 { &secret } else { &[] }),
        };
        unsafe { mt_session_set_proxy(rig.engine, session, &proxy) };
    }
    let behind_proxy = rig.send(session, 10, &[], 0);
    assert!(!rig.completed(behind_proxy, 1), "nothing gets through a proxy that is not there");
    unsafe { mt_session_set_proxy(rig.engine, session, std::ptr::null()) };
    assert!(rig.completed(behind_proxy, 15), "removing the proxy lets the call through");

    unsafe { mt_engine_set_network_available(rig.engine, 0) };
    let offline = rig.send(session, 11, &[], 0);
    assert!(!rig.completed(offline, 1), "no network, no connection");
    unsafe { mt_engine_set_network_available(rig.engine, 1) };
    assert!(rig.completed(offline, 15));
    assert!(rig.sink.find(5, |event| event.kind == CONNECTION_STATE && event.flags & 1 == 0).is_some());
}

#[test]
fn route_memory_and_streams_from_the_host_are_taken_safely() {
    let rig = Rig::new();
    unsafe {
        mt_engine_set_network(rig.engine, bytes(b"home-wifi"));
        mt_engine_set_route_memory(rig.engine, bytes(&[0xff; 64]));
        let mut memory = vec![1u8, 1, 6];
        memory.extend_from_slice(b"office");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
        memory.extend_from_slice(&(now - 10.0).to_le_bytes());
        memory.extend_from_slice(&0f64.to_le_bytes());
        memory.extend_from_slice(&(now - 10.0).to_le_bytes());
        mt_engine_set_route_memory(rig.engine, bytes(&memory));
        mt_engine_set_network(rig.engine, bytes(b"office"));
        mt_engine_set_network(rig.engine, bytes(&[]));
        mt_stream_opened(rig.engine, 12345);
        assert_eq!(mt_stream_received(rig.engine, 12345, bytes(&[1, 2, 3])), 1, "an unknown stream is not throttled");
        mt_stream_sent(rig.engine, 12345, 3);
        mt_stream_closed(rig.engine, 12345, string("connection reset"));
        mt_stream_closed(rig.engine, 12346, MTString { data: std::ptr::null(), length: 0 });
        let endpoint = MTWebEndpoint {
            host: string("venus.web.telegram.org"),
            port: 443,
            path: string("/apiw1"),
            address: string("127.0.0.1"),
            ws_path: string("/apiws"),
        };
        mt_session_set_web_endpoint(rig.engine, 77, &endpoint);
        mt_session_use_telegram_web(rig.engine, 77, 1);
    }
    let key = random_key(45);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let session = rig.session(&server, Some(key.bytes()), 0, 0, &[]);
    let id = rig.send(session, 1, &[], 0);
    assert!(rig.completed(id, 10), "the engine works after all of that");
}

#[test]
fn key_lifecycle_events_cross_the_c_abi() {
    let key = random_key(46);
    let server = TestServer::start(
        vec![key.clone()],
        ServerOptions {
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                live_time: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let rig = Rig::new();
    let waiting = rig.session(&server, None, 0, 0, &[]);
    let required = rig.sink.find(10, |event| event.session == waiting && event.kind == AUTH_KEY_REQUIRED);
    assert!(required.is_some(), "without a key and without making one, the host is asked");

    let pem = mtproto_engine::mtproto_core::test_support::test_rsa_public_key_pem();
    let pems = [string(&pem)];
    let making = rig.session(&server, None, 0, 1, &pems);
    let id = rig.send(making, 3, &[], 0);
    let created = rig.sink.find(15, |event| event.session == making && event.kind == AUTH_KEY_CREATED).expect("key");
    assert_eq!(created.payload.len(), 256, "the key itself goes to the host");
    assert_eq!(created.integer2, 0, "a permanent key does not expire");
    assert!(
        server.keys().iter().any(|known| known.bytes()[..] == created.payload[..]),
        "the server holds the same key"
    );
    assert!(rig.completed(id, 10));

    let bad_pems = [string("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----")];
    let failing = rig.session(&server, None, 0, 1, &bad_pems);
    let failure =
        rig.sink.find(15, |event| event.session == failing && event.kind == AUTH_KEY_CREATION_FAILED).expect("failure");
    assert!(!failure.text.is_empty(), "the reason is given");

    let unknown = random_key(47);
    let rejected = rig.session(&server, Some(unknown.bytes()), 0, 0, &[]);
    rig.send(rejected, 4, &[], 0);
    let invalid = rig.sink.find(15, |event| event.session == rejected && event.kind == AUTH_KEY_INVALID).expect("-404");
    assert_eq!(invalid.code, -404);

    let pfs = rig.session(&server, Some(key.bytes()), 0, 0, &[]);
    unsafe { mt_session_allow_permanent_key(rig.engine, pfs, 0) };
    let enabled = unsafe { mt_session_enable_pfs(rig.engine, pfs, 86_400, pems.as_ptr(), 1, 0, std::ptr::null()) };
    assert_eq!(enabled, 1);
    let call = rig.send(pfs, 5, &[], 0);
    assert!(rig.completed(call, 20));
    assert!(rig.sink.find(5, |event| event.session == pfs && event.kind == TEMPORARY_KEY_BOUND).is_some());
    let in_use = rig.sink.find(5, |event| event.session == pfs && event.kind == TEMPORARY_KEY_IN_USE).expect("in use");
    assert_eq!(in_use.request_id, key.id(), "bound to the session's permanent key");
    assert!(rig.sink.find(1, |event| event.kind == TIME_DIFFERENCE).is_none_or(|event| event.value1.is_finite()));
}
