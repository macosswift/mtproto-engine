//! A host that makes permanent keys with the engine: a session with no key and no requests that only makes
//! one (`generate_key`, no `temp_key_expires_in`), the way the app's MTContext asks for a permanent key.
//! `MTEventKindAuthKeyCreated` says which kind of key it is and which `dc` the handshake carried.

use std::ffi::c_void;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[derive(Clone, Debug)]
struct Recorded {
    session: u64,
    kind: u32,
    code: i32,
    flags: u32,
    integer2: i64,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Recorded>>,
    condvar: Condvar,
}

impl Sink {
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[Recorded]) -> bool) -> Vec<Recorded> {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        while !predicate(&events) && Instant::now() < deadline {
            events = self.condvar.wait_timeout(events, Duration::from_millis(50)).unwrap().0;
        }
        events.clone()
    }
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
    sink.events.lock().unwrap().push(Recorded {
        session,
        kind: event.kind,
        code: event.code,
        flags: event.flags,
        integer2: event.integer2,
        payload,
    });
    sink.condvar.notify_all();
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn proxy() -> MTProxy {
    MTProxy { kind: 0, host: string(""), port: 0, username: string(""), password: string(""), secret: bytes(&[]) }
}

const COMPLETED: u32 = 1;
const AUTH_KEY_CREATED: u32 = 21;

fn server() -> TestServer {
    TestServer::start(
        vec![random_key(77)],
        ServerOptions {
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                live_time: true,
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

struct Host {
    engine: *mut MTEngine,
    sink: &'static Sink,
    host: String,
    port: u16,
    pem: String,
}

impl Host {
    fn new(server: &TestServer) -> Self {
        let sink: &'static Sink = Box::leak(Box::default());
        let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(on_event), None) };
        Self {
            engine,
            sink,
            host: server.address.ip().to_string(),
            port: server.address.port(),
            pem: mtproto_engine::mtproto_core::test_support::test_rsa_public_key_pem(),
        }
    }

    /// The session the app's permanent-key maker creates: no key, no requests, nothing but the handshake.
    fn key_maker(&self, obfuscation_dc_id: i16) -> u64 {
        let address = MTAddress { host: string(&self.host), port: self.port, secret: bytes(&[]) };
        let pems = [string(&self.pem)];
        let setup = MTSessionSetup {
            datacenter_id: 2,
            obfuscation_dc_id,
            role: 1,
            framing: 0,
            addresses: &address,
            address_count: 1,
            proxy: proxy(),
            auth_key: bytes(&[]),
            salts: std::ptr::null(),
            salt_count: 0,
            has_init_hash: 0,
            init_hash: string(""),
            generate_key: 1,
            public_keys_pem: pems.as_ptr(),
            public_key_count: 1,
            temp_key_expires_in: 0,
            environment: std::ptr::null(),
            time_difference: 0.0,
            online: 0,
            paused: 0,
            keep_connected: 0,
            idle_disconnect_after: 60.0,
            request_timeout: 5.0,
            pfs_lifetime: 0,
            pfs_make_permanent_key: 0,
            pfs_temporary_key: std::ptr::null(),
        };
        let session = unsafe { mt_session_create(self.engine, &setup) };
        unsafe { mt_session_set_transport(self.engine, session, 2, 0) };
        session
    }

    fn created(&self, session: u64, timeout: Duration) -> Vec<Recorded> {
        self.sink
            .wait(timeout, |events| events.iter().any(|e| e.session == session && e.kind == AUTH_KEY_CREATED))
            .into_iter()
            .filter(|e| e.session == session && e.kind == AUTH_KEY_CREATED)
            .collect()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        unsafe { mt_engine_destroy(self.engine) };
    }
}

#[test]
fn a_key_only_session_reports_its_permanent_key_with_the_dc_of_its_handshake() {
    let server = server();
    let host = Host::new(&server);
    let session = host.key_maker(10002);
    let created = host.created(session, Duration::from_secs(15));
    assert_eq!(created.len(), 1, "one permanent key: {created:?}");
    let key = &created[0];
    assert_eq!(key.flags, AUTH_KEY_CREATED_PERMANENT);
    assert_eq!(key.code, 10002, "the test offset the handshake carried");
    assert_eq!(key.integer2, 0, "a permanent key never expires");
    assert_eq!(key.payload.len(), 256);
    assert_eq!(server.with_stats(|stats| stats.handshake_dcs.clone()), vec![(10002, false)]);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(server.with_stats(|stats| stats.handshakes), 1, "nothing but the one key");
    unsafe { mt_session_destroy(host.engine, session) };
}

/// The permanent key a censored network needs: TCP to the datacenter gets no answer and Auto makes the
/// key over plain HTTP.
#[test]
fn a_key_only_session_makes_the_permanent_key_over_http_when_tcp_is_blackholed() {
    let server = server();
    server.set_tcp_blackhole(true);
    let host = Host::new(&server);
    let started = Instant::now();
    let session = host.key_maker(2);
    let created = host.created(session, Duration::from_secs(20));
    assert_eq!(created.len(), 1, "made over HTTP: {created:?}");
    assert_eq!((created[0].flags, created[0].code), (AUTH_KEY_CREATED_PERMANENT, 2));
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    assert!(server.with_stats(|stats| stats.http.requests) > 0, "the handshake went over HTTP");
    unsafe { mt_session_destroy(host.engine, session) };
}

/// A PFS session reports the temporary keys it makes as temporary, with their `dc`, and the key the host
/// made with a key-only session is the permanent key it binds them to.
#[test]
fn a_key_made_by_a_key_only_session_serves_a_pfs_session_that_reports_temporary_keys() {
    let server = server();
    let host = Host::new(&server);
    let maker = host.key_maker(2);
    let created = host.created(maker, Duration::from_secs(15));
    unsafe { mt_session_destroy(host.engine, maker) };
    let permanent = created.first().expect("the permanent key").payload.clone();

    let address = MTAddress { host: string(&host.host), port: host.port, secret: bytes(&[]) };
    let pems = [string(&host.pem)];
    let setup = MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: -2,
        role: 1,
        framing: 0,
        addresses: &address,
        address_count: 1,
        proxy: proxy(),
        auth_key: bytes(&permanent),
        salts: std::ptr::null(),
        salt_count: 0,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 0,
        public_keys_pem: pems.as_ptr(),
        public_key_count: 1,
        temp_key_expires_in: 0,
        environment: std::ptr::null(),
        time_difference: 0.0,
        online: 1,
        paused: 0,
        keep_connected: 0,
        idle_disconnect_after: 60.0,
        request_timeout: 5.0,
        pfs_lifetime: 86_400,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: std::ptr::null(),
    };
    let session = unsafe { mt_session_create(host.engine, &setup) };
    let id = unsafe { mt_engine_next_request_id(host.engine) };
    let body = call(5, &[5]);
    let request = MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
    unsafe { mt_session_send(host.engine, session, &request) };
    let events = host
        .sink
        .wait(Duration::from_secs(15), |events| events.iter().any(|e| e.session == session && e.kind == COMPLETED));
    assert!(events.iter().any(|e| e.session == session && e.kind == COMPLETED), "the call ran: {events:?}");
    let made: Vec<_> = events.iter().filter(|e| e.session == session && e.kind == AUTH_KEY_CREATED).collect();
    assert_eq!(made.len(), 1, "{made:?}");
    assert_eq!((made[0].flags, made[0].code), (AUTH_KEY_CREATED_TEMPORARY, -2), "a media temporary key");
    assert_ne!(made[0].integer2, 0);
    let permanent_id = mtproto_engine::mtproto_core::auth_key::AuthKey::from_slice(&permanent).unwrap().id();
    assert!(
        server.with_stats(|stats| stats.executed_under.contains(&(5, permanent_id))),
        "the call ran under the key the key-only session made"
    );
    unsafe { mt_session_destroy(host.engine, session) };
}
