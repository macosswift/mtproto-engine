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
    flags: u32,
    integer1: i64,
    integer2: i64,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Recorded>>,
    condvar: Condvar,
}

impl Sink {
    fn wait(&self, predicate: impl Fn(&[Recorded]) -> bool) -> Vec<Recorded> {
        let deadline = Instant::now() + Duration::from_secs(15);
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
        request_id: event.request_id,
        flags: event.flags,
        integer1: event.integer1,
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
const AUTH_KEY_REQUIRED: u32 = 19;
const AUTH_KEY_CREATED: u32 = 21;
const TEMPORARY_KEY_IN_USE: u32 = 33;

/// A host that keeps keys as the app does: the permanent key comes from it, and the bound temporary
/// key one session made is handed to the next session.
#[test]
fn a_host_supplies_the_permanent_key_and_shares_bound_temporary_keys() {
    let perm = random_key(91);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                live_time: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(on_event), None) };
    let host = server.address.ip().to_string();
    let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&[]) };
    let pem = mtproto_engine::mtproto_core::test_support::test_rsa_public_key_pem();
    let pems = [string(&pem)];
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    let environment = MTEnvironment {
        layer: 230,
        api_id: 1,
        device_model: string("test"),
        system_version: string("1"),
        app_version: string("1"),
        system_lang_code: string("en"),
        lang_pack: string(""),
        lang_code: string("en"),
        has_proxy: 0,
        proxy_address: string(""),
        proxy_port: 0,
        has_params: 0,
        params: bytes(&[]),
        init_hash: string(""),
        disable_updates: 0,
    };
    let setup = |temporary_key: *const MTTemporaryKey| MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: 2,
        role: 0,
        framing: 0,
        addresses: &address,
        address_count: 1,
        proxy: proxy(),
        auth_key: bytes(&[]),
        salts: std::ptr::null(),
        salt_count: 0,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 0,
        public_keys_pem: pems.as_ptr(),
        public_key_count: 1,
        temp_key_expires_in: 0,
        environment: &environment,
        time_difference: 0.0,
        online: 1,
        paused: 0,
        keep_connected: 1,
        idle_disconnect_after: 0.0,
        request_timeout: 5.0,
        pfs_lifetime: 86_400,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: temporary_key,
    };
    let send = |session: u64, tag: u32| -> u64 {
        let id = unsafe { mt_engine_next_request_id(engine) };
        let body = call(tag, &[1, 2, 3]);
        let request = MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
        unsafe { mt_session_send(engine, session, &request) };
        id
    };

    let first = unsafe { mt_session_create(engine, &setup(std::ptr::null())) };
    let first_call = send(first, 1);
    sink.wait(|events| events.iter().any(|e| e.session == first && e.kind == AUTH_KEY_REQUIRED));
    assert_eq!(server.with_stats(|stats| stats.handshakes), 0, "no key is made before the host's");
    unsafe { mt_session_set_auth_key(engine, first, bytes(perm.bytes()), &salt, 1, 0, string("")) };
    let events = sink.wait(|events| {
        events.iter().any(|e| e.session == first && e.kind == COMPLETED && e.request_id == first_call)
            && events.iter().any(|e| e.session == first && e.kind == TEMPORARY_KEY_IN_USE)
    });
    let in_use = events.iter().find(|e| e.session == first && e.kind == TEMPORARY_KEY_IN_USE).expect("in use");
    assert_eq!(in_use.flags, 0, "made by the session");
    assert_eq!(in_use.request_id, perm.id(), "bound to the host's permanent key");
    let created = events
        .iter()
        .find(|e| e.session == first && e.kind == AUTH_KEY_CREATED)
        .expect("the temporary key's AuthKeyCreated");
    assert_ne!(created.integer2, 0, "a temporary key carries its expiry");
    assert_eq!(created.integer2, in_use.integer2);
    assert_eq!(server.with_stats(|stats| (stats.handshakes, stats.binds)), (1, 1));

    let salt_for_temporary = MTSaltEntry { salt: created.integer1, valid_since: now - 60.0, valid_until: now + 1800.0 };
    let kept = MTTemporaryKey {
        key: bytes(&created.payload),
        expires_at: created.integer2 as i32,
        bound_to: in_use.request_id as i64,
        salts: &salt_for_temporary,
        salt_count: 1,
        has_init_hash: 0,
        init_hash: string(""),
    };
    let second = unsafe { mt_session_create(engine, &setup(&kept)) };
    unsafe { mt_session_set_auth_key(engine, second, bytes(perm.bytes()), &salt, 1, 0, string("")) };
    let second_call = send(second, 2);
    let events = sink.wait(|events| {
        events.iter().any(|e| e.session == second && e.kind == COMPLETED && e.request_id == second_call)
    });
    assert!(events.iter().any(|e| e.session == second && e.kind == COMPLETED && e.request_id == second_call));
    let adopted = events.iter().find(|e| e.session == second && e.kind == TEMPORARY_KEY_IN_USE).expect("in use");
    assert_eq!((adopted.flags, adopted.integer1), (1, in_use.integer1), "the host's key, taken as it is");
    assert_eq!(server.with_stats(|stats| (stats.handshakes, stats.binds)), (1, 1), "no second handshake or bind");

    let third = unsafe { mt_session_create(engine, &setup(std::ptr::null())) };
    unsafe { mt_session_set_auth_key(engine, third, bytes(perm.bytes()), &salt, 1, 0, string("")) };
    unsafe { mt_session_offer_temporary_key(engine, third, &kept) };
    let third_call = send(third, 3);
    let events = sink
        .wait(|events| events.iter().any(|e| e.session == third && e.kind == COMPLETED && e.request_id == third_call));
    assert!(events.iter().any(|e| e.session == third && e.kind == TEMPORARY_KEY_IN_USE && e.flags == 1));
    assert_eq!(server.with_stats(|stats| stats.handshakes), 1, "the offer came before a handshake was needed");

    unsafe {
        mt_session_destroy(engine, first);
        mt_session_destroy(engine, second);
        mt_session_destroy(engine, third);
        mt_engine_destroy(engine);
    }
}
