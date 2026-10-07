//! H-03: a key the engine creates reaches the host as a secret buffer, wiped when the host frees it; once the
//! engine is destroyed no copy of it is left in memory the engine freed. The scanning allocator from
//! mtproto-core's tests looks for the key in every heap block the test thread or an engine thread frees.

#[path = "../../mtproto-core/tests/support/freed_memory.rs"]
mod freed_memory;

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

const COMPLETED: u32 = 1;
const AUTH_KEY_CREATED: u32 = 21;

static CREATED_KEY: Mutex<Option<usize>> = Mutex::new(None);
static COMPLETIONS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn keep_the_key(_context: *mut c_void, _session: u64, event: *const MTEvent) {
    let event = unsafe { &*event };
    if event.kind == AUTH_KEY_CREATED && !event.payload.is_null() {
        *CREATED_KEY.lock().unwrap() = Some(event.payload as usize);
        return;
    }
    if !event.payload.is_null() {
        unsafe { mt_buffer_free(event.payload) };
    }
    if event.kind == COMPLETED {
        COMPLETIONS.fetch_add(1, Ordering::AcqRel);
    }
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn wait_until(done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

fn send_call(engine: *mut MTEngine, session: u64, tag: u32) {
    let id = unsafe { mt_engine_next_request_id(engine) };
    let body = call(tag, &[tag as u8; 4]);
    let request = MTRequest { id, body: bytes(&body), flags: 1, expected_response_size: 0, invoke_after: 0 };
    unsafe { mt_session_send(engine, session, &request) };
}

#[test]
fn a_created_key_is_wiped_when_the_host_frees_it_and_after_engine_destroy() {
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                live_time: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let engine = unsafe { mt_engine_create(2, std::ptr::null_mut(), Some(keep_the_key), None) };
    assert!(!engine.is_null());
    let host = server.address.ip().to_string();
    let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&[]) };
    let pem = mtproto_engine::mtproto_core::test_support::test_rsa_public_key_pem();
    let pems = [string(&pem)];
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
        auth_key: bytes(&[]),
        salts: std::ptr::null(),
        salt_count: 0,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 1,
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
        pfs_lifetime: 0,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: std::ptr::null(),
    };
    let session = unsafe { mt_session_create(engine, &setup) };
    assert_ne!(session, 0);
    send_call(engine, session, 1);
    assert!(wait_until(|| COMPLETIONS.load(Ordering::Acquire) >= 1 && CREATED_KEY.lock().unwrap().is_some()));
    let payload = CREATED_KEY.lock().unwrap().take().unwrap() as *mut MTBuffer;
    let created: [u8; 256] = unsafe { std::slice::from_raw_parts(mt_buffer_data(payload), mt_buffer_length(payload)) }
        .try_into()
        .expect("a 256-byte key");

    let mut watch = freed_memory::watch();
    watch.secret("created key", &created);
    freed_memory::only_threads(freed_memory::is_engine_thread);
    watch.arm();
    watch.arm_every_thread();
    unsafe { mt_buffer_free(payload) };
    let freed_by_host = watch.found();
    send_call(engine, session, 2);
    let completed = wait_until(|| COMPLETIONS.load(Ordering::Acquire) >= 2);
    unsafe { mt_session_destroy(engine, session) };
    unsafe { mt_engine_destroy(engine) };
    watch.stop();
    assert!(freed_by_host.is_empty(), "mt_buffer_free leaves the key in freed memory");
    assert!(completed);
    assert!(watch.found().is_empty(), "left in freed memory by the engine: {:?}", watch.found());
    drop(server);
}
