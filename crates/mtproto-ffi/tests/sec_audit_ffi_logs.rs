//! What the engine logs goes to the host's log files and crash reports. A run that makes a permanent
//! key, binds temporary keys (PFS), talks through an MTProxy secret and carries private request bodies
//! must not put any key, salt, proxy secret or body into a log line.

use std::ffi::c_void;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[derive(Default)]
struct Sink {
    logs: Mutex<Vec<String>>,
    keys: Mutex<Vec<(Vec<u8>, i64)>>,
    completed: Mutex<Vec<u64>>,
    condvar: Condvar,
}

unsafe extern "C" fn on_event(context: *mut c_void, _session: u64, event: *const MTEvent) {
    let sink = unsafe { &*(context as *const Sink) };
    let event = unsafe { &*event };
    if !event.payload.is_null() {
        let data =
            unsafe { std::slice::from_raw_parts(mt_buffer_data(event.payload), mt_buffer_length(event.payload)) }
                .to_vec();
        unsafe { mt_buffer_free(event.payload) };
        if event.kind == 21 {
            sink.keys.lock().unwrap().push((data, event.integer1));
        }
    }
    if event.kind == 1 || event.kind == 2 {
        sink.completed.lock().unwrap().push(event.request_id);
    }
    sink.condvar.notify_all();
}

unsafe extern "C" fn on_log(context: *mut c_void, _level: i32, message: MTString) {
    let sink = unsafe { &*(context as *const Sink) };
    let text = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(message.data, message.length) });
    sink.logs.lock().unwrap().push(text.into_owned());
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decimal_list(data: &[u8]) -> String {
    data.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
}

#[test]
fn logs_never_carry_keys_salts_secrets_or_bodies() {
    let mut secret = vec![0xee];
    secret.extend_from_slice(&[
        0x5e, 0xc7, 0x3e, 0x71, 0x9a, 0x2b, 0xd4, 0x08, 0x66, 0x13, 0xf0, 0x4c, 0xa9, 0x37, 0x81, 0xbd,
    ]);
    secret.extend_from_slice(b"front.example.org");
    let server = TestServer::start(
        Vec::new(),
        ServerOptions {
            secret: Some(secret.clone()),
            handshake: mtproto_engine::mtproto_core::test_support::ServerHandshakeBehavior {
                live_time: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(on_event), Some(on_log)) };
    let host = server.address.ip().to_string();
    let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&secret) };
    let pem = mtproto_engine::mtproto_core::test_support::test_rsa_public_key_pem();
    let pems = [string(&pem)];
    let environment = MTEnvironment {
        layer: 230,
        api_id: 1,
        device_model: string("model"),
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
        init_hash: string("init-hash-value"),
        disable_updates: 0,
    };
    let setup = MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: 2,
        role: 0,
        framing: 2,
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
        request_timeout: 10.0,
        pfs_lifetime: 3600,
        pfs_make_permanent_key: 1,
        pfs_temporary_key: std::ptr::null(),
    };
    let session = unsafe { mt_session_create(engine, &setup) };
    let private = b"PRIVATE-BODY-7f3a91";
    for round in 0..3u32 {
        let mut ids = Vec::new();
        for tag in 1..=6u32 {
            let id = unsafe { mt_engine_next_request_id(engine) };
            let body = match (round, tag) {
                (1, 1) => bad_msg_call(16, false),
                (2, 1) => transport_error_call(-404),
                _ => call(tag, private),
            };
            let request =
                MTRequest { id, body: bytes(&body), flags: 1 | 4, expected_response_size: 0, invoke_after: 0 };
            unsafe { mt_session_send(engine, session, &request) };
            ids.push(id);
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut completed = sink.completed.lock().unwrap();
        while !ids[1..].iter().all(|id| completed.contains(id)) && Instant::now() < deadline {
            completed = sink.condvar.wait_timeout(completed, Duration::from_millis(50)).unwrap().0;
        }
        assert!(ids[1..].iter().all(|id| completed.contains(id)), "round {round}: every call answered");
        drop(completed);
        unsafe { mt_engine_reset_connections(engine) };
    }
    unsafe {
        mt_session_destroy(engine, session);
        mt_engine_destroy(engine);
    }

    let keys = sink.keys.lock().unwrap().clone();
    assert!(keys.len() >= 2, "a permanent and a temporary key were made: {}", keys.len());
    let logs = sink.logs.lock().unwrap().join("\n");
    assert!(logs.lines().count() >= 4, "the run logged its keys, drops and errors:\n{logs}");
    let mut forbidden = vec![
        hex(&secret[1..9]),
        decimal_list(&secret[1..9]),
        String::from_utf8_lossy(private).into_owned(),
        hex(private),
        "init-hash-value".to_string(),
    ];
    for (key, salt) in &keys {
        forbidden.push(hex(&key[..8]));
        forbidden.push(hex(&key[248..]));
        forbidden.push(decimal_list(&key[..8]));
        forbidden.push(salt.to_string());
        forbidden.push(format!("{salt:x}"));
    }
    for needle in forbidden {
        assert!(!logs.to_lowercase().contains(&needle.to_lowercase()), "the logs carry {needle:?}:\n{logs}");
    }
}
