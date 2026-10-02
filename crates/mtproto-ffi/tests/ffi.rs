use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::process::Command;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine_ffi::*;
use mtproto_testserver::*;

type Recorded = (u64, u32, u64, i32, Vec<u8>, String);

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<Recorded>>,
    condvar: Condvar,
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
    let text = if event.text.data.is_null() {
        String::new()
    } else {
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(event.text.data, event.text.length) }).into_owned()
    };
    sink.events.lock().unwrap().push((session, event.kind, event.request_id, event.code, payload, text));
    sink.condvar.notify_all();
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

#[test]
fn c_abi_end_to_end() {
    let key = random_key(77);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let sink: &'static Sink = Box::leak(Box::default());
    let engine = unsafe { mt_engine_create(2, sink as *const Sink as *mut c_void, Some(on_event), None) };
    assert!(!engine.is_null());
    assert_eq!(mt_engine_abi_version(), 1);
    let host = server.address.ip().to_string();
    let address = MTAddress { host: string(&host), port: server.address.port(), secret: bytes(&[]) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    let environment = MTEnvironment {
        layer: 230,
        api_id: 9,
        device_model: string("Mac"),
        system_version: string("26"),
        app_version: string("1"),
        system_lang_code: string("en"),
        lang_pack: string("macos"),
        lang_code: string("en"),
        has_proxy: 0,
        proxy_address: string(""),
        proxy_port: 0,
        has_params: 0,
        params: bytes(&[]),
        init_hash: string("hash"),
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
        auth_key: bytes(key.bytes()),
        salts: &salt,
        salt_count: 1,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 0,
        public_keys_pem: std::ptr::null(),
        public_key_count: 0,
        temp_key_expires_in: 0,
        environment: &environment,
        time_difference: 0.0,
        online: 1,
        paused: 0,
        keep_connected: 1,
        idle_disconnect_after: 0.0,
        request_timeout: 5.0,
    };
    let session = unsafe { mt_session_create(engine, &setup) };
    assert_ne!(session, 0);
    let mut expected = Vec::new();
    for tag in 1..=10u32 {
        let id = unsafe { mt_engine_next_request_id(engine) };
        let body = call(tag, &[tag as u8; 3]);
        let request =
            MTRequest { id, body: bytes(&body), flags: 1 | 4 | 8, expected_response_size: 0, invoke_after: 0 };
        unsafe { mt_session_send(engine, session, &request) };
        expected.push((id, tag));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = sink.events.lock().unwrap();
    while events.iter().filter(|e| e.1 == 1).count() < 10 && Instant::now() < deadline {
        events = sink.condvar.wait_timeout(events, Duration::from_millis(100)).unwrap().0;
    }
    for (id, tag) in expected {
        let completed = events.iter().find(|e| e.1 == 1 && e.2 == id).expect("completed");
        assert_eq!(completed.0, session);
        let (result_tag, payload) = parse_result(&completed.4).unwrap();
        assert_eq!(result_tag, tag);
        assert_eq!(payload, vec![tag as u8; 3]);
    }
    assert!(events.iter().any(|e| e.1 == 10 && e.5 == "hash"), "init hash stored");
    assert!(events.iter().any(|e| e.1 == 3), "quick acks");
    assert!(events.iter().any(|e| e.1 == 18), "connection state");
    drop(events);
    unsafe { mt_session_destroy(engine, session) };
    unsafe { mt_engine_destroy(engine) };
}

#[test]
fn null_pointers_are_ignored() {
    unsafe {
        mt_engine_destroy(std::ptr::null_mut());
        assert_eq!(mt_session_create(std::ptr::null_mut(), std::ptr::null()), 0);
        mt_session_send(std::ptr::null_mut(), 1, std::ptr::null());
        mt_buffer_free(std::ptr::null_mut());
        assert_eq!(mt_buffer_length(std::ptr::null()), 0);
        assert!(mt_buffer_data(std::ptr::null()).is_null());
    }
}

#[test]
fn c_header_layout_matches_rust() {
    let header_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/include");
    let out_dir = std::env::temp_dir().join(format!("mtproto-abi-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();
    let source = out_dir.join("abi.c");
    let program = r#"
#include <stdio.h>
#include <stddef.h>
#include "mtproto_engine.h"
#define S(T) printf(#T " %zu\n", sizeof(T));
#define O(T, F) printf(#T "." #F " %zu\n", offsetof(T, F));
int main(void) {
    S(MTBytes) S(MTString) S(MTSaltEntry) S(MTAddress) S(MTProxy) S(MTEnvironment) S(MTSessionSetup) S(MTRequest) S(MTEvent)
    O(MTAddress, port) O(MTAddress, secret)
    O(MTProxy, host) O(MTProxy, port) O(MTProxy, secret)
    O(MTEnvironment, has_proxy) O(MTEnvironment, proxy_port) O(MTEnvironment, params) O(MTEnvironment, init_hash) O(MTEnvironment, disable_updates)
    O(MTSessionSetup, role) O(MTSessionSetup, framing) O(MTSessionSetup, addresses) O(MTSessionSetup, proxy) O(MTSessionSetup, auth_key)
    O(MTSessionSetup, has_init_hash) O(MTSessionSetup, generate_key) O(MTSessionSetup, temp_key_expires_in) O(MTSessionSetup, environment)
    O(MTSessionSetup, time_difference) O(MTSessionSetup, online) O(MTSessionSetup, keep_connected) O(MTSessionSetup, idle_disconnect_after) O(MTSessionSetup, request_timeout)
    O(MTRequest, body) O(MTRequest, flags) O(MTRequest, expected_response_size) O(MTRequest, invoke_after)
    O(MTEvent, request_id) O(MTEvent, code) O(MTEvent, flags) O(MTEvent, text) O(MTEvent, text2) O(MTEvent, payload) O(MTEvent, value1) O(MTEvent, integer1) O(MTEvent, salts) O(MTEvent, salt_count)
    return 0;
}
"#;
    std::fs::write(&source, program).unwrap();
    let binary = out_dir.join("abi");
    let status = Command::new("clang")
        .args(["-std=c11", "-I", header_dir, "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .expect("clang");
    assert!(status.success());
    let output = String::from_utf8(Command::new(&binary).output().unwrap().stdout).unwrap();
    let mut expected: Vec<(String, usize)> = vec![
        ("MTBytes".into(), size_of::<MTBytes>()),
        ("MTString".into(), size_of::<MTString>()),
        ("MTSaltEntry".into(), size_of::<MTSaltEntry>()),
        ("MTAddress".into(), size_of::<MTAddress>()),
        ("MTProxy".into(), size_of::<MTProxy>()),
        ("MTEnvironment".into(), size_of::<MTEnvironment>()),
        ("MTSessionSetup".into(), size_of::<MTSessionSetup>()),
        ("MTRequest".into(), size_of::<MTRequest>()),
        ("MTEvent".into(), size_of::<MTEvent>()),
    ];
    macro_rules! o {
        ($t:ty, $f:ident) => {
            expected.push((format!("{}.{}", stringify!($t), stringify!($f)), offset_of!($t, $f)));
        };
    }
    o!(MTAddress, port);
    o!(MTAddress, secret);
    o!(MTProxy, host);
    o!(MTProxy, port);
    o!(MTProxy, secret);
    o!(MTEnvironment, has_proxy);
    o!(MTEnvironment, proxy_port);
    o!(MTEnvironment, params);
    o!(MTEnvironment, init_hash);
    o!(MTEnvironment, disable_updates);
    o!(MTSessionSetup, role);
    o!(MTSessionSetup, framing);
    o!(MTSessionSetup, addresses);
    o!(MTSessionSetup, proxy);
    o!(MTSessionSetup, auth_key);
    o!(MTSessionSetup, has_init_hash);
    o!(MTSessionSetup, generate_key);
    o!(MTSessionSetup, temp_key_expires_in);
    o!(MTSessionSetup, environment);
    o!(MTSessionSetup, time_difference);
    o!(MTSessionSetup, online);
    o!(MTSessionSetup, keep_connected);
    o!(MTSessionSetup, idle_disconnect_after);
    o!(MTSessionSetup, request_timeout);
    o!(MTRequest, body);
    o!(MTRequest, flags);
    o!(MTRequest, expected_response_size);
    o!(MTRequest, invoke_after);
    o!(MTEvent, request_id);
    o!(MTEvent, code);
    o!(MTEvent, flags);
    o!(MTEvent, text);
    o!(MTEvent, text2);
    o!(MTEvent, payload);
    o!(MTEvent, value1);
    o!(MTEvent, integer1);
    o!(MTEvent, salts);
    o!(MTEvent, salt_count);
    for (name, value) in expected {
        let line = format!("{name} {value}");
        assert!(output.lines().any(|l| l == line), "C layout differs for {name}: rust={value}\n{output}");
    }
}
