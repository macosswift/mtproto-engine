use std::io::BufRead;

use mtproto_core::auth_key::AuthKey;
use mtproto_testserver::{SERVER_SALT, ServerOptions, TestServer, random_key};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut key: Option<AuthKey> = None;
    let mut options = ServerOptions::default();
    options.handshake.live_time = true;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--key-hex" => key = AuthKey::from_slice(&unhex(&args.next().expect("value"))),
            "--secret" => options.secret = Some(unhex(&args.next().expect("value"))),
            "--socks5" => options.socks5 = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let key = key.unwrap_or_else(|| random_key(std::process::id() as u64));
    let server = TestServer::start(vec![key.clone()], options);
    let pem = mtproto_core::test_support::test_rsa_public_key_pem().replace('\n', "\\n");
    println!(
        "{{\"address\":\"{}\",\"key_hex\":\"{}\",\"salt\":{},\"public_key_pem\":\"{}\"}}",
        server.address,
        hex(key.bytes()),
        SERVER_SALT,
        pem
    );
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if let Some(key) = line.trim().strip_prefix("add-key ").and_then(|hex| AuthKey::from_slice(&unhex(hex))) {
            server.add_key(key);
            continue;
        }
        match line.trim() {
            "stats" => {
                let summary = server.with_stats(|stats| {
                    let executions: usize = stats.executions.values().sum();
                    let mut tags: Vec<_> = stats.executions.iter().collect();
                    tags.sort();
                    let tags: Vec<String> = tags.iter().map(|(tag, count)| format!("\"{tag}\":{count}")).collect();
                    let dc_ids: Vec<String> = stats.obfuscation_dc_ids.iter().map(|id| id.to_string()).collect();
                    let handshake_dcs: Vec<String> = stats
                        .handshake_dcs
                        .iter()
                        .map(|(dc, temporary)| format!("{{\"dc\":{dc},\"temporary\":{temporary}}}"))
                        .collect();
                    format!(
                        "{{\"connections\":{},\"invoke_after\":{},\"handshakes\":{},\"binds\":{},\"handshake_dcs\":[{}],\"executions\":{},\"init_connections\":{},\"state_requests\":{},\"pings\":{},\"closed_by_client\":{},\"duplicate_msg_ids\":{},\"redelivered_answers\":{},\"obfuscation_dc_ids\":[{}],\"tags\":{{{}}}}}",
                        stats.connections,
                        stats.invoke_after,
                        stats.handshakes,
                        stats.binds,
                        handshake_dcs.join(","),
                        executions,
                        stats.init_connections,
                        stats.state_requests,
                        stats.pings,
                        stats.closed_by_client,
                        stats.duplicate_msg_ids,
                        stats.redelivered_answers,
                        dc_ids.join(","),
                        tags.join(",")
                    )
                });
                println!("{summary}");
            }
            "tcp-blackhole on" => server.set_tcp_blackhole(true),
            "tcp-blackhole off" => server.set_tcp_blackhole(false),
            "drop-temporary-keys" => server.drop_temporary_keys(),
            "quit" => break,
            _ => {}
        }
    }
}
