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
    println!("{{\"address\":\"{}\",\"key_hex\":\"{}\",\"salt\":{}}}", server.address, hex(key.bytes()), SERVER_SALT);
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        match line.trim() {
            "stats" => {
                let summary = server.with_stats(|stats| {
                    let executions: usize = stats.executions.values().sum();
                    let mut tags: Vec<_> = stats.executions.iter().collect();
                    tags.sort();
                    let tags: Vec<String> = tags.iter().map(|(tag, count)| format!("\"{tag}\":{count}")).collect();
                    let dc_ids: Vec<String> = stats.obfuscation_dc_ids.iter().map(|id| id.to_string()).collect();
                    format!(
                        "{{\"connections\":{},\"executions\":{},\"init_connections\":{},\"state_requests\":{},\"pings\":{},\"closed_by_client\":{},\"duplicate_msg_ids\":{},\"redelivered_answers\":{},\"obfuscation_dc_ids\":[{}],\"tags\":{{{}}}}}",
                        stats.connections,
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
            "quit" => break,
            _ => {}
        }
    }
}
