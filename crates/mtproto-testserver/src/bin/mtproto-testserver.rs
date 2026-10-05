use std::io::BufRead;

use mtproto_core::auth_key::AuthKey;
use mtproto_testserver::{Blackhole, SERVER_SALT, ServerOptions, TestServer, WebFront, random_key};

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
    let mut web_front = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--web-front" => web_front = true,
            "--key-hex" => key = AuthKey::from_slice(&unhex(&args.next().expect("value"))),
            "--secret" => options.secret = Some(unhex(&args.next().expect("value"))),
            "--socks5" => options.socks5 = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let key = key.unwrap_or_else(|| random_key(std::process::id() as u64));
    let server = TestServer::start(vec![key.clone()], options);
    let front = web_front.then(|| (WebFront::start(server.address), Blackhole::start()));
    let pem = mtproto_core::test_support::test_rsa_public_key_pem().replace('\n', "\\n");
    let web = front.as_ref().map_or(String::new(), |(front, blackhole)| {
        format!(",\"web_front\":\"{}\",\"blackhole\":\"{}\"", front.address, blackhole.address)
    });
    println!(
        "{{\"address\":\"{}\",\"key_hex\":\"{}\",\"salt\":{},\"public_key_pem\":\"{}\"{}}}",
        server.address,
        hex(key.bytes()),
        SERVER_SALT,
        pem,
        web
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
            "web-front-stats" => {
                let stats = front.as_ref().map(|(front, _)| front.stats()).unwrap_or_default();
                let quoted =
                    |items: &[String]| items.iter().map(|item| format!("{item:?}")).collect::<Vec<_>>().join(",");
                println!(
                    "{{\"connections\":{},\"handshakes\":{},\"server_names\":[{}],\"alpn\":[{}],\"requests\":[{}],\"websockets\":{},\"frames_in\":{},\"violations\":{}}}",
                    stats.connections,
                    stats.handshakes,
                    quoted(&stats.server_names),
                    quoted(&stats.alpn),
                    quoted(&stats.requests),
                    stats.websockets,
                    stats.frames_in,
                    stats.violations
                );
            }
            "websocket-refused on" | "websocket-refused off" => {
                if let Some((front, _)) = &front {
                    front.set_websocket_refused(line.trim().ends_with("on"));
                }
            }
            "tcp-blackhole on" => server.set_tcp_blackhole(true),
            "tcp-blackhole off" => server.set_tcp_blackhole(false),
            "drop-temporary-keys" => server.drop_temporary_keys(),
            "quit" => break,
            _ => {}
        }
    }
}
