use std::io::BufRead;

use mtproto_core::auth_key::AuthKey;
use std::sync::Arc;

use mtproto_testserver::api::{ApiWorld, WorldOptions};
use mtproto_testserver::{
    BindFault, Blackhole, HelpTestReply, SERVER_SALT, ServerOptions, Stats, TestServer, WebFront, random_key,
};

/// The datacenter a second server plays with `--api`: the foreign datacenter authorizations are
/// transferred to, sharing the API world (exports, imports) with the main one.
const FOREIGN_DATACENTER_ID: i32 = 4;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

fn summary(stats: &Stats) -> String {
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
        "{{\"connections\":{},\"invoke_after\":{},\"handshakes\":{},\"binds\":{},\"handshake_dcs\":[{}],\"executions\":{},\"init_connections\":{},\"state_requests\":{},\"pings\":{},\"closed_by_client\":{},\"duplicate_msg_ids\":{},\"redelivered_answers\":{},\"obfuscation_dc_ids\":[{}],\"tags\":{{{}}},\"bind_failures\":[{}],\"http_requests\":{},\"help_tests\":{},\"hidden_key_rejections\":{}}}",
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
        tags.join(","),
        stats.bind_failures.iter().map(|failure| format!("{failure:?}")).collect::<Vec<_>>().join(","),
        stats.http.requests,
        stats.help_tests,
        stats.hidden_key_rejections
    )
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut key: Option<AuthKey> = None;
    let mut options = ServerOptions::default();
    options.handshake.live_time = true;
    let mut web_front = false;
    let mut api = false;
    let mut world_options = WorldOptions::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--web-front" => web_front = true,
            "--api" => api = true,
            "--import-fails-once" => world_options.import_fails_once = Some((400, "AUTH_BYTES_INVALID")),
            "--import-fails-once-500" => world_options.import_fails_once = Some((500, "INTERDC_4_CALL_ERROR")),
            "--key-hex" => key = AuthKey::from_slice(&unhex(&args.next().expect("value"))),
            "--secret" => options.secret = Some(unhex(&args.next().expect("value"))),
            "--socks5" => options.socks5 = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let key = key.unwrap_or_else(|| random_key(std::process::id() as u64));
    let world = api.then(|| Arc::new(ApiWorld::new(world_options, &[], std::process::id() as u64)));
    if let Some(world) = &world {
        options.api = Some(world.clone());
        options.datacenter_id = world_options.main_datacenter_id;
    }
    let foreign = world.as_ref().map(|_| {
        TestServer::start(vec![key.clone()], ServerOptions { datacenter_id: FOREIGN_DATACENTER_ID, ..options.clone() })
    });
    let server = TestServer::start(vec![key.clone()], options);
    let servers: Vec<&TestServer> = std::iter::once(&server).chain(foreign.as_ref()).collect();
    let front = web_front.then(|| (WebFront::start(server.address), Blackhole::start()));
    let pem = mtproto_core::test_support::test_rsa_public_key_pem().replace('\n', "\\n");
    let web = front.as_ref().map_or(String::new(), |(front, blackhole)| {
        format!(",\"web_front\":\"{}\",\"blackhole\":\"{}\"", front.address, blackhole.address)
    });
    let foreign_address = foreign.as_ref().map_or(String::new(), |foreign| {
        format!(",\"foreign_address\":\"{}\",\"foreign_datacenter_id\":{FOREIGN_DATACENTER_ID}", foreign.address)
    });
    println!(
        "{{\"address\":\"{}\",\"key_hex\":\"{}\",\"salt\":{},\"public_key_pem\":\"{}\"{}{}}}",
        server.address,
        hex(key.bytes()),
        SERVER_SALT,
        pem,
        web,
        foreign_address
    );
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if let Some(key) = line.trim().strip_prefix("add-key ").and_then(|hex| AuthKey::from_slice(&unhex(hex))) {
            for server in &servers {
                server.add_key(key.clone());
            }
            continue;
        }
        if let Some(fault) = line.trim().strip_prefix("refuse-binds ") {
            let mut parts = fault.splitn(2, ' ');
            if let (Some(code), Some(error)) = (parts.next().and_then(|code| code.parse::<i32>().ok()), parts.next()) {
                for server in &servers {
                    server.set_bind_fault(Some(BindFault::Refuse(code, error.to_string())));
                }
            }
            continue;
        }
        if let Some(error) = line.trim().strip_prefix("help-test error ") {
            let mut parts = error.splitn(2, ' ');
            if let (Some(code), Some(text)) = (parts.next().and_then(|code| code.parse::<i32>().ok()), parts.next()) {
                for server in &servers {
                    server.set_help_test_reply(HelpTestReply::Error(code, text.to_string()));
                }
            }
            continue;
        }
        if let Some(id) = line.trim().strip_prefix("remove-key ").and_then(|text| text.parse::<i64>().ok()) {
            for server in &servers {
                server.remove_key(id as u64);
            }
            continue;
        }
        match line.trim() {
            "stats" => println!("{}", server.with_stats(summary)),
            "sessions" => {
                let executed: Vec<String> = server.with_stats(|stats| {
                    stats
                        .executed_in_session
                        .iter()
                        .map(|(tag, session)| format!("{{\"tag\":{tag},\"session\":{session}}}"))
                        .collect()
                });
                println!("{{\"executed\":[{}]}}", executed.join(","));
            }
            "foreign-stats" => {
                println!("{}", foreign.as_ref().map(|foreign| foreign.with_stats(summary)).unwrap_or_default())
            }
            "api-stats" => {
                let stats = world.as_ref().map(|world| world.stats()).unwrap_or_default();
                println!(
                    "{{\"exports\":{},\"refused_exports\":{},\"imports\":{},\"refused_imports\":{}}}",
                    stats.exports, stats.refused_exports, stats.imports, stats.refused_imports
                );
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
            "tcp-blackhole on" | "tcp-blackhole off" => {
                for server in &servers {
                    server.set_tcp_blackhole(line.trim().ends_with("on"));
                }
            }
            "drop-temporary-keys" => server.drop_temporary_keys(),
            "hide-permanent-keys on" | "hide-permanent-keys off" => {
                for server in &servers {
                    server.set_hide_permanent_keys(line.trim().ends_with("on"));
                }
            }
            "help-test ok" | "help-test silent" => {
                for server in &servers {
                    server.set_help_test_reply(if line.trim() == "help-test ok" {
                        HelpTestReply::Answer
                    } else {
                        HelpTestReply::Silent
                    });
                }
            }
            "ignore-binds" | "binds-ok" => {
                for server in &servers {
                    server.set_bind_fault((line.trim() == "ignore-binds").then_some(BindFault::Ignore));
                }
            }
            "quit" => break,
            _ => {}
        }
    }
}
