//! Writes the seed corpora:
//! `cargo +nightly run --manifest-path fuzz/Cargo.toml --features seeds --bin write-seeds [DIR]`
//! (DIR defaults to fuzz/corpus).

use std::path::PathBuf;

use mtproto_cargo_fuzz::seeds;

fn main() -> std::io::Result<()> {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus"));
    let sets: [(&str, Vec<Vec<u8>>); 9] = [
        ("session", seeds::session_streams()),
        ("session_liveness", seeds::session_streams()),
        ("rpc", seeds::session_streams()),
        ("service_tl", seeds::service_messages()),
        ("http_response", seeds::http_responses()),
        ("handshake", seeds::handshake_stages()),
        ("websocket", seeds::websocket_streams()),
        ("route_memory", seeds::route_memories()),
        ("socks5", seeds::socks5_replies()),
    ];
    for (target, inputs) in sets {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir)?;
        for (index, input) in inputs.iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{index:03}")), input)?;
        }
        println!("{target}: {} seeds", inputs.len());
    }
    Ok(())
}
