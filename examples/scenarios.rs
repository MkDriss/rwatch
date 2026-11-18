//! Écrit les scénarios de test sur le disque, pour les rejouer à la main :
//!
//!     cargo run --example scenarios -- captures
//!     cargo run -- --read captures/arp-spoofing.pcap
//!
//! Ce sont exactement les captures utilisées par `tests/replay.rs`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "captures".into()));
    std::fs::create_dir_all(&dir)?;
    for scenario in common::scenarios() {
        let path = dir.join(format!("{}.pcap", scenario.name));
        common::write_pcap(&path, &scenario.frames)?;
        println!("{:<28} {}", path.display(), scenario.description);
    }
    Ok(())
}
