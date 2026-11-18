//! Mesure des silences de chaque machine dans un fichier pcap, pour régler
//! `binding_ttl_secs` d'ARP-001 (voir docs/LIMITES.md) :
//!
//!     cargo run --example silences -- lab-normal.pcap
//!
//! La logique est dans la bibliothèque (`rwatch::silence`), testée.

use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use rwatch::capture;
use rwatch::decode;
use rwatch::silence::SilenceTracker;

fn main() -> Result<(), Box<dyn Error>> {
    let Some(path) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage : cargo run --example silences -- <fichier.pcap>");
        std::process::exit(2);
    };

    let cap = rnifler::capture::open_offline(&path, "arp or ip")?;
    let mut tracker = SilenceTracker::new();
    let mut start: Option<Duration> = None;
    let mut end = Duration::ZERO;
    let seen = capture::for_each_frame(cap, 0, |ts, bytes| -> Result<(), Box<dyn Error>> {
        start.get_or_insert(ts);
        end = end.max(ts);
        // Une trame malformée est ignorée : elle ne prouve l'activité de personne.
        if let Ok(frame) = decode::decode(bytes) {
            tracker.on_frame(ts, &frame);
        }
        Ok(())
    })?;

    let duree = end.saturating_sub(start.unwrap_or(end));
    println!("{} : {seen} trame(s) sur {}", path.display(), human(duree));
    println!();
    println!(
        "{:<16} {:<18} {:>8} {:>16} {:>14}",
        "IP", "MAC", "trames", "plus long silence", "silence final"
    );
    for ((ip, mac), activity) in tracker.report() {
        println!(
            "{:<16} {:<18} {:>8} {:>16} {:>14}",
            ip.to_string(),
            mac.to_string(),
            activity.frames,
            human(activity.longest_silence),
            human(tracker.final_silence(activity))
        );
    }
    println!();
    println!(
        "Plus long silence, toutes machines confondues : {}",
        human(tracker.longest_silence())
    );
    println!("binding_ttl_secs doit être confortablement au-dessus (voir docs/LIMITES.md).");
    Ok(())
}

/// « 4 min 05 s », « 12,3 s ».
fn human(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1} s").replace('.', ",")
    } else {
        let total = d.as_secs();
        format!("{} min {:02} s", total / 60, total % 60)
    }
}
