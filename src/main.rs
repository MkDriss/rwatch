//! rwatch : interface en ligne de commande.
//!
//! Lit les trames (interface ou fichier `.pcap`), les décode, les confie au
//! moteur de détection et écrit chaque alerte en JSON sur la sortie standard,
//! une par ligne (format JSON Lines).
//!
//! Deux canaux bien séparés :
//! - stdout : les alertes, et RIEN d'autre (lisible par un programme) ;
//! - stderr : les messages destinés aux humains (`[*]`, `[!]`, `--verbose`).

use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use pcap::{Activated, Capture};
use rwatch::capture;
use rwatch::decode::{self, Arp, ArpOp, Content, Frame};
use rwatch::detect::{Engine, arp_spoof};

/// IDS réseau : détecte les attaques et émet des alertes JSON (une par ligne).
#[derive(Parser, Debug)]
#[command(name = "rwatch", version, about)]
struct Args {
    /// Interface à écouter (ex. wlan0, wlp3s0)
    #[arg(short, long, required_unless_present = "read")]
    interface: Option<String>,

    /// Lit un fichier de capture (.pcap) au lieu d'écouter une interface
    #[arg(short, long, value_name = "FICHIER", conflicts_with = "interface")]
    read: Option<PathBuf>,

    /// Filtre BPF (syntaxe tcpdump). Par défaut : l'ARP et tout le trafic IP,
    /// qui sert aussi à savoir quelles machines sont actives.
    #[arg(short, long, default_value = "arp or ip or ip6")]
    filter: String,

    /// Nombre de trames à lire avant de s'arrêter (0 = illimité)
    #[arg(short, long, default_value_t = 0)]
    count: u64,

    /// Affiche aussi chaque trame ARP et chaque SYN TCP (sur stderr)
    #[arg(short, long)]
    verbose: bool,
}

/// Compteurs affichés en fin de lecture.
#[derive(Debug, Default)]
struct Stats {
    alerts: u64,
    malformed: u64,
}

/// Point d'entrée. Les erreurs sont affichées avec leur message lisible
/// (`Display`) : si `main` renvoyait directement un `Result`, Rust les
/// afficherait avec `Debug`. Un « tube fermé » (`rwatch ... | head`) n'est
/// pas une erreur : on s'arrête sans bruit (même logique que rnifler).
fn main() -> ExitCode {
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if is_broken_pipe(e.as_ref()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[!] {e}");
            ExitCode::FAILURE
        }
    }
}

fn is_broken_pipe(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

fn run_cli() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Les deux branches ouvrent un type de capture DIFFÉRENT
    // (`Capture<Offline>` / `Capture<Active>`) : chacune appelle donc `run`,
    // qui est générique et accepte les deux.
    match (&args.read, &args.interface) {
        (Some(path), _) => {
            eprintln!(
                "[*] Lecture de {} | filtre BPF : \"{}\"",
                path.display(),
                args.filter
            );
            let cap = rnifler::capture::open_offline(path, &args.filter)?;
            run(cap, &args)
        }
        (None, Some(interface)) => {
            eprintln!(
                "[*] Écoute sur {interface} | filtre BPF : \"{}\"",
                args.filter
            );
            let cap = rnifler::capture::open_live(interface, &args.filter, 65535, 1000)?;
            run(cap, &args)
        }
        // Impossible : clap exige --interface quand --read est absent.
        (None, None) => unreachable!("clap impose --interface ou --read"),
    }
}

/// Lit toutes les trames de `cap`, détecte, émet les alertes, puis un résumé.
fn run<T: Activated + ?Sized>(cap: Capture<T>, args: &Args) -> Result<(), Box<dyn Error>> {
    // Les règles actives et leurs réglages. Pour l'instant : valeurs par
    // défaut ; la prochaine étape les lira dans un fichier de configuration.
    let mut engine = Engine::new(vec![Box::new(arp_spoof::ArpSpoof::new(
        arp_spoof::Config::default(),
    ))]);
    eprintln!("[*] Règles actives : {}", engine.rule_ids().join(", "));

    let mut out = io::stdout().lock();
    let mut stats = Stats::default();
    // Horodatage de la première trame : les temps de --verbose lui sont relatifs.
    let mut start: Option<Duration> = None;

    let seen =
        capture::for_each_frame(cap, args.count, |ts, frame| -> Result<(), Box<dyn Error>> {
            let frame = match decode::decode(frame) {
                Ok(frame) => frame,
                Err(e) => {
                    stats.malformed += 1;
                    eprintln!("[!] {e}");
                    return Ok(());
                }
            };
            if args.verbose {
                let elapsed = ts.saturating_sub(*start.get_or_insert(ts));
                describe(elapsed, &frame);
            }
            for alert in engine.on_frame(ts, &frame) {
                stats.alerts += 1;
                // Une alerte = une ligne de JSON. `to_writer` écrit
                // directement dans stdout, sans chaîne intermédiaire.
                serde_json::to_writer(&mut out, &alert)?;
                writeln!(out)?;
            }
            Ok(())
        })?;
    eprintln!(
        "[*] {seen} trame(s) lue(s) : {} alerte(s), {} trame(s) malformée(s)",
        stats.alerts, stats.malformed
    );
    Ok(())
}

/// Mode --verbose : une ligne lisible par trame ARP ou SYN, sur stderr.
fn describe(elapsed: Duration, frame: &Frame<'_>) {
    let time = format!("{:>11.6}", elapsed.as_secs_f64());
    match &frame.content {
        Content::Arp(arp) => eprintln!("[{time}] {}", describe_arp(arp)),
        // SYN sans ACK = premier paquet d'une connexion.
        Content::Tcp(seg) if seg.flags.syn && !seg.flags.ack => eprintln!(
            "[{time}] SYN  {}:{} -> {}:{}",
            seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port
        ),
        _ => {}
    }
}

/// Une ligne lisible pour un message ARP.
fn describe_arp(arp: &Arp) -> String {
    match arp.operation {
        ArpOp::Request => format!(
            "ARP  requête  qui a {} ? demande {} ({})",
            arp.target_ip, arp.sender_ip, arp.sender_mac
        ),
        ArpOp::Reply => format!(
            "ARP  réponse  {} est à {}  (vers {} / {})",
            arp.sender_ip, arp.sender_mac, arp.target_ip, arp.target_mac
        ),
        ArpOp::Other(code) => format!(
            "ARP  code {code}  {} ({}) -> {}",
            arp.sender_ip, arp.sender_mac, arp.target_ip
        ),
    }
}
