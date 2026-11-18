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
use rwatch::config::FileConfig;
use rwatch::decode::{self, Arp, ArpOp, Content, Frame};
use rwatch::detect::Engine;

/// Filtre BPF utilisé si ni la ligne de commande ni le fichier de
/// configuration n'en donnent un : l'ARP et tout le trafic IP, qui sert aussi
/// à savoir quelles machines sont actives.
const DEFAULT_FILTER: &str = "arp or ip or ip6";

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

    /// Fichier de configuration (TOML). Sans lui : valeurs par défaut
    #[arg(short = 'C', long, value_name = "FICHIER")]
    config: Option<PathBuf>,

    /// Filtre BPF (syntaxe tcpdump), prioritaire sur celui de la
    /// configuration [défaut : "arp or ip or ip6"]
    #[arg(short, long)]
    filter: Option<String>,

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

    // Configuration : le fichier s'il est donné, sinon les valeurs par défaut.
    let config = match &args.config {
        Some(path) => {
            eprintln!("[*] Configuration : {}", path.display());
            FileConfig::load(path)?
        }
        None => {
            eprintln!("[*] Configuration : valeurs par défaut (aucun --config)");
            FileConfig::default()
        }
    };
    // Priorité : ligne de commande, puis fichier, puis valeur par défaut.
    let filter = args
        .filter
        .clone()
        .or_else(|| config.capture.filter.clone())
        .unwrap_or_else(|| DEFAULT_FILTER.to_string());
    // Les règles sont construites AVANT d'ouvrir la capture : une
    // configuration incohérente arrête rwatch avant toute écoute.
    let engine = Engine::new(config.rules()?);
    // D'où vient la configuration de chaque règle, et est-elle active ?
    for line in config.rules_summary() {
        eprintln!("[*] {line}");
    }
    if engine.rule_ids().is_empty() {
        eprintln!("[!] Aucune règle active : rwatch ne lèvera aucune alerte");
    }

    // Les deux branches ouvrent un type de capture DIFFÉRENT
    // (`Capture<Offline>` / `Capture<Active>`) : chacune appelle donc `run`,
    // qui est générique et accepte les deux.
    match (&args.read, &args.interface) {
        (Some(path), _) => {
            eprintln!(
                "[*] Lecture de {} | filtre BPF : \"{filter}\"",
                path.display()
            );
            let cap = rnifler::capture::open_offline(path, &filter)?;
            run(cap, engine, &args)
        }
        (None, Some(interface)) => {
            let mode = if config.capture.promiscuous {
                " (mode promiscuité)"
            } else {
                ""
            };
            eprintln!("[*] Écoute sur {interface}{mode} | filtre BPF : \"{filter}\"");
            // `LiveOptions` est `#[non_exhaustive]` : hors de rnifler, on part
            // des réglages par défaut et on modifie le champ voulu.
            let mut options = rnifler::capture::LiveOptions::default();
            options.promiscuous = config.capture.promiscuous;
            let cap = rnifler::capture::open_live_with(interface, &filter, options)?;
            run(cap, engine, &args)
        }
        // Impossible : clap exige --interface quand --read est absent.
        (None, None) => unreachable!("clap impose --interface ou --read"),
    }
}

/// Lit toutes les trames de `cap`, détecte, émet les alertes, puis un résumé.
fn run<T: Activated + ?Sized>(
    cap: Capture<T>,
    mut engine: Engine,
    args: &Args,
) -> Result<(), Box<dyn Error>> {
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
