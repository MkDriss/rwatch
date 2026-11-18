//! Tests d'intégration de la configuration : le binaire, un vrai fichier
//! TOML et un vrai fichier pcap.

mod common;

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use common::{ATTAQUANT, PASSERELLE, VICTIME};

/// Écrit `contenu` dans un fichier temporaire nommé d'après `nom`.
fn fichier(nom: &str, contenu: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rwatch-{}-{nom}", std::process::id()));
    std::fs::write(&path, contenu).unwrap();
    path
}

/// Capture d'une seule trame : l'attaquant usurpe la passerelle d'emblée,
/// avant que rwatch ait pu apprendre quoi que ce soit.
fn capture_usurpation_immediate(nom: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rwatch-{}-{nom}.pcap", std::process::id()));
    let frame = common::arp_reply((PASSERELLE.0, ATTAQUANT.1), VICTIME);
    common::write_pcap(
        &path,
        &[(common::DEFAULT_START + Duration::from_secs(1), frame)],
    )
    .unwrap();
    path
}

/// Lance le binaire rwatch avec ces arguments (chemins ou texte).
fn rwatch(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rwatch"))
        .args(args)
        .output()
        .expect("lancement de rwatch")
}

#[test]
fn sans_configuration_rien_n_est_appris_donc_aucune_alerte() {
    let pcap = capture_usurpation_immediate("sans-config");
    let sortie = rwatch(&[OsStr::new("--read"), pcap.as_os_str()]);
    std::fs::remove_file(&pcap).ok();
    assert!(sortie.status.success());
    assert!(
        sortie.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&sortie.stdout)
    );
}

#[test]
fn une_association_de_confiance_alerte_des_la_premiere_trame() {
    let pcap = capture_usurpation_immediate("confiance");
    let config = fichier(
        "confiance.toml",
        b"[rules.arp_spoofing.trusted]\n\"192.168.50.1\" = \"dc:a6:32:00:00:01\"\n",
    );
    let sortie = rwatch(&[
        OsStr::new("--config"),
        config.as_os_str(),
        OsStr::new("--read"),
        pcap.as_os_str(),
    ]);
    std::fs::remove_file(&pcap).ok();
    std::fs::remove_file(&config).ok();

    assert!(
        sortie.status.success(),
        "{}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    let alertes: Vec<serde_json::Value> = String::from_utf8(sortie.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(alertes.len(), 1);
    assert_eq!(alertes[0]["target"], "192.168.50.1");
    assert!(
        alertes[0]["details"]
            .as_str()
            .unwrap()
            .contains("l'association de confiance")
    );
}

#[test]
fn une_configuration_invalide_arrete_rwatch_avec_un_message_clair() {
    let config = fichier(
        "faute.toml",
        b"[rules.arp_spoofing]\nbinding_tll_secs = 600\n",
    );
    // Le fichier pcap n'existe même pas : la configuration est vérifiée avant.
    let sortie = rwatch(&[
        OsStr::new("--config"),
        config.as_os_str(),
        OsStr::new("--read"),
        OsStr::new("absent.pcap"),
    ]);
    std::fs::remove_file(&config).ok();

    assert!(!sortie.status.success());
    let erreur = String::from_utf8_lossy(&sortie.stderr);
    assert!(erreur.contains("binding_tll_secs"), "{erreur}");
    assert!(erreur.contains("line 2"), "{erreur}");
}

#[test]
fn le_filtre_de_la_ligne_de_commande_est_prioritaire() {
    let pcap = capture_usurpation_immediate("filtre");
    let config = fichier("filtre.toml", b"[capture]\nfilter = \"arp or ip\"\n");
    let lancer = |extra: &[&str]| {
        let mut args: Vec<&OsStr> = vec![
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--read"),
            pcap.as_os_str(),
        ];
        args.extend(extra.iter().map(OsStr::new));
        String::from_utf8(rwatch(&args).stderr).unwrap()
    };
    let depuis_fichier = lancer(&[]);
    let depuis_cli = lancer(&["--filter", "arp"]);
    std::fs::remove_file(&pcap).ok();
    std::fs::remove_file(&config).ok();

    assert!(
        depuis_fichier.contains("filtre BPF : \"arp or ip\""),
        "{depuis_fichier}"
    );
    assert!(depuis_cli.contains("filtre BPF : \"arp\""), "{depuis_cli}");
}
