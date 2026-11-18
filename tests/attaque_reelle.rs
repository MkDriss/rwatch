//! Test de non-régression sur une ATTAQUE RÉELLE.
//!
//! Contrairement à `tests/replay.rs`, dont les scénarios sont fabriqués en
//! code, ce test rejoue une vraie capture : un empoisonnement ARP mené sur le
//! laboratoire `sec-lab-iot` le 18 novembre 2026 (voir
//! `tests/captures/README.md`). rwatch doit en tirer exactement les deux
//! alertes attendues, aujourd'hui et à chaque modification future.
//!
//! Le test lance le BINAIRE, comme un utilisateur, avec la configuration du
//! labo (associations de confiance). La comparaison est structurelle : chaque
//! ligne est lue comme une valeur JSON (l'ordre des champs du contrat est
//! vérifié ailleurs, par les tests de `alert.rs`).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn captures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/captures")
}

/// Une valeur JSON par ligne non vide.
fn lignes_json(texte: &str, origine: &str) -> Vec<Value> {
    texte
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("{origine}, ligne {} : JSON invalide ({e})", i + 1))
        })
        .collect()
}

#[test]
fn l_attaque_arp_reelle_produit_les_deux_alertes_attendues() {
    let dir = captures_dir();
    let pcap = dir.join("attaque-arp-mitm.pcap");
    let config = dir.join("attaque-arp-mitm.toml");
    let attendu = dir.join("../expected/attaque/attaque-arp-mitm.jsonl");

    // Cargo fournit le chemin du binaire compilé aux tests d'intégration.
    let sortie = Command::new(env!("CARGO_BIN_EXE_rwatch"))
        .arg("--config")
        .arg(&config)
        .arg("--read")
        .arg(&pcap)
        .output()
        .expect("lancement de rwatch");

    assert!(
        sortie.status.success(),
        "rwatch a échoué : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );

    let obtenu = lignes_json(
        &String::from_utf8(sortie.stdout).expect("sortie en UTF-8"),
        "sortie de rwatch",
    );
    let attendu_texte = std::fs::read_to_string(&attendu)
        .unwrap_or_else(|e| panic!("{} illisible ({e})", attendu.display()));
    let attendu = lignes_json(&attendu_texte, &attendu.display().to_string());

    // Deux alertes exactement : une rafale d'une quinzaine de paires de trames
    // forgées ne doit en produire que deux (période anti-rafale d'ARP-001).
    assert_eq!(
        obtenu.len(),
        2,
        "attendu 2 alertes (anti-rafale), obtenu {} :\n{obtenu:#?}",
        obtenu.len()
    );
    for (i, (o, a)) in obtenu.iter().zip(&attendu).enumerate() {
        assert_eq!(
            o,
            a,
            "alerte n°{} différente\n--- obtenu ---\n{}\n--- attendu ---\n{}",
            i + 1,
            serde_json::to_string_pretty(o).unwrap(),
            serde_json::to_string_pretty(a).unwrap()
        );
    }
    assert_eq!(obtenu.len(), attendu.len());
}
