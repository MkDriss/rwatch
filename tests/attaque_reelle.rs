//! Test de non-régression sur une ATTAQUE RÉELLE.
//!
//! Contrairement à `tests/replay.rs`, dont les scénarios sont fabriqués en
//! code, ces tests rejouent de VRAIES captures d'attaques menées sur le
//! laboratoire `sec-lab-iot` (voir `tests/captures/README.md`) : un
//! empoisonnement ARP et une usurpation d'identité MQTT. rwatch doit en tirer
//! exactement les alertes attendues, aujourd'hui et à chaque modification.
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

/// Rejoue la capture `base`.pcap avec la config `base`.toml (dans
/// tests/captures/), par le BINAIRE, et compare aux alertes attendues de
/// tests/expected/attaque/`base`.jsonl. `nb_attendu` fixe le nombre exact
/// d'alertes (vérifie aussi l'absence d'alertes parasites).
fn verifier(base: &str, nb_attendu: usize) {
    let dir = captures_dir();
    let pcap = dir.join(format!("{base}.pcap"));
    let config = dir.join(format!("{base}.toml"));
    let attendu_path = dir.join(format!("../expected/attaque/{base}.jsonl"));

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
    let attendu_texte = std::fs::read_to_string(&attendu_path)
        .unwrap_or_else(|e| panic!("{} illisible ({e})", attendu_path.display()));
    let attendu = lignes_json(&attendu_texte, &attendu_path.display().to_string());

    assert_eq!(
        obtenu.len(),
        nb_attendu,
        "{base} : attendu {nb_attendu} alerte(s), obtenu {} :\n{obtenu:#?}",
        obtenu.len()
    );
    for (i, (o, a)) in obtenu.iter().zip(&attendu).enumerate() {
        assert_eq!(
            o,
            a,
            "{base} : alerte n°{} différente\n--- obtenu ---\n{}\n--- attendu ---\n{}",
            i + 1,
            serde_json::to_string_pretty(o).unwrap(),
            serde_json::to_string_pretty(a).unwrap()
        );
    }
    assert_eq!(obtenu.len(), attendu.len());
}

#[test]
fn attaque_arp_mitm() {
    // Une quinzaine de paires de trames forgées → exactement 2 alertes
    // (une par adresse usurpée) : vérifie aussi la période anti-rafale.
    verifier("attaque-arp-mitm", 2);
}

#[test]
fn attaque_mqtt_impersonation() {
    // Six CONNECT (dont quatre à Client ID vide, ignorés) ; seul le
    // dédoublement de "actionneur1" déclenche une alerte unique.
    verifier("attaque-mqtt-impersonation", 1);
}
