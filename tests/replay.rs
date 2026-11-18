//! Tests de REJEU avec résultats attendus (« golden files »).
//!
//! Pour chaque scénario de `common::scenarios()` :
//! 1. le scénario est écrit dans un vrai fichier pcap ;
//! 2. le BINAIRE `rwatch --read` le rejoue, comme un utilisateur le ferait ;
//! 3. chaque ligne de sa sortie standard (une alerte JSON) est comparée à
//!    `tests/expected/<scénario>.jsonl`.
//!
//! La comparaison est STRUCTURELLE : chaque ligne est lue comme une valeur
//! JSON, donc les espaces et l'ordre des champs n'interviennent pas. (L'ordre
//! des champs du contrat est vérifié séparément, par les tests de `alert.rs`.)
//! En cas d'écart, le test montre la première alerte qui diffère.
//!
//! Mettre à jour les résultats attendus après un changement VOULU :
//!     RWATCH_BLESS=1 cargo test --test replay
//! puis relire le diff (`git diff tests/expected/`) avant de committer.

mod common;

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Dossier des résultats attendus.
fn expected_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/expected")
}

/// Rejoue le scénario `name` avec le binaire ; renvoie la sortie standard brute.
fn rejouer(name: &str) -> String {
    let scenario = common::scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .expect("scénario inconnu");
    let path = std::env::temp_dir().join(format!("rwatch-{}-{name}.pcap", std::process::id()));
    common::write_pcap(&path, &scenario.frames).expect("écriture du pcap");

    // Cargo fournit le chemin du binaire compilé aux tests d'intégration.
    let sortie = Command::new(env!("CARGO_BIN_EXE_rwatch"))
        .arg("--read")
        .arg(&path)
        .output()
        .expect("lancement de rwatch");
    std::fs::remove_file(&path).ok();

    assert!(
        sortie.status.success(),
        "rwatch a échoué : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    String::from_utf8(sortie.stdout).expect("sortie en UTF-8")
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

/// Compare la sortie de rwatch au fichier attendu (ou le réécrit si
/// `RWATCH_BLESS` est défini).
fn verifier(name: &str) {
    let sortie = rejouer(name);
    let fichier = expected_dir().join(format!("{name}.jsonl"));

    if std::env::var_os("RWATCH_BLESS").is_some() {
        // On écrit la sortie BRUTE : elle garde l'ordre des champs du contrat.
        std::fs::write(&fichier, &sortie).expect("écriture du résultat attendu");
        return;
    }

    let attendu_texte = std::fs::read_to_string(&fichier)
        .unwrap_or_else(|e| panic!("{} illisible ({e})", fichier.display()));
    let obtenu = lignes_json(&sortie, "sortie de rwatch");
    let attendu = lignes_json(&attendu_texte, &fichier.display().to_string());

    for (i, (o, a)) in obtenu.iter().zip(&attendu).enumerate() {
        assert_eq!(
            o,
            a,
            "{name} : l'alerte n°{} diffère\n--- obtenu ---\n{}\n--- attendu ---\n{}",
            i + 1,
            serde_json::to_string_pretty(o).unwrap(),
            serde_json::to_string_pretty(a).unwrap()
        );
    }
    assert_eq!(
        obtenu.len(),
        attendu.len(),
        "{name} : {} alerte(s) obtenue(s), {} attendue(s)\n{sortie}",
        obtenu.len(),
        attendu.len()
    );
}

#[test]
fn arp_normal() {
    verifier("arp-normal");
}

#[test]
fn arp_spoofing() {
    verifier("arp-spoofing");
}

#[test]
fn arp_attaquant_inconnu() {
    verifier("arp-attaquant-inconnu");
}

#[test]
fn arp_changement_legitime() {
    verifier("arp-changement-legitime");
}

#[test]
fn arp_victime_active_en_tcp() {
    verifier("arp-victime-active-en-tcp");
}

#[test]
fn arp_sonde() {
    verifier("arp-sonde");
}

#[test]
fn chaque_scenario_a_son_test_et_son_resultat_attendu() {
    // Protège contre un scénario ajouté sans test, ou un fichier attendu
    // orphelin (scénario renommé ou supprimé).
    let scenarios = common::scenarios();
    assert!(scenarios.iter().all(|s| !s.description.is_empty()));
    let noms: Vec<&str> = scenarios.iter().map(|s| s.name).collect();
    assert_eq!(
        noms,
        [
            "arp-normal",
            "arp-spoofing",
            "arp-attaquant-inconnu",
            "arp-changement-legitime",
            "arp-victime-active-en-tcp",
            "arp-sonde",
        ]
    );

    // Seuls les fichiers .jsonl À LA RACINE de tests/expected/ appartiennent
    // aux scénarios de ce test. Les sous-dossiers (ex. expected/attaque/, pour
    // le test d'attaque réelle) ont leur propre test et sont ignorés ici.
    let mut fichiers: Vec<String> = std::fs::read_dir(expected_dir())
        .expect("dossier tests/expected")
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".jsonl"))
        .collect();
    fichiers.sort();
    let mut attendus: Vec<String> = noms.iter().map(|n| format!("{n}.jsonl")).collect();
    attendus.sort();
    assert_eq!(fichiers, attendus);
}
