//! Tests d'intégration de la couche capture : lecture d'un vrai fichier
//! `.pcap`, sans réseau ni privilèges.

mod common;

use std::time::Duration;

use common::{ATTAQUANT, PASSERELLE, VICTIME};
use rwatch::capture::{self, CaptureError};

fn ecrire(nom: &str, frames: &[(Duration, Vec<u8>)]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("rwatch-{}-{nom}.pcap", std::process::id()));
    common::write_pcap(&path, frames).unwrap();
    path
}

#[test]
fn les_trames_et_leurs_horodatages_sont_livres_dans_l_ordre() {
    let arp = common::arp_reply(VICTIME, PASSERELLE);
    let syn = common::syn(ATTAQUANT, PASSERELLE, 22);
    let path = ecrire(
        "ordre",
        &[
            (Duration::from_secs(1_000), arp.clone()),
            (Duration::new(1_000, 250_000_000), syn.clone()),
        ],
    );
    let cap = rnifler::capture::open_offline(&path, "").unwrap();

    let mut recu = Vec::new();
    let seen = capture::for_each_frame(cap, 0, |ts, frame| -> Result<(), CaptureError> {
        recu.push((ts, frame.to_vec()));
        Ok(())
    })
    .unwrap();
    std::fs::remove_file(path).unwrap();

    assert_eq!(seen, 2);
    assert_eq!(
        recu,
        vec![
            (Duration::from_secs(1_000), arp),
            (Duration::new(1_000, 250_000_000), syn),
        ]
    );
}

#[test]
fn la_limite_arrete_la_lecture() {
    let frames: Vec<_> = (22..25)
        .map(|port| {
            (
                Duration::from_secs(u64::from(port)),
                common::syn(ATTAQUANT, PASSERELLE, port),
            )
        })
        .collect();
    let path = ecrire("limite", &frames);
    let cap = rnifler::capture::open_offline(&path, "").unwrap();
    let seen =
        capture::for_each_frame(cap, 2, |_, _| -> Result<(), CaptureError> { Ok(()) }).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(seen, 2);
}

#[test]
fn un_type_de_lien_autre_qu_ethernet_est_refuse() {
    // Fichier pcap valide mais de type 113 (Linux SLL, interface `any`).
    let path = ecrire("sll", &[]);
    let mut octets = std::fs::read(&path).unwrap();
    octets[20..24].copy_from_slice(&113_u32.to_le_bytes());
    std::fs::write(&path, octets).unwrap();

    let cap = rnifler::capture::open_offline(&path, "").unwrap();
    let res = capture::for_each_frame(cap, 0, |_, _| -> Result<(), CaptureError> { Ok(()) });
    std::fs::remove_file(path).unwrap();
    assert!(matches!(res, Err(CaptureError::UnsupportedLinktype(_))));
}
