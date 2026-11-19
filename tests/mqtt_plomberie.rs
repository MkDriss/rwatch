//! Validation de la couche MQTT (plomberie), AVANT toute règle MQTT.
//!
//! On fabrique un pcap contenant deux sessions MQTT qui annoncent le même
//! Client ID depuis deux identités réseau différentes (le futur signal
//! d'usurpation de MQTT-001), et on vérifie que `MqttDecoder` produit bien
//! deux `MqttEvent::Connect` portant le bon Client ID ET la bonne adresse
//! source (IP + MAC) — la MAC venant de la table locale de la couche, puisque
//! rnifler ne la remonte pas.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use common::{ATTAQUANT, PASSERELLE, VICTIME};
use rwatch::capture;
use rwatch::decode::{self, Content, MacAddr};
use rwatch::mqtt::{MqttDecoder, MqttEvent, MqttPacket};

/// Rejoue un pcap par la couche capture + décodage + MqttDecoder, et renvoie
/// les (Client ID, IP source, MAC source) des CONNECT vus.
fn connects(frames: &[(Duration, Vec<u8>)]) -> Vec<(String, String, String)> {
    // Compteur unique par appel : les tests s'exécutent en parallèle et ne
    // doivent pas partager le même fichier (sinon l'un lit le pcap de l'autre).
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rwatch-mqtt-{}-{n}.pcap", std::process::id()));
    common::write_pcap(&path, frames).unwrap();
    let cap = rnifler::capture::open_offline(&path, "tcp").unwrap();

    let mut decoder = MqttDecoder::new();
    let mut vus = Vec::new();
    capture::for_each_frame(cap, 0, |ts, bytes| -> Result<(), capture::CaptureError> {
        if let Ok(frame) = decode::decode(bytes)
            && let (Content::Tcp(seg), Some(sender)) = (&frame.content, frame.ipv4_sender)
        {
            decoder.process(seg, sender, ts, |event: MqttEvent<'_>| {
                let MqttPacket::Connect { client_id } = event.packet;
                vus.push((
                    client_id.to_string(),
                    event.source.ip.to_string(),
                    event.source.mac.to_string(),
                ));
            });
        }
        Ok(())
    })
    .unwrap();
    std::fs::remove_file(&path).ok();
    vus
}

#[test]
fn un_connect_est_decode_avec_son_identite_reseau() {
    let session = common::mqtt_session(VICTIME, PASSERELLE, 50000, "actionneur-labo", 1.0);
    let vus = connects(&session);
    assert_eq!(
        vus,
        vec![(
            "actionneur-labo".to_string(),
            "192.168.50.182".to_string(),
            MacAddr(VICTIME.1).to_string(),
        )]
    );
}

#[test]
fn le_meme_client_id_depuis_deux_identites_donne_deux_connects() {
    // Le signal d'usurpation : même Client ID, deux identités réseau.
    let mut frames = common::mqtt_session(VICTIME, PASSERELLE, 50000, "actionneur-labo", 1.0);
    frames.extend(common::mqtt_session(
        ATTAQUANT,
        PASSERELLE,
        50001,
        "actionneur-labo",
        5.0,
    ));
    let vus = connects(&frames);

    assert_eq!(vus.len(), 2);
    assert_eq!(vus[0].0, "actionneur-labo");
    assert_eq!(vus[1].0, "actionneur-labo");
    // Les deux CONNECT portent des identités réseau DIFFÉRENTES.
    assert_eq!(vus[0].1, "192.168.50.182"); // VICTIME
    assert_eq!(vus[1].1, "192.168.50.50"); // ATTAQUANT
    assert_ne!((&vus[0].1, &vus[0].2), (&vus[1].1, &vus[1].2));
}