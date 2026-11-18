//! Fabrication de captures réseau de test (scénarios), au format pcap.
//!
//! Même approche que les tests de rnifler (`tests/common/mod.rs`) : les
//! trames sont construites en code avec le `PacketBuilder` d'etherparse, puis
//! écrites dans un vrai fichier pcap relu par libpcap. Chaque scénario est
//! donc lisible, modifiable et reproductible octet pour octet.
//!
//! Partagé par les tests d'intégration (`tests/replay.rs`, `tests/capture.rs`)
//! et par l'exemple `examples/scenarios.rs`, qui écrit ces captures sur le
//! disque pour les rejouer avec `rwatch --read`.
//!
//! Ce module est compilé séparément dans chaque test, qui n'en utilise
//! qu'une partie : d'où l'autorisation de code inutilisé.

#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use etherparse::{ArpEthIpv4Packet, ArpOperation, PacketBuilder};

// ===========================================================================
// Écriture d'un fichier pcap (reprise de rnifler, tests/common/mod.rs)
// ===========================================================================

/// Écrit des trames Ethernet dans un fichier au format pcap classique
/// (pcap-savefile(5)) : un en-tête de fichier de 24 octets, puis, pour chaque
/// trame, un en-tête de 16 octets suivi des octets de la trame.
///
/// Tous les champs sont écrits en little-endian ; le nombre magique indique
/// cet ordre aux programmes qui lisent le fichier.
pub fn write_pcap(path: &Path, frames: &[(Duration, Vec<u8>)]) -> io::Result<()> {
    let mut file = File::create(path)?;

    // En-tête de fichier.
    file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?; // nombre magique (microsecondes)
    file.write_all(&2_u16.to_le_bytes())?; // version majeure
    file.write_all(&4_u16.to_le_bytes())?; // version mineure
    file.write_all(&0_i32.to_le_bytes())?; // décalage horaire (inutilisé)
    file.write_all(&0_u32.to_le_bytes())?; // précision (inutilisée)
    file.write_all(&65_535_u32.to_le_bytes())?; // longueur maximale capturée
    file.write_all(&1_u32.to_le_bytes())?; // type de lien : 1 = Ethernet

    // Une trame = en-tête de 16 octets + octets de la trame.
    for (time, frame) in frames {
        let len = u32::try_from(frame.len()).expect("trame trop longue");
        let secs = u32::try_from(time.as_secs()).expect("horodatage trop grand");
        file.write_all(&secs.to_le_bytes())?;
        file.write_all(&time.subsec_micros().to_le_bytes())?;
        file.write_all(&len.to_le_bytes())?; // octets enregistrés
        file.write_all(&len.to_le_bytes())?; // longueur d'origine
        file.write_all(frame)?;
    }
    Ok(())
}

// ===========================================================================
// Les machines du réseau de test
// ===========================================================================

/// Une machine : son adresse IPv4 et sa MAC.
pub type Host = ([u8; 4], [u8; 6]);

pub const PASSERELLE: Host = ([192, 168, 50, 1], [0xdc, 0xa6, 0x32, 0x00, 0x00, 0x01]);
pub const VICTIME: Host = ([192, 168, 50, 182], [0x24, 0x6f, 0x28, 0x00, 0x00, 0xb6]);
pub const ATTAQUANT: Host = ([192, 168, 50, 50], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
/// La même IP que la victime, avec une nouvelle carte réseau.
pub const VICTIME_NOUVELLE_CARTE: Host =
    ([192, 168, 50, 182], [0x24, 0x6f, 0x28, 0x00, 0x00, 0xff]);

// ===========================================================================
// Construction des trames
// ===========================================================================

/// Trame Ethernet contenant un message ARP Ethernet/IPv4.
pub fn arp(operation: ArpOperation, sender: Host, target: Host, eth_dst: [u8; 6]) -> Vec<u8> {
    let arp = ArpEthIpv4Packet {
        operation,
        sender_mac: sender.1,
        sender_ipv4: sender.0,
        target_mac: target.1,
        target_ipv4: target.0,
    };
    let builder = PacketBuilder::ethernet2(sender.1, eth_dst).arp(arp.into());
    let mut frame = Vec::with_capacity(builder.size());
    builder.write(&mut frame).expect("écriture en mémoire");
    frame
}

/// Requête « qui a `qui_a` ? », diffusée à tout le réseau.
pub fn arp_request(from: Host, qui_a: [u8; 4]) -> Vec<u8> {
    arp(ArpOperation::REQUEST, from, (qui_a, [0; 6]), [0xff; 6])
}

/// Réponse « `claimed.0` est à `claimed.1` », envoyée directement à `to`.
pub fn arp_reply(claimed: Host, to: Host) -> Vec<u8> {
    arp(ArpOperation::REPLY, claimed, to, to.1)
}

/// SYN TCP de `from` vers `to`:`dst_port`.
pub fn syn(from: Host, to: Host, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(from.1, to.1)
        .ipv4(from.0, to.0, 64)
        .tcp(51_234, dst_port, 1000, 65_535)
        .syn();
    let mut frame = Vec::with_capacity(builder.size(0));
    builder.write(&mut frame, &[]).expect("écriture en mémoire");
    frame
}

/// Segment TCP de données (ACK + PSH) de `from` vers `to`:`dst_port` : du
/// trafic ordinaire, sans aucun message ARP.
pub fn tcp_data(from: Host, to: Host, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(from.1, to.1)
        .ipv4(from.0, to.0, 64)
        .tcp(51_234, dst_port, 1000, 65_535)
        .psh()
        .ack(1);
    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, payload)
        .expect("écriture en mémoire");
    frame
}

// ===========================================================================
// Scénarios
// ===========================================================================

/// Une capture de test : un nom de fichier, une description, des trames.
pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    pub frames: Vec<(Duration, Vec<u8>)>,
}

/// Date de départ des scénarios : le 1er janvier 2026 à 00:00:00 UTC (la
/// même que rnifler). Fixe, pour que les captures et les alertes attendues
/// soient identiques à chaque exécution, chez tout le monde.
pub const DEFAULT_START: Duration = Duration::from_secs(1_767_225_600);

/// Accumule des trames horodatées en secondes depuis le début du scénario.
struct Timeline {
    start: Duration,
    frames: Vec<(Duration, Vec<u8>)>,
}

impl Timeline {
    fn new(start: Duration) -> Self {
        Timeline {
            start,
            frames: Vec::new(),
        }
    }

    /// Ajoute une trame à l'instant `secs` (en millisecondes près).
    fn at(&mut self, secs: f64, frame: Vec<u8>) -> &mut Self {
        let offset = Duration::from_millis((secs * 1000.0).round() as u64);
        self.frames.push((self.start + offset, frame));
        self
    }

    /// Les trois machines font chacune une requête ARP normale, et reçoivent
    /// leur réponse : rwatch apprend les trois associations légitimes.
    fn presentations(&mut self) -> &mut Self {
        self.at(1.0, arp_request(PASSERELLE, VICTIME.0))
            .at(1.001, arp_reply(VICTIME, PASSERELLE))
            .at(2.0, arp_request(ATTAQUANT, PASSERELLE.0))
            .at(2.001, arp_reply(PASSERELLE, ATTAQUANT))
    }

    fn into_frames(self) -> Vec<(Duration, Vec<u8>)> {
        self.frames
    }
}

/// Tous les scénarios de test, à partir de la date par défaut.
pub fn scenarios() -> Vec<Scenario> {
    scenarios_at(DEFAULT_START)
}

/// Tous les scénarios de test, la première trame étant horodatée à `start`.
pub fn scenarios_at(start: Duration) -> Vec<Scenario> {
    vec![
        Scenario {
            name: "arp-normal",
            description: "requêtes et réponses ARP légitimes, puis une connexion TCP",
            frames: {
                let mut t = Timeline::new(start);
                t.at(0.0, arp_request(PASSERELLE, VICTIME.0))
                    .at(0.001, arp_reply(VICTIME, PASSERELLE))
                    .at(3.5, arp_request(VICTIME, PASSERELLE.0))
                    .at(3.505, arp_reply(PASSERELLE, VICTIME))
                    .at(3.9, syn(VICTIME, PASSERELLE, 1883))
                    .at(9.1, arp_request(PASSERELLE, VICTIME.0))
                    .at(9.101, arp_reply(VICTIME, PASSERELLE));
                t.into_frames()
            },
        },
        Scenario {
            name: "arp-spoofing",
            description: "homme du milieu : l'attaquant se fait passer pour la passerelle \
                          auprès de la victime, et pour la victime auprès de la passerelle",
            frames: {
                let mut t = Timeline::new(start);
                t.presentations();
                // Comme arpspoof : une paire de réponses non sollicitées toutes
                // les 2 secondes, pendant 30 secondes.
                for i in 0..15 {
                    let at = 10.0 + 2.0 * f64::from(i);
                    t.at(at, arp_reply((PASSERELLE.0, ATTAQUANT.1), VICTIME))
                        .at(at + 0.001, arp_reply((VICTIME.0, ATTAQUANT.1), PASSERELLE));
                }
                t.into_frames()
            },
        },
        Scenario {
            name: "arp-attaquant-inconnu",
            description: "une MAC jamais vue usurpe la passerelle : l'attaquant n'a pas \
                          d'IP connue, la victime ne doit pas être désignée",
            frames: {
                let mut t = Timeline::new(start);
                t.at(1.0, arp_request(PASSERELLE, VICTIME.0))
                    .at(1.001, arp_reply(VICTIME, PASSERELLE))
                    .at(5.0, arp_reply((PASSERELLE.0, ATTAQUANT.1), VICTIME));
                t.into_frames()
            },
        },
        Scenario {
            name: "arp-changement-legitime",
            description: "la victime se tait plus de 5 minutes, puis revient avec une \
                          nouvelle carte réseau",
            frames: {
                let mut t = Timeline::new(start);
                t.presentations()
                    .at(400.0, arp_request(VICTIME_NOUVELLE_CARTE, PASSERELLE.0))
                    .at(400.001, arp_reply(PASSERELLE, VICTIME_NOUVELLE_CARTE));
                t.into_frames()
            },
        },
        Scenario {
            name: "arp-victime-active-en-tcp",
            description: "la victime ne fait plus d'ARP mais publie en TCP toutes les \
                          30 s ; l'attaquant l'usurpe au bout de 400 s",
            frames: {
                let mut t = Timeline::new(start);
                t.presentations();
                // Comme un objet IoT qui publie sa télémétrie MQTT : aucun ARP,
                // son cache est confirmé par TCP.
                for i in 1..=13 {
                    t.at(
                        30.0 * f64::from(i),
                        tcp_data(VICTIME, PASSERELLE, 1883, b"21.5"),
                    );
                }
                t.at(400.0, arp_reply((VICTIME.0, ATTAQUANT.1), PASSERELLE));
                t.into_frames()
            },
        },
        Scenario {
            name: "arp-sonde",
            description: "sonde de détection de conflit (émetteur 0.0.0.0, RFC 5227) \
                          puis annonce de la même machine",
            frames: {
                let mut t = Timeline::new(start);
                t.presentations()
                    .at(10.0, arp_request(([0, 0, 0, 0], ATTAQUANT.1), VICTIME.0))
                    .at(11.0, arp_request(ATTAQUANT, ATTAQUANT.0));
                t.into_frames()
            },
        },
    ]
}
