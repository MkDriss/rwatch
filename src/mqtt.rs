//! Couche MQTT : branche l'analyseur de `rnifler` (réassemblage TCP + décodage
//! MQTT) sur les segments TCP que rwatch capture, et traduit ses événements en
//! un type propre à rwatch, [`MqttEvent`].
//!
//! Pourquoi un type à nous plutôt que l'`Event` de rnifler : le trait `Rule`
//! ne doit dépendre que de types rwatch. rnifler peut faire évoluer son `Event`
//! derrière cette frontière sans casser les règles (même logique que `Frame`
//! et `Content` dans `decode`, qui sont des types rwatch alors que le TCP vient
//! de rnifler).
//!
//! rnifler ne remonte jamais la MAC source : son `FlowKey` ne contient que des
//! `SocketAddr` (IP + port). Pour que l'alerte puisse désigner le fautif avec
//! son IP ET sa MAC, cette couche tient une petite table « IP → dernière MAC
//! vue », alimentée par chaque segment, et complète l'événement avec la MAC.
//!
//! Limite connue : cette table IP → MAC fait double emploi avec celle
//! d'ARP-001. Un « contexte partagé » entre règles la mutualiserait, mais il
//! est au backlog (il demande de résoudre le partage d'un état mutable entre
//! règles et moteur). En attendant, chacune a la sienne.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use rnifler::analyzer::{Analyzer, Config, Event};
use rnifler::mqtt::Packet;
use rnifler::parser::TcpSegment;

use crate::decode::{Ipv4Sender, MacAddr};

/// Un paquet MQTT décodé, tel que les règles de rwatch le voient.
///
/// Minimal à dessein : seul le CONNECT est exposé pour l'instant (MQTT-001 n'a
/// besoin que du Client ID). Les autres paquets ne produisent pas de
/// `MqttEvent`. On enrichira ce type quand une règle en aura besoin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttPacket<'a> {
    /// Ouverture de session : porte le Client ID revendiqué.
    Connect { client_id: &'a str },
}

/// Un événement MQTT livré aux règles : le paquet décodé, et l'identité réseau
/// du flux d'où il vient (pour désigner le fautif dans une alerte).
///
/// `'a` : `MqttPacket` emprunte les octets du flux (le Client ID est une vue
/// dans le buffer). Un `MqttEvent` ne vit que le temps de l'appel à la règle :
/// une règle qui veut retenir le Client ID doit le copier (`to_string`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttEvent<'a> {
    pub source: Ipv4Sender,
    pub packet: MqttPacket<'a>,
}

/// Enveloppe l'analyseur de rnifler et la table IP → MAC propre à rwatch.
pub struct MqttDecoder {
    analyzer: Analyzer,
    /// Dernière MAC vue pour chaque IP, pour compléter les événements.
    macs: BTreeMap<Ipv4Addr, MacAddr>,
    /// Borne la table : la mémoire reste maîtrisée même sous un afflux d'IP.
    max_macs: usize,
}

impl MqttDecoder {
    /// Un décodeur MQTT avec les réglages par défaut de rnifler (port 1883,
    /// réassemblage et budget mémoire standard).
    pub fn new() -> Self {
        MqttDecoder {
            analyzer: Analyzer::new(Config::default()),
            macs: BTreeMap::new(),
            max_macs: 1024,
        }
    }

    /// Mémorise la MAC d'un émetteur IPv4 (appelé pour chaque segment).
    fn remember(&mut self, sender: Ipv4Sender) {
        if self.macs.len() >= self.max_macs && !self.macs.contains_key(&sender.ip) {
            return; // table pleine : on n'ajoute pas de nouvelle IP
        }
        self.macs.insert(sender.ip, sender.mac);
    }

    /// Confie un segment TCP à l'analyseur ; appelle `on_event` pour chaque
    /// événement MQTT exploitable par une règle.
    ///
    /// `sender` est l'émetteur du segment (IP + MAC), connu de la couche
    /// décodage. `now` est l'horodatage de capture.
    pub fn process<F>(
        &mut self,
        segment: &TcpSegment<'_>,
        sender: Ipv4Sender,
        now: Duration,
        mut on_event: F,
    ) where
        F: FnMut(MqttEvent<'_>),
    {
        self.remember(sender);
        // `macs` est emprunté en lecture dans la closure ; l'analyseur est
        // emprunté en mutable. Ce sont deux champs distincts de `self`, donc
        // le compilateur accepte les deux emprunts simultanés.
        let macs = &self.macs;
        self.analyzer.process(segment, now, |event| {
            if let Event::Mqtt { flow, packet } = event
                && let Packet::Connect(connect) = packet
            {
                let ip = match flow.src.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    std::net::IpAddr::V6(_) => return, // IPv6 hors périmètre
                };
                // La MAC vient de notre table ; absente seulement si le flux
                // a été pris en cours de route, sans qu'on ait vu l'émetteur.
                let Some(&mac) = macs.get(&ip) else {
                    return;
                };
                on_event(MqttEvent {
                    source: Ipv4Sender { ip, mac },
                    packet: MqttPacket::Connect {
                        client_id: connect.client_id,
                    },
                });
            }
        });
    }
}

impl Default for MqttDecoder {
    fn default() -> Self {
        Self::new()
    }
}
