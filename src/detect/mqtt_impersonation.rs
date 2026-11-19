//! Règle MQTT-001 : usurpation d'identité MQTT par réutilisation d'un Client ID
//! (MITRE ATT&CK T1134, usurpation d'identité ; ici au niveau applicatif).
//!
//! # Principe
//!
//! Un Client ID MQTT identifie un client auprès du broker. Dans l'IoT, il est
//! souvent codé en dur dans le firmware : volé par rétro-ingénierie, il permet
//! à un attaquant de se faire passer pour l'objet légitime. La règle détecte
//! un même Client ID revendiqué depuis DEUX identités réseau différentes.
//!
//! Deux sources de vérité, comme ARP-001 :
//! - association de CONFIANCE (configurée) : « ce Client ID appartient à cette
//!   identité (IP + MAC) ». Tout CONNECT du même Client ID depuis une autre
//!   identité est une usurpation, dès la première fois.
//! - association APPRISE (si `learn`) : le premier CONNECT d'un Client ID
//!   inconnu attache ce Client ID à la MAC de son émetteur. Un CONNECT
//!   ultérieur du même Client ID depuis une AUTRE MAC est une usurpation.
//!
//! L'identité comparée diffère selon la source : le COUPLE (IP + MAC) pour une
//! association de confiance (les deux sont déclarés), la MAC SEULE pour une
//! association apprise (l'IP d'un objet peut changer via DHCP sans que son
//! identité change ; la MAC est l'attribut stable). Contre un attaquant qui
//! usurpe aussi la MAC, c'est ARP-001 qui prend le relais : les deux règles se
//! complètent.
//!
//! # Prudence (comme ARP-001)
//!
//! - Une revendication contradictoire ne remplace JAMAIS l'association connue :
//!   l'attaquant ne peut pas « s'installer » en se reconnectant en boucle.
//! - Le fautif désigné est le NOUVEAU venu (`source`).
//!
//! # Limites connues
//!
//! - Si l'attaquant se connecte AVANT l'objet légitime et qu'aucune
//!   association de confiance n'existe pour ce Client ID, c'est l'identité de
//!   l'attaquant qui est apprise, et le retour de l'objet légitime qui est
//!   signalé. Les associations de confiance éliminent ce cas (recommandées
//!   pour les objets critiques).
//! - Un objet légitime qui change de MAC (carte remplacée) sans association de
//!   confiance produit un faux positif. Pas de péremption : un Client ID est
//!   une identité applicative stable.
//! - Un Client ID vide (le broker en attribue un) n'identifie personne : ignoré.

use std::collections::BTreeMap;
use std::net::IpAddr;

use std::time::Duration;

use super::Rule;
use crate::alert::{Alert, Severity, Timestamp};
use crate::decode::{Ipv4Sender, MacAddr};
use crate::mqtt::{MqttEvent, MqttPacket};

/// Identifiant de la règle (champ `rule_id`).
pub const RULE_ID: &str = "MQTT-001";
/// Type d'alerte (champ `type`).
pub const ALERT_TYPE: &str = "mqtt_impersonation";

/// Réglages de la règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub severity: Severity,
    /// Apprendre les Client ID inconnus. `false` : ne suivre que ceux déclarés
    /// de confiance (inventaire fixe).
    pub learn: bool,
    /// Une seule alerte par période pour un même couple (Client ID, MAC).
    pub alert_cooldown: Duration,
    /// Taille maximale des tables internes.
    pub max_entries: usize,
    /// Associations de confiance : Client ID → identité attendue (IP + MAC).
    pub trusted: BTreeMap<String, Ipv4Sender>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            severity: Severity::High,
            learn: true,
            alert_cooldown: Duration::from_secs(60),
            max_entries: 1024,
            trusted: BTreeMap::new(),
        }
    }
}

/// L'état de la règle.
///
/// Tables `BTreeMap` et non `HashMap` : parcours déterministe (même raison que
/// pour ARP-001).
#[derive(Debug)]
pub struct MqttImpersonation {
    config: Config,
    /// Client ID appris → MAC qui l'a revendiqué en premier.
    learned: BTreeMap<String, MacAddr>,
    /// (Client ID, MAC usurpatrice) → instant de la dernière alerte.
    last_alert: BTreeMap<(String, MacAddr), Duration>,
}

impl MqttImpersonation {
    pub fn new(config: Config) -> Self {
        MqttImpersonation {
            config,
            learned: BTreeMap::new(),
            last_alert: BTreeMap::new(),
        }
    }

    /// Vérifie un CONNECT.
    fn check(&mut self, ts: Duration, client_id: &str, source: Ipv4Sender) -> Option<Alert> {
        // Un Client ID vide n'identifie personne (le broker en attribue un).
        if client_id.is_empty() {
            return None;
        }

        // 1. Association de confiance : identité = couple (IP + MAC).
        if let Some(&expected) = self.config.trusted.get(client_id) {
            return if source == expected {
                None
            } else {
                self.raise(ts, client_id, source, Origin::Trusted(expected))
            };
        }

        // 2. Association apprise : identité = MAC seule.
        match self.learned.get(client_id) {
            Some(&known) if known == source.mac => None, // reconnexion légitime
            Some(&known) => self.raise(ts, client_id, source, Origin::Learned(known)),
            None => {
                if self.config.learn {
                    self.learn(client_id, source.mac);
                }
                None
            }
        }
    }

    /// Apprend une association, si la table n'est pas pleine.
    fn learn(&mut self, client_id: &str, mac: MacAddr) {
        if self.learned.len() < self.config.max_entries {
            self.learned.insert(client_id.to_string(), mac);
        }
    }

    /// Construit l'alerte, sauf si le même couple (Client ID, MAC) a déjà été
    /// signalé il y a moins de `alert_cooldown`.
    fn raise(
        &mut self,
        ts: Duration,
        client_id: &str,
        source: Ipv4Sender,
        origin: Origin,
    ) -> Option<Alert> {
        let key = (client_id.to_string(), source.mac);
        if let Some(&last) = self.last_alert.get(&key)
            && ts.saturating_sub(last) < self.config.alert_cooldown
        {
            return None;
        }
        if self.last_alert.len() >= self.config.max_entries {
            let cooldown = self.config.alert_cooldown;
            self.last_alert
                .retain(|_, last| ts.saturating_sub(*last) < cooldown);
        }
        if self.last_alert.len() < self.config.max_entries {
            self.last_alert.insert(key, ts);
        }

        let known_mac = match origin {
            Origin::Trusted(id) => id.mac,
            Origin::Learned(mac) => mac,
        };
        let origin_label = match origin {
            Origin::Trusted(_) => "l'association de confiance",
            Origin::Learned(_) => "l'association apprise",
        };
        let details = format!(
            "Client ID MQTT « {client_id} » revendiqué par {} ({}), \
             alors que {origin_label} indique {known_mac}",
            source.mac, source.ip
        );

        Some(Alert {
            timestamp: Timestamp(ts),
            kind: ALERT_TYPE,
            severity: self.config.severity,
            source_ip: Some(IpAddr::V4(source.ip)),
            source_mac: Some(source.mac),
            target: Some(client_id.to_string()),
            details,
            rule_id: RULE_ID,
        })
    }
}

/// D'où vient l'association contredite.
#[derive(Debug, Clone, Copy)]
enum Origin {
    Trusted(Ipv4Sender),
    Learned(MacAddr),
}

impl Rule for MqttImpersonation {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn needs_mqtt(&self) -> bool {
        true
    }

    fn on_mqtt(&mut self, ts: Duration, event: &MqttEvent<'_>) -> Vec<Alert> {
        let MqttPacket::Connect { client_id } = event.packet;
        self.check(ts, client_id, event.source)
            .into_iter()
            .collect()
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const CID: &str = "actionneur-labo";
    fn objet() -> Ipv4Sender {
        Ipv4Sender {
            ip: Ipv4Addr::new(192, 168, 60, 124),
            mac: MacAddr([0x20, 0x50, 0x0d, 0x29, 0xe1, 0xf0]),
        }
    }
    fn attaquant() -> Ipv4Sender {
        Ipv4Sender {
            ip: Ipv4Addr::new(192, 168, 60, 104),
            mac: MacAddr([0xba, 0xd9, 0x21, 0xa5, 0x01, 0x02]),
        }
    }
    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn connect(id: &str, src: Ipv4Sender) -> MqttEvent<'_> {
        MqttEvent {
            source: src,
            packet: MqttPacket::Connect { client_id: id },
        }
    }

    #[test]
    fn un_objet_qui_se_reconnecte_ne_declenche_rien() {
        let mut r = MqttImpersonation::new(Config::default());
        assert!(r.on_mqtt(s(1), &connect(CID, objet())).is_empty()); // appris
        assert!(r.on_mqtt(s(2), &connect(CID, objet())).is_empty()); // reconnexion
        assert!(r.on_mqtt(s(3), &connect(CID, objet())).is_empty());
    }

    #[test]
    fn meme_client_id_depuis_une_autre_mac_est_une_usurpation() {
        let mut r = MqttImpersonation::new(Config::default());
        r.on_mqtt(s(1), &connect(CID, objet())); // l'objet légitime se présente
        let alertes = r.on_mqtt(s(5), &connect(CID, attaquant())); // le voleur
        assert_eq!(alertes.len(), 1);
        let a = &alertes[0];
        assert_eq!(a.rule_id, "MQTT-001");
        assert_eq!(a.kind, "mqtt_impersonation");
        assert_eq!(
            a.source_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 60, 104)))
        );
        assert_eq!(a.source_mac, Some(attaquant().mac));
        assert_eq!(a.target.as_deref(), Some("actionneur-labo"));
        assert!(a.details.contains("l'association apprise"));
    }

    #[test]
    fn l_usurpation_ne_remplace_pas_l_association_apprise() {
        let mut r = MqttImpersonation::new(Config::default());
        r.on_mqtt(s(1), &connect(CID, objet()));
        r.on_mqtt(s(5), &connect(CID, attaquant()));
        // L'objet légitime se reconnecte : aucune alerte contre lui.
        assert!(r.on_mqtt(s(6), &connect(CID, objet())).is_empty());
    }

    #[test]
    fn une_rafale_ne_donne_qu_une_alerte_par_periode() {
        let mut r = MqttImpersonation::new(Config::default());
        r.on_mqtt(s(1), &connect(CID, objet()));
        let rafale: usize = (0..30)
            .map(|i| r.on_mqtt(s(5 + i), &connect(CID, attaquant())).len())
            .sum();
        assert_eq!(rafale, 1);
        // Après la période de silence, une nouvelle alerte.
        assert_eq!(r.on_mqtt(s(100), &connect(CID, attaquant())).len(), 1);
    }

    #[test]
    fn un_client_id_vide_est_ignore() {
        let mut r = MqttImpersonation::new(Config::default());
        assert!(r.on_mqtt(s(1), &connect("", objet())).is_empty());
        assert!(r.on_mqtt(s(2), &connect("", attaquant())).is_empty());
    }

    #[test]
    fn sans_apprentissage_un_client_id_inconnu_est_ignore() {
        let mut r = MqttImpersonation::new(Config {
            learn: false,
            ..Config::default()
        });
        // Rien n'est appris : même depuis deux identités, aucune alerte.
        assert!(r.on_mqtt(s(1), &connect(CID, objet())).is_empty());
        assert!(r.on_mqtt(s(5), &connect(CID, attaquant())).is_empty());
    }

    #[test]
    fn association_de_confiance_detecte_des_la_premiere_usurpation() {
        let mut config = Config {
            learn: false,
            ..Config::default()
        };
        config.trusted.insert(CID.to_string(), objet());
        let mut r = MqttImpersonation::new(config);
        // L'attaquant se connecte en premier : la confiance le démasque quand même.
        let alertes = r.on_mqtt(s(1), &connect(CID, attaquant()));
        assert_eq!(alertes.len(), 1);
        assert!(alertes[0].details.contains("l'association de confiance"));
        // Le vrai objet, lui, ne déclenche rien.
        assert!(r.on_mqtt(s(2), &connect(CID, objet())).is_empty());
    }

    #[test]
    fn association_de_confiance_compare_le_couple_ip_et_mac() {
        let mut config = Config::default();
        config.trusted.insert(CID.to_string(), objet());
        let mut r = MqttImpersonation::new(config);
        // Même MAC mais autre IP : avec la confiance, c'est signalé (couple strict).
        let autre_ip = Ipv4Sender {
            ip: Ipv4Addr::new(192, 168, 60, 200),
            mac: objet().mac,
        };
        assert_eq!(r.on_mqtt(s(1), &connect(CID, autre_ip)).len(), 1);
    }

    #[test]
    fn les_evenements_sans_connect_ne_sont_pas_concernes() {
        // La règle ne réagit qu'au CONNECT ; aujourd'hui MqttPacket n'a que ça.
        let mut r = MqttImpersonation::new(Config::default());
        assert!(r.on_mqtt(s(1), &connect(CID, objet())).is_empty());
    }

    #[test]
    fn la_memoire_reste_bornee() {
        let mut r = MqttImpersonation::new(Config {
            max_entries: 8,
            ..Config::default()
        });
        for i in 0..1000 {
            let src = Ipv4Sender {
                ip: Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8),
                mac: MacAddr([0, 0, 0, 0, (i >> 8) as u8, i as u8]),
            };
            r.on_mqtt(s(1), &connect(&format!("client-{i}"), src));
        }
        assert!(r.learned.len() <= 8);
    }
}
