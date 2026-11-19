//! Couche DÉTECTION : un moteur qui confie chaque trame à un ensemble de
//! règles, et collecte les alertes qu'elles lèvent.
//!
//! Le moteur ne connaît aucune règle en particulier : il manipule des
//! `Box<dyn Rule>`. Ajouter une règle = écrire un type qui implémente
//! [`Rule`], sans toucher au moteur.
//!
//! Le temps : les règles ne lisent JAMAIS l'horloge système. Elles reçoivent
//! l'horodatage de capture de chaque trame, ce qui rend la détection
//! identique en direct et en rejeu d'un fichier `.pcap` (déterminisme).
//!
//! # Limite connue : pas de contexte partagé
//!
//! Chaque règle possède son propre état, isolé des autres : les règles sont
//! indépendantes et se testent séparément. En contrepartie, une connaissance
//! utile à plusieurs règles (par exemple la table IP → MAC, qui servirait
//! aussi à une corrélation DHCP/ARP) serait dupliquée dans chacune. Un
//! « contexte » partagé, transmis aux règles par le moteur, sera introduit le
//! jour où ce besoin apparaîtra.

pub mod arp_spoof;
pub mod mqtt_impersonation;

use std::time::Duration;

use crate::alert::Alert;
use crate::decode::Frame;
use crate::mqtt::MqttEvent;

/// Une règle de détection.
///
/// `&mut self` : une règle POSSÈDE son état (par exemple la table IP → MAC
/// de la règle ARP) et le modifie à chaque trame. `&Frame` : la trame est
/// seulement empruntée, toutes les règles lisent la même sans copie.
pub trait Rule {
    /// Identifiant stable de la règle, repris dans le champ `rule_id`.
    fn id(&self) -> &'static str;

    /// `true` si la règle consomme des événements MQTT (`on_mqtt`). Le moteur
    /// s'en sert pour n'activer le décodage MQTT que si nécessaire. Par
    /// défaut `false` : une règle ne regardant que les trames.
    fn needs_mqtt(&self) -> bool {
        false
    }

    /// Examine une trame capturée à l'instant `ts` ; renvoie les alertes
    /// levées (le plus souvent aucune : un `Vec` vide n'alloue rien).
    ///
    /// Corps par défaut vide : une règle qui ne regarde que le MQTT l'ignore.
    fn on_frame(&mut self, _ts: Duration, _frame: &Frame<'_>) -> Vec<Alert> {
        Vec::new()
    }

    /// Examine un événement MQTT (CONNECT…) capturé à l'instant `ts`.
    ///
    /// Corps par défaut vide : une règle qui ne regarde que les trames
    /// (ARP, TCP) l'ignore.
    fn on_mqtt(&mut self, _ts: Duration, _event: &MqttEvent<'_>) -> Vec<Alert> {
        Vec::new()
    }
}

/// Le moteur de détection : une liste de règles hétérogènes.
pub struct Engine {
    rules: Vec<Box<dyn Rule>>,
}

impl Engine {
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Engine { rules }
    }

    /// Identifiants des règles actives, dans l'ordre d'évaluation.
    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.rules.iter().map(|rule| rule.id()).collect()
    }

    /// Vrai si au moins une règle active consomme des événements MQTT.
    pub fn needs_mqtt(&self) -> bool {
        self.rules.iter().any(|rule| rule.needs_mqtt())
    }

    /// Confie la trame à chaque règle, dans l'ordre, et renvoie toutes les
    /// alertes levées. L'ordre des règles étant fixe, l'ordre des alertes
    /// l'est aussi.
    pub fn on_frame(&mut self, ts: Duration, frame: &Frame<'_>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &mut self.rules {
            alerts.extend(rule.on_frame(ts, frame));
        }
        alerts
    }

    /// Confie un événement MQTT à chaque règle, dans l'ordre.
    pub fn on_mqtt(&mut self, ts: Duration, event: &MqttEvent<'_>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &mut self.rules {
            alerts.extend(rule.on_mqtt(ts, event));
        }
        alerts
    }
}
