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

pub mod arp_spoof;

use std::time::Duration;

use crate::alert::Alert;
use crate::decode::Frame;

/// Une règle de détection.
///
/// `&mut self` : une règle POSSÈDE son état (par exemple la table IP → MAC
/// de la règle ARP) et le modifie à chaque trame. `&Frame` : la trame est
/// seulement empruntée, toutes les règles lisent la même sans copie.
pub trait Rule {
    /// Identifiant stable de la règle, repris dans le champ `rule_id`.
    fn id(&self) -> &'static str;

    /// Examine une trame capturée à l'instant `ts` ; renvoie les alertes
    /// levées (le plus souvent aucune : un `Vec` vide n'alloue rien).
    fn on_frame(&mut self, ts: Duration, frame: &Frame<'_>) -> Vec<Alert>;
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
}
