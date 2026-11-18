//! Règle ARP-001 : usurpation d'adresse IP par empoisonnement ARP
//! (MITRE ATT&CK T1557.002, ARP Cache Poisoning).
//!
//! # Principe
//!
//! Chaque message ARP REVENDIQUE une association « IP de l'émetteur → MAC de
//! l'émetteur » : requêtes comme réponses, car les deux mettent à jour les
//! caches des machines qui les reçoivent. La règle apprend ces associations,
//! puis lève une alerte quand une IP est revendiquée par une AUTRE MAC que
//! celle connue :
//!
//! - association de CONFIANCE (configurée, par exemple la passerelle) : toute
//!   autre MAC déclenche l'alerte, même si l'IP n'a encore jamais été vue ;
//! - association APPRISE : alerte si l'ancienne MAC a été vue récemment
//!   (moins de `binding_ttl`). Au-delà, on considère un changement légitime
//!   (carte remplacée, MAC aléatoire renouvelée) et on apprend la nouvelle.
//!
//! Une revendication contradictoire ne remplace JAMAIS l'association connue :
//! l'attaquant ne peut pas « s'installer » en répétant ses réponses.
//!
//! # Qui désigner ?
//!
//! Un message usurpé porte l'IP de la VICTIME et la MAC de l'attaquant. Le
//! champ `source_ip` de l'alerte (l'objet à révoquer) ne doit donc surtout
//! pas reprendre l'IP du message : on cherche l'IP que la MAC de l'attaquant
//! a revendiquée légitimement. Si on ne la connaît pas, `source_ip` reste
//! vide : mieux vaut ne désigner personne que désigner la victime.
//!
//! # Limites connues
//!
//! - Si la victime se tait plus de `binding_ttl` pendant l'attaque, la MAC de
//!   l'attaquant est apprise ; c'est le retour de la victime qui sera signalé.
//! - Une machine qui change de MAC sans se taire assez longtemps (MAC
//!   aléatoire renouvelée à la reconnexion) produit un faux positif : à
//!   régler avec `binding_ttl` ou une association de confiance.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::Rule;
use crate::alert::{Alert, Severity, Timestamp};
use crate::decode::{Arp, ArpOp, Frame, MacAddr};

/// Identifiant de la règle (champ `rule_id`).
pub const RULE_ID: &str = "ARP-001";
/// Type d'alerte (champ `type`).
pub const ALERT_TYPE: &str = "arp_spoofing";

/// Réglages de la règle. `Config::default()` donne des valeurs de départ,
/// à ajuster selon le réseau surveillé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Gravité des alertes levées.
    pub severity: Severity,
    /// Durée au-delà de laquelle une association apprise, sans nouvelle de sa
    /// MAC, peut être remplacée sans alerte.
    pub binding_ttl: Duration,
    /// Une réponse est « sollicitée » si une requête pour la même IP a été
    /// vue dans ce délai (information reportée dans `details`).
    pub request_window: Duration,
    /// Pour un même couple (IP, MAC usurpatrice), une seule alerte par
    /// période : un attaquant envoie ses réponses en rafale.
    pub alert_cooldown: Duration,
    /// Nombre maximal d'entrées par table : la mémoire reste bornée même si
    /// un attaquant inonde le réseau d'adresses différentes.
    pub max_entries: usize,
    /// Associations de confiance (IP → MAC), par exemple la passerelle.
    pub trusted: BTreeMap<Ipv4Addr, MacAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            severity: Severity::High,
            binding_ttl: Duration::from_secs(300),
            request_window: Duration::from_secs(5),
            alert_cooldown: Duration::from_secs(60),
            max_entries: 1024,
            trusted: BTreeMap::new(),
        }
    }
}

/// Une association apprise.
#[derive(Debug, Clone, Copy)]
struct Binding {
    mac: MacAddr,
    /// Dernière fois que CETTE MAC a revendiqué l'IP.
    last_seen: Duration,
}

/// D'où vient l'association contredite (reporté dans `details`).
#[derive(Debug, Clone, Copy)]
enum Known {
    Trusted(MacAddr),
    Learned(MacAddr),
}

/// L'état de la règle ARP-001.
///
/// Les tables sont des `BTreeMap` et non des `HashMap` : leur parcours suit
/// l'ordre des clés, alors que celui d'une `HashMap` change d'une exécution à
/// l'autre. La recherche de l'IP de l'attaquant parcourt `bindings` : avec
/// une `BTreeMap`, son résultat est déterministe.
#[derive(Debug)]
pub struct ArpSpoof {
    config: Config,
    /// IP → association apprise.
    bindings: BTreeMap<Ipv4Addr, Binding>,
    /// IP demandée par une requête → instant de la dernière requête.
    pending: BTreeMap<Ipv4Addr, Duration>,
    /// (IP usurpée, MAC usurpatrice) → instant de la dernière alerte.
    last_alert: BTreeMap<(Ipv4Addr, MacAddr), Duration>,
}

impl ArpSpoof {
    pub fn new(config: Config) -> Self {
        ArpSpoof {
            config,
            bindings: BTreeMap::new(),
            pending: BTreeMap::new(),
            last_alert: BTreeMap::new(),
        }
    }

    /// Mémorise une requête « qui a `ip` ? » vue à l'instant `ts`.
    fn note_request(&mut self, ip: Ipv4Addr, ts: Duration) {
        let window = self.config.request_window;
        if self.pending.len() >= self.config.max_entries && !self.pending.contains_key(&ip) {
            self.pending
                .retain(|_, seen| ts.saturating_sub(*seen) <= window);
        }
        if self.pending.len() < self.config.max_entries || self.pending.contains_key(&ip) {
            self.pending.insert(ip, ts);
        }
    }

    /// Vérifie l'association revendiquée par l'émetteur du message.
    fn check_claim(&mut self, ts: Duration, arp: &Arp) -> Option<Alert> {
        let (ip, mac) = (arp.sender_ip, arp.sender_mac);

        // 1. Association de confiance : elle prime sur tout apprentissage.
        if let Some(&expected) = self.config.trusted.get(&ip) {
            return if mac == expected {
                None
            } else {
                self.raise(ts, arp, Known::Trusted(expected))
            };
        }

        // 2. Association apprise.
        let ttl = self.config.binding_ttl;
        match self.bindings.get_mut(&ip) {
            // Même MAC : l'association est confirmée.
            Some(binding) if binding.mac == mac => {
                binding.last_seen = ts;
                None
            }
            // Autre MAC alors que l'ancienne est encore active : usurpation.
            Some(binding) if ts.saturating_sub(binding.last_seen) <= ttl => {
                let known = binding.mac;
                self.raise(ts, arp, Known::Learned(known))
            }
            // L'ancienne MAC s'est tue depuis longtemps : changement légitime.
            Some(binding) => {
                *binding = Binding { mac, last_seen: ts };
                None
            }
            // Première revendication de cette IP : on apprend.
            None => {
                self.learn(ip, mac, ts);
                None
            }
        }
    }

    /// Ajoute une association, si la table n'est pas pleine (après avoir
    /// oublié les associations expirées).
    fn learn(&mut self, ip: Ipv4Addr, mac: MacAddr, ts: Duration) {
        let ttl = self.config.binding_ttl;
        if self.bindings.len() >= self.config.max_entries {
            self.bindings
                .retain(|_, b| ts.saturating_sub(b.last_seen) <= ttl);
        }
        if self.bindings.len() < self.config.max_entries {
            self.bindings.insert(ip, Binding { mac, last_seen: ts });
        }
    }

    /// Construit l'alerte, sauf si le même couple (IP, MAC) a déjà été
    /// signalé il y a moins de `alert_cooldown`.
    fn raise(&mut self, ts: Duration, arp: &Arp, known: Known) -> Option<Alert> {
        let (ip, mac) = (arp.sender_ip, arp.sender_mac);
        let cooldown = self.config.alert_cooldown;

        // `if let ... && ...` : une « let chain », possible car rwatch est en
        // édition 2024 (voir la discussion sur clippy et rnifler).
        if let Some(&last) = self.last_alert.get(&(ip, mac))
            && ts.saturating_sub(last) < cooldown
        {
            return None;
        }
        if self.last_alert.len() >= self.config.max_entries {
            self.last_alert
                .retain(|_, last| ts.saturating_sub(*last) < cooldown);
        }
        if self.last_alert.len() < self.config.max_entries {
            self.last_alert.insert((ip, mac), ts);
        }

        // L'IP que la MAC usurpatrice a revendiquée légitimement, s'il y en a
        // une. Parcours dans l'ordre des IP : résultat déterministe.
        let attacker_ip = self
            .bindings
            .iter()
            .find(|(other, b)| **other != ip && b.mac == mac)
            .map(|(other, _)| *other);

        let what = match arp.operation {
            ArpOp::Request => "Requête ARP",
            ArpOp::Reply if self.solicited(ip, ts) => "Réponse ARP sollicitée",
            ArpOp::Reply => "Réponse ARP non sollicitée",
            ArpOp::Other(_) => "Message ARP",
        };
        let (origin, known_mac) = match known {
            Known::Trusted(m) => ("l'association de confiance", m),
            Known::Learned(m) => ("l'association apprise", m),
        };
        let mut details =
            format!("{what} : {ip} revendiqué par {mac}, alors que {origin} indique {known_mac}");
        if attacker_ip.is_none() {
            details.push_str(" (IP de l'émetteur inconnue)");
        }

        Some(Alert {
            timestamp: Timestamp(ts),
            kind: ALERT_TYPE,
            severity: self.config.severity,
            source_ip: attacker_ip.map(IpAddr::V4),
            source_mac: Some(mac),
            target: Some(ip.to_string()),
            details,
            rule_id: RULE_ID,
        })
    }

    /// Une requête pour `ip` a-t-elle été vue récemment ?
    fn solicited(&self, ip: Ipv4Addr, ts: Duration) -> bool {
        self.pending
            .get(&ip)
            .is_some_and(|&asked| ts.saturating_sub(asked) <= self.config.request_window)
    }
}

impl Rule for ArpSpoof {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn on_frame(&mut self, ts: Duration, frame: &Frame<'_>) -> Vec<Alert> {
        let Frame::Arp(arp) = frame else {
            return Vec::new();
        };
        if arp.operation == ArpOp::Request {
            self.note_request(arp.target_ip, ts);
        }
        // Émetteur 0.0.0.0 : sonde de détection de conflit (RFC 5227), qui
        // ne revendique aucune IP.
        if arp.sender_ip.is_unspecified() {
            return Vec::new();
        }
        self.check_claim(ts, arp).into_iter().collect()
    }
}

// ===========================================================================
// Tests : la logique de la règle, sans fichier ni réseau
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const PASSERELLE: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 1);
    const VICTIME: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 182);
    const ATTAQUANT: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 50);
    const MAC_PASSERELLE: MacAddr = MacAddr([0xdc, 0xa6, 0x32, 0x00, 0x00, 0x01]);
    const MAC_VICTIME: MacAddr = MacAddr([0x24, 0x6f, 0x28, 0x00, 0x00, 0xb6]);
    const MAC_ATTAQUANT: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn requete(de: (Ipv4Addr, MacAddr), qui_a: Ipv4Addr) -> Arp {
        Arp {
            operation: ArpOp::Request,
            sender_ip: de.0,
            sender_mac: de.1,
            target_ip: qui_a,
            target_mac: MacAddr([0; 6]),
        }
    }

    fn reponse(de: (Ipv4Addr, MacAddr), vers: (Ipv4Addr, MacAddr)) -> Arp {
        Arp {
            operation: ArpOp::Reply,
            sender_ip: de.0,
            sender_mac: de.1,
            target_ip: vers.0,
            target_mac: vers.1,
        }
    }

    /// Passe une suite de (instant, message) à la règle ; renvoie les alertes.
    fn rejouer(regle: &mut ArpSpoof, messages: &[(u64, Arp)]) -> Vec<Alert> {
        messages
            .iter()
            .flat_map(|(t, arp)| regle.on_frame(s(*t), &Frame::Arp(*arp)))
            .collect()
    }

    /// Réseau qui a déjà vu passer la passerelle, la victime et l'attaquant
    /// (chacun a fait une requête ARP normale à t = 1, 2, 3).
    fn reseau_appris() -> ArpSpoof {
        let mut regle = ArpSpoof::new(Config::default());
        let alertes = rejouer(
            &mut regle,
            &[
                (1, requete((PASSERELLE, MAC_PASSERELLE), VICTIME)),
                (2, requete((VICTIME, MAC_VICTIME), PASSERELLE)),
                (3, requete((ATTAQUANT, MAC_ATTAQUANT), PASSERELLE)),
            ],
        );
        assert!(alertes.is_empty());
        regle
    }

    #[test]
    fn echange_normal_sans_alerte() {
        let mut regle = ArpSpoof::new(Config::default());
        let alertes = rejouer(
            &mut regle,
            &[
                (0, requete((PASSERELLE, MAC_PASSERELLE), VICTIME)),
                (
                    0,
                    reponse((VICTIME, MAC_VICTIME), (PASSERELLE, MAC_PASSERELLE)),
                ),
                (9, requete((PASSERELLE, MAC_PASSERELLE), VICTIME)),
                (
                    9,
                    reponse((VICTIME, MAC_VICTIME), (PASSERELLE, MAC_PASSERELLE)),
                ),
            ],
        );
        assert!(alertes.is_empty(), "{alertes:#?}");
    }

    #[test]
    fn reponse_non_sollicitee_d_une_autre_mac_est_une_usurpation() {
        let mut regle = reseau_appris();
        // L'attaquant dit à la victime : « la passerelle, c'est moi ».
        let alertes = rejouer(
            &mut regle,
            &[(
                10,
                reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME)),
            )],
        );
        assert_eq!(alertes.len(), 1);
        let alerte = &alertes[0];
        assert_eq!(alerte.rule_id, "ARP-001");
        assert_eq!(alerte.kind, "arp_spoofing");
        assert_eq!(alerte.severity, Severity::High);
        // L'objet fautif est l'ATTAQUANT, retrouvé par sa MAC.
        assert_eq!(alerte.source_ip, Some(IpAddr::V4(ATTAQUANT)));
        assert_eq!(alerte.source_mac, Some(MAC_ATTAQUANT));
        // La cible est l'IP usurpée.
        assert_eq!(alerte.target.as_deref(), Some("192.168.50.1"));
        assert_eq!(
            alerte.details,
            "Réponse ARP non sollicitée : 192.168.50.1 revendiqué par aa:bb:cc:dd:ee:ff, \
             alors que l'association apprise indique dc:a6:32:00:00:01"
        );
    }

    #[test]
    fn une_rafale_ne_donne_qu_une_alerte_par_periode() {
        let mut regle = reseau_appris();
        let spoof = reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME));
        // arpspoof renvoie sa réponse toutes les 2 s environ.
        let rafale: Vec<(u64, Arp)> = (0..30).map(|i| (10 + 2 * i, spoof)).collect();
        assert_eq!(rejouer(&mut regle, &rafale).len(), 1);
        // Toujours en cours après la période de silence : nouvelle alerte.
        assert_eq!(rejouer(&mut regle, &[(70, spoof)]).len(), 1);
    }

    #[test]
    fn l_usurpation_ne_remplace_pas_l_association_connue() {
        let mut regle = reseau_appris();
        rejouer(
            &mut regle,
            &[(
                10,
                reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME)),
            )],
        );
        // La vraie passerelle parle ensuite : aucune alerte contre elle.
        let alertes = rejouer(
            &mut regle,
            &[(11, requete((PASSERELLE, MAC_PASSERELLE), VICTIME))],
        );
        assert!(alertes.is_empty(), "{alertes:#?}");
    }

    #[test]
    fn deux_reponses_contradictoires_a_une_meme_requete() {
        // Course classique : l'attaquant répond à la requête plus vite que
        // la vraie machine. La réponse est « sollicitée », mais contradictoire.
        let mut regle = reseau_appris();
        let alertes = rejouer(
            &mut regle,
            &[
                (20, requete((VICTIME, MAC_VICTIME), PASSERELLE)),
                (
                    20,
                    reponse((PASSERELLE, MAC_PASSERELLE), (VICTIME, MAC_VICTIME)),
                ),
                (
                    20,
                    reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME)),
                ),
            ],
        );
        assert_eq!(alertes.len(), 1);
        assert!(alertes[0].details.starts_with("Réponse ARP sollicitée"));
    }

    #[test]
    fn changement_de_mac_apres_un_long_silence_est_legitime() {
        let mut regle = reseau_appris();
        let nouvelle_mac = MacAddr([0x24, 0x6f, 0x28, 0x00, 0x00, 0xff]);
        // La victime s'est tue plus de binding_ttl (300 s) : carte remplacée.
        let alertes = rejouer(
            &mut regle,
            &[(400, requete((VICTIME, nouvelle_mac), PASSERELLE))],
        );
        assert!(alertes.is_empty(), "{alertes:#?}");
    }

    #[test]
    fn attaquant_sans_ip_connue_n_est_pas_confondu_avec_la_victime() {
        let mut regle = ArpSpoof::new(Config::default());
        let inconnue = MacAddr([0x02, 0, 0, 0, 0, 0x66]);
        let alertes = rejouer(
            &mut regle,
            &[
                (1, requete((VICTIME, MAC_VICTIME), PASSERELLE)),
                (
                    2,
                    reponse((VICTIME, inconnue), (PASSERELLE, MAC_PASSERELLE)),
                ),
            ],
        );
        assert_eq!(alertes.len(), 1);
        // Surtout pas Some(VICTIME) : l'IdP révoquerait la victime.
        assert_eq!(alertes[0].source_ip, None);
        assert_eq!(alertes[0].source_mac, Some(inconnue));
        assert!(alertes[0].details.ends_with("(IP de l'émetteur inconnue)"));
    }

    #[test]
    fn association_de_confiance_verifiee_des_la_premiere_trame() {
        let mut config = Config::default();
        config.trusted.insert(PASSERELLE, MAC_PASSERELLE);
        let mut regle = ArpSpoof::new(config);
        let alertes = rejouer(
            &mut regle,
            &[
                (1, requete((PASSERELLE, MAC_PASSERELLE), VICTIME)),
                (
                    2,
                    reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME)),
                ),
            ],
        );
        assert_eq!(alertes.len(), 1);
        assert!(alertes[0].details.contains("l'association de confiance"));
    }

    #[test]
    fn association_de_confiance_meme_apres_un_long_silence() {
        // Contrairement à une association apprise, elle n'expire jamais.
        let mut config = Config::default();
        config.trusted.insert(PASSERELLE, MAC_PASSERELLE);
        let mut regle = ArpSpoof::new(config);
        let alertes = rejouer(
            &mut regle,
            &[(
                10_000,
                reponse((PASSERELLE, MAC_ATTAQUANT), (VICTIME, MAC_VICTIME)),
            )],
        );
        assert_eq!(alertes.len(), 1);
    }

    #[test]
    fn la_sonde_rfc_5227_est_ignoree() {
        let mut regle = reseau_appris();
        let sonde = Arp {
            operation: ArpOp::Request,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            sender_mac: MAC_ATTAQUANT,
            target_ip: VICTIME,
            target_mac: MacAddr([0; 6]),
        };
        assert!(rejouer(&mut regle, &[(10, sonde)]).is_empty());
    }

    #[test]
    fn les_trames_non_arp_sont_ignorees() {
        let mut regle = ArpSpoof::new(Config::default());
        assert!(regle.on_frame(s(1), &Frame::Other).is_empty());
    }

    #[test]
    fn la_memoire_reste_bornee() {
        let mut regle = ArpSpoof::new(Config {
            max_entries: 8,
            ..Config::default()
        });
        // Inondation : 1000 IP différentes, une seule MAC.
        for i in 0..1000u32 {
            let ip = Ipv4Addr::from(0x0a00_0000 + i);
            regle.on_frame(s(1), &Frame::Arp(requete((ip, MAC_ATTAQUANT), PASSERELLE)));
        }
        assert!(regle.bindings.len() <= 8);
        assert!(regle.pending.len() <= 8);
    }
}
