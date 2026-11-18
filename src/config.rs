//! Lecture du fichier de configuration (format TOML).
//!
//! # Deux représentations, volontairement séparées
//!
//! - Le FORMAT DU FICHIER (`FileConfig`, `ArpSpoofSection`…) : ce que
//!   l'utilisateur écrit, avec des noms et des unités lisibles
//!   (`binding_ttl_secs = 300`). serde le remplit automatiquement.
//! - La CONFIGURATION INTERNE (`arp_spoof::Config`) : ce que le code utilise,
//!   avec des types précis (`Duration`).
//!
//! La conversion de l'un vers l'autre est l'endroit unique où l'on VALIDE ce
//! que le type seul ne garantit pas (un TTL nul, une table de taille 0…).
//! Le format du fichier peut évoluer sans toucher aux règles, et inversement.
//!
//! # Sécurité par défaut
//!
//! Toute clé inconnue est une ERREUR (`deny_unknown_fields`) : une faute de
//! frappe (`binding_tll_secs`) serait sinon ignorée en silence, et la règle
//! tournerait avec une valeur que l'utilisateur croit avoir changée. Pour un
//! outil de sécurité, mieux vaut refuser de démarrer.
//!
//! Un fichier vide, ou une section absente, donne les valeurs par défaut.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::alert::Severity;
use crate::decode::MacAddr;
use crate::detect::{Rule, arp_spoof};

// ===========================================================================
// Format du fichier
// ===========================================================================

/// Le fichier de configuration complet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub capture: CaptureSection,
    pub rules: RulesSection,
}

/// Section `[capture]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureSection {
    /// Filtre BPF. Absent : celui de la ligne de commande, ou le défaut.
    pub filter: Option<String>,
}

/// Section `[rules]` : une sous-section par règle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesSection {
    pub arp_spoofing: ArpSpoofSection,
}

/// Section `[rules.arp_spoofing]`. Les durées sont en secondes, et le nom
/// de chaque clé le dit : aucune ambiguïté d'unité.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArpSpoofSection {
    pub enabled: bool,
    pub severity: Severity,
    pub binding_ttl_secs: u64,
    pub request_window_secs: u64,
    pub alert_cooldown_secs: u64,
    pub max_entries: usize,
    /// Associations de confiance : `"IP" = "MAC"`.
    pub trusted: BTreeMap<Ipv4Addr, MacAddr>,
}

/// Les valeurs par défaut du fichier sont CELLES DE LA RÈGLE : une seule
/// source de vérité, `arp_spoof::Config::default()`.
impl Default for ArpSpoofSection {
    fn default() -> Self {
        let rule = arp_spoof::Config::default();
        ArpSpoofSection {
            enabled: true,
            severity: rule.severity,
            binding_ttl_secs: rule.binding_ttl.as_secs(),
            request_window_secs: rule.request_window.as_secs(),
            alert_cooldown_secs: rule.alert_cooldown.as_secs(),
            max_entries: rule.max_entries,
            trusted: rule.trusted,
        }
    }
}

/// Conversion vers la configuration interne de la règle, avec validation.
impl TryFrom<&ArpSpoofSection> for arp_spoof::Config {
    type Error = ConfigError;

    fn try_from(section: &ArpSpoofSection) -> Result<Self, Self::Error> {
        let invalid = |key: &str, why: &str| {
            Err(ConfigError::Invalid(format!(
                "[rules.arp_spoofing] {key} : {why}"
            )))
        };
        if section.binding_ttl_secs == 0 {
            return invalid("binding_ttl_secs", "doit être supérieur à 0");
        }
        if section.max_entries == 0 {
            return invalid("max_entries", "doit être supérieur à 0");
        }
        if section.trusted.keys().any(Ipv4Addr::is_unspecified) {
            return invalid(
                "trusted",
                "0.0.0.0 ne peut pas être une association de confiance",
            );
        }
        Ok(arp_spoof::Config {
            severity: section.severity,
            binding_ttl: Duration::from_secs(section.binding_ttl_secs),
            request_window: Duration::from_secs(section.request_window_secs),
            alert_cooldown: Duration::from_secs(section.alert_cooldown_secs),
            max_entries: section.max_entries,
            trusted: section.trusted.clone(),
        })
    }
}

// ===========================================================================
// Erreurs
// ===========================================================================

/// Ce qui peut empêcher de charger la configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Fichier illisible (absent, droits…).
    Io { path: PathBuf, source: io::Error },
    /// Fichier mal écrit : syntaxe TOML, clé inconnue, type ou valeur
    /// incorrects. Le message de `toml` indique la ligne et la colonne.
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// Fichier bien écrit, mais valeur incohérente (un TTL nul…).
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "configuration {} illisible : {source}", path.display())
            }
            ConfigError::Parse { path, source } => {
                write!(f, "configuration {} invalide :\n{source}", path.display())
            }
            ConfigError::Invalid(why) => write!(f, "configuration invalide : {why}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ===========================================================================
// Chargement
// ===========================================================================

impl FileConfig {
    /// Lit et analyse le fichier `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Analyse un texte TOML (séparé de `load` pour être testé sans fichier).
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Construit les règles actives, dans un ordre fixe.
    pub fn rules(&self) -> Result<Vec<Box<dyn Rule>>, ConfigError> {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        let arp = &self.rules.arp_spoofing;
        if arp.enabled {
            let config = arp_spoof::Config::try_from(arp)?;
            rules.push(Box::new(arp_spoof::ArpSpoof::new(config)));
        }
        Ok(rules)
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Le message d'une erreur d'analyse, pour vérifier ce qu'il explique.
    fn erreur(text: &str) -> String {
        FileConfig::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn un_fichier_vide_donne_les_valeurs_par_defaut() {
        let config = FileConfig::parse("").unwrap();
        assert_eq!(config, FileConfig::default());
        assert_eq!(
            arp_spoof::Config::try_from(&config.rules.arp_spoofing).unwrap(),
            arp_spoof::Config::default()
        );
    }

    #[test]
    fn configuration_complete() {
        let config = FileConfig::parse(
            r#"
            [capture]
            filter = "arp or ip"

            [rules.arp_spoofing]
            severity = "critical"
            binding_ttl_secs = 600
            alert_cooldown_secs = 30

            [rules.arp_spoofing.trusted]
            "192.0.2.1" = "00:00:5E:00:53:01"
            "#,
        )
        .unwrap();
        assert_eq!(config.capture.filter.as_deref(), Some("arp or ip"));
        let arp = arp_spoof::Config::try_from(&config.rules.arp_spoofing).unwrap();
        assert_eq!(arp.severity, Severity::Critical);
        assert_eq!(arp.binding_ttl, Duration::from_secs(600));
        assert_eq!(arp.alert_cooldown, Duration::from_secs(30));
        // Les clés absentes gardent leur valeur par défaut.
        assert_eq!(arp.request_window, Duration::from_secs(5));
        assert_eq!(
            arp.trusted.get(&Ipv4Addr::new(192, 0, 2, 1)),
            Some(&MacAddr([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        );
    }

    #[test]
    fn une_faute_de_frappe_est_refusee() {
        let message = erreur("[rules.arp_spoofing]\nbinding_tll_secs = 600\n");
        assert!(message.contains("binding_tll_secs"), "{message}");
        // Le message situe l'erreur : ligne 2.
        assert!(message.contains("line 2"), "{message}");
    }

    #[test]
    fn une_section_inconnue_est_refusee() {
        assert!(erreur("[rules.arp_spoffing]\n").contains("arp_spoffing"));
    }

    #[test]
    fn une_mac_invalide_est_refusee_avec_son_explication() {
        let message = erreur("[rules.arp_spoofing.trusted]\n\"192.0.2.1\" = \"00:00:5e:00:53\"\n");
        assert!(message.contains("adresse MAC invalide"), "{message}");
    }

    #[test]
    fn une_ip_invalide_est_refusee() {
        assert!(
            FileConfig::parse(
                "[rules.arp_spoofing.trusted]\n\"192.0.2.300\" = \"00:00:5e:00:53:01\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn une_gravite_inconnue_est_refusee() {
        assert!(erreur("[rules.arp_spoofing]\nseverity = \"urgent\"\n").contains("urgent"));
    }

    #[test]
    fn un_mauvais_type_est_refuse() {
        // Une durée doit être un nombre, pas une chaîne.
        assert!(FileConfig::parse("[rules.arp_spoofing]\nbinding_ttl_secs = \"300\"\n").is_err());
        // Et pas un nombre négatif.
        assert!(FileConfig::parse("[rules.arp_spoofing]\nbinding_ttl_secs = -1\n").is_err());
    }

    #[test]
    fn des_valeurs_incoherentes_sont_refusees() {
        for text in [
            "[rules.arp_spoofing]\nbinding_ttl_secs = 0\n",
            "[rules.arp_spoofing]\nmax_entries = 0\n",
            "[rules.arp_spoofing.trusted]\n\"0.0.0.0\" = \"00:00:5e:00:53:01\"\n",
        ] {
            let config = FileConfig::parse(text).unwrap();
            assert!(
                matches!(config.rules(), Err(ConfigError::Invalid(_))),
                "accepté à tort : {text}"
            );
        }
    }

    #[test]
    fn une_regle_desactivee_n_est_pas_construite() {
        let config = FileConfig::parse("[rules.arp_spoofing]\nenabled = false\n").unwrap();
        assert!(config.rules().unwrap().is_empty());
        assert_eq!(FileConfig::default().rules().unwrap().len(), 1);
    }

    #[test]
    fn l_exemple_de_configuration_est_valide() {
        // `include_str!` intègre le fichier au test à la compilation : si
        // l'exemple devient invalide, ce test échoue. La doc ne peut pas
        // dériver du code.
        let config = FileConfig::parse(include_str!("../config/rwatch.example.toml")).unwrap();
        assert_eq!(config.rules().unwrap().len(), 1);
    }
}
