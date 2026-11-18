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
//!
//! # Un fichier par règle : la liste explicite `[rules] files`
//!
//! La configuration d'une règle peut vivre dans son propre fichier, listé
//! explicitement dans le fichier principal :
//!
//! ```toml
//! [rules]
//! files = ["rules/arp_spoofing.toml"]
//! ```
//!
//! Garde-fous, tous vérifiés AU DÉMARRAGE :
//! - un chemin relatif est résolu par rapport au fichier principal, jamais par
//!   rapport au répertoire courant ;
//! - un fichier listé mais absent est une erreur : une configuration ne peut
//!   pas disparaître en silence (les associations de confiance avec elle) ;
//! - une section de règle définie deux fois est une erreur qui nomme les deux
//!   fichiers : aucune surcharge cachée, et l'ordre de la liste est sans effet ;
//! - un fichier inclus ne contient que des sections `[rules.*]` : pas de
//!   réglage global, et pas d'inclusion imbriquée (ni boucle ni cascade).

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

/// Section `[rules]` du fichier principal : la liste des fichiers inclus,
/// et éventuellement des sections de règles écrites directement ici.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesSection {
    /// Fichiers de règles à inclure, dans cet ordre.
    pub files: Vec<PathBuf>,
    /// `None` : section absente (valeurs par défaut, sauf si un fichier
    /// inclus la définit). Distinguer « absente » de « présente avec les
    /// valeurs par défaut » permet de détecter les doublons.
    pub arp_spoofing: Option<ArpSpoofSection>,
}

/// Un fichier de règles inclus : uniquement des sections `[rules.*]`.
/// `[capture]` ou `files` y sont refusés (clé inconnue).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IncludedFile {
    rules: IncludedRules,
}

/// Section `[rules]` d'un fichier inclus. Ajouter une règle : un champ ici,
/// le même dans `RulesSection`, et une ligne dans `merge_included`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IncludedRules {
    arp_spoofing: Option<ArpSpoofSection>,
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
    /// Le même fichier figure deux fois dans `[rules] files`.
    DuplicateFile(PathBuf),
    /// Une même section de règle est définie dans deux fichiers.
    DuplicateSection {
        section: &'static str,
        first: PathBuf,
        second: PathBuf,
    },
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
            ConfigError::DuplicateFile(path) => write!(
                f,
                "configuration invalide : {} figure deux fois dans [rules] files",
                path.display()
            ),
            ConfigError::DuplicateSection {
                section,
                first,
                second,
            } => write!(
                f,
                "configuration invalide : [rules.{section}] est définie dans {} ET dans {} \
                 (une section ne peut être définie qu'une fois)",
                first.display(),
                second.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

// ===========================================================================
// Chargement
// ===========================================================================

impl FileConfig {
    /// Lit le fichier principal `path`, puis chaque fichier de règles qu'il
    /// liste dans `[rules] files`, et fusionne le tout.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = read(path)?;
        let mut config = Self::parse(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

        // Où chaque section a été définie, pour nommer les deux fichiers en
        // cas de doublon. On commence par les sections du fichier principal.
        let mut origins: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
        if config.rules.arp_spoofing.is_some() {
            origins.insert("arp_spoofing", path.to_path_buf());
        }

        // Les chemins relatifs partent du dossier du fichier principal.
        // (`Path::join` avec un chemin absolu renvoie ce chemin absolu.)
        let base = path.parent().unwrap_or(Path::new(""));
        let mut seen: Vec<PathBuf> = Vec::new();
        for listed in config.rules.files.clone() {
            let included = base.join(&listed);
            if seen.contains(&included) {
                return Err(ConfigError::DuplicateFile(included));
            }
            let text = read(&included)?;
            let file: IncludedFile =
                toml::from_str(&text).map_err(|source| ConfigError::Parse {
                    path: included.clone(),
                    source,
                })?;
            config.merge_included(file.rules, &included, &mut origins)?;
            seen.push(included);
        }
        Ok(config)
    }

    /// Analyse le texte TOML d'un fichier principal, sans suivre `files`
    /// (séparé de `load` pour être testé sans fichier).
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Reporte les sections d'un fichier inclus, en refusant les doublons.
    fn merge_included(
        &mut self,
        included: IncludedRules,
        from: &Path,
        origins: &mut BTreeMap<&'static str, PathBuf>,
    ) -> Result<(), ConfigError> {
        merge_section(
            "arp_spoofing",
            &mut self.rules.arp_spoofing,
            included.arp_spoofing,
            from,
            origins,
        )
    }

    /// Construit les règles actives, dans un ordre fixe.
    pub fn rules(&self) -> Result<Vec<Box<dyn Rule>>, ConfigError> {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        let arp = self.rules.arp_spoofing.clone().unwrap_or_default();
        if arp.enabled {
            let config = arp_spoof::Config::try_from(&arp)?;
            rules.push(Box::new(arp_spoof::ArpSpoof::new(config)));
        }
        Ok(rules)
    }
}

/// Lit un fichier de configuration en texte.
fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Reporte `incoming` (une section lue dans `from`) dans `target`, sauf si
/// cette section a déjà été définie ailleurs.
///
/// Générique sur `T` : la même fonction servira pour chaque règle, quel que
/// soit le type de sa section.
fn merge_section<T>(
    name: &'static str,
    target: &mut Option<T>,
    incoming: Option<T>,
    from: &Path,
    origins: &mut BTreeMap<&'static str, PathBuf>,
) -> Result<(), ConfigError> {
    let Some(section) = incoming else {
        return Ok(());
    };
    if let Some(first) = origins.get(name) {
        return Err(ConfigError::DuplicateSection {
            section: name,
            first: first.clone(),
            second: from.to_path_buf(),
        });
    }
    origins.insert(name, from.to_path_buf());
    *target = Some(section);
    Ok(())
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
        assert_eq!(config.rules.arp_spoofing, None);
        assert_eq!(
            arp_spoof::Config::try_from(&ArpSpoofSection::default()).unwrap(),
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
        let section = config.rules.arp_spoofing.unwrap();
        let arp = arp_spoof::Config::try_from(&section).unwrap();
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
        // L'exemple livré avec rwatch est chargé comme un utilisateur le
        // ferait, fichiers inclus compris : s'il devient invalide (clé
        // renommée dans le code…), ce test échoue. La doc ne peut pas dériver.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/exemple/rwatch.toml");
        let config = FileConfig::load(&path).unwrap();
        assert_eq!(config.rules.files.len(), 1);
        assert!(
            config.rules.arp_spoofing.is_some(),
            "section incluse non lue"
        );
        assert_eq!(config.rules().unwrap().len(), 1);
    }

    // --- Fichiers inclus ---------------------------------------------------

    /// Un dossier temporaire propre à un test, avec ses fichiers.
    fn dossier(nom: &str, fichiers: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rwatch-cfg-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (chemin, contenu) in fichiers {
            let path = dir.join(chemin);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contenu).unwrap();
        }
        dir
    }

    const PRINCIPAL: &str = "[rules]\nfiles = [\"rules/arp.toml\"]\n";
    const ARP: &str = "[rules.arp_spoofing]\nbinding_ttl_secs = 600\n";

    #[test]
    fn un_fichier_inclus_est_lu_relativement_au_fichier_principal() {
        let dir = dossier(
            "inclus",
            &[("rwatch.toml", PRINCIPAL), ("rules/arp.toml", ARP)],
        );
        // Lancé depuis n'importe quel répertoire courant : seul compte
        // l'emplacement du fichier principal.
        let config = FileConfig::load(&dir.join("rwatch.toml")).unwrap();
        assert_eq!(config.rules.arp_spoofing.unwrap().binding_ttl_secs, 600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn un_fichier_liste_mais_absent_arrete_le_chargement() {
        let dir = dossier("absent", &[("rwatch.toml", PRINCIPAL)]);
        let erreur = FileConfig::load(&dir.join("rwatch.toml")).unwrap_err();
        assert!(
            matches!(&erreur, ConfigError::Io { path, .. } if path.ends_with("rules/arp.toml"))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn une_section_definie_deux_fois_est_refusee() {
        // Dans le fichier principal ET dans un fichier inclus.
        let principal = format!("{PRINCIPAL}\n{ARP}");
        let dir = dossier(
            "doublon",
            &[("rwatch.toml", &principal), ("rules/arp.toml", ARP)],
        );
        let erreur = FileConfig::load(&dir.join("rwatch.toml")).unwrap_err();
        let message = erreur.to_string();
        assert!(
            matches!(
                erreur,
                ConfigError::DuplicateSection {
                    section: "arp_spoofing",
                    ..
                }
            ),
            "{message}"
        );
        // Le message nomme les deux fichiers.
        assert!(
            message.contains("rwatch.toml") && message.contains("arp.toml"),
            "{message}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deux_fichiers_inclus_definissant_la_meme_section_sont_refuses() {
        let principal = "[rules]\nfiles = [\"a.toml\", \"b.toml\"]\n";
        let dir = dossier(
            "doublon-inclus",
            &[("rwatch.toml", principal), ("a.toml", ARP), ("b.toml", ARP)],
        );
        let erreur = FileConfig::load(&dir.join("rwatch.toml")).unwrap_err();
        assert!(matches!(erreur, ConfigError::DuplicateSection { .. }));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn un_fichier_liste_deux_fois_est_refuse() {
        let principal = "[rules]\nfiles = [\"rules/arp.toml\", \"rules/arp.toml\"]\n";
        let dir = dossier(
            "liste-deux-fois",
            &[("rwatch.toml", principal), ("rules/arp.toml", ARP)],
        );
        let erreur = FileConfig::load(&dir.join("rwatch.toml")).unwrap_err();
        assert!(matches!(erreur, ConfigError::DuplicateFile(_)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn un_fichier_inclus_ne_peut_contenir_que_des_regles() {
        for (cas, inclus) in [
            ("capture", "[capture]\nfilter = \"arp\"\n"),
            ("imbrique", "[rules]\nfiles = [\"autre.toml\"]\n"),
        ] {
            let dir = dossier(
                cas,
                &[("rwatch.toml", PRINCIPAL), ("rules/arp.toml", inclus)],
            );
            let erreur = FileConfig::load(&dir.join("rwatch.toml")).unwrap_err();
            // L'erreur désigne le fichier INCLUS, pas le fichier principal.
            assert!(
                matches!(&erreur, ConfigError::Parse { path, .. } if path.ends_with("rules/arp.toml")),
                "{cas} : {erreur}"
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
