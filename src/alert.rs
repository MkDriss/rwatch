//! L'alerte émise par rwatch : la traduction Rust du CONTRAT JSON partagé
//! avec ses consommateurs (dashboard, futur IdP).
//!
//! Exemple de sortie (une alerte par ligne, format JSON Lines) :
//!
//! ```text
//! {"timestamp":"2026-01-01T00:00:01Z","type":"arp_spoofing","severity":"high",
//!  "source_ip":"192.168.50.50","source_mac":"aa:bb:cc:dd:ee:ff",
//!  "target":"192.168.50.1","details":"...","rule_id":"ARP-001"}
//! ```
//!
//! serde sérialise les champs DANS L'ORDRE DE DÉCLARATION de la struct :
//! l'ordre ci-dessous est celui du contrat, et la sortie est stable.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Serialize, Serializer};

use crate::decode::MacAddr;

/// Gravité d'une alerte. Sérialisée en minuscules : `"high"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Une alerte, conforme au contrat JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// Instant où le paquet en cause a été CAPTURÉ (horodatage pcap), et non
    /// l'heure à laquelle rwatch l'a traité.
    pub timestamp: Timestamp,
    /// `type` est un mot réservé en Rust : le champ s'appelle `kind` dans le
    /// code et `type` dans le JSON.
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub severity: Severity,
    /// L'objet fautif, à révoquer côté IAM. `null` dans le JSON s'il est
    /// inconnu : mieux vaut ne désigner personne que désigner la victime.
    pub source_ip: Option<IpAddr>,
    /// Absent du JSON s'il est inconnu.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<MacAddr>,
    /// Ce qui est visé (adresse, service...). Absent du JSON s'il est inconnu.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub details: String,
    pub rule_id: &'static str,
}

/// Un instant, exprimé comme le temps écoulé depuis le 1er janvier 1970 UTC
/// (comme l'horodatage pcap). Sérialisé au format RFC 3339, à la seconde :
/// `"2026-01-01T00:00:01Z"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub Duration);

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let (year, month, day) = civil_from_days(secs / 86_400);
        let in_day = secs % 86_400;
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            in_day / 3600,
            in_day % 3600 / 60,
            in_day % 60
        )
    }
}

/// serde ne sait pas sérialiser notre type : on lui explique (une chaîne).
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Convertit un nombre de jours depuis le 1er janvier 1970 en date
/// (année, mois, jour) du calendrier grégorien.
///
/// Algorithme `civil_from_days` de Howard Hinnant (« chrono-Compatible
/// Low-Level Date Algorithms »), restreint aux dates postérieures à 1970 :
/// le même que dans `rnifler::record`, où il est privé.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468; // jours depuis le 1er mars de l'an 0
    let era = z / 146_097; // ères de 400 ans
    let doe = z % 146_097; // jour dans l'ère [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // année dans l'ère
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // jour dans l'année (depuis mars)
    let mp = (5 * doy + 2) / 153; // mois, mars = 0
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

// ===========================================================================
// Tests : le contrat JSON
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn at(secs: u64) -> Timestamp {
        Timestamp(Duration::from_secs(secs))
    }

    #[test]
    fn dates_de_reference() {
        // Valeurs de référence : `date -u -d @<secondes> +%FT%TZ` (GNU coreutils).
        assert_eq!(at(0).to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(at(1_767_225_600).to_string(), "2026-01-01T00:00:00Z");
        assert_eq!(at(1_709_164_800).to_string(), "2024-02-29T00:00:00Z");
        assert_eq!(at(4_102_444_799).to_string(), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn les_fractions_de_seconde_sont_tronquees() {
        let ts = Timestamp(Duration::new(1_767_225_600, 999_999_999));
        assert_eq!(ts.to_string(), "2026-01-01T00:00:00Z");
    }

    fn alerte() -> Alert {
        Alert {
            timestamp: at(1_767_225_601),
            kind: "arp_spoofing",
            severity: Severity::High,
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 50))),
            source_mac: Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            target: Some("192.168.50.182".to_string()),
            details: "test".to_string(),
            rule_id: "ARP-001",
        }
    }

    #[test]
    fn serialisation_conforme_au_contrat() {
        // Comparaison de la CHAÎNE exacte : vérifie aussi l'ordre des champs.
        assert_eq!(
            serde_json::to_string(&alerte()).unwrap(),
            r#"{"timestamp":"2026-01-01T00:00:01Z","type":"arp_spoofing","severity":"high","source_ip":"192.168.50.50","source_mac":"aa:bb:cc:dd:ee:ff","target":"192.168.50.182","details":"test","rule_id":"ARP-001"}"#
        );
    }

    #[test]
    fn source_inconnue_null_et_champs_optionnels_absents() {
        let alerte = Alert {
            source_ip: None,
            source_mac: None,
            target: None,
            ..alerte()
        };
        let json = serde_json::to_string(&alerte).unwrap();
        assert!(json.contains(r#""source_ip":null"#), "{json}");
        assert!(
            !json.contains("source_mac") && !json.contains("target"),
            "{json}"
        );
    }
}
