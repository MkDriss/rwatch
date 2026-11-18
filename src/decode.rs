//! Couche DÉCODAGE : classe chaque trame Ethernet pour les règles de détection.
//!
//! - pour toute trame IPv4 : l'émetteur (MAC Ethernet source, IP source) ;
//! - TCP sur IPv4/IPv6 : délégué à `rnifler::parser` (avec ses checksums) ;
//! - ARP sur Ethernet/IPv4 : décodé ici, car rnifler range l'ARP dans
//!   `Parsed::Other` (il ne s'intéresse qu'au TCP) ;
//! - tout le reste : `Content::Other`.
//!
//! Comme dans rnifler, ce module ne dépend pas de libpcap : il reçoit des
//! octets et se teste sans réseau ni privilèges.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use etherparse::{ArpOperation, ArpPacketSlice, LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use rnifler::parser::{self, ParseError, Parsed, TcpSegment};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Une adresse MAC (6 octets).
///
/// Type dédié (« newtype ») plutôt qu'un simple `[u8; 6]` : on peut lui
/// donner son propre affichage (`aa:bb:cc:dd:ee:ff`), et le compilateur
/// empêche de la confondre avec un autre tableau de 6 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Dans le JSON, une MAC est une chaîne `"aa:bb:cc:dd:ee:ff"` (son `Display`),
/// pas un tableau de six nombres.
impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Erreur de lecture d'une adresse MAC écrite sous forme de texte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacParseError(String);

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "adresse MAC invalide « {} » (format attendu : aa:bb:cc:dd:ee:ff)",
            self.0.escape_debug()
        )
    }
}

impl std::error::Error for MacParseError {}

/// Lecture d'une MAC depuis du texte : `"aa:bb:cc:dd:ee:ff"` (majuscules
/// acceptées). C'est ce trait qui rend possible `"…".parse::<MacAddr>()`.
impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let error = || MacParseError(text.to_string());
        let mut bytes = [0u8; 6];
        let mut parts = text.split(':');
        for byte in &mut bytes {
            let part = parts.next().ok_or_else(error)?;
            // Exactement deux chiffres hexadécimaux par octet.
            if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(error());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| error())?;
        }
        // Un septième morceau : trop d'octets.
        if parts.next().is_some() {
            return Err(error());
        }
        Ok(MacAddr(bytes))
    }
}

/// Dans un fichier de configuration, une MAC s'écrit comme dans le JSON :
/// on lit une chaîne, puis on la convertit avec `FromStr`.
impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Opération ARP (RFC 826) : demande ou réponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    /// « Qui a cette IP ? » (code 1).
    Request,
    /// « Cette IP est à cette MAC » (code 2).
    Reply,
    /// Tout autre code (RARP, InARP...) : conservé tel quel.
    Other(u16),
}

/// Un message ARP Ethernet/IPv4, avec les quatre adresses qu'il transporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub operation: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

/// L'émetteur d'un paquet IPv4 : la MAC source de l'en-tête Ethernet et
/// l'IP source de l'en-tête IPv4.
///
/// Attention : pour un paquet venu d'un autre réseau (Internet), la MAC est
/// celle du routeur qui l'a relayé, pas celle de la machine d'origine. Ce
/// couple n'a de sens que pour une machine du réseau local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Sender {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

/// Une trame décodée : ce qui est commun à toutes les trames (l'émetteur
/// IPv4, s'il y en a un), plus son contenu.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Présent si la trame transporte de l'IPv4 (TCP, UDP, ICMP...) ;
    /// absent pour l'ARP, l'IPv6, etc.
    pub ipv4_sender: Option<Ipv4Sender>,
    pub content: Content<'a>,
}

/// Le contenu d'une trame, tel que les règles le regardent.
///
/// `'a` : la variante `Tcp` contient un `TcpSegment<'a>` dont le payload
/// EMPRUNTE les octets de la trame (zéro-copie, comme dans rnifler). Une
/// `Frame` ne peut donc pas survivre à la trame dont elle provient. `Arp`,
/// lui, ne contient que des valeurs copiées (adresses) : il n'emprunte rien.
#[derive(Debug)]
pub enum Content<'a> {
    Arp(Arp),
    Tcp(TcpSegment<'a>),
    /// Trame valide qui n'intéresse pas les règles actuelles (UDP, ICMP,
    /// ARP non Ethernet/IPv4...).
    Other,
}

/// Décode une trame qui commence par un en-tête Ethernet II.
///
/// Un seul découpage par etherparse pour toutes les trames ; les segments TCP
/// sont en plus confiés à `rnifler::parser` (checksums, flags, payload).
///
/// Une trame malformée renvoie une `ParseError` (le type de rnifler) : c'est à
/// l'appelant de décider quoi en faire (pour un IDS, c'est une information).
pub fn decode(frame: &[u8]) -> Result<Frame<'_>, ParseError> {
    let sliced = SlicedPacket::from_ethernet(frame).map_err(ParseError::Malformed)?;

    // L'émetteur IPv4, commun à TCP, UDP, ICMP...
    let ipv4_sender = match (&sliced.link, &sliced.net) {
        (Some(LinkSlice::Ethernet2(eth)), Some(NetSlice::Ipv4(ipv4))) => Some(Ipv4Sender {
            mac: MacAddr(eth.source()),
            ip: ipv4.header().source_addr(),
        }),
        _ => None,
    };

    let content = match (&sliced.net, &sliced.transport) {
        (Some(NetSlice::Arp(arp)), _) => arp_from_slice(arp).map_or(Content::Other, Content::Arp),
        // TCP (sur IPv4 ou IPv6) : délégué à rnifler.
        (_, Some(TransportSlice::Tcp(_))) => match parser::parse_ethernet(frame)? {
            Parsed::Tcp(segment) => Content::Tcp(segment),
            Parsed::Other => Content::Other,
        },
        _ => Content::Other,
    };

    Ok(Frame {
        ipv4_sender,
        content,
    })
}

/// Convertit un message ARP découpé en [`Arp`], ou `None` s'il n'est pas de
/// type Ethernet/IPv4.
fn arp_from_slice(arp: &ArpPacketSlice<'_>) -> Option<Arp> {
    // Vue typée Ethernet/IPv4 : échoue si les tailles d'adresses ne sont
    // pas 6 (MAC) et 4 (IPv4). `?` sur une `Option` : renvoie `None` aussitôt.
    let arp = arp.to_packet().try_eth_ipv4().ok()?;
    let operation = match arp.operation {
        ArpOperation::REQUEST => ArpOp::Request,
        ArpOperation::REPLY => ArpOp::Reply,
        ArpOperation(code) => ArpOp::Other(code),
    };
    Some(Arp {
        operation,
        sender_mac: MacAddr(arp.sender_mac),
        sender_ip: arp.sender_ipv4_addr(),
        target_mac: MacAddr(arp.target_mac),
        target_ip: arp.target_ipv4_addr(),
    })
}

// ===========================================================================
// Tests : sans réseau ni privilèges
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{ArpEthIpv4Packet, PacketBuilder};

    const MAC_PI: [u8; 6] = [0xdc, 0xa6, 0x32, 0x01, 0x02, 0x03];
    const MAC_ESP: [u8; 6] = [0x24, 0x6f, 0x28, 0xaa, 0xbb, 0xcc];

    /// Trame Ethernet contenant un message ARP Ethernet/IPv4.
    fn trame_arp(
        operation: ArpOperation,
        sender: ([u8; 6], [u8; 4]),
        target: ([u8; 6], [u8; 4]),
    ) -> Vec<u8> {
        let arp = ArpEthIpv4Packet {
            operation,
            sender_mac: sender.0,
            sender_ipv4: sender.1,
            target_mac: target.0,
            target_ipv4: target.1,
        };
        let builder = PacketBuilder::ethernet2(sender.0, [0xff; 6]).arp(arp.into());
        let mut frame = Vec::with_capacity(builder.size());
        builder.write(&mut frame).unwrap();
        frame
    }

    fn expect_arp(frame: &[u8]) -> Arp {
        match decode(frame) {
            Ok(Frame {
                ipv4_sender: None,
                content: Content::Arp(arp),
            }) => arp,
            other => panic!("ARP attendu, obtenu : {other:?}"),
        }
    }

    #[test]
    fn reponse_arp() {
        let frame = trame_arp(
            ArpOperation::REPLY,
            (MAC_PI, [192, 168, 50, 1]),
            (MAC_ESP, [192, 168, 50, 182]),
        );
        let arp = expect_arp(&frame);
        assert_eq!(arp.operation, ArpOp::Reply);
        assert_eq!(arp.sender_mac, MacAddr(MAC_PI));
        assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(arp.target_mac, MacAddr(MAC_ESP));
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 50, 182));
    }

    #[test]
    fn requete_arp() {
        // Une requête ne connaît pas encore la MAC cible : elle vaut 0.
        let frame = trame_arp(
            ArpOperation::REQUEST,
            (MAC_ESP, [192, 168, 50, 182]),
            ([0; 6], [192, 168, 50, 1]),
        );
        assert_eq!(expect_arp(&frame).operation, ArpOp::Request);
    }

    #[test]
    fn arp_avec_bourrage_ethernet() {
        // Sur le câble, une trame Ethernet fait au moins 60 octets : l'ARP
        // (42 octets) est complété par des zéros, qui doivent être ignorés.
        let mut frame = trame_arp(
            ArpOperation::REPLY,
            (MAC_PI, [192, 168, 50, 1]),
            (MAC_ESP, [192, 168, 50, 182]),
        );
        assert_eq!(frame.len(), 42);
        frame.resize(60, 0);
        assert_eq!(expect_arp(&frame).sender_ip, Ipv4Addr::new(192, 168, 50, 1));
    }

    #[test]
    fn code_arp_inconnu_est_conserve() {
        let frame = trame_arp(
            ArpOperation(8), // InARP request (RFC 2390)
            (MAC_PI, [192, 168, 50, 1]),
            (MAC_ESP, [192, 168, 50, 182]),
        );
        assert_eq!(expect_arp(&frame).operation, ArpOp::Other(8));
    }

    #[test]
    fn syn_tcp_est_delegue_a_rnifler() {
        let builder = PacketBuilder::ethernet2(MAC_ESP, MAC_PI)
            .ipv4([192, 168, 50, 50], [192, 168, 50, 1], 64)
            .tcp(51234, 22, 1000, 65535)
            .syn();
        let mut frame = Vec::new();
        builder.write(&mut frame, &[]).unwrap();
        let decoded = decode(&frame).unwrap();
        match decoded.content {
            Content::Tcp(seg) => {
                assert!(seg.flags.syn && !seg.flags.ack);
                assert_eq!(seg.dst_port, 22);
            }
            other => panic!("segment TCP attendu, obtenu : {other:?}"),
        }
        assert_eq!(
            decoded.ipv4_sender,
            Some(Ipv4Sender {
                mac: MacAddr(MAC_ESP),
                ip: Ipv4Addr::new(192, 168, 50, 50)
            })
        );
    }

    #[test]
    fn udp_est_ignore() {
        let builder = PacketBuilder::ethernet2(MAC_ESP, MAC_PI)
            .ipv4([192, 168, 50, 182], [192, 168, 50, 1], 64)
            .udp(5353, 5353);
        let mut frame = Vec::new();
        builder.write(&mut frame, b"x").unwrap();
        let decoded = decode(&frame).unwrap();
        assert!(matches!(decoded.content, Content::Other));
        // L'émetteur IPv4 est connu même si le contenu n'intéresse aucune règle.
        assert_eq!(
            decoded.ipv4_sender.map(|s| s.ip),
            Some(Ipv4Addr::new(192, 168, 50, 182))
        );
    }

    #[test]
    fn trame_tronquee_est_une_erreur() {
        let frame = trame_arp(
            ArpOperation::REPLY,
            (MAC_PI, [192, 168, 50, 1]),
            (MAC_ESP, [192, 168, 50, 182]),
        );
        // En-tête Ethernet (14) + 10 octets d'ARP sur 28.
        assert!(decode(&frame[..24]).is_err());
    }

    #[test]
    fn affichage_d_une_mac() {
        assert_eq!(MacAddr(MAC_PI).to_string(), "dc:a6:32:01:02:03");
    }

    #[test]
    fn lecture_d_une_mac() {
        assert_eq!("dc:a6:32:01:02:03".parse(), Ok(MacAddr(MAC_PI)));
        // Majuscules acceptées ; l'affichage reste en minuscules.
        let mac: MacAddr = "DC:A6:32:01:02:03".parse().unwrap();
        assert_eq!(mac.to_string(), "dc:a6:32:01:02:03");
    }

    #[test]
    fn mac_mal_formee_refusee() {
        for texte in [
            "",
            "dc:a6:32:01:02",       // 5 octets
            "dc:a6:32:01:02:03:04", // 7 octets
            "dc-a6-32-01-02-03",    // mauvais séparateur
            "dc:a6:32:01:02:3",     // un seul chiffre
            "dc:a6:32:01:02:+3",    // signe accepté par from_str_radix
            "gg:a6:32:01:02:03",    // pas hexadécimal
        ] {
            assert!(
                texte.parse::<MacAddr>().is_err(),
                "accepté à tort : {texte:?}"
            );
        }
    }
}
