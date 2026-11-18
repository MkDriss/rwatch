//! Mesure des silences : pour régler `binding_ttl_secs` d'ARP-001 sur des
//! données, pas sur une intuition.
//!
//! Pour chaque machine du réseau local, on mesure le plus long intervalle
//! entre deux trames qui prouvent qu'elle est active. Le TTL d'ARP-001 doit
//! être confortablement supérieur au plus long silence de la machine la plus
//! discrète : sinon, une machine légitime pourrait « expirer » et la règle
//! accepterait sans alerte qu'une autre MAC prenne son IP.
//!
//! La mesure compte EXACTEMENT ce que compte ARP-001 :
//! - une revendication ARP (émetteur différent de 0.0.0.0) fait connaître la
//!   machine et compte comme une preuve d'activité ;
//! - une trame IPv4 compte seulement si son couple (IP source, MAC source) a
//!   déjà été revendiqué en ARP ; elle n'apprend jamais rien (un paquet venu
//!   d'Internet porte la MAC du routeur, pas celle de son émetteur).
//!
//! Mesurer autre chose que ce qu'utilise la règle donnerait un TTL faux.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::decode::{Content, Frame, MacAddr};

/// L'activité observée d'une machine (un couple IP, MAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    /// Nombre de trames prises en compte.
    pub frames: u64,
    /// Première et dernière trame prises en compte.
    pub first: Duration,
    pub last: Duration,
    /// Plus long intervalle entre deux trames consécutives (zéro s'il n'y a
    /// eu qu'une trame).
    pub longest_silence: Duration,
}

/// Accumule l'activité de chaque machine au fil des trames.
#[derive(Debug, Default)]
pub struct SilenceTracker {
    /// Couples revendiqués en ARP : les seuls dont le trafic IPv4 compte.
    learned: BTreeSet<(Ipv4Addr, MacAddr)>,
    /// Activité par couple, dans l'ordre des IP (sortie déterministe).
    activity: BTreeMap<(Ipv4Addr, MacAddr), Activity>,
    /// Horodatage de la dernière trame lue, pour le « silence final ».
    end: Option<Duration>,
}

impl SilenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Prend en compte une trame capturée à l'instant `ts`.
    pub fn on_frame(&mut self, ts: Duration, frame: &Frame<'_>) {
        self.end = Some(self.end.map_or(ts, |end| end.max(ts)));
        if let Content::Arp(arp) = &frame.content
            && !arp.sender_ip.is_unspecified()
        {
            let pair = (arp.sender_ip, arp.sender_mac);
            self.learned.insert(pair);
            self.record(pair, ts);
        }
        if let Some(sender) = frame.ipv4_sender {
            let pair = (sender.ip, sender.mac);
            if self.learned.contains(&pair) {
                self.record(pair, ts);
            }
        }
    }

    fn record(&mut self, pair: (Ipv4Addr, MacAddr), ts: Duration) {
        self.activity
            .entry(pair)
            .and_modify(|a| {
                a.longest_silence = a.longest_silence.max(ts.saturating_sub(a.last));
                a.last = ts;
                a.frames += 1;
            })
            .or_insert(Activity {
                frames: 1,
                first: ts,
                last: ts,
                longest_silence: Duration::ZERO,
            });
    }

    /// L'activité de chaque machine, dans l'ordre des IP.
    pub fn report(&self) -> impl Iterator<Item = (&(Ipv4Addr, MacAddr), &Activity)> {
        self.activity.iter()
    }

    /// Silence entre la dernière trame d'une machine et la fin de la capture.
    /// Il n'est PAS compté dans `longest_silence` : on ne sait pas combien de
    /// temps il aurait encore duré. Mais un silence final très long signale
    /// une machine partie, ou une capture trop courte.
    pub fn final_silence(&self, activity: &Activity) -> Duration {
        self.end
            .map_or(Duration::ZERO, |end| end.saturating_sub(activity.last))
    }

    /// Le plus long silence, toutes machines confondues.
    pub fn longest_silence(&self) -> Duration {
        self.activity
            .values()
            .map(|a| a.longest_silence)
            .max()
            .unwrap_or(Duration::ZERO)
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Arp, ArpOp, Ipv4Sender};

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 60, 105);
    const MAC: MacAddr = MacAddr([0x70, 0x4b, 0xca, 0x03, 0x7d, 0x74]);
    const AUTRE_MAC: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn annonce(ip: Ipv4Addr, mac: MacAddr) -> Frame<'static> {
        Frame {
            ipv4_sender: None,
            content: Content::Arp(Arp {
                operation: ArpOp::Request,
                sender_ip: ip,
                sender_mac: mac,
                target_ip: ip,
                target_mac: MacAddr([0; 6]),
            }),
        }
    }

    fn ipv4(ip: Ipv4Addr, mac: MacAddr) -> Frame<'static> {
        Frame {
            ipv4_sender: Some(Ipv4Sender { mac, ip }),
            content: Content::Other,
        }
    }

    #[test]
    fn le_plus_long_silence_combine_arp_et_ipv4() {
        let mut t = SilenceTracker::new();
        t.on_frame(s(0), &annonce(IP, MAC));
        t.on_frame(s(10), &ipv4(IP, MAC));
        t.on_frame(s(70), &ipv4(IP, MAC)); // 60 s de silence
        t.on_frame(s(100), &annonce(IP, MAC));
        let (_, a) = t.report().next().unwrap();
        assert_eq!(a.frames, 4);
        assert_eq!(a.longest_silence, s(60));
        assert_eq!(t.longest_silence(), s(60));
    }

    #[test]
    fn l_ipv4_avant_tout_arp_ne_compte_pas() {
        // Comme dans ARP-001 : le trafic IP n'apprend jamais une machine.
        let mut t = SilenceTracker::new();
        t.on_frame(s(0), &ipv4(IP, MAC));
        assert_eq!(t.report().count(), 0);
        t.on_frame(s(5), &annonce(IP, MAC));
        assert_eq!(t.report().next().unwrap().1.frames, 1);
    }

    #[test]
    fn l_ipv4_avec_une_autre_mac_ne_compte_pas() {
        // Trafic relayé (IP de la victime, MAC d'un autre) : ne prouve rien.
        let mut t = SilenceTracker::new();
        t.on_frame(s(0), &annonce(IP, MAC));
        t.on_frame(s(10), &ipv4(IP, AUTRE_MAC));
        let (_, a) = t.report().next().unwrap();
        assert_eq!(a.frames, 1);
    }

    #[test]
    fn la_sonde_rfc_5227_n_est_pas_une_machine() {
        let mut t = SilenceTracker::new();
        t.on_frame(s(0), &annonce(Ipv4Addr::UNSPECIFIED, MAC));
        assert_eq!(t.report().count(), 0);
    }

    #[test]
    fn le_silence_final_est_mesure_a_part() {
        let mut t = SilenceTracker::new();
        t.on_frame(s(0), &annonce(IP, MAC));
        t.on_frame(s(30), &annonce(IP, MAC));
        // Une autre machine parle encore à t = 500 : fin de la capture.
        t.on_frame(s(500), &annonce(Ipv4Addr::new(192, 168, 60, 1), AUTRE_MAC));
        // Le rapport suit l'ordre des IP : .1 avant .105, on cherche donc .105.
        let (_, a) = t.report().find(|((ip, _), _)| *ip == IP).unwrap();
        assert_eq!(a.longest_silence, s(30));
        assert_eq!(t.final_silence(a), s(470));
    }
}
