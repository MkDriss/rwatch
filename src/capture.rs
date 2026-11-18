//! Couche CAPTURE : lit les trames d'une capture libpcap, interface ou fichier.
//!
//! L'ouverture de la capture est déléguée à `rnifler::capture` (`open_live`,
//! `open_offline`). Ce module ajoute la boucle de lecture commune aux deux
//! sources : il livre chaque trame à l'appelant avec son horodatage de
//! capture, sans rien savoir de ce que l'appelant en fait.

use std::fmt;
use std::time::Duration;

use pcap::{Activated, Capture, Linktype};

/// Ce qui peut empêcher la lecture d'une capture.
#[derive(Debug)]
pub enum CaptureError {
    /// Erreur remontée par libpcap (interface absente, droits, fichier...).
    Pcap(pcap::Error),
    /// Le décodage suppose des trames Ethernet ; cette capture fournit un
    /// autre type de lien (par exemple Linux SLL sur l'interface `any`).
    UnsupportedLinktype(Linktype),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Pcap(e) => write!(f, "capture : {e}"),
            CaptureError::UnsupportedLinktype(lt) => write!(
                f,
                "type de lien {lt:?} non supporté (Ethernet attendu) : \
                 choisis une interface précise plutôt que `any`"
            ),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Permet à `?` de convertir une `pcap::Error` en `CaptureError`.
impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> Self {
        CaptureError::Pcap(e)
    }
}

/// Lit les trames de `cap` et appelle `on_frame(horodatage, octets)` pour
/// chacune. S'arrête à la fin du fichier, après `limit` trames (`0` = sans
/// limite), ou à la première erreur renvoyée par `on_frame`.
///
/// Renvoie le nombre de trames lues.
///
/// - `T: Activated + ?Sized` : accepte `Capture<Active>` (interface) comme
///   `Capture<Offline>` (fichier), avec un seul code ;
/// - `E` : le type d'erreur de l'APPELANT. `E: From<CaptureError>` garantit
///   qu'une erreur de capture peut s'y convertir : la boucle n'impose pas
///   son propre type d'erreur au reste du programme.
pub fn for_each_frame<T, F, E>(mut cap: Capture<T>, limit: u64, mut on_frame: F) -> Result<u64, E>
where
    T: Activated + ?Sized,
    F: FnMut(Duration, &[u8]) -> Result<(), E>,
    E: From<CaptureError>,
{
    let linktype = cap.get_datalink();
    if linktype != Linktype::ETHERNET {
        return Err(CaptureError::UnsupportedLinktype(linktype).into());
    }

    let mut seen: u64 = 0;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                seen += 1;
                let ts = rnifler::capture::timestamp(packet.header);
                on_frame(ts, packet.data)?;
                if limit != 0 && seen >= limit {
                    break;
                }
            }
            // Pas de trame pendant le délai d'attente (capture live) : on continue.
            Err(pcap::Error::TimeoutExpired) => continue,
            // Fin du fichier de capture.
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(CaptureError::from(e).into()),
        }
    }
    Ok(seen)
}