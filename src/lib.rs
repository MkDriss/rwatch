//! Bibliothèque `rwatch` : moteur de détection d'intrusion réseau.
//!
//! Le package contient deux crates :
//! - ce crate bibliothèque (`src/lib.rs`), qui porte toute la logique ;
//! - le crate binaire (`src/main.rs`), une simple interface en ligne de commande.
//!
//! La capture brute, le parsing TCP/IP et le décodage MQTT viennent de la
//! bibliothèque `rnifler` ; rwatch y ajoute ce qui est propre à la détection.
//!
//! Modules, de la trame à l'alerte :
//! - [`capture`] : boucle de lecture des trames (interface ou fichier `.pcap`) ;
//! - [`decode`] : classe chaque trame (ARP, segment TCP, autre) ;
//! - [`detect`] : moteur et règles de détection ;
//! - [`alert`] : l'alerte émise, conforme au contrat JSON.

pub mod alert;
pub mod capture;
pub mod decode;
pub mod detect;
