//! Couche ÉMISSION : porte les alertes de la boucle de capture vers leurs
//! destinations (stdout aujourd'hui, HTTP ensuite) SANS jamais bloquer la
//! capture.
//!
//! # Pourquoi un fil séparé
//!
//! Écrire sur stdout est quasi instantané, mais une future destination HTTP
//! peut attendre longtemps (dashboard lent, injoignable). Si la boucle de
//! capture émettait directement, un POST bloquant ferait s'accumuler puis
//! perdre les paquets : l'IDS serait aveuglé par un simple souci réseau.
//!
//! La boucle de capture DÉPOSE donc chaque alerte dans une file bornée et
//! continue aussitôt ; un fil dédié la vide à son rythme, et peut attendre.
//!
//! ```text
//! [capture] --alerte--> (file bornée, mpsc) --> [fil d'émission] --> destinations
//!   (ne bloque jamais)                            (a le droit d'attendre)
//! ```
//!
//! # File pleine
//!
//! La file est bornée : un consommateur mort ne doit pas faire exploser la
//! mémoire (ce serait un déni de service). Quand elle est pleine, on JETTE
//! l'alerte et on COMPTE la perte, plutôt que de bloquer la capture. Perdre
//! une alerte est moins grave qu'aveugler l'IDS. Les pertes sont signalées.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;

use crate::alert::Alert;

/// Une destination d'alertes. `emit` peut échouer (HTTP) ou attendre ; c'est
/// pour cela qu'elle vit dans le fil d'émission, jamais dans la capture.
pub trait Sink: Send {
    /// Nom lisible, pour les messages de démarrage.
    fn name(&self) -> String;
    /// Émet une alerte. Une erreur est signalée mais n'arrête pas le fil :
    /// une destination en panne ne doit pas empêcher les autres d'émettre.
    fn emit(&mut self, alert: &Alert) -> std::io::Result<()>;
}

/// Capacité par défaut de la file : assez pour absorber une rafale, assez
/// petit pour borner la mémoire. Réglable plus tard si besoin.
const DEFAULT_CAPACITY: usize = 4096;

/// Poignée côté capture : on y dépose les alertes, sans jamais bloquer.
pub struct Emitter {
    tx: SyncSender<Alert>,
    /// Nombre d'alertes jetées parce que la file était pleine.
    dropped: u64,
}

impl Emitter {
    /// Démarre le fil d'émission avec ces destinations, et renvoie la poignée
    /// de dépôt et le handle du fil (pour l'arrêt propre).
    pub fn start(sinks: Vec<Box<dyn Sink>>) -> (Emitter, JoinHandle<u64>) {
        Self::with_capacity(sinks, DEFAULT_CAPACITY)
    }

    pub fn with_capacity(sinks: Vec<Box<dyn Sink>>, capacity: usize) -> (Emitter, JoinHandle<u64>) {
        // `sync_channel(capacity)` : file BORNÉE. `try_send` échoue plutôt que
        // d'attendre quand elle est pleine, ce qui protège la capture.
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        let handle = std::thread::spawn(move || drain(rx, sinks));
        (Emitter { tx, dropped: 0 }, handle)
    }

    /// Dépose une alerte dans la file. Ne bloque JAMAIS : si la file est
    /// pleine, l'alerte est jetée et comptée.
    pub fn send(&mut self, alert: Alert) {
        match self.tx.try_send(alert) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.dropped += 1,
            // Le fil d'émission s'est arrêté : plus personne pour recevoir.
            Err(TrySendError::Disconnected(_)) => self.dropped += 1,
        }
    }

    /// Nombre d'alertes jetées (file pleine) depuis le démarrage.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Le fil d'émission : consomme la file jusqu'à sa fermeture, puis rend le
/// nombre total d'alertes émises. Fermer le dernier `SyncSender` (en libérant
/// l'`Emitter`) termine la boucle : c'est le signal d'arrêt propre.
fn drain(rx: Receiver<Alert>, mut sinks: Vec<Box<dyn Sink>>) -> u64 {
    let mut emitted = 0;
    // `recv()` rend `Err` quand tous les émetteurs sont libérés : on a alors
    // vidé la file, on peut sortir.
    for alert in rx.iter() {
        for sink in &mut sinks {
            if let Err(e) = sink.emit(&alert) {
                eprintln!("[!] émission ({}) : {e}", sink.name());
            }
        }
        emitted += 1;
    }
    emitted
}

// ===========================================================================
// Destinations
// ===========================================================================

/// Écrit chaque alerte en JSON sur un flux (stdout en production), une par
/// ligne (JSON Lines).
pub struct JsonLines<W: std::io::Write + Send> {
    writer: W,
    label: String,
}

impl<W: std::io::Write + Send> JsonLines<W> {
    pub fn new(writer: W, label: impl Into<String>) -> Self {
        JsonLines {
            writer,
            label: label.into(),
        }
    }
}

impl<W: std::io::Write + Send> Sink for JsonLines<W> {
    fn name(&self) -> String {
        self.label.clone()
    }

    fn emit(&mut self, alert: &Alert) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, alert)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Severity, Timestamp};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Destination de test : accumule les alertes reçues en mémoire.
    #[derive(Clone)]
    struct Memory(Arc<Mutex<Vec<Alert>>>);

    impl Sink for Memory {
        fn name(&self) -> String {
            "mémoire".to_string()
        }
        fn emit(&mut self, alert: &Alert) -> std::io::Result<()> {
            self.0.lock().unwrap().push(alert.clone());
            Ok(())
        }
    }

    fn alerte(n: u64) -> Alert {
        Alert {
            timestamp: Timestamp(Duration::from_secs(n)),
            kind: "test",
            severity: Severity::Low,
            source_ip: None,
            source_mac: None,
            target: None,
            details: format!("alerte {n}"),
            rule_id: "TEST",
        }
    }

    #[test]
    fn les_alertes_deposees_sont_toutes_emises() {
        let recu = Arc::new(Mutex::new(Vec::new()));
        let (mut emitter, handle) = Emitter::start(vec![Box::new(Memory(recu.clone()))]);
        for n in 0..100 {
            emitter.send(alerte(n));
        }
        // Libérer l'emitter ferme le canal : le fil vide la file puis s'arrête.
        drop(emitter);
        let emises = handle.join().unwrap();
        assert_eq!(emises, 100);
        assert_eq!(recu.lock().unwrap().len(), 100);
    }

    #[test]
    fn plusieurs_destinations_recoivent_chaque_alerte() {
        let a = Arc::new(Mutex::new(Vec::new()));
        let b = Arc::new(Mutex::new(Vec::new()));
        let (mut emitter, handle) = Emitter::start(vec![
            Box::new(Memory(a.clone())),
            Box::new(Memory(b.clone())),
        ]);
        emitter.send(alerte(1));
        drop(emitter);
        handle.join().unwrap();
        assert_eq!(a.lock().unwrap().len(), 1);
        assert_eq!(b.lock().unwrap().len(), 1);
    }

    /// Destination qui bloque jusqu'à ce qu'on la débloque : simule un
    /// consommateur lent pour remplir la file.
    struct Blocking(Arc<Mutex<bool>>, Arc<std::sync::Condvar>);
    impl Sink for Blocking {
        fn name(&self) -> String {
            "bloquante".to_string()
        }
        fn emit(&mut self, _alert: &Alert) -> std::io::Result<()> {
            let (lock, cvar) = (&*self.0, &*self.1);
            let mut go = lock.lock().unwrap();
            while !*go {
                go = cvar.wait(go).unwrap();
            }
            Ok(())
        }
    }

    #[test]
    fn une_file_pleine_jette_et_compte_sans_bloquer() {
        let go = Arc::new(Mutex::new(false));
        let cvar = Arc::new(std::sync::Condvar::new());
        // File minuscule + destination bloquée : la file se remplit vite.
        let (mut emitter, handle) =
            Emitter::with_capacity(vec![Box::new(Blocking(go.clone(), cvar.clone()))], 2);

        // On dépose bien plus que la capacité. Ça ne doit JAMAIS bloquer.
        for n in 0..1000 {
            emitter.send(alerte(n));
        }
        // La plupart ont été jetées (file pleine), et comptées.
        assert!(emitter.dropped() > 0, "des alertes auraient dû être jetées");
        assert!(emitter.dropped() < 1000, "tout n'aurait pas dû être jeté");

        // On débloque la destination et on ferme : le fil se termine.
        *go.lock().unwrap() = true;
        cvar.notify_all();
        drop(emitter);
        handle.join().unwrap();
    }
}
