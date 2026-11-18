# Captures de test

Ce dossier contient des fichiers `.pcap` rejoués par la suite de tests, et la
configuration associée.

## `attaque-arp-mitm.pcap`

Capture RÉELLE d'une attaque de l'homme du milieu par empoisonnement ARP,
menée sur le laboratoire isolé `sec-lab-iot` le 18 novembre 2026, avec les
outils du projet (`scapy` pour l'empoisonnement, un proxy MQTT pour
l'altération). La capture a été réalisée sur le point d'accès du labo
(`rnifler -i wlan0 --promisc`), puis réduite à ses 30 premières trames ARP.

Déroulé (visible avec `tcpdump -r attaque-arp-mitm.pcap -n`) :
- l'attaquant (`192.168.60.104`) résout les MAC de la passerelle
  (`192.168.60.1`) et de l'actionneur (`192.168.60.124`) ;
- puis il émet, toutes les 2 s, une paire de réponses ARP forgées revendiquant
  ces deux adresses avec sa propre MAC (`ba:d9:21:a5:01:02`).

Toutes les adresses appartiennent au labo isolé ; aucune donnée personnelle.

Rejouée dans rwatch avec `attaque-arp-mitm.toml`, elle doit produire EXACTEMENT
les deux alertes de `../expected/attaque-arp-mitm.jsonl` : une par adresse
usurpée. Les ~15 paires de trames forgées ne donnent que 2 alertes, ce qui
vérifie la période anti-rafale d'ARP-001 (`alert_cooldown_secs`).

## `attaque-arp-mitm.toml`

La configuration utilisée pour rejouer la capture ci-dessus : les associations
de confiance de la passerelle et de l'actionneur. Voir les commentaires du
fichier.
