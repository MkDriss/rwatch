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

## `attaque-mqtt-impersonation.pcap`

Capture RÉELLE de la phase MQTT de la même attaque (trafic du port 1883),
menée sur le labo le 18 novembre 2026. Déroulé (visible avec
`rwatch -C attaque-mqtt-impersonation.toml -r attaque-mqtt-impersonation.pcap -v`) :
- l'actionneur légitime (`192.168.60.124`) se connecte au broker avec son
  Client ID codé en dur `actionneur1` ;
- 2 ms plus tard, le proxy de l'attaquant (`192.168.60.104`) se connecte avec
  le MÊME `actionneur1` : le Client ID a été volé par rétro-ingénierie du
  firmware ;
- l'attaquant ouvre par ailleurs plusieurs connexions à Client ID vide, que
  MQTT-001 ignore (un Client ID vide n'identifie personne).

Rejouée avec `attaque-mqtt-impersonation.toml` (MQTT-001, `learn = false`,
`actionneur1` de confiance), elle doit produire EXACTEMENT une alerte
(`../expected/attaque/attaque-mqtt-impersonation.jsonl`) : l'usurpation de
`actionneur1` par l'attaquant. Les connexions à Client ID vide ne produisent
aucune alerte.

## `attaque-mqtt-impersonation.toml`

La configuration pour rejouer la capture MQTT : ARP-001 désactivée, MQTT-001
sans apprentissage, `actionneur1` déclaré de confiance.
