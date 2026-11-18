# rwatch

![Tests](https://github.com/MkDriss/rwatch/actions/workflows/test.yaml/badge.svg)

**rwatch** est un système de détection d'intrusion réseau (IDS) écrit en Rust. Il
lit le trafic d'une interface réseau ou d'un fichier de capture `.pcap`, l'analyse
avec des règles de détection, et émet chaque alerte en JSON, une par ligne, pour
qu'un autre programme (tableau de bord, gestionnaire d'identités…) puisse la
consommer.

> **Statut : en développement.** La capture, le moteur de règles, le contrat
> d'alerte et une première règle (empoisonnement ARP) sont fonctionnels et
> testés, et se règlent par un fichier de configuration. Les autres règles et
> l'émission HTTP sont en cours (voir la [feuille de route](#feuille-de-route)).

rwatch est le troisième outil d'une trilogie Rust, avec
[rmap](https://github.com/MkDriss/rmap) (scanner de ports) et
[rnifler](https://github.com/MkDriss/rnifler) (sniffer MQTT défensif), dont il
réutilise la bibliothèque. Il a été conçu pour le labo de cybersécurité IoT
`sec-lab-iot`, mais reste un outil générique : rien de propre au labo n'est codé
en dur.

## Exemple

Rejeu d'une attaque de l'homme du milieu par empoisonnement ARP :

```console
$ rwatch --read captures/arp-spoofing.pcap 2>/dev/null | jq .
{
  "timestamp": "2026-01-01T00:00:10Z",
  "type": "arp_spoofing",
  "severity": "high",
  "source_ip": "192.168.50.50",
  "source_mac": "aa:bb:cc:dd:ee:ff",
  "target": "192.168.50.1",
  "details": "Réponse ARP non sollicitée : 192.168.50.1 revendiqué par aa:bb:cc:dd:ee:ff, alors que l'association apprise indique dc:a6:32:00:00:01",
  "rule_id": "ARP-001"
}
{
  "timestamp": "2026-01-01T00:00:10Z",
  "type": "arp_spoofing",
  "severity": "high",
  "source_ip": "192.168.50.50",
  "source_mac": "aa:bb:cc:dd:ee:ff",
  "target": "192.168.50.182",
  "details": "Réponse ARP non sollicitée : 192.168.50.182 revendiqué par aa:bb:cc:dd:ee:ff, alors que l'association apprise indique 24:6f:28:00:00:b6",
  "rule_id": "ARP-001"
}
```

L'attaquant se fait passer pour la passerelle auprès de la victime, et pour la
victime auprès de la passerelle. rwatch lève une alerte par adresse usurpée et
désigne l'attaquant, retrouvé grâce à sa MAC, sans jamais accuser la victime.

## Fonctionnalités

- **Capture** depuis une interface réseau, ou **rejeu** d'un fichier `.pcap`
  avec exactement la même logique.
- **Moteur de règles extensible** : chaque règle est un type indépendant qui
  implémente un trait commun ; en ajouter une ne modifie pas le moteur.
- **Règle ARP-001** : détection de l'usurpation d'adresse par empoisonnement de
  cache ARP (MITRE ATT&CK T1557.002).
- **Alertes JSON** conformes à un contrat stable, au format JSON Lines sur la
  sortie standard. Les messages destinés aux humains passent sur la sortie
  d'erreur : la sortie standard ne contient que des alertes.
- **Détection déterministe** : les règles ne lisent jamais l'horloge système,
  seulement l'horodatage de capture des paquets. Une capture rejouée donne
  toujours exactement les mêmes alertes.
- **Configuration par fichiers TOML** (un fichier par règle, listés
  explicitement), validée au démarrage : une clé inconnue, une valeur
  incohérente ou un fichier manquant arrête rwatch avec un message qui indique
  le fichier et la ligne en cause, avant toute écoute.
- **Mémoire bornée** : un attaquant ne peut pas saturer rwatch en inondant le
  réseau d'adresses différentes.

## Architecture

```
[interface réseau] ---\
                       (capture) --> (decode) --> (moteur de règles) --> (alerte JSON) --> stdout
[fichier .pcap] ------/                              |-- (ARP-001)
                                                     '-- (règles à venir)
```

| Module | Rôle |
|---|---|
| `capture` | Boucle de lecture commune à l'interface et au fichier ; ouverture déléguée à `rnifler::capture` |
| `decode` | Classe chaque trame (ARP, segment TCP, autre) et extrait l'émetteur IPv4 ; TCP délégué à `rnifler::parser` |
| `detect` | Le trait `Rule`, le moteur `Engine`, et les règles (`arp_spoof`) |
| `alert` | La struct `Alert`, traduction Rust du contrat JSON |
| `config` | Lecture, fusion et validation des fichiers de configuration TOML |

Le paquet contient une bibliothèque (`src/lib.rs`, toute la logique) et un
binaire (`src/main.rs`, l'interface en ligne de commande). La capture libpcap, le
parsing TCP/IP et le décodage MQTT proviennent de la bibliothèque
[rnifler](https://github.com/MkDriss/rnifler), utilisée comme dépendance Git
épinglée sur une version publiée.

## Installation

### Prérequis

- Rust 1.88 ou plus récent ;
- libpcap et ses en-têtes : `libpcap-dev` (Debian, Ubuntu, Raspberry Pi OS) ou
  `libpcap-devel` (Fedora).

### Compilation

```console
$ git clone https://github.com/MkDriss/rwatch.git
$ cd rwatch
$ cargo build --release
```

Le binaire est produit dans `target/release/rwatch`. Les releases publiées
fournissent des binaires précompilés pour x86_64 et arm64 (Raspberry Pi 64 bits).

## Utilisation

```console
$ rwatch --read capture.pcap          # rejoue un fichier de capture
$ rwatch --interface wlan0            # écoute une interface en direct
$ rwatch -C rwatch.toml -i wlan0      # avec un fichier de configuration
$ rwatch -i wlan0 | jq .              # alertes lisibles
$ rwatch -i wlan0 >> alertes.jsonl    # alertes archivées, une par ligne
```

| Option | Rôle |
|---|---|
| `-i, --interface <INTERFACE>` | Interface à écouter (ex. `wlan0`) |
| `-r, --read <FICHIER>` | Lit un fichier `.pcap` au lieu d'une interface |
| `-C, --config <FICHIER>` | Fichier de configuration TOML (sans lui : valeurs par défaut) |
| `-f, --filter <FILTRE>` | Filtre BPF, syntaxe tcpdump, prioritaire sur la configuration (défaut : `arp or ip or ip6`) |
| `-c, --count <N>` | S'arrête après N trames (défaut : 0, illimité) |
| `-v, --verbose` | Affiche aussi chaque trame ARP et chaque SYN TCP, sur stderr |

### Mode promiscuité

En capture live, rwatch active par défaut le mode promiscuité : l'interface
lui remonte aussi les trames échangées entre d'autres machines. C'est
indispensable sur un point d'accès WiFi : sans ce mode, le trafic direct entre
deux stations (un attaquant et sa victime) est invisible, comme l'a montré la
validation sur le labo (voir [`docs/LIMITES.md`](docs/LIMITES.md)). Pour le
désactiver : `promiscuous = false` dans la section `[capture]`.

### Privilèges

Lire un fichier ne demande aucun privilège. Écouter une interface en demande :
plutôt que de lancer rwatch avec `sudo`, accordez au binaire la seule capacité
nécessaire, selon le principe du moindre privilège :

```console
$ sudo setcap cap_net_raw=eip target/release/rwatch
```

Sur un Raspberry Pi 4 (Raspberry Pi OS 64 bits), cette seule capacité suffit,
y compris en mode promiscuité. Elle est perdue à chaque recompilation ou
réinstallation du binaire, et tout utilisateur qui peut l'exécuter peut alors
écouter le réseau : restreignez son exécution à un groupe dédié.

## Configuration

La configuration tient dans un fichier principal, et la configuration de
chaque règle peut vivre dans son propre fichier, **listé explicitement** :

```
/etc/rwatch/
├── rwatch.toml              # réglages globaux + liste des fichiers de règles
└── rules/
    └── arp_spoofing.toml    # réglages de la règle ARP-001
```

```toml
# rwatch.toml
[rules]
files = ["rules/arp_spoofing.toml"]
```

```toml
# rules/arp_spoofing.toml
[rules.arp_spoofing]
binding_ttl_secs = 600

[rules.arp_spoofing.trusted]
"192.0.2.1" = "00:00:5e:00:53:01"
```

L'exemple complet et commenté se trouve dans [`config/exemple/`](config/exemple/).
Toutes les clés sont facultatives. Les règles de chargement, toutes vérifiées
au démarrage :

- les chemins relatifs partent du dossier du fichier principal ;
- un fichier listé mais absent arrête rwatch : une configuration (et ses
  associations de confiance) ne peut pas disparaître en silence ;
- une même règle ne peut être configurée que dans un seul fichier ; un doublon
  est signalé avec les deux fichiers en cause ;
- un fichier de règle ne contient que des sections `[rules.*]`, et ne peut pas
  en inclure d'autres ;
- toutes les règles sont validées, y compris les règles désactivées : une
  configuration invalide n'attend pas la réactivation d'une règle pour être
  découverte.

Au démarrage, rwatch affiche l'état de chaque règle et l'origine de sa
configuration :

```console
[*] Configuration : /etc/rwatch/rwatch.toml
[*] ARP-001 : active (/etc/rwatch/rules/arp_spoofing.toml)
```

Pour désactiver une règle, écrivez `enabled = false` dans son fichier. Retirer
le fichier de la liste ne la désactive pas : la règle tourne alors avec ses
valeurs par défaut, sans ses associations de confiance, ce que le résumé de
démarrage rend visible (`ARP-001 : active (valeurs par défaut)`).

Une faute de frappe n'est jamais ignorée en silence :

```console
$ rwatch -C rwatch.toml -i wlan0
[!] configuration rwatch.toml invalide :
TOML parse error at line 3, column 1
  |
3 | binding_tll_secs = 600
  | ^^^^^^^^^^^^^^^^
unknown field `binding_tll_secs`, expected one of `enabled`, `severity`, `binding_ttl_secs`, ...
```

Priorité des réglages : la ligne de commande, puis le fichier, puis les valeurs
par défaut.

## Règles de détection

### ARP-001 : usurpation par empoisonnement ARP

Chaque message ARP, requête ou réponse, revendique une association « IP de
l'émetteur → MAC de l'émetteur ». rwatch apprend ces associations et lève une
alerte quand une IP connue est revendiquée par une autre MAC alors que la MAC
connue est toujours active (vue, en ARP ou en IPv4, depuis moins de
`binding_ttl`), ou quand une association de confiance est contredite.

- Une revendication contradictoire ne remplace jamais l'association connue :
  l'attaquant ne peut pas s'installer en répétant ses réponses.
- Une seule alerte par période pour un même couple (IP, MAC usurpatrice).
- Les sondes ARP (émetteur `0.0.0.0`, RFC 5227) sont ignorées : elles ne
  revendiquent aucune adresse.
- Si l'IP de l'attaquant est inconnue, `source_ip` vaut `null` : mieux vaut ne
  désigner personne que désigner la victime.

Les limites connues de la règle, et la méthode pour régler `binding_ttl`, sont
décrites dans [`docs/LIMITES.md`](docs/LIMITES.md).

## Contrat d'alerte

Chaque alerte est un objet JSON sur une ligne :

| Champ | Présence | Contenu |
|---|---|---|
| `timestamp` | toujours | Horodatage de capture du paquet en cause, RFC 3339, UTC, à la seconde |
| `type` | toujours | Type d'attaque (ex. `arp_spoofing`) |
| `severity` | toujours | `low`, `medium`, `high` ou `critical` |
| `source_ip` | toujours, peut valoir `null` | IP de l'objet fautif ; `null` si elle est inconnue |
| `source_mac` | si connue | MAC de l'objet fautif |
| `target` | si connue | Ce qui est visé (adresse usurpée, service…) |
| `details` | toujours | Description lisible ; à traiter comme du texte, jamais comme du HTML |
| `rule_id` | toujours | Identifiant de la règle (ex. `ARP-001`) |

`source_ip` et `source_mac` permettent à un consommateur d'identifier l'objet
fautif, par exemple pour révoquer son identité.

## Tests

```console
$ cargo test
```

Les tests de rejeu (`tests/replay.rs`) écrivent chaque scénario d'attaque ou de
trafic normal dans un vrai fichier pcap, le font rejouer **par le binaire**, et
comparent chaque alerte produite à un résultat attendu (`tests/expected/`). La
comparaison est structurelle : en cas d'écart, le test affiche la première
alerte qui diffère.

Les scénarios sont construits en code (`tests/common/mod.rs`), ce qui les rend
lisibles et reproductibles octet pour octet. Pour les écrire sur le disque et les
rejouer à la main :

```console
$ cargo run --example scenarios -- captures
$ cargo run -- --read captures/arp-spoofing.pcap
```

Pour régler `binding_ttl_secs` sur le trafic réel d'un réseau, l'exemple
`silences` mesure le plus long silence de chaque machine dans une capture :

```console
$ cargo run --example silences -- trafic-normal.pcap
```

Après une modification **voulue** du comportement, les résultats attendus se
régénèrent avec `RWATCH_BLESS=1 cargo test --test replay`, puis se relisent
(`git diff tests/expected/`) avant d'être committés.

Un test distinct, `tests/attaque_reelle.rs`, rejoue une CAPTURE RÉELLE : un
empoisonnement ARP mené sur le laboratoire du projet (voir
[`tests/captures/README.md`](tests/captures/README.md)). rwatch doit en tirer
exactement les deux alertes attendues, et seulement deux malgré la rafale de
trames forgées (vérification de la période anti-rafale).

## Feuille de route

- [x] Capture : interface réseau et rejeu de fichiers `.pcap`
- [x] Contrat d'alerte JSON et moteur de règles
- [x] ARP-001 : empoisonnement ARP, avec tests de rejeu
- [x] Configuration par fichier (associations de confiance, seuils, gravités)
- [ ] Émission des alertes vers un endpoint HTTP configurable
- [x] Validation en conditions réelles sur le labo (attaque ARP détectée, test de non-régression)
- [ ] SCAN-001 : détection de scan de ports
- [ ] Règles MQTT : usurpation de Client ID, débit de publication anormal
- [ ] Déploiement sur Raspberry Pi (service systemd, privilèges minimaux)
- [ ] Détection d'anomalies par apprentissage d'une référence (baseline)

## Usage responsable

rwatch est un outil défensif. Il ne doit être utilisé que sur des réseaux dont
vous êtes propriétaire ou que vous êtes autorisé à surveiller : les captures
réseau peuvent contenir des données personnelles et des identifiants.

## Références

- RFC 826, *An Ethernet Address Resolution Protocol*.
- RFC 5227, *IPv4 Address Conflict Detection*.
- MITRE ATT&CK, T1557.002 *ARP Cache Poisoning*, et stratégie de détection
  DET0387.
- T. Ptacek, T. Newsham, *Insertion, Evasion, and Denial of Service: Eluding
  Network Intrusion Detection*, 1998.
- NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*.
- capabilities(7), page de manuel Linux.

## Licence

Double licence MIT ou Apache-2.0, au choix, comme rnifler. Voir le fichier
`LICENSE`.
