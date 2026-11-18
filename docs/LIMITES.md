# rwatch — limites connues et évolutions prévues

Ce document recense ce que rwatch ne fait pas (encore), ou fait imparfaitement,
et pourquoi. Il est tenu à jour à chaque étape ; il alimentera le
`LAB-STORY.md` et le README. Une limite assumée et documentée vaut mieux
qu'une limite découverte par un utilisateur.

## Limites connues

### Rôle : un IDS passif

rwatch est un système de **détection** : il observe une copie des trames
(libpcap) et émet des alertes. Il ne bloque rien et ne corrige aucun cache ARP
empoisonné ; ce serait le rôle d'un IPS (NIST SP 800-94). C'est un choix de
conception : rwatch émet, ses consommateurs décident (dans le labo, l'IdP
révoque l'identité de l'objet fautif), et un faux positif ne coupe jamais le
réseau.

### Moteur de détection

- **Pas de contexte partagé entre les règles.** Chaque règle possède son propre
  état. Les règles restent indépendantes et testables séparément, mais une
  connaissance utile à plusieurs règles (par exemple la table IP → MAC, qui
  servirait aussi à une corrélation DHCP/ARP) serait dupliquée. Un contexte
  partagé, transmis par le moteur, sera introduit quand le besoin apparaîtra.

### Règle ARP-001 (usurpation par empoisonnement ARP)

- **Silence total de la victime.** Si la victime n'émet plus rien (ni ARP ni
  IPv4) pendant plus de `binding_ttl`, la MAC de l'attaquant est apprise ;
  c'est alors le retour de la victime qui est signalé.
- **Changement de MAC légitime et rapide** (MAC aléatoire renouvelée à la
  reconnexion) : sur le réseau, il est indiscernable d'une usurpation et
  produit un faux positif. Parades : régler `binding_ttl`, déclarer les
  machines critiques (passerelle, broker) en associations de confiance.
- **Trafic pris en compte pour savoir qu'une machine est active** : l'ARP et
  l'IPv4 uniquement (pas l'IPv6), et seulement s'il est capturé (filtre BPF).
- **Identification du fautif** : si la MAC de l'attaquant n'a jamais revendiqué
  sa propre IP, `source_ip` vaut `null` et seule `source_mac` le désigne.

### Contrat d'alerte

- Deux façons d'exprimer « inconnu » coexistent : `null` pour `source_ip`
  (champ obligatoire) et l'absence du champ pour `source_mac` et `target`
  (champs facultatifs). C'est cohérent avec la règle des champs minimum du
  contrat, mais les consommateurs doivent gérer les deux.

### Configuration

- Le fichier est lu une seule fois, au démarrage : toute modification demande
  de relancer rwatch (pas de rechargement à chaud).
- Le fichier contient les associations de confiance : quiconque peut le
  modifier peut désactiver la détection pour une adresse. En production, il
  doit appartenir à root et n'être modifiable que par lui (à mettre en place
  lors du déploiement sur le Pi).

### Décodage

- Les segments TCP sont découpés deux fois (etherparse pour l'émetteur IPv4,
  puis `rnifler::parser`). Le coût est négligeable aux débits d'un réseau IoT ;
  à optimiser si une future version de rnifler expose la MAC source.

## Méthode de réglage du TTL d'ARP-001

La valeur par défaut (300 s) est un point de départ, pas une vérité. Méthode :

1. capturer le trafic normal du réseau surveillé pendant une période
   représentative ;
2. mesurer, pour chaque machine, l'intervalle maximal entre deux de ses trames
   (ARP ou IPv4) ;
3. régler `binding_ttl` confortablement au-dessus de ce maximum.

Plus le TTL est long, plus l'attaquant a besoin d'un long silence de la
victime ; plus il est court, moins un changement de MAC légitime produit de
faux positifs.

## Évolutions prévues

1. ✅ Rafraîchir les associations ARP avec tout le trafic IPv4 (une machine
   active en TCP ne refait pas forcément d'ARP).
2. ✅ Fichier de configuration (associations de confiance, TTL, gravités),
   validé au démarrage.
3. Corrélation DHCP/ARP : une machine légitime qui change de MAC obtient
   d'abord un bail DHCP avec sa nouvelle MAC, ce que ne fait pas un usurpateur.
   Nécessite le décodage de l'UDP (ports 67 et 68).
4. Schéma JSON du contrat d'alerte, partagé avec le dashboard, contre lequel
   les tests valident chaque alerte.
5. Piste : l'incohérence IP/MAC (paquets portant l'IP de la victime mais la
   MAC de l'attaquant, qui les relaie) comme signal d'homme du milieu
   indépendant de l'ARP.

## Références

- RFC 826 (ARP), RFC 5227 (détection de conflit d'adresse IPv4).
- arp(7), page de manuel Linux (durée de validité du cache, confirmation par
  les couches supérieures).
- MITRE ATT&CK T1557.002 (ARP Cache Poisoning) et stratégie de détection
  DET0387.
- T. Ptacek, T. Newsham, *Insertion, Evasion, and Denial of Service: Eluding
  Network Intrusion Detection*, 1998.
- NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*.
