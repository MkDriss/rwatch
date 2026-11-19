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

### Positionnement du capteur

Un IDS ne détecte que ce que son interface lui montre. Sur le labo (Raspberry
Pi 4 en point d'accès WiFi, hostapd, `ap_isolate=0`), la validation en
conditions réelles a montré que :

- sans mode promiscuité, les trames échangées directement entre deux stations
  (par exemple la réponse ARP usurpée d'un attaquant à sa victime) ne sont PAS
  vues : seules le sont les trames adressées au Pi ou diffusées à tout le
  réseau ;
- avec le mode promiscuité, ces trames sont visibles.

rwatch active donc ce mode par défaut (via `rnifler::capture::open_live_with`,
ajoutée dans rnifler 1.2.0). Sur ce matériel, la capacité `CAP_NET_RAW` suffit,
y compris en mode promiscuité : `CAP_NET_ADMIN` n'est pas nécessaire (vérifié
avec rwatch 0.2.1). Ce qu'un point d'accès laisse remonter dépend
toutefois de son pilote et de son firmware : sur un autre matériel, la
visibilité est à vérifier de la même façon (un ping entre deux stations,
observé depuis le capteur avec `tcpdump` puis `tcpdump -p`).

Avec `ap_isolate=1`, les stations ne peuvent plus échanger directement : la
question de la visibilité disparaît, et l'empoisonnement ARP entre stations
devient impossible au niveau 2 (une mesure de prévention, hors du rôle de
rwatch).

### Règle MQTT-001 (usurpation d'identité MQTT)

- Si l'attaquant se connecte AVANT l'objet légitime et qu'aucune association de
  confiance n'existe pour ce Client ID, l'identité de l'attaquant est apprise,
  et c'est le retour de l'objet légitime qui est signalé. Les associations de
  confiance éliminent ce cas (recommandées pour les objets critiques ; dans le
  labo, l'actionneur est déclaré de confiance avec `learn = false`).
- Un objet légitime qui change de MAC sans association de confiance produit un
  faux positif. Pas de péremption : un Client ID est une identité applicative
  stable (codée en dur dans le firmware).
- En mode appris, l'identité comparée est la MAC seule : un attaquant qui usurpe
  aussi la MAC n'est pas vu par MQTT-001. C'est ARP-001 qui détecte alors
  l'usurpation de MAC : les deux règles se complètent.
- La table Client ID → MAC de cette règle et la table IP → MAC de la couche
  MQTT font double emploi avec celle d'ARP-001 (voir ci-dessous, contexte
  partagé).

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

- Les fichiers sont lus une seule fois, au démarrage : toute modification
  demande de relancer rwatch (pas de rechargement à chaud).
- Les fichiers contiennent les associations de confiance : quiconque peut les
  modifier peut désactiver la détection pour une adresse. En production, ils
  doivent appartenir à root et n'être modifiables que par lui (à mettre en
  place lors du déploiement sur le Pi).
- Les fichiers de règles sont listés un par un (`[rules] files`) : pas de
  motif du type `rules/*.toml`. C'est un choix (une règle ne peut ni
  apparaître ni disparaître sans modification visible du fichier principal),
  qui pourra être assoupli si rwatch accepte un jour des centaines de
  signatures écrites par l'utilisateur.

### Décodage

- Les segments TCP sont découpés deux fois (etherparse pour l'émetteur IPv4,
  puis `rnifler::parser`). Le coût est négligeable aux débits d'un réseau IoT ;
  à optimiser si une future version de rnifler expose la MAC source.

## Méthode de réglage du TTL d'ARP-001

La valeur par défaut (300 s) est un point de départ, pas une vérité. Méthode :

1. capturer le trafic normal du réseau surveillé pendant une période
   représentative, avec TOUTES les machines qui seront présentes ;
2. mesurer, pour chaque machine, le plus long silence entre deux de ses trames
   (ARP ou IPv4), avec l'outil fourni, qui compte exactement ce que compte
   ARP-001 :

   ```console
   $ cargo run --example silences -- trafic-normal.pcap
   ```

3. régler `binding_ttl_secs` confortablement au-dessus du plus long silence de
   la machine la plus discrète.

L'outil affiche aussi le « silence final » de chaque machine (entre sa
dernière trame et la fin de la capture). Il n'est pas compté dans la mesure,
puisqu'on ignore combien de temps il aurait duré, mais un silence final très
long signale une machine partie en cours de capture, ou une capture trop
courte.

Plus le TTL est long, plus l'attaquant a besoin d'un long silence de la
victime ; plus il est court, moins un changement de MAC légitime produit de
faux positifs.

## Évolutions prévues

1. ✅ Rafraîchir les associations ARP avec tout le trafic IPv4 (une machine
   active en TCP ne refait pas forcément d'ARP).
2. ✅ Fichiers de configuration (associations de confiance, TTL, gravités),
   un fichier par règle listé explicitement, validés au démarrage.
3. Corrélation DHCP/ARP : une machine légitime qui change de MAC obtient
   d'abord un bail DHCP avec sa nouvelle MAC, ce que ne fait pas un usurpateur.
   Nécessite le décodage de l'UDP (ports 67 et 68).
4. Schéma JSON du contrat d'alerte, partagé avec le dashboard, contre lequel
   les tests valident chaque alerte.
5. Attestation de provenance des binaires publiés : l'empreinte SHA-256 de la
   release protège contre un téléchargement corrompu, pas contre un compte
   GitHub compromis (elle vient de la même page que l'archive).
6. Piste : l'incohérence IP/MAC (paquets portant l'IP de la victime mais la
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
