# Négociation transport-wide-cc (prompt d'implémentation)

> **Ce document est un prompt autoporteur.** Il donne à un agent (ou un
> développeur) tout ce qu'il faut pour implémenter, dans CE dépôt, la moitié
> contrôleur du chantier « estimateur émetteur » du mediaserver
> (`mediaserver/sender_bwe_plan.md`, sous-lot 6.5 — chantier SDP commun avec
> son lot 4). Le côté mediaserver est ENTIÈREMENT implémenté et testé
> (457 tests verts au 2026-08-19) : il ne manque que la négociation, qui
> vit ici.

## 1. Mission

Sur les pattes **vidéo** WebRTC, négocier l'extension d'en-tête RTP
*transport-wide congestion control* et l'attribut `a=rtcp-fb … transport-cc`,
puis poser la propriété RTP correspondante sur la jambe mediaserver. Derrière
un bouton de configuration, désactivé par défaut.

Une fois cela fait, le mediaserver écrit un numéro de séquence transport-wide
sur chacun de ses paquets sortants, le navigateur lui renvoie des rapports
d'arrivée (RTCP RTPFB fmt 15), et l'estimateur de bande passante **côté
émetteur** du mediaserver (nouveau, lot 6) pilote l'encodeur en fonction de ce
que le réseau absorbe réellement.

## 2. Le contrat exact avec le mediaserver

Tout le côté serveur existe déjà. Le contrat se réduit à UNE propriété RTP :

- **Clé** : `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01`
  (l'URI de l'extmap, telle quelle — c'est la convention du mediaserver pour
  les extensions, identique à `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time`).
- **Valeur** : l'**id extmap négocié** (entier, en chaîne), celui de la ligne
  `a=extmap` retenue dans l'échange SDP.
- **Canal** : le même que les propriétés `remb` / `tmmbr` / `useNACK` déjà
  posées — `EndpointSetRTPProperties` (construit par `rtcp_fb_props/1`).
  Attention à la valeur : les commutateurs rtcp-fb se posent à `"1"`, l'extmap
  se pose à **l'id négocié** — ne pas le faire passer par la même
  `Map.new(…, "1")`.
- **Effet côté mediaserver** (pour comprendre, rien à faire) : l'extension est
  écrite sur tous les paquets sortants de la session, les rapports fmt 15
  entrants sont appariés à l'historique d'émission et nourrissent le
  `SenderBWE`, dont la consigne compose par `min()` avec le REMB/TMMBR reçu.
  Traces sous `-d` : `BWE-TX: estimation stream=… target=…`.
- **Ce que le mediaserver ne fait PAS encore** : émettre des rapports fmt 15
  pour ce qu'il reçoit (c'est son lot 4, non implémenté). Il lit l'extension
  entrante mais ne rapporte rien. Conséquence au §5.

Une clé de propriété inconnue du mediaserver produit une ligne
`Unknown RTP property` dans `/var/log/mcu.log` : son ABSENCE est le premier
contrôle que la clé est la bonne.

## 3. Ce qu'il faut implémenter ici

### 3.1 SDP — côté answer (l'offre vient du navigateur)

Chrome/Firefox offrent sur la m-line vidéo :

```
a=extmap:<id> http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=rtcp-fb:<pt> transport-cc        (répété pour chaque PT vidéo)
```

Si le bouton de configuration est actif ET que l'offre porte cet extmap sur la
m-line vidéo :

1. reprendre dans l'answer la ligne `a=extmap` avec le **même id** (RFC 8285 :
   l'answer ne renumérote pas) ;
2. reprendre `transport-cc` dans les `a=rtcp-fb` des PT vidéo retenus ;
3. poser la propriété du §2 sur la jambe mediaserver, avec cet id.

Sinon (bouton inactif, ou offre sans extmap) : ne rien reprendre, ne rien
poser — comportement strictement inchangé.

Grammaire extmap (RFC 8285) : `a=extmap:<id>[/<direction>] <URI>`. En v1, ne
reprendre que les extmap **sans direction** ou `sendrecv` ; une direction
asymétrique se laisse tomber (hors périmètre).

### 3.2 SDP — côté offre (jambes où kelixip offre)

Quand c'est nous qui offrons la m-line vidéo et que le bouton est actif :
inclure `a=extmap:3 <URI>` (id 3 recommandé : aucun autre extmap n'est offert
aujourd'hui, donc pas de collision) et `a=rtcp-fb:<pt> transport-cc` sur les PT
vidéo. Si l'answer du pair reprend l'extmap, poser la propriété avec l'id ;
sinon, ne rien poser.

### 3.3 Configuration

Un booléen `[mediaserver] transport_cc` dans `config.toml`, **défaut `false`**,
calqué trait pour trait sur `bitrate_feedback` (le motif vient d'être posé) :
`Kelix.Config` → bloc app env `MediaServer.Mendooze` → lecture dans mendooze.
Le défaut passera à `true` quand la recette du §6 aura validé le comportement
du pair — pas avant, la décision se consigne dans ce document.

### 3.4 Points d'ancrage dans ce dépôt

- `apps/elixip2/lib/framework/mendooze/MediaServerMendoozeConn.ex` :
  - `@supported_rtcp_fb` (~l.130) — la table `attribut rtcp-fb → propriété
    mediaserver`. Attention : `transport-cc` n'y entre PAS tel quel — sa
    propriété à lui vient de l'**extmap** (clé URI, valeur id), pas de
    l'attribut rtcp-fb. L'attribut, lui, doit seulement survivre au filtrage
    et être repris dans l'answer.
  - `answered_rtcp_fb/1` (~l.2894) et `drop_rate_control_fb/1` — le filtrage
    par la config, modèle pour le nouveau bouton.
  - `rtcp_fb_props/1` (~l.2534) et l'appel `EndpointSetRTPProperties`
    juste au-dessus — là où partent les properties.
- **`apps/kelix_modules/lib/kelix/mod/mcu/adapter/conn.ex` porte une copie
  parallèle** (`answered_rtcp_fb` ~l.843) : les DEUX contrôleurs se mettent à
  jour dans le même jeu de changements, comme l'a fait la propriété `remb`
  (rate-control lot 2). Un seul des deux mis à jour = un des deux chemins
  d'appel sans contrôle de débit émetteur, silencieusement.
- Le parsing SDP : vérifier si la couche SDP expose déjà `a=extmap` ;
  sinon, l'y ajouter (c'est probablement le vrai travail).

## 4. Périmètre v1 — dit explicitement

- **Vidéo seulement.** L'audio n'a pas d'estimateur émetteur côté mediaserver
  (hors v1 là-bas aussi) ; ne pas négocier l'extmap sur la m-line audio.
- **Pattes WebRTC/mediaserver seulement.** Rien à faire sur les pattes SIP
  pures : un pair SIP n'offre pas cet extmap, et le cas « offre sans extmap »
  est déjà le comportement inchangé.
- **Pas de CCFB (RFC 8888, fmt 11)** : viendra derrière la même interface,
  côté mediaserver d'abord.
- **Pas de renumérotation d'id, pas de direction extmap asymétrique.**

## 5. Le piège de séquencement (à lire avant de coder)

Négocier `transport-cc` a **deux effets à la fois**, et un seul des deux est
servi aujourd'hui :

1. Le pair envoie des rapports fmt 15 sur **nos** paquets sortants → consommés
   par le mediaserver (lot 6, prêt). C'est le but.
2. Le pair pose l'extension sur **ses** paquets et attend des rapports fmt 15
   de notre part → le mediaserver n'en émet pas encore (son lot 4). Le BWE
   émetteur du navigateur retombe alors sur ses rapports de perte RR et sur le
   REMB/TMMBR que nous émettons toujours (rate-control lot 2) — c'est-à-dire
   le régime actuel. **Hypothèse à VÉRIFIER à la recette**, pas à croire sur
   parole : si le débit du navigateur vers nous s'effondre ou plafonne au
   démarrage une fois le bouton actif, c'est ce mécanisme-là qu'il faut
   regarder en premier.

Effet de bord attendu et voulu : dès que nos paquets portent l'extension, le
navigateur **cesse d'émettre du REMB** pour notre flux (son contrôleur de
réception change de barreau — un mécanisme par paquet, pas par renégociation).
La consigne côté mediaserver compose les deux sources par `min()`, donc rien à
faire — mais ne pas s'étonner de voir les REMB entrants disparaître des logs.

C'est précisément pour ces deux points que le bouton naît à `false`.

## 6. Tests et recette

**Tests unitaires** (modèle : ceux de `bitrate_feedback`, dans les DEUX
contrôleurs) :
- offre avec extmap + bouton actif → answer avec extmap même id, rtcp-fb
  `transport-cc` repris, propriété posée avec l'id ;
- offre avec extmap + bouton inactif → answer sans extmap ni transport-cc,
  aucune propriété ;
- offre sans extmap + bouton actif → rien de repris, aucune propriété ;
- offre avec `a=extmap:7/sendonly …` → non repris (direction asymétrique) ;
- côté offre : extmap id 3 présent si bouton actif, propriété posée seulement
  si l'answer le reprend.

**Recette live** (appel Chrome ↔ mediaserver, bouton actif sur dev, mcu avec `-d`) :
1. `grep -a 'Unknown RTP property' /var/log/mcu.log` → ne doit rien rendre de
   nouveau.
2. `grep -a 'BWE-TX: estimation' /var/log/mcu.log` → des lignes avec
   `stream=<nom de la patte>` et une cible qui bouge : la boucle est fermée.
3. pcap : nos paquets RTP portent l'extension one-byte (`0xBEDE`) avec l'id
   négocié ; le RTCP entrant porte des paquets PT=205 FMT=15.
4. `chrome://webrtc-internals` côté navigateur : vérifier l'hypothèse du §5 —
   le débit d'émission du navigateur vers nous reste gouverné (par nos
   REMB/TMMBR) et ne s'effondre pas.
5. La séance de mesure complète (netem sur le lien sortant du mediaserver,
   critères chiffrés) est décrite côté mediaserver :
   `mediaserver/mcu/tests/tools/README.md`, patte `tx:<stream>` de
   `bwe_report.py`.

## 7. Références

- `mediaserver/sender_bwe_plan.md` — conception du lot 6, décision D6
  (négociation) ; son lot 4 décrit le générateur fmt 15 à venir.
- `mediaserver/rate_control_plan.md` — le plan chapeau (lots 2, 4, 6).
- RFC 8285 (extmap), draft-holmer-rmcat-transport-wide-cc-extensions-01
  (l'extension et le format fmt 15).
- Le motif `bitrate_feedback` de ce dépôt — configuration, filtrage, tests.
