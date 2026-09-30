# Flux vidéo multiples et BUNDLE : ce qu'elixip doit faire

> Statut : **plan**. Rien n'est codé dans elixip. Branche `feat/unified-plan`.
>
> Ce document est le lot 4 de la conception du serveur média :
> `mediaserver/docs/conception/UNIFIED-PLAN/SPEC.md` (appelée « SPEC serveur »
> ci-dessous), §4.7. La SPEC serveur dit **quoi** ; ce document dit **où** et
> **dans quel ordre** dans elixip.

## 1. Objectif

Un navigateur partage son écran à côté de sa caméra. Son offre SDP porte alors
**deux sections `m=video`**. Aujourd'hui, elixip ne sait traiter qu'une section
par type de média. Le but :

- chaque section vidéo devient un **flux** du serveur média ;
- en conférence, chaque flux prend **un slot de mosaïque** ;
- en appel point à point (JSR-309), chaque flux est relayé vers l'autre jambe ;
- l'offre par défaut d'un navigateur est acceptée **telle quelle**, sans
  réglage du client.

Le dernier point impose le **BUNDLE** (RFC 8843) : c'est le transport unique
qui porte toutes les sections. Un navigateur réglé par défaut offre sa
deuxième vidéo en `bundle-only`, avec le port 0 (RFC 9429 §4.1.1). Sans BUNDLE,
cette section est perdue. Voir la SPEC serveur §2.

## 2. Ce que le serveur offre, et quand

| Capacité | API | État côté serveur |
|---|---|---|
| N flux vidéo par participant de conférence | `CreateVideoStream`, `DeleteVideoStream`, `SetVideoStreamMosaic`, `GetVideoStreamSource` ; `role` ≥ 2 sur toutes les méthodes média | **fait** (lot 1, commit `e259011`) |
| Document BFCP comme une source du mixeur | `SetAppCodec(BFCP)`, `sourceId` en dernier champ de l'événement 2 | **fait** (lot 1b, commit `fa56a3d`) |
| Transport partagé (BUNDLE), conférence | `CreateParticipant(…, bundle=1)` ; propriétés `mid`, `remote-ssrc` ; extmap `sdes:mid` | `bundle=1` **refusé** tant que le lot 2 n'est pas fait ; `mid`/`remote-ssrc`/extmap **faits** (lot 0) |
| N flux et BUNDLE en JSR-309 | `EndpointCreate(…, bundle)`, `EndpointCreateVideoStream`, `role` sur tous les `Endpoint*` | **à faire** (lots 2 et 3) |

Conséquence : les lots elixip s'alignent sur ceux du serveur (§6). Le lot E1
peut commencer tout de suite ; E2 attend le lot 2 du serveur ; E3 attend les
lots 2 et 3.

## 3. Ce qui existe dans elixip (vérifié dans le code)

Deux clients du serveur média, qui partagent la couche SDP :

- **Conférence (MCU)** : `apps/kelix_modules/lib/kelix/mod/mcu/adapter/conn.ex`
  (une jambe = un GenServer) et `apps/kelix_modules/lib/kelix/mod/mcu.ex`
  (mosaïque, noms, événements).
- **Point à point (JSR-309)** :
  `apps/elixip2/lib/framework/mendooze/MediaServerMendoozeConn.ex`.
- **SDP** : `apps/elixip2/lib/framework/mendooze/MediaServerMendoozeSdp.ex`
  (appelé « Sdp » ci-dessous), sur ExSDP.

| Fait | Où |
|---|---|
| Tout l'état par média est une map **indexée par type** (`:audio`, `:video`, `:text`) | MCU : `negotiated`, `local_sdes` (`conn.ex:236`, `:516`). JSR-309 : `local_ports`, `negs`, `proposed_recv`, `accepted`… (`MediaServerMendoozeConn.ex:318-401`) |
| MCU, deux `m=video` : la seconde est **sautée**, mais la réponse lui donne le port de la première | `open_receive_plane`, garde `Map.has_key?(acc, desc.type)` (`conn.ex:572`) ; `answer_or_reject` retrouve le même `neg` (`conn.ex:1611`) |
| JSR-309, deux `m=video` : la seconde **écrase** la première, et `EndpointStartSending` part deux fois sur la vidéo | `open_offered_receive_plane` sans garde (`MediaServerMendoozeConn.ex:2121-2129`) |
| Le rôle passé est **toujours 0**, en dur | MCU : `@role_main 0` (`conn.ex:48`). JSR-309 : aucun `Endpoint*` ne passe de rôle |
| `CreateParticipant` a 5 paramètres, sans `bundle` | `conn.ex:275-283` |
| `EndpointCreate` : `[sess, tag, audio?, video?, text?]` | `MediaServerMendoozeConn.ex:516`, `:619` |
| Toute source va dans la mosaïque 0, un participant = un slot | `join_mixer` (`conn.ex:1544-1559`) ; `video_participants` compte les participants (`mcu.ex:2432-2436`) |
| `a=group:BUNDLE` jamais lu, jamais écrit ; `a=bundle-only` absent | Sdp `build/1` (`:388-418`) ; commentaire Sdp `:459-463`. Des tests **exigent** son absence : `mendooze_sdp_test.exs:1761`, `mendooze_conn_test.exs:3459` |
| `a=mid` lu et renvoyé section par section | Sdp `find_mid` (`:1156`), `add_mid` (`:537`) |
| `a=ssrc`, `a=msid`, `a=content` : ignorés | absents de Sdp |
| extmap : seul transport-cc est traité ; `sdes:mid` ne l'est pas | Sdp `:81`, `:1693-1700` ; `conn.ex:1700` |
| ICE et DTLS écrits **par section**, mêmes identifiants pour toutes les sections d'une jambe | Sdp `add_ice` (`:777`), `add_crypto` (`:763`) |
| Événements MCU : type 2 lu par `[2 \| _rest]` et ignoré ; types 3 et 4 tolèrent un champ de plus | `event_queue.ex:322-331` |
| Événements JSR-309 : **arité exacte**, rôle jeté | `MediaServerMendoozePoller.ex:222-257` |
| Aucun code BFCP ; une section `m=application` BFCP est refusée en port 0 | `conn.ex:72`, `:1665-1676` |
| Aucun code n'utilise les protos MOTELI | aucune dépendance protobuf ni AMQP dans les `mix.exs` |
| Aucun client navigateur dans le dépôt | aucun `RTCPeerConnection` |

### Défauts trouvés en lisant, hors multi-vidéo

Ils se trouvent sur le chemin à modifier. Il faut les connaître avant d'y
toucher.

1. **MCU : une section offerte en port 0 est ouverte.** `answerable?`
   (`conn.ex:2007-2010`) ne regarde pas le port. Une section `m=video 0` reçoit
   un `StartReceiving` et un port vivant dans la réponse. Le chemin JSR-309, lui,
   la traite comme un retrait (`MediaServerMendoozeConn.ex:1575-1578`). Avec
   BUNDLE, **toute section `bundle-only` arrive en port 0** : ce défaut devient
   bloquant, mais dans l'autre sens (§4.3).
2. **MCU : après une renégociation, l'ACK rejoue tout l'attachement.**
   `conn.ex:317` remet `status` à `:answered`. Le commentaire de `:319-322` dit
   que « le chemin de l'ACK sort tôt sur une jambe attachée ». C'est faux :
   l'ACK suivant repasse par `handle_call(:attach)` (`:345`), et rejoue
   `SetCodec`, `StartSending` et `AddMosaicParticipant`.
3. **MCU : une renégociation tire une nouvelle clé SDES** (`conn.ex:504`).
4. **JSR-309 : une réoffre côté UAS tire de nouveaux identifiants ICE.**
   `setup_local_security_for_offer` (`MediaServerMendoozeConn.ex:1948`) ne
   regarde pas `local_ice`. Avec BUNDLE, c'est un redémarrage ICE de tout
   l'appel à chaque `addTrack`.
5. **JSR-309 : un candidat ICE distant va toujours sur l'audio**
   (`MediaServerMendoozeConn.ex:1628-1632`). Le `sdpMid` du candidat est perdu.
6. **Aucun retrait du mixeur en renégociation.** Le chemin conférence
   n'appelle jamais `RemoveMosaicParticipant` ni `StopReceiving` sur une
   section retirée.

## 4. Conception

### 4.1 Une clé par section, pas par type

C'est la modification de fond. Tout le reste en découle.

Chaque section média de l'offre a une **clé de flux** `{type, role}` :

- la première section d'un type a le rôle 0 ;
- chaque section vidéo suivante reçoit le rôle que rend `CreateVideoStream`
  (MCU) ou `EndpointCreateVideoStream` (JSR-309) ;
- l'audio et le texte gardent une seule section, rôle 0. Une seconde section
  audio ou texte reste refusée, comme aujourd'hui.

La jambe tient une table `mid → {type, role}`. Sans `a=mid` (vieux endpoint
SIP), la position de la section dans l'offre sert de clé. Les maps d'état
passent de `media` à `{media, role}` : `negotiated`, `local_ports`, `negs`,
`accepted`, `proposed_recv`, `local_sdes`, `watchdogs`, `connected`,
`timed_out`.

Exemple, l'offre d'un navigateur caméra + écran :

| Section | `mid` | Clé | Appel au serveur |
|---|---|---|---|
| `m=audio` | `0` | `{:audio, 0}` | `StartReceiving(…, Audio, …, role=0)` |
| `m=video` | `1` | `{:video, 0}` | `StartReceiving(…, Video, …, role=0)` |
| `m=video` | `2` | `{:video, 2}` | `CreateVideoStream` → `(2, sourceId)`, puis `StartReceiving(…, Video, …, role=2)` |

La table vit **avec la jambe**, pour toute la durée de l'appel. Une réoffre
retrouve le rôle d'une section par son `mid` : le rôle ne change jamais pour
une même section. Une section nouvelle (`addTrack`) crée un flux ; une section
passée en port 0 ou `inactive` (`removeTrack`) supprime le sien. Le serveur ne
réattribue jamais un rôle supprimé : la jambe non plus.

Options écartées :

- **Indexer par `mid` seul** : les RPC du serveur parlent en `(media, role)`.
  Il faudrait traduire à chaque appel, et un endpoint sans `mid` n'aurait pas
  de clé.
- **Indexer par position seule** : une réoffre peut ajouter une section, ce qui
  ne décale pas les positions (RFC 3264 §8) ; mais un endpoint qui recycle une
  section retirée garde sa position et change de `mid`. La clé doit suivre le
  `mid` quand il existe.

### 4.2 Conférence : un flux de plus = une source de plus

Pour une section vidéo de rôle ≥ 2 :

1. `CreateVideoStream(conf_id, part_id)` → `(role, source_id)`, à la réponse,
   avant `StartReceiving`.
2. Les appels de jambe habituels, avec ce rôle : `SetRTPProperties`,
   `SetLocalSTUNCredentials`, `SetLocalCryptoSDES`, `SetRemoteCryptoDTLS`,
   `SetRemoteSTUNCredentials`, `StartReceiving`, `StartRTPTimeout`.
3. **Pas de `SetVideoCodec`, pas de `StartSending`.** Le flux est reçu
   seulement : la réponse porte `a=recvonly`, que l'offre soit `sendrecv` ou
   `sendonly`. Le décodeur du serveur se crée d'après le codec de chaque paquet
   (`VideoStream::RecVideo`), il n'a pas besoin de `SetVideoCodec`.
4. À l'ACK : `AddMosaicParticipant(conf_id, 0, source_id)`.
5. **Fixer le slot** si la conférence est en VAD : un flux autre que la caméra
   n'est jamais élu locuteur, et serait donc remplacé à la première prise de
   parole. `SetMosaicSlot(conf_id, 0, slot, source_id)`, avec le slot choisi
   par `mcu.ex` (le même mécanisme que `do_slot/3`, `mcu.ex:3497`).
6. **Nommer la source** : `SetParticipantDisplayName(conf_id, -1, source_id,
   nom, 0)`, les mêmes arguments que pour un participant (`mcu.ex:750-778`). Le nom vient de `a=content:slides` si l'offre le porte, sinon du nom
   du participant suivi de « (écran) ». Le serveur ne change que le bandeau
   vidéo pour un `source_id`.

Côté `mcu.ex`, une conférence compte ses **sources** et non plus ses
participants : `video_participants/1` (`:2432`) et la mise en page
automatique (`follow_auto_layout/1`, `:2411`) comptent un slot par flux vidéo
reçu. Les événements `participant.*` restent par participant.

Suppression : `DeleteVideoStream(conf_id, part_id, role)`. Le serveur retire la
source de toutes les mosaïques et libère le slot. `DeleteParticipant` emporte
tous les flux : la fin d'appel ne change pas.

Le serveur ne fait **rien** pour un flux ≥ 2 que le contrôleur n'a pas demandé.
En particulier, il ne le met dans aucune mosaïque.

### 4.3 BUNDLE

Côté SDP (Sdp) :

- **Lire** `a=group:BUNDLE <mid>…` au niveau session, et `a=bundle-only` au
  niveau section. Une section `bundle-only` en port 0 est une section **normale**
  du groupe, pas un refus : c'est le cœur du changement, et c'est ce qui
  distingue un `bundle-only` d'un retrait (défaut 1 du §3).
- **Écrire**, dans la réponse, `a=group:BUNDLE` avec les `mid` de toutes les
  sections acceptées, dans l'ordre de l'offre. Sur **chaque** section du
  groupe : le même port, les mêmes `a=ice-ufrag`/`a=ice-pwd`, la même
  `a=fingerprint`, les mêmes candidats, et `a=rtcp-mux`.
- Refuser en port 0 toute section RTP hors du groupe (SPEC serveur §4.4 : le
  serveur ne prend pas de groupe partiel).
- Écrire `a=ssrc` et `a=msid` sur nos sections émises, avec le SSRC que le
  contrôleur pose déjà par la propriété `ssrc`.
- Renvoyer l'extmap `urn:ietf:params:rtp-hdrext:sdes:mid` si l'offre le porte,
  avec l'id de l'offre, comme transport-cc aujourd'hui (`conn.ex:1700`).

Côté serveur, une jambe groupée :

- MCU : `CreateParticipant(…, bundle=1)` quand l'offre porte le groupe. **C'est
  à la création** : un participant créé sans ne se groupe plus ensuite.
- Par section : `SetRTPProperties` avec `mid` (la valeur de `a=mid`),
  `remote-ssrc` (le SSRC de `a=ssrc`, s'il y en a un) et l'extmap `sdes:mid`,
  **avant** `StartReceiving`.
- Les appels de transport (STUN, DTLS, profil d'adressage) restent envoyés
  section par section : le serveur les accepte et ignore ceux des sections
  jointes. Le contrôleur n'a pas à savoir quelle section porte le transport.
- `StartReceiving` rend le même port pour toutes les sections : c'est celui de
  la porteuse.

Les tests qui exigent l'absence de BUNDLE (`mendooze_sdp_test.exs:1761`,
`mendooze_conn_test.exs:3459`) deviennent faux. Ils se réécrivent en « BUNDLE
seulement si l'offre le porte ». Le commentaire Sdp `:459-463` et
`DESIGN-MCU.md:550-552` disent qu'un navigateur réglé par défaut « est
servi ». C'est vrai pour une section par type, et faux dès la deuxième vidéo :
elle est offerte `bundle-only`, en port 0. Les deux textes sont à réécrire.

### 4.4 JSR-309

Mêmes règles que la conférence, avec les RPC `Endpoint*` :

- `EndpointCreate(…, bundle)` ; `EndpointCreateVideoStream(sess, ep)` → rôle ;
  `EndpointDeleteVideoStream(sess, ep, role)`.
- Le rôle en dernier argument de **tous** les `Endpoint*` qui visent une jambe
  (SPEC serveur §4.6). Aujourd'hui aucun ne le porte : la liste des sites est
  dans le §3.
- **Candidat ICE distant** (défaut 5) : le rôle se déduit du `sdpMid` du
  candidat, par la table `mid → {type, role}`. Avec BUNDLE, tout candidat vise
  la porteuse, donc l'audio ; sans BUNDLE, le `sdpMid` dit la section.
- **Événements** : le décodeur garde le rôle au lieu de le jeter
  (`MediaServerMendoozePoller.ex:222-257`), et `handle_server_event` indexe par
  `{media, role}`. `:external_fir` renvoie `EndpointRequestUpdate` avec ce
  rôle.
- **B2BUA** : `EndpointAttachToEndpoint(sess, a, b, media, role)` par paire de
  flux, dans les deux sens. Le flux de rôle k d'une jambe s'attache au flux de
  même rang de l'autre ; il faut donc créer côté sortant autant de flux vidéo
  qu'en entrée, avant l'offre sortante.
- Réoffre (défaut 4) : garder les identifiants ICE et DTLS de la jambe. Avec
  BUNDLE, en changer redémarre tout l'appel.

La transcodification d'un flux ≥ 2 en B2BUA est **à trancher** (§9).

### 4.5 BFCP, pour un endpoint SIP

elixip ne pilote pas le BFCP aujourd'hui (`mcu_module_guide.md:292`). Le
serveur le sait faire seul. Ce qu'il faudrait :

- Section `m=application … TCP/BFCP` ou `UDP/BFCP` : `SetAppCodec(BFCP)`, puis
  `StartReceiving(…, Application, {pt: BFCP}, role=0, proto)` ; écrire
  `a=confid`, `a=userid`, `a=floorid:1 mstrm:<label>` (MCU-API §6.12).
- Section vidéo `a=content:slides` : c'est la jambe de rôle 1, pas un flux ≥ 2.
- Une fois par conférence : `SetDocSharingMosaic(conf_id, mosaïque)`. Le
  serveur retient cette mosaïque et gère seul chaque présentation.
- Événement 2 (`ParticipantRequestDocSharing`, `[2, conf, tag, part, status,
  source_id]`) : sur `WAITING_ACCEPT`, `AcceptDocSharingRequest` ou
  `RefuseDocSharingRequest` selon la politique ; sur `ACTIVE`, placer
  `source_id` dans la mosaïque des navigateurs si on veut qu'ils voient le
  document ; sur `NONE`, l'en retirer.

Ce lot rend recettables les scénarios 9 et 10 de la SPEC serveur §7. Il se
code et se prouve **sur bouchon** : aucun endpoint SIP BFCP n'est aujourd'hui
disponible pour la recette réelle, qui reste à faire.

### 4.6 MOTELI

Rien à faire : aucun code d'elixip n'utilise les protos. Ils sont tenus à
jour avec l'API XML-RPC (commits `04adaff`, `32dc604`).

## 5. Tests

Les deux bouchons existent déjà et enregistrent chaque appel :

- conférence : `apps/kelix_modules/test/support/mcu_stub.exs`
  (`Kelix.Mcu.TestStub`, `rpc_calls/1`, `rpc_order/1`) ;
- JSR-309 : `apps/elixip2/test/support/jsr309_fake_server.exs`.

Aucun test ne couvre aujourd'hui deux sections du même type, un rôle autre que
0, le BUNDLE ou le BFCP. Chaque lot ajoute les siens (§6). Les offres de
référence viennent de vrais navigateurs, capturées et versionnées comme
`SDP-webrtc-electron-offer.txt` (qui porte déjà `a=group:BUNDLE 0 1`) :

- Chrome, caméra + `getDisplayMedia`, `bundlePolicy` par défaut ;
- Chrome, même chose en `max-compat` ;
- Firefox, caméra + écran ;
- la réoffre de chacun après `removeTrack` puis `addTrack`.

Le bouchon MCU rend `CreateVideoStream => [2, 731]` ; le test vérifie les
appels et leur ordre, et la réponse SDP.

## 6. Lots

| Lot | Contenu | Attend côté serveur | Preuve |
|---|---|---|---|
| **E0** | Corrections préalables : défauts 1 (port 0 en MCU), 2 (ACK après renégociation), 6 (retrait en renégociation). Clé `{type, role}` dans les deux adaptateurs, rôle 0 partout : aucun changement visible. | rien | toute la suite reste verte ; un test par défaut corrigé |
| **E1** | Conférence, N vidéos sans BUNDLE (§4.2) : `CreateVideoStream`, `recvonly`, slot, nom, mise en page par source, `DeleteVideoStream` en renégociation. | lot 1 (**fait**) | tests bouchon ; recette : Chrome en `max-compat`, caméra + écran, deux slots (scénario 5 de la SPEC serveur §7) |
| **E2** | Conférence, BUNDLE (§4.3) : SDP, `bundle=1`, `mid`, `remote-ssrc`, extmap `sdes:mid`. | lot 2 | tests SDP et bouchon ; recette : Chrome et Firefox par défaut (scénarios 1 à 3, 7, 8) |
| **E3** | JSR-309, N vidéos et BUNDLE (§4.4), défauts 4 et 5. | lots 2 et 3 | tests `jsr309_fake_server` ; recette : B2BUA Chrome ↔ Chrome (scénario 6) |
| **E4** | BFCP pour endpoint SIP (§4.5). | lot 1b (**fait**) | tests bouchon ; recette réelle (scénarios 9 et 10) reportée faute d'endpoint |

E0, E1 et E4 peuvent commencer tout de suite. E4 est indépendant des autres.

Chaque lot met à jour la documentation qu'il rend fausse :
`docs/design/DESIGN-MCU.md` (§ BUNDLE, hors périmètre BFCP),
`docs/design/DESIGN-FRAMEWORK.md` §6.3 et §6.5,
`docs/kelixip/modules/mcu_module_guide.md`.

## 7. Pièges

- **Une section `bundle-only` arrive en port 0.** Tant que le parseur la traite
  comme un retrait (chemin JSR-309) ou comme une section vivante sans groupe
  (chemin MCU, défaut 1), elle est mal servie. La règle : le port 0 n'est un
  retrait que si la section **n'est pas** `bundle-only`.
- **Le groupe se décide à la création du participant.** Un participant créé
  avant d'avoir lu l'offre ne peut plus se grouper. Sur le chemin MCU,
  `create_participant/3` doit donc connaître l'offre.
- **Un rôle ne se réattribue jamais.** Une section retirée puis rajoutée reçoit
  un nouveau rôle, et un nouveau `source_id`.
- **Le slot d'un écran doit être fixé en VAD.** Sinon, la première prise de
  parole d'un autre participant le chasse de la mosaïque.
- **Les événements JSR-309 sont décodés à arité exacte.** Un champ de plus
  côté serveur fait perdre l'événement, avec un simple warning
  (`MediaServerMendoozePoller.ex:178-179`, `:257`). Toute évolution des événements
  du serveur doit être livrée **avec** le décodeur.

## 8. Hors périmètre

- Émettre une seconde mosaïque vers un navigateur sur un flux ≥ 2 (SPEC
  serveur §8).
- Simulcast (`a=rid`, `a=simulcast`).
- Un groupe BUNDLE partiel.
- Offrir N vidéos depuis elixip (UAC).
- Un client navigateur dans ce dépôt : les recettes utilisent un navigateur
  externe.

## 9. Arbitrages

Décidés par le mainteneur le 2026-09-30.

| Sujet | Décision | Option écartée |
|---|---|---|
| B2BUA : un flux ≥ 2 qui demande une transcodification | le relayer seulement si les codecs coïncident, sinon le refuser en port 0 | une chaîne de transcodeurs par flux : double le coût CPU d'un appel pour un cas que les navigateurs ne produisent pas |
| Nom affiché d'un écran partagé | `a=content` s'il est présent, sinon « nom (écran) » ; le script peut le remplacer | laisser le script seul le fixer : un appel sans script serait illisible |
| Mosaïque d'un flux ≥ 2 | la mosaïque 0, comme la caméra | une mosaïque dédiée aux écrans : elixip n'utilise que la mosaïque 0 (`mcu_module_guide.md:293`), c'est un chantier de mise en page à part |
| BFCP (E4) | **dans ce chantier**, codé et prouvé sur bouchon ; la recette réelle attend un endpoint SIP BFCP | le reporter : laisserait les scénarios 9 et 10 sans contrôleur |
