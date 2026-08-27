# Evolution des listener dans kelixip

## Description des besoins

Premier besoin : être compatible IP V6.

Second besoin : préparer l'avenir où kelixip traitera d'autre protocoles que SIP

Troisième besoin : pour le futur produit SBC borderline, on doit avoir la possibilité de désigner des
interfaces réseaux comme faisant partie du reseau interne et d'autre comme du réseau publique.

## Fonctions attendue

Par ordre de priorité

- support réseuau public IPV6
- médiation entre un réseau IPV4 et un réseau IPV6 avec relais de média
- médiation entre un réseau interne et un réseau externe
- kelixip dans un réseau interne avec une IP interne nattée 1 - 1 avec une ip publique. Des utilisateurs dans le réseau interne et des utilisateurs dans le réseau externe. Ecriture automatique du SDP selon la destination. Equivalent du internal_network asterisk et du public IP

Une session porte un profil réseau **par jambe**, et les deux peuvent différer.
C'est l'objectif, pas un cas limite : à terme, toutes les combinaisons de famille
(IPv4, IPv6) et de côté (interne, publique) doivent pouvoir se rencontrer dans un
même appel.

## Fonction future (pas à implémenter) : kelixip multiprotocole

- Pile XMPP et Pile Matrix intégrées à l'intérieur de kelixp (comme module ?)
- Pile SIP transformée en module
- possibilité de transformer kelixip en simple exécuteur de scénario ou orchestrateur de machine à état via un protocole de contrôle type CTI.
  Ex : pour implémenter un bot teams.

## Evolution des blocs [[listen]]

```
[[listen]]
application_layer = "sip" # pas utilisé, pas obligatoire. Sera étendu avec "xmpp" ...
proto = "wss" | "tls" | "tcp" | "udp" | "ws" # On vérifie si l'application_layer et le proto sont compatibles
addr = <ipv4 ou ipv6>
port = 5071
cert = "/etc/pki/tls/certs/dev.ives.fr.crt" # pour TLS et WSS
key = "/etc/pki/tls/private/dev.ives.fr.key" # pour TLS ou WSS
tag = "public" | "internal" # public par défaut
nat = "yes" # Signifie que l'on doit utiliser un serveur stun pour trouver sont IP publique
network = <specification du réseau interne> # toute IP qui vient de ce réseau est considéré comme interne. Le réseau doit contenir addr sinon c'est une IP qui vient de l'extérieur et on doit répondre avec des SDP publique
```

### Décisions sur les clés

Le parseur refuse toute clé inconnue dans un `[[listen]]`
(`Kelix.Config.parse_listener/1`) : chaque clé ajoutée est donc strictement
additive et aucune configuration existante ne casse. En contrepartie, tout ajout
met à jour `docs/kelixip/installation.md` et `packaging/config/config.toml` dans
le même lot.

- **`addr`** ne change pas de forme : `Kelix.Config` valide l'adresse par
  `:inet.parse_address/1`, donc une IPv6 y passe. C'est elle qui donne sa
  famille au listener, et c'est elle qui lui donnera son profil réseau
  (étape 5) ; un listener wildcard prend le profil par défaut du nœud. Les deux
  wildcards sont acceptés et portent chacun leur famille (`0.0.0.0`, `::`) ;
  `addr` absent est la seule écriture qui n'en nomme aucune (étape 4).
- **`tag`** n'a qu'une valeur utile : `"internal"`. Le côté public est le défaut
  déduit de l'absence de clé. `"public"` reste accepté sans effet. Introduit à
  l'étape 5. Un listener `internal` porte aussi le ou les sous-réseaux qui le
  définissent : auto-détectés depuis le masque de son interface
  (`:inet.getifaddrs/0`), et énonçables par une clé pour un réseau interne joint
  par un routeur, qui n'est attaché à aucune interface.
- **`network`** ne vit pas dans le bloc. Écrite par listener, la liste de
  préfixes se recopie autant de fois qu'il y a de listeners et deux listeners
  peuvent se contredire. Et ce n'est pas `addr` qui décide qu'un correspondant
  est interne, c'est **l'adresse du correspondant**. La liste est donc un énoncé
  de topologie du nœud : une section `[network]` avec `internal = ["10.0.0.0/8",
  "fd00::/8", …]`, introduite à l'étape 6.
- **`nat`** est remplacée par **`advertise = "<ip>"`**, l'adresse à publier dans
  la signalisation. Le besoin est un NAT 1:1 : l'exploitant connaît cette
  adresse, une EIP AWS ne bouge pas. Une découverte par STUN ajoute une
  dépendance réseau au démarrage et un mode de panne pour aucune information de
  plus. Le mediaserver fait le même choix avec `--public-ip`. Introduite à
  l'étape 6.
- **`proto = "ws"`** demande un transport et un listener qui n'existent pas :
  seul le WSS, entrant comme sortant, est implémenté, plus le `ws` sortant.
  C'est un chantier propre, hors des sept étapes, légitime derrière un nginx qui
  termine TLS.
- **`application_layer`** n'est pas livrée tant qu'elle ne fait rien. Sa
  validation (« vérifier que l'`application_layer` et le `proto` sont
  compatibles ») suppose la conception multiprotocole, hors périmètre. Une clé
  parsée et ignorée devient une clé que l'exploitant renseigne, puis accuse.

## API XMLRPC de Medooze

Le mediaserver Medooze 1.13.0 a été modifié pour supporter IP V6 et la désignation du type de réseau
Voici la doc de l'API https://github.com/neutrino38/mediaserver/blob/master/design/xmlrpc_jsr309_api.md

## Étapes d'implémentation

Sept étapes. Les deux premières ne touchent aucun listener. Le besoin « réseau
public IPv6 » est satisfait à l'étape 3, la médiation IPv4↔IPv6 aux étapes 4
et 5, la médiation interne/externe à l'étape 6 — dont la classification par
préfixe est déjà là, l'étape 5 en ayant besoin.

Deux chantiers restent hors de cette suite, parce qu'ils n'en sont pas des
prérequis : un client STUN (étape 6) et le transport `ws` en clair.

### Étape 1 — Couche message : lire et écrire un `IPv6reference` — livrée

Le nœud lit et écrit une adresse IPv6 dans un message SIP (RFC 3261 §19.1.1
`IPv6reference`, §20.42 `sent-by`).

**Écriture — un seul endroit.** `SIP.NetUtils.sip_host/1` rend la production
`host` de la §25.1 : un littéral IPv6 sort entre crochets, une adresse IPv4, un
nom d'hôte ou un littéral déjà entre crochets sortent inchangés. Elle accepte
un tuple comme une chaîne, parce qu'une adresse locale arrive en tuple
(`SIP.Transport.build_contact_uri/2`) et une adresse relue en chaîne.
`SIP.Uri.serialize_addr_spec/1` et `SIP.Msg.Ops.build_via_addr/3` l'appellent
tous les deux. La conversion tuple → chaîne était recopiée cinq fois ; c'est
cette recopie qui ferait diverger les crochets.

**Lecture.** `SIP.Uri.parse_host_port/1` reconnaît d'abord la forme `[…]`, garde
l'intérieur comme domaine et ne cherche un port qu'après le `]`. Le domaine est
donc stocké sans crochets, et `sip_host/1` les remet à la sérialisation. Un
littéral IPv6 sans ses crochets est refusé : il n'est pas une URI SIP.

**Le parseur ne lève jamais sur une entrée mal formée.** Son canal d'erreur est
l'atome (`:invalid_sip_domain`, `:invalid_sip_uri_port`,
`:invalid_sip_uri_general`) et le callback de parsing. Le découpage du
`host:port` et celui du `user@host` ont chacun une clause de repli : n'importe
quel hôte à deux `:` ou une seconde `@` — une coquille, un scanner — arrivait
sur un `case` sans clause. La frontière entrante se protège de son côté :
`SIP.Transport.ImplHelpers.process_sip_message/7` entoure le traitement d'un
`try/rescue`, donc un pair ne tue pas le transport qui sert tout le monde — une
connexion TCP/TLS/WSS, ou la seule socket UDP du nœud.

**Identifiant de zone** (`fe80::1%eth0`, RFC 6874) : refusé, et refusé
explicitement, parce que `:inet.parse_address/1` accepte la zone et la jette en
silence. Une adresse link-local dans un Via ou un Contact ne se joint pas depuis
un autre lien ; l'accepter donnerait l'illusion du contraire.

Ce qui est juste par voie de conséquence, sans code propre : l'extraction de la
branche du Via (`SIPMsg` réinjecte le `sent-by` dans le parseur d'URI), le
Contact, le Record-Route, la Request-URI (`SIP.Uri.serialize_ruri/1` passe par la
même fonction) et le calcul du digest, qui emploie la même chaîne.

Tests : `apps/elixip2/test/sip_ipv6_message_test.exs`.

Aucun listener n'est touché.

### Étape 2 — Couche adresse : choisir une adresse locale — livrée

Le nœud choisit une adresse locale annonçable, dans une famille qu'il demande.

**La portée se reconnaît en un seul endroit.** `SIP.NetUtils.address_scope/1`
rend `:loopback`, `:link_local`, `:private` ou `:global`, pour les deux
familles : RFC 1918 et les ULA de la RFC 4193 (`fc00::/7`) se lisent tous les
deux `:private`. `MediaServer.Mockup` portait sa propre copie du test
`fe80::/10` ; elle a disparu. La reconnaissance des adresses `:private` sert de
nouveau à l'étape 6.

**`get_local_ips/1` filtre la portée.** Les adresses `:global` et `:private`
sortent toujours ; `:loopback` et `:link_local` ne sortent que si l'appelant les
nomme. Une `fe80::` ne s'annonce pas : elle demande un identifiant de zone
qu'aucun pair ne peut employer.

**L'ordre du retour rend `hd/1` défendable** : IPv6 avant IPv4, et dans une
famille `:global` avant `:private` avant `:link_local` avant `:loopback`.
Demander aucune famille rend une liste vide. La famille d'une adresse locale est
une décision, pas un effet de l'ordre d'énumération des interfaces.

**La famille est un paramètre sur les cinq sites qui la figeaient.**
`SIP.Transport.UDP` la lit sur `:udp_local_addr` quand cette adresse est posée,
sinon sur `:udp_family` (`:ipv4` par défaut) : il démarre donc sur un hôte sans
IPv4, et n'échoue en `:networkdown` que s'il n'a réellement rien à annoncer. Les
trois listeners (`TCPListener`, `TLSListener`, `WSSListener`) la lisent sur
`addr` quand elle est explicite, sinon sur l'option `:family` ; sans adresse à
annoncer ils s'arrêtent sur un message clair au lieu de lever sur une liste
vide. Le transport mockup des tests lit `:mockup_local_family`.

**Le filtre `:running` était mort** : `:up in flaglist and :running in flaglist
not in flaglist` se lit `(:running in flaglist) not in flaglist`, toujours vrai,
donc une interface UP mais pas RUNNING était retenue.

Tests : `apps/elixip2/test/netutils_test.exs`.

Aucune socket de listener ne change de famille : c'est l'étape 3.

### Étape 3 — Un listener IPv6 explicite — livrée

Une jambe, une famille, pas de dual-stack. Les blocs `[[listen]]` ne changent
pas : `addr` accepte une IPv6, et c'est cette adresse qui donne sa famille au
listener.

OTP 26 déduit la famille de l'option `{:ip, tuple}` : `:gen_tcp.listen/2`,
`:gen_udp.open/2` et `:ssl.listen/2` acceptent une adresse IPv6 sans `:inet6`
(mesuré). Un listener TCP, TLS ou WSS dont `addr` nomme une IPv6 lie donc déjà
correctement sa socket.

**UDP est l'exception.** `SIP.Transport.UDP` ouvre sa socket directement par
`:gen_udp.open/2`, avec la famille, l'adresse et `:ipv6_v6only`, et non par
`Socket.UDP.open/2` : ce wrapper traduit un vocabulaire d'options fixe et jette
en silence ce qui n'y figure pas — l'adresse de bind si elle n'est pas imbriquée
sous `:local`, et la famille toujours. `:udp_local_addr` lie la socket **en
plus** de fournir l'adresse annoncée, comme le fait chaque listener TCP, TLS
et WSS.

**Le wildcard IPv6 est refusé.** `addr = "::"` devrait dire quelle famille il
porte, et rien ne le décide avant l'étape 4. `Kelix.Config` le rejette avec un
message clair, dans toutes ses écritures.

**Une seule décision de famille.** `SIP.NetUtils.preferred_family/0` rend la
famille du nœud : celle de `:udp_local_addr` quand une adresse est configurée,
sinon `:udp_family`, IPv4 par défaut. La socket UDP et le résolveur la lisent
tous les deux au même endroit, parce qu'ils ne peuvent pas diverger sans casser
l'émission : une socket IPv4 et une destination AAAA n'envoient rien du tout,
le datagramme échouant sur `:eafnosupport`. La famille ne se devine donc jamais
depuis ce que la machine porte — un nœud IPv6 est un nœud dont le listener
nomme une adresse IPv6.

**Résolution.** `SIP.Resolver.resolve/2` demande d'abord l'enregistrement de la
famille du nœud et ne tente l'autre que sur `:nxdomain` : un nœud IPv6 ne part
pas vers une adresse v4 sans route. `srv_lookup/1` accepte un serveur DNS en
tuple à huit éléments et, sans clé `:nameserver`, prend le résolveur du système
— un `{8,8,8,8}` en dur, un nœud sans IPv4 ne le joint pas.
`get_dns_default_dns_server/0` laisse `:nameserver` vide plutôt que d'échouer
quand `/etc/resolv.conf` ne se lit pas ou porte une adresse à identifiant de
zone.

**Ce qui est déjà juste, à ne pas refaire.** ExSDP déduit la famille du tuple :
`MediaServer.Mendooze.Sdp.build/1` avec une adresse v6 rend `o=` et `c=` en
`IN IP6` (mesuré). `Sdp.parse_media_candidate/1` lit `rtp://[::1]:22000` et rend
l'hôte sans crochets. `Sdp.ws_url_attribute/1` conserve les crochets, ce qu'une
URL WebSocket exige. `SIP.NetUtils.ip2string/1` et `parse_address/1` sont
agnostiques.

**Trou connu, refermé à l'étape 4.** La famille du nœud sort du bloc `udp`. Un
nœud dont le seul listener IPv6 est TCP, TLS ou WSS lit donc encore `:ipv4` :
ses résolutions sortantes retombent sur AAAA au lieu de le demander d'abord.
Rien ne casse — le repli répond — mais l'ordre est faux tant qu'une famille par
jambe n'existe pas.

Tests : `apps/elixip2/test/sip_ipv6_transport_test.exs`, et le refus du wildcard
dans `apps/kelixip/test/config_test.exs`.

**Recette.** Une machine de développement ne porte souvent aucune IPv6 globale
ni ULA, seulement une `fe80::` : un essai de bout en bout demande `::1` ou une
ULA (`fd00::/8`) ajoutée sur une interface, et un port qu'aucun autre serveur
SIP local ne tient. Critère de sortie : un REGISTER puis un appel de bout en
bout entre deux UA IPv6 à travers kelixip, avec un Contact et un Via relus par
le pair, et le média relayé annoncé en `IN IP6`.

**Validé en trafic le 2026-08-24** sur `wesh-controleur1`, un nœud dont les trois
listeners — `udp` 5060, `tls` 5061, `wss` 8443 — nomment la même adresse IPv6
publique. La socket UDP se lie bien en `udp6` sur cette adresse. Deux comptes
s'enregistrent, et un appel entre eux traverse le B2BUA : 407 sur l'INVITE,
INVITE sortant, 180, 200. Les deux pattes portent le SDP l'une de l'autre sans
serveur média.

Deux points du critère restent ouverts, et aucun ne tient au code de cette étape :

- **Le média relayé.** Le pool `[mediaserver.pool.*]` du nœud est vide, donc tout
  appel demandant du média est refusé et le `IN IP6` du SDP relayé n'est pas
  exercé.
- **La résolution par famille.** La patte sortante de l'essai vise un Contact
  WSS enregistré, dont l'hôte est résolu par la couche socket. `resolve/2` n'a
  donc pas été traversé. L'exercer demande une cible nommée en UDP, TCP ou TLS.

### Étape 3 bis — IPv6 du module MCU — livrée

Une conférence est joignable en IPv6, sur un nœud d'une seule famille. Hors des
sept étapes : le module MCU ouvre ses propres canaux de contrôle et ne passe pas
par `Kelix.MediaPool.checkout/1`, donc rien de l'étape 5 ne le couvre.

**Le canal de contrôle ne joignait aucune IPv6.** `:httpc` a l'option `ipfamily`
à `:inet` par défaut : une `url` de pool nommant un littéral IPv6 échouait en
`{:failed_connect, …, :nxdomain}` avant qu'un octet ne sorte du nœud, le nom
entre crochets partant vers un `:gen_tcp.connect/3` en IPv4 seule. L'option se
pose par profil `:httpc`, donc le module a désormais le sien
(`Kelix.Mod.Mcu.XmlRpc.profile_options/0`, en `:inet6fb4`) plutôt que de modifier
le profil par défaut du nœud depuis un module chargeable. Le long-poll
d'événements lit les mêmes options : même serveur, même question.

Côté serveur il n'y avait rien à faire : le mediaserver crée sa socket d'écoute
lui-même en `AF_INET6` avec `IPV6_V6ONLY=0` (`mcu/src/xmlrpcserver.cpp`) — une
socket pour les deux familles — parce que le `ServerCreate()` d'Abyss ouvrait un
`AF_INET`. `/mcu` et `/events/mcu` sont servis par ce serveur. À savoir :
`--internal-ip` restreint cette écoute au réseau interne, et si les deux profils
internes existent, **l'IPv4 l'emporte**.

**Le profil d'adressage est demandé, jambe par jambe.** `StartReceiving` et
`StartSending` portent un paramètre `profile` facultatif en fin de liste (API MCU
§6.7 bis), et `GetNetworkProfiles` (§6.7) dit ce que le serveur porte vraiment.
Les deux existent et sont implémentés côté serveur ; kelixip ne les employait pas,
donc toute jambe obtenait le profil par défaut du serveur — `publicv4` sauf
`--default-profile`. Un appelant IPv6 recevait donc une adresse IPv4 et aucun
média. Le détail de la règle est dans
[DESIGN-MCU.md](DESIGN-MCU.md#61-the-address-a-leg-announces) ; l'essentiel :

- **l'offre** dit les familles où le pair peut recevoir : c'est la permission. Ses
  deux endroits sont lus, le `c=` de la média **et** chaque `a=candidate`. Le `c=`
  seul suffit hors ICE ; sous ICE il porte la candidate par défaut que le pair a
  élue (RFC 8839 §5.1), souvent une adresse privée de VPN ou de LAN, alors que
  l'adresse publique où il répondrait aussi est une ligne plus bas ;
- **l'adresse locale par laquelle l'appel est arrivé** dit laquelle de nos
  interfaces ce pair sait joindre : c'est la préférence, à l'intérieur de la
  permission. C'est l'adresse que porte déjà le Contact de la jambe, et le
  framework la passe à tout adaptateur (`local_ip:`). Elle ne fait que réordonner
  ce que l'offre autorise : annoncer la famille de notre listener à un pair qui ne
  l'a pas offerte, c'est du média envoyé nulle part ;
- **le serveur média** dit les profils qu'il porte (`GetNetworkProfiles`) : c'est
  la disponibilité. La famille du nœud, elle, ne décide rien — elle serait juste
  pour une jambe et fausse pour l'autre sur la topologie même qui justifie tout
  ceci ;
- le profil se fixe **une fois** par jambe, comme le serveur l'exige, et une
  renégociation réemploie celui de la jambe ;
- une intersection vide **fait échouer l'appel**. Jamais de repli : il enverrait
  le média par la mauvaise interface sans que rien ne le dise ;
- un serveur qui ignore la notion est appelé exactement comme avant, sans
  paramètre — le même chemin de montée de version que le verdict codec.

Seuls les profils publics sont demandés. Le côté du réseau est l'étape 6 : la
famille se déduit de l'adresse locale, le `tag` d'un `[[listen]]` n'est pas encore
lu.

**Le trou noir IPv6 se lit enfin.** `c=IN IP6 ::` (RFC 6157 §4) est la mise en
attente historique d'un pair IPv6, et trois copies de cette lecture ne
connaissaient que `0.0.0.0` — donc une pause de plus de dix secondes lisait comme
une patte morte et raccrochait un appel sain. La lecture est maintenant unique
(`MediaServer.SdpTools.blackholed?/1`), et les trois appelants y délèguent : le
chien de garde du module MCU, celui de l'adaptateur JSR-309, et la détection de
mise en attente du B2BUA.

**Une faute XML-RPC n'est plus une perte de transport.** Le client marquait le
serveur média `down` sur toute erreur autre qu'applicative, faute comprise. Un
serveur qui répond « méthode inconnue » à `GetNetworkProfiles` à chaque connexion
aurait donc battu indéfiniment.

Tests : `apps/kelix_modules/test/mcu_ipv6_test.exs` (le canal sur `::1` avec un
vrai socket, la découverte des profils, le profil des deux familles, le navigateur
qui offre les deux, l'adresse locale qui tranche, le refus franc, le serveur
ancien, la pause `::`) et `blackholed?/1` / `peer_families/1` dans
`apps/elixip2/test/mendooze_sdp_test.exs`.

**Trou connu, côté serveur.** Le texte temps réel sur WebSocket ne marche pas en
IPv6 : le mediaserver construit l'URL qu'il rend en `scheme://host:port` sans
crochets (`multiconf.cpp`), donc une adresse annoncée IPv6 donne
`ws://fd00::1:9090/…`, qui se relit hôte `fd00`, port 80. L'audio et la vidéo ne
sont pas touchés.

**Recette.** Un nœud IPv6 avec un `[mediaserver.pool.*]` dont l'`url` nomme une
adresse IPv6, et un serveur média démarré avec une adresse publique v6
(`--default-profile publicv6` est alors obligatoire : le défaut historique
`publicv4` indisponible refuse le démarrage). Critère de sortie : deux clients
IPv6 dans la même conférence, audio et vidéo relayés, `c=IN IP6` dans les deux
réponses, et le journal du canal listant `publicv6` comme profil disponible.

### Étape 4 — Wildcard et dual-stack — livrée

Un nœud entend et parle les deux familles en même temps.

#### Trois écritures de `addr`, une seule ne nomme pas de famille

```toml
addr = "0.0.0.0"   # toutes les interfaces IPv4
addr = "::"        # toutes les interfaces IPv6
                   # absent : toutes les interfaces des deux familles
```

Un `addr` absent vaut `nil`, pas `"0.0.0.0"` : cette chaîne **est** une adresse
IPv4, et l'exploitant qui l'écrit demande de l'IPv4. Seul le silence peut vouloir
dire les deux. `Kelix.Listener.Supervisor` déplie alors le bloc en un enfant par
famille, et `status/0` rend le wildcard que chaque enfant a réellement lié, pas
la ligne de config.

Uniquement les familles dont l'hôte porte une adresse annonçable. Un listener
écrit une adresse locale dans son Via et son Contact : lier une famille que
l'hôte n'a pas s'arrête en `:networkdown` et fait échouer le démarrage — ce qui,
sur un hôte v4 seul, serait toute config ne nommant pas d'adresse. Là, rien ne
change.

#### Une socket UDP par famille

Un datagramme ne sort que par une socket de la famille de sa destination ;
l'autre répond `:eafnosupport`. Le nom d'instance d'un transport non fiable porte
donc la famille — `"UDP_ipv4"`, `"UDP_ipv6"` — et
`SIP.Transport.Selector.unreliable_instance_name/2` est le seul endroit qui
l'écrit, pour que le listener qui enregistre et le sélecteur qui cherche ne
puissent pas diverger. La famille se lit sur l'adresse de destination résolue.

Deux sockets distinctes plutôt qu'une socket v6 dual-stack. Deux raisons, pas
une : les adresses mappées `::ffff:a.b.c.d` polluent tout ce qui écrit une
adresse dans un message, et surtout une socket v6 dual-stack **prend aussi le
port v4**, donc la seconde liaison de la paire revient en `:eaddrinuse`. C'est
`ipv6_v6only` qui rend le port partagé possible.

`SIP.Transport.UDP.init/1` accepte une forme de liaison explicite,
`{:bind, ip, port, opts}`, en plus de celle que lance le sélecteur,
`{dest_ip, dest_port}`, dont il ne lit que la famille. Le superviseur garde un
enfant `udp` par famille ; deux blocs d'une même famille se disputeraient un nom
d'instance, donc le second est ignoré avec un avertissement.

#### Ce que l'étape ne fait pas

- **`elixipp`** n'a pas de syntaxe d'adresse dans `--listen` et reste sur le
  wildcard IPv4.
- **L'ordre des requêtes DNS** reste celui de la socket UDP primaire
  (`SIP.NetUtils.preferred_family/0`, alimentée par le premier bloc `udp`). Les
  deux familles étant liées, cet ordre coûte au pire une requête de plus, plus un
  échec.

#### Conséquence à assumer

**Un appel IPv4↔IPv6 impose le relais média.** Il n'y a pas de passe-plat SDP
possible entre deux familles. C'est aussi ici qu'un profil réseau devient
distinguable par jambe en UDP (étape 5).

### Étape 5 — Profils réseau du média — livrée

Annoncer dans le SDP l'adresse du bon côté du réseau, en posant le paramètre
`profile` de JSR309 (`xmlrpc_jsr309_api.md` §6.7 bis et §6.7 ter). Prérequis de
tout appel IPv4↔IPv6 relayé.

**Livré** : l'adaptateur `MediaServer.Mendooze` interroge le serveur
(`GetNetworkProfiles`) à la connexion, chaque jambe dérive son profil et le pose
sur `EndpointStartReceiving` (6e) et `EndpointStartSending` (7e), la voie
texte/WS est réordonnée, et le pool relit les profils de chaque serveur à chaque
sonde de santé.

**Livré aussi** : les trois phases de la médiation. Le B2BUA résout son Peer avant
d'essayer (`b2bua_resolve/1`), marque chaque cible de son côté de réseau, et
`media_connect/0` demande alors au pool un serveur portant tous les profils en
jeu. Détail sous « Deux jambes, deux profils, un seul serveur » plus bas.

Y compris un endpoint par profil quand une chasse en traverse plusieurs. Voir
« Une jambe porte un profil » plus bas.

Le mediaserver porte jusqu'à quatre adresses — `publicv4`, `publicv6`,
`internalv4`, `internalv6` — déclarées par `--public-ip` et `--internal-ip`.
Chacune est un couple (adresse liée, adresse annoncée). Le contrôleur désigne
celle à employer, jambe par jambe. Un contrôleur qui ne pose pas ce paramètre
obtient toujours le profil par défaut : c'est l'état actuel de kelixip, et une
machine à deux adresses ne lui apporte donc rien.

#### Le listener porte le profil

- Chaque listener déclare une adresse explicite, IPv4 ou IPv6. La famille se
  déduit de l'adresse ; elle ne se déclare pas.
- Sans `tag`, l'adresse vaut le profil `publicv4` ou `publicv6`.
- Avec `tag = "internal"`, elle vaut `internalv4` ou `internalv6`.
- Un listener sans adresse explicite (`0.0.0.0`, `::`) ne porte aucun profil :
  ses appels prennent le profil par défaut du nœud.

#### Une jambe hérite du profil de l'adresse locale qu'elle emploie

La table `adresse locale → profil` se construit au démarrage depuis les blocs
`[[listen]]`. Une jambe lit son adresse locale par
`SIP.Transport.get_local_ip_port/1` — le `tp_pid` de son transport voyage dans
la R-URI de la requête entrante — donc la règle vaut dans les deux sens, entrant
comme sortant, sans plomberie nouvelle.

- TCP, TLS, WSS : une adresse locale par connexion, donc un profil par jambe.
- UDP : une seule socket par nœud tant que l'étape 4 n'est pas faite, donc **un
  seul profil UDP pour tout le nœud** — celui du bloc `udp`.

#### Le mediaserver est interrogé, jamais recopié

`GetNetworkProfiles` (§6.7 ter) rend les profils disponibles et celui par
défaut. La sonde de santé du pool ouvre déjà une connexion et la referme toutes
les 30 s : la découverte y prend place, et elle se rafraîchit d'elle-même quand
un mediaserver redémarre avec d'autres adresses. Aucune liste de profils n'est
écrite côté kelixip. Un adaptateur qui ne sait pas répondre — le mockup — ne
contraint rien.

#### La sélection du serveur média porte le profil

La sonde de santé du pool ouvre déjà une connexion toutes les 30 s : elle en
rapporte les profils, que `status/0` expose par entrée. Une sonde qui n'a pas pu
demander n'efface pas ce que la précédente avait appris — un serveur injoignable
est en panne, pas devenu sans adresse.

`Kelix.MediaPool.checkout/1` recevra les profils demandés — un par jambe, donc
souvent deux — et ne retiendra que les entrées `enabled`, saines **et** portant
**tous** ces profils ; le round-robin reste inchangé parmi les éligibles. Sans
serveur éligible, l'appel échoue en 503. Jamais de repli sur un autre profil : un
repli enverrait le média par la mauvaise interface sans que rien ne le signale.
Une entrée dont les profils sont inconnus ne satisfait aucune contrainte : on ne
lui demande donc jamais de profil, et elle reste éligible aux appels qui n'en
demandent pas.

#### Le profil est posé sur la jambe

Le serveur choisi voyage dans `:mediaserver_instance` (`%{module, url}`) et le
profil s'attache à la jambe, pas à la session : les deux jambes partagent le
serveur et non le profil. L'adaptateur le passe en dernier paramètre de
`EndpointStartReceiving` et `EndpointStartSending` — le même sur les deux, posé
avant que le port ne soit publié. L'adaptateur ne passe aujourd'hui aucun profil
et n'appelle jamais `GetNetworkProfiles`. Trois pièges du contrat :

- le paramètre est positionnel et sixième sur `EndpointStartReceiving`, donc
  `offer` doit être envoyé même vide ;
- un serveur qui refuse le profil fait échouer l'appel. Le repli vers la forme
  d'appel plus ancienne, légitime pour un `offer`, est interdit ici ;
- la voie texte/WS appelle aujourd'hui `GetMediaCandidates` avant
  `EndpointStartReceiving`. À réordonner : sinon l'URL publiée porte l'adresse
  du profil par défaut.

#### Deux jambes, deux profils, un seul serveur

Un B2BUA relaie à l'intérieur d'une seule session, et ses deux jambes portent
chacune leur profil. La médiation IPv4↔IPv6 est ce cas même : jambe entrante en
v6, jambe sortante en v4. Le serveur retenu doit donc porter les deux profils.

Le serveur est aujourd'hui choisi au routage — `Kelix.Router.overrides_for/1` le
pose en `mediaserver_instance` dans l'appdata de l'instance, avant même que le
script démarre. Il faut qu'il le soit quand les deux profils sont connus
ensemble. Or le profil de la jambe sortante se déduit de sa **cible résolue**, et
la cible d'un `b2bua_forward/3` n'est pas une adresse : c'est une liste d'URI, que
le B2BUA résout aujourd'hui **au moment de la tentative**, une par une
(`apply_ruri_policy/3`, et seulement pour `ruri: :keep`).

C'est donc le B2BUA, pas le routeur ni `media_connect/0`, qui porte la décision.
Il le fait en trois phases.

##### Phase 1 — résoudre le Peer avant d'essayer quoi que ce soit

`b2bua_forward/3` reçoit un `%SIP.B2bua.Peer{}`. Avant toute tentative, chaque
URI de `uris` est résolue : `destip`, `destport`, et le `tp_pid` quand un flux
existe déjà. `%SIP.Uri{}` porte déjà ces champs et `SIP.Uri.has_tp_info/1` sait
reconnaître une URI déjà résolue — une contact de registrar l'est.

**La résolution de cette phase n'est pas `SIP.Transport.Selector.select_transport/1`.**
Le sélecteur ne résout pas, il *lance* le transport : sur TCP, TLS ou WSS il
ouvre la connexion. Résoudre toute la liste avec lui ouvrirait une connexion vers
chaque cible d'un fork, y compris celles qui ne seront jamais essayées. Cette
phase s'arrête donc à `SIP.Resolver`, qui ne fait que du DNS ; le transport reste
lancé paresseusement, à la tentative.

##### Phase 2 — marquer chaque URI résolue de son profil réseau

La famille se lit sur l'adresse résolue. Le côté du réseau se lit sur son
appartenance :

- chaque listener `tag = "internal"` porte un ou plusieurs **sous-réseaux** ;
- une adresse de destination qui tombe dans l'un d'eux est `internal`, le reste
  est `public`.

Le sous-réseau est **auto-détecté par défaut**, et `:inet.getifaddrs/0` suffit :
il rend le masque à côté de l'adresse, en IPv4 comme en IPv6. Le sous-réseau
directement attaché à l'interface du listener s'en déduit sans lire la table de
routage — et la question d'écarter une passerelle par défaut ne se pose pas,
puisqu'une passerelle n'apparaît pas dans cette liste.

**L'auto-détection se force.** Une clé de listener énonce la liste des réseaux, et
quand elle est présente elle **remplace** ce qui aurait été détecté ; elle ne s'y
ajoute pas. Deux raisons, et la seconde suffit : un réseau interne joint par un
routeur n'est attaché à aucune interface et ne serait jamais détecté ; et une
détection qu'on ne peut que compléter est une détection qu'on ne peut pas
corriger — sur une machine dont l'interface porte un /16 alors que l'interne est
un /24, l'exploitant n'aurait aucun moyen de restreindre.

###### Le marquage : un champ `net_side` sur `%SIP.Uri{}`

Le résultat s'attache à l'URI résolue, dans **un** champ nouveau :

```elixir
net_side: :public | :internal | nil
```

Quatre décisions, dans l'ordre où elles se prennent.

**Il ne stocke que le côté, pas la famille.** La famille se lit déjà sur
`destip`, et `SIP.NetUtils.address_family/1` est le seul lecteur partout ailleurs
— le nommage d'instance du sélecteur, le transport UDP, le `local_profile/1` du
module MCU. La stocker ici en ferait une seconde source du même fait, et ce dépôt
a la cicatrice de ce motif : trois copies de la liste de codecs, cinq
redérivations de la durée de vie d'un REGISTER. Seule la moitié non déductible est
retenue, et le côté l'est : il dépend de la topologie du nœud, pas de l'adresse.

**Il ne porte pas le nom du profil serveur.** `"publicv4"` est du vocabulaire
JSR309 (§6.7 bis) ; l'écrire dans `%SIP.Uri{}` ferait dépendre la couche SIP du
nommage du serveur média. La traduction existe déjà au bon endroit, `profile_name/1`
dans les adaptateurs, contre le code qui parle au serveur. L'URI énonce un fait
de réseau ; l'adaptateur le traduit dans le mot du serveur.

**Il vit à côté de `destip`, `destport` et `tp_pid`.** Ces champs sont déjà la
grappe « routage résolu » et ne font déjà pas partie de l'identité textuelle de
l'URI. `serialize/1` construit la forme filaire depuis des champs nommés — scheme,
userpart, domain, port, params, hparams — donc un champ nouveau ne peut pas fuir
dans un message. Vérifié, pas supposé.

**Son défaut est `nil`, « non classé ».** Deux endroits seulement comparent un
`%SIP.Uri{}` entier dans les suites, tous deux contre un littéral de structure :
les deux côtés prennent le défaut, donc l'ajout ne casse rien.

Et pas `profile` : le nom est déjà pris sur `%SIP.B2bua.Peer{}`, où il désigne
l'échelle média (`:webrtc_required`, `:avp`, …), et `address_profile` est le mot
des adaptateurs pour le nom côté serveur. `net_side` dit ce qu'il contient et ne
se confond avec aucun des deux.

###### Qui classe

La classification a besoin des sous-réseaux internes du nœud, qui sont de la
configuration kelixip et non une donnée du framework. Elle arrive donc comme une
clé d'app env, écrite par `Kelix.Config.apply_app_env/1` et lue par **une** seule
fonction du framework — le motif de `:udp_local_addr`. Conséquence à assumer :
une part du `[network]` de l'étape 6 remonte ici, parce que la phase 2 ne peut pas
s'en passer. L'étape 6 garde ce qui lui reste en propre, `advertise`.

##### Phase 3 — choisir un serveur média qui porte les profils demandés

À la sortie de la phase 2, le Peer porte une liste d'URI résolues **et**
marquées. `Kelix.MediaPool.checkout/1` reçoit alors les profils demandés — celui
de la jambe entrante et ceux des cibles — et ne retient que les entrées
`enabled`, saines et portant **tous** ces profils. La sonde de santé du pool
connaît déjà les profils de chaque serveur (§6.7 ter) : elle les relit à chaque
cycle.

Deux cas particuliers, et ils sont la raison d'être de la phase :

- **des URI de profils différents dans la même liste.** On ouvre **un endpoint
  par profil**, et on supprime celui dont la mise en relation échoue. Cela suit
  le contrat serveur plutôt que de le contourner : le profil se fixe une fois par
  jambe (§6.7 bis), donc deux profils demandent deux endpoints, et
  `EndpointAttachToEndpoint` les veut dans une seule `MediaSession` — donc sur un
  seul serveur, ce que la contrainte du `checkout` garantit.
- **aucun serveur ne porte le profil d'une URI.** On éteint cette branche et on
  passe à l'URI suivante. Quand il n'en reste plus, l'appel échoue. Jamais de
  repli sur un autre profil : il enverrait le média par la mauvaise interface sans
  que rien ne le signale.

##### L'ordre qu'un script énonce

Le serveur média était choisi avant que la cible existe — `media_connect()` à la
ligne 47 de `webrtc-gw.exs`, `b2bua_forward` à la 60. Cet ordre portait sa propre
raison : sans serveur média il n'y a rien pour répondre à l'appelant, et l'INVITE
sortant n'a pas de corps à porter. On ne pouvait donc pas à la fois répondre avant
de forwarder **et** choisir le serveur en connaissant la cible.

Un verbe résout la contradiction en séparant les deux :

```elixir
b2bua_resolve(peer)                                  # où va l'appel
media_connect()                                      # puis qui le porte
b2bua_forward(req, b2bua_resolved_peer(), @media)
```

`b2bua_resolve/1` fait la phase 1 et la phase 2 : chaque cible reçoit son adresse
et son `net_side`, avant que quoi que ce soit soit tenté. `media_connect/0` lit
alors `resolved_profiles/1` et demande au pool un serveur portant **tous** ces
profils.

**Le verbe n'est jamais obligatoire**, et c'est ce qui rend le changement additif.
`b2bua_forward/4` face à un Peer non résolu :

| Le Peer… | ce qui se passe |
|---|---|
| est résolu | ses rungs servent, rien n'est résolu deux fois |
| ne l'est pas, mais les **mêmes** cibles l'ont été | cette résolution est adoptée |
| ne l'est pas, et rien ne l'a été | résolu à la tentative, comme avant le verbe |
| ne l'est pas, et d'**autres** cibles l'ont été | résolu à la tentative, **avec un avertissement** |

Le dernier cas est le seul piège : le serveur média a été choisi pour un appel qui
part ailleurs. Il est dit à voix haute plutôt que débogué comme du média qui
arrive sur la mauvaise interface.

##### Une jambe porte un profil, et c'est celui de sa cible

Une jambe que le nœud **place** n'a pas d'adresse locale : `local_ip:` dit laquelle
des nôtres un pair a atteinte, et il n'y en a pas encore. Ce qui décide est
l'interface du **callee** — c'est elle qui fixe par laquelle des nôtres le média
sort. Le framework la connaît depuis la cible résolue et la passe en option de
connexion, `address_profile:`, que les deux adaptateurs préfèrent à tout ce qu'ils
pourraient dériver.

Sans elle, la jambe sortante ne demandait rien et le serveur appliquait son défaut
— faux pour tout callee v6 ou interne dès que le serveur porte deux adresses.

##### Un endpoint par profil, au fil de la chasse

L'adresse de la ligne `c=` est figée à la création de l'endpoint : elle ne se
renégocie pas en place. Une chasse qui quitte une cible v4 pour une v6 a donc
besoin d'un **autre** endpoint — exactement comme le redémarrage de l'échelle
d'offres, qui ferme et reconstruit déjà (`regenerate_offer/3`). Les deux passent
par le même mécanisme, et c'est pourquoi c'est une seule fonction :
`restart_ladder/3` reconstruit quand l'échelle repart **ou** quand le rung suivant
change de profil d'adressage.

Un endpoint **au fil de la chasse** plutôt que tous d'avance, puis les perdants
supprimés : moins de ressources serveur, aucun chemin de suppression à se
tromper, et cela se compose avec le redémarrage d'échelle déjà là. La `%Leg{}`
retient le profil sur lequel son endpoint a été construit (`addr_profile`), ce qui
rend la décision lisible et testable.

Un rung qui échoue à se reconstruire garde l'offre précédente et le dit : une
chasse qui s'arrête parce que le serveur média a hoqueté perdrait un appel qui
avait d'autres endroits où aller.

**Un rung est une offre.** `SIP.Dialog.fork_branch/3` prend un seul corps pour
autant de branches qu'il compose, donc deux branches d'un même rung ne peuvent pas
porter deux lignes `c=`. Un rung dont les cibles diffèrent est donc composé sur la
première, avec un avertissement qui dit quoi faire : mettre les cibles d'interfaces
différentes dans des **rungs** différents, et chacune est alors servie sur la
sienne. C'est une propriété du forking, pas une limite d'implémentation.

##### La couture, parce que le framework ne peut pas appeler le pool

`Kelix.MediaPool` est une surface kelixip et `media_connect/0` est du framework.
La sélection est donc **injectée** — `:elixip2, :mediaserver_selector` vaut
`{module, fonction}`, appelée avec les paires `{famille, côté}` —, comme l'est le
transport de test unitaire. Absente, ou rien de résolu, et le choix se fait comme
avant.

Et le croisement famille × côté → nom du profil serveur est écrit **une** fois,
dans `MediaServer.profile_name/2`. Trois copies d'un tableau de quatre entrées,
c'est ainsi que la liste de codecs est devenue fausse.

#### Hors périmètre de cette étape

- **La MCU.** Le module ouvre ses propres canaux de contrôle vers les serveurs du
  pool et ne passe pas par `checkout/1` : il pose son profil lui-même, par jambe.
  Le côté vient de l'adresse locale que le pair a atteinte, la famille de son
  offre — donc une conférence atteinte depuis un listener `internal` annonce
  l'adresse interne.
- **La classification d'un correspondant par son adresse.** Ici c'est le
  listener qui décide, pas le pair. Une jambe sortante hérite du côté de la
  jambe entrante, et sa famille de l'adresse résolue de la cible. Le reste est
  l'étape 6.

#### Effet d'exploitation à connaître

Dès qu'un `--internal-ip` est donné au mediaserver, son API XML-RPC ne répond
plus que sur l'adresse interne : la loopback cesse d'être une porte d'entrée, et
l'`url` des entrées `[mediaserver.pool.*]` doit viser l'adresse interne. Avec
une adresse interne v4 et une v6, l'API n'écoute qu'en IPv4.

### Étape 6 — `advertise`

Les besoins « médiation interne/externe » et « IP interne nattée 1:1 ».

#### `advertise` — livrée : une interface à deux faces

`advertise = "<ip>"` par listener nomme la **face publique** de `addr`. C'est la VM
nattée 1:1, où l'exploitant connaît l'adresse publique — une EIP AWS ne bouge pas —
et où rien sur la machine ne peut la déduire.

**Ce n'est pas une substitution plate**, et c'est le point qui a demandé deux
essais. La même interface sert les deux côtés : une UA privée et une UA publique
arrivent sur la même socket, le NAT ayant réécrit la destination. Chacune doit
voir la face qu'elle peut joindre.

| le pair est… | ce qu'il reçoit |
|---|---|
| `public` | l'alias |
| `internal` | l'adresse liée |
| inconnu | l'alias — un nœud natté sert surtout l'extérieur |

**La substitution ne vit pas dans le transport.** Il continue de rapporter
l'adresse qu'il **lie réellement** : la couche média la lit pour choisir une
interface, et une comparaison contre une vraie socket doit tenir. Elle a lieu au
moment de **publier**, en un seul endroit — `SIP.Transport.publish_ip/2` —, depuis
une table de nœud `:advertise_map` (`adresse liée => alias`) écrite par
`Kelix.Config.apply_app_env/1`.

Trois en-têtes la traversent, chacun avec le pair qu'il connaît déjà :

- **Contact** — `build_contact_uri/3`. Le pair vient de `ruri.destip` : la
  destination résolue pour une requête sortante, la source estampillée par le
  transport pour une réponse. **Le même champ**, d'où une seule clause.
- **Via** — `transaction_start_common`. Le `sent-by` est là où reviennent les
  réponses de cette transaction, donc il se publie comme un Contact.
- **Route et Record-Route** — **rien à faire.** elixip les *lit* (route set d'une
  réponse pour bâtir l'ACK, `Path` d'un REGISTER) et n'en écrit jamais : un B2BUA
  est un UA sur chaque patte, il n'ajoute pas de Via de proxy et n'enregistre pas
  de route. Aucune adresse à nous n'y figure. Vérifié plutôt que supposé.

Deux contraintes, refusées au démarrage :

- **`addr` explicite exigée.** `advertise` nomme la face d'**une** adresse ; un
  listener wildcard couvre toutes les interfaces de sa famille, et la substitution
  est indexée sur l'adresse que le transport rapporte lier — jamais `0.0.0.0`. La
  clé ne serait jamais trouvée, donc la configuration est refusée plutôt
  qu'acceptée et silencieusement inerte.
- **Même famille que `addr`** : un Via et un Contact de l'autre famille nomment une
  adresse qu'aucun pair de ce listener ne peut rappeler.

#### `[network] internal` — non retenue

La classification par préfixe est livrée depuis l'étape 5, mais **par listener** :
`tag = "internal"` et son `networks` optionnel, le nœud prenant l'union.

Cette étape prévoyait une section `[network]` au niveau du nœud, contre l'écriture
par listener, avec deux objections : la liste se recopierait autant de fois qu'il
y a de listeners, et deux listeners pourraient se contredire. Aucune ne tient sur
ce qui a été livré — la détection automatique fait qu'il n'y a rien à recopier, et
l'union ne peut pas se contredire.

Ajouter `[network]` maintenant donnerait deux façons d'énoncer la même chose, donc
une question de préséance à trancher et à documenter, pour zéro capacité de plus.
Un nœud sans listener `internal` n'a d'ailleurs pas de côté interne à annoncer :
la clé n'aurait rien à décrire.

#### Le second axe — livré : le côté vient du pair

Le cas qui l'a tranché : **une seule interface**, privée, nattée 1:1 avec une
publique, une UA dans le réseau privé et une UA sur Internet. Les deux atteignent
la **même socket** — le NAT a réécrit la destination — donc `local_ip` vaut
`10.0.0.5` pour les deux. Notre adresse ne discrimine rien : elle n'est pas
fausse, elle est **muette**. L'adresse source du pair est la seule preuve qui
reste.

Le profil se scinde donc en deux moitiés, chacune avec sa source, et
`MediaServer.leg_profile_name/1` les assemble en un seul endroit :

| moitié | source | pourquoi |
|---|---|---|
| famille | `local_ip` | vérité de routage : le pair a atteint cette adresse |
| côté | `peer_ip` | seule preuve du côté quand une interface a deux faces |

`peer_ip` est l'adresse source de la requête entrante, que le transport a déjà
estampillée dans `ruri.destip` en la recevant — lue dans la même structure que
`tp_pid`, donc elle ne peut pas en dériver. Sans elle — une jambe qu'on place, un
transport sans pair — le côté retombe sur `local_ip`, ce dont il était déduit
avant.

**`advertise` ne suffisait pas pour ce cas** : c'est une substitution plate, elle
donnerait l'adresse publique aux deux UA. Elle reste juste pour un nœud dont
l'interface ne sert **que** des pairs extérieurs.

Et la substitution SDP n'est pas écrite ici : le mediaserver la fait. Chaque
profil porte deux adresses, liée et annoncée, et il accepte la **même adresse
liée** dans `publicv4` et `internalv4` — vérifié par deux tests ajoutés à sa
suite (`test_addressprofiles.cpp`, 551 tests verts), pas par lecture. La table ne
lie rien : le bind a lieu par session RTP, chacune avec son couple de ports.

```
--public-ip 10.0.0.5 --nat 203.0.113.9 --internal-ip 10.0.0.5
```

**Conséquence d'exploitation** : dès qu'un `--internal-ip` est donné, l'API de
contrôle XML-RPC ne répond plus que sur l'adresse interne. Les entrées
`[mediaserver.pool.*]` doivent viser `10.0.0.5`, plus la loopback.

Le Contact et le Via portent la même discrimination — voir « `advertise` » plus
haut. Un BYE de l'UA publique visant `10.0.0.5` n'arriverait nulle part.

#### Pas de client STUN — hors périmètre

`SIP.Stun` sait uniquement reconnaître et décoder l'en-tête d'un message entrant ;
son moduledoc énumère ce qui manque (attributs, XOR-MAPPED-ADDRESS, encodage,
MESSAGE-INTEGRITY), et son seul appelant est un `Logger.debug`. Une découverte
automatique de l'adresse publique demande donc d'écrire un client complet,
retransmissions comprises (RFC 5389 §7.2.1).

C'est un chantier facultatif, et `advertise` le rend rarement nécessaire : il
ajouterait une dépendance réseau au démarrage et un mode de panne pour la même
information. Le mediaserver fait le même choix avec `--public-ip`.

### Étape 7 — mTLS

Le listener TLS ne passe ni `verify` ni `cacertfile` : ajouter `verify_peer`,
`fail_if_no_peer_cert` et le CA par listener est petit.

Le vrai trou est de l'autre côté. La jambe **sortante** se connecte avec
`verify: false`. Un mTLS servi par un client qui ne vérifie rien est un
théâtre : la vérification du certificat sur la jambe sortante précède le mTLS,
et elle n'attend pas cette étape pour valoir la peine.

Voir <https://www.cloudflare.com/fr-fr/learning/access-management/what-is-mutual-tls/>.
