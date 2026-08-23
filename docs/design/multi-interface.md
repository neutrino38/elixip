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

- **`addr`** ne change pas de forme : `Kelix.Config` valide déjà l'adresse par
  `:inet.parse_address/1`, donc une IPv6 y passe. Une adresse explicite est ce
  qui donne un profil réseau au listener (étape 5) ; un listener wildcard
  (`0.0.0.0`, `::`) prend le profil par défaut du nœud.
- **`tag`** n'a qu'une valeur utile : `"internal"`. Le côté public est le défaut
  déduit de l'absence de clé. `"public"` reste accepté sans effet. Introduit à
  l'étape 5.
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
et 5, la médiation interne/externe à l'étape 6.

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

### Étape 3 — Un listener IPv6 explicite

Une jambe, une famille, pas de dual-stack. Les blocs `[[listen]]` ne changent
pas : `addr` accepte déjà une IPv6.

OTP 26 déduit la famille de l'option `{:ip, tuple}` : `:gen_tcp.listen/2`,
`:gen_udp.open/2` et `:ssl.listen/2` acceptent une adresse IPv6 sans `:inet6`
(mesuré). Un listener TCP, TLS ou WSS dont `addr` nomme une IPv6 lie donc déjà
correctement sa socket — ce qui manque est en amont (étape 1) et en aval
(étape 2).

**UDP est l'exception.** `SIP.Transport.UDP` ouvre sa socket par
`Socket.UDP.open(port, mode: :active)`, qui ignore l'adresse de bind et ouvre en
IPv4. Passer la famille et l'adresse à l'ouverture est le seul travail de bind
de cette étape.

**Résolution.** `SIP.Resolver.resolve/2` tente A, puis AAAA seulement sur
`:nxdomain` : sur un nom dual-stack, A gagne toujours, et sur un nœud IPv6-only
la jambe sortante part vers une adresse v4 injoignable. La règle de cette
étape : la famille demandée découle de celle de l'adresse locale du nœud. Et
`srv_lookup/1` n'accepte un serveur DNS que sous forme de tuple à quatre
éléments, avec `{8,8,8,8}` en dur par défaut : un nœud IPv6-only ne résout aucun
SRV. Accepter un tuple à huit éléments, et prendre le résolveur du système par
défaut.

**Ce qui est déjà juste, à ne pas refaire.** ExSDP déduit la famille du tuple :
`MediaServer.Mendooze.Sdp.build/1` avec une adresse v6 rend `o=` et `c=` en
`IN IP6` (mesuré). `Sdp.parse_media_candidate/1` lit `rtp://[::1]:22000` et rend
l'hôte sans crochets. `Sdp.ws_url_attribute/1` conserve les crochets, ce qu'une
URL WebSocket exige. `SIP.NetUtils.ip2string/1` et `parse_address/1` sont
agnostiques.

**Recette.** Une machine de développement ne porte souvent aucune IPv6 globale
ni ULA, seulement une `fe80::` : un essai de bout en bout demande `::1` ou une
ULA (`fd00::/8`) ajoutée sur une interface, et un port qu'aucun autre serveur
SIP local ne tient. Critère de sortie : un REGISTER puis un appel de bout en
bout entre deux UA IPv6 à travers kelixip, avec un Contact et un Via relus par
le pair, et le média relayé annoncé en `IN IP6`.

### Étape 4 — Wildcard et dual-stack

La marche la plus haute.

`bind_addr(:all)` vaut `{0, 0, 0, 0}` dans les trois listeners, et
`resolve_localip(:all)` prend la première IPv4 : un listener sans `addr`
n'entend pas l'IPv6. `:all` cesse d'être une adresse IPv4.

**La socket UDP unique devient une socket par famille.** `Socket.UDP.open/2`
ignore l'adresse de bind, et `Kelix.Listener.Supervisor.drop_extra_udp/1` ignore
déjà tout bloc `udp` surnuméraire avec un avertissement : deux familles en UDP
demandent deux sockets, et le choix de la socket sortante devient une décision
du `SIP.Transport.Selector`.

Deux sockets distinctes plutôt qu'une socket v6 dual-stack : les adresses
mappées `::ffff:a.b.c.d` polluent tout ce qui écrit une adresse dans un message,
et le code écrit `:inet.ntoa/1` partout.

Conséquence à assumer : **un appel IPv4↔IPv6 impose le relais média**. Il n'y a
pas de passe-plat SDP possible entre deux familles.

C'est aussi ici qu'un profil réseau devient distinguable par jambe en UDP
(étape 5).

### Étape 5 — Profils réseau du média

Annoncer dans le SDP l'adresse du bon côté du réseau, en posant le paramètre
`profile` de JSR309 (`xmlrpc_jsr309_api.md` §6.7 bis et §6.7 ter). Prérequis de
tout appel IPv4↔IPv6 relayé : à faire avec l'étape 4, pas après.

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

`Kelix.MediaPool.checkout/1` reçoit le profil demandé et ne retient que les
entrées `enabled`, saines **et** portant ce profil ; le round-robin reste
inchangé parmi les éligibles. Aucun serveur éligible fait échouer l'appel (503).
Jamais de repli sur un autre profil : un repli enverrait le média par la
mauvaise interface sans que rien ne le signale.

#### Le profil est posé sur la jambe

Le profil voyage avec le serveur choisi dans `:mediaserver_instance`
(`%{module, url, profile}`), et l'adaptateur le passe en dernier paramètre de
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

#### Deux jambes, un seul serveur

Un B2BUA relaie à l'intérieur d'une seule session. Si les deux jambes n'ont pas
le même profil — la médiation IPv4↔IPv6 de l'étape 4 — le serveur retenu doit
porter les deux. Le serveur est aujourd'hui choisi au routage, avant que la
cible sortante ne soit connue : la contrainte posée au `checkout` est donc celle
de la jambe entrante, et la jambe sortante vérifie le serveur déjà retenu. Son
profil manque : l'appel échoue en 503.

#### Hors périmètre de cette étape

- **La MCU.** Le module ouvre ses propres canaux de contrôle vers les serveurs
  du pool et ne passe pas par `checkout/1` : les conférences gardent le profil
  par défaut. Conséquence assumée : une conférence atteinte depuis un listener
  `internal` annonce l'adresse publique.
- **La classification d'un correspondant par son adresse.** Ici c'est le
  listener qui décide, pas le pair. Une jambe sortante hérite du côté de la
  jambe entrante, et sa famille de l'adresse résolue de la cible. Le reste est
  l'étape 6.

#### Effet d'exploitation à connaître

Dès qu'un `--internal-ip` est donné au mediaserver, son API XML-RPC ne répond
plus que sur l'adresse interne : la loopback cesse d'être une porte d'entrée, et
l'`url` des entrées `[mediaserver.pool.*]` doit viser l'adresse interne. Avec
une adresse interne v4 et une v6, l'API n'écoute qu'en IPv4.

#### À trancher avant de coder

Deux jambes d'une même session peuvent-elles porter deux profils différents ? Le
contrat serveur dit « un profil par jambe » ; il ne dit pas si deux profils
coexistent dans une session. C'est exactement le cas de la médiation IPv4↔IPv6.

### Étape 6 — `[network]` et `advertise`

Les besoins « médiation interne/externe » et « IP interne nattée 1:1 ». C'est
ici qu'un correspondant se classe par son adresse, et qu'un appel qui
**traverse** d'un côté à l'autre devient possible.

- **`[network] internal = [<préfixes>]`**, au niveau du nœud. Toute adresse de
  ces préfixes est interne ; le reste est externe. La reconnaissance des portées
  de l'étape 2 sert de base.
- **`advertise = "<ip>"`** par listener : l'adresse publiée dans la
  signalisation quand elle diffère de l'adresse liée. C'est le cas de la VM
  nattée 1:1, où l'exploitant connaît l'adresse publique.
- La table de l'étape 5 gagne son second axe : le côté ne vient plus seulement
  du listener de la jambe entrante, mais de la classification du correspondant.
  Le `checkout` du pool gagne alors à se déplacer après la résolution de la
  cible, les deux profils étant connus ensemble.
- **Un client STUN n'existe pas.** `SIP.Stun` sait uniquement reconnaître et
  décoder l'en-tête d'un message entrant ; son moduledoc énumère ce qui manque
  (attributs, XOR-MAPPED-ADDRESS, encodage, MESSAGE-INTEGRITY), et son seul
  appelant est un `Logger.debug`. Une découverte automatique de l'adresse
  publique demande donc d'écrire un client complet, retransmissions comprises
  (RFC 5389 §7.2.1). C'est un chantier facultatif, et `advertise` statique le
  rend rarement nécessaire.

### Étape 7 — mTLS

Le listener TLS ne passe ni `verify` ni `cacertfile` : ajouter `verify_peer`,
`fail_if_no_peer_cert` et le CA par listener est petit.

Le vrai trou est de l'autre côté. La jambe **sortante** se connecte avec
`verify: false`. Un mTLS servi par un client qui ne vérifie rien est un
théâtre : la vérification du certificat sur la jambe sortante précède le mTLS,
et elle n'attend pas cette étape pour valoir la peine.

Voir <https://www.cloudflare.com/fr-fr/learning/access-management/what-is-mutual-tls/>.
