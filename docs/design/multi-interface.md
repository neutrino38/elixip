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

## API XMLRPC de Medooze

Le mediaserver Medooze 1.13.0 a été modifié pour supporter IP V6 et la désignation du type de réseau
Voici la doc de l'API https://github.com/neutrino38/mediaserver/blob/master/design/xmlrpc_jsr309_api.md

## Phase d'implémentation

### Phase 1

Support d'IP V6 dans kelixip. Pas de modif des blocs [[listen]]

### Phase 2

Support mixte IP V6 et IP V4 sur deux listener. Appel IPV4 vers IPV6. Pas de modif des blocs [[listen]]

### Phase 3

Annoncer dans le SDP l'adresse du bon côté du réseau, en posant le paramètre
`profile` de JSR309 (`xmlrpc_jsr309_api.md` §6.7 bis et §6.7 ter).

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
- UDP : une seule socket par nœud, liée à toutes les interfaces, donc **un seul
  profil UDP pour tout le nœud** — celui du bloc `udp`. C'est cohérent avec la
  limite déjà en place : les blocs `udp` surnuméraires sont ignorés. Lever cette
  limite est le travail de la phase 2.

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
avant que le port ne soit publié. Trois pièges du contrat :

- le paramètre est positionnel et sixième sur `EndpointStartReceiving`, donc
  `offer` doit être envoyé même vide ;
- un serveur qui refuse le profil fait échouer l'appel. Le repli vers la forme
  d'appel plus ancienne, légitime pour un `offer`, est interdit ici ;
- la voie texte/WS appelle aujourd'hui `GetMediaCandidates` avant
  `EndpointStartReceiving`. À réordonner : sinon l'URL publiée porte l'adresse
  du profil par défaut.

#### Deux jambes, un seul serveur

Un B2BUA relaie à l'intérieur d'une seule session. Si les deux jambes n'ont pas
le même profil — la médiation IPv4↔IPv6 de la phase 2 — le serveur retenu doit
porter les deux. Le serveur est aujourd'hui choisi au routage, avant que la
cible sortante ne soit connue : la contrainte posée au `checkout` est donc celle
de la jambe entrante, et la jambe sortante vérifie le serveur déjà retenu. Son
profil manque : l'appel échoue en 503.

#### Hors périmètre de cette phase

- **La MCU.** Le module ouvre ses propres canaux de contrôle vers les serveurs
  du pool et ne passe pas par `checkout/1` : les conférences gardent le profil
  par défaut. Conséquence assumée : une conférence atteinte depuis un listener
  `internal` annonce l'adresse publique.
- **La classification d'un correspondant par son adresse** (`network`). En phase
  3 c'est le listener qui décide, pas le pair. Une jambe sortante hérite du côté
  de la jambe entrante, et sa famille de l'adresse résolue de la cible.

#### Effet d'exploitation à connaître

Dès qu'un `--internal-ip` est donné au mediaserver, son API XML-RPC ne répond
plus que sur l'adresse interne : la loopback cesse d'être une porte d'entrée, et
l'`url` des entrées `[mediaserver.pool.*]` doit viser l'adresse interne. Avec
une adresse interne v4 et une v6, l'API n'écoute qu'en IPv4.

#### À trancher avant de coder

Deux jambes d'une même session peuvent-elles porter deux profils différents ? Le
contrat serveur dit « un profil par jambe » ; il ne dit pas si deux profils
coexistent dans une session. C'est exactement le cas de la médiation IPv4↔IPv6.

### Phase 4

Support interface unique nattée avec une IP interne nattée sur une IP externe
(cas VM AWS). Autodétection par STUN.

### Phase 5

Support procédure mTLS
https://www.cloudflare.com/fr-fr/learning/access-management/what-is-mutual-tls/
