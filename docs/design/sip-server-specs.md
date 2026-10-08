# SIP Server specs

Je voudrais introduire la notion de serveur SIP dans kelixip qui ressemble un peu à un
endpoint dans PJSIP https://docs.pjsip.org/en/latest/pjsua2/using/endpoint.html
ou un peer SIP.

# Prologue: letting a script trust an inbound P-Asserted-Identity

A prerequisite, in the framework (`elixip2`), before the server entity itself.

Today an inbound PAI can never leave the node: `prepare_forwarded_request/2` strips
it on every forward and writes back only `sip_ctx.asserted_identity`
(DESIGN-AUTH.md, "P-Asserted-Identity"). The pieces to re-assert it already exist
but are not joined: `SIP.Msg.Ops.asserted_identity/1` reads the inbound PAI as a
`%SIP.Uri{}` (display name kept), and `SIP.Context.assert_identity/2` (FSL macro
`assert_identity/1`) records a `%SIP.Uri{}` as the identity to assert.

What to add:

- `SIP.Context.trust_asserted_identity(ctx, req)`: record the PAI of `req` as
  `asserted_identity`. A request with no parsable `sip:` PAI leaves the context
  unchanged: an identity proved earlier (a digest verdict) is not withdrawn by the
  absence; `assert_identity(nil)` remains the explicit withdrawal.
- The FSL macro `trust_asserted_identity(req)` next to `assert_identity/1` in
  `SIP.Context.__using__`, so a script writes
  `{_slug, _peer} -> trust_asserted_identity(req)` after `matches_server/1`.
- Tests in `msg_ops_b2bua_test.exs`: PAI taken with its display name; the forward
  then asserts it; no PAI keeps an earlier identity.
- DESIGN-AUTH.md §4.2: replace "it arrives as `[domain] trusted_peers`" with this
  verb. The trust decision is the script's, not configuration, and the guarantee
  holds: the inbound header still never crosses a leg boundary, and the only PAI
  that leaves is one recorded in the context.

The framework function must not name `Kelix.Mod.SipServers`: `elixip2` knows
nothing of kelixip.

# Objectifs

Pouvoir traiter les cas suivants :

- kelixip agit en tant que SIP proxy / registrar et interagit avec des serveur d'application
  SIP (ex : un ACD externe). Il peut envoyer et recevoir des appels vers / depuis ce serveur.
  Il peut tester si le serveur est debout en envoyant des OPTIONS.

- kelixip doit s'enregistrer auprès d'une infrastructure externe avec un compte identifié
  comme un trunk SIP individuel. Il peut envoyer des OPTIONS pour vérifier l'état et/ou 
  répondre à des OPTIONS envoyé par l'infra. On peut envoyer des appels, recevoir des appels
  présence et chat.

- kelixip agit en tant que serveur SIP et intéragit avec un proxy / registrar extérieur.
  par exemple, c'est un ACD qui traite des appels venant du proxy et renvoie les appels vers
  ce proxy.

# Nouvelles entités dans kelixip

L'entité centrale pour définir un serveur est : ̀ SIP.Server`

C'est une entité en mémoire mais persistée (comme les conférences pou le module MCU). Il est
défini par :

- un slug qui doit être au format hostname
- une ou deux SIP uri (primary_uri, backup_uri)
- use_dns_srv 
- send_keepalive
- max_sessions
- ha_mode = failover | loadsharing
- initiate_connection = true | false # Qui initie la connexion dans le cas d'un transport connecté ?


Il est typé :
- sip-application 
- sip-proxy
- sip-trunk

On peut lui attacher un script UAC
- register_script =

On peut lui attacher des données d'identifications chiffrées
- authusername
- authpassword (stockée sous forme de ha1 MD5 / sha256)

Il a plusieurs états en mémoire

- remote IPs -> available (selons OPTIONS reçues / envoyées)
- registration_state

Il est attaché à un domaine. Ce n'est pas un objet global.

## Différences de comportements en fonction du type

### sip-application

Dans ce cas, le serveur agit comme un 'trusted' kamailio / un peer asterisk.
Attention, c'est le script du domaine qui va déterminer le comportement.
La ou les URI qui définisse le serveur n'ont pas de userpart

Pas de réécriture du From dans le cas d'un appel vers le sip application.

### sip-proxy

A priori, même comportement plus
on peut définir des AOR attachés à ce proxy et demander à ce que ces AOR soient
sondés par des OPTIONS. Chacun des AOR se comporte alors un peu comme un AOR local.
propriété spéciale 

ext_domain = 
ext_domain_aliases = 
probe_remote_aors = true | false
subscribe_presence = true | false

pour traduire modifier les requests URI et les To correctement. Attention, on ne peut
pas définir plus d'un peer par domain kelixip qui porte le même domaine.

envoi du PAI si l'appelant est identifié.
réception du PAI

### sip trunk

Il est défini par une URI complète : 

uri = sip:user@sip_server:port;transport=

S'il faut reformater car sip_server != domaine
on utilise 

ext_domain =

C'est le seul pour lequel on peut ajouter un script register (ou un comportement interne 
est-il plus approprié ?)
C'est le seul qui répond automatiquemment à un challenge du distant (voir SBB)
La R-URI et le To sont remplacés


# Module et fonctions

Nouveau module kelixip chargeable `Kelix.Mod.SipServers`

## Management

- commandes kelictl, API

- de quoi construire une interface graphique de gestion des serveurs dans kelescope

## Functions

### matches_server(req)

Cette fonction examine une requête entrante et détermine si elle vient d'un des serveur SIPs 
définis dans le domaine en comparant le transport attaché à la requpete et en les comparant avec ceux attendus par les IP / port / transport résolus pour le serveur.

Retourne { server-slug, %SIP.Peer{} } ou :no_match

Routing is unchanged. `Kelix.Router` still picks the domain from the R-URI host
(else the To host), then the script; `matches_server/1` is a predicate the invoked
script calls afterwards, not a routing step. A request from a server must therefore
reach a declared domain first: a trunk calling `sip:+331…@<our IP>`, or with the
operator's domain in the R-URI, only finds one if that IP or domain is listed in the
domain's `aliases`. Otherwise the Router answers 404 before any script runs. This is
configuration, not code.

Recognising a server is not trusting it. `matches_server/1` says where a request
comes from; the script decides what that is worth: reject it, challenge it, accept
it, and whether the received P-Asserted-Identity is forwarded. The module grants
nothing by itself. Keeping a received PAI goes through an explicit framework verb
called by the script, since `prepare_forwarded_request/2` drops any inbound PAI by
default (DESIGN-AUTH.md, "Where the assertion comes from").

### forward(req, server-name)

Si server-name est omis, on utilise le domaine de la R-URI pour trouver le serveur SIP
qui convient.

Retourne { newreq,  %SIP.Peer{} }

### SBB.forward(req, server-name)

Fait tout le boulot

Appelle B2BUA
Gère le challenge dans le cas d'un trunk SIP


## AOR et SIP proxy

Ajout des AOR par commande ou API  

kelictl server <servename> aor add <aor>
kelictl server <servename> aor rm <aor>
kelictl server <servename> aor list

