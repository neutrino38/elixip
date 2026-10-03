# SIP Server specs

Je voudrais introduire la notion de serveur SIP dans kelixip qui ressemble un peu à un
endpoint dans PJSIP https://docs.pjsip.org/en/latest/pjsua2/using/endpoint.html

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

Nouveau module kelixip Kelix.SipServers

## Management

- commandes kelictl, API
- de quoi construire une interface graphique de gestion des serveurs dans kelescope

## Functions

### matches_server(req)

Cette fonction examine une requête entrante et détermine si elle vient d'un des serveur SIPs 
définis dans le domaine en comparant le transport attaché à la requpete et en les comparant avec ceux attendus par les IP / port / transport résolus pour le serveur.

Retourne { server-slug, %SIP.Peer{} } ou :no_match

### forward(req, server-name)

Si server-name est omis, on utilise le domaine de la R-URI pour trouver le serveur SIP
qui convient.

Retourne { newreq, peer }

### SBB.forward(req, server-name)

Fait tout le boulot

Appelle B2BUA

Gère le challenge dans le cas d'un trunk SIP


## AOR et SIP proxy

Ajout des AOR par commande ou API  

kelictl servers aor add <servername> <aor>

