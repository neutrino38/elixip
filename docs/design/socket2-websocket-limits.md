# Borner ce que socket2 accumule sur une connexion WebSocket

**Statut : vulnérabilité connue, non corrigée. Auditée le 2026-09-08.**

Le correctif appartient au fork socket2, pas à elixip. Il n'est pas écrit.

Ne pas ouvrir de ticket public pour ce document : le dépôt elixip est
source-available et public.

## Le défaut

Un pair WebSocket peut faire tenir au nœud autant de mémoire qu'il veut.

Un message WebSocket peut arriver en plusieurs morceaux. La RFC 6455 §5.4
appelle cela un message *fragmenté*. Le lecteur de socket2 empile ces morceaux
jusqu'au dernier, puis livre le message reconstitué.

Cette pile n'a aucune limite — ni en nombre de morceaux, ni en taille totale.
Elle vit dans le tas du processus lecteur, un par connexion. Chaque listener
accepte 100 connexions par défaut (`:wss_max_connections`).

Le code concerné : `active_websocket_process/2` dans
`deps/socket2/lib/socket/web.ex`.

Deux aggravations :

- **aucune authentification n'est nécessaire.** Une connexion WSS établie
  suffit ;
- **notre garde WSS ne récupère pas la connexion.** Le lecteur continue de
  répondre aux `ping` pendant qu'il empile. Le `pong` arrive donc à l'heure, et
  la garde de `SIPTransportWSS` (30 s, trois périodes) conclut que la connexion
  est saine.

> Constaté par **lecture du code**. L'attaque elle-même n'a pas été exercée,
> contrairement aux mesures de la section suivante.

## Ce qui est déjà borné

Deux autres chemins d'accumulation ont été examinés. Aucun n'est un trou. Le
driver inet d'Erlang les borne, sans que socket2 y soit pour quelque chose.

**La trame unique.** Une trame WebSocket peut annoncer sa taille sur 64 bits
(`length == 127`). socket2 passe cette taille telle quelle à
`Socket.Stream.recv`. Mesuré sur une paire de sockets locale :

| taille annoncée | ce que rend `gen_tcp:recv/3` |
|---|---|
| 1 Mo | `{:error, :timeout}` — la taille est respectée |
| 100 Mo, 2^31−1 | `{:error, :enomem}` — le driver refuse d'allouer |
| 2^31, 4·10⁹ | `{:ok, <ce qui est disponible>}` — la taille est **ignorée** |

Pas de fuite mémoire, donc. Mais la dernière ligne est un défaut : la trame est
lue trop court, et les octets suivants sont lus comme un nouvel en-tête de
trame. Le flux WebSocket se désynchronise, sur une frontière choisie par le
pair.

**La poignée de main HTTP.** Avant la bascule en WebSocket, la socket est en
mode `{packet, :http_bin}`. Une ligne d'en-tête sans fin est refusée par le
driver : `{:error, :emsgsize}`. Mesuré : 60 Mo poussés, RSS du nœud +1 Mo.

## Le correctif prévu

Il va dans le fork, parce que seul le lecteur de trames peut refuser **avant**
d'assembler. Depuis `SIPTransportWSS`, on ne voit que des messages déjà
reconstitués : il est trop tard.

Trois changements dans `Socket.Web` :

1. `active_websocket_process/2` porte la taille cumulée des morceaux, et refuse
   au-delà du maximum ;
2. `recv/4` refuse une taille annoncée hors borne **avant** d'appeler
   `Socket.Stream.recv`. Cela supprime aussi la lecture trop courte au-delà de
   2^31, puisqu'une telle taille est refusée en amont ;
3. un `timeout` explicite. Aujourd'hui `recv/2` est appelé sans options, donc
   avec `timeout: :infinity`.

Le refus ferme la connexion avec le code WebSocket **1009 `message_too_big`**,
que la table de codes du fork nomme déjà.

**Aucune réponse SIP n'est possible ici.** Le message ne s'assemble jamais, donc
il n'y a pas d'en-têtes, donc rien à répondre. Le code 1009 *est* la réponse.
C'est le même raisonnement que la branche « rien à répondre » du dépaquetiseur
TCP.

Le maximum vient de l'appelant : une option de `Socket.Web.accept` et de
`Socket.Web.connect`. Côté elixip, l'écouteur WSS passe
`SIPMsg.max_message_size()`. Un seul nombre pour les quatre transports.

## Le lot

Une merge request sur le fork `neutrino38/elixir-socket`, **et** le bump de
`mix.lock` dans elixip, dans le même lot.

Piège connu : la CI du fork impose `mix format --check-formatted` sur Elixir
1.12 à 1.15. elixip n'a pas de formateur, donc l'habitude ne suit pas.

## Critère de sortie

Un test elixip qui ouvre une connexion WSS, égoutte des trames de continuation
sans jamais poser la trame finale, et vérifie deux choses : la mémoire du nœud
ne suit pas, et la connexion est fermée avec le code 1009.

## Ce qui est déjà fait

Le même défaut a été corrigé côté TCP et TLS, où le dépaquetiseur est le nôtre
(commit `d182ea5`). La règle qui en sort vaut aussi ici :

> Une limite de taille sur le chemin entrant se vérifie sur ce que le pair
> **annonce**, avant d'allouer quoi que ce soit. On répond si on peut, puis on
> ferme.
