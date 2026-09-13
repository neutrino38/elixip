# Présence et messagerie instantantanée

## Objectifs

Implémenter RFC 3856 et l'utiliser de façon créative comme suit :

1- Proposer un état composite qui contiendrait à la fois
   - l'état d'enregistrement de l'usager
   - l'état de présence publié par l'usager 
   - l'état d'occupation en terme d'appels via RFC 7463 - Shared Line Appearence
   - la localisation soit publiée par l'usager, soit déterminée par IP location
   - ses terminaux enregistrés pour les notifications push

2- Implémenter la messagerie instantanée pair à pair (MESSAGE)


Script .exs qui gère:
- Souscription pour rentrer dans la "liste d'amis" ( SUBSCRIBE monami@domain.com )
- NOTIFY sip:monami@domain.com et acceptation ou pas.
- NOTIFY sip:jechercheunami@domain.com avec le résultat.

Question ouverte : comment obtenir sa liste d'amis ?

Envoi

Possibilité d'enregistrer un message audio / video / texte ? ou une photo et la pousser comme pièce jointe.

3- Implémenter la messagerie instantanée entre une UA et un scénario agissant comme un chatbot avec des sessions long terme

La première idée est de faire des scénarios .exs capable de décrire des scénarios de chatbot et de reprendre des conversations si besoin.


4- Implémenter un SBB de type Automatic Call Distribution basé sur la présence

L'idée est de réimplémenter l'équivalent d'app_queue asterisk avec une interface purement SIP.
Les files d'attentes (queues) sont des objets persistents similaire aux conférences du module MCU. On peut les
créer, les éditer et les détruire par commandes kelictl, API et via une vue kelescope ad hoc.

Sousscrire à une file d'attente serait fait comme ceci

``̀ 
SUBSCRIBE sip:queuename@acddomain
``̀ 

Le message subscribe serait traité par un scénario e.g. `acd-agent-subscribe.exs` après avoir fait 
ses vérifications il appelle une fonction ACD.add_agent(queue, agent_sip_uri)


``̀ Elixir

STATE add_to_queue do
    req = last_req()
    ACD.add_agent(req.ruri.userpart, req.pai)
    ...
end

``̀ 

Un appel d'un usager à un agent est mis en file d'attente grâce à un fonction `ACD.queue_call(queue_name, req, options)`

Cela ressemblerait (à préciser et si besoin remettre en cause)

``̀ Elixir

STATE queue_call do
    req = last_uas_req()
    ACD.queue_call("myqueue", req, [])
    
    on_events do
        { :queued, queue_entry } -> goto session_progress
        { :unknown_queue, queue_entry } -> ...
        { :empty_queue, queue_entry } -> ...
    end
end

STATE session_progress do
    reply_invite_with_sdp(183, [media: :tc, webrtc: :if_offered])
    on_events do
        {:ACK, _req, _trans, _dlg} -> goto play_background
        {:CANCEL, _req, _trans, _dlg} -> 
            ACD.cancel_queue_call("myqueue")
    end
end

STATE session_progress do

    media_play("background.mp4")
    on_events do
        {:ms_event, _res, :player_ended} -> stay()

``̀ 


Le SBB sélectionne place l'appel dans une file la file d'attente (tenue par un process à part ?). Le prochain agent
disponible (= qui a souscrit à la file, qui ne traite pas un appel, qui est enregitré et qui s'est déclaré disponible) est sélectionné en fonction de la politique de la file d'attente et grâce au module B2BUA, on tente de mettre en relation
l'usager et l'appelant. Si l'agent décroche, bingo. Sinon, on passe à l'agent suivant (possiblement en modifiant l'état
de présence de l'agent si option autopause).

On doit utiliser la fonction hunt du module B2BUA ici évidement.

On devra construire un joli ACD.SBB.queue() aussi facile à utiliser qu'asterisk app_queue()

## Configuration dans domains.toml

``̀ 
[[domain.presence]]
event-package=<event package>
publish=publish-<event package>.exs
subscribe=subscribe-<event package>.exs
notify=notify-<event package>.exs

[[domain.chat]]
pattern = "mybot"
script = "mybot.exs"

[[domain.chat]]
pattern="room-.*"
script="chatroom.exs"

[[domain.chat]]
default = true                    # catch-all, must be last
script="p2p-chat.exs"

``̀ 

# Notes de conceptions

## Implémentation dans elixip2

- SIP stack: handling of presence
- SIP.Presence.* - parsers des corps de messages
- scénario présence UAC, présence UAS
- scenario chat

## Module Silo 

Un module Silo qui permet de stocker un message SIP et de l'envoyer "plus tard" à un AOR quand l'abonné est enregistré. Durée de rétention. Limite de message et de taille par AOR.
Persistence en cas de redémarrage de kelixip. 

Probablemetn un module kelixip - à confirmer
Un par domain avec forte isolation. Lien avec le registrar: 
- doit-on exiger un registrar dans le même domaine ? Simple et direct !
ou 
- un module qui implémente un behavior particulier ? Permettrait de le déporter dans elixip2 et de faire des scénarios de test. Dans ce cas, registrar implémenterait le behavior et kelixip initialiserai Silo en passant l'implémentation de registrar.

contrainte : pas de présence sans registrar dans la même instance kelixip ? (ce n'est pas un problème d'imposer cela à mon sens)

## Module kelixip Presence

Module pub/sub générique pour la présence. Comme le registrar, un par domaine avec une isolation forte. Dépend du module SILO

Traite les SUBSCRIBE et PUBLISH, envoie les NOTIFY

## Chat

Pour le chat pair à pair : un B2BUA chat

Pour les chatrooms : 
- un module kelixip,
- des objets chatroom comme les conference du module 
- des fonctions pour poster des messages

Support des médias: 

configurer un répertoire média pour photo et vidéo + vignette.
envoi par URL dans un MESSAGE ? S'inspirer de RCS ?

Expiration des médias, téléchagement par le client?

Quid de RCS d'ailleurs ?

## Bot

Besoin d'un module minimum qui crée des grammaires. Comment traiter les messages ?


# Terminaux de test

- Linphone comme première référence
- Faire évoluer Trix pour aller plus loin.
-