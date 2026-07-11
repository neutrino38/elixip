# Spec pour les scénario UAS INVITE (appels entrants)

Un scénario UAS invite est un scénario qui traite des appels entrants.
Cela peut être dans le cadre de l'outil de test elixipp qui se comporte 
comme un terminal SIP mais aussi dans le cadre du future serveur SIP (kalixip)
ou l'on peut traiter un appel, le refuser, etc.

## Principe généraux

Les principes généraux sont décrit dans le document `docs/uas_scenario_desin.md`
Le présent document détaille le bloc fonctionnel traitement des appels (Call Server).
On s'inspire des principes pour les scénario de type Registrar

## Objectif fonctionnels

Dans un scénario UAS de traitement d'appel on doit

- configurer le ou les domaines d'appels (un peu comme un serveur virtuel appache). Si la R-URI initial de l'appel ne correspond pas, ce dernier est refusé avec un code 604
- configurer un "catchall" qui traite les appels entrants quels que soit le domaine de le R-URI
- on doit pouvoir configurer si l'on va utiliser un médiaserveur ou non.

## Macros et module 

Pour l'instant le code des modules offrant les macros et fonctions de traitement d'appels entrant
seront ajouté au fichier SIPSessionInvite.ex. Si ce dernier devient trop volumineux, on pourra le séparer en deux ou en trois
On créera un nouveau module SIP.Session.InviteUAS

### Traitement des messages INVITE / re-INVITE / UPDATE

Idéalement, la réception d'un message INVITE provoque automatiquement son stockage ainsi que le `transaction_id` dans le contexte `sip_ctx`. Peut être ajouter un système de hook configurable dans `on_event` qui est armé quand on fait  `use SIP.Session.InviteUAS`? Si ce n'est pas possible, disposer d'une macro `store_invite()` mais c'est moche... peut être lui trouver un meilleur nom à cette macro. Propose moi la solution la plus élégante compatible avec l'esprit du projet.

Disposer d'une série de macros `reply_invite(code, reason)` qui permettent de répondre à des messages INVITE ou UPDATE. Ces macros doivent échouer en cas de réponse 2xx ou 183 Session progress qui nécessitent un SDP. Elle doivent réutiliser les infos stockées dans le contexte pour ne pas avoir à repasser le message. Elle ne doivent pas vérifier l'état du dialogue sous-jacent pour permettre de créer des scénario de tests avec des enchainements potentiellement incorrects. Si tu as une meilleur idée de nom pour les macros, tu peux le proposer.

Une macro `reply_invite_with_sdp(code)` qui:
- ouvre une session avec le mediaserver. En cas d'échec répond '400 Mediaserver Error'.
- négocie avec le mediaserveur la réponse local et envoit un 183 Session Progress ou un 200 OK avec SDP.
- tout autre code que 183 ou 200 n'est pas supporté (ajouter une garde).

Une macro `reply_invite_with_body(code, [ contenttype: "application/sdp", body: mysdp ])` qui permette de
créer un invite avec un SDP arbitraire. Les body multiples doivent être supportés. Vérifie que la struture des bodies
correspond à celle retournée par le parser SIP existant.

imagine aussi une macro pour les réponses redirect du type 3xx

### Traitement des autres requêtes in-dialog

J'ai besoin d'une macro / plusieurs macros pour répondre aux autres requêtes in-dialog. Imagine cela et voir comment on peut
les mettre en commun avec les différents autres modules de session CallUAC

### Envoi de requête in-dialog

J'ai besoin de macros pour envoyer les messages suivants in dialog

- MESSAGE + body
- INFO + body
- BYE + body optionnel
- REFER
- UPDATE + sdp

de même, ces macros doivent être communes avec CallUAC. 
Indique moi les autres messages qui peuvent être envoyé in dialog dans un dialogue type INVITE et propose-moi des macros.

Faut-il un module SIP.Session.CallReqInDialog qui rassemblent les macros communes ?

### Mis de côté

- les refresh timers INVITE
- les INVITE replace 

# Ce que je te demande de faire

En tant que lead dev versé en Elixir, en DSL et avec un parfaite connaissance du protocole SIP du devra

- créer dans ce document, une spec pour le module SIP.Session.CallUAS et peut être un module commun
- explorer les restrictions et la faisabilité
- proposer une extention du DSL à l'instar du module Registrar pour configurer le modile
- créer une conception logiciel en me proposant les choix techniques structurants dans ce doc. N'hésite pas à interagir avec moi pour faire valider ces choix
- plus tard, me proposer une conception logicielle pour cette spec + conception.
- exprime-toi en français.

---

# Spécification & conception détaillée (2026-07-12)

> Cette partie répond à la demande ci-dessus. Elle s'appuie sur l'architecture
> existante (Transaction → Dialog → Session → DSL) et sur le travail Registrar
> (`docs/uas_scenario_design.md`, `scenarios/uas_register.exs`,
> `Elixip.RegistrarUAS`). Les choix structurants ont été validés le 2026-07-12.

## 0. Décisions structurantes (validées)

| # | Sujet | Décision |
|---|---|---|
| D1 | Stockage auto de l'INVITE/UPDATE entrant | **Instrumentation transparente d'`on_events`** : chaque clause est réécrite en as-pattern et `auto_store/2` range la requête + son `transaction_id` dans le contexte. Pas de macro `store_invite()`. |
| D2 | Macros in-dialog communes UAC/UAS | Nouveau mixin **`SIP.Session.CallInDialog`** (dans `SIPSessionInvite.ex`), consommé par `CallUAC` et `CallUAS`. |
| D3 | Fabrique d'instances côté elixipp | **Généralisation d'`Elixip.RegistrarUAS`** en fabrique unique (quota, monitor, stats) implémentant les behaviours `SIP.Session.Registrar` **et** `SIP.Session.Call`. |
| D4 | Nommage | Module **`SIP.Session.CallUAS`** (symétrique de `CallUAC`), macros **`reply_invite*`** / `redirect_invite`. |

## 1. Vue d'ensemble du flux entrant

Le flux est le même que pour le Registrar (voir le diagramme de
`uas_scenario_design.md` §1) en remplaçant `on_new_registration/3` par
`on_new_call/3` :

```
INVITE → Transaction (IST) → Dialog.init(:inbound)
       → ConfigRegistry.dispatch(dlg, req, trans_pid)
       → fabrique UAS : contrôle domaine (604) + quota (503)
       → spawn instance scénario → {:accept, pid}
       → l'instance reçoit {:INVITE, req, trans_pid, dialog_pid}
       → elle répond via reply_invite* (SIP.Dialog.reply/5)
```

Les réponses passent par `SIP.Dialog.reply(dialog_pid, req, code, reason,
upd_fields)` qui **ne vérifie pas l'état du dialogue** — exigence de la spec
(scénarios de test avec enchaînements incorrects) déjà satisfaite.

## 2. Faisabilité — restrictions relevées dans le code actuel

Revue de code du 2026-07-12 ; chaque point est un pré-requis ou une limitation
assumée.

1. **Négociation média UAS : déjà faisable.** Le behaviour média expose
   `set_remote_offer/2 :: {:ok, answer} | {:error, _}` (`MediaServer.ex`) :
   accepter l'offre entrante et récupérer la réponse locale ne demande **aucune
   évolution du behaviour**. Il manque seulement un helper côté
   `SIP.Session.Media` (§3.3).
2. **Bodies multipart non sérialisables.** `SIP.Msg.Ops.update_sip_msg/2`
   lève `"Multipart bodies are not yet supported"` pour une liste de plus d'un
   body. Le **parseur** sait produire `[%{contenttype: ct, data: bin}, …]`,
   mais pas le sérialiseur. → `reply_invite_with_body` avec bodies multiples
   nécessite d'implémenter la sérialisation `multipart/mixed` (génération du
   boundary, Content-Type global). Phase dédiée ; le cas mono-body marche déjà.
3. **`on_new_call/2` n'a pas le `transaction_id`.** Contrairement à
   `on_new_registration/3`. → passer à **`on_new_call/3`** (même évolution que
   pour le Registrar ; `ConfigRegistry.dispatch/3` a déjà le pid sous la main).
4. **ACK et CANCEL entrants ne remontent pas à l'app.** Dans
   `SIP.DialogImpl.handle_cast({:sipmsg, …})`, `on_new_transaction/3` renvoie
   `:nonewtrans` pour ACK/CANCEL, ce qui court-circuite `send_req_to_app/3`.
   Un scénario UAS ne verrait donc jamais l'ACK de son 200 OK ni le CANCEL de
   l'appelant. → faire suivre `{:ACK, req, nil, dialog_pid}` et
   `{:CANCEL, req, trans_pid, dialog_pid}` à l'app. Le scénario décide
   lui-même de répondre 487 à l'INVITE (pas d'automatisme : outil de test).
5. **`allows(:INVITE)`** = `[:BYE, :UPDATE, :ACK, :MESSAGE, :INFO, :INVITE,
   :REFER]`. Il manque **`:NOTIFY`** (souscription implicite du REFER,
   RFC 3515) et **`:OPTIONS`** (keepalive in-dialog). → les ajouter.
6. **Challenge INVITE : machinerie déjà en place.** Le chemin
   `{:replyreq, req, 401|407, reason, realm}` de `DialogImpl` (nonce_map,
   `check_nonce`) est agnostique de la méthode → `challenge_invite` est
   gratuit.
7. **`100 Trying`** : à vérifier dans `SIP.IST` (émission automatique à la
   création de la transaction serveur). Si absent, l'ajouter au niveau IST —
   pas au niveau scénario. *(Point ouvert §8.)*
8. **Code d'échec mediaserver.** La spec demandait `400 Mediaserver Error` ;
   400 signifie « requête malformée » côté client. Proposition retenue dans la
   conception : **`500 Media Server Error`** (erreur serveur), le code restant
   surchargeable via option `on_media_error:`.

## 3. Module `SIP.Session.CallUAS` (dans `SIPSessionInvite.ex`)

### 3.1 Stockage automatique de la requête à répondre (D1)

La macro `on_events` (dans `SIPScenario.ex`) instrumente déjà chaque clause
pour inférer le type d'événement. On étend cette instrumentation :

- chaque motif `pattern` devient l'as-pattern `pattern = __evt__` (y compris
  sous garde `when`) ;
- le corps de clause est préfixé par
  `var!(sip_ctx) = SIP.Session.CallUAS.auto_store(var!(sip_ctx), __evt__)`.

`auto_store/2` est une fonction pure et bon marché :

```elixir
def auto_store(sip_ctx, {m, req, trans_pid, _dlg}) when m in [:INVITE, :UPDATE] do
  sip_ctx
  |> SIP.Context.appdata_set(:last_uas_req, req)
  |> SIP.Context.appdata_set(:last_uas_req_tid, trans_pid)
end
def auto_store(sip_ctx, _evt), do: sip_ctx
```

- **Un seul slot** `{:last_uas_req, :last_uas_req_tid}` : la requête offrante
  la plus récente (INVITE initial, re-INVITE ou UPDATE) est celle que les
  macros `reply_invite*` servent. Limitation assumée (documentée) : un UPDATE
  reçu pendant un re-INVITE pendant écrase le slot — acceptable pour un outil
  de test.
- L'instrumentation est **universelle** (elle profite aussi aux scénarios UAC
  qui reçoivent un re-INVITE) et transparente : aucun changement dans les
  scénarios existants.

### 3.2 Macros de réponse

Toutes opèrent sur le slot du §3.1 (pas de paramètre `req`), passent par
`SIP.Dialog.reply/5` (aucun contrôle d'état du dialogue) et notent la commande
dans le `SIP.Scenario.Monitor`.

| Macro | Réponse | Règles |
|---|---|---|
| `reply_invite(code, reason \\ nil, upd_fields \\ [])` | tout code **sans SDP** | **Garde** : lève si `code == 183` ou `code in 200..299` — sauf si la requête stockée est un UPDATE sans body SDP (un 200 sans SDP y est légal). `reason` nil → phrase standard. |
| `reply_invite_with_sdp(code)` | `183 Session Progress` ou `200 OK` + SDP négocié | **Garde** : `code in [183, 200]` uniquement. Séquence : §3.3. En cas d'échec média → `500 Media Server Error` (surchargeable `on_media_error: {code, reason}`) et `sip_ctx.lasterr` positionné (le `goto` suivant avorte le scénario, sauf gestion explicite). |
| `reply_invite_with_body(code, reason \\ nil, bodies)` | tout code + body(s) arbitraire(s) | `bodies` : binaire (SDP brut, contenttype `application/sdp`) ou liste `[%{contenttype: ct, data: bin}, …]` — **la structure du parseur** (`SIPMsg`), directement acceptée par `update_sip_msg({:body, …})`. Multi-bodies : après la phase multipart (§2.2). |
| `redirect_invite(contacts, code \\ 302, reason \\ nil)` | `3xx` + `Contact` | `contacts` : `String.t \| %SIP.Uri{} \|` liste. Garde `code in 300..399`. |
| `challenge_invite(realm, code \\ 407)` | `401/407` + digest | Réutilise le chemin nonce de `DialogImpl` (§2.6). |

Un `reply_invite(487)` après réception de `{:CANCEL, …}` clôt proprement un
appel annulé (le scénario garde la main, §2.4).

### 3.3 Séquence `reply_invite_with_sdp` et helper média

Nouveau helper `SIP.Session.Media.get_sdp_answer(sip_ctx, remote_offer)`,
symétrique de `get_sdp_offer/3` :

1. `mediaserverpid` absent → **raise** (même contrat que `get_sdp_offer` ; le
   scénario doit avoir fait `media_connect()` — config-driven, cf. « utiliser
   un médiaserveur ou non » de la spec) ;
2. crée la peer connection au premier appel (stockée dans
   `:mediapeerconnectionid`, réutilisée ensuite — ce qui couvre le re-INVITE) ;
3. `set_remote_offer(cnx, remote_offer)` → `{:ok, answer}` ;
4. la macro extrait l'offre du body de la requête stockée (binaire, mono-part
   ou multipart via la même logique que `CallUAC.process_sdp_resp/2`, à
   factoriser en `SIP.Session.extract_sdp/1`), puis envoie
   `SIP.Dialog.reply(dlg, req, code, reason, body: answer)`.

Le cycle de vie des ressources média est inchangé : macros
`media_play`/`media_record`/`media_start_echo` puis
`media_cleanup_ressources()` sur `{:dialog_terminated, …}` (contrat existant).

### 3.4 Behaviour `SIP.Session.Call`

```elixir
# AVANT
@callback on_new_call(dialog_id :: pid, invitereq :: map) :: {:accept, pid} | {:reject, integer, binary}
# APRÈS (aligné sur on_new_registration/3)
@callback on_new_call(dialog_id :: pid, invitereq :: map, transaction_id :: pid) ::
            {:accept, pid} | {:reject, integer, binary}
@callback on_call_end(dialog_id :: pid, app_pid :: pid) :: nil
```

`ConfigRegistry.dispatch/3` transmet le pid (déjà reçu, actuellement ignoré).

## 4. Module commun `SIP.Session.CallInDialog` (D2)

Mixin regroupant l'envoi de requêtes in-dialog et la réponse générique aux
requêtes in-dialog reçues. `SIP.Session.CallUAC` et `SIP.Session.CallUAS` font
tous deux `use SIP.Session.CallInDialog` (garde anti-double-injection comme
`SIP.Context`). Les fonctions s'appuient sur `SIP.Session.send_sip_request/3`
(routage route-set/remote-target déjà géré par `fix_outbound_request`).

### 4.1 Macros d'envoi

| Macro | Méthode | Notes |
|---|---|---|
| `send_MESSAGE(body, opts \\ [])` | MESSAGE | `opts[:contenttype]` (défaut `text/plain`). |
| `send_INFO(body, opts \\ [])` | INFO | idem (`application/dtmf-relay` typique). |
| `send_BYE(body \\ nil)` | BYE | **déplacé depuis `CallUAC`** (l'arité 0 y reste déléguée pour compat) ; body optionnel (spec). |
| `send_REFER(refer_to, opts \\ [])` | REFER | `Refer-To` ; `opts[:referred_by]`. |
| `send_UPDATE(sdp_or_ms, opts \\ [])` | UPDATE | `:mediaserver` (offre via `get_sdp_offer`) ou SDP explicite, comme `send_INVITE`. |
| `send_reINVITE(sdp_or_ms, opts \\ [])` | INVITE | re-INVITE in-dialog (même convention). |
| `send_NOTIFY(event, body, opts \\ [])` | NOTIFY | pour la souscription implicite REFER (`Event: refer`, `sipfrag`). Nécessite §2.5. |
| `send_inDialog_OPTIONS()` | OPTIONS | keepalive in-dialog (nécessite §2.5). |

**Autres messages possibles in-dialog dans un dialogue INVITE** (réponse à la
question de la spec) : `CANCEL` (déjà couvert par `SIP.Session.Common.send_CANCEL`),
`PRACK` (lié à 100rel — mis de côté avec les refresh timers), `SUBSCRIBE`
in-dialog (rare, hors périmètre). Aucune macro supplémentaire proposée.

### 4.2 Réponse générique aux requêtes in-dialog reçues

```elixir
reply_request(req, code, reason \\ nil, upd_fields \\ [])
```

Macro unique pour répondre à MESSAGE / INFO / OPTIONS / NOTIFY / REFER / BYE
reçus (remplace les appels directs à `SIP.Dialog.reply/5` qu'on voit dans
`uac_invite.exs`). Ici la requête **est** passée en paramètre : ces requêtes ne
sont pas stockées dans le contexte (seul le couple INVITE/UPDATE l'est), et la
clause `on_events` l'a déjà sous la main.

## 5. Extension DSL + elixipp

### 5.1 Annotation et configuration du scénario

```elixir
defmodule UAS.InviteExample do
  use SIP.Scenario

  uas(:invite)          # → __scenario_type__() == :uas_invite

  config(
    # Domaines servis (serveur virtuel) : la R-URI de l'INVITE initial doit
    # matcher, sinon la fabrique répond 604 Does Not Exist Anywhere.
    # :any = catchall (tous domaines).
    domains: ["example.com", "sip.example.com"],
    # Sélection du médiaserveur — mécanisme existant (config / JSON externe) ;
    # un scénario sans média ne fait simplement pas media_connect().
    mediaserver: %{module: :mockup, url: "sip:localhost:8080"}
  )
end
```

- `uas :invite` réutilise la macro `uas/1` existante — **zéro changement DSL**.
- `domains:` est une clé du bloc `config`, lue par la fabrique (§5.2) via les
  `:scenario_overrides` — même canal que `password` côté Registrar. Défaut si
  absente : `:any` (catchall).

### 5.2 Fabrique UAS généralisée (D3)

`Elixip.RegistrarUAS` devient **`Elixip.ScenarioUAS`** (alias
`Elixip.RegistrarUAS` conservé pendant une transition) :

- l'état, le quota (`max_instances` → 503), `max_run`, le monitoring
  d'instances (`spawn_uas_instance/2` + `Process.monitor`), `stats/0` et
  `shutdown_all/1` sont **inchangés** — ils sont déjà génériques ;
- il implémente **les deux behaviours** :
  - `on_new_registration/3` (existant) ;
  - `on_new_call/3` (nouveau) : vérifie `domains` (§5.1) → sinon
    `{:reject, 604, "Does Not Exist Anywhere"}` ; puis quota → 503 ; puis
    spawn d'instance (mêmes opts `:dialog_pid` / `:inbound_request` /
    `:parent_pid`) → `{:accept, pid}` ;
  - `on_call_end/2` : symétrique d'`on_registration_expired/2`.
- `ElixippCLI.run_server_mode/4` gagne une clause `:uas_invite` qui enregistre
  la fabrique via `SIP.Session.ConfigRegistry.set_call_processing_module/1`
  (un scénario `:uas_register` continue de passer par
  `set_registration_processing_module/1`).

### 5.3 Scénario de référence `scenarios/uas_invite.exs`

```elixir
defmodule UAS.InviteExample do
  use SIP.Scenario

  uas(:invite)
  config(domains: :any)

  # {:INVITE, …} est déjà dans la mailbox au démarrage de l'instance.
  state initial_state do
    media_connect()
    goto(next)
  end

  state wait_invite do
    on_events do
      {:INVITE, _req, _trans, _dlg} ->
        # auto_store a rangé req + trans_pid dans le contexte
        reply_invite(180, "Ringing")
        goto(answer_call, "INVITE")
    after
      32_000 -> scenario_failure("no INVITE received")
    end
  end

  state answer_call do
    reply_invite_with_sdp(200)
    goto(next)
  end

  state wait_ack do
    on_events do
      {:ACK, _req, _t, _dlg} -> goto(in_call, "ACK")
      {:CANCEL, _req, _t, _dlg} ->
        # 200 (CANCEL) + 487 (INVITE) already sent by the INVITE server
        # transaction (see impl plan phase 1); nothing to reply here.
        scenario_success("caller cancelled")
    after
      10_000 -> scenario_failure("no ACK")
    end
  end

  state in_call do
    media_start_echo()
    on_events do
      {:BYE, req, _t, _dlg} ->
        reply_request(req, 200)
        scenario_success("BYE")
      {:INVITE, _req, _t, _dlg} ->        # re-INVITE
        reply_invite_with_sdp(200)
        goto(loop, "re-INVITE")
      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("call ended")
    after
      600_000 -> scenario_success("idle timeout")
    end
  end
end
```

*(Le nettoyage média sur fin d'appel s'appuie sur le contrat
`{:dialog_terminated, …}` + `media_cleanup_ressources()`, géré par le moteur /
`on_shutdown` comme aujourd'hui.)*

## 6. Inventaire des changements

| Zone | Fichier(s) | Nature |
|---|---|---|
| Behaviour Call | `SIPSessionInvite.ex` | `on_new_call/3` ; nouveau `SIP.Session.CallUAS` (auto_store + macros `reply_invite*`, `redirect_invite`, `challenge_invite`) ; nouveau `SIP.Session.CallInDialog` ; `send_BYE` migré depuis `CallUAC` |
| Dispatch | `SIPSession.ex` | `dispatch/3` INVITE transmet le `transaction_id` ; helper `extract_sdp/1` factorisé |
| Dialog | `SIPDialogImpl.ex` | remontée ACK/CANCEL à l'app (§2.4) ; `allows(:INVITE)` + `:NOTIFY`, `:OPTIONS` |
| Média | `SIPSessionMedia.ex` | `get_sdp_answer/2` (peer connection partagée avec `get_sdp_offer`) |
| Message | `SIPMsgOps.ex`, `SIPMsg.ex` | sérialisation multipart (phase dédiée, §2.2) |
| DSL | `SIPScenario.ex` | instrumentation as-pattern + `auto_store` dans `on_events` |
| Outil | `ElixippCLI.ex`, `ElixippRegistrarUAS.ex` → `ElixippScenarioUAS.ex` | fabrique généralisée (double behaviour, contrôle `domains`/604) ; mode serveur `:uas_invite` |
| Scénario réf. | `scenarios/uas_invite.exs` | exemple §5.3 |
| Tests | `test/uas_invite_test.exs` | sur le modèle de `uas_register_test.exs` (UDP mockup + Mockup média) |

## 7. Découpage en phases (proposition)

1. **Framework couche basse** : `on_new_call/3`, remontée ACK/CANCEL, allows.
2. **`CallUAS` + auto_store** : instrumentation `on_events`, `reply_invite`,
   `redirect_invite`, `challenge_invite` (sans média).
3. **Média UAS** : `get_sdp_answer/2` + `reply_invite_with_sdp` +
   `reply_invite_with_body` (mono-body).
4. **`CallInDialog`** : migration `send_BYE`, nouvelles macros d'envoi,
   `reply_request`.
5. **elixipp** : fabrique généralisée + `--listen` mode `:uas_invite` +
   scénario de référence + tests E2E.
6. **Multipart** (indépendante) : sérialisation `multipart/mixed`.

## 8. Points ouverts / mis de côté

1. ~~`100 Trying` automatique par l'IST : à vérifier en phase 1 (§2.7).~~
   **Tranché (2026-07-12)** : l'IST n'en émettait pas ; il est ajouté en
   phase 1 (voir `uas_invite_impl_plan.md` §1.3). De même, le **487 sur
   CANCEL est automatique** (déjà le cas dans l'IST) : les scénarios n'ont ni
   `reply_invite(100)` ni `reply_invite(487)` à faire.
2. Sémantique fine du 604 : la spec dit 604 ; 404/420 possibles selon le cas —
   on garde **604** configurable plus tard si besoin.
3. Source des credentials pour `challenge_invite` : même statut que le
   Registrar (acceptation par défaut, `password` par config).
4. Mis de côté (spec) : refresh timers INVITE (Session-Expires/100rel/PRACK)
   et INVITE Replaces.
5. Interleaving UPDATE/re-INVITE simultanés : slot unique (§3.1), à revoir si
   un scénario réel l'exige.
