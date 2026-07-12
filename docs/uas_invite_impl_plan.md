# Plan d'implémentation — scénarios UAS INVITE

Découpage issu de `docs/uas_invite.md` §7. Ce document détaille la conception
d'implémentation phase par phase. **Phases 1 à 4 réalisées** (2026-07-12) ;
phases 5-6 à venir.

Rappel des phases :

1. **Framework couche basse** : `on_new_call/3`, remontée ACK/CANCEL,
   propagation des rejets, `100 Trying`, allows — *ce document*.
2. `CallUAS` + auto_store (`reply_invite`, `redirect_invite`, `challenge_invite`).
3. Média UAS (`get_sdp_answer/2`, `reply_invite_with_sdp`, `reply_invite_with_body`).
4. `CallInDialog` (macros d'envoi in-dialog communes UAC/UAS — dont
   **`send_reINVITE` / `send_UPDATE`** —, `reply_request`). Cf. §2.8.
5. elixipp (fabrique généralisée, mode serveur `:uas_invite`, scénario réf., E2E).
6. Multipart (sérialisation `multipart/mixed`) — indépendante.

---

# Phase 1 — Framework couche basse

## Constats de la revue de code (2026-07-12)

La revue préalable a mis au jour **trois défauts préexistants** que la phase 1
corrige, en plus des évolutions prévues :

- **P1 — Rejet applicatif cassé.** `SIP.DialogImpl.init(:inbound)` retourne
  `{:stop, :abnormal, reason}` sur `{:reject, code, reason}` — retour
  **invalide** pour `GenServer.init/1` (le 3-tuple n'existe pas) →
  `GenServer.start` produit `{:error, {:bad_return_value, …}}` →
  `start_dialog` renvoie une erreur générique → `process_UAS_request`
  (branche « General error », `SIPTransactionCommon.ex:550`) répond
  **`403 Denied`** quel que soit le code demandé par l'application. Le 503 de
  quota du registrar et le futur 604 sont donc réécrits en 403 sur le réseau.
  (Non détecté : le test quota appelle `on_new_registration/3` directement.)
- **P2 — CANCEL invisible de l'application.** Le CANCEL porte le branch de
  l'INVITE → il matche l'IST (`Registry.SIP.Transac`) et y est absorbé
  (`SIP.IST` : 200 au CANCEL + **487 automatique** à l'INVITE). Ni le dialogue
  ni l'app ne sont notifiés : le dialogue entrant survit jusqu'à son timeout
  (1800 s) et le handler `{:CANCEL, …}` de `sip_call_test.exs:169` est du code
  mort (le test « abandonned call » passe uniquement grâce au 487 de l'IST).
- **P3 — ACK d'un 2xx : transaction parasite.** L'ACK d'un 200 porte un
  **nouveau** branch (RFC 3261 §13.2.2.4) → aucune transaction ne matche → le
  transport appelle `start_uas_transaction` (aucune garde ACK,
  `SIPTransaction.ex:184`) → un **NIST** est créé pour l'ACK, ne reçoit
  jamais de réponse, et son timer F finit par **émettre un 408 en réponse à un
  ACK** (violation du protocole). De plus l'ACK, transmis au dialogue, y est
  jeté (`on_new_transaction` → `:nonewtrans` court-circuite
  `send_req_to_app`). Non détecté : `simulate_remote_ack` réutilise le branch
  de l'INVITE.

Enfin, confirmation que **l'IST n'émet pas de `100 Trying` automatique**
(point ouvert §8.1 de la spec — tranché : on l'ajoute, RFC 3261 §17.2.1).

## 1.1 Behaviour `SIP.Session.Call` — `on_new_call/3`

**Fichiers** : `lib/framework/SIPSessionInvite.ex`, `lib/framework/SIPSession.ex`,
`test/sip_call_test.exs`.

```elixir
# SIPSessionInvite.ex — SIP.Session.Call
@callback on_new_call(dialog_id :: pid, invitereq :: map, transaction_id :: pid) ::
            {:accept, pid} | {:reject, integer, binary}
@callback on_call_end(dialog_id :: pid, app_pid :: pid) :: nil
```

- `ConfigRegistry.dispatch/3` (`SIPSession.ex:219`) : la clause INVITE passe
  `[dialog_id, req, transaction_id]` (le pid est déjà reçu, actuellement
  ignoré) ; supprimer le commentaire « on_new_call/2 keeps its arity ».
- Migration de l'unique implémentation existante : `TestCall.on_new_call/2`
  (`test/sip_call_test.exs:198`) → arité 3 (le paramètre peut y rester
  inutilisé : les réponses passent par le dialogue).

Pas de compatibilité d'arité à maintenir : le behaviour n'a qu'un
implémenteur, dans les tests.

## 1.2 Propagation des rejets (correction P1)

Chaîne visée : `{:reject, code, reason}` (callback) → réponse SIP `code
reason` sur la transaction serveur d'origine. La forme d'erreur attendue par
`process_UAS_request` existe déjà (`{:error, {code, reason, {_, _, totag}}}` →
`reply_to_UAC(code)`, `SIPTransactionCommon.ex:545`) ; il manque les maillons
intermédiaires.

1. **`SIP.DialogImpl.init(:inbound)`** (`SIPDialogImpl.ex:382`) :

   ```elixir
   {:reject, code, reason} ->
     Logger.info(...)
     {:stop, {:reject, code, reason, state.totag}}   # retour GenServer VALIDE
   ```

   Le `totag` (généré en tête d'`init`) est embarqué : la réponse de rejet
   doit porter un To-tag (exigé par `reply_to_request` pour tout code > 100).

2. **`SIP.Dialog.start_dialog/4`** (`SIPDialog.ex:80`) : `GenServer.start`
   renvoie alors `{:error, {:reject, code, reason, totag}}` → nouvelle clause
   qui le retourne tel quel (log en `info`, pas `error` : c'est un refus
   applicatif nominal, pas une panne).

3. **`SIP.Dialog.process_incoming_request/3`** (`SIPDialog.ex:122`, branche
   « no such dialog ») : mapper

   ```elixir
   {:error, {:reject, code, reason, totag}} ->
     {:error, {code, reason, {fromtag, req2.callid, totag}}}
   ```

   soit exactement la forme que `process_UAS_request` sait déjà transformer en
   réponse SIP. Les autres erreurs de `start_dialog` restent inchangées
   (→ 403 « General error », comportement actuel conservé).

Bénéficiaires immédiats : le **503** de quota du registrar (aujourd'hui émis
403) et le futur **604** de contrôle de domaine (phase 5). Aucun changement
côté fabrique/callbacks.

## 1.3 `100 Trying` automatique (IST)

**Fichier** : `lib/framework/SIPIST.ex` (`handle_cast(:sipreq)`).

```elixir
def handle_cast(:sipreq, state) do
  case process_UAS_request(state) do
    {:ok, state} ->
      # RFC 3261 §17.2.1: the IST sends 100 Trying itself; the TU (scenario)
      # never has to. reply_to_request/5 accepts code 100 without a totag.
      {_rc, state} = reply_to_UAC(state, state.msg, 100, "Trying", [], nil)
      {:noreply, schedule_timer_F(state)}
    {:upperlayerfailure, state} -> {:noreply, state}
  end
end
```

- Émis **après** `process_UAS_request` : un rejet (§1.2) part alors seul, sans
  100 préalable — plus simple et sans conséquence (le 100 est optionnel).
- `fsm_reply` passe l'IST en `:proceeding` ; un 100/180 émis ensuite par
  l'application reste accepté (idempotent). Le `SIP.Dialog.reply(…, 100, …)`
  du test `sip_call_test.exs:151` devient redondant → à retirer lors de la
  mise à jour des tests (§1.7).
- Les scénarios UAS n'auront donc **jamais** à faire `reply_invite(100)`.

## 1.4 Remontée du CANCEL (correction P2)

Décision : l'IST **conserve** son traitement RFC (200 au CANCEL + 487
automatique — pas d'aller-retour vers l'application, pas de course), mais
**notifie ensuite la couche dialogue**, qui notifie l'application puis
s'arrête.

1. **`SIP.IST`** (handler CANCEL, `SIPIST.ex:49`) : après le
   `reply_to_UAC(487)`, si `state.app` est un pid (posé par
   `process_UAS_request` — c'est le pid du dialogue) :

   ```elixir
   GenServer.cast(state.app, {:sipmsg, req, self()})   # req = le CANCEL
   ```

   (même canal que les requêtes in-dialog ; rien à faire dans la branche
   `CANCEL rejected` — 481.)

2. **`SIP.DialogImpl`** : clause **dédiée**, placée avant la clause générique
   `{:sipmsg, …}` (le pipeline `with` actuel jetterait le CANCEL via
   `:nonewtrans`, et `check_seqno` le refuserait — l'ACK et le CANCEL portent
   le CSeq de l'INVITE) :

   ```elixir
   def handle_cast({:sipmsg, msg, transact_pid}, state)
       when is_req(msg) and msg.method == :CANCEL do
     send(state.app, {:CANCEL, msg, transact_pid, self()})
     # The IST already replied 200 to the CANCEL and 487 to the INVITE.
     # The early dialog is over: stop and let terminate/2 notify the app.
     {:stop, {:shutdown, :cancelled}, state}
   end
   ```

3. **`SIP.DialogImpl.terminate/2`** (`SIPDialogImpl.ex:518`) : déballer les
   raisons `{:shutdown, r}` pour préserver le contrat applicatif existant :

   ```elixir
   reason = case reason do {:shutdown, r} -> r ; r -> r end
   send(state.app, {:dialog_terminated, self(), reason})
   ```

   L'app reçoit donc, dans l'ordre : `{:CANCEL, req, ist_pid, dlg_pid}` puis
   `{:dialog_terminated, dlg_pid, :cancelled}`. (`{:shutdown, _}` évite le
   crash-report GenServer d'une raison anormale.)

4. **Côté scénario** (phases 2+) : ne **pas** répondre 487 — c'est déjà fait.
   Un `reply_invite(487)` résiduel recevra `:ignore` de `fsm_reply`
   (« Final response already sent ») ; la macro `reply_invite` devra mapper
   `:ignore` sur `lasterr :ok` (noté pour la phase 2). L'exemple §5.3 de la
   spec est corrigé en conséquence.

## 1.5 Remontée de l'ACK (correction P3)

Deux cas distincts :

- **ACK d'une réponse non-2xx** (même branch que l'INVITE) : absorbé par
  l'IST (état `:confirmed`) — **inchangé**, l'application n'en a pas besoin.
- **ACK d'un 2xx** (nouveau branch) : doit atteindre l'application (il
  confirme l'établissement de l'appel et peut porter le SDP en delayed offer).

Modifications :

1. **Routeur transport** (`SIP.Transport.ImplHelpers.process_incoming_message`,
   `SIPTransport.ex:217`) : dans la branche `{:no_matching_transaction, …}`,
   **si `method == :ACK`, ne pas créer de transaction UAS** (RFC 3261
   §17.2.3 : l'ACK ne crée pas de transaction serveur) ; router directement :

   ```elixir
   if parsed_msg.method == :ACK do
     SIP.Dialog.process_incoming_request(msg, nil, false)   # msg = RURI enrichie tp_*
     {:noreply, state}
   else
     ... start_uas_transaction(...)                          # chemin actuel
   end
   ```

2. **Garde de sûreté** dans `SIP.Transac.start_uas_transaction/2` : clause
   `is_this_req(sipmsg, :ACK)` → log erreur + `{:req_cannot_create_trans, nil}`
   (symétrique de la garde UAC existante, `SIPTransaction.ex:158`).

3. **`SIP.Dialog.process_incoming_request/3`** : la clause « no matching
   dialog » pour `:ACK` (`SIPDialog.ex:137`) reste `:nomatchingdialog`
   (RFC : un ACK orphelin s'ignore). Avec dialogue matché, le cast
   `{:sipmsg, ack, nil}` existant fait l'affaire — accepter `transact_id = nil`.

4. **`SIP.DialogImpl`** : clause dédiée, comme pour CANCEL :

   ```elixir
   def handle_cast({:sipmsg, msg, _transact_pid}, state)
       when is_req(msg) and msg.method == :ACK do
     # No transaction, no CSeq bump (the ACK carries the INVITE's CSeq).
     # Forward as an app event; the body may carry the SDP (delayed offer).
     send(state.app, {:ACK, msg, nil, self()})
     {:noreply, state}
   end
   ```

   L'app reçoit `{:ACK, req, nil, dialog_pid}` — cohérent avec le contrat
   `{method, req, transaction_pid, dialog_pid}` (pid nil : rien à répondre à
   un ACK).

## 1.6 `allows(:INVITE)`

**Fichier** : `SIPDialogImpl.ex:64`.

```elixir
defp allows(:INVITE) do
  [:BYE, :UPDATE, :ACK, :MESSAGE, :INFO, :INVITE, :REFER, :NOTIFY, :OPTIONS]
end
```

`:NOTIFY` : souscription implicite du REFER (RFC 3515). `:OPTIONS` :
keepalive in-dialog. (Consommés par la phase 4.)

## 1.7 Tests

**`test/sip_call_test.exs`** (UDP mockup, existant) :

| Test | Évolution |
|---|---|
| `TestCall.on_new_call` | arité 3 (§1.1) ; retirer le `reply(…, 100, …)` du process de test (§1.3) |
| « answered call » (les 2) | asserter le `100 Trying` **auto** ; ACK simulé avec un **branch neuf** (nouvel helper `simulate_remote_ack2xx/1`) ; asserter que l'app reçoit `{:ACK, …}` ; asserter qu'**aucun 408 tardif** n'arrive (P3) |
| « abandonned call » | asserter que l'app reçoit `{:CANCEL, …}` **puis** `{:dialog_terminated, _, :cancelled}` ; le 487 reste asserté ; vérifier qu'il est **unique** |
| nouveau : rejet | `on_new_call` retourne `{:reject, 604, "Does Not Exist Anywhere"}` (piloté par le paramètre `scenario` de la RURI, mécanisme du test) → asserter **604** sur le réseau (aujourd'hui : 403) |

**`test/uas_register_test.exs`** : non-régression (le chemin de rejet §1.2 est
partagé) ; si l'infra du test le permet, ajouter l'assertion E2E « quota
dépassé → **503** sur le réseau ».

## Récapitulatif des changements phase 1

| Fichier | Changement |
|---|---|
| `SIPSessionInvite.ex` | behaviour : `on_new_call/3` |
| `SIPSession.ex` | dispatch INVITE : passe le `transaction_id` |
| `SIPDialogImpl.ex` | init : `{:stop, {:reject, …}}` valide ; clauses dédiées ACK / CANCEL ; `terminate/2` déballe `{:shutdown, r}` ; allows +`:NOTIFY`/`:OPTIONS` |
| `SIPDialog.ex` | `start_dialog` : propage `{:reject, …}` ; `process_incoming_request` : mappe vers `{:error, {code, reason, dlg_id}}` ; accepte `transact_id nil` pour ACK |
| `SIPIST.ex` | `100 Trying` auto ; notification du dialogue après absorption du CANCEL |
| `SIPTransaction.ex` | garde ACK dans `start_uas_transaction` |
| `SIPTransport.ex` | routeur : ACK sans transaction → dialogue direct |
| `test/sip_call_test.exs` | §1.7 |

## Risques & points d'attention

1. **Ordre 100 / 180** : le 100 auto part avant tout 1xx applicatif ; les
   retransmissions UAC (timer A côté client) cessent au premier 1xx — aucun
   impact négatif attendu, mais vérifier les asserts de timing des tests.
2. **`terminate/2` déballant `{:shutdown, r}`** : auditer les autres
   producteurs de raisons d'arrêt du dialogue (`:tcp_closed`, etc. — matchés
   par `uas_register.exs`) : ils utilisent des atomes nus, non impactés.
3. **Double 487** : impossible côté IST (`fsm_reply` en `:terminated` →
   `:ignore`) ; le point est reporté sur `reply_invite` en phase 2 (mapper
   `:ignore` → `lasterr :ok`).
4. **`state.app` nil dans l'IST** : si `process_UAS_request` a échoué, pas de
   notification CANCEL — garder le `if is_pid(state.app)`.
5. **Dialogues UAC et CANCEL entrant** : la clause CANCEL du `DialogImpl`
   s'applique aussi à un dialogue sortant (cas exotique : CANCEL reçu par un
   UAC) — l'arrêt `{:shutdown, :cancelled}` y est acceptable, à mentionner
   dans la doc du module.

---

## État d'implémentation (2026-07-12) — Phase 1 RÉALISÉE

Toutes les évolutions §1.1–1.6 sont implémentées et testées
(`test/sip_call_test.exs`, 5/5 ; non-régression `sip_register` /
`sip_transaction` / `uas_register`, 26/26). Les échecs de la suite complète
(`Call2`, `Mendooze.ServerTest`, `scenario_integration`) sont **préexistants**
(tests média sans serveur / flakiness sous charge) et confirmés identiques sur
l'arbre propre.

Fichiers touchés : `SIPSessionInvite.ex` (behaviour `on_new_call/3`),
`SIPSession.ex` (dispatch INVITE /3), `SIPDialogImpl.ex` (init reject valide,
clauses dédiées ACK/CANCEL, `terminate/2` déballe `{:shutdown, r}`, allows
+`:NOTIFY`/`:OPTIONS`), `SIPDialog.ex` (`start_dialog` propage le reject,
helper `start_inbound_dialog/4` mappe vers `{:error, {code, reason, dlgid}}`),
`SIPIST.ex` (100 Trying auto, notification du dialogue après CANCEL),
`SIPTransaction.ex` (garde ACK), `SIPTransport.ex` (routeur ACK → dialogue),
`SIPUDPMockup.ex` (forward du 100 pour les asserts).

### Écart relevé pendant l'implémentation (à traiter en phase ≥ 2)

**ACK d'un 2xx non testable e2e pour l'instant.** Le routage framework de
l'ACK 2xx (§1.5 : transport → `SIP.Dialog.process_incoming_request(ack, nil,
false)` → clause dédiée `DialogImpl`) est en place et correct, mais il ne peut
pas encore être exercé de bout en bout : un **dialogue entrant n'est jamais
ré-enregistré sous son dialog-id complet** (`{fromtag, callid, totag}`).
`add_totag/2` ne (ré)enregistre que si `state.totag` est nil, or il est déjà
généré à l'`init` d'un dialogue `:inbound` (`SIPDialogImpl.ex:351`, garde
`SIPDialogImpl.ex:738`). Un ACK 2xx à **branche neuve** (RFC 3261 §13.2.2.4)
porte le to-tag local ; le `Registry.lookup` sur `{fromtag, callid, totag}` (et
son swap) échoue donc → l'ACK est traité `:nomatchingdialog` et n'atteint pas
l'app. La correction (enregistrer le dialogue entrant sous l'id complet quand le
to-tag local est posé) est **hors périmètre phase 1** ; le test e2e de l'ACK
2xx→app est donc reporté. Le cas ACK *non-2xx* (même branche que l'INVITE,
absorbé par l'IST) reste inchangé et couvert.

### Note d'implémentation — fixture de test `TestCall` (timeout scenario)

La fabrique UAS réelle spawn ses instances via `spawn_monitor` (pas de lien).
La fixture `TestCall` utilise `spawn_link` : sur CANCEL, le dialogue s'arrête
avec `{:shutdown, :cancelled}` et le signal d'exit **tuerait** l'instance liée
avant qu'elle ne draine les messages `{:CANCEL}` / `{:dialog_terminated}` déjà
en file (un process suspendu en `receive` est terminé au traitement du signal
fatal, sans exécuter le corps du `receive`). La fixture pose donc
`Process.flag(:trap_exit, true)`. Les vraies instances (monitorées) ne sont pas
concernées.

---

# Phase 2 — `SIP.Session.CallUAS` + auto_store  *(RÉALISÉE 2026-07-12)*

> Conception validée sur le code réel le 2026-07-12. **Sans média** : `reply_invite`,
> `redirect_invite`, `challenge_invite` et le stockage automatique de la requête
> à répondre. Les macros média (`reply_invite_with_sdp`, `reply_invite_with_body`)
> sont explicitement reportées à la phase 3.

## Objectif

Donner à un scénario UAS de quoi **répondre à un INVITE / re-INVITE / UPDATE**
sans repasser la requête ni le dialogue à chaque macro : la requête offrante la
plus récente est rangée automatiquement dans le contexte (D1), et les macros
`reply_invite*` la relisent. Elles passent toutes par `SIP.Dialog.reply/5`
(aucun contrôle d'état du dialogue — exigence « scénarios de test aux
enchaînements potentiellement incorrects »).

## Pré-requis déjà en place (revue 2026-07-12)

- `SIP.Scenario.Runner.run_instance/2` pose déjà **`ctx.dialogpid`** (opt
  `:dialog_pid`, `SIPScenarioRunner.ex:117`) et **`ctx.appdata[:inbound_request]`**
  (opt `:inbound_request`, ligne 123). Une instance UAS a donc le dialogue sous
  la main sans plomberie supplémentaire.
- `reply_to_request/5` applique la **phrase de raison standard** quand `reason`
  est `nil` (`sip_reason/1`, `SIPMsgOps.ex:70`) → `reply_invite(code)` sans
  raison marche.
- Le chemin challenge 401/407 (`DialogImpl.handle_call({:replyreq, req,
  401/407, reason, realm})`) est agnostique de la méthode → `challenge_invite`
  est quasi gratuit (`SIP.Dialog.challenge/4` existe déjà).
- La phase 1 a tranché : les scénarios ne répondent **jamais** `100`/`487`
  eux-mêmes. `reply_invite` doit néanmoins mapper le `:ignore` de `fsm_reply`
  (réponse finale déjà émise) sur `lasterr :ok`.

## 2.1 Stockage automatique (D1) — instrumentation d'`on_events`

`SIP.Scenario.instrument_receive_clause/1` (`SIPScenario.ex:391`) préfixe déjà
chaque corps de clause par `Process.put(:scenario_event_type, type)`. On l'étend
pour (a) **lier l'événement matché** à une variable hygiénique et (b) préfixer
le corps par l'appel `auto_store`.

```elixir
# SIPScenario.ex — remplace instrument_receive_clause/1
defp instrument_receive_clause({:->, meta, [head, body]}) do
  type = clause_event_type(head)          # calculé AVANT réécriture du head
  evt  = Macro.unique_var(:evt, __MODULE__)

  new_body =
    quote do
      Process.put(:scenario_event_type, unquote(type))
      # auto_store est une fonction pure : no-op sauf INVITE/UPDATE entrant.
      var!(sip_ctx) = SIP.Session.CallUAS.auto_store(var!(sip_ctx), unquote(evt))
      unquote(body)
    end

  {:->, meta, [bind_event_var(head, evt), new_body]}
end

# Réécrit le motif `pattern` en as-pattern `pattern = evt`, sous garde `when` ou non.
defp bind_event_var([{:when, m, [pattern | guards]}], evt),
  do: [{:when, m, [{:=, [], [pattern, evt]} | guards]}]
defp bind_event_var([pattern], evt), do: [{:=, [], [pattern, evt]}]
defp bind_event_var(other, _evt), do: other
```

- **Hygiène** : `Macro.unique_var(:evt, SIP.Scenario)` est distinct de tout `evt`
  du scénario ; le même nœud sert au binding et à `auto_store`, donc ils
  désignent la même variable.
- **Universel & transparent** : profite aussi aux scénarios UAC recevant un
  re-INVITE ; aucun changement dans les scénarios existants (l'as-pattern est
  neutre pour tous les motifs, y compris `when`, `^pin`, la clause de shutdown
  auto-injectée et la clause `{:scenario_ctl, …}`).
- La clause `after` n'est pas dans `do_clauses` → non instrumentée (inchangé).

`auto_store/2` (dans `SIP.Session.CallUAS`, `SIPSessionInvite.ex`) :

```elixir
@doc "Range la requête offrante entrante (INVITE/UPDATE) + son transaction id."
def auto_store(sip_ctx, {m, req, trans_pid, _dlg})
    when m in [:INVITE, :UPDATE] and is_map(req) do
  sip_ctx
  |> SIP.Context.appdata_set(:last_uas_req, req)
  |> SIP.Context.appdata_set(:last_uas_req_tid, trans_pid)
end

def auto_store(sip_ctx, _evt), do: sip_ctx
```

- **Slot unique** `{:last_uas_req, :last_uas_req_tid}` : la dernière requête
  offrante (INVITE initial, re-INVITE ou UPDATE) est celle que servent les
  macros. Limitation assumée (documentée) : un UPDATE reçu pendant un re-INVITE
  écrase le slot — acceptable pour un outil de test.
- Tout autre événement (réponses `{code, …}`, `{:ms_event, …}`, timers,
  `{:scenario_*}`, `{:ACK,…}`, `{:CANCEL,…}`, `{:BYE,…}`, `{:dialog_terminated,…}`)
  tombe sur la clause no-op. (Notamment `:ACK`/`:BYE`/`:CANCEL` ne sont **pas**
  stockés — ils se répondent avec la requête sous la main via `reply_request`,
  phase 4.)

## 2.2 Répartition des macros — `reply_invite` commun, redirect/challenge UAS

**Décision affinée (user 2026-07-12) :** un **UAC** en dialogue établi peut
recevoir un **re-INVITE / UPDATE** et doit y répondre → `reply_invite*` est une
macro **in-dialog commune**, exposée par **`SIP.Session.CallUAC`** (donc
disponible dans tout scénario via `SIP.Scenario`). Les macros purement
**serveur** — `redirect_invite` (3xx) et `challenge_invite` (401/407) — restent
en **opt-in** dans `SIP.Session.CallUAS`.

Pour éviter toute duplication et tout double-`defmacro` (un scénario UAS fait
`use SIP.Scenario` **et** `use SIP.Session.CallUAS`), chaque macro n'est définie
**qu'une fois**, et **toutes les fonctions de service** (`auto_store/2`,
`do_reply_invite/4`, `do_redirect_invite/4`, `do_challenge_invite/3` + helpers)
vivent dans le module `SIP.Session.CallUAS`, appelées en pleinement-qualifié.

### `reply_invite` — ajouté à `SIP.Session.CallUAC.__using__` (`SIPSessionInvite.ex`)

```elixir
# dans le quote de SIP.Session.CallUAC.__using__, à côté de send_INVITE/send_BYE…
defmacro reply_invite(code, reason \\ nil, upd_fields \\ []) do
  quote do
    SIP.Scenario.Monitor.note_command(:sip, "reply_invite #{unquote(code)}")
    var!(sip_ctx) =
      SIP.Session.CallUAS.do_reply_invite(
        var!(sip_ctx), unquote(code), unquote(reason), unquote(upd_fields))
  end
end
```

`CallUAC` fait déjà `use SIP.Context` : `reply_invite` s'insère sans plomberie
supplémentaire. `auto_store` (§2.1) range déjà les re-INVITE/UPDATE reçus par un
UAC (instrumentation universelle), donc `reply_invite` y a la requête sous la
main.

### Module `SIP.Session.CallUAS` (nouveau, `SIPSessionInvite.ex`)

`__using__` définit **uniquement** les macros serveur (`redirect_invite`,
`challenge_invite`) ; le module porte **toutes** les fonctions de service (y
compris `do_reply_invite/4`, utilisée par la macro de `CallUAC`).

```elixir
defmodule SIP.Session.CallUAS do
  require Logger

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      defmacro redirect_invite(contacts, code \\ 302, reason \\ nil) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "redirect_invite #{unquote(code)}")
          var!(sip_ctx) =
            SIP.Session.CallUAS.do_redirect_invite(
              var!(sip_ctx), unquote(contacts), unquote(code), unquote(reason))
        end
      end

      defmacro challenge_invite(realm, code \\ 407) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "challenge_invite #{unquote(code)}")
          var!(sip_ctx) =
            SIP.Session.CallUAS.do_challenge_invite(
              var!(sip_ctx), unquote(realm), unquote(code))
        end
      end
    end
  end

  # ── backing functions (partagées CallUAC/CallUAS) ───────────────────────────

  # (auto_store/2 : cf. §2.1)

  @doc """
  Répond à la requête INVITE/UPDATE stockée (slot §2.1) avec un code SANS SDP.
  Garde : lève pour 183 ou 2xx (ils exigent un SDP → reply_invite_with_sdp /
  reply_invite_with_body, phase 3), SAUF pour un 2xx à un UPDATE sans offre
  (légal sans SDP). Passe par SIP.Dialog.reply/5 (aucun contrôle d'état).
  """
  def do_reply_invite(sip_ctx = %SIP.Context{}, code, reason, upd_fields)
      when is_integer(code) do
    req = fetch_stored_req!(sip_ctx)

    if needs_sdp?(code) and not (req.method == :UPDATE and not has_sdp?(req)) do
      raise "reply_invite: code #{code} requires an SDP body; " <>
              "use reply_invite_with_sdp/reply_invite_with_body (phase 3)"
    end

    rc = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, reason, upd_fields)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  @doc "Réponse 3xx + Contact(s). `contacts` : String | %SIP.Uri{} | liste."
  def do_redirect_invite(sip_ctx = %SIP.Context{}, contacts, code, reason)
      when code in 300..399 do
    req = fetch_stored_req!(sip_ctx)
    rc  = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, reason, contact: contacts)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  @doc "Challenge 401/407 + digest (réutilise le chemin nonce de DialogImpl)."
  def do_challenge_invite(sip_ctx = %SIP.Context{}, realm, code)
      when code in [401, 407] do
    req = fetch_stored_req!(sip_ctx)
    rc  = SIP.Dialog.challenge(sip_ctx.dialogpid, req, code, realm)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  # Slot §2.1, avec repli sur la requête initiale (rangée par le runner) pour le
  # cas — atypique — d'une réponse émise avant toute clause on_events.
  defp fetch_stored_req!(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
           SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      req when is_map(req) -> req
      _ -> raise "reply_invite*: no stored INVITE/UPDATE to reply to"
    end
  end

  defp needs_sdp?(code), do: code == 183 or code in 200..299

  defp has_sdp?(req) do
    case Map.get(req, :body) do
      b when is_binary(b) and b != "" -> true
      [ _ | _ ] -> true
      _ -> false
    end
  end

  # :ok et :ignore (réponse finale déjà émise — ex. auto-487 après CANCEL, §1.4)
  # valent succès ; tout autre code (transport / :invalid_sip_msg) est une erreur.
  defp reply_lasterr(:ok), do: :ok
  defp reply_lasterr(:ignore), do: :ok
  defp reply_lasterr(other), do: other
end
```

### Table récapitulative des macros

| Macro | Défini dans | Réponse | Garde | lasterr |
|---|---|---|---|---|
| `reply_invite(code, reason \\ nil, upd \\ [])` | **CallUAC** (global) | tout code **sans SDP** (100/18x/4xx/5xx/6xx) | lève si `183`/`2xx` sauf 2xx→UPDATE-sans-SDP | `:ok`/`:ignore`→`:ok` |
| `redirect_invite(contacts, code \\ 302, reason \\ nil)` | **CallUAS** (opt-in) | 3xx + Contact | `code in 300..399` | idem |
| `challenge_invite(realm, code \\ 407)` | **CallUAS** (opt-in) | 401/407 + digest | `code in [401,407]` | idem |

`reply_invite` est commun (re-INVITE/UPDATE côté UAC comme côté UAS) ; les deux
autres sont des réponses purement serveur.

## 2.3 Câblage DSL — `reply_invite` global, redirect/challenge opt-in

Deux niveaux d'exposition (décisions user 2026-07-12) :

- **`reply_invite`** vit dans `SIP.Session.CallUAC`, que `SIP.Scenario` tire déjà
  (`SIPScenario.ex:66`) → **disponible dans tout scénario** sans `use`
  supplémentaire, UAC comme UAS (un UAC en dialogue peut recevoir un
  re-INVITE/UPDATE et doit y répondre).
- **`redirect_invite` / `challenge_invite`** vivent dans `SIP.Session.CallUAS`
  → **opt-in explicite** côté scénario serveur :

```elixir
defmodule UAS.InviteExample do
  use SIP.Scenario
  use SIP.Session.CallUAS   # ← ajoute redirect_invite / challenge_invite
  uas(:invite)
  ...
  # reply_invite est déjà là (via SIP.Scenario → CallUAC)
end
```

Rationale : `reply_invite` est une réponse in-dialog générique (offre/réponse),
tandis que rediriger (3xx) ou défier (401/407) un appel entrant est un rôle
serveur. **Conséquence** : l'exemple §5.3 de `docs/uas_invite.md` doit ajouter
`use SIP.Session.CallUAS` (uniquement s'il utilise redirect/challenge ; il
utilise `reply_invite`, déjà couvert). Idem futur `scenarios/uas_invite.exs`.

- **Pas de double `defmacro`** : `reply_invite` n'est défini **que** dans
  `CallUAC` ; `redirect_invite`/`challenge_invite` **que** dans `CallUAS`. Un
  scénario UAS faisant `use SIP.Scenario` **et** `use SIP.Session.CallUAS`
  n'a donc aucune redéfinition.
- **Pas de duplication de logique** : les trois macros délèguent aux fonctions
  `SIP.Session.CallUAS.do_*` (dont `do_reply_invite/4`, appelée par la macro de
  `CallUAC` en pleinement-qualifié).
- `use SIP.Context` **idempotent** (garde `@sip_context_used`,
  `SIPContext.ex:47`) : `CallUAC` + `CallUAS` + `Media` n'injectent `ctx_*`
  qu'une fois.
- **auto_store universel** : l'appel `SIP.Session.CallUAS.auto_store/2` injecté
  par `on_events` (§2.1) est **runtime pleinement qualifié** (pas un import) —
  fonctionne dans tout scénario sans dépendance de compilation ; `CallUAS` est
  compilé avec le framework, avant la couche `dsl`.

## 2.4 Restrictions & points d'attention

1. **Réponse finale déjà émise.** Après un 2xx/final, l'IST/NIST se ferme ;
   un `reply_invite` ultérieur reçoit `:ignore` (mappé `:ok`) ou, si la
   transaction a disparu, `:invalid_transaction`. `reply_req` **ne sait pas
   destructurer** un `:invalid_transaction` (bug latent préexistant,
   `SIPTransaction.ex:267` renvoie l'atome nu là où `handle_call` attend un
   tuple) → à surveiller ; hors périmètre phase 2 (ne se produit pas dans un
   enchaînement nominal).
2. **`reply_invite(2xx/183)` interdit** tant que la phase 3 (média) n'est pas
   là : la garde lève un message explicite pointant vers `reply_invite_with_sdp`.
   Le cas 2xx→UPDATE-sans-offre reste permis (pas de SDP requis).
3. **`dialogpid` absent** : si le scénario est mal câblé (pas d'instance UAS),
   `SIP.Dialog.reply(nil, …)` lèvera — comportement voulu (erreur de
   programmation, pas un cas réseau).
4. **Non-régression `on_events`** : l'as-pattern réécrit **toutes** les clauses
   de **tous** les scénarios (UAC compris). À valider : `uac_invite.exs`,
   `uac_register.exs`, `uas_register.exs`, `scenario_engine_test.exs`,
   `sub_fsm`/shutdown, inférence de type d'événement (`goto` auto-typé).

## 2.5 Tests (phase 2)

Deux niveaux, sans dépendre de l'outil elixipp (phases 5) :

- **Unitaire `auto_store/2`** (fonction pure) : `{:INVITE, req, tid, dlg}` et
  `{:UPDATE, …}` rangent `:last_uas_req`/`:last_uas_req_tid` ; `{200, …}`,
  `{:ms_event, …}`, `{:BYE, …}`, un timer, etc. laissent le contexte inchangé.
- **Scénario `test/uas_invite_test.exs`** sur le modèle de
  `uas_register_test.exs` : une petite fabrique implémentant `on_new_call/3`
  (phase 1) → `SIP.Scenario.Runner.spawn_uas_instance/2` d'un scénario UAS
  minimal (`initial_state → wait_invite`), INVITE injecté via `UDPMockup`
  (`{:recv, parsed_msg}`), puis assertions sur le fil : `reply_invite(180)` →
  **180**, `reply_invite(486, "Busy")` → **486**, `redirect_invite("sip:…", 302)`
  → **302**, `challenge_invite(@realm)` → **401/407**. Le `UDPMockup` reforwarde
  déjà les codes `1xx`/`2xx..6xx` au process de test (`handle_resp`, scénario
  `:inboundinvite`), donc les `assert_receive(code, …)` de `sip_call_test.exs`
  se réutilisent tels quels. Vérifier aussi qu'un `reply_invite(200)` **lève**
  (garde SDP).
  *(NB : ce test réutilise l'infra IST/dialogue de la phase 1, déjà validée.)*

## 2.6 Inventaire des changements phase 2

| Fichier | Changement |
|---|---|
| `SIPScenario.ex` | `instrument_receive_clause/1` étendu (as-pattern + `auto_store`) ; helper `bind_event_var/2`. **Pas** de `use CallUAS` ici |
| `SIPSessionInvite.ex` (`CallUAC`) | macro **`reply_invite`** ajoutée à `__using__` (déléguant à `CallUAS.do_reply_invite/4`) |
| `SIPSessionInvite.ex` (`CallUAS`, nouveau) | `auto_store/2` ; macros **`redirect_invite`/`challenge_invite`** ; backing `do_reply_invite/4`, `do_redirect_invite/4`, `do_challenge_invite/3` + helpers `fetch_stored_req!`/`needs_sdp?`/`has_sdp?`/`reply_lasterr` |
| `docs/uas_invite.md` | corriger l'exemple §5.3 : ajouter `use SIP.Session.CallUAS` (pour redirect/challenge) |
| `test/uas_invite_test.exs` | nouveau — unitaire `auto_store` + scénario UDP mockup (`use SIP.Session.CallUAS` pour tester redirect/challenge) |

## 2.7 Hors périmètre phase 2 (→ phase 3)

`reply_invite_with_sdp/1` et `reply_invite_with_body/2` (négociation média,
helper `SIP.Session.Media.get_sdp_answer/2`, code d'échec `500 Media Server
Error`). La garde SDP de `reply_invite` prépare le terrain : les codes 183/2xx
y sont déjà réservés à ces macros. À traiter aussi en phase 3 : le
ré-enregistrement des dialogues entrants sous leur dialog-id complet (écart
relevé en phase 1) si l'on veut tester l'ACK 2xx delayed-offer de bout en bout.

## 2.8 À FAIRE — émission de re-INVITE / UPDATE (côté envoi), commun UAC/UAS

> Demande user 2026-07-12. Symétrique de `reply_invite` : ce dernier couvre la
> **réception** d'un re-INVITE/UPDATE (phase 2, commun) ; il faut aussi couvrir
> leur **émission**.

Ajouter les macros **`send_reINVITE(sdp_or_ms, opts \\ [])`** et
**`send_UPDATE(sdp_or_ms, opts \\ [])`** (in-dialog, même convention que
`send_INVITE` : `:mediaserver` → offre via `get_sdp_offer`, ou SDP explicite),
et elles doivent être **disponibles côté CallUAC *comme* côté CallUAS** — un UAS
qui a décroché doit pouvoir renégocier (re-INVITE) ou mettre à jour la session
(UPDATE) tout autant qu'un UAC.

C'est exactement le rôle du mixin commun **`SIP.Session.CallInDialog`** (D2) de
la **phase 4** : `send_MESSAGE`/`INFO`/`BYE`/`REFER`/**`UPDATE`**/**`reINVITE`**/
`NOTIFY` + `reply_request`, consommé par `use SIP.Session.CallInDialog` dans
`CallUAC` **et** `CallUAS`. Ces deux macros s'appuient sur
`SIP.Session.send_sip_request/3` (routage route-set/remote-target déjà géré par
`fix_outbound_request`).

**Point d'attention (à trancher en phase 4) :** l'émission d'un re-INVITE/UPDATE
implique un SDP ⇒ dépend de la couche média (phase 3). Séquencer en conséquence
(la variante SDP-explicite ne dépend pas du média et peut arriver plus tôt ; la
variante `:mediaserver` suit la phase 3). Récapitulatif de symétrie à garder :

| Sens | re-INVITE / UPDATE | Où | Phase |
|---|---|---|---|
| **Réception** (répondre) | `reply_invite*` | CallUAC (commun) | 2 (SDP en 3) |
| **Émission** (envoyer) | `send_reINVITE` / `send_UPDATE` | CallInDialog (commun UAC/UAS) | 4 (SDP dépend de 3) |

---

# Phase 3 — Média UAS  *(RÉALISÉE 2026-07-12)*

> `reply_invite_with_sdp` (183/200 avec SDP négocié) et `reply_invite_with_body`
> (body arbitraire mono-part). Média mono-body uniquement (multipart = phase 6).

## Ce qui a été fait

1. **`SIP.Session.extract_sdp/1`** (`SIPSession.ex`, nouveau) : extraction du SDP
   d'un message (body binaire, mono-part `[%{data}]`, ou multipart → part
   `contenttype =~ "sdp"` avec repli sur la 1ʳᵉ part). Factorisé depuis
   `CallUAC.process_sdp_resp/2` (refactorisé pour l'appeler → simplification :
   la logique de body dupliquée disparaît). Partagé UAC (réponse) / UAS (offre).

2. **`SIP.Session.Media.get_sdp_answer/3`** (`SIPSessionMedia.ex`, nouveau),
   symétrique de `get_sdp_offer/3` : `set_remote_offer` sur la peer connection.
   Retourne `{ctx, {:ok, answer} | {:error, reason}}` (l'erreur média → 500 côté
   macro ; **raise** seulement si aucun médiaserveur connecté, même contrat que
   `get_sdp_offer`). Création/réutilisation de la peer connection factorisée en
   `ensure_peer_connection/3` (partagée offer/answer → réutilisation couvrant le
   re-INVITE). Défaut `media: :audio_video` (⚠ **pas** `:tc`, valeur invalide qui
   cause les échecs préexistants de `Call2`/`scenario_integration` — voir plus
   bas).

3. **Macros `reply_invite_with_sdp/1..2` et `reply_invite_with_body/2..3`**
   ajoutées à **`SIP.Session.CallUAC.__using__`** (donc communes UAC/UAS via
   `SIP.Scenario`, comme `reply_invite`), backées par
   `SIP.Session.CallUAS.do_reply_invite_with_sdp/3` et
   `do_reply_invite_with_body/4` :
   - `reply_invite_with_sdp(code, opts)` — garde `code in [183, 200]` (sinon
     raise) ; extrait l'offre du slot `:last_uas_req`, négocie, répond
     `body: answer` + **Contact local ajouté automatiquement** (exigé par un 2xx
     à un INVITE ; surchargeable `opts[:contact]`). Échec média → `500 Media
     Server Error` (surchargeable `on_media_error: {code, reason}`), `lasterr`
     = `{:media_error, reason}`. `opts` : `:reason`, `:contact`, `:webrtc`,
     `:media`, `:on_media_error`.
   - `reply_invite_with_body(code, bodies, opts)` — `bodies` : binaire (→
     `application/sdp`), `%{contenttype, data}`, ou liste mono-part. Liste > 1
     → raise (multipart = phase 6). Contact local ajouté aussi.
   - Signature retenue `reply_invite_with_body(code, bodies, opts \\ [])` (et non
     `(code, reason \\ nil, bodies)` de la spec §3.2 : un défaut ne peut précéder
     un argument requis en Elixir) ; `reason` passe par `opts[:reason]`.

## Écart / décision

- **`media: :tc` abandonné comme défaut.** La revue a confirmé que le mockup
  (`MediaServer.Mockup.Conn.init`) n'accepte que `:audio | :video |
  :audio_video`. `client_invite`/`get_sdp_offer` propagent `:tc` par défaut →
  c'est la cause racine des échecs préexistants `Call2`/`scenario_integration`
  (hors périmètre ici, mais tracé). `get_sdp_answer` prend `:audio_video`.
- **ACK 2xx delayed-offer e2e** : toujours reporté (écart phase 1 — dialogue
  entrant non ré-enregistré sous son dialog-id complet). L'e2e phase 3 asserte
  le **200 + SDP sur le fil** ; l'ACK 2xx n'est pas exercé.

## Tests (`test/uas_invite_test.exs`, étendu — 24/24)

- `get_sdp_answer` : négociation OK + réutilisation de la peer connection ;
  raise sans médiaserveur.
- `do_reply_invite_with_sdp` : 200 + SDP + Contact local ; échec média → 500 ;
  `on_media_error` surchargé → 503 ; code non supporté → raise ; requête stockée
  sans SDP → raise.
- `do_reply_invite_with_body` : binaire, `%{contenttype, data}`, liste mono ;
  multipart → raise ; body invalide → raise.
- e2e UDP mockup : `reply_invite_with_sdp(200)` (fixture `AnswerSdp` avec
  `media_connect()` config-driven → mockup) → **100 auto puis 200** sur le fil.

Non-régression : `sip_call` (5), `uas_register`, `sip_transaction` — 24/24 (les
échecs `Call2`/`Mendooze.ServerTest`/`scenario_integration` restent préexistants
et inchangés).

## Récapitulatif des changements phase 3

| Fichier | Changement |
|---|---|
| `SIPSession.ex` | `extract_sdp/1` (nouveau, factorisé) |
| `SIPSessionInvite.ex` | `process_sdp_resp/2` réutilise `extract_sdp` ; macros `reply_invite_with_sdp`/`reply_invite_with_body` (dans `CallUAC`) ; backing `do_reply_invite_with_sdp/3`, `do_reply_invite_with_body/4` + helpers `reply_fields`/`local_contact`/`media_opts`/`normalize_bodies` |
| `SIPSessionMedia.ex` | `get_sdp_answer/3` (nouveau) ; `ensure_peer_connection/3` factorisé ; défaut média `:audio_video` |
| `test/uas_invite_test.exs` | tests média + e2e answer-with-SDP |

---

# Phase 4 — `SIP.Session.CallInDialog` (mixin commun UAC/UAS)  *(RÉALISÉE 2026-07-12)*

> Envoi de requêtes in-dialog (D2) + réponse générique `reply_request`, migration
> de `send_BYE`. Répond aussi à §2.8 (émission re-INVITE/UPDATE, commune UAC/UAS).

## Ce qui a été fait

**Nouveau module `SIP.Session.CallInDialog`** (dans `SIPSessionInvite.ex`), tiré
par **`use SIP.Session.CallInDialog`** dans `CallUAC` **et** `CallUAS` (garde
impérative `@sip_call_indialog_used`, patron `SIP.Context`, → 2ᵉ injection no-op
pour un scénario UAS qui atteint le mixin par les deux chemins). Donc **toutes
les macros sont disponibles dans tout scénario d'appel** via `SIP.Scenario`.

Macros injectées (chacune backée par une fonction `do_*` pleinement qualifiée,
construisant la requête et la passant à `SIP.Session.send_sip_request/3` — le
dialogue remplit Call-ID/CSeq/tags/remote-target/route-set via
`fix_outbound_request/3`) :

| Macro | Méthode | Détails |
|---|---|---|
| `send_MESSAGE(body, opts \\ [])` | MESSAGE | contenttype défaut `text/plain` |
| `send_INFO(body, opts \\ [])` | INFO | défaut `application/dtmf-relay` |
| `send_BYE(body \\ nil)` | BYE | **migré depuis CallUAC** ; body optionnel |
| `send_REFER(refer_to, opts \\ [])` | REFER | `Refer-To` + `opts[:referred_by]` |
| `send_UPDATE(sdp_or_ms, opts \\ [])` | UPDATE | `:mediaserver` (offre via `get_sdp_offer/3`) ou SDP explicite + Contact local |
| `send_reINVITE(sdp_or_ms, opts \\ [])` | INVITE | idem UPDATE |
| `send_NOTIFY(event, body, opts \\ [])` | NOTIFY | header `Event` + body (défaut `message/sipfrag`) |
| `send_inDialog_OPTIONS()` | OPTIONS | keepalive in-dialog |
| `reply_request(req, code, reason \\ nil, upd_fields \\ [])` | — | réponse générique à une requête in-dialog reçue (BYE/MESSAGE/INFO/OPTIONS/NOTIFY/REFER) via `SIP.Dialog.reply/5` (pas de contrôle d'état ; `:ignore`→`:ok`) |

Helpers privés : `in_dialog_request/3` (squelette method/URIs/UA — construit avec
`SIP.Context.from/to`, exige username+domain comme l'ancien `bye_message`),
`put_body/3` (body + Content-Type, no-op si nil/vide), `send_offer_request/4`
(UPDATE/reINVITE : `:mediaserver` → `get_sdp_offer` puis récursion binaire),
`local_contact/1`, `reply_lasterr/1`.

**Migration `send_BYE`** : retiré de `CallUAC.__using__` ainsi que `client_bye/1`
et `bye_message/1` ; l'arité 0 reste couverte par `send_BYE(body \\ nil)` de
CallInDialog (aucun scénario/test à changer — `send_BYE()` marche toujours).

**Migration DSL** : les scénarios de référence `lib/scenarios/uac_invite.ex` et
`scenarios/uac_invite.exs` remplacent les `SIP.Dialog.reply(dialog_pid, req, …)`
directs (MESSAGE/BYE) par `reply_request(req, 200, "OK")`.

## Décisions / notes

- **Signatures Elixir** : les macros à défaut multiple respectent l'ordre
  (défauts en fin) ; `send_NOTIFY(event, body, opts)` a `event`/`body` requis.
- Les autres méthodes in-dialog (CANCEL → `SIP.Session.Common.send_CANCEL`,
  PRACK/100rel, SUBSCRIBE in-dialog) restent hors périmètre (§4.1 spec).
- Un UAS qui envoie du in-dialog (BYE/reINVITE) doit avoir username+domain dans
  son contexte (contrat inchangé depuis `bye_message`) — config de scénario.

## Tests (`test/uas_invite_test.exs`, étendu — 33/33)

`StubDialog` gère désormais `{:newreq, req}` (renvoie `{:ok, pid}`, notifie le
test). Tests unitaires des backing `do_send_*` : MESSAGE (text/plain +
Content-Length), INFO (défaut + override contenttype), BYE (avec/sans body),
REFER (`Refer-To`/`Referred-By`), UPDATE/reINVITE (SDP explicite + Contact),
UPDATE `:mediaserver` (offre négociée via mockup), NOTIFY (`Event`), OPTIONS ;
`do_reply_request` (200 → `:ok` ; 487 → `:ignore`→`:ok`).

Non-régression : `sip_call` 5/5, `scenario_engine`, `uas_register`,
`sip_transaction` — verts. `scenario_integration` (1 échec) confirmé
**préexistant** sur l'arbre propre (`git stash` : « UDP mockup transport was
never created », lié au `:tc` média, indépendant de la phase 4).

## Récapitulatif des changements phase 4

| Fichier | Changement |
|---|---|
| `SIPSessionInvite.ex` | nouveau module `SIP.Session.CallInDialog` (macros send_* + reply_request + backing + helpers) ; `use CallInDialog` dans CallUAC & CallUAS ; `send_BYE`/`client_bye`/`bye_message` retirés de CallUAC |
| `lib/scenarios/uac_invite.ex`, `scenarios/uac_invite.exs` | MESSAGE/BYE : `SIP.Dialog.reply` direct → `reply_request` |
| `test/uas_invite_test.exs` | `StubDialog` +`{:newreq}` ; tests send_* + reply_request |
