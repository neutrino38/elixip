# Plan d'implémentation — scénarios UAS INVITE

Découpage issu de `docs/uas_invite.md` §7. Ce document détaille la conception
d'implémentation phase par phase ; seule la **phase 1** est détaillée à ce
stade, les suivantes seront ajoutées au fil de l'eau.

Rappel des phases :

1. **Framework couche basse** : `on_new_call/3`, remontée ACK/CANCEL,
   propagation des rejets, `100 Trying`, allows — *ce document*.
2. `CallUAS` + auto_store (`reply_invite`, `redirect_invite`, `challenge_invite`).
3. Média UAS (`get_sdp_answer/2`, `reply_invite_with_sdp`, `reply_invite_with_body`).
4. `CallInDialog` (macros d'envoi in-dialog communes UAC/UAS, `reply_request`).
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
