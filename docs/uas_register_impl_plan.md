# Plan d'implémentation — Scénarios UAS Register

> Plan d'exécution de la conception décrite dans
> [`uas_scenario_design.md`](uas_scenario_design.md). Découpé en phases
> indépendamment testables, ordonnées par dépendance et par risque croissant.
> **MVP = transport UDP uniquement** (déjà bidirectionnel) ; les listeners
> TCP/TLS/WSS forment une phase séparable (phase 7), plus lourde.

## Constat préalable : ce qui existe déjà (à réutiliser)

| Brique | Localisation | Réutilisation |
|---|---|---|
| Challenge 401/407 + génération nonce | `SIPDialogImpl.handle_call({:replyreq, req, 401/407, reason, realm})` → `challenge_request/7` (`SIPMsgOps.ex:350`) | `challenge_registration` = simple wrapper de `SIP.Dialog.reply(dlg, req, 401, reason, realm)` |
| Stockage / validation nonce | `add_new_nonce/2`, `valid_nonce?/2`, `:checknonce` (`SIPDialogImpl.ex:323-347`) | rien à écrire |
| Vérif. Authorization | `SIP.Msg.Ops.check_authrequest/3` (`SIPMsgOps.ex:456`) | `check_registration_auth` délègue |
| Réponse → fil (UDP) | transaction IST/NIST mémorise `tpid/destip/destport`, `sendout_msg/2` (`SIPTransactionCommon.ex:10`) | aucun changement pour UDP |
| Bornage Expires/Contact | `SIP.Session.Registrar.check_register/1` (`SIPSessionRegister.ex:65`) | réutilisé dans `accept_registration` |
| Réponse 200/contact | `SIP.Dialog.reply/5` (`SIPDialog.ex:185`) | utilisé par `accept_registration` |
| Injection message entrant (test) | `UDPMockup` `{:recv, parsed_msg}` (`SIPUDPMockup.ex:337`) + `test/SIP-REGISTER*.txt` | base des tests |
| Fixture registrar | `TestRegistrar` (`test/test_helper.exs`) | à adapter à `/3` |

**Conséquence** : le cœur du protocole (challenge/auth/réponse) est déjà
fonctionnel. Le travail neuf porte sur (a) le passage du `transaction_id`,
(b) l'habillage DSL serveur, (c) la fabrique d'instances avec quota, (d) la CLI
et le mode serveur, (e) les listeners connectés, (f) scénario/tests/doc.

---

## Phase 1 — Couche Session : passage du `transaction_id`

**But** : enrichir `on_new_registration` comme demandé dans la spec.

- `SIPSessionRegister.ex` :
  - `@callback on_new_registration(dialog_id :: pid, registerreq :: map, transaction_id :: pid) :: {:accept, pid} | {:reject, integer, binary}`
- `SIPSession.ex` (`ConfigRegistry`) :
  - `dispatch(dialog_id, req, transaction_id)` pour `:REGISTER`.
  - corriger la faute `dispach/3` → `dispatch/3` et router vers
    `:on_registration_expired` (au lieu de `:on_new_registration`).
- `SIPDialogImpl.ex` (`init/1` `:inbound`) : propager le pid de transaction
  (`pid`) → `ConfigRegistry.dispatch(self(), req, pid)`.
- Mettre à jour le callers existant : `TestRegistrar` (`test/test_helper.exs`)
  passe en `/3`.

**Test (Phase 1)** : `test/sip_register_test.exs` existant doit toujours passer
après adaptation de `TestRegistrar`. Ajouter une assertion que le 3ᵉ argument
reçu est bien un pid de transaction.

---

## Phase 2 — DSL : annotation de type de scénario

**But** : rendre un scénario introspectable comme `:uas_register`.

- `lib/dsl/SIPScenario.ex` :
  - importer `uas: 1` dans `__using__`.
  - macro `uas(kind)` → `@scenario_type :"uas_#{kind}"`.
  - `@scenario_type :uac` par défaut (init dans `__using__`).
  - `__before_compile__` génère `def __scenario_type__, do: @scenario_type`.
- `lib/dsl/SIPScenarioLoader.ex` :
  - `scenario_type(module)` → `module.__scenario_type__()` si exporté, sinon `:uac`.

**Test (Phase 2)** : `test/scenario_type_test.exs` — un module `uac` minimal
retourne `:uac` ; un module avec `uas :register` retourne `:uas_register` ;
`Loader.scenario_type/1` cohérent.

---

## Phase 3 — Mixin serveur `SIP.Session.RegisterUAS`

**But** : fournir les macros de réponse côté UAS. Quasiment des wrappers.

Dans `SIPSessionRegister.ex`, nouveau module `SIP.Session.RegisterUAS` avec
`__using__` qui : `use SIP.Context`, pose `@scenario_type :uas_register`, et
définit les macros (opérant sur `var!(sip_ctx)`) :

| Macro | Implémentation |
|---|---|
| `challenge_registration(req, dialog_pid, opts \\ [])` | `SIP.Dialog.reply(dialog_pid, req, 401, "Unauthorized", opts[:realm] || ctx.domain)` (déclenche la clause challenge existante) |
| `accept_registration(req, dialog_pid, opts \\ [])` | `req = SIP.Session.Registrar.check_register(req)` (catch `{:reject,…}`) puis `SIP.Dialog.reply(dialog_pid, req, 200, "OK", contact: …, expires: …)` |
| `reject_registration(req, dialog_pid, code, reason)` | `SIP.Dialog.reply(dialog_pid, req, code, reason, [])` |
| `check_registration_auth(req, opts \\ [])` (helper, fonction) | `SIP.Msg.Ops.check_authrequest(req, password_or_ha1, nonce)` → `:ok \| :invalid_password \| :authorization \| :nonce_mismatch` |

- Source du mot de passe pour `check_registration_auth` : point ouvert §8.4 —
  pour le MVP outil de test, prendre `ctx.appdata[:accounts]` ou un
  `opts[:password]`, à défaut acceptation inconditionnelle (mode « test loopback »).
- Notes : la vérification de nonce côté dialog est déjà faite via `:checknonce` /
  `check_authrequest` ; ne pas dupliquer.

**Test (Phase 3)** : test unitaire du mixin via un scénario factice qui répond
à un REGISTER injecté (réutilise `UDPMockup`), en vérifiant les codes 401 puis
200 capturés côté UAC mock.

---

## Phase 4 — Runner : variante UAS

**But** : permettre au registrar de lancer une instance liée au dialog entrant.

- `lib/dsl/SIPScenarioRunner.ex` :
  - `run_instance/2` : reconnaître les opts `:dialog_pid` (→ `ctx.dialogpid`) et
    `:inbound_request` (→ `ctx.appdata[:inbound_request]`). `:parent_pid` déjà géré.
  - `build_context/1` : ne pas exiger `passwd/ha1` (contexte serveur sans compte sortant).
  - `spawn_uas_instance(module, opts)` → `spawn_monitor(fn -> run_instance(module, opts) end)`,
    renvoie `{pid, ref}`.

**Test (Phase 4)** : `spawn_uas_instance/2` démarre une instance, lui envoie un
`{:REGISTER, …}`, vérifie qu'elle atteint son état d'attente puis se termine et
émet `{:scenario_exit, …}` vers le parent.

---

## Phase 5 — `Elixip.RegistrarUAS` (fabrique + quota)

**But** : implémenter le behaviour `SIP.Session.Registrar` côté outil.

- Nouveau `lib/elixipp/ElixippRegistrarUAS.ex`, `defmodule Elixip.RegistrarUAS` :
  - `@behaviour SIP.Session.Registrar`, `use GenServer`.
  - `start_link(scenario_module:, max_instances:)`.
  - state : `%{scenario_module, max_instances, instances: %{ref => %{pid, dialog_id}}, total_started, total_rejected_quota}`.
  - `on_new_registration(dlg, req, trans)` → `GenServer.call(__MODULE__, {:new_registration, dlg, req, trans})` :
    - quota atteint → `{:reject, 503, "Service Unavailable"}` (++ `total_rejected_quota`) ;
    - sinon `spawn_uas_instance(scenario_module, dialog_pid: dlg, parent_pid: self(), inbound_request: req)`, enregistre `{ref => …}`, `{:accept, pid}`.
  - `on_registration_expired(dlg, app_pid)` → `GenServer.cast`.
  - `handle_info({:DOWN, ref, …})` et/ou `{:scenario_exit, …}` → libère le slot.
  - exposer les compteurs au `--monitor` via `SIP.Scenario.Monitor`.

**Test (Phase 5)** : injecter N+1 REGISTER (UDPMockup) avec `max_instances: N`,
vérifier N × `{:accept}` + 1 × 503 ; vérifier la libération de slot après
terminaison d'une instance.

---

## Phase 6 — CLI `elixipp` : mode serveur + `--listen`

**But** : sélectionner le mode serveur et démarrer listeners + registrar.

- `lib/elixipp/ElixippCLI.ex` :
  - ajouter aux `strict:` `listen: :keep` (répétable) ; alias éventuel.
  - parser `--listen proto:port` → `{proto, :all, port}` (forme `proto:addr:port`
    = point ouvert §8.3).
  - après `resolve_module`, lire `Loader.scenario_type/1` :
    - `:uac` → comportement actuel inchangé ;
    - `:uas_register` → **mode serveur** :
      1. `Runner.bootstrap_stack()` ;
      2. démarrer listeners (`--listen` sinon défaut `{:udp, :all, 5060}`) ;
      3. `Elixip.RegistrarUAS.start_link(scenario_module: mod, max_instances: opts[:limit] || défaut)` ;
      4. `SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.RegistrarUAS)` ;
      5. boucle d'attente (réutiliser la gestion `q`/shutdown coopératif existante).
  - mettre à jour l'aide (`--help`).

**Test (Phase 6)** : test du parseur `--listen` (proto:port → triplet) ; smoke
test du mode serveur (UDP) avec un REGISTER injecté de bout en bout.

---

## Phase 7 — Listeners transports connectés (séparable, plus lourde)

**But** : écoute TCP/TLS/WSS. UDP ne nécessite que le bind paramétrable.

- UDP (`SIPTransportUDP.ex`) : `init/1` accepte `{ip, port}` de bind au lieu des
  constantes `@default_local_port`/`hd(ips)`.
- Nouveau `SIP.Transport.Listener` + `SIP.Transport.ListenerSupervisor`
  (DynamicSupervisor) ; expansion `:all` via `SIP.NetUtils.get_local_ips/1`.
- TCP/TLS/WSS : acceptor `listen` + boucle d'accept → instance de transport
  par-connexion réutilisant `Depack` + `process_incoming_message` ; variante
  `init` « socket acceptée » (cf. point ouvert §8.2). WSS : handshake `Upgrade`.
- Routage réponse : pour les transports connectés, la transaction doit utiliser
  l'instance par-connexion (déjà mémorisée comme `tpid`) — vérifier qu'aucun
  appel à `Selector.select_transport/1` n'écrase ce choix sur une réponse
  (point ouvert §8.1).

**Test (Phase 7)** : test d'intégration TCP (un client SIP de test se connecte,
envoie un REGISTER, reçoit la réponse sur la même socket).

---

## Phase 8 — Scénario de référence `scenarios/uas_register.exs`

**But** : livrer `SIP.Scenario.RegisterUAS` (cf. §5.6 du doc de conception).

- États : `initial_state` → `wait_register` (challenge/accept) → `registered`
  (refresh / un-REGISTER / `{:dialog_terminated, …}`).
- Utilise `use SIP.Scenario` + `use SIP.Session.RegisterUAS`, annotation
  `uas :register`.
- Aligner sur le style des scénarios existants (`scenarios/uac_register.exs`).

**Test (Phase 8)** : `test/uas_register_scenario_test.exs` — REGISTER sans auth
→ 401 ; REGISTER authentifié → 200 ; refresh → 200 ; expiration/un-REGISTER →
`scenario_success`. Réutiliser `test/SIP-REGISTER.txt` et
`test/SIP-REGISTER-AUTH.txt` + injection `UDPMockup`.

---

## Phase 9 — Documentation

- `README` / docs : section « Mode serveur UAS Register » — usage CLI
  (`elixipp --listen udp:5060 scenarios/uas_register.exs`), exemple de scénario,
  callbacks `SIP.Session.Registrar`, macros `SIP.Session.RegisterUAS`.
- Mettre à jour `CLAUDE.md` (couche Session : behaviour Registrar étendu /3 ;
  nouveau mixin RegisterUAS ; notion de listener) une fois l'implémentation
  stabilisée.
- Marquer dans `uas_scenario_design.md` les points ouverts §8 résolus.

---

## Ordre recommandé & jalons

1. **Jalon MVP UDP** : Phases 1 → 6 + 8 + tests associés → un `elixipp` qui
   répond aux REGISTER UDP via scénario, avec challenge/auth/quota.
2. **Jalon transports** : Phase 7 (TCP/TLS/WSS).
3. **Jalon doc** : Phase 9.

## Vérification globale

```bash
mix compile
mix test                      # suite complète
mix test test/uas_register_scenario_test.exs   # scénario de référence
# Smoke test manuel (MVP UDP) :
mix escript.build && ./elixipp --listen udp:5060 scenarios/uas_register.exs
# puis envoyer un REGISTER depuis un UAC (ex. scenarios/uac_register.exs sur un autre port)
```

> Rappel (mémoire projet) : les tests `sip_call*`/`Call2` sont *flaky* sous
> charge pleine suite (passent en isolation) — sans rapport avec ce travail.

## Points ouverts à trancher avant Phase 7 / auth réelle

Repris de `uas_scenario_design.md` §8 — les plus bloquants pour ce plan :
1. Routage des réponses sur transport **connecté** (Phase 7) — confirmer que la
   transaction réutilise bien le `tpid` accepté et non le Selector.
2. Modules acceptors dédiés vs `init` « socket acceptée » sur les transports
   existants (Phase 7).
3. Forme CLI `--listen` : `proto:port` seul, ou aussi `proto:addr:port` (Phase 6).
4. Source des credentials pour `check_registration_auth` (Phase 3) : acceptation
   inconditionnelle (test), rejeu des `accounts`, ou base dédiée.
