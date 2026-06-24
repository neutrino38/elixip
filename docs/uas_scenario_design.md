# Specs

## Listeners

Pour qu'elixip et ses produit dérivés puisse se comporter comme un UAS, il faut qu'il écoute sur des
port TCP, UDP et s'attendent à des connexion SIP sur UDP, TCP, TLS ou WSS. On doit donc ajouter à 
elixip la notion de listener, c'est à dire d'instance de transport à l'écoute de requête entrante,
mais surtout, dans le cas des transport connecté, un serveur TCP, un serveur TLS et un serveur WSS.

- on doit pouvoir configurer des 'listener SIP' soit programmatiquement soit par config.
- chaque listner est un triplet { protocole, adresse, port }. Par ex { :wss, 172.21.100.2, 8443 }
- L'adresse IP peut être IP V4 ou IP V6.
- si l'adresse est remplacée par :all alors un listener par adresse IP valide est créé
- la commande elixipp (l'outil de test) doit pouvoir prendre une ou plusieurs commande --listen protocole:port équivalent à { protocole, :all, port } pour configurer dynamiquement des listener

## Blocs fonctionnels SIP

Le protocole SIP couvre trois blocs fonctionnels distincts :

- le traitement des appels (Call Server)
- le Registrar
- le serveur de présence et de messagerie instantanée

Dans un serveur SIP, chacun des trois blocs fonctionnels sera traité par un script distinct.

On va se concentrer dans un premier temps sur le registrar

## Scénarios de type serveur (UAS)

L'idée est de proposer que le traitement de requête SIP entrante puisse être pris en charge par un
scénario en DSL d'automate a état fini pour proposer

- un outil de test `elixipp` capable d'attendre des requêtes et de les traiter par scénario
- un serveur SIP scriptable qui traite les requêtes par des scénario chargés à froid ou à chaud

Un script UAS commence par un état `initial_state` qui comporte essentiellement un bloc qui ressemble à :

```Elixir
on_event do
   { :REGISTER, req, transaction_id, dialog_id } -> next 
```
Le scénario est en charge de traiter le message et d'envoyer la réponse

Un scénario UAS register comporte des annotation qui permette d'indiquer au moteur de scénario que l'on est dans le cadre d'un scénario UAS type Registrar.


# Points de conception

## Mécanisme de traitement du module SIP.Session.Registrar

Le mécanisme pour traiter des requêtes SIP entrante est le suivant :

on doit enregistrer un module pour chaque type de requête :
  - pour un dialog initié par un REGISTER, il faut appeler SIP.Session set_registration_processing_module(monmodule)
  - ensuite ce module doit implémenter les callbacks définie dans SIP.Session.Registar
    - @callback on_new_registration(dialog_id :: pid, registerreq :: map) :: { :accept, pid } | { :reject, integer, binary }
    - @callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: nil
  - la callback lance une instance du scénario associé au registrar et retourne { :accept, scenario_pid }
  - la callback envoi ensuite au scénario { :REGISTER, registerreq, trans_id, dialog_id }

  Il faut donc enrichir la callback pour qu'elle transmette le transaction_id associé à la création du dialog.

On a donc besoin de deux modules dans le cas d'Elixipp (l'outil de test)


- Elixip.RegistrarUAS qui offre les callbacks
- le module de test SIP.Scenario.RegisterUAS (ou un autre) 

## Rôle d'Elixipp

Le rôle d'Elixipp est de :
- de charger le scénario passé en ligne de commande, de l'inspecter pour déterminer que c'est un scénarion type UAS Register.
- démarrer les différentes couches de la pile SIP Elixip
- de démarrer les listener passés en ligne de commande ou configurés dans elixip.
- d'enregistrer le SIP.Scenario.RegisterUAS à l'aide de SIP.Session set_registration_processing_module()
- d'implémenter les callback du module SIP.Session.Registrar pour être conforme au behavior
- dans cette callback de vérifier que la limite de nombre d'instance de scénario n'est pas dépasser et de refuser le REGISTER sinon.
- de lancer une instance de scénario sinon et d'envoyer le message { :REGISTER, req, transaction_id, dialog_id } à ce dernier.

---

# Conception détaillée

> Cette partie complète la spec ci-dessus. Elle s'appuie sur l'architecture
> existante : couche Transaction → Dialog → Session/ConfigRegistry, et moteur
> de scénario `SIP.Scenario.Runner`. Elle réutilise les briques déjà en place
> (voir [[project-dialog-terminated-contract]] et [[project-sub-fsm-design]]).

## 1. Vue d'ensemble du flux entrant

```
 (réseau)                Transaction         Dialog              ConfigRegistry        Elixip.RegistrarUAS         Instance scénario
    │                        │                  │                      │                       │                         │
    │  REGISTER ───────────► │                  │                      │                       │                         │
    │              process_sip_message          │                      │                       │                         │
    │                        │  crée UAS trans   │                      │                       │                         │
    │                        │ ───────────────► process_incoming_request│                       │                         │
    │                        │                  │ start_dialog(:inbound)│                       │                         │
    │                        │                  │   init/1  ──────────► dispatch(dlg, req)      │                         │
    │                        │                  │                      │  on_new_registration   │                         │
    │                        │                  │                      │  (dlg, req, trans) ───►│  vérifie quota          │
    │                        │                  │                      │                       │  spawn instance ──────► │ run_instance (UAS)
    │                        │                  │                      │  ◄── {:accept, pid} ───│  monitor(pid)           │ (FSM démarre, attend
    │                        │                  │ ◄── {:accept, app}    │                       │                         │  en on_events)
    │                        │                  │ send(app,             │                       │                         │
    │                        │                  │  {:REGISTER,req,       ─────────────────────────────────────────────► │ initial_state reçoit
    │                        │                  │   trans, dlg})        │                       │                         │ le message
    │                        │                  │                      │                       │                         │
    │  401 / 200 ◄───────────────────────────── reply(dlg, req, code…) ◄──────────────────────────────────────────────── │ accept/challenge/reject
```

Trois nouveautés sont nécessaires :

1. **Listeners** côté transport (écoute des requêtes entrantes) — §2.
2. **Enrichissement de la couche Session** : passage du `transaction_id` à la
   callback `on_new_registration` — §3.
3. **Côté DSL** : annotation de type de scénario + mixin serveur
   `SIP.Session.RegisterUAS` + variante UAS de `run_instance` — §5.

## 2. Listeners

### 2.1 Modèle

Un **listener** est une instance de transport en mode écoute, décrite par le
triplet `{ protocole, adresse, port }` :

- `protocole ∈ { :udp, :tcp, :tls, :wss }`
- `adresse` : IPv4 / IPv6, ou `:all`
- `port` : entier

`:all` est développé **au démarrage** en un listener par adresse IP valide
retournée par `SIP.NetUtils.get_local_ips/1` (déjà utilisé par le transport UDP).
L'expansion produit donc N triplets concrets `{proto, ip, port}`.

### 2.2 Configuration

Deux sources, fusionnées (la CLI a priorité sur la config) :

- **Config statique** dans `config/config.exs` :
  ```elixir
  config :elixip2, :listeners, [
    {:udp, :all, 5060},
    {:wss, {172,21,100,2}, 8443}
  ]
  ```
- **CLI `elixipp`** : option répétable `--listen proto:port` équivalente à
  `{proto, :all, port}`. Ex. `--listen udp:5060 --listen wss:8443`.
  Une forme étendue `--listen proto:addr:port` est réservée pour cibler une IP
  précise (point ouvert §8).

### 2.3 Architecture des processus

Ajout d'un superviseur de listeners (nouveau module, p.ex.
`SIP.Transport.Listener` + `SIP.Transport.ListenerSupervisor`) démarré par
`Runner.bootstrap_stack/0` **uniquement en mode serveur** (l'outil UAC actuel
n'en a pas besoin) :

```
SIP.Transport.ListenerSupervisor (DynamicSupervisor)
  ├── listener {:udp,  ip, port}   → réutilise SIP.Transport.UDP (déjà bidirectionnel)
  ├── listener {:tcp,  ip, port}   → acceptor :gen_tcp/Socket.TCP.listen + accept loop
  ├── listener {:tls,  ip, port}   → idem TLS
  └── listener {:wss,  ip, port}   → idem + handshake WebSocket
```

### 2.4 Impact par transport

- **UDP** (`SIP.Transport.UDP`) : déjà en `mode: :active` et reçoit les
  datagrammes entrants (`handle_info({:udp, …})` → `process_incoming_message`).
  Le **seul changement** est de paramétrer l'IP/port de bind au lieu des
  constantes `@default_local_port = 5060` et `hd(ips)`. `init/1` doit accepter
  `{ip, port}` de bind. Un listener UDP = une instance de transport bindée.

- **TCP / TLS / WSS** : aujourd'hui **client uniquement** — `init/1` *se connecte*
  à une destination (`ImplHelpers.connect`). Côté serveur il manque un
  **acceptor** :
  1. `listen` sur `{ip, port}` ;
  2. boucle d'accept qui, pour chaque connexion entrante, **démarre une
     instance de transport par-connexion** réutilisant la logique de réception
     existante (`Depack` + `process_incoming_message`). Il faut donc une
     variante d'`init` qui prend une **socket déjà connectée** plutôt qu'une
     destination à joindre.
  3. WSS ajoute le handshake `Upgrade: websocket` avant de passer en flux SIP.

### 2.5 Routage des réponses (point clé)

Pour un transport connecté, la réponse doit repartir **sur la même connexion**
que la requête. Le chemin actuel `Selector.select_transport(ruri)` choisit un
transport à partir de l'URI de destination — inadapté à une réponse UAS.

Décision de conception : la requête entrante propage l'instance de transport
qui l'a reçue (`process_incoming_message` connaît déjà `__MODULE__`/socket).
La transaction serveur (IST/NIST) doit mémoriser cette instance et l'utiliser
pour émettre la réponse, court-circuitant le Selector. À détailler avec la
couche Transaction (§8, point ouvert).

## 3. Couche Session — enrichissement des callbacks

### 3.1 Behaviour `SIP.Session.Registrar`

La spec demande que la callback reçoive le `transaction_id` de la transaction
ayant créé le dialog. On fait évoluer la signature :

```elixir
# AVANT
@callback on_new_registration(dialog_id :: pid, registerreq :: map) ::
            {:accept, pid} | {:reject, integer, binary}

# APRÈS
@callback on_new_registration(
            dialog_id :: pid,
            registerreq :: map,
            transaction_id :: pid
          ) :: {:accept, pid} | {:reject, integer, binary}

@callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: any()
```

### 3.2 ConfigRegistry.dispatch + DialogImpl.init

`SIP.DialogImpl.init/1` dispose déjà du pid de transaction (`pid`, premier
élément de `transactions`). Il faut le propager :

```elixir
# lib/framework/SIPSession.ex  (ConfigRegistry)
def dispatch(dialog_id, req, transaction_id)
    when is_map(req) and req.method == :REGISTER do
  internal_dispatch(:registration, :on_new_registration,
    [dialog_id, req, transaction_id], "No registration server defined")
end

# lib/framework/SIPDialogImpl.ex  (init :inbound)
case SIP.Session.ConfigRegistry.dispatch(self(), req, pid) do
  {:accept, app_id} ->
    send(app_id, {req.method, req, pid, self()})   # inchangé
    {:ok, Map.put(state, :app, app_id)}
  {:reject, code, reason} -> {:stop, :abnormal, reason}
end
```

> Remarque : le `transaction_id` arrive donc **deux fois** côté application —
> une fois à la callback (pour décider accept/reject, voire répondre
> immédiatement à un challenge) et une fois dans le message `{:REGISTER, …}`
> envoyé à l'instance de scénario. C'est voulu : la callback et l'instance sont
> deux processus distincts.

> Bug annexe repéré, à corriger au passage : `ConfigRegistry.dispach/3`
> (faute de frappe, ligne ~220) pour `on_registration_expired` appelle
> `:on_new_registration`. À renommer `dispatch` et router vers
> `:on_registration_expired`.

## 4. Module `Elixip.RegistrarUAS` (callbacks génériques de l'outil)

Module fourni par **elixipp** (et réutilisable par un serveur dérivé). Il
implémente le behaviour `SIP.Session.Registrar` et joue le rôle de fabrique
d'instances de scénario, avec **contrôle de quota**.

```elixir
defmodule Elixip.RegistrarUAS do
  @behaviour SIP.Session.Registrar
  use GenServer        # détient l'état : module de scénario, quota, table d'instances

  # Configuré au démarrage par elixipp :
  #   - scenario_module : le module SIP.Scenario.* de type :uas_register chargé
  #   - max_instances   : limite (depuis --limit / config)

  @impl true
  def on_new_registration(dialog_id, registerreq, transaction_id) do
    GenServer.call(__MODULE__, {:new_registration, dialog_id, registerreq, transaction_id})
  end

  @impl true
  def on_registration_expired(dialog_id, app_pid) do
    GenServer.cast(__MODULE__, {:expired, dialog_id, app_pid})
  end
end
```

État interne (struct GenServer) :

| Champ | Rôle |
|---|---|
| `scenario_module` | module de scénario UAS chargé par elixipp |
| `max_instances`   | quota d'instances concurrentes |
| `instances`       | `%{monitor_ref => %{pid, dialog_id}}` |
| `total_started` / `total_rejected_quota` | compteurs pour le `--monitor` |

Logique de `{:new_registration, …}` :

1. Si `map_size(instances) >= max_instances` → `{:reject, 503, "Service Unavailable"}`
   (incrémente `total_rejected_quota`).
2. Sinon : spawn d'une instance via la variante UAS du runner (§5.4) :
   ```elixir
   {pid, ref} = SIP.Scenario.Runner.spawn_uas_instance(
     scenario_module,
     dialog_pid:     dialog_id,
     parent_pid:     self(),
     inbound_request: registerreq)
   ```
   enregistre `{ref => %{pid, dialog_id}}`, renvoie `{:accept, pid}`.
3. À la réception de `{:DOWN, ref, :process, pid, _reason}` ou de
   `{:scenario_exit, _name, _outcome, _reason}` → retire l'entrée, libère un
   slot de quota.

> Pas besoin de stocker le `transaction_id` côté registrar : l'instance le
> reçoit dans le message `{:REGISTER, …}` et c'est elle qui répond. La callback
> pourrait l'utiliser pour un rejet immédiat (quota dépassé → `:reject` sans
> même spawner), auquel cas le code Dialog construit lui-même la réponse.

## 5. Couche DSL — scénarios UAS

### 5.1 Annotation de type de scénario

Nouvelle macro DSL exposant `__scenario_type__/0`. Par défaut un scénario est
`:uac` ; un scénario serveur le déclare explicitement :

```elixir
defmodule SIP.Scenario.RegisterUAS do
  use SIP.Scenario
  use SIP.Session.RegisterUAS     # mixin serveur (§5.3) ; pose aussi le type

  uas :register                   # → @scenario_type :uas_register
  config domain: "example.com"
  ...
end
```

Implémentation dans `SIP.Scenario` :

- macro `uas(kind)` qui fait `@scenario_type :"uas_#{kind}"` ;
- `@before_compile` génère `def __scenario_type__, do: @scenario_type`
  (valeur par défaut `:uac`).

### 5.2 Introspection par le Loader

`SIP.Scenario.Loader` expose le type pour qu'elixipp décide du mode (UAC
sortant vs UAS écoute) :

```elixir
def scenario_type(module) do
  if function_exported?(module, :__scenario_type__, 0),
    do: module.__scenario_type__(), else: :uac
end
```

`scenario_module?/1` reste inchangé (run/1 + __scenario_states__/0).

### 5.3 Mixin serveur `SIP.Session.RegisterUAS`

Symétrique de `SIP.Session.RegisterUAC`, mais pour **répondre** aux REGISTER.
Fournit les macros de réponse, opérant sur `var!(sip_ctx)` et s'appuyant sur
`SIP.Dialog.reply/5` (déjà existant) et `SIP.Auth` / `nonce_map` du dialog
(déjà géré dans `SIP.DialogImpl`, cf. `check_expired_nonces`). `use` de ce
mixin pose aussi `@scenario_type :uas_register`.

| Macro | Effet | Réponse SIP |
|---|---|---|
| `challenge_registration(req, dialog_pid, opts \\ [])` | génère un nonce (stocké dans le dialog), renvoie un défi digest | `401 Unauthorized` + `WWW-Authenticate` |
| `accept_registration(req, dialog_pid, opts)` | valide les bindings ; `opts[:expires]` (sinon valeur négociée via `SIP.Session.Registrar.check_register/1`) ; `opts[:contact]` (défaut : écho des Contact reçus) | `200 OK` + `Contact` + `Expires` |
| `reject_registration(req, dialog_pid, code, reason)` | rejet explicite | `code reason` (ex. 403, 423, 503) |
| `check_registration_auth(req, dialog_pid)` (helper, retourne bool/`:ok`/`:stale`) | vérifie l'`Authorization` contre `ha1`/`nonce` connus | — |

`check_register/1` (déjà présent dans `SIP.Session.Registrar`) est réutilisé
pour borner/ajuster les `Expires` (min 60, max 3600, max 5 contacts) et lever
le `{:reject, 423, …}` / `{:reject, 400, …}` approprié.

### 5.4 Variante UAS du runner

Décision retenue : **étendre `run_instance/2`** (option recommandée), pas de
runner séparé. On ajoute :

- une fonction `spawn_uas_instance(module, opts)` qui fait
  `spawn_monitor(fn -> Runner.run_instance(module, opts) end)` et renvoie
  `{pid, ref}` (utilisée par le registrar) ;
- de nouvelles `opts` reconnues par `run_instance/2` /`build_context/1` :
  - `:dialog_pid` → `ctx.dialogpid` (les macros de réponse ciblent ce dialog),
  - `:inbound_request` → rangé en `ctx.appdata[:inbound_request]` (optionnel :
    l'instance le reçoit aussi via le message `{:REGISTER, …}`),
  - `:parent_pid` (déjà supporté) → le registrar, pour `{:scenario_exit, …}`.

Le **contexte** d'un scénario UAS n'est plus semé depuis un compte de la config
externe (pas de `passwd`/`ha1` sortant) ; il est semé depuis la requête
entrante. La résolution `ha1` pour la vérification d'auth se fait au moment du
challenge à partir d'une base de comptes (point ouvert §8 : source des
credentials côté serveur — pour l'outil de test, on peut accepter
inconditionnellement ou rejouer la config externe `accounts`).

### 5.5 Contrat de l'état initial & cycle de vie

- `initial_state` d'un scénario UAS **n'émet rien** : il enchaîne aussitôt sur
  un état qui attend le message via `on_events` (le message est de toute façon
  déjà dans la mailbox de l'instance — pas de course).
- L'instance répond via les macros §5.3, puis :
  - reste vivante tant que l'enregistrement est actif (gère refresh / OPTIONS) ;
  - reçoit `{:dialog_terminated, dialog_pid, reason}` (contrat existant,
    [[project-dialog-terminated-contract]]) à l'expiration / un-REGISTER, ce
    qui déclenche un `scenario_success` / cleanup ;
  - participe au shutdown coopératif `{:scenario_ctl, :shutdown, _}` déjà géré
    par le moteur ([[project-sub-fsm-design]]).
- En fin de vie, le moteur émet `{:scenario_exit, name, outcome, reason}` vers
  le `parent_pid` (le registrar), qui libère le slot de quota.

### 5.6 Scénario de référence `SIP.Scenario.RegisterUAS`

```elixir
defmodule SIP.Scenario.RegisterUAS do
  use SIP.Scenario
  use SIP.Session.RegisterUAS

  uas :register
  config domain: "example.com"

  # Reçu en mailbox dès l'accept par le registrar.
  state initial_state do
    goto next                       # → wait_register
  end

  state wait_register do
    on_events do
      {:REGISTER, req, _trans, dialog_pid} ->
        if check_registration_auth(req, dialog_pid) == :ok do
          accept_registration(req, dialog_pid, expires: 300)
          goto registered, "200 OK"
        else
          challenge_registration(req, dialog_pid)
          goto loop, "401 Unauthorized"     # ré-attend le REGISTER authentifié
        end
    after
      32_000 -> scenario_failure("no REGISTER received")
    end
  end

  state registered do
    on_events do
      {:REGISTER, req, _trans, dialog_pid} ->       # refresh ou un-REGISTER
        accept_registration(req, dialog_pid, expires: 300)
        goto loop, "refresh"
      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("registration ended")
    after
      330_000 -> scenario_failure("registration not refreshed")
    end
  end
end
```

## 6. Rôle d'Elixipp (mis à jour)

Au lancement avec un scénario de type `:uas_register` :

1. Charger le scénario (`Loader.load_file!/1` ou `load_module!/1`) et lire son
   type via `Loader.scenario_type/1`. Si `:uas_*`, basculer en **mode serveur**.
2. `Runner.bootstrap_stack/0` (Transaction, Selector, Dialog, ConfigRegistry)
   **+** démarrage du `ListenerSupervisor`.
3. Démarrer les listeners issus de `--listen …` et/ou `config :elixip2,
   :listeners`. Si aucun n'est fourni → défaut `{:udp, :all, 5060}`.
4. Démarrer `Elixip.RegistrarUAS` (GenServer) avec `scenario_module` = le
   scénario chargé et `max_instances` = `--limit`.
5. `SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.RegistrarUAS)`.
6. Le quota et les rejets `503` sont gérés par `Elixip.RegistrarUAS` (§4).
7. Le `--monitor` lit les compteurs du registrar (instances actives, total,
   rejets quota) via `SIP.Scenario.Monitor` comme pour le mode UAC.

> Le mode UAC actuel (envoi sortant, `--rate`, comptes round-robin) reste
> inchangé : il est sélectionné quand `scenario_type == :uac`.

## 7. Inventaire des changements (sans implémentation)

| Zone | Fichier(s) | Nature |
|---|---|---|
| Behaviour Registrar | `lib/framework/SIPSessionRegister.ex` | `on_new_registration/3` ; mixin `SIP.Session.RegisterUAS` |
| Dispatch | `lib/framework/SIPSession.ex` | `dispatch/3` REGISTER ; fix `dispach`→`dispatch` expired |
| Dialog | `lib/framework/SIPDialogImpl.ex` | propage `transaction_id` à `dispatch/3` |
| Listeners | `lib/framework/SIPTransport*.ex` + nouveaux `Listener`/`ListenerSupervisor` | bind paramétrable UDP ; acceptors TCP/TLS/WSS ; routage réponse via transaction |
| DSL type | `lib/dsl/SIPScenario.ex`, `SIPScenarioLoader.ex` | macro `uas/1`, `__scenario_type__/0`, `Loader.scenario_type/1` |
| Runner UAS | `lib/dsl/SIPScenarioRunner.ex` | `spawn_uas_instance/2` ; opts `:dialog_pid`/`:inbound_request` |
| Outil | `lib/elixipp/ElixippCLI.ex`, nouveau `Elixip.RegistrarUAS` | `--listen` ; sélection mode serveur ; registrar + quota |
| Scénario réf. | `scenarios/uas_register.exs` (`SIP.Scenario.RegisterUAS`) | exemple |

> **Changement de conception (2026-06-24).** Le mixin framework
> `SIP.Session.RegisterUAS` initialement prévu (§5.3) a été **supprimé** : répondre
> à un REGISTER (challenge / accept / reject / vérif. auth) relève de
> l'applicatif. Ces helpers sont donc des **fonctions privées définies dans le
> scénario** lui-même (`scenarios/uas_register.exs`), pas dans le framework. Ils
> s'appuient sur `SIP.Dialog.reply/5`, `SIP.Session.Registrar.check_register/1` et
> `SIP.Msg.Ops.check_authrequest/3`. (Ce sont des fonctions et non des macros : un
> module ne peut pas appeler une macro qu'il définit lui-même, et `sip_ctx` est le
> paramètre de la fonction d'état, donc directement passable.)
>
> **État d'implémentation (MVP UDP livré).** Les phases 1→6 + 8 du plan
> `uas_register_impl_plan.md` sont implémentées et testées
> (`test/uas_register_test.exs`, suite complète verte). Deux bugs de framework
> pré-existants ont été corrigés au passage, exposés par le chemin de challenge
> jamais exercé auparavant : `authproc: "Digest "` (espace en trop) dans
> `SIPDialogImpl` et la lecture `resp.www_authenticate.nonce` (mauvaise clé) dans
> `SIPTransactionCommon`. Restent : la phase 7 (listeners TCP/TLS/WSS) et la vérif.
> digest réelle (credentials, §8.4).

## 8. Points ouverts à confirmer

1. **Routage des réponses UAS** sur transport connecté : où mémoriser
   l'instance de transport (transaction IST/NIST ?) et comment court-circuiter
   `Selector.select_transport/1`. Nécessite une revue de la couche Transaction.
2. **Acceptors TCP/TLS/WSS** : réutiliser les modules transport existants avec
   un `init` « socket acceptée », ou créer des modules `*Server` dédiés ?
3. **Forme CLI `--listen`** : ne supporte-t-on que `proto:port` (≡ `:all`), ou
   aussi `proto:addr:port` pour cibler une IP ?
4. **Source des credentials serveur** (vérif. digest) : acceptation
   inconditionnelle (outil de test), rejeu des `accounts` de la config externe,
   ou base dédiée ?
5. **Sémantique du quota dépassé** : `503 Service Unavailable` (retenu) avec ou
   sans `Retry-After` ?
6. **Persistance des bindings** : l'outil de test garde-t-il un registrar
   « réel » (table de localisation interrogeable) ou se contente-t-il de
   répondre 200 OK par scénario ? (impacte un futur bloc Call Server / présence).

