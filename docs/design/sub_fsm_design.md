# Conception — Sous-FSM (`sub_fsm`) et arrêt coopératif généralisé

Statut : **conception uniquement, non implémentée.** Implémentation prévue à la
prochaine session.
Public : développeur en charge de l'implémentation.

## 1. Objectif

Permettre à une machine à état (FSM) de scénario de lancer un autre scénario en
tant que **sous-machine à état**, d'obtenir un handle dessus, d'échanger `self()`
pour que les deux communiquent par envoi de messages, puis de démonter la
sous-FSM proprement.

Dans le même mouvement, **généraliser le mécanisme d'arrêt coopératif** pour
qu'il ne soit pas propre à la relation parent/enfant : n'importe quel
contrôleur externe — en particulier `elixipp` lors d'un arrêt progressif (`q`)
— peut demander à une instance de scénario en cours de se terminer proprement
via le *même* message de contrôle.

## 2. Contrainte fondamentale (pourquoi une sous-FSM doit être un process séparé)

`SIP.Scenario.Runner.run_instance/1` exécute toute la FSM **dans le process
appelant**, parce que les couches dialog/média lient les événements SIP et média
à `self()` (voir le moduledoc de `lib/dsl/SIPScenarioRunner.ex`). Deux FSM dans
un même process partageraient une seule mailbox et se voleraient mutuellement
les `{:ms_event, …}` / réponses SIP.

Donc une sous-FSM **est son propre process**, avec sa propre mailbox SIP/média.
Les deux FSM ne communiquent que par envoi explicite de messages. C'est
exactement le modèle demandé : spawn → PID → échange de `self()`.

## 3. Décisions (déjà actées)

| Décision | Choix |
|---|---|
| Référence au parent dans le contexte enfant | champ de struct dédié `parent_pid` sur `%SIP.Context{}` |
| Couplage OTP | **monitor seul** (`spawn_monitor`) ; pas de link |
| Nettoyage de l'enfant à l'arrêt du parent | **arrêt coopératif** (message de contrôle) + kill brutal de secours après timeout |
| Profondeur d'imbrication | **arbre complet** (un enfant peut lui-même spawner des enfants) |
| Nom de la fonction de spawn | **`sub_fsm`** |
| Portée de l'arrêt coopératif | **généralisée** : même message de contrôle utilisable par tout contrôleur, y compris l'arrêt progressif d'`elixipp` |

## 4. Protocole de messages

Trois familles de messages. Tous sont de simples `send/2` délivrés dans la
mailbox du process FSM et filtrés (pattern-match) dans `on_events`.

### 4.1 Messages applicatifs (entre FSM)
```
{:scenario_msg, from_name, payload}
```
- `from_name :: atom` — le *nom local stable* de l'émetteur tel que connu par le
  destinataire. Parent→enfant utilise toujours le nom fixe `:parent` (un enfant
  a exactement un parent). Enfant→parent utilise le nom que le parent a attribué
  à l'enfant au spawn (`as:`), de sorte que le parent matche un littéral stable à
  travers tous ses états.
- `payload :: term` — défini par l'application.

### 4.2 Messages de contrôle (contrôleur → FSM)
```
{:scenario_ctl, :shutdown, reason}
```
- Envoyé par un parent qui arrête ses enfants **et** par `elixipp` lors d'un
  arrêt progressif. `reason` est informatif, ex. `:parent_terminated`,
  `:elixipp_graceful`.
- `:shutdown` est le seul verbe pour l'instant ; la forme à 3 éléments laisse de
  la place pour de futurs verbes (`:pause`, `:status`, …) sans changer
  l'enveloppe.

### 4.3 Messages de cycle de vie (FSM → parent)
```
{:scenario_exit, self_name, outcome, reason}      # outcome :: :success | :failure | :aborted
{:DOWN, mon_ref, :process, pid, down_reason}      # filet de sécurité du monitor OTP
```
- Le runner émet `:scenario_exit` depuis `finalize/…` quand la FSM a un parent.
- Le `{:DOWN, …}` est le filet de sécurité si l'enfant meurt sans envoyer
  `:scenario_exit` (crash). Le parent le corrèle via le `mon_ref` stocké dans le
  handle enfant (§6.2).

## 5. Nouvelle surface DSL (`SIP.Scenario`)

Toutes les macros s'étendent en de fins wrappers au-dessus de fonctions de
`SIP.Scenario.Runner`, pour que la vraie logique soit du code testable et que
les macros restent triviales.

### 5.1 `sub_fsm/2`
```elixir
sub_fsm(target, opts)
```
- `target` — soit un module de scénario compilé (`UAS.AutoAnswer`), soit un
  chemin vers un fichier scénario `.exs` (`"scenarios/callee.exs"`). La
  résolution réutilise `SIP.Scenario.Loader.load_module!/1` / `load_file!/1`
  (déjà présents).
- `opts` :
  - `as: atom` (**obligatoire**) — nom local de l'enfant dans ce parent. Sert à
    l'adresser (`notify/2`) et à taguer les messages que l'enfant renvoie au
    parent.
  - `args: map` (optionnel) — données initiales fusionnées dans l'appdata du
    contexte enfant, lisibles dans l'enfant via `appdata_get/1`.
- Effet : charge le module, `spawn_monitor` un process exécutant
  `run_instance(module, parent_pid: self(), self_name: name, appdata: args,
  slot_id: …)`, enregistre un handle `%SIP.Scenario.Child{}` dans l'appdata du
  contexte parent sous la clé `:__children__`, et **réaffecte `sip_ctx`** (pour
  que le handle survive d'un état à l'autre).
- Retour : le `sip_ctx` mis à jour (la macro réaffecte `var!(sip_ctx)`, comme
  `ctx_set`), de sorte qu'un corps d'état l'utilise comme une instruction
  normale :

```elixir
state initial_state do
  sub_fsm UAS.AutoAnswer, as: :callee, args: %{play: "ring.wav"}
  goto calling
end
```

### 5.2 `notify/2` et `notify_parent/1`
```elixir
notify(child_name, payload)   # parent → enfant nommé : {:scenario_msg, :parent, payload}
notify_parent(payload)        # enfant → parent       : {:scenario_msg, self_name, payload}
```
- `notify/2` résout le PID de l'enfant depuis
  `sip_ctx.appdata[:__children__][name]`. Nom inconnu → log + no-op (ne fait pas
  planter la FSM).
- `notify_parent/1` lit `sip_ctx.parent_pid`. **No-op quand `parent_pid == nil`**
  — c'est ce qui rend un scénario sous-FSM également exécutable de façon autonome
  (`mix scenario`, exécution `elixipp` simple) sans aucun cas particulier.

### 5.3 `on_shutdown do … end` (optionnel)
Un état spécial, déclaré optionnellement, qui s'exécute lorsqu'un
`{:scenario_ctl, :shutdown, _}` est reçu (voir §7). Compile vers une fonction
d'état réservée `__state___shutdown__/1`. Son corps se termine par une macro de
transition normale (`scenario_aborted/1` recommandé, mais `goto une_etape` ou
même `scenario_success/1` sont autorisés si le scénario veut une terminaison
spécifique).

```elixir
on_shutdown do
  # libérer les ressources applicatives, envoyer un BYE, etc.
  scenario_aborted("le contrôleur a demandé l'arrêt")
end
```
Si un scénario ne déclare **pas** `on_shutdown`, le runner fournit un défaut
intégré (§7.3).

### 5.4 `scenario_aborted/1` (nouvelle macro terminale)
Reflète `scenario_success/1` / `scenario_failure/1` mais produit un troisième
verdict, `:aborted`, pour qu'une terminaison provoquée par un contrôleur ne soit
*pas* comptée comme un échec. Forme : `{:terminal, :aborted, reason, type,
sip_ctx}`.

## 6. Changements du contexte et du handle

### 6.1 `%SIP.Context{}` (`lib/framework/SIPContext.ex`)
- Ajouter le champ `parent_pid: nil`.
- L'ajouter à `@props` et ajouter une clause `set/3` :
  ```elixir
  def set(context, :parent_pid, nil), do: Map.put(context, :parent_pid, nil)
  def set(context, :parent_pid, pid) when is_pid(pid), do: Map.put(context, :parent_pid, pid)
  ```
- `get/2` route déjà les props connues ; y ajouter `:parent_pid`.
- `self_name` et la map des enfants restent dans `appdata` (variable, pas de
  premier ordre) :
  - `appdata[:__self_name__] :: atom | nil`
  - `appdata[:__children__] :: %{atom => %SIP.Scenario.Child{}}`

### 6.2 `SIP.Scenario.Child` (nouveau struct)
```elixir
defmodule SIP.Scenario.Child do
  defstruct [:name, :pid, :ref, :module]
  # name   :: atom        nom local attribué par le parent (`as:`)
  # pid    :: pid         process de la FSM enfant
  # ref    :: reference   ref de monitor (pour corréler {:DOWN, ref, …})
  # module :: module      module de scénario résolu
end
```

## 7. Arrêt coopératif généralisé

C'est la partie partagée par le démontage piloté par le parent et l'arrêt
progressif d'`elixipp`.

### 7.1 Comment une FSM observe une demande d'arrêt
Un scénario ne lit sa mailbox que lorsqu'il est dans un `on_events` (un
`receive`). Donc `on_events` est **auto-instrumenté à la compilation** pour
matcher aussi le message de contrôle, *sauf si le scénario a déjà écrit une
clause `:scenario_ctl` explicite* (détectée en réutilisant l'inspection de
pattern de clause existante dans `SIPScenario.ex`, `first_element_type/1`).

La clause injectée est ajoutée aux clauses du `do` :
```elixir
{:scenario_ctl, :shutdown, _reason} ->
  Process.put(:scenario_event_type, :control)
  {:goto, :__shutdown__, "shutdown", :control, var!(sip_ctx)}
```
Ceci saute vers l'état réservé `:__shutdown__`. Comme elle est ajoutée en fin,
toute clause utilisateur qui matche un message plus spécifique gagne par
position.

> Limite à documenter : une demande d'arrêt n'est traitée qu'au prochain
> `on_events`. Un scénario bloqué dans un long état synchrone (ou un `receive`
> nu) ne réagira pas tant qu'il n'atteint pas un `on_events`. Le kill brutal de
> secours du contrôleur (§7.4 / §8) couvre ce cas.

### 7.2 L'état réservé `:__shutdown__`
- Si le scénario a déclaré `on_shutdown`, le runner trouve
  `__state___shutdown__/1` et l'exécute comme n'importe quel état.
- Le type d'événement `:control` alimente le monitor / le journal de séquence
  comme une nouvelle voie (§9).

### 7.3 Défaut intégré quand `on_shutdown` est absent
Dans `Runner.loop/4`, quand la cible est `:__shutdown__` et que
`function_exported?(module, :__state___shutdown__, 1)` est faux :
```elixir
finalize(module, ctx, :aborted, reason)   # reason "shutdown"
```
Ainsi chaque scénario est shutdown-aware gratuitement : il se termine avec le
verdict `:aborted` et passe par le nettoyage normal (libération média, callback
cleanup, flush du journal de séquence).

### 7.4 Parent arrêtant ses enfants
Dans `Runner.finalize/…`, après avoir calculé le verdict et **avant** de
retourner, pour chaque handle enfant dans `appdata[:__children__]` :
1. `send(child.pid, {:scenario_ctl, :shutdown, :parent_terminated})`.
2. Attendre (borné, ex. 5 s au total, en réutilisant/étendant la fenêtre
   d'attente existante de `release_media/1`) un `{:scenario_exit, name, …}` ou un
   `{:DOWN, ref, …}` pour chaque enfant.
3. Tout enfant encore vivant après le délai de grâce → `Process.exit(pid,
   :kill)`.

Comme l'arbre est arbitraire, ceci est naturellement récursif : chaque niveau
arrête ses propres enfants en se finalisant.

## 8. Intégration `elixipp` (arrêt progressif)

Fichier : `lib/elixipp/ElixippCLI.ex`.

### 8.1 Conserver le PID de l'enfant
`spawn_slot/2` stocke aujourd'hui `slots: %{slot_id => mon_ref}` et jette le PID.
À changer en `slots: %{slot_id => {pid, mon_ref}}`. Mettre à jour tous les
lecteurs :
- `handle_slot_done/2`, `handle_slot_crash/2` (le `Enum.find` sur `mon_ref`),
- `done?/1`, `block_state/1` (utilise `map_size(state.slots)` — non affecté).

### 8.2 L'arrêt progressif envoie le message de contrôle
`handle_graceful_stop/1` ne fait aujourd'hui que poser `shutdown: :graceful`
(stopper les spawns, attendre). L'étendre : au premier `q`, diffuser aussi à
chaque slot actif
```elixir
send(pid, {:scenario_ctl, :shutdown, :elixipp_graceful})
```
et démarrer un **timer de grâce** (ex. `Process.send_after(self(),
:shutdown_deadline, grace_ms)`), pour que le `receive` existant de
`parallel_loop/1` apprenne un nouveau message :
```elixir
:shutdown_deadline ->
  # tuer tout slot encore vivant, puis retomber sur done?/1
  Enum.each(state.slots, fn {_sid, {pid, _ref}} -> Process.exit(pid, :kill) end)
  parallel_loop(state)
```
Effet net de `q` : plus de nouveaux appels **et** les appels actifs sont invités
à se terminer proprement ; ceux qui ignorent la demande (aucun `on_events`
atteint) sont tués au délai. `Ctrl+D` (`:force_quit`) est inchangé — arrêt
immédiat et brutal.

### 8.3 Nouveau compteur de verdict `:aborted`
Point de décision (recommandé : **l'ajouter**). `run_instance/2` retourne
`{:aborted, reason}` pour le nouveau verdict. Répercussions :
- Cas exécution unique de `Elixipp.CLI.main/1` (`module.run(true)`) : ajouter une
  clause `{:aborted, _}` (traiter comme une sortie sans échec, message +
  `System.halt(0)` ou un code dédié).
- `handle_slot_done/2` : ajouter `{:aborted, _} -> total_aborted + 1` et porter
  un compteur `total_aborted` dans `state`.
- `print_summary/1` + la ligne de compteurs (`render_counters/7`) : afficher
  « Interrompus ».
- Code de sortie : garder `1` uniquement quand `total_failed > 0` ; un abort ne
  fait pas échouer le run.

Si on fond plutôt `:aborted` dans `:failure`, aucun des changements ci-dessus
n'est nécessaire, mais les arrêts progressifs gonflent le compteur d'échecs —
**non recommandé**.

## 9. Inférence de type d'événement et monitoring

- `SIPScenario.ex` `first_element_type/1` : ajouter
  - `:scenario_msg → :scenario`
  - `:scenario_ctl → :control`
  - `:scenario_exit → :scenario`
  pour qu'un `goto` après une telle clause soit auto-typé (pas besoin de `type`
  explicite).
- `SIP.Scenario.Monitor` `@type command_type` : étendre avec `:scenario |
  :control`.
- `Elixipp.CLI.color_for/1` : ajouter des couleurs pour les voies `:scenario` et
  `:control`.
- Le journal de séquence enregistre déjà `(state, event, event_type)` ; les deux
  nouveaux types passent inchangés et donnent des voies inter-FSM / contrôle dans
  le diagramme.

## 10. Résumé des flux de messages

```
Spawn :
  parent : sub_fsm(M, as: :callee)
        → spawn_monitor → l'enfant exécute run_instance(M, parent_pid: parent, self_name: :callee)
        → handle %Child{name: :callee, pid, ref, module: M} stocké dans l'appdata parent

Échange en régime établi :
  enfant : notify_parent(:ready)     → mailbox parent : {:scenario_msg, :callee, :ready}
  parent : notify(:callee, :go)      → mailbox enfant : {:scenario_msg, :parent, :go}

L'enfant se termine normalement :
  enfant finalize(:success)          → mailbox parent : {:scenario_exit, :callee, :success, r}
                                     (+ {:DOWN, ref, …, :normal} ignoré par le parent)

Le parent se termine (quel que soit le verdict) :
  parent finalize                    → chaque enfant : {:scenario_ctl, :shutdown, :parent_terminated}
                                     → attente ≤ grâce → Process.exit(:kill) des retardataires

elixipp progressif (q) :
  CLI                                → PID de chaque slot actif : {:scenario_ctl, :shutdown, :elixipp_graceful}
                                     → :shutdown_deadline → kill des retardataires
  le scénario réagit dans on_events → :__shutdown__ → finalize(:aborted)
                                     → CLI slot_done {:aborted, r} → total_aborted++
```

## 11. Checklist d'implémentation (par fichier)

1. `lib/framework/SIPContext.ex` — champ `parent_pid`, `@props`, clauses `set/3`
   + `get/2`.
2. `lib/dsl/SIPScenario.ex` —
   - macros `sub_fsm/2`, `notify/2`, `notify_parent/1`, `scenario_aborted/1`
     (les ajouter à la liste `import only:` dans `__using__`) ;
   - macro `on_shutdown` → état réservé `__state___shutdown__/1` ;
   - auto-injection dans `on_events` de la clause `:scenario_ctl` (ignorée si
     présente) ;
   - étendre `first_element_type/1` pour les trois nouveaux tags.
3. `lib/dsl/SIPScenarioRunner.ex` —
   - `run_instance/2` avec les options `parent_pid:`/`self_name:`/`appdata:`/`slot_id:`
     (garder `run_instance/1` qui délègue avec des défauts) ;
   - helpers `spawn_child/4`, `notify_child/3`, `notify_parent/2` ;
   - gestion dans `loop/4` de la cible `:__shutdown__` (défaut → `:aborted`) et de
     la branche `{:terminal, :aborted, …}` ;
   - `finalize/…` émet `{:scenario_exit, …}` vers `parent_pid` et arrête les
     enfants (coopératif + kill de secours) ; ajouter la gestion du verdict
     `:aborted` et le retour `{:aborted, reason}`.
4. `lib/dsl/SIPScenarioChild.ex` (nouveau) — struct `SIP.Scenario.Child`.
5. `lib/elixipp/ElixippCLI.ex` — conserver le pid dans `slots`, diffuser
   `:scenario_ctl` à l'arrêt progressif + timer `:shutdown_deadline` + kill de
   secours, compteur `total_aborted`, résumé/compteurs, clause `{:aborted, _}`
   en exécution unique.
6. `lib/elixipp/SIPScenarioMonitor.ex` — étendre `command_type` avec `:scenario |
   :control`.
7. Tests — une paire de scénarios parent + enfant sous `test/`, utilisant
   `MediaServer.Mockup` / `UDPMockup`, vérifiant : l'aller-retour de messages, la
   propagation de la fin de l'enfant, l'arrêt piloté par le parent, l'enfant
   autonome (`parent_pid == nil` → no-op), et un chemin d'arrêt progressif
   `elixipp`.

## 12. Points ouverts à confirmer avant de coder

- **`:aborted` comme verdict distinct** vs fondu dans `:failure` (§8.3).
  Recommandé : distinct.
- **Valeurs des délais de grâce** : attente d'arrêt des enfants dans `finalize`
  (réutiliser la fenêtre média de 5 s ?) et `:shutdown_deadline` d'`elixipp` (ex.
  5–10 s). Choisir des nombres concrets.
- **`as:` obligatoire ?** Proposé : oui (l'adressage + le re-tag nécessitent un
  nom). Alternative : générer un nom automatiquement quand il est omis (enfants à
  qui on ne parle jamais).
- **Enfant autonome recevant `:scenario_ctl`** : avec la conception généralisée,
  il réagit même sans parent (bien pour `elixipp`) ; confirmer que c'est
  souhaité pour *tous* les scénarios.
```
