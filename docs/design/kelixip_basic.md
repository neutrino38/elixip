# Kelixip

> Statut : **conception.** La fonction *registrar* et l'infrastructure serveur
> (config, packaging, CLI, API de contrôle, modules) constituent le périmètre
> « basic ». Les fonctions *b2bua* et *présence*, ainsi que la *haute
> disponibilité*, sont conçues ici mais leur implémentation est **roadmap**
> (voir §14).

## 1. Kelixip en quelques mots

Kelixip est un serveur d'application SIP scriptable. Il s'inspire de **Kamailio**
et **OpenSIPS**. Les scénarios de kelixip sont écrits en FSL
(`SIP.Scenario`) et exécutés par le moteur FSM déjà présent dans elixip.

Kelixip est packagé comme un **service systemd** (release OTP) et se pilote via
un CLI (`kelictl`) et une API de contrôle REST.

## 2. Architecture : domaines et fonctions combinables

Kelixip sert **un ou plusieurs domaines SIP**. Chaque domaine active
**indépendamment** tout ou partie des **trois fonctions** ; toutes les
combinaisons sont possibles (un domaine registrar seul, un autre registrar +
appels, etc.).

| Fonction    | Rôle SIP                              | Méthodes                | Statut    |
|-------------|---------------------------------------|-------------------------|-----------|
| `registrar` | Enregistrement / localisation (usrloc)| `REGISTER`              | **basic** |
| `calls`     | Traitement d'appels (B2BUA)           | `INVITE` (+ in-dialog)  | roadmap   |
| `presence`  | Serveur de présence                   | `SUBSCRIBE` / `PUBLISH` / `NOTIFY` / `MESSAGE` | roadmap |

### 2.1 Dispatch d'une requête entrante

Les listeners sont **partagés** par tous les domaines et fonctions. Une requête
out-of-dialog est routée en **trois temps** :

1. **Domaine** — le host de la Request-URI (à défaut, le host du `To`) est
   comparé au `name` et aux `aliases` de chaque domaine ; premier domaine qui
   matche. Aucun domaine ⇒ `404 Not Found`.
2. **Fonction** — selon la méthode (table ci-dessus). Fonction non activée sur
   ce domaine ⇒ `405 Method Not Allowed`.
3. **Script** — pour `registrar`/`presence`, le script de la fonction. Pour
   `calls`, le **dial-plan** du domaine : première règle dont le pattern matche
   la user-part gagne (voir §3.3).

Il n'y a donc **pas** de script de routage global à la Kamailio.

### 2.2 Séparation config / code

Principe de conception assumé : **le dispatch (quel domaine, quelle fonction,
quel script) est de la configuration déclarative ; la logique (ce que fait
l'appel) est du FSL.** Le FSL ne contient **aucun routage**.

| Couche | Question | Où |
|---|---|---|
| **Dispatch** | domaine ? fonction activée ? pattern → script ? | config (`domains.toml`) |
| **Logique d'appel** | que fait l'appel une fois le script choisi ? | FSL |
| **Décision sur données runtime** | routage selon BDD, heure, droits… | FSL, **dans le script choisi** (logique d'appel, pas dispatch) |

Conséquences : le dial-plan est de la **donnée** (éditable par l'exploitant ou
l'API de contrôle, rechargeable à chaud sans risque) ; le FSL reste un FSM
par-appel ; et un routage dépendant de données runtime (numéro porté, heure…) se
fait naturellement **en Elixir dans le script sélectionné**, sans mini-langage
de routage dans le FSL. Ce dispatch prolonge le mécanisme existant d'elixip
(type de scénario `__scenario_type__/0`, détection par le runner), étendu au
domaine et au dial-plan.

## 3. Fichiers de configuration

La configuration est **déclarative** (aucun code exécuté, aucune injection
d'atome arbitraire) et répartie sur **deux fichiers**, séparés par cycle de vie :

| Fichier | Contenu | Change | Reload à chaud |
|---|---|---|---|
| `/etc/kelixip/config.toml` | infra : `server`, `log`, listeners, pool média, modules, API de contrôle | rarement (admin système) | non (redémarrage) |
| `/etc/kelixip/domains.toml` | domaines + fonctions activées + dial-plan | souvent (exploitant / API) | **oui** (§9) |

Les deux sont en **TOML** : un seul langage, commentaires possibles, et ordre
garanti par les *array-of-tables* `[[…]]` — essentiel pour le dial-plan (§3.3).

### 3.1 config.toml — infrastructure

```toml
# /etc/kelixip/config.toml — infrastructure (rarely changes, root-owned)

# ─── Server & global limits ───────────────────────────────────────────────
[server]
node_name  = "kelixip@127.0.0.1"   # OTP node name (used by the CLI over RPC)
script_dir = "/usr/share/kelixip"  # default directory for .exs scripts
module_dir = "/usr/lib/kelixip/modules"
user_agent = "Kelixip/1.4.0"
max_calls  = 2000                  # server-wide cap (503 beyond); per-domain caps in domains.toml

# ─── Logging ─────────────────────────────────────────────────────────────
[log]
target   = "syslog"    # "syslog" | "stdout"  (stdout also forced by --stdout)
facility = "local0"    # like Kamailio
level    = "info"       # debug | info | warning | error

# ─── SIP transports (repeatable) ─────────────────────────────────────────
[[listen]]
proto = "udp"
addr  = "0.0.0.0"       # optional, defaults to 0.0.0.0
port  = 5060

[[listen]]
proto = "tcp"
port  = 5060

[[listen]]
proto = "tls"
port  = 5061
cert  = "/etc/kelixip/tls/fullchain.pem"
key   = "/etc/kelixip/tls/privkey.pem"

[[listen]]
proto = "wss"
port  = 5065
cert  = "/etc/kelixip/tls/fullchain.pem"   # reuse the same certificate
key   = "/etc/kelixip/tls/privkey.pem"

# ─── Media server pool ───────────────────────────────────────────────────
# Several entries => selection/round-robin + failover. `enabled` is togglable
# at runtime via the CLI.
[mediaserver.pool.mcu1]
module  = "mendooze"
url     = "http://10.0.0.1:8080"
enabled = true

[mediaserver.pool.mcu2]
module  = "mendooze"
url     = "http://10.0.0.2:8080"
enabled = true

# ─── Loadable modules (.beam) ────────────────────────────────────────────
# [module.<name>] : the name links the .beam to its config block and is the
# namespace a scenario imports.
[module.auth_db]
driver   = "mariadb"
host     = "127.0.0.1"
database = "kelixip"
username = "kelixip"
password = "s3cret"
table    = "subscriber"

[module.radius_billing]
server = "10.0.0.9:1813"
secret = "radsecret"

# ─── REST control API ────────────────────────────────────────────────────
[control_api]
enabled = true
addr    = "127.0.0.1"                # loopback by default (exposure = explicit)
port    = 8090
auth    = "token"                    # "token" | "mtls" | "none"
token   = "change-me"

# ─── Metrics (Prometheus) & health ────────────────────────────────────────
[metrics]
enabled = true
addr    = "127.0.0.1"                # loopback by default; /metrics + /health
port    = 9095
```

### 3.2 domains.toml — domaines et dial-plan

Fichier **rechargeable à chaud** (§9). Un bloc de fonction **présent = activé**
(pas de clé `enabled`). Chaque domaine est une entrée `[[domain]]` ; les règles
d'appel sont des entrées `[[domain.call]]` dont **l'ordre du fichier est
significatif** (premier match gagne).

```toml
# /etc/kelixip/domains.toml — domains & dial-plan (hot-reloadable)
# A function block present = enabled. Method routing: REGISTER→registrar,
# INVITE→calls, SUBSCRIBE/PUBLISH→presence.

# ─── example.com : registrar + presence only ─────────────────────────────
[[domain]]
name      = "example.com"
aliases   = ["example.fr", "example.ca"]
max_calls = 500                        # per-domain cap (<= server.max_calls)

[domain.registrar]
script           = "registrar-example.com.exs"
default_expires  = 3600
min_expires      = 60
keepalive_period = 15                  # OPTIONS keep-alive (seconds)

[domain.presence]
script = "presence-example.com.exs"

# ─── mydomain.de : registrar + calls (dial-plan) ─────────────────────────
[[domain]]
name = "mydomain.de"

[domain.registrar]
script          = "registrar-common.exs"
default_expires = 3600
min_expires     = 60

# dial-plan: first matching rule wins (file order is significant)
[[domain.call]]
pattern = "XXXX"              # 4 digits → internal user-to-user
script  = "user2user.exs"

[[domain.call]]
pattern = "0[1-9]XXXXXXXX"    # national number → PSTN gateway
script  = "user2pstn.exs"

[[domain.call]]
pattern = "888"               # service number → voicemail
script  = "vm.exs"

[[domain.call]]
default = true                # catch-all (no pattern)
script  = "catchall.exs"
```

### 3.3 Langage de pattern (dial-plan)

Les règles `[[domain.call]]` sont évaluées **dans l'ordre du fichier** ; la
**première** dont le `pattern` matche la user-part de la Request-URI gagne
(sémantique *premier-match*, plus prévisible que le « plus spécifique »
d'Asterisk). `pattern` utilise les **patterns d'extension Asterisk** :

| Symbole  | Signifie                                              |
|----------|-------------------------------------------------------|
| `X`      | un chiffre `[0-9]`                                     |
| `Z`      | un chiffre `[1-9]`                                     |
| `N`      | un chiffre `[2-9]`                                     |
| `[...]`  | un caractère dans l'ensemble/plage, ex. `[13-6]`      |
| `.`      | un ou plusieurs caractères quelconques                |
| `!`      | zéro ou plusieurs caractères quelconques              |
| autre    | se matche littéralement                               |

- Une règle `default = true` (sans `pattern`) est le **catch-all** : au plus une
  par domaine, placée en dernier.
- Aucune règle ne matche et pas de catch-all ⇒ `404 Not Found`.
- La cible matchée est la **user-part** de la Request-URI (le seul mode du
  périmètre basic).
- Échappatoire prévue (hors basic) : `regex = "..."` par règle, en alternative à
  `pattern`.

### 3.4 Certificats TLS / WSS

Les certificats sont définis **par listener** (`cert` / `key`), ce qui permet
d'utiliser le même certificat pour TLS et WSS ou d'en différencier. TOML n'a
pas d'ancres/références, donc les chemins sont simplement répétés.

## 4. Scripts

Les scripts par défaut sont dans **`/usr/share/kelixip`** (donnée statique du
package, conforme FHS). `server.script_dir` permet de spécifier un autre
répertoire (p. ex. `/var/lib/kelixip/scripts` pour des scripts mutables).

Chaque fonction d'un domaine (`domains.toml`) référence son script par un chemin
**relatif à `script_dir`**. Un même script peut être partagé par plusieurs
domaines (ex. `registrar-common.exs`).

> **À faire (migration FSL).** Les scénarios UAS INVITE actuels
> (`scenarios/uas_invite.exs`, conception `docs/design/uas_invite.md`) embarquent leur
> propre configuration de domaine. Avec le dispatch déclaratif de kelixip
> (§2.2), cette config de domaine doit **sortir des scénarios** : le domaine et
> le routage viennent de `domains.toml`, le scénario ne porte plus que la
> logique d'appel. → **revoir / supprimer la config de domaine dans les
> scénarios UAS INVITE.**

## 5. Modules supplémentaires (`.beam`)

On peut créer des modules supplémentaires, compilés (`.beam`) et déposés dans
**`/usr/lib/kelixip/modules`** (`server.module_dir`). Un module est un **service
OTP avec état** (p. ex. un pool de connexions, un socket), pas une simple
bibliothèque de fonctions. Il a **deux facettes** :

- **(A) un service** — un process (souvent un superviseur de pool) que kelixip
  démarre sous son propre superviseur, avec la config du bloc `[module.<nom>]` ;
- **(B) des façades** — les fonctions **importées par le scénario** (`import
  Kelix.Mod.AuthDb, only: [lookup: 2, ...]`), stateless, qui
  retrouvent le service par son nom (le `<nom>` du bloc) et lui délèguent.

A l'instar des modules kamailio, chaque module peut:

- disposer de paramètres qui sont lu dans le fichier de configuration (config.toml)
- enrichir l'API REST en ajoutant des endpoint /modules/<nom>/...
- ajouter des commandes dans kelictl <module> <commande> <argument>


### 5.1 Behaviour `Kelix.Module`

```elixir
defmodule Kelix.Module do
  # Valider le bloc [module.<name>] AVANT de démarrer/reconfigurer quoi que ce
  # soit. Une config invalide est rejetée sans toucher au service en cours.
  @callback validate_config(config :: map) :: :ok | {:error, reason :: term}

  # child_spec placé sous Kelix.ModuleSupervisor. `name` = clé TOML, sert de
  # nom enregistré pour la résolution côté façade.
  @callback child_spec(name :: atom, config :: map) :: Supervisor.child_spec()

  # Métadonnées : version + fonctions exportées aux scénarios.
  @callback describe() :: %{version: String.t(), exports: [{atom, arity :: non_neg_integer}]}

  # Reload à chaud — OPTIONNEL. Présent ⇒ reconfiguration en place (sans couper
  # les ressources). Absent ⇒ kelixip restart proprement le child.
  @callback reload(name :: atom, config :: map) :: :ok | {:error, term}

  # Surface de contrôle (REST + CLI) — OPTIONNEL. Déclaration UNIQUE dont dérivent
  # les DEUX frontaux (parité par construction). Enregistrée dans un registre
  # central `Kelix.Control.Registry` par le ModuleSupervisor au démarrage,
  # déregistrée au stop/reload. Voir §10.
  @callback describe_control() :: [%{
              name: String.t(),                                  # sous-commande
              args: [%{name: String.t(), required: boolean}],
              rest: {:get | :post | :delete, path :: String.t()},
              rw:   :r | :w,
              help: String.t()
            }]
  # Exécute une commande déclarée. NE vérifie PAS l'auth (déjà faite au frontal).
  @callback handle_control(name :: String.t(), args :: map) :: {:ok, term} | {:error, term}

  @optional_callbacks reload: 2, describe_control: 0, handle_control: 2
end
```

### 5.2 Décisions actées

- **Instanciation unique** par module (un bloc `[module.<nom>]` = un service ;
  le multi-instances est une évolution).
- **Façades non bloquantes pour l'instance** : une façade renvoie **`{:error,
  reason}`** si le service est indisponible ; elle ne lève pas — l'instance de
  scénario survit et garde le contrôle de la réponse SIP.
- **Timeout configurable** : `call_timeout_ms` dans `[module.<nom>]` borne un
  appel de façade (une BDD lente ne fige pas l'instance indéfiniment).
- **Reload** (§9, commande `module reload <nom>`) : `validate_config/1` d'abord ;
  puis `reload/2` si le module l'exporte, sinon **restart propre** du child.

Modules prévus :

- **`registrar`** - gestion des contacts et enregistrement.
- **`auth_db`** — accès BDD MariaDB/MySQL, lit la table `subscriber` pour
  l'**authentification** du registrar.
- **`radius_billing`** — facturation par RADIUS.

> Reste à préciser : la **stratégie de versionnage** d'un module lors d'un
> code-reload (`.beam` remplacé) — migration d'état type OTP `code_change`.

## 6. Pool de media servers

Le `[mediaserver.pool.*]` déclare plusieurs MCU. Kelixip gère :

- la **sélection** (round-robin) d'un MCU disponible pour un nouvel appel ;
- le **health-check** et le **failover** si un MCU tombe ;
- l'**activation/désactivation à chaud** d'un MCU via le CLI.

> Extension de la config actuelle (`config :elixip2, :mediaserver`), qui ne gère
> aujourd'hui qu'**un seul** media server.

## 7. Packaging systemd

Kelixip est livré comme une **release OTP** (`mix release`, ERTS embarqué), pas
un escript, ce qui donne un service géré proprement.

- Plateformes : **Alma Linux 9** (rpm) et **Ubuntu** (deb).
- Arborescence FHS :
  - `/etc/kelixip/config.toml` — configuration
  - `/etc/kelixip/tls/` — certificats
  - `/usr/share/kelixip/` — scripts par défaut (package)
  - `/usr/lib/kelixip/` — release OTP + `modules/`
  - `/var/lib/kelixip/` — données mutables (scripts rechargés, futur usrloc)
  - `/var/log/kelixip/` — logs si `target = "stdout"` redirigé (sinon syslog)
- Unit systemd dédiée (utilisateur/groupe `kelixip` non privilégié), arrêt
  gracieux (drain des appels en cours), `epmd` géré par la release.

Lancement en spécifiant un fichier de conf :

```bash
kelixip --config /etc/kelixip/config.toml
kelixip --config /etc/kelixip/config.toml --stdout   # logs sur stdout (debug)
```

## 8. Logs & observabilité

### 8.1 Logs

Utilise **syslog** facility `local0` par défaut (comme Kamailio). La rotation
est déléguée à syslog/journald. L'option `--stdout` (ou `log.target =
"stdout"`) redirige les logs sur la sortie standard pour le debug / conteneur.

### 8.2 Métriques (Prometheus) & health

Instrumentation via **`:telemetry`** (standard Elixir) : des events sont émis aux
points clés et exportés au format Prometheus par `TelemetryMetricsPrometheus`.
Bloc **`[metrics]`** dédié (port séparé de l'API de contrôle, loopback par
défaut) exposant **`/metrics`** et **`/health`** (liveness/readiness pour systemd
/ orchestrateurs).

Métriques (calquées sur les *statistics* de Kamailio), **ventilées par domaine**
(label `domain=…`) :

- **Registrations** : enregistrements actifs (gauge), taux de REGISTER, échecs d'auth ;
- **Appels** : dialogs actifs (gauge), tentatives / répondus / échoués, temps d'établissement ;
- **Transactions** : par méthode, distribution des codes (2xx/4xx/5xx) ;
- **Transport** : messages in/out par proto, connexions WSS/TCP actives ;
- **Média** : sessions actives par MCU du pool, MCU up/down ;
- **Système** : `503` (dépassement `max_calls`), erreurs de parsing, timeouts (timers B/F).

Le `--monitor` (TUI) et les diagrammes de séquence PlantUML par instance restent
des outils de debug complémentaires.

## 9. Couche de contrôle, CLI et API — parité par construction

Les opérations d'administration vivent dans **une seule couche de commandes
interne** (un module `Kelix.Control`). Le CLI et l'API REST n'en sont que deux
**frontaux** :

- le **CLI `kelictl`** (§9.1) — client **local** du nœud via **Erlang
  distribution/RPC** (`node_name` + cookie) ;
- l'**API REST** (§10) — frontal **HTTP** pour le distant et l'outillage.

**Règle de parité :** toute opération est exposée par les **deux** frontaux.
Cette parité est garantie *par construction* — les deux délèguent aux mêmes
fonctions de `Kelix.Control`, aucun frontal n'implémente de logique métier
propre. Ajouter une commande = l'ajouter à la couche, puis la câbler dans les
deux frontaux.

### 9.1 kelictl : le CLI de contrôle

Le script `/usr/sbin/kelictl` est un **client local** du nœud en cours d'exécution (Erlang
RPC, `node_name` + cookie). Il permet de :

- arrêter, démarrer et afficher l'état d'exécution
- afficher le **moniteur** des scénarios en cours d'exécution ;
- afficher le contenu du **registrar** (et du futur serveur de présence) ;
- **désenregistrer** un AOR ou un contact ;
- envoyer un message **`:shutdown`** à une exécution de scénario ;
- **recharger à chaud** un ou plusieurs scripts (voir §9.2) ;
- recharger **`domains.toml`** (voir §9.2) ;
- **activer/désactiver** un media server du pool ;
- **changer le niveau de log**.

### 9.2 Contrat de chargement et de reload

**Contrôle au chargement (obligatoire, au démarrage ET au reload).** kelixip
**refuse** un script — et **loggue une erreur claire** — si :

- ce n'est pas un scénario valide (`function_exported?(mod, :__scenario_type__,
  0)` faux) → *« … n'est pas un scénario kelixip valide »* ;
- il ne gère pas l'**arrêt coopératif de façon explicite**
  (`function_exported?(mod, :__state___shutdown__, 1)` faux, c.-à-d. pas de bloc
  `on_shutdown`) → *« … ne gère pas l'arrêt coopératif (bloc `on_shutdown`
  manquant) : refusé »*.

  Rationale : elixip rend tout scénario shutdown-aware *par défaut*, mais ce
  défaut est **abrupt** (termine en `:aborted` sans BYE ni libération média). En
  production, kelixip **interdit ce défaut** : chaque script servi doit prouver
  qu'il draine proprement. Un registrar peut se contenter d'une ligne
  (`on_shutdown do scenario_aborted("shutdown") end`) ; un `calls` y met le BYE +
  la libération média. Règle **appliquée à tous les scripts** (registrar,
  presence, calls).

**Reload de script (B) — versionné, sans coupure.** Un `.exs` rechargé est
versionné : les instances **en cours gardent leur version** (leur FSM continue
avec le code chargé à leur démarrage) ; **seules les nouvelles instances**
prennent la version rechargée. L'ancienne version est déchargée quand sa
**dernière instance se termine** (comptage de références). Aucune migration
d'état en plein appel.

**Reload de `domains.toml` (E) — atomique, tout-ou-rien.** Le fichier entier est
parsé et validé **hors** de la config vivante (domaines, patterns, et **contrôle
au chargement ci-dessus sur chaque script référencé**). Si un seul élément est
invalide, le reload est **rejeté** : la config courante reste intacte, l'erreur
est remontée au CLI/API. Jamais de config à moitié appliquée.

### 9.3 Surface de commandes `Kelix.Control`

Source unique dont dérivent CLI et REST (parité). `R` = lecture, `W` = écriture.

| Commande | | CLI | REST (indicatif) |
|---|---|---|---|
| `monitor` — scénarios en cours | R | `kelictl monitor` | `GET /scenarios` |
| `registrations` — usrloc (filtrable par domaine) | R | `kelictl registration list [domain]` | `GET /registrations`, `GET /domains/<domaine>/registrations` |
| `presence_state` *(futur)* | R | — | `GET /presence` |
| `status` — uptime, compteurs, pool | R | `kelictl status` | `GET /status` |
| `unregister` — purger un AOR ou un contact | W | `kelictl registration remove <domain> <aor> [contact]` | `DELETE /domains/<domaine>/registrations/<aor>` |
| `shutdown_scenario` — `:shutdown` à une instance | W | `kelictl stop <id>` | `POST /scenarios/<id>/shutdown` |
| `reload_script` — recharger un/des `.exs`, **versionné** (§9.2) | W | `kelictl reload-script <name…>` | `POST /scripts/reload` |
| `reload_script_notify` — reload **+ prévient les instances en cours** | W | `kelictl reload-script --notify <name…>` | `POST /scripts/reload?notify=1` |
| `reload_domains` — recharger `domains.toml` (§9.2) | W | `kelictl domain reload-all` | `POST /domains/reload` |
| `module_reload` — recharger un module (§5.2) | W | `kelictl module reload <name>` | `POST /modules/<name>/reload` |
| `mediaserver_toggle` — activer/désactiver un MCU | W | `kelictl mediaserver enable\|disable <name>` | `POST /mediaservers/<name>` |
| `set_log_level` — niveau de log (global) | W | `kelictl log-level <lvl>` | `PUT /log/level` |
| `graceful_shutdown` — drain coopératif puis arrêt du nœud | W | `kelictl graceful-shutdown` | `POST /graceful-shutdown` |

- **`graceful_shutdown`** : envoie `{:scenario_ctl, :shutdown, …}` à **toutes**
  les instances (drain coopératif — d'où l'exigence `on_shutdown` §9.2), attend
  le drain (avec deadline + kill de secours), puis arrête le nœud proprement.
- **`reload_script_notify`** : comme `reload_script` (les nouvelles instances
  prennent la nouvelle version), **mais notifie en plus** les instances en cours
  via un message de contrôle `{:scenario_ctl, :reloaded, …}`, pour qu'un script
  long (p. ex. `calls`) puisse choisir de se terminer proprement et se recycler
  sur la nouvelle version. Nouveau verbe sur le canal `:scenario_ctl` existant.

> **Futur.** `set_log_level` **par domaine / par fonction** (`registrar`,
> `calls`, `presence`) pour débugger sans noyer les logs. En basic : global.

> **Orthographe CLI (2026-08-02).** La colonne `kelictl` ci-dessus porte les noms
> effectivement livrés : les verbes sont regroupés **sous le nom qu'ils
> manipulent** (`domain reload-all`, `mediaserver enable|disable <name>`,
> `registration list|show|remove`), et trois verbes de lecture s'y ajoutent
> (`mediaserver list` / `mediaserver show` / `registration show`). Les
> registrations étant propres à un domaine (§6.1), le domaine fait partie de
> l'adresse et non d'un filtre : REST les imbrique sous
> `/domains/<domaine>/registrations[/<aor>]` — voir la conception §10.1. Les
> fonctions de
> `Kelix.Control` et les routes REST, elles, sont bien celles de ce tableau.

## 10. API de contrôle (REST)

Kelixip propose une API de contrôle REST sur un port configurable
(`[control_api]`), destinée au **distant** et à l'**outillage**. C'est un
frontal HTTP sur la couche `Kelix.Control` (§9) : **même surface que le CLI**,
par construction (règle de parité). Par défaut : écoute en **loopback** avec
authentification par **token** (exposition réseau = décision explicite ; `mtls`
disponible pour l'exposer).

Un endpoint par commande de `Kelix.Control` (§9.3), **plus** les endpoints
`/modules/<nom>/…` contribués par chaque module. Ces derniers ne sont pas câblés
à la main : chaque module **déclare** sa surface via `describe_control/0` (§5.1),
que le `Kelix.ModuleSupervisor` enregistre dans un registre central
**`Kelix.Control.Registry`** au démarrage (déregistre au stop/reload). **Les deux
frontaux (REST et `kelictl`) dérivent de ce même registre** — parité par
construction : REST y monte ses routes, `kelictl` y génère ses sous-commandes et
son aide. L'exécution passe par `handle_control/2`.

**Auth — séparée de la logique.** L'authentification admin est appliquée **à la
frontière des frontaux**, jamais dans la couche commande : côté REST un
middleware (Plug) valide le token (ou `mtls`) avant d'appeler `Kelix.Control` /
`handle_control` ; côté CLI c'est le cookie Erlang de la distribution qui
authentifie. Ni `Kelix.Control` ni les `handle_control/2` des modules ne
vérifient de token — ils supposent l'appelant déjà authentifié. En **basic** : un
**unique token admin** (toutes commandes, tous domaines, y compris celles des
modules) ; pas de RBAC.

> **Futur (RBAC par domaine)** : un **token admin** global (tous domaines) + par
> domaine **deux tokens** — un **lecture seule** (le domaine + les paramètres
> communs) et un **écriture** (le domaine). Permet de déléguer l'exploitation
> d'un domaine sans donner les clés du serveur.

## 11. Sécurité

- Config **déclarative** : aucun code exécuté au chargement, pas d'injection
  d'atome arbitraire.
- **Modules `.beam`** : charger du bytecode = exécuter du code ⇒ `module_dir`
  doit être en propriété `root`, non modifiable par le service.
- **API de contrôle** : loopback + token par défaut ; `mtls` pour l'exposition.
- Service exécuté sous un **utilisateur non privilégié**.
- Certificats TLS/WSS : voir §3.4.

### 11.1 Authentification digest & nonce stateless

**Auth du registrar.** `SIP.Auth` fournit déjà les primitives digest. Câblage :

- **realm = le nom de domaine** (un realm par domaine qui correspond au champ name de chaque domaine) ;
- Si la R-URI utilise un alias pour le domaine, le challenge renvoie le nom nominale (champ name) du domaine dans le challenge.
- **secret via `auth_db`** au format **HA1** (`MD5(user:realm:password)`,
  pas de mot de passe en clair) ; `password_hash = "md5" | "sha256"` configurable
  dans `[module.auth_db]` (défaut `md5`), champ utilisé pour stocker le hash configurable ; 
  table et BDD utilisée configurable.

- **séparation décision / composition** : `auth_db` **décide** (verdict), le
  **script compose et envoie** la réponse SIP via les helpers
  `SIP.Session.Registrar.*` (challenge/accept/reject). `auth_db` ne construit
  aucun message SIP. Concrètement `auth_db` expose :

  ```elixir
  do_registration_auth(req, domain) :: :ok | {:requireauth, stale :: bool} | {:reject, code, reason}
  ```

  - `{:requireauth, stale}` → le script appelle `challenge_registration(req,
    dialog_pid, realm: domain, stale: stale)` (401 ; `stale` pour le re-challenge
    transparent d'un nonce périmé) ;
  - `:ok` → le script enchaîne sur `registrar.save/3` (voir §12.2) ;
  - `{:reject, code, reason}` → `reject_registration(...)`.

  `do_registration_auth` fait en interne : validation du nonce stateless
  (`SIP.Auth.Nonce`), lookup HA1, vérification de la réponse digest (via `SIP.Auth`
  étendu §14). C'est la version BDD de l'actuel `check_registration_auth`.

**Nonce unifié, stateless (remplace le stateful).** Le nonce stateful actuel
(`SIP.DialogImpl.Nonce`, map par dialogue) et le `generate_nonce` faible
(sha256 sans secret, prévisible) sont **remplacés** par un nonce stateless
infalsifiable, utilisé partout (registrar + challenges de dialogue) :

```
nonce = base64( ts ‖ rand ‖ HMAC-SHA256(server_secret, ts ‖ rand ‖ realm) )
```

- validation = recalcul du HMAC (aucun stockage) + contrôle de fraîcheur
  `now − ts ≤ max_age` (30–60 s) ; au-delà ⇒ **`401 stale=true`** (le client
  rejoue avec un nonce frais, de façon transparente) ;
- `realm` lié dans le HMAC ⇒ un nonce d'un domaine est inutilisable sur un autre ;
- **anti-rejeu intra-fenêtre** : `qop=auth` + nonce-count (`nc`) avec un **cache
  éphémère par nœud** `nonce → nc max` (borné, TTL = `max_age`) ; `nc ≤ dernier
  vu` ⇒ rejet. Soft-state minuscule, perte au restart inoffensive (⇒ `stale`).

**Compatibilité (dégradation gracieuse).** Le format interne du nonce est
**opaque** au client (il le recopie tel quel) ⇒ le passage stateless est
transparent, aucun risque de compat. Le seul levier est `qop` :

- le serveur **offre `qop=auth`** ; les clients modernes (RFC 2617, référencé par
  RFC 3261 → parc quasi universel) l'utilisent → anti-rejeu `nc` complet ;
- le serveur **accepte aussi la réponse sans `qop`** (validation RFC 2069) pour
  les très vieux clients : ils fonctionnent, mais retombent sur l'anti-rejeu
  **par fenêtre seule** (`max_age` + `stale`, pas de `nc`) ;
- **algorithme MD5** (ne pas exiger SHA-256/RFC 8760, mal supporté) ;
- nonce en **base64url** (éviter `+`/`/`) et **`max_age` ≥ 60 s** pour limiter les
  re-challenges `stale` et les parseurs anciens pointilleux.

Implications :

- **Étendre `SIP.Auth` pour supporter `qop=auth`** (`ha1:nonce:nc:cnonce:qop:ha2`)
  **en plus** de la forme RFC 2069 actuelle (conservée pour le fallback).
- **`server_secret`** : **éphémère régénéré au boot** en basic (un restart
  invalide les nonces en vol ⇒ `stale`) ; **partagé entre nœuds** pour la HA
  (futur), n'importe quel nœud validant alors n'importe quel nonce.

## 12. usrloc, NAT & haute disponibilité

### 12.1 NAT / flow — *basic* (critique WebRTC)

Sans ça, un client WSS/UDP derrière NAT est **injoignable**. Le registrar :

- stocke la **source réelle** (`received` IP:port), **pas** le Contact annoncé
  (un UA/browser NATé y met une adresse privée inutilisable) ;
- stocke le **handle de flow** (la connexion transport) pour les transports
  **connectés** (WSS/TCP/TLS) : on ne peut pas ouvrir une connexion *vers* un
  browser, donc l'inbound **réutilise la connexion existante** (flow, RFC 5626) ;
- route tout inbound (INVITE vers l'AOR) **sur le flow / `received` stocké**.

**`Path` (RFC 3327)** : **honoré s'il est présent** (stocké comme route de
retour), mais **non généré** en basic — la génération/edge-proxy `Path` relève
du multi-hop (*futur*). Pour un kelixip seul, edge des clients WebRTC, le
stockage du flow suffit à router l'inbound.

### 12.2 registrar en mémoire & haute disponibilité — *futur*

C'est un module supplémentaire `registrar.beam`, `Kelix.Mod.Registrar`. 

Son rôle est de stocker les AOR (Address of Record) et les contacts des UA enregistrées. 
L'équilent kamailo est le module `registrar` + `usrloc`. Comme kamailio, il stocke: les AOR, 
c.-à-d. le **userpart du champ `To`** (l'AOR enregistré, conformément à la RFC 3261) et la
liste des contacts.

Pour chaque contact, il stocke également:

- le domaine
- la SIP URI du contact telle que présentée dans le message REGISTER
- Le transport, l'adresse IP et le port réel d'où vient le message REGISTER (note de conception : extraire cet info du dialogue ?)
- le PID du dialogue associé au register
- une info supplémentaire arbitraire fournie par le scénario

fournis par la fonction save() décrite plus bas.


Note de conception à déplacer dans kelixip_basic_design.md: 

pouvoir séparer fortement les domaines. Je suggère : 

  **Décidé (2026-07-26) : une table ETS par domaine** (séparation forte), + un
  index `%{ "domain" => tid }`. La table d'un domaine est créée/supprimée avec le
  domaine ; purge par binding via un monitor du pid de dialogue. Détail dans
  `kelixip_basic_design.md` §6.1.

  aor_map:

  %{ "aor" => [ contact_info1, ... ] }

  La gestion de l'expiration doit être traitée dans la couche dialogue. Tout cela doit s'appuyer sur la couche Dialogue et  SIP.Session.Registrar

On preprend la spec

Comme tout module, il est configuré par un bloc **`[module.registrar]`** — mais,
à la différence des autres modules (dont le bloc est dans `config.toml`), le
sien est placé dans **`domains.toml`** (fichier des domaines), car sa
configuration est liée aux domaines et **rechargeable à chaud**. Le
`Kelix.ModuleSupervisor` lit donc ce module depuis `domains.toml` et le
reconfigure lors d'un `reload_domains`.

Paramètre du bloc `[module.registrar]` :
- `max_contacts_per_aor` : le nombre max de contacts par AOR.

(Les bornes d'expiration `default_expires` / `min_expires` restent **par
domaine** dans `[domain.registrar]`, §3.2 — c'est de la config d'activation de la
fonction, distincte des paramètres du module.)

Il exporte quatre fonctions :

``̀ Elixir
save(req, domain, info \\ nil)
``̀ 
ou 
- req est un message REGISTER
- domaine
- info est une info arbitraire fournie par le scénario.

La fonction extrait le ou les contacts présent dans le message REGISTER, vérifie la validité
du expire et effectue l'enregistrement ou le désenregistrement. Elle **ne compose PAS** la
réponse SIP : elle renvoie `{ :ok, granted }` où `granted` porte les contacts et les
expires **réellement accordés** (après clamp). Le script s'en sert pour appeler
`SIP.Session.Registrar.accept_registration(req, dialog_pid, granted)`, qui échoe exactement
ce qui a été stocké (le 200 OK est ainsi cohérent avec le store *par construction*, sans
re-calcul des bornes). En cas d'erreur, elle renvoie `{ :error, { code, reason } }` et le
script appelle `reject_registration(...)`.

> Note de conception : les bornes d'expiration sont ainsi appliquées à **un seul endroit**
> (`save`), jamais dupliquées dans `accept_registration` — le helper ne fait qu'échoer
> `granted`. (Refactor du helper actuel qui re-fait `check_register`/`adjust`.)

Elle lit les paramètres dans la section `[domain.registrar]` (dans `domains.toml`, cf. §3.2)
pour valider les durées d'expiration. Elle s'abonne aux évènements du dialogue pour capter le
désenregistrement ou la coupure du transport. En particulier dans le cas des transport connecté
s'il y a rupture de connexion l'enregistrement est invalidé.

``̀ Elixir
lookup(reqn)
``̀ 

Cette fonction prend en entrée d'importe quel message SIP a relayer vers un UA enregistré. Elle
extrait le userpart de la R-URI de la requête et la prend comme AOR à joindre. Utilise le domain de la R-URI (le rabat sur le nom principal en cas d'utilisation d'un alias). Puis elle retourne
un liste de requêtes modifiées prêtes être envoyées vers l'UA enregistrée. Pour ce faire, pour chaque contact enregistré pour l'AOR, la fonction:

- crée une copîe de la requête initiale,
- remplace la R-URI de la requête initiale par exactement le contact
- enrichi les champs destip, destport et destproto de la R-URI

L'ensemble est retourné comme: 

``̀ Elixir
{ :ok, [ newreq1, newreq2 ... ] }
``̀ 

Aucun contact pour l'AOR :  retour `:notfound`

En cas d'erreur elle renvoie : `{ :error, reason }`

Note de conception, passer la R-URI des requêtes retournées par lookup() a TransportSelector.select_transport() doit permette de retrouver EXACTEMENT le transport utilisable pour joindre l'UA. C'est en particulier vrai pour les transports connectés comme TCP, TLS et WSS dont les client DOIVENT maintenir une connexion permanente avec le registrar.

**Décidé (2026-07-26) — `select_transport/1` doit honorer une R-URI déjà résolue**
(aujourd'hui il l'ignore et re-résout, cf. `kelixip_basic_design.md` §6.4).
Court-circuit à deux niveaux : (1) si `tp_pid` est vivant → l'utiliser tel quel ;
(2) sinon si `destip` et `destport` sont présents → utiliser `destip`/`destport`/
`destproto` directement (`destproto = nil` ⇒ UDP par défaut), sans résolution DNS ;
(3) sinon résolution complète depuis la R-URI. `lookup()` renseigne `tp_pid` **et**
`destip`/`destport`/`destproto`.

La dernière fonction permet de souscrire/désouscrir aux évènements relatifs à un AOR@domain exprimé comme un `%SIP.Uri{}`

``̀ Elixir
subscribe_register_event(uri, pid)
unsubscribe_register_event(uri, pid)
``̀ 

Ce peut être pour un AOR non encore enregistré. Dans ce cas, le processus qui souscrit
reçoit :

``̀ Elixir
{ :registrar, :registered, aor@domaine }
{ :registrar, :unregistered, aor@domaine }
{ :registrar, :expired, aor@domaine }
{ :registrar, :disconnected, aor@domaine }
``̀ 



**Décision (basic) : l'usrloc reste 100 % en mémoire** (`Registry`), sans
persistance ni abstraction de stockage anticipée. Rationale :

- pour les transports **connectés** (WSS/TCP/TLS — l'essentiel de la cible
  WebRTC), persister l'usrloc à travers un redémarrage est de peu de valeur : la
  connexion est fermée au restart, le Contact pointerait vers un *flow* mort, le
  client doit se reconnecter et se ré-enregistrer de toute façon ;
- la persistance n'a de vraie valeur que pour l'**UDP** (sans connexion) et pour
  le **partage inter-nœuds** — qui relève de la HA, explicitement *futur*.


Note : le registrar (**location**) est distinct de l'auth (**subscriber**, gérée par
le module `auth_db`). Une future persistance usrloc serait une table
`location` séparée (comme chez Kamailio).

**Cluster 2-3 nœuds.** Cluster de **2 ou 3 instances** kelixip redondantes.

> Interviendra plus tard. Le registrar/usrloc et les dialogs étant **en mémoire**
> (choix ci-dessus), la clusterisation supposera alors de **factoriser l'usrloc
> derrière un store** (`SIP.Registrar.Store`, in-memory par défaut) et de fournir
> un backend répliqué (Mnesia / CRDT) ou *shared-nothing + persistance BDD*.
> Assumé comme un chantier au moment d'attaquer la HA, pas avant.

**Support natif des push notifications Google, iOS et Microsoft**

Une version ultérieur permettra d'associer à AOR avec un "contact" permettant de notifier
les applications mobiles iOS, Google et Microsoft par notification push. C'est un chantier
a faire pour une version utlérieure. Indépendante de la HA mais PAS en version basique.

### 12.3 module `auth_db` (`Kelix.Mod.AuthDb`)

Module qui se connecte à une base de données **MySQL / MariaDB** et fournit
l'**authentification** du registrar. Il **décide** mais ne compose **jamais** de
réponse SIP (§11.1).

Paramètres (`[module.auth_db]`) : `driver`, `host`, `database`, `username`,
`password`, `table`, la colonne stockant le hash, et `password_hash =
"md5" | "sha256"` (défaut `md5`) — au format HA1 `H(user:realm:password)`.

Il exporte :

```elixir
# verdict d'authentification (aucune composition SIP)
do_registration_auth(req, domain) :: :ok | {:requireauth, stale :: bool} | {:reject, code, reason}

# lookup du secret HA1 (façade bas niveau, réutilisable)
lookup_ha1(user, realm) :: {:ok, ha1 :: binary} | :notfound | {:error, reason}
```

`do_registration_auth` : valide le nonce stateless (`SIP.Auth.Nonce`), fait le
lookup HA1, vérifie la réponse digest (via `SIP.Auth` étendu `qop=auth`, §14).
`{:requireauth, stale}` quand il n'y a pas d'`Authorization` valide (ou nonce
périmé ⇒ `stale=true`). C'est la version BDD de l'actuel `check_registration_auth`.

## 12.4 Scénario `registrar.exs`

Orchestrateur **mince** : il ne contient aucune logique d'auth ni de stockage
(déléguées aux modules) — il ne fait que router les verdicts vers les helpers
`SIP.Session.Registrar.*` qui composent et envoient la réponse SIP. C'est aussi
lui qui porte le bloc `on_shutdown` obligatoire (§9.2).

```elixir
# état sur réception d'un REGISTER (domaine injecté par le dispatch, cf. §2)
case do_registration_auth(req, domain) do
  {:requireauth, stale} -> challenge_registration(req, dialog_pid, realm: domain, stale: stale)
  {:reject, code, reason} -> reject_registration(req, dialog_pid, code, reason)
  :ok ->
    case save(req, domain, info) do
      {:ok, granted}          -> accept_registration(req, dialog_pid, granted)
      {:error, {code, reason}} -> reject_registration(req, dialog_pid, code, reason)
    end
end
```

Le désenregistrement (Contact `expires=0`) et l'invalidation sur coupure de
transport connecté sont gérés par `save/3` + l'abonnement du module `registrar`
aux évènements du dialogue (§12.2) ; le script en est notifié via
`subscribe_register_event/2` s'il en a besoin.

## 13. Intégration de kelixip dans un produit

Kelixip peut servir de base à un produit plus complexe. Exemple : **borderline**
sera bâti sur base elixip/kelixip. Les points d'extension sont les **modules**
(§5) et les **scripts** FSL (§4).

## 14. Statut & roadmap

| Élément                              | Statut     |
|--------------------------------------|------------|
| Fonction `registrar` (UDP/TCP/TLS/WSS) | basic      |
| Auth digest (realm=domaine, HA1 via `auth_db`) | basic |
| Nonce stateless unifié (HMAC + `qop`/`nc` + `stale`) — remplace le nonce stateful | basic |
| Extension `SIP.Auth` : support `qop=auth` (`nc`/`cnonce`) + fallback RFC 2069 | basic — *fait (P4)* |
| NAT / flow (received + réutilisation de connexion), `Path` honoré | basic |
| Génération `Path` / edge-proxy multi-hop | **futur** |
| Config déclarative TOML (`config.toml` + `domains.toml`) | basic |
| Multi-domaine + dial-plan déclaratif (patterns Asterisk) | basic |
| Migration : sortir la config de domaine des scénarios UAS INVITE | **à faire** |
| Packaging systemd (rpm/deb)          | basic      |
| CLI `kelictl` + API de contrôle REST | basic      |
| Observabilité : `:telemetry` + `/metrics` Prometheus + `/health` (labels par domaine) | basic |
| Modules `.beam` (registrar, auth_db, radius_billing) | basic |
| Pool de media servers                | basic      |
| Fonction `calls` (B2BUA)             | **futur** — conception `docs/design/b2bua_module.md` |
| Fonction `presence`                  | **futur** — squelette `SIP.Session.Presence` |
| Persistance usrloc / registrar en BDD | **futur** |
| Haute disponibilité (cluster 2-3)    | **futur**  |

> **La fonction `calls` (B2BUA) est la suite logique du basic**, mais relève d'une
> **version future** : c'est un chantier de cadrage à part entière, pas une simple
> extension. Contrairement au registrar (une transaction, une réponse), le B2BUA
> gère **deux tronçons de dialogue** (entrant + sortant) que le scénario doit
> relayer lui-même (pas de bridging automatique façon `t_relay()`/`Dial()`), avec
> tout ce que cela implique : macro de création du second dialogue, discrimination
> des legs, relais requêtes/réponses, couplage média inter-legs, gestion des cas
> d'erreur/annulation sur chaque leg. La conception démarre dans
> `docs/design/b2bua_module.md` (aujourd'hui à l'état d'ébauche) et devra être menée avant
> toute implémentation.
