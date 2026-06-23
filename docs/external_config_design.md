# Conception — Paramétrage des scénarios par fichier JSON externe

Statut : **conception uniquement, non implémentée.**
Public : développeur en charge de l'implémentation.

## 1. Objectif

Permettre de paramétrer un scénario depuis un fichier JSON externe, contenant :

1. un **entête** : `domain`, `proxyuri`, `proxyusesrv`, `optionkeepaliveperiod` ;
2. **N enregistrements** (`accounts`) : `{ username, password, domain }`.

Tout en **conservant** le paramétrage programmatique actuel (bloc `config` du
scénario). Sans fichier, le comportement reste strictement celui d'aujourd'hui.

## 2. État actuel (point de départ)

Le flux de paramétrage est :

```
config username: …, domain: …, passwd: …, proxy: …   (macro SIP.Scenario.config/1)
  └─> @scenario_config (keyword list)
        └─> SIP.Scenario.Runner.build_context/1
              └─> %SIP.Context{}
```

Deux familles de paramètres cohabitent — c'est la clé du design :

| Famille | Exemples | Destination actuelle |
|---|---|---|
| **Par session** (par compte) | `username`, `authusername`, `passwd`, `domain` | champs du `%SIP.Context{}` via `config` |
| **Globaux** (partagés) | `proxyuri`, `proxyusesrv`, `optionkeepaliveperiod` | `Application.put_env(:elixip2, …)` codé en dur dans `initial_state` |

Points d'ancrage existants réutilisés :

- `Runner.build_context/1` (`lib/dsl/SIPScenarioRunner.ex`) — construit le contexte.
- `Runner.run_instance/2` + `apply_run_opts/2` — acceptent déjà des options par
  instance (`:appdata`, `:parent_pid`, `:self_name`, `:slot_id`).
- `Elixipp.CLI` — `OptionParser`, résolution du module, boucle parallèle/slots.
- `mix scenario` (`lib/mix/tasks/scenario.ex`).
- `jason ~> 1.4` est déjà une dépendance.

## 3. Décisions (déjà actées)

| Décision | Choix |
|---|---|
| Précédence quand `config` block ET JSON définissent la même clé | **JSON > programmatique** (le `config` block est un jeu de défauts) |
| `--limit` par défaut quand `--config` est fourni | **`limit = 1` conservé** (pas de slot-par-compte automatique) |
| Sélection du compte par instance | par **compteur monotone d'instances** : `accounts[rem(total_started, N)]` |
| `put_env` dans `initial_state` | **retiré** ; clés globales routées via `config`/JSON. Migration des scénarios incluse |
| Clé inconnue dans le JSON | **erreur bloquante** (strict partout) |

### 3.1 Conséquence de `limit = 1` à bien noter

Avec `--config` et `limit = 1` (défaut), **un seul compte est traité par
exécution**. Pour enregistrer les N comptes, il faut recycler les slots :

```
elixipp --config accounts.json --max-run 0  scenarios/uac_register.exs   # illimité, cycle sur tous les comptes
elixipp --config accounts.json --limit  N   scenarios/uac_register.exs   # N comptes en parallèle
```

Le compte est choisi sur le **compteur monotone `total_started`** (et non sur
`slot_id`, qui est recyclé par `maybe_spawn_next`). Ça couvre les deux cas :

- séquentiel (`limit = 1`, `--max-run k`) : comptes parcourus l'un après l'autre ;
- concurrent (`--limit N`, `--max-run N`) : les N slots reçoivent des comptes distincts.

## 4. Format JSON

```json
{
  "domain": "visioassistance.net",
  "proxyuri": "sip:sip.djanah.com:5060",
  "proxyusesrv": false,
  "optionkeepaliveperiod": 5,
  "accounts": [
    { "username": "33970262546", "password": "TestKam1" },
    { "username": "33970262547", "password": "TestKam2", "domain": "autre.net" }
  ]
}
```

Règles :

- Entête = clés de premier niveau. `accounts` = tableau (au moins 1 entrée).
- Compte : `username` et `password` **requis** ; `domain` optionnel (hérite de
  l'entête) ; `authusername` optionnel (⇐ `username`) ; `displayname` optionnel.
- `domain` doit être résolu pour chaque compte (entête OU compte), sinon erreur.
- Toute clé hors whitelist (entête ou compte) → **erreur bloquante**.

## 5. Modèle de fusion (3 couches, précédence croissante)

```
1. config block du scénario   (défauts programmatiques)
2. entête JSON                 (si --config fourni)
3. compte JSON courant         (par instance)
```

Dans le `Runner`, ordre de fusion sur des keyword lists :

```
effective =
  module.__scenario_config__()
  |> Keyword.merge(json_header_kw)    # domain, proxyuri, proxyusesrv, optionkeepaliveperiod
  |> Keyword.merge(json_account_kw)   # username, password, authusername, displayname, domain
```

Sans `--config`, on passe seulement `module.__scenario_config__()` → comportement
actuel inchangé, paramétrage programmatique 100 % préservé.

## 6. Routage des clés : global vs contexte

Le `Runner` route chaque clé (qu'elle vienne du `config` block OU du JSON) selon
une table unique :

```
GLOBAL  (Application.put_env(:elixip2, …)) : :proxyuri, :proxyusesrv, :optionkeepaliveperiod
CONTEXTE (champs %SIP.Context{})           : :username, :authusername, :displayname,
                                             :domain, :algorithm, :debug, :passwd
APPDATA  (reste)                           : toute autre clé connue routée en appdata
```

- `:proxyuri` arrive en string `"sip:host:port"` → parsée en `%SIP.Uri{}` (le
  code consommateur attend déjà cette struct) au moment de poser l'app env.
- Les clés globales sont posées **une seule fois** au bootstrap (idempotent),
  pas par instance — elles sont partagées par tous les slots.

### 6.1 Migration des scénarios (retrait du `put_env`)

Aujourd'hui `scenarios/uac_register.exs` (initial_state) fait :

```elixir
Application.put_env(:elixip2, :proxyuri, %SIP.Uri{domain: @proxy, scheme: "sip:", port: 5060})
Application.put_env(:elixip2, :proxyusesrv, false)
Application.put_env(:elixip2, :optionkeepaliveperiod, @options_keepalive)
```

Après migration, ces valeurs vont dans le bloc `config` (ou le JSON) :

```elixir
config username: @username,
       authusername: @authusername,
       displayname: @displayname,
       domain: @domain,
       passwd: @passwd,
       proxyuri: "sip:#{@proxy}:5060",
       proxyusesrv: false,
       optionkeepaliveperiod: @options_keepalive
```

Le `Runner` route automatiquement `proxyuri`/`proxyusesrv`/`optionkeepaliveperiod`
vers l'app env. `initial_state` n'a plus de `put_env`.

Rétro-compatibilité : un ancien scénario qui fait encore `put_env` continue de
marcher (il écrit dans l'app env après le routage du runner — même cible). Le
seul piège documenté : si un scénario fait `put_env` ET qu'un JSON fournit la
même clé, le `put_env` (exécuté plus tard, dans `initial_state`) l'emporte. À
éviter — d'où la migration.

## 7. Composants à créer / modifier

### 7.1 Nouveau module `SIP.Scenario.ExternalConfig` (`lib/dsl/`)

```
@spec load!(Path.t()) :: %SIP.Scenario.ExternalConfig{
        header: keyword(),      # clés entête normalisées (atomes whitelistés)
        accounts: [keyword()]   # un keyword list par compte
      }
```

- Lit le fichier, parse via `Jason.decode!/1`.
- **Whitelist** des clés : conversion string→atom seulement pour des clés
  connues (jamais `String.to_atom/1` sur entrée libre → pas d'épuisement
  d'atomes). Clé inconnue → `raise` avec message clair.
- Validation de types : `proxyusesrv` booléen, `optionkeepaliveperiod` entier,
  `proxyuri` parsable par `SIP.Uri`, `accounts` liste non vide.
- Erreurs explicites : fichier absent, JSON invalide, compte sans
  `username`/`password`, `domain` non résolu.
- Fonction publique → réutilisable programmatiquement (cf. §9).

### 7.2 `SIP.Scenario.Runner`

- `build_context/1` : ajouter le routage des **clés globales** vers l'app env
  (au lieu de les ranger en appdata) + parse `proxyuri`.
- `run_instance/2` : nouvel opt `:config_overrides` (keyword list déjà fusionnée
  entête + compte), mergée sur `module.__scenario_config__()` avant
  `build_context`.
- Nouvelle fonction `apply_global_config/1` (idempotente), appelée une fois au
  bootstrap, qui pose les clés globales de l'entête dans l'app env.

### 7.3 `Elixipp.CLI` + `mix scenario`

- Nouveau flag `--config PATH` / `-c` (`:string`).
- Au démarrage : `ExternalConfig.load!/1`, puis `apply_global_config/1` **une
  fois**.
- `spawn_slot/2` : calculer le compte depuis `total_started`
  (`accounts[rem(total_started, N)]`), le fusionner avec l'entête, et passer
  `run_instance(module, config_overrides: account_kw, slot_id: …)`.
- `--limit`/`--max-run` : comportement par défaut **inchangé** (limit 1,
  max_run 1). L'utilisateur pilote le balayage des comptes via `--max-run` /
  `--limit` explicites.

## 8. Validation & messages d'erreur

Toutes bloquantes (échec tôt, avant le bootstrap stack) :

- fichier introuvable / illisible ;
- JSON invalide (remonter l'erreur Jason) ;
- clé inconnue (entête ou compte) → lister les clés attendues ;
- `accounts` absent / vide / non-liste ;
- compte sans `username` ou `password` ;
- `domain` non résolu pour un compte ;
- `proxyusesrv` non booléen, `optionkeepaliveperiod` non entier, `proxyuri`
  non parsable.

## 9. Voie programmatique préservée

1. **Sans `--config`** : le bloc `config` fonctionne comme aujourd'hui.
2. **Hybride** : `ExternalConfig.load!/1` étant public, un scénario ou un script
   peut charger un fichier lui-même et fusionner par code, ou appeler
   `Runner.run_instance(module, config_overrides: kw)` directement.

## 10. Points hors périmètre (pour plus tard)

- Rechargement à chaud du fichier de config.
- Schéma JSON par scénario (clés spécifiques validées par le scénario).
- Secrets chiffrés / variables d'environnement dans le fichier.
- Pondération / ordre de tirage des comptes autre que le round-robin
  `rem(total_started, N)`.
```
