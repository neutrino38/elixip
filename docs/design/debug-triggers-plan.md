# debug-triggers-plan.md — journals started by a rule

**Status: plan, 2026-11-06. Nothing implemented. Decisions 1 to 6 taken
2026-11-06 (§3).**

## 1. Scope

Today a journal is started by hand, on a scenario that is already running
(`kelictl debug <id> on`). The call an operator wants to see is usually the next
one — the one a customer is about to place — and it has no id yet.

A **debug trigger** is a rule attached to one script served by one domain:

> Journal the next **N** runs of script **S** on domain **D**, for the next
> **duration** (minutes, hours, days or months), optionally only for runs whose
> starting request matches **one filter**:
>
> - `caller=<user>` — the user part of `From` **or** of `P-Asserted-Identity`;
> - `callee=<user>` — the user part of `To` **or** of the Request-URI;
> - `source=<ip|cidr>` — the address the request came from.

- **One rule per `{domain, script}`.** Setting a rule on a pair that has one
  replaces it.
- A rule ends when its last run is claimed **or** when its window closes,
  whichever comes first. It is then removed.
- Every frontal reads, sets and removes rules: `kelictl`, the REST control API,
  kelescope. Each shows the time left and the runs left.
- A triggered journal is an ordinary journal: it lands in `Kelix.Traces`, is read
  with `kelictl debug show <id>` and kelescope's popup, and expires like the others.
  Its summary says it was started by a rule.

Out of scope:

- several rules per script, or a rule spanning several scripts or domains;
- filters combined with AND, or filters on other headers (see decision 2);
- journaling the child machines of a triggered run (`spawn_fsm`) separately: they
  already record into their parent's journal;
- replication across a cluster: rules are per node, like `domains.toml`.

## 2. What exists

- **The journal can start at the first state.** `FSL.Runner.run_instance/2`
  starts it before `initial_state` when the context's `debug` field is true
  (`maybe_start_sequence_journal/3`), and `SIP.FSL.Host.put_config/3` accepts
  `debug` as a config key. `Kelix.InstancePool.spawn_instance/9` already passes
  `config_overrides:` to `SIP.Scenario.Runner.spawn_uas_instance/2`: adding
  `debug: true` there is all the activation needs.
- **The request that started the run is caught up.** `SIP.FSL.Host.journal_started/1`
  records the inbound request and adopts the dialog, so a journal started at spawn
  shows the INVITE (or REGISTER, MESSAGE…) that caused it.
- **One place spawns.** Every run — routed request, woken conversation,
  `run_script` — goes through `InstancePool.reserve_and_spawn/6` →
  `spawn_instance/9`, in the pool process, with `domain`, `script` and the request
  (`nil` for `run_script`) in hand. That is where a rule is matched and claimed.
- **The message layer reads the identities.** `SIP.Msg.Ops` has
  `from_username/1`, `to_username/1`, `target_aor/1` (R-URI user part), a private
  `header_userpart/2` used for `P-Asserted-Identity` (two values, `tel:` included),
  and `source_flow/1` (`{transport, ip, port}`).
- **CIDR matching exists.** `SIP.NetUtils.parse_prefix/1` and `in_prefix?/2`,
  already used by `[[listen]] networks`.
- **The journal store.** `Kelix.Traces` keeps journals in memory, bounded by
  `[debug] trace_retention`, `max_traces`, `max_trace_bytes`, and pushes
  `{:kelix_traces, …}` to subscribers (kelescope).
- **The domain write path** (`dynamic-domains-plan.md`): `Kelix.Domains`
  snapshot, `delete_domain/2`, `reload-all`. A rule must follow a domain it names.

## 3. Decisions

### Decision 1 — rules live in a state file

A rule is not configuration: its counter moves at every claim. It does not belong
in `domains.toml`, whose every write is an encode/parse/check cycle and a version
bump that kelescope and `--version N` users see. Nor in memory only: a rule of
"one month" would silently vanish at the first restart for an upgrade.

Rules are kept in **`/var/lib/kelixip/debug_triggers.json`**, `kelixip:kelixip
0640`, rewritten atomically (write + rename) on every change: set, remove, claim,
expiry. Writes are bounded by N per rule. The file is read at boot; rules already
expired are dropped then, with an INFO line. The packages create the directory
entry as they do for `domains.toml` and never overwrite the file.

### Decision 2 — at most one filter per rule

"Caller **or** callee **or** source": a rule carries zero or one filter.
The filter is stored as a map from the start (`%{caller: …}`), with a single key
enforced by validation, so combining filters (AND) later does not change the
storage shape.

### Decision 3 — what "a month" is

A **duration**, not a calendar: `m` = 60 s, `h` = 3600 s, `d` = 86 400 s,
`mo` = 30 d. The rule stores the absolute `expires_at` (UTC) computed at `set`;
time left is `expires_at − now`. Upper bound: 12 months.

### Decision 4 — the bound on N

`N ≥ 1`, and at most `[debug] max_traces`: more triggered journals than the store
keeps would evict the first ones before anybody reads them. `set` refuses a larger
N with the reason. (Triggered journals evict operator journals like any other,
oldest first — the summary's `origin` lets an operator see what took the room.)

### Decision 5 — a rule names a script its domain serves

`set` refuses a domain that does not exist, and a script no function of the domain
names (registrar, call/chat/options rules, presence, keepalive). When a domain
change makes a rule orphan — `domain delete`, `reload-all`, a rule edit that drops
the last reference to the script — the rule is removed, with an INFO line naming
it. A script **reload** (new version) keeps the rule: the key is the script name.

### Decision 6 — what counts as a run, and when it is claimed

A run is claimed when the pool has secured a slot **and** checked the script out
(the `{:ok, module, version}` branch of `spawn_instance/9`), right before the
spawn — never on a request answered 404/503/500 by the pool. A woken conversation
is a run. A `run_script` launch has no request: only a rule **without filter**
matches it. A non-matching request consumes nothing.

### Fixed points

- Message interpretation stays in `SIP.Msg.Ops` (CLAUDE.md, *Message Layer*): the
  trigger store asks "who is the caller", it does not read headers.
- Matching is case-insensitive on user parts; no normalisation beyond that
  (`+33…` and `0033…` are two users). Documented, not guessed.
- The hot path pays one ETS lookup when no rule exists for the pair.

## 4. The design

### 4.1 Framework — `SIP.Msg.Ops`

```elixir
@spec caller_users(map) :: [String.t()]   # From user part ++ every PAI user part
@spec callee_users(map) :: [String.t()]   # To user part ++ Request-URI user part
@spec source_ip(map)    :: :inet.ip_address() | nil   # from source_flow/1
```

Deduplicated, `nil`s dropped. `asserted_username/1` is not reused: it prefers the
digest username, which is not what "caller" means here.

### 4.2 `Kelix.DebugTriggers` — the store

A GenServer in `Kelix.Application`, after `Kelix.Domains`, before
`Kelix.InstancePool`, owning a protected ETS table (`read_concurrency: true`).

```elixir
%{
  domain: "example.com", script: "call.exs",
  remaining: 3, total: 5,
  filter: nil | %{caller: "1001"} | %{callee: "1002"} | %{source: "10.1.0.0/16"},
  created_at: ~U[…], expires_at: ~U[…], created_by: "admin"
}
```

- `set(domain, script, opts, admin)` — validate (decisions 2–5), replace, persist,
  push. Returns the rule.
- `remove(domain, script, admin)`, `list()`, `get(domain, script)`.
- `claim(domain, script, req_or_nil) :: :journal | :no` — called by the pool.
  `:ets.lookup` first, in the caller's process; only when a live rule matches, a
  `GenServer.call` decrements, persists and, at 0, removes. The call is what makes
  "N runs" exact under concurrency.
- One timer per rule on `expires_at` (`Process.send_after`, re-armed by `set`);
  expiry removes and pushes.
- `prune(domains_snapshot)` — decision 5, called by `Kelix.Domains` after every
  accepted snapshot.
- `subscribe(pid)` → `%{rules: […]}`, then `{:kelix_debug_triggers, {:upsert, rule}}`
  and `{:kelix_debug_triggers, {:remove, {domain, script}, reason}}` with `reason`
  in `:exhausted | :expired | :removed | :orphan`. Same model as `Kelix.Traces`.
- Every returned rule carries the derived `seconds_left`, so no frontal computes it.

### 4.3 Wiring — pool and journal

- `spawn_instance/9`: `DebugTriggers.claim(domain, script, req)`; on `:journal`,
  `Keyword.put(overrides, :debug, true)` and `origin: :rule` on the instance map.
- `Kelix.Traces` summary gains `origin: :operator | :rule`, read from the
  instance row as `script`/`domain` already are. `kelictl debug <id> off` works on
  a triggered run as on any other.
- INFO log on every claim: `debug trigger <domain>/<script>: instance <id>
  journaled (<remaining> left)`.

### 4.4 Frontals

`Kelix.Control`: `debug_triggers/0`, `debug_trigger/2`, `set_debug_trigger/4`,
`remove_debug_trigger/3`, `subscribe_debug_triggers/1`,
`unsubscribe_debug_triggers/1`. kelescope calls these over RPC.

**kelictl** — under the existing `debug` noun, in the `key=value` style of the
domain commands:

```
debug trigger list [<domain>]
debug trigger show <domain> <script>
debug trigger set <domain> <script> count=N for=<n>{m|h|d|mo}
                  [caller=U | callee=U | source=IP[/len]]   [--admin NAME]
debug trigger remove <domain> <script>                      [--admin NAME]
```

```
$ kelictl debug trigger list
DOMAIN        SCRIPT    RUNS LEFT   TIME LEFT   FILTER
example.com   call.exs  3/5         1h 42m      caller=1001
acme.org      reg.exs   10/10       6d 3h       source=10.1.0.0/16
```

`debug list` gains an `ORIGIN` column (`operator` / `rule`). Help topic `debug`,
completion (domains, then that domain's scripts) and exit codes follow the
existing `debug` commands.

**REST** — same authentication as `POST /scenarios/:id/debug`:

| Route | Body / answer |
|---|---|
| `GET /debug/triggers` | `[rule]` (`?domain=` filters) |
| `GET /debug/triggers/:domain/:script` | `rule` / 404 |
| `PUT /debug/triggers/:domain/:script` | `{"count": 5, "duration": "2h", "filter": {"caller": "1001"}}` → `rule` / 400 with reason |
| `DELETE /debug/triggers/:domain/:script` | 204 / 404 |

`:script` is URL-encoded (a script name may hold `/`).

### 4.5 kelescope

kelescope (its own repo) shows rules in three places and edits them in one.
Its specification goes in `kelescope/docs/conception/declencheurs-debug/SPEC.md`
(French, like the other kelescope specs), on the model of
`journal-scenario/SPEC.md` and `domaines-editables/SPEC.md`.

**Link.** `Kelescope.Kelixip.DebugTriggersLink` in `kelescope_monitor`, modelled
on `TracesLink`: it subscribes once per node with
`Kelix.Control.subscribe_debug_triggers/1`, keeps the snapshot and rebroadcasts
the pushes on a PubSub topic, which both the monitor and the Domaines screen
subscribe to. A node without the contract (kelixip before the release that ships
T4) gets no trigger UI at all, as `traces_mode` does for journals.

**Rights.** Reading a rule follows the domain: whoever sees the domain sees its
rules. Setting or removing one needs `Scope.can?(scope, :debug, domain)` — the
right that already gates `debug on|off` in the monitor — not the right to edit
the domain. The account id goes to `--admin` (`created_by`).

**1. Domaines › Scénarios — where rules are read and edited.** The tab already
lists every `.exs` of the domain, function by function
(`KelescopeWeb.Domaines.ScenariosTab`). Each script line gains:

- when the script has a rule: a badge *Débug · 3/5 · 1 h 42* (runs left / total,
  time left, counted down live) and the filter in clear (*appelant 1001*);
- for an account with `:debug` on the domain: a *Débug…* button (or *Modifier*
  / *Supprimer* on the badge). It opens the form **under the script line**, one
  form at a time, as the domain edit forms do: number of runs, duration and unit
  (min / h / j / mois), one optional filter (a select *aucun / appelant / appelé
  / adresse IP*, then the value). The node's refusal reason (N above
  `max_traces`, invalid CIDR…) shows in the form.

A script listed under several functions of the same domain is one rule: the badge
shows on each of its lines, and editing from any of them edits the same rule.

**2. Domaines › Vue d'ensemble — the domain's count.** One line *Déclencheurs de
débug actifs : 2*, linking to the Scénarios tab. No editing there.

**3. Monitor — the node-wide list.** A folding panel *Déclencheurs de débug*
beside the database panels of `ScenarioMonitorLive`: every rule of the node, the
columns of `kelictl debug trigger list`, sorted by time left. Each row offers
*Supprimer* (with `:debug` on its domain) and a link to Domaines › Scénarios of
its domain, where it is edited. The journals list of the same page shows a *règle*
badge on journals whose `origin` is `:rule`.

## 5. Lots

| Lot | Content | Tests |
|---|---|---|
| T1 | `SIP.Msg.Ops.caller_users/1`, `callee_users/1`, `source_ip/1` | PAI on one and two lines, `tel:`, missing headers, hand-built request |
| T2 | `Kelix.DebugTriggers`: validation, ETS, claim, expiry timers, pushes; persistence per decision 1 | concurrent claims never exceed N; expiry; restart reload drops expired rules; corrupt file → node starts, rules empty, ERROR line |
| T3 | Pool wiring (`claim` + `debug: true` + `origin`), `Traces` `origin`, `prune` from `Kelix.Domains` | mockup INVITE matching/non-matching each filter; journal holds the inbound request; 503 consumes nothing; domain delete removes the rule |
| T4 | `Kelix.Control`, `Kelix.ControlAPI` routes, `kelictl` grammar, render, help, completion | CLI parse/render; REST status codes; `debug list` ORIGIN |
| T5 | kelescope (its repo, §4.5): SPEC, `DebugTriggersLink`, Scénarios tab badge + form, overview count, monitor panel, journal `règle` badge | its own suite |
| T6 | `administration.md`, `rest-api.md`, `DESIGN-KELIXIP.md` section, release notes, version bump (CLAUDE.md, *Changing the version*) | — |

T1 → T2 → T3 is the critical path; T4 can start once T2's API is fixed. T5
needs T4's `Kelix.Control` functions only.

## 6. Risks

- **Store eviction.** A wide rule (no filter, busy script) fills `Kelix.Traces`
  with N journals and pushes older ones out. Bounded by decision 4; `origin` makes
  it visible.
- **Personal data.** A journal holds full SIP messages (numbers, names; chat
  content is already never journaled). A rule running for a month on a busy script
  journals strangers' calls. The `created_by` field and the INFO line on every
  claim are the audit trail; the release notes say so.
- **Pool latency.** `claim` runs in the pool process. The lookup is ETS; the
  `GenServer.call` happens only for a matching run, at most N times per rule.
