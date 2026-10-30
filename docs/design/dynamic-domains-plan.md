# dynamic-domains-plan.md — defining domains at run time

**Status: lots M, D0 to D2 implemented (2026-10-29), D3 (2026-10-30); D4 to D7 not
started.
Decisions taken 2026-10-29 (§3), command grammar decided 2026-10-30 (§4).**

## 1. Scope

Create, edit and delete a served domain on a running node, one element at a time,
through three frontals that share one implementation:

- `kelictl domain …` commands (§4);
- the REST control API, one route per command (§5);
- kelescope, over the Erlang RPC it already uses (kelescope ADR-001).

There is no definition document. An operator does not write a domain as a file and
send it: they create it, then add its functions, its aliases and its rules with one
command each. `kelictl domain show` is how a domain is read.

**`domains.toml` is the store.** It lives in `/var/lib/kelixip/domains.toml`, is
owned by the `kelixip` user, and kelixip rewrites it on every change made through
the frontals. There is one source of truth for the domains, and it is the file the
node reads at boot and on `reload-all`. A domain created through the API is a
domain written in `domains.toml`, nothing else.

Out of scope:

- **uploading scripts.** A domain names scripts that already exist in
  `server.script_dir`. Pushing code to a node through an API is a separate decision,
  with its own security review.
- **editing `[module.registrar]` through the frontals.** It stays in `domains.toml`
  and kelixip keeps it as it is when it rewrites the file.
- **`config.toml`.** It stays in `/etc/kelixip`, read once at boot.
- **replication across a cluster.** The file is per node.

## 2. What exists

Lots M to D3 are in the tree.

- The packages install the node's file as `/var/lib/kelixip/domains.toml`,
  `kelixip:kelixip 0640`, and never overwrite it. An upgrade from a package that
  shipped `/etc/kelixip/domains.toml` copies it there (§6).
- `Kelix.Domains` holds one `%Kelix.Domains{}` snapshot. Besides the parsed domains,
  it keeps the decoded map of the whole file (`source`) and the SHA-256 of the text
  it was parsed from (`source_hash`).
- `Kelix.Domains.Toml.encode/1` writes that map back as TOML, with a generated
  header. It covers the schema's types only and refuses a text that does not read
  back as the same data (decision 1).
- `Kelix.Domains.put_domain/2` and `delete_domain/2` are the write path of §3 and
  §7: one `[[domain]]` table replaced, appended or removed, then encoded, parsed,
  checked and written.
- `Kelix.Domains.Edit` holds the commands of §4 as pure transformations of one
  domain's table (`change/2`, `new/2`, `rules/2`).
- `Kelix.Control` has one function per command family — `create_domain/3`,
  `set_domain/3`, `add_alias/3`, `remove_alias/3`, `set_registrar/3`,
  `remove_registrar/2`, `add_presence/4`, `set_presence/4`, `remove_presence/3`,
  `add_rule/5`, `update_rule/5`, `move_rule/5`, `remove_rule/4`, `set_keepalive/3`,
  `remove_keepalive/2` — and `delete_domain/2`. A new name is purged before it is
  created. A delete, and a reload that removes a domain, stop the domain's
  scenarios and purge its state (decision 3). Every write is logged with its
  actor and the command.
- `Kelix.InstancePool.shutdown_domain/3` stops the instances of one domain, and
  answers 404 to a route resolved from a snapshot older than the deletion.
- `Kelix.Mod.Registrar.purge_domain/1` and `Kelix.Mod.Presence.purge_domain/1`
  drop the state a module holds for one domain.
- `Kelix.Domains.writable/1` checks that the node can write the file and create a
  sibling `.tmp`. The node logs a warning at boot when it cannot.

## 3. Decisions

### Decision 1 — a TOML encoder of our own

The encoder covers the `domains.toml` schema only. The schema is closed:
`@allowed_top_keys` already refuses any other top-level key, and every key below is
known to the parser. The encoder writes strings, integers, booleans, string arrays,
tables and arrays of tables, nested ones included (`[[domain.presence.subscribe]]`).
No new dependency in the release.

Every write is checked by reading the text back: the encoded text goes through
`parse/1` and the result must equal the intended snapshot. A write that does not
round-trip is refused, and nothing reaches the disk.

### Decision 2 — a hand edit blocks the frontals until a reload succeeds

The file stays a text file. An operator can still edit it and run
`kelictl domain reload-all`.

- **Comments do not survive a write.** kelixip writes the file from its data, with
  a generated header saying the node owns the file and pointing to the commented
  example in `/usr/share/doc/kelixip/domains.toml.example`.
- **A hand edit not yet reloaded is never overwritten.** Before a write, kelixip
  compares the hash of the file on disk with `source_hash`. If they differ, the
  write answers `file_changed` and nothing is applied.
- **A successful `reload-all` lifts the block.** It builds a new snapshot from the
  file on disk, so the two hashes agree again. A failed `reload-all` keeps the old
  snapshot and its old hash: the block stays, and the error says the file must be
  fixed and reloaded first.

### Decision 3 — deleting a domain stops every scenario attached to it

`delete` is never refused because the domain is in use. It runs in this order:

1. the snapshot without the domain is written and swapped (§7). From this point
   the router answers 404 to any new request for the domain;
2. `Kelix.InstancePool.shutdown_domain(name, {:domain_deleted, actor}, version)`,
   one call to the pool: every instance whose `domain` is `name` receives
   `{:scenario_ctl, :shutdown, reason}`, as `kelictl stop` sends it;
3. the registrations and the presence state of the domain are purged (below);
4. the answer gives the number of scenarios asked to stop and what each purge
   did. It does not wait for the scenarios to end: the shutdown is cooperative,
   and a call in progress ends with its BYE.

A request routed with the old snapshot just before the swap can reach the pool just
after step 2. A route carries the `version` of the snapshot it was resolved from,
and `shutdown_domain/3` records the version that no longer has the domain. The pool
answers 404 to a route of that domain resolved from an older version. A domain
created again under the same name is resolved from a later version, so it runs, and
nothing has to be cleared. The check and `shutdown_domain/3` both run in the pool's
GenServer, so one of them always sees the other. A route built without a version,
as the test suite builds them, is not checked.

**The purge.** A domain created again under the same name must not inherit the
contacts or the published states of the old one.

- `Kelix.Mod.Registrar.purge_domain(name)` drops every binding of every AOR of the
  domain and pushes the removals to the subscribers of the domain's registrations
  (kelescope);
- `Kelix.Mod.Presence.purge_domain(name)` drops every published state of the
  domain and tells its watchers. The watchers are SUBSCRIBE scenarios of the
  domain: step 2 already stopped them.

Both take the **canonical name** and never resolve it through the snapshot, which
no longer has the domain. `Kelix.Control` calls them through
`Kelix.ModuleRegistry.facade/4`. A module that is not loaded holds nothing, so its
purge is a no-op.

A purge can fail: the module is down or times out. The domain is deleted anyway,
and the answer names the module that failed. Nothing routes to the domain any
more, but a script of another served domain can still look up its AORs:
`Registrar.lookup` of `bob@gone.example` answers the old contact. The leftovers are
purged again when a domain of that name is created: `domain create` runs both
purges **before** the swap, so a recreated domain always starts empty.

**A reload ends a removed domain as `delete` does.** `reload_domains/0` runs steps
2 and 3 for every name present in the old snapshot and absent from the new one,
with actor `nil`. Without it, a domain removed by a hand edit kept its running
scenarios, its bindings and its published states until they expired. A
`reload-all` that removes a domain therefore stops its calls in progress.

### Decision 4 — a file the node cannot write: the node starts, and writes fail explicitly

An operator may have set `KELIXIP_DOMAINS` to a path of their own, or a file may
have the wrong owner. The node starts and serves the file as today.

- At boot, kelixip checks that it can write the file **and** create a `.tmp` next
  to it, since the atomic write needs both, and logs a warning when it cannot. The
  result shows in `kelictl status` and `GET /status` (`domains_writable`), checked
  at the time of the request.
- Every write then answers `read_only`, with a message an operator can act on: the
  path, the system reason (`eacces`, `erofs`, …), the user the node runs as, and the
  fix — give the file and its directory to that user, or point `KELIXIP_DOMAINS` to
  `/var/lib/kelixip/domains.toml`.
- The same check runs again before each write. A fixed permission works without a
  restart; a lost one gives the same explicit error, never a half-written file.

### Decision 5 — one command per element, rules addressed by number

- **One command changes one element**: the domain's own keys, an alias, a function
  block, or one rule of an ordered list. Each is a complete write: read, change,
  validate, write, swap.
- **A rule is addressed by its number**, 1-based, in the order `domain show` prints
  it, which is the order the router tries it. The number of a rule changes when a
  rule is inserted, moved or removed before it.
- **Optimistic concurrency protects the number.** `domain show` prints the snapshot
  version. Every write command accepts `--version N`: if the domains changed since
  version N, it answers `conflict` and nothing is applied. Without `--version`, the
  command applies to the domains as they are when it runs. kelescope always sends
  the version it displayed.
- **One noun per function**: `call`, `chat`, `options`, and `subscribe` under a
  presence package. The noun names the list being edited, as `[[domain.call]]` and
  `[[domain.chat]]` name it in the file.
- **The catch-all stays last.** A rule added without a position goes just before
  the domain's `default` rule, or at the end when there is none. A command that
  would leave the `default` rule anywhere but last is refused by the parser, as the
  file is.

### Fixed points

- **One validation.** Whatever a command changes goes through the same `parse/1` as
  the file at boot, since it *is* the file at boot.
- **One write path.** kelictl, the API and kelescope call the same `Kelix.Control`
  functions. No frontal validates or writes on its own.
- **Domain order in the file is kept.** An edited domain keeps its place. A new
  domain goes at the end.
- **The actor is logged.** Every write takes the name of who asked (`nil` allowed)
  and logs it with the domain, the command, the new version and, for a delete, the
  number of scenarios stopped. kelictl passes the operator's Unix user name unless
  `--admin` names someone else.

## 4. The commands

`<d>` is a domain's canonical name. `<n>` and `<m>` are rule numbers. `<rule>` is
either a dial pattern or the keyword `default`. Every write command also takes
`--version N` and `--admin NAME`.

```
domain create <d> [aliases=a,b] [max_calls=N]
domain delete <d>
domain <d> set [max_calls=N|none]
domain <d> alias add <host>
domain <d> alias remove <host>

domain <d> registrar set script=X [default_expires=N|none] [min_expires=N|none]
                                  [keepalive_period=N|none]
domain <d> registrar remove

domain <d> presence add <package> subscribe=X [publish=Y]
domain <d> presence set <package> [subscribe=X] [publish=Y|none]
domain <d> presence remove <package>
domain <d> presence <package> subscribe add <rule> script=X [at=N]
domain <d> presence <package> subscribe update <n> [pattern=P|default] [script=X]
domain <d> presence <package> subscribe move <n> to=<m>
domain <d> presence <package> subscribe remove <n>

domain <d> call add <rule> script=X [at=N]
domain <d> call update <n> [pattern=P|default] [script=X]
domain <d> call move <n> to=<m>
domain <d> call remove <n>

domain <d> chat add <rule> script=X [idle_timeout=N] [at=N]
domain <d> chat update <n> [pattern=P|default] [script=X] [idle_timeout=N]
domain <d> chat move <n> to=<m>
domain <d> chat remove <n>

domain <d> options keepalive set script=X
domain <d> options keepalive remove
domain <d> options add <rule> script=X [at=N]
domain <d> options update <n> [pattern=P|default] [script=X]
domain <d> options move <n> to=<m>
domain <d> options remove <n>
```

- `create` also purges the name first (decision 3). It refuses a name or an alias
  another domain already serves.
- `set` and `registrar set` change only the keys they are given. `none` removes an
  optional key. `registrar set` on a domain without registrar creates the block,
  and then needs `script`.
- `presence set <package> subscribe=X` replaces the package's SUBSCRIBE rules with
  the single catch-all `X`. The `subscribe` commands edit them one by one.
- `add … at=N` inserts at position N; the rules from N on move down by one.
- A `default` pattern cannot be a dial pattern: `default` is a keyword wherever a
  rule is given.

`domain show` prints the snapshot version and numbers every rule list, `subscribe`
rules included. `domain list`, `domain show` and `domain reload-all` are unchanged.

## 5. The REST routes

The same operations, under `/domains`. A body is JSON with the arguments of the
command, string keys. `version` goes in the body or the query string; the admin
name in the `X-Kelix-Admin` header.

| Command | Route |
|---|---|
| `create` | `POST /domains` `{name, aliases, max_calls}` |
| `delete` | `DELETE /domains/<d>` |
| `set` | `PATCH /domains/<d>` |
| `alias add` / `remove` | `POST /domains/<d>/aliases` `{host}` / `DELETE /domains/<d>/aliases/<host>` |
| `registrar set` / `remove` | `PATCH /domains/<d>/registrar` / `DELETE /domains/<d>/registrar` |
| `presence add` / `set` / `remove` | `POST /domains/<d>/presence` / `PATCH` and `DELETE /domains/<d>/presence/<package>` |
| `<list> add` | `POST /domains/<d>/<list>` |
| `<list> update` | `PATCH /domains/<d>/<list>/<n>` |
| `<list> move` | `POST /domains/<d>/<list>/<n>/move` `{to}` |
| `<list> remove` | `DELETE /domains/<d>/<list>/<n>` |
| `options keepalive set` / `remove` | `PUT` / `DELETE /domains/<d>/options/keepalive` |

`<list>` is `calls`, `chat`, `options` or `presence/<package>/subscribe`. Status
codes: 400 invalid (the parser's message), 404 unknown domain, package or rule
number, 409 `conflict` or `file_changed`, 503 `read_only`. `GET /status` carries
`domains_path`, `domains_writable` and, when the file is not writable,
`domains_write_error`.

## 6. Migration of existing nodes

Done in lot M, package 1.9.0-2. On installation and on upgrade, the package moves
the operator's file. It never loses it and never overwrites a file already in
`/var/lib/kelixip`.

- if `/var/lib/kelixip/domains.toml` exists: nothing is moved;
- else if `/etc/kelixip/domains.toml` exists: it is copied to
  `/var/lib/kelixip/domains.toml`, `kelixip:kelixip 0640`, comments included (they
  last until the first write through the frontals);
- else: a file with a header and no domain is created.

The package no longer ships `/etc/kelixip/domains.toml`. The RPM `%post` runs while
the old file is still present, so the copy happens before rpm removes it, or saves
it as `.rpmsave` if it was edited. The deb removes the old conffile with
`dpkg-maintscript-helper rm_conffile`, and keeps an edited one as `.dpkg-bak`. An
environment file that still names `/etc/kelixip/domains.toml` is pointed at the new
path. The commented example is `/usr/share/doc/kelixip/domains.toml.example`.

## 7. The write path

Every command is a transformation of one `[[domain]]` table, in `Kelix.Control`:

1. read the current snapshot and the domain's table in its `source`. An unknown
   domain, package or rule number answers `not_found`;
2. apply the command to the table: set or remove a key, insert, replace, move or
   remove one entry of an ordered list;
3. hand the table to `Kelix.Domains.put_domain/2` with the version given by the
   caller, or else the version read at step 1. `delete` hands the name to
   `delete_domain/2`.

`Kelix.Domains` then:

1. replaces the domain in the decoded file, in its place;
2. encodes the file to TOML and parses that text: this validates the result,
   catches collisions of names and aliases, and proves the round trip;
3. runs `check_scripts/1` on the new snapshot, outside the GenServer. A delete
   skips it: removing a domain cannot make a script unservable;
4. in the GenServer, as one call: compares the expected `version`, compares the
   hash of the file on disk with `source_hash`, checks the file is writable, writes
   `.tmp` then renames, swaps the snapshot. A failed check answers `conflict`,
   `file_changed` or `read_only`, and nothing is applied.

Writes are serialized by the last step. Of two concurrent writes, the second
answers `conflict`. It is never retried on its own: a rule number read before the
first write may name another rule after it.

After a successful write, `Kelix.Control` calls
`Kelix.ModuleSupervisor.warn_missing_function_modules/0`, as `reload_domains/0`
does.

## 8. Lots

Each lot builds and passes its tests before the next one starts.

| Lot | Content | Proof |
|---|---|---|
| M ✓ | **1.9.0-2 package:** the move of §6. | RPM and deb builds; upgrades from 1.8.2 and 1.9.0-1 with an edited file serve the same domains from `/var/lib/kelixip`; a fresh install starts with no domain |
| D0 ✓ | What a reload removing a domain did (decision 3). `source` and `source_hash` in the snapshot. | findings in decision 3 |
| D1 ✓ | The TOML encoder (decision 1). | round-trip tests |
| D2 ✓ | The write path of §7 below `Kelix.Control`; `shutdown_domain/3` and the version check in the pool; `purge_domain/1` in registrar and presence; the end of a removed domain on delete and on reload. | write, refusal, race and purge tests |
| D3 ✓ | `Kelix.Control`: one function per command family of §4, each a transformation of the domain's table handed to `put_domain/2`; `domain create` purges first and refuses an existing name or alias. The JSON document entry points (`put_domain/2` as a public command, `export_domain/1`) leave `Kelix.Control`. | per command: the table it writes; `not_found` for an unknown domain, package or number; `add` before the catch-all and `at=N`; `move`; a `default` moved off the end refused; `none` removes a key; `--version` conflict after a rule was inserted before the one addressed; the file read back gives the same snapshot |
| D4 | kelictl: the grammar of §4, `domain show` with the version and numbered lists, help and completion. `domain delete` and the `domains file` line of `kelictl status` stay. | CLI parse and render tests; one run against a node started from the release |
| D5 | REST: the routes of §5, `docs/kelixip/rest-api.md`. | Plug tests, token auth included |
| D6 | Docs of the frontals: `administration.md` (the commands, the rule numbers and `--version`, the `file_changed` and `read_only` errors), the release notes. | a node installed from the package creates a domain, adds a rule, routes a call to it and deletes the domain through kelictl and through the API |
| D7 | **kelescope** (separate repository, its own SPEC in French): forms per element over the same commands, the version sent on every write, delete with a confirmation that shows the active calls and registrations about to end and asks for the admin name. Role rule: a domain admin edits only their domains. kelescope enforces it, because its RPC access to the node is total (ADR-001, *Conséquences*). | kelescope tests; end to end against a dev node |

## 9. Risks

- **A rule number can name another rule.** Between `domain show` and `call remove
  3`, another write may insert a rule before rule 3. Without `--version`, the
  command removes whatever is rule 3 by then. `--version` closes it; kelescope
  always sends it; the documentation of D6 says so next to every numbered command.
- **A domain is built in several writes.** Each command is a complete write, so a
  domain being set up is served in its intermediate states: `create` alone serves a
  domain that answers 405 to every method until its functions are added.
- **A delete ends calls.** One command stops every call of a domain. kelictl and the
  API do not ask for confirmation; kelescope does (D7). The log line names who did
  it and how many scenarios it stopped.
- **Comments disappear.** The first write through the frontals removes every comment
  of a hand-written file. The copy made at migration is the operator's last
  commented version if they need it.
- **Configuration under `/var/lib`.** The domains are node state. Whatever backs up
  `/etc/kelixip` must also back up `/var/lib/kelixip/domains.toml`.
- **deb `purge` deletes the domains**, since it removes `/var/lib/kelixip`.
- **No cluster.** Two nodes behind one load balancer each have their own file. A
  domain created on one does not exist on the other. Until a cluster design
  exists, kelescope must say which node it writes to.
