# dynamic-domains-plan.md — defining domains at run time

**Status: lots M, D0, D1 and D2 implemented 2026-10-29; D3 to D6 not started. Decisions taken 2026-10-29 (§3).**

## 1. Scope

Create, replace and delete a served domain on a running node, through three
frontals that share one implementation:

- `kelictl domain apply | export | delete`;
- the REST control API (`PUT` / `GET` / `DELETE /domains/:name`);
- kelescope, over the Erlang RPC it already uses (kelescope ADR-001).

**`domains.toml` is the store.** It moves to `/var/lib/kelixip/domains.toml`, is
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

- `KELIXIP_DOMAINS` (`apps/kelixip/rel/env.sh.eex`) gives the path, default
  `/etc/kelixip/domains.toml`. The packages install it there,
  `root:kelixip 0640`, `%config(noreplace)` in the RPM and a conffile in the deb:
  the node can read it, not write it.
- `Kelix.Domains` holds one `%Kelix.Domains{}` snapshot, built off to the side and
  swapped whole (`reload/2`). One bad element rejects the reload.
- `Kelix.Domains.parse/1` is two steps: `decode/1` turns the TOML text into a map,
  then `parse_domains/1` and `build_index/1` validate that map.
- `Kelix.Domains.check_scripts/1` runs the §5.3 contract on every referenced
  script. `Kelix.Control.reload_domains/0` calls it.
- The `toml` dependency decodes only. Nothing in the tree writes TOML.
- `Kelix.Mod.Mcu.Store` writes its JSON file atomically: a sibling `.tmp`, then a
  rename in the same directory.
- `Kelix.InstancePool.list/0` gives every running instance with its `domain`.
  `Kelix.InstancePool.shutdown/2` stops one cooperatively: it sends
  `{:scenario_ctl, :shutdown, reason}`, and the §5.3 contract makes every script
  answer it.
- `Kelix.Control.unregister/4` and `shutdown_scenario/2` take the name of the admin
  who asked, and log it.
- The deb `postrm` removes `/var/lib/kelixip` on `purge`.

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
- **A hand edit not yet reloaded is never overwritten.** The snapshot keeps the
  hash of the text it was built from. Before a write, kelixip compares it with the
  hash of the file on disk. If they differ, the write answers `file_changed` and
  nothing is applied.
- **A successful `reload-all` lifts the block.** It builds a new snapshot from the
  file on disk, so the two hashes agree again. A failed `reload-all` keeps the old
  snapshot and its old hash: the block stays, and the error says the file must be
  fixed and reloaded first.

### Decision 3 — deleting a domain stops every scenario attached to it

`delete` is never refused because the domain is in use. It runs in this order:

1. the snapshot without the domain is written and swapped (§4). From this point
   the router answers 404 to any new request for the domain;
2. `Kelix.InstancePool.shutdown_domain(name, {:domain_deleted, actor}, version)`, one call
   to the pool: every instance whose `domain` is `name` receives
   `{:scenario_ctl, :shutdown, reason}`, as `kelictl stop` sends it;
3. the registrations and the presence state of the domain are purged (below);
4. the answer gives the number of scenarios asked to stop and what each purge
   did. It does not wait for the scenarios to end: the shutdown is cooperative,
   and a call in progress ends with its BYE.

A race remains between the two steps. A request routed with the old snapshot just
before the swap can reach `InstancePool.launch` just after step 2, and its instance
would then live on a deleted domain. `InstancePool` closes it. A route carries the
`version` of the snapshot it was resolved from, and `shutdown_domain/3` records the
version that no longer has the domain. The pool answers 404 to a route of that
domain resolved from an older version. A domain created again under the same name
is resolved from a later version, so it runs, and nothing has to be cleared. The
check and `shutdown_domain/3` both run in the pool's GenServer, so one of them
always sees the other. The pool does not read the snapshot itself: a route built
without a version, as the test suite builds them, is not checked.

**The purge.** A domain created again under the same name must not inherit the
contacts or the published states of the old one. Two new facades do it, one per
module that holds state per domain:

- `Kelix.Mod.Registrar.purge_domain(name)` drops every binding of every AOR of the
  domain, as `kelictl registration remove` does for one AOR, and pushes the
  removals to the subscribers of the domain's registrations (kelescope);
- `Kelix.Mod.Presence.purge_domain(name)` drops every published state of the
  domain, as `kelictl presence remove` does for one AOR. The watchers are SUBSCRIBE
  scenarios of the domain: step 2 already stopped them.

Both take the **canonical name** and never resolve it through the snapshot: at step
3 the domain is no longer in it, and `Presence.served_domain/1` would not find it.
`Kelix.Control` calls them through `Kelix.ModuleRegistry.facade/4`. A module that
is not loaded holds nothing, so its purge is a no-op.

A purge can fail: the module is down or times out. The domain is deleted anyway,
and the answer names the module that failed. Nothing routes to the domain any
more, but a script of another domain can still look up its AORs (below). The
leftovers are purged again when a domain of that name is created: `put_domain/2` runs both purges **before** the swap that
creates a new name, so a recreated domain always starts empty.

**A domain removed by a reload (lot D0).** `Kelix.Domains` swaps the snapshot and
does nothing else: no process is told. Measured with a domain `gone.example`,
alias `alias.example`, one binding and one published state, then a reload of a
file without the domain:

- the running instances of the domain run to their own end. `InstancePool` does
  not read the snapshot after `launch`;
- the binding and the published state stay, under the canonical name, until the
  expiry sweep of each module removes them;
- `Registrar.lookup` of `bob@gone.example` still answers the old contact. A script
  of another served domain that looks up this AOR reaches it. Through the alias it
  answers `:notfound`, because folding an alias to its canonical name needs the
  snapshot.

A domain removed by a hand edit and a domain removed by `delete` therefore do not
end in the same state.

**Decided: a reload ends a removed domain as `delete` does.** `reload_domains/0`
runs steps 2 and 3 of `delete` for every name present in the old snapshot and
absent from the new one, with actor `nil`. Both removals share one path after the
swap. A `reload-all` that removes a domain therefore stops its calls in progress.

### Decision 4 — a file the node cannot write: the node starts, and writes fail explicitly

An operator may have set `KELIXIP_DOMAINS` to a path of their own, or a file may
have the wrong owner. The node starts and serves the file as today.

- At boot, kelixip checks that it can write the file **and** create a `.tmp` next
  to it, since the atomic write needs both. The result shows in `kelictl status`
  and `GET /status` (`domains_writable`).
- Every write then answers `read_only`, with a message an operator can act on: the
  path, the system reason (`eacces`, `erofs`, …), the user the node runs as, and the
  fix — give the file and its directory to that user, or point `KELIXIP_DOMAINS` to
  `/var/lib/kelixip/domains.toml`.
- The same check runs again before each write. A fixed permission works without a
  restart; a lost one gives the same explicit error, never a half-written file.

### Fixed points

- **The document is the `[[domain]]` table, in JSON.** Same keys, same nesting,
  same spelling (`event-package` included). `export` returns it and `apply` accepts
  it back. No second vocabulary.
- **One validation.** A written document goes through the same `parse/1` as the
  file at boot, since it *is* the file at boot.
- **One write path.** kelictl, the API and kelescope all call `Kelix.Control`. No
  frontal validates or writes on its own.
- **Whole-domain writes.** A `PUT` replaces the whole domain. No sub-resource for
  one dial-plan rule: the dial-plan is ordered, and patching one rule in an
  ordered list is how two editors produce a plan neither of them wrote.
- **Domain order in the file is kept.** A replaced domain keeps its place. A new
  domain goes at the end.
- **Optimistic concurrency.** A write may carry the snapshot `version` it was read
  from. If the snapshot moved since, the write answers `conflict` and nothing is
  applied. kelescope always sends it; kelictl sends it when `apply` is given
  `--version`.
- **The actor is logged.** Every write takes the name of who asked (`nil` allowed),
  like `shutdown_scenario/2`, and logs it with the domain name, the new version
  and, for a delete, the number of scenarios stopped.

## 4. The write path

The snapshot keeps two things it drops today: the decoded map of the whole file
(`source`) and the hash of the text it came from (`source_hash`).

`Kelix.Domains.put_domain(doc, opts)` and `delete_domain(name, opts)`:

1. take the current snapshot's `source`;
2. replace, append or remove one entry of its `"domain"` list;
3. encode the new map to TOML text, then `parse/1` that text: this validates the
   result, catches collisions of names and aliases, and proves the round trip;
4. `check_scripts/1` on the new snapshot, outside the GenServer, as `reload/2` does.
   A delete skips it: removing a domain cannot make a script unservable, and a
   delete must not be refused for a script of another domain;
5. in the GenServer, as one call: compare the expected `version`, compare the hash
   of the file on disk with `source_hash` (decision 2), check the file is writable
   (decision 4), write `.tmp` then rename, swap the snapshot. If a check fails,
   answer `conflict`, `file_changed` or `read_only`. If the write fails, answer the
   error and keep the current snapshot.

Writes are serialized by step 5. Two concurrent writes both pass steps 1–4; the
second one fails at step 5 with `conflict`, and its caller retries from step 1.

`Kelix.Control` gains `put_domain/2`, `delete_domain/2` (doc or name, then
`opts`: `actor`, `version`) and `export_domain/1`. `delete_domain/2` runs the
shutdown of decision 3 once the swap is done. After a successful write, both call
`Kelix.ModuleSupervisor.warn_missing_function_modules/0`, as `reload_domains/0`
does.

## 5. Migration of existing nodes

**The 1.9.0 package does the move.** It ships before the frontals can write: a
1.9.0 node reads its domains from `/var/lib/kelixip/domains.toml`, and the rest of
this plan lands on a node whose file is already there. 1.9.0-1 is already built,
so the move comes with a new `Release` of 1.9.0 (1.9.0-2), never a rebuild of
1.9.0-1 (`CLAUDE.md`, *Changing the version*).

On installation and on upgrade, the package moves the operator's file. It never loses it and never
overwrites a file already in `/var/lib/kelixip`.

- if `/var/lib/kelixip/domains.toml` exists: nothing is moved;
- else if `/etc/kelixip/domains.toml` exists: it is copied to
  `/var/lib/kelixip/domains.toml`, `kelixip:kelixip 0640`, comments included (they
  last until the first write through the frontals);
- else: an empty file with the generated header is created.

The package stops shipping `/etc/kelixip/domains.toml`. The RPM `%post` of the new
version runs while the old file is still present, so the copy happens before rpm
removes it (or saves it as `.rpmsave` if it was edited). The deb removes the old
conffile with `dpkg-maintscript-helper rm_conffile`. Both mechanisms are checked in
lot D5 on a real upgrade, not assumed.

`env.sh.eex` defaults `KELIXIP_DOMAINS` to `/var/lib/kelixip/domains.toml`. The
commented example moves to `/usr/share/doc/kelixip/domains.toml.example`.

## 6. Lots

Each lot builds and passes its tests before the next one starts. M ships in the
1.9.0 package; D0 to D6 come after it.

| Lot | Content | Proof |
|---|---|---|
| M | **1.9.0 package:** the move of §5 — `env.sh.eex` default, RPM spec and deb `postinst` / `conffiles` / maintscript, the example in the doc directory, `Release` bumped to 2 in both packages and a `deb/changelog` entry. Docs: `installation.md`, `administration.md`, the `config.toml` comments that name the file's location, the 1.9.0 release notes. | RPM and deb builds; an **upgrade** from 1.8.2 and from 1.9.0-1 on each, with an edited `/etc/kelixip/domains.toml`, ends with the same domains served from `/var/lib/kelixip`; a fresh install starts with the empty generated file |
| D0 | Record what a reload removing a domain does today to its instances, registrations and presence state (decision 3). Keep `source` and `source_hash` in the snapshot. | the existing `domains` tests pass unchanged; the D0 findings written into this plan |
| D1 | The TOML encoder (decision 1). | round-trip tests: the shipped example, every block type, strings needing escapes, nested arrays of tables, `[module.registrar]` kept as is |
| D2 | `put_domain` / `delete_domain` / `export_domain` in `Kelix.Domains` and `Kelix.Control`; version, hash and writability checks; `InstancePool.shutdown_domain/3` and the version check in `accept` and `launch`; `purge_domain/1` in the registrar and presence modules (`apps/kelix_modules`), called on delete, on a reload that removes a domain, and before creating a name; actor in the log. | tests: a delete leaves no binding and no published state of the domain, a recreated domain starts empty even after a purge that failed, a purge with the module not loaded is a no-op; a domain created then routed (a REGISTER reaches its script); an invalid doc changes nothing on disk; a missing script is refused; `conflict` on a stale version; `file_changed` after a hand edit, lifted by a successful reload and kept by a failed one; `read_only` with path, reason and user in the message; a delete stops a running call and a launch racing it gets 404; a reload removing a domain stops its call and purges its state; the file read back after a restart of `Kelix.Domains` gives the same snapshot |
| D3 | kelictl: `domain apply <file.json>` (and `-` for stdin), `domain export <name>`, `domain delete <name>` (prints the number of scenarios stopped), help and completion. `domains_writable` in `kelictl status`. | CLI parse and render tests; one run against a node started from the release |
| D4 | REST: `PUT /domains/:name`, `DELETE /domains/:name`, `GET /domains/:name/document`, `domains_writable` in `GET /status`. Status codes: 400 invalid, 404 unknown, 409 `conflict` / `file_changed`, 503 `read_only`. `docs/kelixip/rest-api.md`. | Plug tests, token auth included |
| D5 | Docs of the frontals: `administration.md` (apply, export, delete, the `file_changed` and `read_only` errors), the generated header of the file, the release notes. | a node installed from the package creates, routes and deletes a domain through kelictl and through the API |
| D6 | **kelescope** (separate repository, its own SPEC in French): create and edit forms, export/import JSON, delete with a confirmation that shows the active calls and registrations about to end and asks for the admin name, version sent on every write. Role rule: a domain admin edits only their domains. kelescope enforces it, because its RPC access to the node is total (ADR-001, *Conséquences*). | kelescope tests; end to end against a dev node |

## 7. Risks

- **A delete ends calls.** One command stops every call of a domain. kelictl and the
  API do not ask for confirmation; kelescope does (D6). The log line names who did
  it and how many scenarios it stopped.
- **Comments disappear.** The first write through the frontals removes every comment
  of a hand-written file. The release notes of the version say so, and the copy
  made at migration is the operator's last commented version if they need it.
- **Configuration under `/var/lib`.** The domains become node state. Whatever backs
  up `/etc/kelixip` must now also back up `/var/lib/kelixip/domains.toml`. D5
  documents it.
- **deb `purge` deletes the domains**, since it removes `/var/lib/kelixip`. Purge
  already removes the configuration, so the behaviour stays coherent, but it is
  worth one line in `installation.md`.
- **No cluster.** Two nodes behind one load balancer each have their own file. A
  domain created on one does not exist on the other. Until a cluster design
  exists, kelescope must say which node it writes to.
