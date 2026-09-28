# Release 1.6.0

2026-09-26 — 69 commits since 1.5.5 (2026-09-19). Theme: presence (SUBSCRIBE,
PUBLISH, NOTIFY and buddy lists), and the Finite State Language leaving the tree
as a package of its own.

## Presence

kelixip provides s now a presence server function (RFC 6665 / 3856 / 3903): it accepts
subscriptions, stores what presentities publish, and NOTIFYs every watcher when
a state changes. The function ships as a new package, **`kelixip-mod-presence`**,
with its reference scripts.

| Script | Serves |
|---|---|
| `presence-subscribe.exs` | SUBSCRIBE — authenticates, admits, NOTIFYs the state |
| `presence-publish.exs` | PUBLISH — authenticates, stores, fans out |
| `presence-rls.exs` | a buddy list: one SUBSCRIBE for the whole roster |
| `registrar-presence.exs` | `registrar.exs` + presence follows registrations |

A domain declares one `[[domain.presence]]` block **per event package**. The
`Event` header selects the block; a package the domain does not serve is answered
**489** with `Allow-Events`, before any script runs.

```toml
[[domain]]
name = "example.com"

  [domain.registrar]
  script = "registrar-presence.exs"

  [[domain.presence]]
  event-package = "presence"
  subscribe     = "presence-subscribe.exs"
  publish       = "presence-publish.exs"
```

**The module stores and pushes; it decides nothing about who may watch whom.**
Admission is the subscribe script's. Both reference scripts challenge SUBSCRIBE
and PUBLISH with a 401 through `auth_db`.

**A subscriber that does not PUBLISH is open while registered.** With
`registrar-presence.exs`, a subscriber is open while at least one of its devices
holds a registration and closed when the last one goes — un-REGISTER, connection
lost, or lapse. `kelictl registration remove` and the REST equivalent update
presence too.

**Buddy lists (RFC 4662 / RFC 5367).** The list travels in the SUBSCRIBE: no XCAP
server yet, no list store. The answer is one NOTIFY carrying an RLMI manifest and one
PIDF part per buddy; later changes are batched every 500 ms. Each buddy is looked
up on the domain of its own URI, not the domain that routed the request. Linphone
hard-codes `sip:rls@sip.linphone.org`: declare that host as a domain served by
`presence-rls.exs` (see `packaging/config/domains.toml`).

Control commands: `kelictl presence list | show | watchers | remove`, and
`/modules/presence/presentities` over REST.

Limitations: full state only (no PIDF diff), no composition of several
publishers, in memory and local to one node, no `presence.winfo`.

Reference: [docs/kelixip/modules/presence.md](../kelixip/modules/presence.md),
`DESIGN-PRESENCE.md`.

### In the framework

- **`SIP.EventPackage`** and its registry; `presence` is the first package.
- **The subscription layer** (`SIP.Session.Subscribe`): `accept_subscription/1`,
  `notify/1`, `terminate_subscription/1`, with the 406 / 423 / 489 answered by the
  verbs, not the script. The UAC side is there too.
- **PUBLISH** (`SIP.Session.Publish`): `check_publish/1` answers 400 / 415 / 423 /
  489 and hands the script a `%SIP.Publication{}`.
- **PIDF, RLMI, resource lists** (`SIP.Presence.Pidf`, `.Rlmi`,
  `.ResourceLists`), hardened against untrusted XML.
- **`challenge_request/2`**: the digest challenge of `challenge_invite`, for any
  method.
- **elixipp**: `uac_subscribe.exs` (watcher) and `uas_presence.exs` (notifier,
  `uas :presence`) test presence end to end with no node.

## SIP stack

- **Compressed bodies support.** `Content-Encoding: deflate` (zlib or raw
  DEFLATE) is decoded after the Content-Length cut; an unknown coding gets a 415
  with `Accept-Encoding`. 
- **A NOTIFY above 500 octets is deflated** when the watcher accepts it. A list
  NOTIFY over IPv6 otherwise exceeds the path MTU and never arrives.
- **UDP receives datagrams up to 64 KB.** OTP's default buffer silently truncated
  anything above 1460 octets. `max_message_size` remains the size policy.
- **A SUBSCRIBE demanding an unimplemented extension** (`Require:`) is answered
  **420** with `Unsupported`.
- **`multipart/related`** is parsed whatever the parameter order, and parts carry
  their `Content-ID`.
- **An optional callback the host does not implement** is answered **501**
  instead of crashing the dialog before any response. An out-of-dialog MESSAGE
  (e.g. a Linphone typing indicator) is now refused cleanly.
- **A REGISTER dialog ends with its application.** Refreshes no longer reach a dead
  session and time out 408.
- **A subscription challenged once** is established on the 2xx to its replay; an
  un-SUBSCRIBE no longer crashes the dialog.
- **OPTIONS advertises** INVITE, ACK, CANCEL, BYE, SUBSCRIBE, PUBLISH and NOTIFY in
  `Allow`.

## kelixip

- **Registrar**: `Expires: 0` removes only the contacts it names (RFC 3261
  §10.3), no longer every binding of the AOR.
- **kelictl**: module commands take positional arguments —
  `kelictl presence list example.com`.
- **Media**: a pool selector answering `nil` (pool not running) falls back to the
  configuration instead of crashing the call.
- **User-Agent is `Kelixip/1.6.0`**, and `Elixipp-1.6.0` for the tool.

## The Finite State Language is a package

FSL now lives in its own repository and is fetched from hex as
**`finite_state_language` 0.2.0** (OTP app `:fsl`, modules `FSL.*`), under
**Apache-2.0**. `LICENSE.md` says so; everything built on it stays BUSL-1.1.

SIP plugs into it through **`SIP.FSL.Host`**, eleven callbacks. **Scenarios and
scripts are unchanged**: `use SIP.Scenario`, `SIP.Scenario.Runner`, `SIP.SBB` and
the other SIP names remain, as facades over `FSL.*`.

Two names did change, because a facade cannot forward them:

- the live-monitor registry is registered as **`FSL.Monitor`**;
- its push tag is **`{:fsl_monitor, …}`**.

Reference: `DESIGN-FSL.md` (the SIP binding), and the package's own design doc.

## Build and packaging

- **mint 1.10.1**, fixing CVE-2026-82672 (GHSA-rj5m-69wp-cxq9).
- **Module packages require the core version, not its release**: a rebuild of the
  core no longer forces a rebuild of every module.
- New deb/rpm package `kelixip-mod-presence`.

## Upgrading

| Change | Effect if you leave it alone |
|---|---|
| `[domain.presence]` single table in `domains.toml` | **refused at load** — rewrite it as `[[domain.presence]]` with `event-package = "presence"` |
| Code matching the monitor by name or push tag | stops receiving updates — use `FSL.Monitor` / `{:fsl_monitor, …}` |
| `registrar-presence.exs` | none: `registrar.exs` reports nothing to presence |
| Out-of-dialog MESSAGE | answered 405 (it used to reach the presence function) |
| Anything else | scenarios and scripts load unchanged |
