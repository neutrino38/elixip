# options-plan.md — out-of-dialog OPTIONS served by scripts

**Status: phases 0 to 6 implemented and unit-tested; phase 7 (real traffic) not
done.** Decisions taken on 2026-09-29. This document is the order the work was
built in, what each phase delivers, and what proves it.

## 1. Scope

A domain declares how it answers an out-of-dialog OPTIONS, the way it declares its
dial-plan:

```toml
[[domain.options]]
keepalive = true
script    = "options-keepalive.exs"

[[domain.options]]
pattern = "conf-."
script  = "options-mcu.exs"

[[domain.options]]
default = true
script  = "options-probe-ua.exs"
```

- `keepalive = true` serves an R-URI with **no user-part** (`sip:domain`): the
  liveness ping of an upstream proxy or load balancer. At most one per domain; its
  position in the list does not matter, since no pattern is tried against an empty
  user-part.
- `pattern` serves the R-URI user-part, with the `Kelix.DialPlan` syntax of
  `[[domain.call]]`. The syntax has a trap: `*` is a literal character, so
  `conf-*` matches only the string `conf-*`. Write `conf-.` (one or more
  characters) or `conf-!` (zero or more).
- `default = true` is the catch-all for an R-URI that has a user-part, and must be
  the last rule.

| In scope | Why |
|---|---|
| `[[domain.options]]` parsing, validation, preflight | a rule that cannot load must be refused at reload, not on the first ping |
| routing an OPTIONS to a script instance | the whole point |
| a short dialog for a scripted OPTIONS | the digest challenge and the relay both need one (§3) |
| digest challenge of the OPTIONS **sender** | a probe of a registered UA is not answered to anyone |
| relaying an OPTIONS to a registered UA, and its answer back with its capabilities | the capability query reaches the only party that can answer it |
| reference scripts `options-keepalive.exs`, `options-probe-ua.exs` | a function without a script is not shipped |

| Out of scope | Why |
|---|---|
| `options-mcu.exs` | an example in `domains.toml` and in the documentation only |
| in-dialog OPTIONS on a call or a registration | the dialog already answers them itself |
| `[[domain.options]]` in `kelictl domain show` and the control API | not asked for; `describe_domain/3` lists `registrar`, `calls`, `presence` only |

## 2. The starting point

What existed on `framagit/master` (`10a2e99`).

| Piece | State |
|---|---|
| `SIP.Dialog.process_incoming_request/3` | answered an out-of-dialog OPTIONS **synchronously, inside the server transaction process**, through `ConfigRegistry.dispatch_options/2`. No dialog was created, on purpose: a 60 s dialog per ping from a monitoring proxy was the previous defect |
| `Kelix.Options.on_options/2` | 200 with a fixed `Allow`, or 503 while the node drains. Knew nothing of the domains |
| `ConfigRegistry.dispatch/3` | had no clause for `:OPTIONS`: an initial OPTIONS reaching it got 501 |
| `SIP.DialogImpl`, in-dialog OPTIONS | answered 200 by the dialog itself, whatever dialog it was |
| `SIP.Session.B2bua.dialog_forming?/1` | refused OPTIONS: `b2bua_forward/4` failed with `:not_dialog_forming` |
| `SIP.Msg.Ops.forwarded_reply_fields/1` | relayed `Reason`, `Warning`, `Retry-After` and nothing else of a response's headers |
| `CallUAS.auto_store/2` | stored INVITE, UPDATE, REGISTER, SUBSCRIBE, PUBLISH in `last_uas_req` — not OPTIONS |
| `Kelix.Mod.AuthDb` `@never_challenged` | listed OPTIONS, so that challenging a liveness ping could not make the node look down |
| `Kelix.Mod.AuthDb.SBB.Authenticate` | method-generic, but awaited the re-submission of INVITE, SUBSCRIBE and PUBLISH only |
| `Kelix.Mod.Registrar.targets/2` | resolves the AOR of the R-URI to a peer; reused as is |

## 3. Decisions

### A scripted OPTIONS gets a short dialog

Two designs were weighed:

- **(a) a short dialog**, created only when the OPTIONS is routed to a script.
  The re-submission after a 407 keeps the Call-ID and the From-tag and carries no
  To-tag, so it finds the same dialog and the same instance, exactly as an INVITE
  does. `on_events`, the `authenticate` block, `b2bua_forward` and
  `Registrar.targets` then work with small changes.
- **(b) no dialog**: a new delivery path to the application, a new relay
  primitive for a lone transaction, and a stateless challenge (one instance per
  attempt). More new code, and a second way of doing what (a) already does.

**Chosen: (a).** The dialog lives 32 s (timer F). An OPTIONS arriving on the same
dialog (same Call-ID and From-tag) rearms that timer and is delivered to the
running instance instead of being answered by the dialog. When the instance ends,
the dialog ends (17974e7); the next OPTIONS opens a new one.

An OPTIONS that is not routed to a script keeps the synchronous, dialog-less path.
The previous fix stays valid for every ping the core answers.

### What the core still answers

The 503 of a draining node is decided **first**, before any script: leaving the
upstream rotation must never depend on a script loading.

The core (`Kelix.Options`, 200 with `Allow`) also answers when:

- the R-URI host matches no domain — a load balancer pinging an address must keep
  getting 200;
- the domain has no `[[domain.options]]` rule;
- the R-URI has no user-part and the domain has no `keepalive` rule.

The `default` rule never serves an R-URI with no user-part. Otherwise
`options-probe-ua.exs` would answer 480 to the load balancer's ping.

An R-URI with a user-part matching no rule is answered 404, as a call is.

If `domains.toml` is reloaded between `Kelix.Options` routing an OPTIONS to a
script and its dialog reaching `Kelix.Router.dispatch/3`, and no rule claims it
any more, the dialog is refused with the core's answer (200 and `Allow`).

### Quota

A scripted OPTIONS instance **counts in `max_calls`**, through the same
`InstancePool.accept` as a call, and gets 503 beyond it. Consequence: a burst of
probes can make calls be refused. The keepalive the core answers creates no
instance and is never refused this way.

For the same reason `options-keepalive.exs` answers and ends at once, rather than
waiting on its dialog for the next OPTIONS: an instance per ping held for 32 s
would keep several slots taken by a load balancer pinging every few seconds with a
fresh Call-ID each time.

### Who is challenged

The **sender** of the OPTIONS, with a 407, before anything is relayed.
`@never_challenged` loses OPTIONS: the liveness ping is protected by the routing
(it goes to the keepalive rule or to the core), no longer by its method.

### What crosses back from the UA

The answer to a relayed OPTIONS carries the UA's `Allow`, `Accept`,
`Accept-Encoding`, `Accept-Language`, `Supported` and `Allow-Events` — the whole
answer to a capability probe. Only on the answer to an OPTIONS: on an INVITE's
answer the same headers would promise extensions the B2BUA does not perform on the
other leg (100rel, replaces).

## 4. Phases

| # | App | Delivers | Proven by |
|---|---|---|---|
| 0 | — | `feat/options` fast-forwarded to `framagit/master` | `git merge --ff-only` |
| 1 | elixip2 | `SIP.Session.Options.on_options/2` may answer `:dispatch`; the optional `on_new_options/3` receives the dialog. `SIP.Dialog` opens a 32 s inbound OPTIONS dialog; `SIP.DialogImpl` rearms it and delivers every OPTIONS on it to the application. `ConfigRegistry.dispatch/3` gains its `:OPTIONS` clause. The B2BUA accepts OPTIONS as a leg (`dialog_forming?/1`, `@default_timeouts`) | `options_out_of_dialog_test.exs`: a dispatched OPTIONS reaches the app on a dialog of its own and nothing is answered before the app; a second OPTIONS with the same Call-ID and From-tag reaches the same app and rearms the timer; a non-dispatched OPTIONS still creates no dialog |
| 2 | kelixip | `Kelix.Domain` gains `options_keepalive` (the keepalive script) and `options` (`%Kelix.DialRule{}` list). `Kelix.Domains` parses `[[domain.options]]` and feeds `script_refs/1`, hence the preflight | `domains_test.exs`: one test per refusal (two keepalive rules, `keepalive = false`, a keepalive rule with a pattern, catch-all not last, a rule of no kind) |
| 3 | kelixip | `Kelix.Router.resolve_options/2` decides per §3; `Kelix.Options` asks it after the drain; `Router.dispatch/3` routes the OPTIONS dialog through the pool, `max_calls` included; metric function label `:options` | `router_test.exs`, `options_test.exs`, `dispatch_test.exs` (a scripted OPTIONS takes the only slot, and the INVITE after it gets 503) |
| 4 | elixip2, kelix_modules | OPTIONS is challengeable; `Authenticate` awaits an `{:OPTIONS, …}` re-submission; `auto_store/2` stores the OPTIONS in `last_uas_req` | `auth_sbb_test.exs`: 407 with no 100 Trying, then authenticated on the re-submission |
| 5 | elixip2, kelixip scripts | `forwarded_reply_fields/1` relays the capabilities of an OPTIONS answer. `options-keepalive.exs` (200 with `Kelix.Options.allow()`, then ends); `options-probe-ua.exs` (407 → `Registrar.targets` → 480 when unregistered, otherwise relay and relay the answer back, 408 when the UA never answers) | `msg_ops_b2bua_test.exs`; `options_scripts_test.exs` — both scripts with the mockup UA, plus one OPTIONS injected on the mockup transport and answered 200 by `options-keepalive.exs` through the whole chain |
| 6 | docs | `packaging/config/domains.toml`, `docs/kelixip/installation.md`, `DESIGN-KELIXIP.md` §4, the challenge rule in `DESIGN-AUTH.md` and `modules/auth_db.md`, the behaviour table in `DESIGN-FRAMEWORK.md` | review |
| 7 | — | real traffic: a registered Linphone probed through `sip:bob@domain`, and a keepalive ping on `sip:domain` | **not done** |

Checked to fail with the change they cover removed: the second-OPTIONS delivery
(phase 1), the `{:OPTIONS, …}` re-submission clause (phase 4), the B2BUA
accepting OPTIONS and the wire test telling the script from the core (phase 5).

## 5. Found on the way, not fixed here

`SIPMsg.parse_header/4` accepts a header name only if it starts with an upper-case
letter (`~r/^[A-Z][0-9 a-zA-Z\-]+$/`). Header names are case-insensitive (RFC 3261
§7.3.5), so a message carrying `allow:` or a compact form such as `v:` is refused
as a whole with `invalid_header_name`. A UA answering a relayed OPTIONS that way
would get its answer dropped.
