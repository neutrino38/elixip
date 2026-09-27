# dialog-state-plan.md — call occupancy of a served AOR

**Status: planned.** The presence design is [DESIGN-PRESENCE.md](DESIGN-PRESENCE.md),
the B2BUA design [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md); this document is the
order the *call occupancy* of objective 1 gets built in, what each phase delivers,
and what proves it.

The consumer this plan is written for is the ACD (objective 3): it needs to know,
per agent, whether a call is ringing or up, and to be told the moment that changes.
A BLF key on a desk phone (`Event: dialog`, RFC 4235) and the composite presence
state (`on-the-phone`) are the same fact read through two other doors.

RFC 7463 — shared appearances, line numbers, seize arbitration, `Alert-Info
;appearance=` — is built on the dialog package this plan delivers, and is **not**
in it (§5).

## 1. What is known, and by whom

A dialog does not know who is on its far end. Its `From` is a claim, and on the
outbound leg of a B2BUA its Request-URI is a Contact, not an AOR. Reading "this
is a user of the domain" off the host part is how a trunk that carries our domain
in its `From` gets a lit BLF key.

The fact is proven in exactly two places, and nowhere else:

| The leg | Who proves it | With what |
|---|---|---|
| inbound — a UA of the domain is calling | `Kelix.Mod.AuthDb` | the digest: `{:ok, %{user, realm}}` |
| outbound — a UA of the domain is called | `Kelix.Mod.Registrar` | `targets/2` built the `%SIP.B2bua.Peer{}` from the AOR's bindings |

So the module that proves it **stamps the dialog**, and a dialog carrying no stamp
reports nothing. `direct-call.exs`, which authenticates nobody, lights no key —
correctly. `mcu.exs` stamps its caller, and its callee is a room `mcu_presence`
already reports.

## 2. What a reader sees

**The ACD** subscribes to the module and receives one row per stamped dialog,
on every transition:

```elixir
%{domain: "example.com", aor: "sip:bob@example.com",
  id: "a84b4c76e66710",            # Call-ID
  direction: :initiator | :recipient,   # from the AOR's point of view (RFC 4235)
  state: :trying | :proceeding | :early | :confirmed | :terminated,
  remote: "sip:alice@example.com", # the other party, as the request names it
  since: ~U[…]}
```

**A watcher of `Event: dialog`** (RFC 4235) receives `application/dialog-info+xml`
with `entity` = the AOR and one `<dialog>` per live dialog of that AOR; an AOR
with no call gets an empty document, not `noresource`. State is always `full`.

**A watcher of `Event: presence`** sees `open` + the RPID activity `on-the-phone`
while one dialog of the AOR is `confirmed`, through the reported-state rank of
the resolution order — below what the UA publishes itself, above the bare
registration. No rule is added: a UA that publishes is the authority on its own
state, and when the report is withdrawn the resolution falls back to `open`.

## 3. Decisions

| # | Decision | Why |
|---|---|---|
| 1 | The stamp is a field of the **dialog**, `remote_aor :: %SIP.Uri{} \| nil`, set by `SIP.Dialog.set_remote_aor/2` | the dialog is the process that sees its own transitions, and `sip_ctx` is not visible from it. `SIP.Context.asserted_identity` stays what it is — the identity a digest proved, written to `P-Asserted-Identity` — and is not reused: "what the network asserts" and "which served AOR this leg's far end is" are two facts that happen to coincide on the inbound leg only |
| 2 | Transitions leave the dialog through a `:duplicate` `Registry.SIPDialogEvents`, and **only stamped dialogs dispatch** | no new dependency; the unstamped dialogs of a trunk-to-trunk node pay nothing; a subscriber that is not there costs one ETS lookup |
| 3 | The outbound stamp travels in `%SIP.B2bua.Peer{aor: …}`, filled by `Registrar.targets/2`, applied by `b2bua_forward` when the leg is created | the fact is born with the peer; the scripts, `SBB.Call` and the B2BUA forward path do not learn a new argument |
| 4 | `early` is derived, not stored: a 1xx while the dialog is `:initial` | `SIP.DialogImpl.state` has no early state and the dialog layer is not being redesigned here |
| 5 | The module aggregates every dialog of one AOR into one document and reports once per AOR | presence keeps one reported document per `{resource, source}` — "latest wins" would drop the second call of a call-waiting handset |
| 6 | Neither `presence` nor the B2BUA depends on the new module; `dialog_state` holds the link, as `mcu_presence` does | both halves are optional packages; a node with calls and no presence, or the reverse, must not change |
| 7 | An AOR `auth_db` knows and no dialog resolves, on the `dialog` package, to an **empty** document | the reverse — `noresource` — would end the BLF subscription of every idle phone at subscribe time |
| 8 | Module name `dialog_state` (`Kelix.Mod.DialogState`) | the RPM `%files` and deb globs match `Elixir.Kelix.Mod.Presence*.beam`: a module named `Presence…` is swallowed by the presence package (the `Mcu*`/`McuPresence` trap, `build-deb.sh:250`) |
| 9 | On restart the module resyncs from `SIP.Dialog.dump/0` + `SIP.Dialog.info/1`, and monitors each stamped dialog | a dialog that crashes emits no `terminated`; a module that restarts has missed every event before it |

## 4. Phases

### DS1 — framework: the stamp and the push

`SIP.DialogImpl` gains `remote_aor: nil`. `SIP.Dialog`:

```elixir
SIP.Dialog.set_remote_aor(pid, %SIP.Uri{} = aor) :: :ok
SIP.Dialog.info(pid) :: %{callid, fromtag, totag, direction, state, remote_aor, msg, since}
SIP.Dialog.subscribe_events() :: :ok         # Registry.register on the caller
```

Setting the stamp dispatches the dialog's **current** state at once: the inbound
stamp arrives after the INVITE, from the authentication state, when the dialog is
already `trying` or `early`.

Dispatch points, each mapped to an RFC 4235 state:

| Where in `SIP.DialogImpl` | State | 4235 `event` on `terminated` |
|---|---|---|
| dialog created from an INVITE, or the INVITE sent | `trying` | |
| 1xx received or sent, dialog `:initial`; `< 180` without to-tag | `proceeding` | |
| 18x received or sent, dialog `:initial` | `early` | |
| 2xx — `establish_inbound`, `handle_UAS_response` | `confirmed` | |
| BYE either way | `terminated` | `local-bye` / `remote-bye` |
| CANCEL, 4xx-6xx, timer, `terminate/2` | `terminated` | `cancelled` / `rejected` / `timeout` / `error` |

Message: `{:sip_dialog, pid, %{… as info/1 …, event: …}}`. The registry is
started in `SIP.Dialog.start/0` next to `Registry.SIPDialog`.

Proved by: `apps/elixip2` tests over `SIP.Test.Transport.Mockup` — a stamped
inbound INVITE answered 180 then 200 then BYE yields exactly the four events, with
the inbound stamp set after the 180 yielding `early` first; an outbound leg
stamped at creation yields `trying` first; an unstamped dialog yields nothing;
a crash of the dialog yields nothing and the subscriber's monitor fires.

### DS2 — framework: the `dialog` event package

`SIP.EventPackage.Dialog`, builtin, name `dialog`, content type
`application/dialog-info+xml`, bounds as `presence`. Its document:

```elixir
%SIP.DialogInfo.Doc{entity: "sip:bob@example.com", version: 0, state: :full,
                    dialogs: [%SIP.DialogInfo.Dialog{
                      id, call_id, local_tag, remote_tag, direction,
                      state, event, code, local: %{identity, target},
                      remote: %{identity, target}}]}
```

`version` is the subscription's, not the document's: `send_notify` stamps it
before serialising when the document has a `:version` key. `parse` reads the same
XML back; nothing PUBLISHes it (a domain serving `dialog` answers `405`, as
`Kelix.Domain` already says).

Proved by: round trips of the RFC 4235 §6 examples; the version stamped by two
successive NOTIFYs on one subscription.

### DS3 — the two stamps

- `Kelix.Mod.AuthDb.SBB.authenticate`, on `{:ok, identity}`, after
  `assert_identity/1`: `SIP.Dialog.set_remote_aor(sip_ctx.dialogpid, aor)`.
- `%SIP.B2bua.Peer{}` gains `aor: nil`; `Kelix.Mod.Registrar.targets/2` fills it
  with the AOR whose bindings it grouped; `b2bua_forward` applies it to the
  outbound dialog at leg creation, when `peer.aor` is set.

No script changes. `config(uses_modules: …)` is untouched.

Proved by: `apps/kelix_modules` — the authenticate block stamps the inbound
dialog; `targets/2` returns the AOR; the reference `direct-call-with-auth.exs`
run over the mockup produces a stamped leg on each side, and `direct-call.exs`
none.

### DS4 — presence: a report per package

`Kelix.Mod.Presence.report/5` takes the package; `report/4` stays as the
`"presence"` case. On the `dialog` package:

- resolution is `reported_doc || empty document for a subscriber auth_db knows ||
  nil` (decision 7); the registration rank does not apply;
- `known?` is the same question as today, asked of the same subscriber base;
- the panel rows and `kelictl presence show` render a non-PIDF document by its
  package and dialog count instead of `status: nil`.

A domain declares it in `domains.toml` with the script it already has:

```toml
[[domain.presence]]
event-package = "dialog"
subscribe = "presence-subscribe.exs"
```

Proved by: unit tests of the `dialog` resolution; a watcher pushed on report and
on withdrawal, back to the empty document; `presence-subscribe.exs` accepting
`Event: dialog` for a known idle user and refusing an unknown one with `404`.

### DS5 — the `dialog_state` module

`Kelix.Mod.DialogState`: a GenServer, no SIP function, no script.

- at start, `SIP.Dialog.subscribe_events/0`, then the resync of decision 9;
- each `{:sip_dialog, pid, ev}` on a served domain updates `dialogs` (`pid =>
  row`) and `by_aor` (`aor => MapSet of pid`); a `:DOWN` on a monitored dialog
  is a `terminated` with event `error`;
- per AOR touched, two reports, **each only if its document changed**:
  - `report(domain, user, :dialog_state, dialog_info_doc, "dialog")` — the live
    dialogs of the AOR; `nil` when none;
  - `report(domain, user, :dialog_state, presence_doc)` — `open` + `on_the_phone`
    while one dialog is `confirmed`; `nil` otherwise. A ringing agent is `open`,
    not on the phone: the ACD reads the ringing from the dialog row;
- it monitors the presence module: a presence restart is a full re-report; while
  presence is down it keeps its state and retries, as `mcu_presence` does;
- push for the ACD: `subscribe_dialogs(domain, pid) :: {:ok, %{owner, dialogs}}`,
  then `{:kelix_dialogs, domain, {:upsert, row} | {:remove, id}}`, exposed by
  `Kelix.Control.subscribe_dialogs/2` through the module facade, as
  `subscribe_conferences` is.

Configuration:

```toml
[module.dialog_state]
# every key optional
domains = ["example.com"]   # absent: every served domain
```

`validate_config/1` refuses the block when `presence` is not loaded.

Control: `kelictl dialog_state list --domain example.com` — the live dialogs and
the state each AOR was reported in.

Proved by: unit tests of event → row → the two documents; two dialogs of one AOR
in one document; the resync after a module restart against a live dialog; the
re-report after a presence restart; the ACD push on each transition and the
`remove` on termination.

### DS6 — end to end, packaging, documentation

Integration test in `apps/kelix_modules`, `direct-call-with-auth.exs` over the
mockup, a BLF watcher on Alice and one on Bob:

1. Alice INVITEs → Alice `trying`, then `early` when Bob rings, Bob `early`
   `recipient`; the presence of both unchanged;
2. Bob answers → both `confirmed`; both `on-the-phone` to a presence watcher;
3. Bob hangs up → both empty documents; both back to `open`;
4. a second Alice → Bob call cancelled by Alice → `terminated;cancelled`, never
   `on-the-phone`.

Packaging: `kelixip-mod-dialog_state`, requiring `kelixip-mod-presence`, in both
the RPM and the deb build; the `dialog` package is in the core (elixip2).

Documentation: `docs/kelixip/modules/dialog_state.md` on the model of
`mcu_presence.md`; a *Call occupancy* section in
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md) with the stamp rule of §1 as an
invariant; the `dialog` package in `docs/kelixip/administration.md` next to
`presence`; a pointer from `presence.md` and `auth_db.md`.

## 5. Out of this plan

- **RFC 7463 — shared appearances.** Needs the Appearance Agent: appearance
  numbers per AOR, the seize by a `PUBLISH` of a `trying` dialog and its refusal,
  `Alert-Info ;appearance=N` on the INVITE forked to the sharing UAs,
  `<joined-dialog>` / `<exclusive>`. Built on this plan's package and module; no
  known terminal on this node asks for it.
- **Forked branches as separate early dialogs.** A parallel fork to two devices of
  one AOR is one dialog process here, and is reported as one `early` dialog; RFC
  4235 would list two. The ACD does not need the difference.
- **`include-session-description`** and the SDP in the document.
- **A UA publishing its own dialog state** (RFC 3903 on the `dialog` package).
  The stamp answers the question for calls that cross this node; a call that does
  not, does not exist here.
- **The registrar on `report/4`** — see mcu-presence-plan.md MP1.
