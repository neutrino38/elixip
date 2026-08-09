# B2BUA primitives — DSL extension (design)

A B2BUA (back-to-back user agent) capability is essential for what comes next:
it unlocks useful functions for the `borderline` and `kelixip` products. The
goal of this document is a **formalism that fits the existing DSL** — a B2BUA
is written as a plain scenario FSM, with two call legs feeding events into the
same `on_events` mailbox.

Guiding principles (unchanged from the first draft):

- a macro creates a **second dialog** attached to the running scenario;
- the scenario then owns two call legs: the **inbound** leg (the dialog that
  spawned the UAS instance) and the **outbound** leg (the dialog it created).
  Both legs exchange SIP events with the scenario process;
- the scenario can tell at a glance which leg an event came from;
- unlike kamailio's `t_relay()` or Asterisk's `Dial()`, the scenario itself
  drives the relaying of requests and responses between the legs. The
  framework provides the primitives (rewriting, correlation, teardown); the
  scenario provides the **policy** (what to relay, when, and what to answer
  locally).

This is **not** a kelixip module: it is part of the shared library
(`apps/elixip2`), usable from `elixipp` and from kelixip scripts alike.

## 1. Placement and naming

The code goes in the **framework**, next to the other session mixins
(`apps/elixip2/lib/framework/SIPSessionB2bua.ex`), because it is exactly a
session-layer concern: it spans two dialogs and threads its state through
`sip_ctx`, like `SIP.Session.Media` does for media handles.

Module name: **`SIP.Session.B2bua`**, for coherence with `SIP.Session.CallUAC`
/ `CallUAS` / `Media` (the first draft said `SIP.B2bua`; the shorter name is
kept for the *peer struct* namespace, see §3). `use SIP.Scenario` pulls the
mixin in, so every scenario gets the `b2bua_*` macros for free — same
mechanism as `use SIP.Session.CallUAC`.

Layer split, following the framework rule (message interpretation in exactly
one place — CLAUDE.md, Message Layer):

| Layer | What it owns |
|---|---|
| `SIP.Msg.Ops` (message) | `prepare_forwarded_request/2` — strip the hop-scoped headers off a request before it is re-sent on the other leg; `forwarded_reply_fields/1` — what to copy from a response relayed leg-to-leg |
| `SIP.DialogImpl` (dialog) | per-dialog **event tag** (§2); everything it already does: CSeq, tags, Call-ID, route set, remote target |
| `SIP.Session.B2bua` (session) | leg bookkeeping, request↔response correlation (§5), the `b2bua_*` macros, automatic teardown (§8) |
| the scenario (DSL) | the relay policy, as FSM states |

## 2. Telling the legs apart: dialog event tags

Both dialogs deliver their events to the same scenario process, with the same
tuple shapes (`{method, req, trans_pid, dialog_pid}` / `{code, resp,
trans_pid, dialog_pid}` / `{:dialog_terminated, pid, reason}`). Discriminating
on `dialog_pid` in guards is possible but unreadable; the DSL needs a literal
to pattern-match on.

**Decision: the dialog layer learns an optional `tag`.** A dialog created with
`tag: :outbound` wraps *every* message it sends to its app process:

```elixir
{:outbound, {200, resp, trans_pid, dialog_pid}}
{:outbound, {:BYE, req, trans_pid, dialog_pid}}
{:outbound, {:dialog_terminated, dialog_pid, reason}}
{:outbound, {:onnewdialog, :ok, trans_pid}}
```

- The tag wraps (nested 2-tuple) rather than flattens into the event tuple:
  every event kind — including `:dialog_terminated` and `:onnewdialog`, which
  the flat form cannot tag without changing their arity — is covered by one
  rule, and a catch-all `{:outbound, evt}` clause can relay whatever arrives.
- An untagged dialog (tag `nil`, the default) behaves exactly as today: the
  inbound leg stays untagged, so **existing scenarios are untouched**.
- Implementation: a `tag` field in `%SIP.DialogImpl{}` and one
  `send_to_app(state, msg)` helper replacing the direct `send(state.app, …)`
  calls (there are ~6 of them).
- `on_events` compile-time type inference: `{:outbound, …}` starts with an
  atom, which already infers `:sip`. The instrumentation additionally records
  the **leg** of the matched event (process-dictionary key
  `:scenario_event_leg`, mirroring `:scenario_event_type`), which is what lets
  the relay macros infer their direction (§4). `auto_store/2` learns to unwrap
  the tag; a tagged INVITE/UPDATE is stored under leg-qualified keys
  (`:last_uas_req_out`…), never in the inbound slot — `reply_invite*` keeps
  targeting the inbound leg only.

## 3. Creating the outbound leg: `b2bua_forward/3`

```elixir
b2bua_forward(req, peer, media)
```

Creates the outbound dialog and attaches it to the scenario. Rebinds
`sip_ctx` (stores the leg in the context, like the `media_*` macros).

- `req` — a request that can create a dialog (INVITE, MESSAGE, REGISTER,
  SUBSCRIBE…). Typically the inbound request just received; anything else
  fails immediately (`lasterr` set, the `goto` aborts the scenario).
- `peer` — a `%SIP.B2bua.Peer{}` (§3.1), or a plain URI string/`%SIP.Uri{}`
  as shorthand for a one-URI peer.
- `media` — the media handling mode (§7):
  - `false` — pure signaling B2BUA, SDP relayed verbatim;
  - `{:mediaserver, media_opts}` — terminate media on both legs on a Medooze
    server (relay + transcoding);
  - `{:rtpengine, opts}` — future: drive an
    [rtpengine](https://github.com/sipwise/rtpengine) for media relay.

What it does, in order:

1. `SIP.Msg.Ops.prepare_forwarded_request(req, opts)` — message layer.
   Strips everything hop- or dialog-scoped: `Via`, `Route`, `Record-Route`,
   `Path`, `Contact`, the `From`/`To` tags, and **`Call-ID`** (left `nil` so
   `start_dialog` mints a fresh one — reusing the inbound Call-ID/from-tag
   would collide with the inbound dialog in `Registry.SIPDialog`). Decrements
   `Max-Forwards` (loop protection; ≤ 0 fails with `lasterr = :too_many_hops`
   so the scenario answers 483). Keeps the body and a pass-through header
   whitelist (at least: `From`/`To` identities, `P-Asserted-Identity`,
   `Privacy`, `User-Agent` is replaced, custom `X-*` configurable).
2. Applies the peer's `ruri:` policy (§3.1): rewrites the R-URI to the
   branch target (`:peer`) or keeps it and stamps the destination fields
   only (`:keep`); then resolves (DNS SRV per the peer options, via
   `SIP.Resolver`).
3. `SIP.Dialog.start_dialog(fwd_req, timeout, :outbound, debug, tag: :outbound)`
   and consumes the tagged `{:outbound, {:onnewdialog, :ok, trans_pid}}` to
   capture the initial client transaction (needed later for CANCEL/ACK).
   It must **not** go through `SIP.Session.send_sip_request/3`: that helper
   routes through `sip_ctx.dialogpid`, which is the *inbound* leg.
4. Stores the leg under `sip_ctx.appdata[:__b2bua__]`:

```elixir
%SIP.Session.B2bua.State{
  legs: %{
    outbound: %Leg{dialogpid: pid, tag: :outbound, peer: peer,
                   initial_trans: tpid, state: :trying, media: media_mode}
  },
  # correlation map, see §5
  pending: %{}
}
```

`sip_ctx.dialogpid` keeps pointing at the inbound leg — every existing macro
(`reply_invite*`, `send_BYE`, …) keeps its meaning on the inbound side.

**V1 constraint: one single outbound leg per scenario.** A second
`b2bua_forward/3` while one leg is alive sets `lasterr =
:outbound_leg_exists`. (Note: a UAC scenario can already create a second
dialog through `send_sip_request` with a standalone method — the B2BUA leg
registry is separate bookkeeping and does not conflict with it.) Forking does
**not** require more legs — it happens *below* the leg, inside its dialog
(§3.3). Lifting the constraint to N legs (attended transfer, 3pcc) only
generalizes the `legs` map and the tag atoms (`:outbound2`, or user-supplied
`as:` names like `sub_fsm`).

### 3.1 The SIP peer

```elixir
%SIP.B2bua.Peer{
  uris: ["sip:gw1.example.com;transport=tcp", "sip:gw2.example.com"],
  use_srv: true,          # DNS SRV resolution (RFC 3263) on each target
  fork: :none,            # :none | :serial | :parallel (v1: :none)
  ruri: :peer,            # :peer (rewrite R-URI) | :keep (route-only), see below
  outbound_proxy: nil,    # per-peer proxy URI; nil -> global :proxyuri env
  trunk_pid: nil          # future: SIP trunk process holding availability state
}
```

**Where fork targets come from — the three cases.** They all converge on the
branch mechanics of §3.3, but they multiply at two different levels:

1. **One URI, SRV enabled** (`uris: [one], use_srv: true`) — the SRV
   resolution itself returns several records. These are *destinations* of the
   same URI, not different targets: the branches share the R-URI and differ
   only by `destip`/`destport` (the Via branch differs per transaction as
   always). RFC 3263 semantics apply: serial failover across priority groups,
   weighted selection within a group (`resolve_srv_multiple/2` implements
   both) — SRV multiplicity is a **failover list, always serial**, whatever
   the peer's `fork` mode.
2. **A list of URIs** (`uris: [several]`) — each URI is a branch target in
   its own right; `fork` (`:serial`/`:parallel`) governs how the branches are
   armed. With `use_srv: true`, each branch additionally carries its own
   case-1 destination list.
3. **Registrar contacts** (§3.2, `Kelix.Mod.Registrar.targets/2`) — case 2
   with the list coming from the location store: URIs pre-stamped with their
   destination/flow, ordered by q-value.

So the branch plan is two-level: an ordered list of **branches** (URI-level,
forked serially or in parallel), each with an ordered list of
**destinations** (SRV-level, always serial). This mirrors kamailio, where
branches are URI-level and SRV failover happens per branch below TM.

- `uris` — ordered target list (strings or `%SIP.Uri{}`, possibly
  pre-resolved). With `fork: :none`, only the head is used.
- `ruri` — **is the R-URI rewritten or not?** Kamailio's `$ru`/`$du`
  distinction, which the framework already embodies: a `%SIP.Uri{}` carries
  its routing (`destip`/`destport`/`destproto`/`tp_pid`) *next to* its
  textual identity, so targeting a peer does not have to change what the
  request asks for.
  - `:peer` (default) — the forwarded request's R-URI **becomes** the branch
    target URI (kamailio `lookup()` / `rewritehostport` style). Mandatory for
    case 3: a registered contact only recognizes a request whose R-URI is the
    contact it bound (RFC 3261 §16.5).
  - `:keep` — the original R-URI is preserved; the branch target only
    supplies the *destination* (stamped into the dest fields, kamailio `$du`
    style). The trunk/SBC case: the INVITE for `sip:+3312345@ourdomain` keeps
    its R-URI and is simply sent to the gateway.
  - Anything fancier (grafting the original userpart onto the peer's host,
    prefix rewriting…) is **policy**: the scenario builds the exact URI it
    wants — it has `req` in hand — and passes it in `uris`. The framework
    only offers the two SIP-meaningful behaviors.
- `fork` — implemented on the **kamailio TM model** (§3.3): the leg stays a
  single dialog; each fork target is a *branch*, i.e. one more client
  transaction inside that dialog, sharing the dialog-forming fields (Call-ID,
  from-tag, CSeq) and differing only by its Via branch and R-URI.
  - `:serial` (delivered): on a retryable final from the current branch, arm
    the next target as a new branch of the same dialog (kamailio
    failure-route style). `retry_on` is a peer option — a list of codes and/or
    ranges; the default is **any 4xx or 5xx**. Not 6xx: that is a global
    refusal (RFC 3261 §16.7), and ringing a subscriber's other phones after
    they pressed Decline is what they asked not to happen. Not 3xx either — a
    redirect names new targets, which is its own handling (P4).
  - `:parallel` (P4): send all branches at once; first 2xx/6xx wins, pending
    branches are CANCELled.
- `trunk_pid` — reserved: attaches the peer to a trunk process that will hold
  reachability state (OPTIONS pinging, blacklisting). Ignored in v1.
- `outbound_proxy` — the global `:proxyuri` application env is honored as
  today (`SIP.Resolver.resolve_and_add_dest/1`), but it is process-global:
  fine for elixipp, wrong for a kelixip server whose different peers need
  different next hops. The per-peer field takes precedence when set.

### 3.2 Use case: registrar-driven forking (location service)

The kamailio pattern `lookup("location"); t_relay()`, done as a B2BUA: an
INVITE arrives for an AOR of a domain the server owns, the location store says
the AOR registered **several contacts** (a desk phone over UDP, a softphone
over WSS…), and the call must fork to them.

Everything needed is already stored by `Kelix.Mod.Registrar`: each
`%Contact{}` binding keeps the contact URI, the NAT-corrected destination
(`received` → `destip`/`destport`/`destproto`) and the inbound registration
flow (`flow_pid`/`flow_module`, RFC 5626 — reach the device back over the
connection it registered on). Its `lookup/1` facade even stamps all of that
onto per-contact rewritten requests.

That proxy-shaped `lookup(req) → {:ok, [req]}` does not fit `b2bua_forward/3`,
which builds its own forwarded request (`prepare_forwarded_request`) and wants
**targets**, not requests. **API addition — delivered** (the `rewrite/2` helper
was factored into `target_uri/1`; `lookup/1` stays for the registrar script):

```elixir
@doc "B2BUA-shaped lookup: the AOR's live contacts as ready-to-dial URIs,
      sorted by descending q-value."
@spec targets(domain :: String.t(), aor :: String.t()) ::
        {:ok, [SIP.Uri.t()]} | :notfound | {:error, term}
def targets(domain, aor)
```

Each returned `%SIP.Uri{}` is the stored contact stamped with
`destip`/`destport`/`destproto`/`tp_pid`/`tp_module` — exactly what
`SIP.Transport.Selector` short-circuits on, so the forwarded INVITE reuses the
registration flow (NAT traversal for free) and skips DNS. Because the facade
returns plain `%SIP.Uri{}`, **the dependency direction is preserved**:
`elixip2` never references the module — the *script* (running inside kelixip,
where the module is loaded) performs the lookup and feeds the result to a
peer:

```elixir
state initial_state do
  on_events do
    {:INVITE, req, _tpid, _dlg} ->
      case Kelix.Mod.Registrar.targets(req.ruri.domain, req.ruri.userpart) do
        {:ok, uris} ->
          b2bua_reply(req, 100, "Trying")
          b2bua_forward(req, %SIP.B2bua.Peer{uris: uris, use_srv: false,
                                             fork: :serial}, false)
          goto proceeding, "forked to #{length(uris)} contact(s)"

        :notfound ->
          b2bua_reply(req, 480, "Temporarily Unavailable")
          scenario_failure("AOR has no binding")

        {:error, reason} ->
          b2bua_reply(req, 500, "Location Service Error")
          scenario_failure("registrar lookup: #{inspect(reason)}")
      end
  end
end
```

(`use_srv: false` — the targets are already resolved or carry a live flow.
The default `ruri: :peer` is the right one here, and the only valid one: the
R-URI of each branch must become the registered contact, §3.1.)

The reference script is `apps/kelixip/scripts/b2bua.exs`, tested in
`apps/kelix_modules/test/b2bua_script_test.exs` — the only app where both
halves exist.

Fork ordering follows the **q-value** of the Contact header (RFC 3261
§10.2.1.2), with kamailio/proxy semantics (RFC 3261 §16.6): parallel within a
group of equal q, serial across groups in descending q. Two consequences:

- `save/4` **preserves the `q` parameter** — confirmed: it stores the whole
  Contact `%SIP.Uri{}`, so `q` survives in `contact.params` and `targets/2`
  orders on it. Nothing had to be added to `%Contact{}`. An absent q ranks
  **top** (RFC 3261 §20.10: no stated preference is not last preference —
  otherwise the single-contact case would sort below anyone who asked for 0.3),
  and an unparsable one is read as absent rather than raising;
- phasing: **P2a (delivered)** dials the highest-q contact, which is the whole
  call for a single-contact AOR. **P2b** turns the rest of the ordered list
  into serial branches; **P4** adds parallel forking *within* each q group
  (first 2xx wins, losers CANCELled). Both use the branch mechanics of §3.3 —
  the fork never creates extra legs, so the script above does not change shape
  when they land.

When every branch fails, the B2BUA relays one final response to the caller: a
6xx ends the hunt immediately (RFC 3261 §16.7); otherwise the serial hunt
relays the **last** branch's final response (P2), upgraded to a best-response
selection when parallel groups land (P4).

One genuine simplification over a forking proxy: a proxy forwards the
branches' multiple early dialogs downstream (one 180 per to-tag) and the
caller sees them all; the B2BUA **collapses** them — every relayed 18x goes
out in its single inbound UAS dialog, with our to-tag. No downstream
early-dialog bookkeeping is imposed on the caller.

### 3.3 Forking mechanics: the kamailio TM model

How kamailio's TM module forks, and what we copy from it: **one transaction
context, N branches** (`append_branch`). Each branch is a copy of the request
differing only by its Via **branch ID** and its R-URI; the dialog-forming
elements — Call-ID, From tag, CSeq — are shared by all branches, untouched.
Serial forking (`failure_route` + `t_relay`) adds a new branch to the *same*
context. On the first 2xx (or 6xx) TM CANCELs the pending branches
(`t_cancel_branches`); when every branch fails it aggregates the finals and
forwards the best one upstream (`t_pick_branch`, RFC 3261 §16.7).

Transposed to elixip: **the outbound leg stays a single dialog; the fork
lives below it, as a branch set inside `SIP.DialogImpl`.** The transaction
layer needs no change at all — `SIP.Transac.start_uac_transaction/2` already
mints a unique Via branch per transaction, and `%SIP.DialogImpl{}` already
carries a transaction list. What forking adds is branch *orchestration* in
the dialog:

- the initial request is fixed **once** (`fix_outbound_request/3` — Call-ID,
  from-tag, CSeq shared), then sent once per target, only the
  R-URI/destination differing; one client transaction per branch, tracked in
  a branch table `%{trans_pid => %{target, totag, state}}` (the existing
  4-transaction cap exempts fork branches);
- **per-branch to-tags**: each branch's 18x/2xx carries its own to-tag, so
  the single-slot `add_totag/2` must not adopt a provisional's tag in forked
  mode (today it latches the first `< 300` tag it sees — with branches, the
  first 180's tag would block the winning 2xx's). The dialog id is completed
  only with the **winning** branch's tag; that branch's Contact/Record-Route
  become the remote target/route set, as today;
- provisionals from any branch are forwarded to the app unchanged — the
  B2BUA relays them inside its single inbound UAS dialog, which is exactly
  the collapsing already specified in §3.2;
- **first 2xx (or 6xx) wins**: adopt its to-tag, CANCEL every pending
  branch, surface the response to the app. Which target won is recorded on
  the leg (readable by the scenario for accounting);
- **the late-2xx race** (a loser answers 200 after — or crossing — our
  CANCEL): the dialog ACKs then BYEs that 2xx, building both from the
  response's own tags/Contact/Record-Route. A proxy like kamailio cannot do
  this (the caller's UAC does it, RFC 3261 §16.7); a B2BUA must, and it
  stays invisible to the scenario;
- **all branches fail** → surface one aggregated final response, kamailio
  `t_pick_branch` style: a 6xx immediately, otherwise the §16.7 preference
  order (serial mode degenerates to "the last branch's final", since earlier
  failures triggered the next branch instead of being surfaced);
- serial mode is the same machinery armed lazily: next branch on failure,
  same Call-ID/from-tag/CSeq, fresh transaction.

What this buys over one-dialog-per-target (the approach a first draft of
this section took): the **leg abstraction survives forking** — the FSM, the
event tag, the correlation map and the §8 teardown all see exactly one
outbound leg whatever the fork mode, and the N-leg generalization stays
motivated only by attended transfer / 3pcc. The cost is contained in
`SIP.DialogImpl`: a branch table, a forked-mode response path (the
`add_totag` rework), and the late-2xx ACK+BYE — the transaction layer is
untouched. This also settles the first draft's open question ("should
forking go in the transaction layer?"): *between* the layers — the
transaction layer is already per-branch by construction (RFC 3261 §17), and
the branch set is dialog-layer orchestration.

## 4. Relaying in-dialog requests: `b2bua_forward/1`

```elixir
b2bua_forward(req)
```

One argument: relays a request received on one leg **to the other leg**. The
direction is inferred from the event the enclosing `on_events` clause matched
(the `:scenario_event_leg` recorded by the instrumentation, §2): a request
received untagged (inbound leg) is relayed to the outbound leg, and a request
received `{:outbound, …}` is relayed to the inbound leg. Symmetric by
construction — the same FSM clause shape works in both directions.

- Regular requests (BYE, MESSAGE, INFO, UPDATE, re-INVITE, REFER, NOTIFY):
  `prepare_forwarded_request` (header purge — here the dialog layer's
  `fix_outbound_request/3` regenerates CSeq/tags/Call-ID/route set anyway,
  the purge mainly drops Via/Route and rewrites nothing dialog-owned), then
  `SIP.Dialog.new_request(other_leg_pid, req)`. The returned client
  transaction pid feeds the correlation map (§5).
- **ACK** is special-cased: an ACK received on the leg we answered 2xx on is
  translated into `SIP.Dialog.ack(other_leg_pid, invite_trans_pid)` on the
  leg that sent us the 2xx (§6 discusses the timing choice).
- **CANCEL** is special-cased: a CANCEL received while the forwarded INVITE
  is still pending becomes `SIP.Dialog.cancel(other_leg_pid,
  invite_trans_pid)`. (The inbound dialog auto-answers the CANCEL and stops —
  the scenario only has to relay and wind down; §8 covers the leg left
  behind.)
- Failure (dead leg, method not allowed, too many transactions) lands in
  `lasterr`, as every other macro.

Convenience wrappers (added as needed, all one-liners over the above):
`b2bua_send_BYE()`, `b2bua_send_UPDATE(sdp_or_ms)`, `b2bua_send_MESSAGE(body)`
— they *originate* a request on the outbound leg (not a relay), for policies
where the B2BUA acts on its own (e.g. session timer expiry, admin hangup).

## 5. Relaying responses: `b2bua_forward_reply/1` and correlation

The problem stated in the first draft: when the response to a relayed request
comes back, how do we know which request on the *other* leg it answers?

**Answer: the correlation is established at forward time and keyed by the
client transaction pid.** When `b2bua_forward/1` (or the initial
`b2bua_forward/3`) sends the forwarded request, it gets the UAC transaction
pid back (`SIP.Dialog.new_request/2` returns `{:ok, trans_pid}`; the initial
leg captures it from `:onnewdialog`). It records:

```elixir
pending[fwd_trans_pid] = %Pending{
  orig_req: req,              # the request as received on the source leg
  orig_leg: :inbound,         # which leg to answer on
  method: req.method
}
```

Every response event carries its transaction pid (`{code, resp, trans_pid,
dialog_pid}`), so:

```elixir
b2bua_forward_reply(resp)
```

looks the *current event's* transaction pid up in `pending`, and replies on
the recorded leg: `SIP.Dialog.reply(orig_leg_pid, orig_req, resp.response,
reason, SIP.Msg.Ops.forwarded_reply_fields(resp))`. This reuses the existing
reply path end-to-end — the dialog layer already knows how to build a
response from the original request (Via set, tags, CSeq mirroring); the
message layer decides what is copied over from the relayed response (body +
Content-Type, and a small pass-through whitelist: `Reason`, custom `X-*`).

No new dialog-layer entry point is needed: `SIP.Dialog.reply/5` on the
original request *is* "make a response of another dialog into a response of
this dialog's transaction", once the message layer has extracted the portable
fields. This resolves the draft's open question without touching the dialog
GenServer.

Bookkeeping rules:

- a **final** response (≥ 200) pops the `pending` entry; provisionals (1xx)
  leave it in place — they may be relayed several times (`goto loop`);
- a 2xx to a forwarded INVITE moves the entry to the leg's `awaiting_ack`
  slot (the client transaction must survive until we ACK it, which the dialog
  layer already guarantees);
- entries whose transaction dies unanswered (`{:transaction_timeout, …}` /
  leg termination) are dropped, and the source request is answered
  `408 Request Timeout` by the automatic teardown (§8) unless the scenario
  did it first.

## 6. Answering locally: `b2bua_reply/3..4`

```elixir
b2bua_reply(req, code, reason, upd_fields \\ [])
```

Replies to a request received on **either** leg without relaying it — the
local-policy escape hatch (405 on a method the B2BUA won't relay, 483, an
immediate 100/180, a 486 while the outbound leg is down…). Same direction
inference as `b2bua_forward/1`: the reply goes out on the leg the current
event came from. Thin wrapper over `SIP.Dialog.reply/5` + monitor note —
`reply_request` already covers the inbound leg, this one adds the
leg-awareness.

**ACK timing (decision).** Two possible disciplines when the outbound leg
answers 2xx:

1. *Immediate ACK*: ACK the outbound 200 at once, then relay the 200 inbound
   and let the caller's ACK terminate there. Simple, and safe when media is
   terminated per-leg (`:mediaserver` mode) — each leg's media is already
   established independently.
2. *Deferred ACK* (strict B2BUA): hold the outbound ACK until the caller's
   ACK arrives, relaying the end-to-end confirmation. Required for pure
   signaling mode with picky far ends, but the dialog layer retransmits
   nothing itself (the peer's 200 retransmissions are absorbed by the
   transaction), so holding the ACK for a few seconds is harmless.

The **scenario decides**, because it is one line of FSM either way: ACK-ing
immediately means calling `b2bua_forward(ack)` is unnecessary (the module did
it), deferring means the `{:ACK, …}` clause relays it. Default in the
reference scenario: **deferred** (`b2bua_forward(req)` on the ACK event) —
it is the truthful relay and exercises the correlation machinery.

## 7. Media handling modes

### `false` — pure signaling B2BUA

The SDP bodies are relayed **verbatim** in both directions (they are part of
the body `prepare_forwarded_request` / `forwarded_reply_fields` keep). Media
flows directly between the endpoints. No media server involvement; nothing to
release at teardown. This is the P1 mode.

### `{:mediaserver, media_opts}` — Medooze-terminated relay

Both legs terminate their media on the media server (transcoding, WebRTC↔RTP
gatewaying — the `borderline` case). Requires two peer connections on one
server connection, and today's `SIP.Session.Media` is **single-slot**
(`:mediapeerconnectionid`, `:mediaactionid` in appdata): the media mixin must
grow leg-qualified handles. Plan:

- appdata keys become leg-scoped for the B2BUA (`{:mediapeerconnectionid,
  leg}`), with the bare key remaining an alias for the inbound leg so every
  existing scenario/macro is untouched;
- offer/answer choreography on `b2bua_forward(invite_req, peer,
  {:mediaserver, opts})`:
  1. `set_remote_offer(PC_in, offer_A)` on the inbound connection,
  2. `get_local_offer(PC_out)` → fresh offer for the outbound leg (this is
     where transcoding/WebRTC profile conversion is applied, reusing the
     `webrtc_sdp_design.md` work),
  3. on the outbound 2xx: `set_remote_answer(PC_out, answer_B)`, then answer
     the inbound leg with the local answer of `PC_in`
     (`reply_invite_with_sdp`-equivalent, driven by `b2bua_forward_reply`);
- **open extension**: `MediaServer.Behaviour` has player/recorder/echo but no
  primitive to *bridge two peer connections*. A `bridge(conn_a, conn_b)` /
  `unbridge` callback pair must be added (Mendooze side: join the two
  endpoints, as the MCU module already does inside a conference). Until it
  exists, `:mediaserver` mode can only do media-terminated-but-not-connected
  legs, which is useless — so the bridge callback is the gating item of P3.

`media_opts` carries the usual `:webrtc` / `:media` options per leg
(`inbound: [webrtc: :yes], outbound: [webrtc: :no]` — the gateway case).

### `{:rtpengine, opts}` — future

rtpengine keeps the media path in kernel space and only rewrites SDP
(ng-protocol over UDP). Fits the same seam as `forwarded_reply_fields`: offer
and answer bodies are passed through rtpengine instead of verbatim. Out of
scope for now; the mode atom is reserved so scenarios written today don't
need to change shape later.

## 8. Lifecycle and automatic teardown

Resources tied to the scenario are released when it ends, whatever the exit
path (success, failure, abort, exception) — extending the existing
`Runner.finalize/4` chain (`shutdown_children → release_media → cleanup`):

1. **New step `release_b2bua_legs`** (before `release_media`): for every leg
   still alive —
   - forwarded INVITE still pending → `SIP.Dialog.cancel/2` it;
   - dialog established → send BYE (`SIP.Dialog.new_request/2`);
   - unanswered relayed requests in `pending` → answer their source
     `408`/`487` so no transaction is left hanging;
2. `release_media` must wait for **all** legs' `{:dialog_terminated, …}`
   (today it waits for exactly one, bounded 5 s) before releasing media —
   with per-leg media, release each leg's handles as its dialog dies;
3. `{:outbound, {:dialog_terminated, pid, reason}}` is also delivered to the
   scenario like any event, so a policy can react mid-call (e.g. outbound leg
   dies → send BYE inbound and fail the scenario).

The dialog-terminated contract (`{:dialog_terminated, dialogpid, reason}`) is
unchanged; the outbound leg's is simply tagged.

## 9. Reference scenario (target formalism)

The acceptance test for the formalism: a complete pure-signaling B2BUA in
~60 lines of FSM. This is the shape the implementation must make work:

```elixir
defmodule B2BUA.Basic do
  use SIP.Scenario

  uas :invite

  state initial_state do
    on_events do
      {:INVITE, req, _tpid, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        b2bua_forward(req, %SIP.B2bua.Peer{uris: ["sip:gw.example.com"]}, false)
        goto proceeding, "INVITE relayed"
    after
      30_000 -> scenario_failure("no INVITE")
    end
  end

  state proceeding do
    on_events do
      {:outbound, {code, resp, _tpid, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto loop, "provisional #{code}"

      {:outbound, {200, resp, _tpid, _dlg}} ->
        b2bua_forward_reply(resp)
        goto wait_ack, "200 OK relayed"

      {:outbound, {code, resp, _tpid, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)
        scenario_failure("callee answered #{code}")

      {:CANCEL, req, _tpid, _dlg} ->
        b2bua_forward(req)                    # cancels the pending INVITE
        scenario_aborted("caller cancelled")
    after
      60_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("callee never answered")
    end
  end

  state wait_ack do
    on_events do
      {:ACK, req, nil, _dlg} ->
        b2bua_forward(req)                    # deferred ACK, see §6
        goto connected, "ACK relayed"
    end
  end

  state connected do
    on_events do
      # hangup from either side: relay the BYE, answer it, wait for the far 200
      {:BYE, req, _tpid, _dlg} ->
        b2bua_forward(req)
        reply_request(req, 200, "OK")
        goto wait_far_bye_ok, "caller hung up"

      {:outbound, {:BYE, req, _tpid, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto wait_far_bye_ok, "callee hung up"

      # default relay: any other in-dialog traffic crosses over
      {:outbound, {m, req, _tpid, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        goto loop, "relayed #{m}"

      {:outbound, {code, resp, _tpid, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto loop, "relayed #{code}"

      {m, req, _tpid, _dlg} when is_atom(m) and m not in [:ACK] ->
        b2bua_forward(req)
        goto loop, "relayed #{m}"

      {code, resp, _tpid, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto loop, "relayed #{code}"
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _tpid, _dlg}} -> scenario_success("call relayed")
      {200, _resp, _tpid, _dlg}              -> scenario_success("call relayed")
    after
      5_000 -> scenario_success("BYE unanswered, closing anyway")
    end
  end
end
```

Notes on the formalism this example locks in:

- leg discrimination is **purely syntactic**: `{:outbound, {…}}` vs the bare
  tuple — no guards on pids, no helper calls in patterns;
- `b2bua_forward/1` and `b2bua_forward_reply/1` are **direction-free**: the
  same clause body relays in either direction, so symmetric states (like
  `connected`) don't duplicate logic beyond the pattern;
- the "relay everything else" policy is two catch-all clauses per direction —
  a `t_relay`-like default remains *expressible* without being imposed;
- `last_uas_req()` is a small reader macro over the stored inbound request
  (already in appdata) so the timeout clause can answer it — naming to be
  settled at implementation time.

## 10. Testing strategy

Four suites, from the bottom up. The first three are delivered with P1:

| Suite | What it pins |
|---|---|
| `msg_ops_b2bua_test.exs` | the leg-crossing rules alone, on the real-traffic samples of `test/SIP-*.txt`: what is dropped, what crosses, Max-Forwards |
| `sip_dialog_tag_test.exs` | the dialog event tag over a full dialog lifecycle, and that an untagged dialog is byte-for-byte unchanged |
| `b2bua_session_test.exs` | leg bookkeeping, correlation and teardown, by calling the backing functions directly |
| `b2bua_scenario_test.exs` | the **macro** layer: the reference scenario driven from INVITE to BYE, real outbound leg, stub inbound dialog |
| `b2bua_three_party_test.exs` | the crossing itself: a caller, the B2BUA and a callee, **each on its own transport**, nothing stubbed |
| `kelix_modules/test/b2bua_script_test.exs` | the registrar-driven script (§3.2), where both halves exist |

### Named mockup peers (delivered 2026-08-09)

A three-party test needs the two legs on two transports.
`SIP.Transport.Selector` gave every unreliable transport a single instance per
protocol, so both legs shared one mockup process and overwrote each other's
current request — an answer meant for the callee was built from the caller's
INVITE.

The fix revives a hook that already existed and was never called: a transport
module may export **`select_instance/1`** and name the instance a URI gets;
the historical rule (one per connection when reliable, one per protocol
otherwise) is the fallback. `UDPMockup` implements it on the `unittest`
parameter — `;unittest=1` stays THE shared instance every existing suite uses,
and any other value (`;unittest=callee`) names a peer of its own.

Real loopback sockets were the alternative and are more faithful, but also the
more likely to be flaky under load — which the existing `ScenarioIntegration`
media tests already are. They remain worth having later as a separate `:live`
test; the CI-facing one stays on the mockup.

This was the prerequisite for **P2b**: "first 2xx wins, CANCEL the losers,
ACK+BYE the late 2xx" cannot be tested credibly against a single shared peer.

## 11. Phasing

| Phase | Content |
|---|---|
| **P1** ✅ | message-layer purge/copy functions; dialog `tag:` option; leg + correlation state; `b2bua_forward/3` (single URI, media `false`), `b2bua_forward/1`, `b2bua_forward_reply/1`, `b2bua_reply/3..4`, `b2bua_send_BYE/0`; ACK/CANCEL special cases; automatic teardown; reference scenario `scenarios/b2bua_basic.exs` + 38 tests. **Left open:** the three-party test (§10) |
| **P2a** ✅ | registrar-driven calling (§3.2): `Kelix.Mod.Registrar.targets/2`, q ordering, `apps/kelixip/scripts/b2bua.exs`. Dials the highest-q contact — the whole call for a single-contact AOR, and no shape change when P2b lands |
| **P2b-1** ✅ | dialog-layer branches: `SIP.Dialog.fork_branch/2`, the branch table, the `add_totag` rework (a forked dialog adopts only a 2xx's tag), winner adoption + CANCEL of the losers, and the dialog surviving a branch failure so the next target can be armed |
| **P2b-2** ✅ | session-layer serial hunt: `%Peer{fork: :serial}` + the `retry_on` list, the untried-target list on the leg, `b2bua_hunting?/0`, and the kelixip script hunting an AOR's contacts in q order |
| **P2b-3** | failover across SRV priorities, per-peer `outbound_proxy`. A branch that dies **without** a response already drives the hunt: the dialog reports a client-transaction timeout to the application as a synthetic 408 (RFC 3261 §17.1.1.2, §8.1.3.1), which the default retry-on list covers |
| **P3** | `{:mediaserver, …}` mode: leg-qualified media handles, `bridge/2` callback in `MediaServer.Behaviour` + Mendooze implementation, offer/answer choreography |
| **P4** | parallel forking (branch sets in the leg dialog, §3.3: winner adoption, late-2xx ACK+BYE, best-response aggregation; q-group semantics of §3.2), `{:rtpengine, …}` mode, trunk processes (`trunk_pid`); multi-leg generalization only if attended transfer / 3pcc demands it |

## 12. Open questions

1. **Tag shape** — nested `{:outbound, {…}}` is specified here (uniform, tags
   `:dialog_terminated` too); the flat 5-tuple `{:outbound, 200, resp, tpid,
   dlg}` reads slightly better in simple clauses but cannot tag the 3-tuples.
   Confirm nested.
2. **Deferred vs immediate ACK default** (§6) — deferred specified; confirm.
3. **Pass-through header whitelists** for `prepare_forwarded_request` and
   `forwarded_reply_fields` — exact lists to be fixed during P1 against real
   traffic (kelixip will want them configurable per domain eventually).
4. **`Contact` on the inbound 2xx** — the relayed 200 must carry *our*
   Contact, not the callee's (`forwarded_reply_fields` drops it; the reply
   path adds the local contact like `reply_invite_with_sdp` does). Verify the
   placeholder-rewrite (`0.0.0.0` → bound address) also fires on this path.
5. **kelixip integration** — how a kelixip script declares the allowed peers
   (dial-plan owns the routing; the script should receive the peer from
   `Kelix.Router` rather than hardcode it — the registrar case of §3.2 is the
   exception, where the script legitimately queries the location store
   itself). Belongs to the kelixip design doc, flagged here so the `Peer`
   struct stays serializable (TOML-friendly).
6. ~~**q-value storage**~~ — **confirmed 2026-08-09.** `save/4` stores the whole
   Contact `%SIP.Uri{}`, and the parser puts the header's `q` in its params, so
   the preference survives with nothing added to `%Contact{}`. Pinned by a test.
7. ~~**`address_in_dialog/2` is asymmetric**~~ — **fixed 2026-08-09.** Its
   outbound clause restored only the To and took the From from the request as
   given, so an in-dialog request originated with a placeholder From (the shape
   `SIP.Session.CallInDialog` builds for a context with no identity of its own —
   a UAS instance, a B2BUA leg) went out with an empty From, which serializes to
   nothing and takes the whole message down. Both ends now come from the dialog,
   symmetrically with the inbound clause, as RFC 3261 §12.2.1.1 requires. The
   `%Leg{local_uri:}` workaround is gone with it.
