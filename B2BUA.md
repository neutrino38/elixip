# Back to back user agent function

## Introduction

Purpose: to forward incoming calls

A B2BUA terminates the incoming call and places a second one of its own, then
relays between the two for as long as they live. Unlike a proxy it stays a user
agent on both sides: it owns two dialogs, it can hang either of them up, and it
can put a media server in the middle.

In a scenario both dialogs are driven by **one** FSM:

- the **inbound** leg is the scenario's own dialog. Everything you already know
  keeps its meaning (`reply_invite*`, `last_uas_req()`, …) and its events arrive
  bare: `{:INVITE, req, trans, dlg}`;
- the **outbound** leg is created by `b2bua_forward/3` and its events arrive
  **tagged**: `{:outbound, {200, resp, trans, dlg}}`.

That is the whole discrimination rule, and it is syntactic — an `on_events`
clause tells the two apart by shape. The relay verbs take no direction: they act
on the *other* leg, whichever the matched event came from, so one clause says a
rule once and works in both directions.

Nothing is relayed unless the scenario says so.

We will consider three common use cases:

- a kamailio like SIP proxy scenario `direct-call.exs` where Alice calls Bob. No media relay invovled.
  Bob can have registered his SIP account on several devices.
- A customer service: Alice calls in on a short number and the scenario `customer-service.exs` calls 
  several phone number serially.
- a WebRTC to SIP gateway scenario `webrtc-gw.exs` that takes a WebRTC call from a proxy and resend this call
  to the proxy using a mediaserver to translate the bitstream.

> The DSL reference is [DSL.md](DSL.md). The design document, which answers *why*
> rather than *how to use*, is
> [docs/design/b2bua_module.md](docs/design/b2bua_module.md). Two reference
> scenarios ship with elixip and are worth reading as a pair — same call, same
> states, and the difference between the files is what a media server costs:
> [`b2bua_basic.exs`](apps/elixip2/scenarios/b2bua_basic.exs) and
> [`b2bua_media.exs`](apps/elixip2/scenarios/b2bua_media.exs).

## Main functions provided by B2BUA

`use SIP.Scenario` pulls them in — there is nothing to opt into. A B2BUA is an
incoming-call scenario, so it declares `uas(:invite)`.

Like the other DSL verbs they rebind the scenario context in place: they return
nothing, and their verdict is read from `sip_ctx.lasterr` (`:ok`, or a
`{:b2bua, …}` tuple naming what failed).

**Teardown is automatic.** However the scenario ends — success, failure, crash,
controller shutdown — an attempt still ringing is CANCELled, an established leg
is BYEd, and every relayed request still unanswered gets a final response on the
leg it came from. A scenario never unwinds its legs by hand.

### Creating the outbound leg

```elixir
b2bua_forward(req, peer, media, opts \\ [])
```

`req` is the inbound request, `peer` says where the second call goes, `media` is
`false` or `{:mediaserver, …}`. `opts`: `:timeout` (dialog lifetime in seconds),
`:useragent`.

Nothing is sent when it fails: the request cannot create a dialog, a leg already
exists, `Max-Forwards` is exhausted (`{:b2bua, :too_many_hops}` → answer `483`),
or there is no target.

A binary or a `%SIP.Uri{}` is shorthand for a one-target peer. The full form:

| Field | Default | Meaning |
|---|---|---|
| `uris` | `[]` | Ordered target list (binaries or `%SIP.Uri{}`, possibly already carrying their destination). Exclusive with `provider` |
| `use_srv` | `false` | Resolve each target through DNS SRV (RFC 3263). SRV multiplicity is a failover list, always tried in order |
| `fork` | `:none` | `:none` — one attempt, no failover; `:serial` — walk the list on a retryable refusal |
| `ruri` | `:peer` | `:peer` rewrites the forwarded R-URI to the target (mandatory to reach a registered contact); `:keep` preserves it and only *routes* to the target (trunk / gateway) |
| `retry_on` | `nil` | Which finals make a serial hunt move on: a list of codes and/or ranges. Default `400..599`; `487` never retries |
| `provider` | `nil` | `{module, server}` handing out targets one at a time instead of `uris` |
| `notify_progress` | `false` | Surface the hunt's progress as `{:outbound, …}` events |
| `outbound_proxy` | `nil` | Per-peer next hop, winning over the global `:proxyuri` |

Forking creates branches **inside** the leg's dialog, never a second leg — a hunt
over ten devices is one outbound dialog, and nothing above it notices how many
were tried. Parallel forking (ringing them all at once) is not available yet;
`fork: :serial` is the working value.

### Relaying

```elixir
b2bua_forward(req)          # a request, onto the other leg
b2bua_forward_reply(resp)   # a response, back onto the leg its request came from
b2bua_reply(req, code, reason \\ nil, upd_fields \\ [])   # answer here, relay nothing
```

`b2bua_forward/1` re-addresses the request wholesale — Call-ID, CSeq, tags, route
set, Contact — so nothing dialog-scoped from one leg reaches the other. ACK and
CANCEL are translated onto the correlated INVITE transaction rather than re-sent.

`b2bua_forward_reply/1` finds the leg through the correlation established when
the request was forwarded, and puts **our** Contact in a `2xx`/`3xx` to an INVITE.

`b2bua_reply/3..4` answers on the leg the matched event came from. The `487`
after a CANCEL is automatic; `100 Trying` is not.

```elixir
b2bua_send_BYE()   # hang the outbound leg up on our own initiative
```

### Hunting several targets

```elixir
b2bua_hunting?()          # true while the search is still walking targets
b2bua_cancel_forward()    # stop searching: CANCEL what rings, drop the rest
b2bua_try_next()          # give up on this target, ask the provider for the next
b2bua_ring_timeout()      # ms the provider asked for this target, or nil
```

A refusal from one target of a serial hunt is not the answer to the call — it is
the answer of one device. `b2bua_forward_reply/1` swallows it and tries the next
target by itself, so `b2bua_hunting?/0` is how a scenario tells "this device said
no" from "the call is over".

Relaying the caller's CANCEL and stopping the search are two different things,
and both are usually wanted: `b2bua_forward(req)` tells the *callee* to stop
ringing, `b2bua_cancel_forward()` tells the *search* to stop looking.

The last two need a `provider:` peer — with a static list there is nothing to
ask, its refusals already walk it.

### Media

The third argument of `b2bua_forward/3`:

- **`false`** — signalling relay. The SDP bodies cross verbatim and the two
  endpoints talk to each other directly. Nothing to configure, no media server.
- **`{:mediaserver, opts}`** — both legs terminate their media on the server. The
  bodies that cross are **ours** in both directions and neither side ever sees
  the other's SDP. The scenario must `media_connect()` first.

```elixir
@media {:mediaserver,
        inbound:  [webrtc: :yes, media: :audio_video],
        outbound: [webrtc: :no,  media: :audio_video],
        transcode: [audio: :avoid, video: :force]}
```

`inbound:` / `outbound:` say how each leg terminates its media — `webrtc:` takes
`:yes`, `:no`, `:if_offered` or `:no_avp`, and this is where a gateway is
expressed. `transcode:` is a policy per media: `:avoid` (default) connects the
two endpoints directly when they share a codec and transcodes only when they do
not, `:force` always transcodes, `:forbid` fails the call instead.

The bridge is **automatic**: `b2bua_forward_reply/1` builds it when it relays the
`2xx`, the first moment both SDPs are known.

```elixir
b2bua_bridge(opts \\ [])   # wire the legs together ahead of the 2xx (early media)
b2bua_unbridge()           # take the media path down without ending the call
b2bua_media_error()        # why the media plane failed, or nil
```

A `2xx` whose media cannot be bridged reaches the scenario as a `488`, so it
reads as one device refusing rather than as the call failing.
`b2bua_media_error/0` is where the reason is, since the relay that followed
succeeded and `lasterr` truthfully says `:ok`.

The media plane is call-scoped — one server connection, two endpoints — so the
server going away takes the **call** down, not one leg:

```elixir
{:ms_event, _ref, {:media_timeout, media}}  # one media went quiet
{:ms_event, _ref, :media_lost}              # every negotiated media is silent
{:ms_event, _ref, :server_disconnected}     # the media plane is gone
```

Release with `media_cleanup_ressources()` on the way out, not `media_stop()`:
only the former skips dead handles and releases both legs.

### Re-offers on an established call

```elixir
b2bua_reoffer_kind(req)     # :hold | :resume | :media_change
                            # | :address_change | :no_sdp | :no_change | :unknown
b2bua_reply_reoffer(req)    # answer it here, relay nothing
```

A re-INVITE or an UPDATE carries several different intentions. With a media
server in the middle two of them concern nobody but us: a peer that merely
**moved** (a new `c=`, a new port, an ICE restart) has changed nothing the far
end can see, because our endpoint did not move — and a session-timer refresh
carries no offer at all.

| Kind | What changed | Usual policy |
|---|---|---|
| `:hold` / `:resume` | `a=sendonly`, `a=inactive`, `c=0.0.0.0`, and back | relay |
| `:media_change` | a media added or withdrawn, a codec list narrowed, a direction changed | relay |
| `:address_change` | `c=`, a port, ICE credentials, a DTLS fingerprint | answer here |
| `:no_sdp` | no body — a session-timer refresh | answer here |
| `:no_change` | the same offer again | answer here |
| `:unknown` | nothing to compare against, or an unparseable SDP | relay |

Name what is absorbed and relay the rest — that way `:unknown` falls on the safe
side. In signalling mode all of them relay: the SDP belongs to the endpoints.

`b2bua_reply_reoffer/1` needs a media server. An offerless re-INVITE is answered
with an offer of ours, whose answer arrives in the ACK; that ACK is absorbed, so
the scenario keeps its single ACK clause. A media server that refuses the new
description leaves the call as it was and the re-offer gets a `488`.

## Scenario direct-call.exs

> Ships as [`apps/kelixip/scripts/direct-call.exs`](apps/kelixip/scripts/direct-call.exs).
> It is a kelixip script rather than an elixipp scenario: it asks the registrar
> module where the subscriber is.

Alice calls Bob; the registrar says where Bob is; the call is relayed there over
a second dialog we own. This is kamailio's `lookup("location"); t_relay()` done
as a B2BUA — and the difference is that we stay in the signalling path for the
whole call, so we can be told to hang up, and can meter.

Bob may be registered on several devices. They are **alternatives**, not a group
to ring together, and the registrar already ordered them by `q` — by which one
Bob wants tried first. So one leg, `fork: :serial`, and the hunt walks them.

```elixir
defmodule Kelix.DirectCall do
  use SIP.Scenario
  require Logger

  uas(:invite)

  # Refuse to load when the location service is absent, instead of failing on
  # the first INVITE.
  config(uses_modules: [:registrar])

  state initial_state do
    goto(wait_invite)
  end

  # The {:INVITE, …} that created this instance is already in our mailbox.
  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(place_call, "INVITE received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Where is Bob? A state with no on_events: it decides and moves on.
  state place_call do
    req = last_uas_req()

    case where_is(req, ctx_get(:domain)) do
      {:ok, peer} ->
        b2bua_forward(req, peer, false)
        goto(proceeding, "call forwarded")

      {:answer, code, reason} ->
        b2bua_reply(req, code, reason)
        scenario_success("answered #{code} locally")
    end
  end

  state proceeding do
    on_events do
      # Everything the device says goes back to Alice, collapsed into our single
      # inbound dialog.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A refusal. If Bob has another device, the hunt is already trying it.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          goto(loop, "#{code}, trying Bob's next device")
        else
          scenario_success("Bob answered #{code}")
        end

      # Alice gave up. Two different things, and both are wanted: stop the
      # search, and tell the device that is ringing.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        scenario_success("caller hung up before answer")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 500, "Outbound leg lost")
        scenario_failure("outbound leg died: #{inspect(reason)}")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("Bob never answered")
    end
  end

  # Alice's ACK is relayed rather than answered here: what Bob's device gets is
  # what Alice sent.
  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      # RFC 3261 timer H: no ACK is coming. Hang up the leg we did establish.
      32_000 ->
        b2bua_send_BYE()
        scenario_failure("no ACK from the caller")
    end
  end

  state connected do
    on_events do
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "callee hung up")

      {:dialog_terminated, _dlg, reason} ->
        scenario_success("inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        scenario_success("outbound leg ended: #{inspect(reason)}")

      # The ACK of a re-INVITE's 200 is a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else
      # in-dialog (re-INVITE, UPDATE, INFO, MESSAGE, REFER…), then the responses.
      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (callee -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (callee -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (caller -> callee)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (caller -> callee)")
    after
      14_400_000 -> scenario_failure("maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> scenario_success("call relayed and ended")
      {200, _resp, _trans, _dlg} -> scenario_success("call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> scenario_success("call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> scenario_success("call ended")
    after
      5_000 -> scenario_success("BYE unanswered, closing anyway")
    end
  end

  on_shutdown do
    # Both legs are wound down by the automatic teardown; there is nothing left
    # to do here but say why we stopped.
    scenario_aborted("B2BUA stopped gracefully")
  end

  # ── application logic ───────────────────────────────────────────────────────

  # The module decides WHERE Bob is; the scenario decides what SIP that means.
  defp where_is(req, domain) do
    aor = to_string(req.ruri.userpart)

    case Kelix.Mod.Registrar.targets(domain, aor) do
      # ready-to-dial URIs, already carrying the flow they registered over, in
      # descending q — hence use_srv: false and ruri: :peer
      {:ok, uris} ->
        {:ok, %SIP.B2bua.Peer{uris: uris, use_srv: false, ruri: :peer, fork: :parallel}}

      :notfound ->
        {:answer, 480, "Temporarily Unavailable"}

      {:error, reason} ->
        Logger.error("lookup for #{aor}@#{domain} failed: #{inspect(reason)}")
        {:answer, 500, "Registrar Unavailable"}
    end
  rescue
    # A module unloaded mid-call must not kill the instance and leave Alice with
    # nothing.
    err ->
      Logger.error("lookup raised: #{Exception.message(err)}")
      {:answer, 500, "Location Service Unavailable"}
  end
end
```

What is worth noticing:

- **`ruri: :peer` is mandatory here.** A registered contact is reached by asking
  for it by name; routing Alice's unchanged R-URI at the device would arrive
  asking for the AOR, which the device does not answer to.
- **`use_srv: false`** for the same reason: the contacts already carry the flow
  they registered over. Resolving them again would undo that.
- **`b2bua_hunting?/0` in `proceeding`** is the whole multi-device story. Without
  it, Bob's laptop answering `486 Busy` would be relayed to Alice as the answer
  of the call while the hunt kept ringing his desk phone.
- **`place_call` has no `on_events`.** A state may simply decide and `goto`;
  the lookup happens once, not on every event.
- **The `rescue`** is load-bearing. The `uses_modules` contract makes a missing
  module unlikely at load time, not impossible at call time.

## Scenario customer-service.exs

> Ships as
> [`apps/elixip2/scenarios/customer-service.exs`](apps/elixip2/scenarios/customer-service.exs).

Alice calls a short number. Behind it there is no registered device but a list of
phone numbers to try, in order, until one picks up.

The scenario is the one above with two states changed: the targets are a static
list instead of a lookup, and the ending says "nobody was reachable" rather than
"Bob refused". Everything from `wait_ack` on is the shape every B2BUA scenario
shares, elided here and written out in the shipped file.

```elixir
defmodule B2BUA.CustomerService do
  use SIP.Scenario

  uas(:invite)

  config(
    domains: :any,
    # tried in this order; the first one that answers takes the call
    agents: [
      "sip:+33140000001@trunk.example.com",
      "sip:+33140000002@trunk.example.com",
      "sip:+33612345678@trunk.example.com"
    ],
    trunk: "sip:trunk.example.com:5060"
  )

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        # A caller on a queue-like service expects to hear something.
        b2bua_reply(req, 180, "Ringing")

        peer = %SIP.B2bua.Peer{
          uris: ctx_get(:agents),
          fork: :serial,
          # 486 Busy and 480 Unavailable mean "try the next one"; 603 Decline is
          # this service refusing the call, and stops the hunt.
          retry_on: [408, 480, 486, 500..599],
          # the trunk is the next hop for every one of them
          outbound_proxy: ctx_get(:trunk),
          notify_progress: true
        }

        b2bua_forward(req, peer, false)

        if ctx_get(:lasterr) == :ok do
          goto(proceeding, "hunting the agents")
        else
          b2bua_reply(req, 500, "Server Internal Error")
          scenario_failure("cannot place the call: #{inspect(ctx_get(:lasterr))}")
        end
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state proceeding do
    on_events do
      # notify_progress: true — the hunt says which number it is on. Useful to
      # log, to meter, or to feed a supervision screen.
      {:outbound, {:serial_attempting, uri, _at}} ->
        goto(loop, "calling #{uri}")

      {:outbound, {:serial_not_reachable, uri, code, _at}} ->
        goto(loop, "#{uri} did not take it (#{inspect(code)})")

      {:outbound, {:serial_exhausted, _at}} ->
        goto(loop, "no agent left to try")

      # 18x from an agent: relayed, but Alice already heard our 180. Relaying a
      # 183 with SDP would pin the call to that agent, which the hunt has not
      # decided yet.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "an agent took the call")

      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          goto(loop, "#{code}, next agent")
        else
          # The list is exhausted: this final IS the answer of the call.
          scenario_success("no agent available (#{code})")
        end

      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        scenario_success("caller hung up while we were hunting")
    after
      # The whole hunt, not one agent — see below.
      120_000 ->
        b2bua_cancel_forward()
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("nobody answered")
    end
  end

  # wait_ack, connected, wait_far_bye_ok and on_shutdown: the states every B2BUA
  # scenario shares, as in direct-call.exs above.
end
```

What is worth noticing:

- **`retry_on` is where the business rule lives.** The default (`400..599`) walks
  the list on any refusal. Naming the codes instead is what makes `603 Decline`
  mean "this service says no" and end the hunt, while `486` merely means "this
  agent is on another call".
- **`outbound_proxy`** sends all three numbers through the trunk without touching
  their URIs. The R-URI still asks for the number; only the next hop changes.
- **`notify_progress: true`** turns the hunt from a silent mechanism into events.
  It is off by default: a scenario that did not ask should not receive framework
  bookkeeping it might relay by accident to Alice.
- **The `after` bounds the whole hunt, not one agent.** With a static list there
  is no per-target ring timeout: the hunt moves on when a target *refuses*, not
  when it merely keeps ringing. Ringing each agent for 15 s and then moving on
  needs a `provider:` peer, which hands out targets one at a time:

  ```elixir
  peer = %SIP.B2bua.Peer{provider: {MyQueue, queue_pid}, fork: :serial}
  ```

  ```elixir
  after
    b2bua_ring_timeout() || 15_000 ->
      b2bua_try_next()          # this agent did not pick up; ask for another
      goto(loop, "next agent")
  end
  ```

  The provider implements `SIP.B2bua.TargetProvider`: `next_target/3` answers
  `{:ok, uri}`, `{:ok, uri, ring_timeout: ms}`, `{:wait, ms}` (nobody free —
  Alice waits and we ask again later) or `:exhausted`; `attempt_ended/3` tells it
  how the attempt it handed out ended, which is what releases the reservation it
  made — including `:abandoned` when Alice gives up.

## Scenario webrtc-gw.exs

> Ships as [`apps/elixip2/scenarios/webrtc-gw.exs`](apps/elixip2/scenarios/webrtc-gw.exs).

A browser calls in through the proxy over WebRTC — DTLS-SRTP, ICE, `RTP/SAVPF`.
The callee is an ordinary SIP phone behind the same proxy and understands none of
that. The gateway terminates the media on both sides and lets the media server
translate between them.

Two things make this scenario different from the two above:

- `media` is `{:mediaserver, …}`, with `webrtc:` set differently on each leg.
  From there the SDP bodies that cross are **ours** in both directions: the
  browser is answered by the media server, the phone is offered by the media
  server, and the two endpoints are attached when the phone answers;
- the call now has a media plane it can lose, which is three more clauses.

The R-URI is kept and the request routed back to the proxy — the proxy decided
whom this call is for, and the gateway does not second-guess it.

```elixir
defmodule B2BUA.WebrtcGw do
  use SIP.Scenario

  uas(:invite)

  config(
    domains: :any,
    proxy: "sip:proxy.example.com:5060",
    mediaserver: %{module: :mendooze, url: "http://10.0.0.12:9090"}
  )

  # The browser leg takes WebRTC, the phone leg must not. Audio transcodes only
  # if the two do not share a codec; video is forced because a browser's VP8 and
  # a phone's H.264 never meet.
  @media {:mediaserver,
          inbound: [webrtc: :yes, media: :audio_video],
          outbound: [webrtc: :no, media: :audio_video],
          transcode: [audio: :avoid, video: :force]}

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")

        # The media server first: without one there is nothing to answer the
        # browser with, and the outbound INVITE has no body to carry.
        media_connect()

        peer = %SIP.B2bua.Peer{
          uris: [req.ruri],
          # keep what the proxy asked for; only route it back to the proxy
          ruri: :keep,
          outbound_proxy: ctx_get(:proxy)
        }

        b2bua_forward(req, peer, @media)

        if ctx_get(:lasterr) == :ok do
          goto(proceeding, "INVITE relayed")
        else
          # The offer could not be terminated (no common codec, a WebRTC offer
          # we were told not to take). That is a statement about what the caller
          # asked for, so it is a 488 — not a 500, which would blame us.
          b2bua_reply(req, 488, "Not Acceptable Here")
          scenario_failure("media setup failed: #{inspect(ctx_get(:lasterr))}")
        end
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state proceeding do
    on_events do
      # A provisional. Its SDP, if it has one, is dropped by the framework: with
      # a media server the phone's early media is a media event, not an answer
      # to relay — the browser's answer was decided when its INVITE arrived.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      # The phone answered: the framework feeds its answer to the outbound
      # endpoint, attaches the two, and puts OUR answer in the 200 the browser
      # receives. One line, and it is the same line as in direct-call.exs.
      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the phone — or a 2xx whose media could not be bridged,
      # which the framework hands over as a 488.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        case b2bua_media_error() do
          nil -> scenario_success("callee answered #{code}")
          reason -> scenario_failure("call cannot be bridged: #{inspect(reason)}")
        end

      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

      # The media plane went away while we were still ringing. There is no call
      # to hang up yet — the browser gets a 500 and the teardown CANCELs the
      # INVITE still ringing at the phone.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_reply(last_uas_req(), 500, "Media Server Unavailable")
        goto(releasing, "media server gone before answer")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        goto(releasing, "callee never answered")
    end
  end

  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      32_000 ->
        b2bua_send_BYE()
        goto(releasing, "no ACK from the caller")
    end
  end

  state connected do
    on_events do
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "callee hung up")

      # A re-offer. On a WebRTC leg this is most often an ICE restart or a new
      # candidate address — the browser moved, our endpoint did not, and telling
      # the phone would be noise at best.
      {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            goto(loop, "#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind})")
        end

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            goto(loop, "#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind})")
        end

      # One media went quiet. Worth saying, not worth hanging up for — a browser
      # that turned its camera off is still on the call.
      {:ms_event, _ref, {:media_timeout, media}} ->
        goto(loop, "#{media} went silent")

      # Every negotiated media is silent: there is nothing left to carry.
      {:ms_event, _ref, :media_lost} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media stopped flowing")

      # The media server itself is gone. With one media session per call this
      # takes the CALL down, not one leg.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media server disconnected")

      {:dialog_terminated, _dlg, reason} ->
        goto(releasing, "inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        goto(releasing, "outbound leg ended: #{inspect(reason)}")

      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (callee -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (callee -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (caller -> callee)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (caller -> callee)")
    after
      14_400_000 -> goto(releasing, "maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> goto(releasing, "call relayed and ended")
      {200, _resp, _trans, _dlg} -> goto(releasing, "call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> goto(releasing, "call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> goto(releasing, "call ended")
    after
      5_000 -> goto(releasing, "BYE unanswered, closing anyway")
    end
  end

  # Every exit path comes through here.
  state releasing do
    media_cleanup_ressources()
    scenario_success("call released")
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("controller asked to stop")
  end
end
```

What is worth noticing:

- **The scenario never touches an SDP body** and never calls a bridge primitive.
  `b2bua_forward_reply/1` builds the bridge when it relays the `200`, the one
  moment both sides are known.
- **`webrtc: :yes` / `webrtc: :no` is the gateway.** Everything else — DTLS
  fingerprints, ICE candidates, `RTP/SAVPF` versus `RTP/AVP`, rtcp-mux — follows
  from those two words.
- **`transcode: [video: :force]`** because a browser and a SIP phone rarely share
  a video codec, and `:avoid` would then have to build the chain anyway. Forcing
  it makes the cost explicit at read time instead of at call time.
- **`ruri: :keep` + `outbound_proxy`** are two orthogonal questions: *what* the
  forwarded request asks for, and *where* it is sent. A gateway sitting beside a
  proxy answers them differently — keep the target, change the hop.
- **The re-offer clauses are the only place the media mode changes what crosses.**
  In `direct-call.exs` a re-INVITE simply relays; here reading it first is what
  keeps a browser's ICE restart from waking the phone up.
- **`releasing` exists** because there is now something to release. It is reached
  from every path, including the ones where the server is already gone — which is
  why it uses `media_cleanup_ressources()` and not `media_stop()`.
