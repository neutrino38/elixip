# Elixip ↔ Phoenix LiveView adapter — design study

Status: study — 2026-08-15. No implementation yet.
Related: `improve-fsl-elixir.md`, the FSL-TS spec
(`finite-state-language/spec/fsl-js-ts.md`).

## Verdict first

Building LiveView-driven communication services on top of Elixip scenarios is
**viable and genuinely interesting** — but only if the adapter lives **on the
Elixir side**, as a separate optional package (`elixip_liveview`), and only
with two constraints accepted up front:

1. **The FSM bridges to LiveView; it does not run inside it.**
2. **Media never goes through LiveView.** A JS hook in the browser is
   mandatory for WebRTC — a "pure LiveView web phone" is impossible.

A LiveView adapter on the FSL-TS side was considered and **rejected**:
LiveView events (`phx-click`, form events…) are delivered **server-side**, to
the LiveView process's `handle_event/3`. The browser half of LiveView is a
thin DOM-diff client; a browser FSM never sees those events. An FSL-TS
"LiveView adapter" would sit on the wrong side of the wire. What remains
browser-side (the media hook) needs FSL-TS as a plain machine + ~50-line
binding, not an adapter package — see "Media plane" below.

## Why the impedance match is excellent (server-side)

- A LiveView is a BEAM process receiving messages (`handle_event` from the
  browser, `handle_info` from anywhere).
- An Elixip scenario is a BEAM process receiving messages
  (`on_events` ⇒ `receive`; one spawned process per scenario instance —
  `SIPScenarioRunner.ex`, `spawn_monitor` in `spawn_child/5` and
  `spawn_uas_instance/2`).
- Bridging the two is *literally* message passing, and the scenario side
  already has the exact pattern: the **sub-FSM protocol**
  (`{:scenario_msg, from, payload}` / `notify` / `notify_parent`, DSL.md
  §Sub-scenarios). To a scenario, a LiveView is a parent-like peer.

What this buys that no JS stack can offer:

- **No SIP in the browser.** The full Elixip stack runs server-side:
  credentials never leave the server, the SIP transport is server-grade
  (TCP/TLS), and the browser carries only UI events + one media leg.
- **Call logic survives the page.** The scenario process is not the LiveView
  process: a refresh or a network blip on the websocket does not hang up the
  call (see Lifecycle).
- **Observability for free**: the scenario Monitor feed
  (`SIP.Scenario.Monitor`) becomes a LiveView supervision dashboard with
  almost no code.

## The one architectural constraint: bridge, don't embed

The scenario runner **owns its process**: states are plain function calls and
`on_events` compiles to a blocking `receive`
(`SIPScenario.ex`, `on_events/1` ⇒ `{:receive, [], …}`). A LiveView, by
contrast, is callback-driven: `handle_event/3` must return. Embedding the FSM
in the LiveView process would require rewriting the runner in
continuation-passing / `gen_statem` style — a rearchitecture of Elixip's
heart for zero functional gain. **Ruled out.**

So: one LiveView process ⟷ one (or more) scenario process(es), talking
through messages. Exactly the sub-FSM topology.

## Proposed design — `elixip_liveview` (separate, optional)

Elixip has **no Phoenix dependency today** (checked: no `phoenix*` in
`mix.lock`) and must stay that way — same doctrine as FSL-TS's
"pure core + thin adapters". `elixip_liveview` is a separate app/package
depending on `elixip2` + `phoenix_live_view`.

### Scenario side: `use SIP.Session.LiveView`

A session mixin in the style of `SIP.Session.*` (macros operate on the
implicit `sip_ctx`, note their commands to the Monitor):

```elixir
use SIP.Session.LiveView

state in_call do
  lv_assign(call_state: :connected, peer: appdata_get(:peer))  # patch assigns
  on_events do
    {:lv, "hangup", _params}   -> send_BYE(); goto hangup_wait, "UI hangup"
    {:lv, "dtmf", %{"d" => d}} -> send_INFO(dtmf_body(d)); stay "DTMF"
    {:BYE, req, _t, _dlg}      -> reply_request(req, 200); scenario_success("BYE")
  end
end
```

- Browser events arrive as `{:lv, event_name, params}` — matched in
  `on_events` like any SIP/media event. **One event model** (the FSL law).
- `lv_assign(keyword)` — send an assigns patch to the attached LiveView.
- `lv_push(event, payload)` — reach the browser (`push_event/3`, consumed by
  a JS hook: ringtones, DOM focus, media commands).
- The current FSM state is pushed **automatically on every transition** as
  `@fsl_state` — the state name *is* the UI state (same doctrine as FSL-TS
  §7.2); templates render `<button disabled={@fsl_state != :ready}>`.
- Detached LiveView (websocket down): patches are coalesced (last-write-wins
  per key), delivered on re-attach. `lv_push` events are dropped with a log —
  they are ephemeral by nature.

### LiveView side: `use Elixip.LiveView.Bridge`

```elixir
defmodule MyAppWeb.PhoneLive do
  use MyAppWeb, :live_view
  use Elixip.LiveView.Bridge

  def mount(_params, %{"session_id" => sid}, socket) do
    {:ok, attach_scenario(socket, WebPhone.Scenario, key: sid)}
  end

  # phx-click etc. forwarded by default to the scenario as {:lv, event, params};
  # a LiveView keeps plain handle_event/3 clauses for purely-visual events —
  # its clauses win, the fallback forwards the rest.
end
```

`attach_scenario/3` spawns the scenario **or re-attaches to a live one**
found under `key` (see Lifecycle). The bridge injects the `handle_info`
clauses for `{:elixip_lv, :assigns | :state | :push_event, …}` and a
fallback `handle_event/3` that forwards to the scenario.

### Lifecycle — the actual hard part

LiveView processes die on every disconnect (refresh, tunnel change, mobile
network blip); a phone call must not. Therefore:

- Scenarios are **never linked** to the LiveView. They register under an
  application key (`Registry` — `{key, scenario_pid}`; `key` is typically the
  user session id).
- LiveView `mount` re-attaches if a scenario is alive under `key`; the
  scenario learns the new LiveView pid (`{:lv_attached, pid}`) and re-sends
  its current state + full assigns snapshot.
- On LiveView death the scenario keeps running with a **detach grace period**
  (configurable; e.g. in-call = until call end, idle = 60 s), after which the
  bridge requests cooperative shutdown — the existing
  `{:scenario_ctl, :shutdown, reason}` contract, `on_shutdown` can send the
  BYE. No new termination machinery.

### Media plane — where FSL-TS re-enters

LiveView cannot carry media. The browser needs a JS hook owning
`getUserMedia` / `RTCPeerConnection`, and that hook is itself a small
stateful machine (permissions → gathering → connected → failed) — the
textbook FSL-TS use case. The two FSLs meet here, one per side of the wire:

```
browser                              server
┌───────────────────────┐            ┌──────────────────────────────┐
│ FSL-TS machine in a   │ pushEvent  │ LiveView ⟷ Elixip scenario  │
│ phx hook: media only  │──────────▶│ (bridge)     (FSL Elixir)    │
│ (gUM, PC, ICE, SDP)   │◀──────────│ SIP + call logic + UI state  │
└───────────┬───────────┘ handleEvent└──────────────┬───────────────┘
            │  WebRTC media                         │ SIP/RTP
            ▼                                       ▼
        MCU / SFU (e.g. Mendooze) ◀────────────────── PSTN / SIP peers
```

SDP/ICE transit as ordinary LiveView events (`{:lv, "sdp_answer", …}` on the
scenario side; `lv_push("sdp_offer", …)` toward the hook). Server-side the
scenario negotiates via the media macros / B2BUA (`B2BUA.md`, WebRTC-to-SIP
gateway scenario) with media terminated on the MCU. The hook binding is a
documented recipe in the FSL-TS repo (an `examples/` entry), **not** a
package.

## What it enables

- **Web phone / softphone portals** with zero SIP in the browser.
- **Call-center consoles**: agent state machine server-side, N supervised
  browser sessions, barge-in as just another event.
- **Supervision dashboards**: Monitor feed → LiveView, live call graphs.
- **Total-conversation services**: real-time text via LiveView is natural
  (it is just events/diffs); only audio/video need the media hook.

## Honest counter-indications (when NOT to do this)

- **Keypress-latency UI**: every UI event round-trips the websocket. Fine
  for call control (~tens of ms vs. SIP timers in seconds), wrong for
  T140-style per-character rendering *from the local user* — local echo must
  stay in the hook.
- **Static or barely-stateful pages**: plain LiveView suffices; the bridge
  earns nothing.
- **No-BEAM-ops teams**: this stack demands running Elixir in production;
  for a pure-frontend team, FSL-TS + JsSIP (the finite-state-language track) is the
  right tool. The two tracks are complementary, not competing.

## Open questions

1. Scenario supervision: plain `Registry` + `DynamicSupervisor` per key, or
   reuse/extend the dispatcher (`SIPScenarioCallDispatcher.ex`)?
2. `{:lv, name, params}` — keep raw string names from the DOM, or an
   app-declared mapping to atoms (mailbox hygiene vs. atom-leak safety)?
3. Multi-view attach (several LiveViews mirroring one scenario — e.g. agent
   + supervisor): broadcast assigns via PubSub instead of a single pid?
4. Backpressure on `lv_assign` floods (a chatty scenario vs. render cost).

## Phasing

- **P0 spike (1–2 days)**: hand-rolled bridge in a sample Phoenix app — one
  UAC scenario, two buttons, `@fsl_state` badge. Validates the message
  contract; no package yet.
- **P1**: extract `elixip_liveview` (mixin + bridge + Registry/reattach +
  grace periods + tests).
- **P2**: media hook recipe with an FSL-TS machine (joint example with the
  finite-state-language repo), against Mendooze mockup.
- **P3**: Monitor → LiveView dashboard component.

Acceptance demo for P1+P2: refresh the page mid-call; the call is still up
and the UI re-syncs to the correct state.
