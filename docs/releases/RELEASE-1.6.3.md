# Release 1.6.3

## 1.6.3-2

2026-10-06 — package revision 2 of 1.6.3. Theme: RFC 4028 session timers, one
per call leg.

### Fixes

- **A long call is no longer cut after 90 seconds.** A B2BUA relayed the
  caller's `Session-Expires: 90;refresher=uac` to the callee as it stood. The
  callee then waited for this node to refresh its leg every 45 s, which it never
  did, and hung up at the end of the interval with `Reason: SIP ;cause=408
  ;text="Session Timer Expired"`. `Session-Expires`, `Min-SE` and the `timer`
  option tag no longer cross from one leg to the other, on the initial INVITE as
  on every relayed re-offer.

### Session timers (RFC 4028)

- **Each call dialog negotiates and keeps its own session timer**
  (`SIP.DialogImpl.SessionTimer`). The two legs of a B2BUA are timed
  independently.
- **As UAS**, every 2xx to an INVITE or an UPDATE states the negotiated
  `Session-Expires` (and `Require: timer` when the peer supports it), whoever
  composed the response. A request asking for less than `min_se` is answered
  `422` with our `Min-SE`, before the application sees it.
- **As UAC**, every INVITE or UPDATE carries `Supported: timer`, a
  `Session-Expires` and our `Min-SE`. The 2xx states the timer in force; a 2xx
  stating none turns it off. A `422` sends the request again, once, with the far
  end's `Min-SE`, without the application seeing it.
- **Refreshing.** When this node refreshes, it sends an UPDATE without a body at
  half the interval — or a re-INVITE re-offering its last SDP unchanged to a peer
  that does not accept UPDATE. Neither the request nor its answer reaches the
  application. A `491` is retried after the RFC 3261 §14.1 delay, another refusal
  well before the peer's deadline.
- **Expiry.** A peer that stops refreshing is sent a BYE with `Reason: SIP
  ;cause=408 ;text="Session Timer Expired"` shortly before the interval ends. A
  refresh answered `408` or not at all ends the call the same way; one answered
  `481` ends it without a BYE. The application receives
  `{:dialog_terminated, pid, :session_expired}`.
- **`SBB.Call.bridge/1`** returns `{:bridge, :session_expired, %{leg: :caller |
  :callee}}` (`:callee_left` with `reason: :session_expired` under
  `on_callee_hangup: :keep_caller`). The reference scripts (`direct-call*.exs`)
  and scenarios (`b2bua_basic`, `b2bua_media`, `webrtc-gw`, `customer-service`)
  handle it.

### kelixip

- **New `[session_timer]` section in `config.toml`**: `enabled` (default
  `true`), `expires` (1800), `min_se` (90, at least 90), `refresher` (`local` |
  `remote`, default `local`: this node refreshes each leg itself when the peer
  leaves it the choice). See [installation.md](../kelixip/installation.md).

### elixipp and the framework

- Session timers are **off** by default in the framework
  (`config :elixip2, :session_timer, enabled: false`): an elixipp scenario sends
  and answers exactly what it did before unless it enables them.

### Upgrading

- `dnf upgrade kelixip` replaces 1.6.3-1. A node that must keep the previous
  behaviour sets `[session_timer] enabled = false`.

## 1.6.3-1

2026-10-03 — 1 fix since 1.6.2 (2026-10-02). Theme: presence, a client's own
activity marks.

### Fixes

- **The composite person keeps the elements a client adds to its activity.** A
  client may put elements of its own namespace in `<rpid:activities>` beside the
  RPID activity: Trix says "do not disturb" as `<rpid:busy/><trix:dnd/>`, and "set
  by a rule" as `<trix:auto/>`. The composite state kept the activity and lost
  them, so a Trix watching its own presence read DND back as plain busy, took it
  for another device's choice, and replaced DND with busy on the next page load.

  Such an element is now a mark, not an activity: it is carried by the composite
  person and written back in its own namespace after the activity, at most eight
  per document. Before, it was also mis-read as an activity and re-emitted as
  `<rpid:dnd/>`.
