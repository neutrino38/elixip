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

- **Each call dialog keeps its own session timer**
  (`SIP.DialogImpl.SessionTimer`); the two legs of a B2BUA are timed
  independently. Negotiation (`Session-Expires`, `Min-SE`, `422`), refreshes
  (UPDATE without a body, or re-INVITE to a peer without UPDATE) and their
  answers are handled by the dialog, unseen by the application.
- **Expiry.** A session that is not refreshed ends with a BYE carrying `Reason:
  SIP ;cause=408 ;text="Session Timer Expired"`; the application receives
  `{:dialog_terminated, pid, :session_expired}`, and `SBB.Call.bridge/1` returns
  `{:bridge, :session_expired, %{leg: :caller | :callee}}`. The reference
  scripts and scenarios handle it.

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
