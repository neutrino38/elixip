# Release 1.6.2

Unreleased — since 1.6.1 (2026-09-27). Theme: instant messaging, and the
presence of a user with several devices.

## Instant messaging (page mode, RFC 3428)

- **`[[domain.chat]]`** rules route out-of-dialog MESSAGEs to a script, like the
  dial-plan; one instance per conversation, ended after `idle_timeout`. See
  [installation.md](../kelixip/installation.md#domainchat--page-mode-chat).
- **Reference scripts** `p2p-chat.exs` (authenticates, relays to every device of
  the recipient, stores what nobody took) and `registrar-chat.exs` (delivers the
  stored messages when a device registers).
- **New modules**, each its own package and SQL schema (MariaDB/MySQL,
  PostgreSQL): [`silo`](../kelixip/modules/silo.md), store-and-forward;
  [`conversation`](../kelixip/modules/conversation.md), conversations
  hibernated and resumed on any node. `kelictl silo|conversation show`.
- **`[database]`** in `config.toml`: SQL link defaults inherited by every SQL
  module.
- **The content of a MESSAGE is never logged**, journaled nor shown.
- **elixipp** sends and receives pages without a node: `UAC.Page`, `UAS.Page`.

## Presence

- **Composite state.** A watcher is told one document built from all the user's
  devices: the union of their tuples, plus one open tuple per registered device
  that publishes nothing, and the last activity expressed — which survives the
  device that set it. See
  [presence.md](../kelixip/modules/presence.md#the-composite-state).
- **One publication per device**, removed when its connection drops or it
  un-registers.
- **`[[domain.presence.subscribe]]` rules** route a SUBSCRIBE by user part, so a
  buddy list on the account's own domain (`sip:rls@example.com`) reaches
  `presence-rls.exs`.
- Limitation: devices relayed by a proxy over one connection count as one.

## Dependency

FSL **0.5.0** (`finite_state_language` on hex).

## Fixes

- A SUBSCRIBE refresh keeps its resource, and a buddy-list refresh without a
  body keeps its list.
- A buddy-list un-SUBSCRIBE without a body (Linphone) is no longer answered 400.
- A refused SUBSCRIBE refresh leaves the subscription notified.
- `GET /scenarios` no longer answers 500.
