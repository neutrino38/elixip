# Release 1.6.4

## 1.6.4-1

2026-10-08 — since 1.6.3-2 (2026-10-06). Theme: screen sharing through the
B2BUA, and security incidents for fail2ban.

### Unified Plan (several video streams, BUNDLE)

Added support for screen sharing and more generally Unified Plan: a browser
sharing its screen next to its camera is served as it offers, in a conference
(one more tile) and through the B2BUA (relayed to the other leg). A share that
stops is paused, not withdrawn, so sharing again resumes it. Tested on MCU and
B2BUA calls. See [unified-plan.md](../kelixip/unified-plan.md).

### Security incidents (fail2ban)

Added a security incident API that is called in some selected situations: a
refused credential, an unknown domain, a refused API token, a packet that is
not SIP, a failed TLS or WebSocket handshake. See
[installation.md](../kelixip/installation.md#security). It produces a specific
security log that can be processed by fail2ban or equivalent.

- **One line per incident**, `key=value` pairs in a fixed order, type first and
  source address second, written twice: to the journal as a warning, and to the
  file `[security] log_file` names (`/var/log/kelixip/security.log` in the
  packaged `config.toml`).
- **`[security] ignore`** drops incident types on arrival, for a UA whose
  messages the parser refuses: `["invalid-packet"]` keeps the other jails
  working.
- **Packaging**: the four filters and the jail example are installed under
  `/usr/share/kelixip/fail2ban/` as data, fail2ban itself being optional;
  `/etc/logrotate.d/kelixip` rotates the file weekly, without `copytruncate`,
  since the reporter keeps nothing open. See
  [running.md](../kelixip/running.md#fail2ban).
- The shipped filters are held to the lines the reporter writes by a unit
  test; the real fail2ban has not been run against them.

### Fixes

- **The SIP parser accepts what RFC 3261 §7.3 allows**: a header name in any
  case, the one-letter compact forms (`f:`, `t:`, `v:`, `l:`…), and a colon with
  no space after it. All three were refused, and the whole message with them.
  Compact forms are expanded at parse time, so the rest of the stack keeps
  seeing one name per header. Over TCP, `l: 0` is now framed instead of being
  answered 400.
- **The reference media call script carries text too.** Trix ↔ Trix through
  kelixip logged a failed T.140 channel on every call: the script asked for
  audio and video alone, so the browser's data channel section was declined
  with port 0. `:tc` on both legs is all it takes; a SIP endpoint without text
  declines the section and loses nothing.

### elixipp and the framework

- `Elixip.Security.report/1` is a no-op without a sink in the `:elixip2` app
  env: the tool reports nothing and needs nothing.
- User-Agent is `Elixipp-1.6.4` / `Kelixip/1.6.4`.

### Upgrading

- `dnf upgrade kelixip` replaces 1.6.3-2. A node that must keep its own
  `config.toml` adds `[security] log_file` to get the file fail2ban reads;
  without it the incidents reach the journal only.
