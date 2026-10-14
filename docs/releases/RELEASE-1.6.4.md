# Release 1.6.4

## 1.6.4-4

2026-10-12 — package revision 4 of 1.6.4. Theme: a SIP server with three
addresses and a source range, for Microsoft Teams Direct Routing.

### SIP servers

- **`tertiary_uri`**: a third URI, tried when the backup fails or is down too.
  Probed, failed over and load-shared like the other two.
- **`source_networks`**: CIDR ranges, comma-separated in kelictl. A request
  from one of them, over a transport the server's URIs name, comes from that
  server. An address a URI resolved to still names its own server first. Two
  servers of a domain may not declare overlapping ranges.
- Microsoft Teams Direct Routing is the case: `sip`, `sip2` and `sip3`
  `.pstnhub.microsoft.com` each resolve to one datacenter, and the hub sends
  from anywhere in `52.112.0.0/14` and `52.120.0.0/14`.
- `kelictl sip_servers server.list` shows the primary URI, cut at 48 characters,
  then `additional_uris` and `reachable` as `Y`/`N`; `server.show` lays the URIs
  out as a table, role, URI and state. The REST rows and kelescope keep every key
  they had, plus `uris`, and the list rows carry the two flags as booleans.
- The application-server type is named `sip-appsrv`.

### kelictl

- Two render hints a module may declare: `first:` shows, in a table column
  holding a list, the first entry's key and counts the rest; `hide:` leaves a
  field out of a detail view.

### Upgrading

- `dnf upgrade kelixip kelixip-mod-sip_servers` replaces 1.6.4-3. No
  configuration change; a `server_file` from 1.6.4-2 or -3 is read as is, its
  `sip-application` servers loading as `sip-appsrv`. The file is rewritten
  with the current name at the next change. elixipp 1.6.4-4 is the same tool
  as 1.6.4-3, rebuilt alongside.

## 1.6.4-3

2026-10-12 — package revision 3 of 1.6.4. Theme: what the registrar and the
presence collection show of what they hold.

### Registrations

- A binding keeps the REGISTER's **User-Agent**, **Call-ID** and **CSeq**: the
  software behind the contact, and the registration dialog its refreshes
  continue. `kelictl registration show`, `GET /domains/<domain>/registrations`
  and kelescope's live registrations carry them as `user_agent`, `callid` and
  `cseq`. A REGISTER without User-Agent gives `null`, and no line in the CLI.

### Presence

- A `publish` state row carries `received_time`, the instant the PUBLISH was
  accepted in epoch seconds, next to its remaining `expires`. A `registrar` or
  module row has none.

### Upgrading

- `dnf upgrade kelixip` replaces 1.6.4-2. No configuration change. elixipp
  1.6.4-3 is the same tool as 1.6.4-2, rebuilt alongside.

## 1.6.4-2

2026-10-12 — package revision 2 of 1.6.4. Theme: the SIP servers of a domain —
application servers, proxies and trunks.

### SIP servers (new module `sip_servers`)

A domain can now declare the remote hosts it exchanges calls with. See
[sip_servers.md](../kelixip/modules/sip_servers.md).

- **Three types.** `sip-appsrv` (an ACD, an IVR), `sip-proxy` (a partner
  PBX with users of its own), `sip-trunk` (an account at an operator). The type
  decides how a forwarded call is shaped: Request-URI, To, and for a trunk the
  From.
- **Declared at run time.** `kelictl sip_servers server.create|list|show|update|delete`,
  the same commands over REST, and kelescope 0.7.0. The servers are kept in
  `server_file`, never in `config.toml` or `domains.toml`. A trunk's password is
  kept only as its MD5 and SHA-256 HA1.
- **Scripts decide.** `matches_server/2` says which server a request comes
  from, `find_server/2` which one it is addressed to, `forward/3` how to send a
  call to one. Recognising a server is not trusting it: keeping its
  P-Asserted-Identity is the script's `trust_asserted_identity/1`.
- **Liveness.** Each URI is probed by OPTIONS; a call skips a URI known to be
  down instead of waiting for its timeout. A server's own OPTIONS prove it
  alive when a `[[domain.options]]` rule hands them to a script that calls
  `matches_server/2`.
- **Trunks** register their account (`register = false` for one that only
  answers challenges) and answer the operator's 401/407 on INVITE, re-INVITE,
  UPDATE, BYE and MESSAGE.
- **Proxies**: their remote AORs are probed through them and reported to
  presence, so a remote user is watched like a local one.
- **Supervision**: per server, the state of each URI, the registration, calls
  in and out, failures by response code, OPTIONS response time, and two alarms
  — a challenge for an unexpected realm, an address shared by two servers.
  kelescope shows them live in the domain screen.

### elixipp and the framework

- B2BUA: a peer's `trunk_pid` is asked `{:reachable?, uri}` before each
  target, and told each attempt's outcome (`{:call_result, target, code}`); a
  peer's `credentials` answer a 401/407 on the outbound leg.
- `trust_asserted_identity/1` records an inbound P-Asserted-Identity as the
  identity a forward asserts.
- Digest: a challenge naming `SHA-256`, the RFC 8760 spelling, is answered;
  only `SHA256` was.

### Upgrading

- `dnf upgrade kelixip` replaces 1.6.4-1. `dnf install
  kelixip-mod-sip_servers` (`apt install kelixip-mod-sip-servers`), then a
  `[module.sip_servers]` block with `server_file` in `config.toml` and a
  restart. Nothing changes for a node that does not load the module.

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
