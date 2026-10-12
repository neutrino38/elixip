# fail2ban-plan.md — the security incident log, and the shipped jails

**Status: phases 0 to 6 delivered 2026-10-07; phase 7 (real traffic on a node
with fail2ban) not done.** Phase 5 was proven with `packaging/build-rpm.sh` on
the Alma 9 build host itself, not in a container; the deb build was not run. The
discussion is
[integration-fail2ban.md](integration-fail2ban.md); this document is the order the
work gets built in, what each phase delivers, and what proves it. Where the
discussion leaves a point open, §3 states the choice this plan is written against.

## 1. Scope

One function the whole stack calls to say "someone is knocking", one process on a
kelixip node that turns the call into a line, and the fail2ban filters that read
those lines. Delivered together, they make a packaged node protectable by
installing the package, enabling a jail, and nothing else.

Incident types in this plan, and where each is raised:

| Type | Raised by | Reason codes |
|---|---|---|
| `auth-failure` | `Kelix.Mod.AuthDb` | `bad_password`, `unknown_user`, `bad_realm` |
| `invalid-domain` | `Kelix.Router` | `unknown_domain`, `no_domain` |
| `invalid-packet` | `SIP.Transport.*` | `unparsable`, `too_large`, `bad_frame`, `garbage` |
| `transport-error` | the TLS and WSS listeners | `tls_handshake`, `ws_upgrade` |
| `api-auth` | `Kelix.ControlAPI.Auth` | `missing_token`, `invalid_token`, `no_client_cert` |

Also in this plan, because `invalid-packet` is only honest once it is done: the
parser accepts what RFC 3261 allows and it refuses today (§3, phase 0). And a
`[security] ignore` list lets an operator switch a type off without losing the
others.

Not in this plan, each for a reason given in §3: `api-error`, `unusual-traffic`,
an inactivity timeout on TCP/TLS, forwarded-address handling behind a reverse
proxy, and the in-process ACL (discussion §7, phase 2).

## 2. The starting point

Every fact below is read from the tree on 2026-10-07.

- **The source address is in scope at every raising point.** All inbound traffic
  on the four transports goes through
  `SIP.Transport.ImplHelpers.process_incoming_message/7`
  (`apps/elixip2/lib/framework/SIPTransport.ex:479`), whose last two arguments are
  the peer's address and port. A request that reaches the router or a module
  carries it on its R-URI (`destip`, `destport`, `tp_module`, stamped at
  `SIPTransport.ex:580-595`), and `SIP.Msg.Ops.source_flow/1`
  (`SIPMsgOps.ex:1358`) reads it back as `{"UDP", ip, port}`. A control-API
  request has `conn.remote_ip`.
- **No security-relevant line carries it today.** `Kelix.Mod.AuthDb.reject/3`
  (`auth_db.ex:622-629`) is the single funnel of every 403 and logs
  `INVITE refused (bad_password): digest mismatch for "alice"@example.com` — cause
  named, source absent. `Kelix.Router.log_reject/2` (`router.ex:643-648`) logs
  the rejected R-URI at `info`, source absent. `Kelix.ControlAPI.Auth.deny/3`
  (`control_api/auth.ex:67-72`) logs nothing at all.
- **The parse-failure path logs twice and reports nothing usable.** The parser
  callback (`SIPTransaction.ex:360-364`) has no peer; the transport's catch-all
  (`SIPTransport.ex:653-658`) has it but prints it with `ip2string/1`, which the
  WSS fallback can hand a hostname. `SIP.Transport.Depack` discards a stream that
  does not start with a SIP line silently (`SIPTransport.ex:111-114`) and refuses
  an oversized or unframeable one without the peer (`208-219`); the TCP and TLS
  callbacks that receive `:too_large` / `:bad_frame` do have it.
- **Keep-alives and STUN never reach the parser.** `SIPMsg.keepalive?/1` and
  `SIP.Stun.decode/1` are checked first (`SIPTransport.ex:482-509`), so neither
  can be mistaken for an invalid packet. The empty datagram is a keep-alive.
- **No inactivity timeout exists on TCP or TLS.** A connection ends on a close,
  a Depack refusal or a crash. WSS has a ping liveness check
  (`SIPTransportWSS.ex:155-191`), not an idle timer. TLS handshake and WebSocket
  upgrade failures are logged (`TLSListener 247-251`, `WSSListener 251-264`)
  without the peer.
- **The log plumbing.** `[log]` accepts exactly `target`, `facility`, `level`
  (`config.ex:459-469`); the release installs the console sink only
  (`config/runtime.exs:34`), plus `Kelix.Log.Syslog` on demand. `/var/log/kelixip`
  is created by the package and by the unit (`LogsDirectory=kelixip`, mode 0750,
  owner `kelixip`), and nothing writes there. No logrotate file is shipped.
- **How the library reaches an optional kelixip component.** A `{module, fun}` in
  the `:elixip2` app env, set by `Kelix.Config.apply_app_env/1` with a comment
  naming the reader, applied when present and a no-op when absent:
  `:sequence_output` (`SIPFSLHost.ex:525`) and `:mediaserver_selector`
  (`SIPSessionMedia.ex:316`).
- **The dev box has no fail2ban.** `fail2ban-regex` is not installed here; the
  shipped filters can only be exercised against a real fail2ban on a target host.

## 3. Decisions

### One entry point, in the library

`Elixip.Security.report/1` in `apps/elixip2/lib/framework/ElixipSecurity.ex`, taking a
`%Elixip.Security.Incident{}`. The discussion names the module `Security`; it is
placed under `Elixip.`, the library's own protocol-neutral namespace
(`Elixip.ScenarioUAS`, `Elixip.RegistrarUAS`), and not under `SIP.`: an XMPP
front will raise the same incidents one day, and a library claiming a bare
`Security` is a collision waiting for the next dependency. The struct is neutral
too — `proto` is a string, `method` a SIP method atom or a string (an HTTP verb
today, a stanza name tomorrow).

The function reaches the sink through the convention the tree already uses:
`Application.get_env(:elixip2, :security_sink)` is `{module, fun}`, applied when
present, `:ok` when absent. The alternative — a registered name the library fixes
and kelixip's process takes, as `FSL.Monitor` does — needs no configuration, but
the `{module, fun}` form is what `Kelix.Config.apply_app_env/1` already does twice,
and a test injects a sink without starting a process. The modules and the kelixip
core call the same `Elixip.Security.report/1`: one entry point, not two.

The `product` argument of the discussion's sketch is dropped. The sink knows what
product it is; the library only describes the incident.

### The struct

```elixir
%Elixip.Security.Incident{
  type: :auth_failure,          # :invalid_domain | :invalid_packet | :transport_error | :api_auth
  src: {192, 0, 2, 5},          # :inet.ip_address(), never a hostname
  port: 5060,
  proto: "UDP",                 # "UDP" | "TCP" | "TLS" | "WSS" | "HTTP" | "HTTPS"
  method: :REGISTER,            # a SIP method, or an HTTP verb as a string
  realm: "example.com",
  user: "alice",                # attacker-controlled text; quoted and escaped on output
  reason: :bad_password
}
```

Every field defaults to `nil` and a `nil` field is omitted from the line. The
discussion's sketch defaulted `srcport` to 5060 and `realm` to `"unknown"`: a
default that fabricates a value is a lie on a line whose whole purpose is
evidence. `proto` is added because the line format (discussion §5) carries it and
the sketch did not.

`String.Chars` renders the fields in a fixed order, `type` first and `src` second:

```
auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER realm=example.com user="alice" reason=bad_password
```

`user` is the only free text. It is rendered between double quotes with `"`, `\`,
and every control character escaped, so a username cannot forge a second `src=`
or terminate the line early. Everything else is an atom, an integer, an address or
a value the node configured.

### The reporter, and what it writes

`Kelix.Security.IncidentReporter` is a GenServer started by `Kelix.Application`
after `Kelix.Config` and before the listeners. It receives incidents by cast,
stamps the time on arrival, and emits each one twice:

- **to the regular logger**, as a warning tagged with the module, so it lands in
  journald and in syslog with everything else. The text is the prefix `kelixip: `
  followed by the rendered incident, so one `failregex` serves the journal and the
  file. Under `[log] level = "error"` this copy is filtered out, and the doc says
  so; the file is not;
- **to the dedicated file** named by `[security] log_file`, one line per incident:
  the ISO 8601 UTC timestamp (`DateTime.to_iso8601/1`), a space, then the same
  `kelixip: …` text. The reporter opens the file in append mode, writes every
  incident its mailbox holds at that moment, and closes it. One open per batch
  costs nothing at the rate incidents arrive, and it is what makes rotation a
  non-event: the release handles no signal, so a kept-open descriptor would force
  `copytruncate`, and the window that loses lines with it.

A file that cannot be opened is reported once at `warning` and the reporter stays
up; the journal copy continues. This is `Kelix.Log.Syslog`'s rule — logging is
never what stops the server.

Successful authentications are not reported (discussion §5).

### What is an incident, and what is not

- **`auth-failure`** is raised from `Kelix.Mod.AuthDb.reject/3`, the one place
  every 403 of the module already goes through. The discussion's earlier §4 chose
  a core observer so that no backend could forget to report; with the library
  function, a backend reports in one line from the place that knows the cause, and
  the facade contract (`{:reject, 403, "Forbidden"}`) does not change. Nothing is
  counted that the SBB does not count either (DESIGN-AUTH.md §3.3): not the first
  challenge, not `stale`, not a nonce replay, not the 500s. The `identity_check:
  :strict` 403 is not reported: it is a misconfigured phone, not a guess.
- **`invalid-domain`** is raised from `Kelix.Router.match_domain/2`, in both
  branches: a host no domain claims, and no host at all. An OPTIONS to an unknown
  host is `:core` and reports nothing — a load balancer's ping is not an incident
  (router.ex:146). A 405 for a function the domain does not enable is not one
  either.
- **`invalid-packet`** is raised from the transport layer where the peer is in
  scope: the catch-all for a message the parser refused, the `rescue` around
  dispatch, `refuse_too_large/6`, and the TCP/TLS callbacks for `:too_large` and
  `:bad_frame`. For the stream that does not begin with a SIP line, `Depack`
  gains a `:garbage` callback value next to `:ping`, so the transport can report
  what Depack discards. A 415 on an unsupported body encoding is a well-formed
  SIP message and is not reported; a response that matches no transaction is a
  stray retransmission and is not reported.
- **`transport-error`** covers the two failures the listeners already see and
  log without a peer: a TLS handshake that fails or times out, and a WebSocket
  upgrade that fails. These are what a TLS scanner leaves behind. An inactivity
  timeout on TCP/TLS, which the discussion's §3 describes, does not exist and is a
  transport feature with its own configuration; it is not built here, and the day
  it is, it reports through the same function.
- **`api-auth`** is raised from `Kelix.ControlAPI.Auth.deny/3`, with
  `conn.remote_ip` and the HTTP verb; never the path, which is attacker-controlled.
- **`api-error` is dropped.** The auth plug runs before routing, so an
  unauthenticated probe of an unknown route already raises `api-auth`. What is
  left is an authenticated operator sending a wrong argument: an error in their
  script, not an incident, and counting it would ban the operator's own tooling.

### The configuration key

A new `[security]` table, born with one key: `log_file`, a path. Absent, no file
is written. The table is where the later security keys go (`trusted_proxies`,
the ACL, the `unusual-traffic` thresholds), which is why it is not `[log]`: a
`[log]` is about the logger, and only the first of those keys is.

The packaged `config.toml` sets `/var/log/kelixip/security.log`. An existing
install upgrades with `%config(noreplace)`, so it does not get the key by itself;
the journal copy is there regardless, and the doc gives the line to add.

### The jails, and the parser they depend on

Four filters, one per jail, in `packaging/fail2ban/filter.d/`, installed under
`/usr/share/kelixip/fail2ban/filter.d/`; one commented `jail.d/kelixip.conf`
example next to them. The two sinks share the regexes: `logpath =
/var/log/kelixip/security.log` for the file, `backend = systemd` plus
`journalmatch = _SYSTEMD_UNIT=kelixip.service` for the journal.

| Jail | Matches | `maxretry` |
|---|---|---|
| `kelixip-auth` | `auth-failure … reason=bad_password` | 5 |
| `kelixip-scan` | `auth-failure … reason=(unknown_user\|bad_realm)`, `invalid-domain` | 2 |
| `kelixip-api` | `api-auth` | 3 |
| `kelixip-packet` | `invalid-packet`, `transport-error` | 20 |

All four are enabled in the example. `kelixip-packet` can only be, because
**the parser is fixed in this lot**. Today `SIPMsg.parse_header/4` is stricter
than RFC 3261 in three ways, each of which refuses a legitimate message as a
whole — and, with this plan, would report its sender as an invalid packet:

- a header name must start with an upper-case letter
  (`~r/^[A-Z][0-9 a-zA-Z\-]+$/`, SIPMsg.ex:395), where §7.3.1 makes names
  case-insensitive;
- that same pattern wants two characters or more, so every compact form of
  §7.3.3 (`v:`, `f:`, `t:`, `i:`, `m:`, `l:`, `c:`, `k:`, `e:`, `s:`, `o:`, `u:`,
  `r:`, `b:`, `a:`, `x:`) is refused;
- the line is split on `": "` (SIPMsg.ex:393), where HCOLON allows no space at
  all (`Via:SIP/2.0/UDP …`) and tabs or spaces before the colon.

Phase 0 fixes the three. The one trap in it is the fallback of
`headername_to_atomkey/1`: a name it does not know is kept **as written**
(SIPMsg.ex:88), so after the case fix `allow:` and `Allow:` would land on two
different keys unless the fallback normalises case. Callers read unknown headers
by string key, so the normalised form is what they must keep reading.

**Reporting `invalid-packet` is switchable off**: `[security] ignore =
["invalid-packet"]`, a list of incident types the reporter drops on arrival,
default empty. It is applied in the reporter and not in the transport, so the
library stays free of configuration and the switch covers every type at the
same cost as one. An operator whose UAs trip a parser case this lot did not
foresee turns the type off and keeps the other three jails.

The `<HOST>` placeholder is fail2ban's; the unit test in phase 4 stands in for
it with an IPv4-or-IPv6 literal pattern and says so in a comment. It is not a
proof that the real fail2ban matches — that is phase 7, with `fail2ban-regex` on
a host that has it.

### What the doc says, not the code

Unchanged from the discussion §9: UDP sources are spoofable, ban an IPv6 `/64`,
a NATed office is one address. Added: **do not enable the jails behind a reverse
proxy or a load balancer** that terminates the connection — every source the node
sees is the proxy's, and the first ban cuts off every user. Forwarded-address
handling is the discussion's open point and stays open.

## 4. Phases

| # | App | Delivers | Proven by |
|---|---|---|---|
| 0 | elixip2 | `SIPMsg.parse_header/4` accepts header names in any case, the compact forms of RFC 3261 §7.3.3 (expanded to their long key, so the rest of the stack sees one name), and HCOLON without a space; the unknown-name fallback is case-normalised | `sip_parser_test.exs`: `allow:` and `Allow:` parse to the same key; a REGISTER written entirely in compact forms parses to the same map as its long form; `Via:SIP/2.0/UDP` and `Via :` parse; the three samples round-trip through serialisation with long names; an invalid name is still refused |
| 1 | elixip2 | `Elixip.Security.Incident` and `Elixip.Security.report/1` (`framework/ElixipSecurity.ex`): the struct, its `String.Chars` rendering, the `:security_sink` lookup | `security_test.exs`: the field order; a `nil` field is omitted; `user` is quoted and `"`, `\`, CR, LF and a forged ` src=` inside it come out escaped; an IPv6 source renders unbracketed; `report/1` with no sink returns `:ok`; with `{mod, fun}` configured, the function receives the struct |
| 2 | elixip2 | The transport raises `invalid-packet`: the parser catch-all and the `rescue` in `SIPTransport.ex`, `refuse_too_large/6`, the TCP and TLS `:too_large` / `:bad_frame` branches, and the new `Depack` `:garbage` callback. The catch-all's `ip2string/1` becomes `peer_str/2` on the way. The TLS and WSS listeners raise `transport-error` with the peer they obtain before the handshake | `sip_depack_test.exs`: a stream starting with `GET / HTTP/1.1` yields `:garbage` once, then resynchronises nothing (the buffer is dropped, as today). A new `security_transport_test.exs` with a sink registered by the test: a garbage UDP datagram on a real socket yields one `invalid_packet` from the sender's address; an empty datagram and a STUN binding yield nothing; a datagram past the configured bound yields `too_large` (a UDP datagram cannot carry 70 kB, so the bound is lowered to 2 000 bytes for the test); over TCP, a non-SIP prefix yields `garbage`; over TLS, a client that connects and closes without a handshake yields `transport-error`. Negative: a well-formed REGISTER yields nothing |
| 3 | kelix_modules, kelixip | `Kelix.Mod.AuthDb.reject/3` takes the user and realm and reports `auth-failure` with `source_flow/1`; `Kelix.Router.match_domain/2` reports `invalid-domain`; `Kelix.ControlAPI.Auth.deny/3` reports `api-auth` | `auth_db_test.exs`: a wrong password, an unknown user and a foreign realm each yield one incident with the request's source, and the first challenge, a `stale` nonce and a lookup error yield none. `router_test.exs` "reject logs": an unknown domain yields `unknown_domain`, a To-only request with no host yields `no_domain`, an OPTIONS to an unknown host yields nothing. `control_api_test.exs` "auth middleware": a wrong bearer yields `api_auth` from `127.0.0.1`, a correct one yields nothing |
| 4 | kelixip | `Kelix.Security.IncidentReporter`; the `[security]` table with `log_file` and `ignore` in `Kelix.Config` (section allowlist included) and the `:security_sink` entry in `apply_app_env/1`; the child in `Kelix.Application`. The filters and the jail example under `packaging/fail2ban/` | `security_reporter_test.exs`: one line per incident in a scratch file, timestamp then `kelixip: `; two incidents cast back to back land in order; the file removed under the reporter is recreated on the next incident; an unwritable path warns once and the journal copy (`capture_log`) still carries the line. `config_test.exs`: `log_file` parses, defaults to `nil`, rejects a non-string; `ignore` accepts the known type names and refuses an unknown one. `security_reporter_test.exs` also: with `ignore = ["invalid-packet"]`, an `invalid_packet` incident writes nothing and an `auth_failure` still does. `fail2ban_filter_test.exs`: reads every `packaging/fail2ban/filter.d/*.conf`, extracts `failregex`, substitutes `<HOST>`, and asserts each jail matches the lines it targets, captures the real source when the username carries a forged one, and matches nothing it must not — a `bad_password` line against `kelixip-scan`, a REGISTER without credentials against anything |
| 5 | packaging | `stage.sh` stages `packaging/fail2ban` and `packaging/logrotate`; `kelixip.spec` installs the filters under `%{_datadir}/%{name}/fail2ban/` and `/etc/logrotate.d/kelixip` as `%config(noreplace)`; `build-deb.sh` mirrors both and `deb/conffiles` lists the logrotate file; `packaging/config/config.toml` sets `log_file`. The logrotate entry rotates weekly, `create 0640 kelixip kelixip`, no `copytruncate` | `packaging/build-in-container.sh`, then `rpm -qlp` on the core package lists the four filters, the jail example and the logrotate file |
| 6 | docs | `docs/kelixip/running.md` §Logs rewritten whole with the security file and a `## fail2ban` section (the jails, the four caveats, the reverse-proxy warning, the upgrade note); the `[log]` table in `installation.md`; `DESIGN-KELIXIP.md` §11; `DESIGN-AUTH.md` §3.3 and `evolution-auth-db.md` §3, which still describe a core observer and a reason code on the verdict; `integration-fail2ban.md` to *implemented* status | review |
| 7 | — | real traffic on a node with fail2ban: `fail2ban-regex` against the live file and against the journal; a sipvicious-style scan (`svmap`, `svwar`) banned by `kelixip-scan`; five wrong passwords from a Linphone banned by `kelixip-auth`; a phone registering normally through a restart never counted; the date pattern read by fail2ban without an explicit `datepattern`, else the filters get one | **not done** |

Checked to fail with the change they cover removed, as the plan's own bar: each
of the three parser relaxations (phase 0), the escaping of `user` (phase 1), the `:garbage` callback (phase 2), each of the
three raising points (phase 3), the file recreation after rotation (phase 4), and
every filter against its lines (phase 4).

Phases 0 to 4 are one branch and one delivery: the line is worthless without the
filter that reads it, and the filter is unverifiable without the line.

## 5. Out of this plan

- **Forwarded addresses and `trusted_proxies`** (discussion §7). The WSS
  listener already collects the upgrade headers into a map it discards
  (`WSSListener 343-367`), so `X-Forwarded-For` is one lookup away for WSS; it is
  a PROXY-protocol prefix for TCP and TLS, and a Plug for the control API. One
  change, three transports, its own plan.
- **The in-process ACL** (`kelictl acl ban`), discussion §7 phase 2.
- **`unusual-traffic`**: a per-source request counter with an allowlist of
  peers. The counter does not exist (`Kelix.Metrics` has no label keyed by
  address), and the allowlist is the same list `trusted_proxies`
  needs.
- **An inactivity timeout on TCP and TLS connections.** A transport feature with
  its own `[server]` key; when built, it reports `transport-error` with reason
  `idle` through phase 1's function.
- **Per-source suppression in the reporter.** A UDP garbage flood produces one
  cast per datagram. The batch write bounds the file cost, not the mailbox; if a
  measurement shows the reporter falling behind, the fix is to count repeats of
  the same `{src, type}` within a second and emit one line with the count.
