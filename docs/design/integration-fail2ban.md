# fail2ban integration — design discussion

**Status: implemented** (2026-10-07) along [fail2ban-plan.md](fail2ban-plan.md),
which is the build order and, in its §3, settles every point marked **OPEN**
below — the sketches of §4 to §6 and §8 read as the starting point, the plan as
what was built. §7's forwarded-address handling and in-process ACL stay open.

Goal: make kelixip *trivially* protectable by fail2ban. "Trivially" means an
operator installs the package, drops in the shipped filter, enables a jail, and is
done — no regex authoring, no log-format archaeology.

## 1. What fail2ban actually needs

fail2ban does one thing: it tails a log, applies a `failregex` that must capture a
host (`<HOST>`), counts occurrences per host within `findtime`, and runs an action
(usually iptables/nftables) past `maxretry`. Everything else follows from that:

1. **one line per authentication failure**, on a file or journal unit it can tail;
2. **the source IP on that line**, in a fixed position;
3. **a stable, greppable prefix**, so the regex cannot match anything else;
4. **only real failures**, since every matched line counts toward a ban.

Point 4 is where SIP servers usually get this wrong — see §3.

## 2. What we have today

| Need | State |
|---|---|
| Source IP available | **Yes.** The transport stamps `req.ruri.destip` / `destport` / `destproto` on every inbound request — this is what `Kelix.Mod.Registrar` stores as `received` |
| Auth failure logged | **Partly.** `Kelix.Mod.AuthDb` logs one warning naming the cause — `INVITE refused (bad_password): digest mismatch for "alice"@example.com` — but **without the source IP**, which is the one field a jail needs. Not a parseable line, and only for requests that reach `auth_db` |
| A log sink an operator can point a jail at | **Partly.** `Kelix.Log.Syslog` is an RFC 3164 sink with a configurable facility (`[log] target = "syslog"`, `facility = …`); stdout is always live and captured by systemd |
| Failure counters | `Kelix.Metrics.Emit.dispatch_rejected/3` counts rejections per domain/function/code — useful for alerting, useless to fail2ban (no IP) |

| Attempts counted per dialog | **Partly.** `Kelix.Mod.AuthDb.SBB.authenticate/1` (design [DESIGN-AUTH.md](DESIGN-AUTH.md) §3) gives up after `max_attempts` rejected attempts, default 3, and answers `{:auth, :refused, %{attempts: n}}`. That bounds the work one unauthenticated dialog can extract; it is **not** a detection channel — see below |

So the work is almost entirely **"emit the line"**. That is the good news.

## 3. The event to catch

- `invalid-domain`: a request is sent to a domain that is not served by the configured kelixip
- `auth-failure`: a request is served and `auth_db` determines that there is a mismatch between the response and the expected response.
- `auth-failure`: a request is served and `auth_db` that the user is not defined the DB
- `invalid-packet`: an invalid packet that is not SIP, not STUN not a keepalive is sent. Or a SIP packet that is not parsable or a packet that is too big.
- `transport-error`: lingering TCP / TLS / Websocket without activity is closed by kelixip after a given timeout.
- `unusual-traffic`: a single IP that send a number request above a certain threshold. Requires some instrumentaion (counters) and exceptions for defined SIP peers / servers. To be done later
- `api-auth`: REST API is called with an invalid token
- `api-error`: REST API is called on an invalid endpoint or with invalid arguments

## 4. The modules, beahviors and functions

A new module Security in elixip2. My ideas below: 

Elixir
```
defmodule Security do

   def module Incident do
       defstruct srcip: nil,
                 srcport: 5060,
                 type: :unspecified,
	 	 realm: "unknown",
		 user: nil,
		 method: nil,
		 reason: nil


      defimpl String.Chars do
         def to_string(incident) do
	   # Implementation
           end
        end
      end
   end

   def report_incident(product , incident = %Security.Incident{}) do
       # Check if there is any registered process for incident reporting
       # get its PID
       GenServer.cast( pid_incident_reporter, :report_incident, incident) 
   end 
end
```

Kelixip impléments such a LOCAL process and produce a specific file in a module called
`Kelix.Security.IncidentReporter`. The file is:

/var/log/kelixip/security.log


## 5. Line format

Proposal — one line, `key=value`, source first, no free text before the keys:

```
kelixip: auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER realm=example.com user="alice" reason=bad_password
```

Which makes the filter a one-liner:

```ini
# /etc/fail2ban/filter.d/kelixip.conf
[Definition]
failregex = ^.*kelixip: auth-failure src=<HOST> .*reason=(bad_password|unknown_user|bad_realm)$
ignoreregex =
```

Rules the format must hold to:

- the **prefix `kelixip: `** is a contract. It is versioned with the
  filter shipped alongside, and a test asserts the emitted line matches the shipped
  regex (see §8);
- `user=` is quoted and escaped — a username is attacker-controlled text and must
  never be able to forge a second `src=` field. **OPEN:** log it at all? It is very
  useful for triage (`user="100"`, `user="admin"` = scanner) and it is personal data
  in a file that often leaves the host;
- never the nonce, the response digest, or anything from `Authorization` beyond the
  username;
- IPv6 unbracketed in `src=` (fail2ban's `<HOST>` handles both).

*Successful* authentication are not logged. This is only for reporting
security **incidents**.

## 6. Where the line goes

- In the regular journald as warning traces.
- To a dedicated file — `[log] security_file = "/var/log/kelixip/security.log"`

## 7. Banning: outside vs. inside

**Phase 1 — outside, and that is enough.** fail2ban's default action is
iptables/nftables; the packet then never reaches us. Nothing to build but the log
line and the shipped filter/jail. This should be the whole of the first delivery.

**Phase 2 — an internal ACL**, `kelictl acl ban <ip> [--ttl 600]` / `acl unban` /
`acl list`, consulted early (transport accept, or `Kelix.Router` before any dialog
is created). It earns its keep in two cases the firewall cannot serve:

- a container without `NET_ADMIN` (no iptables to manipulate);
- **WSS/TCP behind a reverse proxy**, where the TCP peer is the proxy: banning it at
  the firewall cuts off every user. The ban must then be on the forwarded identity,
  which only we can see.

That second case is the real argument, and it drags in its own prerequisite: we do
not read `X-Forwarded-For` / PROXY protocol today, so behind a proxy **every** source
IP we log is the proxy's. **OPEN and important:** a `trusted_proxies` list plus
forwarded-address extraction is a precondition for both phases to be honest — without
it, the shipped jail is actively dangerous behind a load balancer.

## 8. What ships in the package

This is what makes the integration "easy", more than the code does:

- `/usr/share/kelixip/fail2ban/kelixip.conf` — the filter, matching what we emit;
- `/usr/share/kelixip/fail2ban/jail.example` — two jails (`kelixip-auth`,
  maxretry 5; `kelixip-scan`, maxretry 1 on `unknown_user`), commented, with the UDP
  caveat spelled out;
- a paragraph in [administration.md](../kelixip/administration.md);
- **a test asserting the emitted line matches the shipped `failregex`.** Without it
  the two drift on the first refactor, and the failure mode is silent: the jail stops
  banning and nobody notices.

## 9. Caveats to document, not to solve

- **UDP source addresses are spoofable.** An attacker who forges a legitimate
  customer's IP can get it banned. This is inherent to IP-based banning over UDP and
  affects every SIP server; the mitigations are `ignoreip` for known-good ranges and
  not counting bare 401s (§3). Say it in the doc rather than pretend otherwise.
- **IPv6:** ban a `/64`, not a `/128` — a single host has more addresses than
  `maxretry` will ever see.
- **NAT:** one banned IP can be a whole office. Argues for a generous `maxretry` on
  `bad_password` and a strict one on `unknown_user`.

## 10. Proposed sequencing

1. reason codes in the auth verdict (contract change, small);
2. the observer + the line + `[log] security_file`;
3. filter + jail + doc + regex test in the package;
4. *(later)* forwarded-address handling and `trusted_proxies`;
5. *(later)* `kelictl acl` and the in-process ACL.

Steps 1–3 are one focused piece of work and deliver the whole stated goal.

Nothing here waits on the authentication SBB, and the SBB does not wait on this:
[DESIGN-AUTH.md](DESIGN-AUTH.md) §3 shipped without step 2, and this document's
step 1 — the reason code on the verdict — is the only place the two touch. Doing
them in either order works.
