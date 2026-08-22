# fail2ban integration — design discussion

**Status: discussion, nothing implemented.** Decisions marked **OPEN** are the ones
to settle before writing code.

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

## 3. The trap: a 401 is not a failure

Every SIP UA sends its first REGISTER **without** credentials and gets a `401`.
That is the protocol working as designed. A filter that counts 401s bans every
phone on the network within a minute of a restart.

The line must therefore carry a **cause**, decided from what the request contained,
not from the response code:

| Situation | Verdict today | Countable? |
|---|---|---|
| No `Authorization` header at all | `{:requireauth, false}` → 401 | **No** — normal first contact |
| Authorization present, nonce expired | `{:requireauth, true}` → 401 stale | **No** — normal, the client replays |
| Authorization present, nonce forged/unknown realm | `{:requireauth, false}` → 401 | **Yes**, weakly — a scanner, or a client that lost sync |
| Authorization present, digest mismatch | `{:reject, 403, …}` | **Yes** — wrong password |
| Authorization present, user unknown | `{:reject, 403, …}` | **Yes, strongly** — nobody mistypes a username 5 times; this is enumeration |
| `realm` ≠ served domain | `{:reject, 403, …}` | **Yes** — a probe |

Two reason codes carry most of the value: `bad_password` and `unknown_user`. They
deserve **different jails** (5 tries vs. 1–2), which is only possible if the line
distinguishes them.

> Note the asymmetry that must be preserved: the *SIP response* stays `403 Forbidden`
> for both, so the wire leaks no user enumeration. Only the *log* distinguishes them.
> **OPEN:** are we comfortable with that distinction living in a log an operator may
> ship off-host?

## 4. Where the line is emitted from

Three candidates:

- **(a) in `Kelix.Mod.AuthDb`** — it knows the verdict. But it is a *loadable module*:
  a host without the package gets no protection, and a second backend (see
  [evolution-auth-db.md](evolution-auth-db.md)) would have to re-implement the
  logging. Also, the module does not see the transport (it gets `req`, which does
  carry the IP — so this is workable but duplicated).
- **(b) in the scenario** — worst option. Every script author must remember to log,
  and forgetting is silent.
- **(c) in the core, observing the outcome** — `Kelix.Router` / the dialog layer see
  every inbound request and every final response on it. One observer turns
  "final response 401/403/407 to an initial request" plus "what the request
  carried" into one line, for **every** script and **every** backend, present or
  future.

**Recommendation: (c)**, with the same argument that put `Kelix.Options` in the core
(design §8.3): answering a liveness ping is not a SIP *function*, and neither is
telling the infrastructure that someone is knocking. A server whose brute-force
visibility depends on which optional package is installed is a trap.

**The authentication SBB does not change this, and it is worth saying because it
looks like it should.** `Kelix.Mod.AuthDb.SBB.authenticate/1` now runs the
challenge cycle for the reference scripts and counts rejected attempts, so it is
the one place that knows "this dialog failed three times". Emitting from there is
still option (b) in disguise: a script that writes its own authentication states —
which the block deliberately keeps possible — would emit nothing, and so would
every scenario authenticating against a future non-`auth_db` backend. Its
`{:auth, :refused, …}` outcome exists to bound work, not to raise an alarm.

**OPEN:** (c) needs the verdict cause, which only the auth backend knows. Two ways:
carry it back in the rejection (`{:reject, 403, "Forbidden", reason: :bad_password}`
— a contract change on the module facade), or have the core re-derive it from the
request (it can distinguish "no Authorization" from "Authorization present", which
is the 80 % case, but not `bad_password` from `unknown_user`). The first is cleaner
and is the one to spec.

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

- the **prefix `kelixip: auth-failure`** is a contract. It is versioned with the
  filter shipped alongside, and a test asserts the emitted line matches the shipped
  regex (see §8);
- `user=` is quoted and escaped — a username is attacker-controlled text and must
  never be able to forge a second `src=` field. **OPEN:** log it at all? It is very
  useful for triage (`user="100"`, `user="admin"` = scanner) and it is personal data
  in a file that often leaves the host;
- never the nonce, the response digest, or anything from `Authorization` beyond the
  username;
- IPv6 unbracketed in `src=` (fail2ban's `<HOST>` handles both).

**OPEN:** should a *successful* authentication also be logged (`auth-ok`)? It costs
one line per registration refresh — noisy at scale — but it is what lets an operator
answer "who registered from this IP" during an incident. Suggested: off by default,
`[log] auth_success = true`.

## 6. Where the line goes

- **always** to the normal logger (stdout → journald, plus syslog when enabled). A
  jail can then use `backend = systemd` + `journalmatch`, which is the modern default;
- **optionally** to a dedicated file — `[log] security_file = "/var/log/kelixip/security.log"` —
  so `logpath` is trivial and the jail never scans gigabytes of call logs. This is the
  variant most operators will actually use. Needs logrotate config in the package;
- **OPEN:** a third variant is syslog facility `authpriv`, which rsyslog files into
  `/var/log/secure` — the file fail2ban already watches on RHEL/Alma. Tempting
  (zero config for the operator) but it splits our logs across two facilities and
  couples us to a distro convention.

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
