# Release 1.5.3

2026-09-08 — 5 commits since 1.5.2 (2026-09-06). Theme: **a node tells what it
is doing**. A supervision app clustered with kelixip now receives registrations
and domain counters as they change, and the destructive actions it drives are
traced to a person. One dependency upgrade closes two CVEs.

Reference: [kelixip_liveview.md](../design/kelixip_liveview.md) — the design of
the push mechanism and of the app that consumes it.

## Observability — what kelescope shows, it is told

[kelescope](https://github.com/neutrino38/kelescope) is the admin web console,

| New in `Kelix.Control` | What the subscriber receives |
|---|---|
| `subscribe_domain_counters/1` | `{:kelix_domain_counter, domain, :active_calls \| :registrations, count}` |
| `subscribe_registrations/2` | `{:kelix_registrations, domain, {:upsert, %{domain, aor, contacts}}}`, or `{:remove, aor}` when an AOR loses its last contact |

Each call returns the current snapshot — the shape of `domains/0` and of
`registrations/1` — then the changes arrive one by one. 

`unsubscribe_domain_counters/1` and `unsubscribe_registrations/2` stop a
subscription; so does the death of the subscribing pid.

The subscription to one domain's detail is per domain, and costs nothing for a
domain nobody watches. The counters subscription covers every domain at once:
a domain list wants all of them.

Reference: [kelixip_liveview.md](../design/kelixip_liveview.md) — the design of
the push mechanism and of the app that consumes it.

### A destructive action is traced to a name

kelescope asks for an operator name in the confirmation popup, before it sends
the request. That name is now logged by the node itself:

- `Kelix.Control.unregister/4` and `Kelix.Control.shutdown_scenario/2` — new
  arities. They call the existing verb unchanged, then log the target, the name
  and the outcome.
- the `mcu` module's `conference.create` and `conference.delete` accept an
  optional `admin` argument, logged the same way. It is not a conference field.

`kelictl` and the REST frontal stay on the untraced arities: they have no
identity to offer, and their behaviour does not change.

**This is not authentication.** `admin` is free text.

## Security — `mint` upgraded, two CVEs closed

`mint` goes from **1.9.3 to 1.10.0**.

| CVE | Severity | Problem |
|---|---|---|
| [CVE-2026-82728](https://osv.dev/vulnerability/EEF-CVE-2026-82728) | HIGH | unbounded buffering of the HTTP/1 status line and of chunk extensions — memory-exhaustion DoS |
| [CVE-2026-82729](https://osv.dev/vulnerability/EEF-CVE-2026-82729) | MEDIUM | quadratic chunk-size parsing in `Mint.HTTP1.Parse` — CPU-exhaustion DoS |

Both are in the parsing of an HTTP **response**, so the exposure is the client
side. In kelixip that is one path: `req` → `finch` → `mint`, used by the
`http_GET/3` scenario macro. A scenario calling an HTTP backend was the way in;
the backend, or whatever answered in its place, was the attacker.

`mint` is a transitive dependency: the upgrade is one line of `mix.lock`, and
`mix deps.get` is enough to pick it up.
