# Release 1.8.1

2026-10-24 — since 1.8.0 (2026-10-21). Theme: the addresses a SIP server is
recognised by, and security updates of the HTTP stack.

## SIP servers

- **Each URI of a server carries its resolved addresses.** `server.show`, the
  REST API and the push to kelescope give, for each entry of `uris`, an
  `addresses` list. Each address is the transport and IP a request is
  recognised by (`matches_server/2`), and says whether another server of the
  domain resolved to it too:

  ```elixir
  %{role: "primary", uri: "sip:10.0.0.5:5070;transport=tcp", state: "up",
    addresses: [%{transport: "TCP", address: "10.0.0.5", shared: false}]}
  ```

  `addresses` is `nil` before the first resolution. A shared address is
  recognised as neither server: `shared: true` shows which one the
  `shared_address` alarm is about.
- **A change of resolution is pushed.** When a server's URIs resolve to other
  addresses, its row goes to the subscribers at once.
- kelictl shows the addresses as a fourth column of the URI table, for example
  `(address=10.0.0.5 shared=false transport=TCP)`.

kelescope must be updated to display the addresses. The fields it already reads
do not change.

## Security updates

`mix hex.audit` reported advisories on three dependencies:

| Package | Before | After | Advisories | Shipped |
|---|---|---|---|---|
| `bandit` | 1.12.5 | 1.13.1 | CVE-2026-105659 (high, HTTP/2), CVE-2026-105660 (medium, HTTP/1 request-target) | yes, the REST API and the metrics endpoint |
| `plug_crypto` | 2.2.0 | 2.2.1 | CVE-2026-105963 (medium) | yes |
| `hex_core` | 0.15.0 | 0.21.1 | CVE-2026-103502, CVE-2026-105274, CVE-2026-96596 | no, dev-only tooling of the SBoM |

`thousand_island`, the socket layer under bandit, goes from 1.5.0 to 1.6.0 with
it. `sbom` 0.10 pins `hex_core ~> 0.15.0`: the root `mix.exs` forces 0.21.1, as
it already forces `protobuf`, until the OTP upgrade allows a newer `sbom`.
`mix hex.audit` now reports nothing.

elixipp carries none of these packages.

## Dependency updates

| Package | Before | After | Why |
|---|---|---|---|
| `certifi` | 2.17.0 | 2.18.0 | the root CA bundle of the outbound TLS and WSS connections |
| `req` | 0.7.4 | 0.7.5 | two fixes: a 303 redirect is now followed with GET, and AWS SigV4 signing on retries |
| `myxql` | 0.8.2 | 0.9.0 | the MySQL / MariaDB driver of `auth_db`; 0.9.0 requires `decimal ~> 3.0`, already locked at 3.2.0 |

## Continuous integration

A tag pipeline runs `mix hex.audit` beside the tests. A tag whose locked
dependencies carry a security advisory, or a retired package, produces no
package.

## Packaging

- The `%changelog` of `elixipp.spec` is sorted by date. rpm stops reading a
  changelog at the first entry out of order, so the elixipp packages carried
  only the entries down to 1.7.0. They now carry all of them.

## Upgrading

- `dnf upgrade kelixip kelixip-mod-sip_servers` from 1.8.0. No configuration
  change.
- User-Agent: `Kelixip/1.8.1`, `Elixipp-1.8.1`.
