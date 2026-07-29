# Release 1.1.0

2026-07-29 — 85 commits since 1.0.0 (2026-07-19). The repo is now a 4-app Mix
umbrella: `elixip2` (shared SIP stack), `elixipp` (test tool), `kelixip` (server),
`kelix_modules` (loadable modules).

## Framework changes

- added an OPTIONS dialog handling in ConfigRegistry: a `SIP.Session.Options`
  An out-of-dialog OPTIONS is answered before any dialog is created (RFC 3261
  §11.2), through the new `{:answered, code, reason, fields}` reply shape
- centralised the REGISTER lifetime rule (§10.2.4) in `SIP.Msg.Ops`:
  `requested_expires/2`, `contact_lifetimes/2`, `unregister?/2` & friends. 
- SIP.Session.Registrar: one refresh mechanism: the session layer refreshes at half the *granted*  lifetime, the dialog layer keeps only the `:registerexpire` safety net
- keepalive ownership is explicit (`keepalive_owner` on the dialog): exactly one
  OPTIONS sender per dialog, the dialog's or the scenario's
- bindings can be keyed on `+sip.instance` / `reg-id` (RFC 5626), so a device  reaching us from a new address replaces its binding instead of adding one
- Transport Selector: send-over-flow: short-circuit + `Contact.flow_module`
- Nonce facility: stateless HMAC (`SIP.Auth.Secret` + `SIP.Auth.Nonce`); migrated from a stateful nonce handler in Dialog do a stateless one. `SIP.Auth` supports `qop=auth` (additive, RFC 2069 fallback kept)
- per-listener options on the TCP / TLS / WSS listeners
- per-instance media override in `SIP.Session.Media`
- replies are instrumented in `SIP.Session`, not in the dialog layer

## Framework corrections

- proper handling of rebinding REGISTER that contains both unregistration and registration contact.
- an in-dialog request whose dialog is gone is answered 481, not "403 Denied" via  a `function_clause` crash — what a client saw when its registration lapsed while  it kept sending keepalives. 
- An initial request without registed module handles gets 501
- `SIP.Uri`: a one-character user now part parses e.g. `sip:1@host`
- a bracketed URI no longer loses its URI parameters
- both URI forms agree on `proto`;
- a synthesized `transport` parameter is emitted lower-case (§19.1.1)
- the digest challenge defaults to MD5, which a UAC holding one derived HA1 can
  answer — the hardcoded SHA256 produced an unavoidable, silent 403
- registrar: a rebinding REGISTER is not an un-registration; 
- a REGISTER is never left unanswered; `ha1b` and wildcard Contact supported; 
- the raw `To` header accepted 
- a connectionless binding  outlives the dialog that created it;
- a too-brief lifetime is anwered with 423, not a crash
- the dialog keepalive no longer advertises methods as `Supported` option tags
- a TLS/WSS *client* no longer requires a certificate: the hardcoded
  `certs/certificate.pem` / `private_key.pem` paths are gone
- `decimal` 3.1.1 clears EEF-CVE-2026-32686
- test infrastructure: the UDP mockup no longer dies on an inbound method it has
  no canned scenario for, and the suite binds 5070 (`ELIXIP_TEST_UDP_PORT`)

## Domain Specific language changes

- removed domain registration for scenarios
- a `sub_fsm` path is resolved next to the scenario that declares it (`include`
  semantics), not against the current directory
- `config uses_modules: [:registrar, :auth_db]` — a script declares the kelixip
  modules it calls, checked against the module registry at load time
- `config options_keepalive: :scenario` — the scenario owns its OPTIONS
  keepalives (default: the dialog layer does)

## elixipp testing tool changes

- doc: ELIXIPP.md rewritten for the tester — quickstart, reading the outcome,
  server mode, testing kelixip with elixipp, troubleshooting; the documented
  defaults now match the code and every `scenarios/…` path resolves
- `--tls-cert` / `--tls-key` (or `ELIXIPP_TLS_CERT` / `ELIXIPP_TLS_KEY`): TLS and
  WSS were unreachable from the escript, which cannot write the application env
  the transports read
- server (UAS) mode: `--config` credentials reach the instances, `--max-run 0`
  means no limit, `--limit` defaults to 50 (was 1, so a registrar 503-ed the
  second phone), an all-down listener set aborts with exit 2 and says why, `q`
  always terminates, and the 503 (quota) / 604 (unserved domain) rejections
  appear in the summary
- one log file per run, not two

## kelixip

This is the first release of kelixip

- registrar function only: REGISTER (with digest auth against a kamailio subscriber DB)
  and OPTIONS. No call (INVITE) function yet 
- configuration and dispatch: `config.toml` + `domains.toml` 
- Asterisk-style dial plan, domain → function → script routing
- Loadable server modules
- first version of REST API
- Prometheus observability with `/metrics` + `/health`, dispatch and registrar events
- kelictl: command line based 
- graceful stop
- packaging: RPM and .deb packages

## kelixip modules

### auth_db

New module handling SIP authentication based on a subscriber kamailio table in mysql DB

### registrar

New module that stores contacts. Per domain location store and NAT/flow connection handling.
