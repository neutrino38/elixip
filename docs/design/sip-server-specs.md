# SIP Server specs

Je voudrais introduire la notion de serveur SIP dans kelixip qui ressemble un peu à un
endpoint dans PJSIP https://docs.pjsip.org/en/latest/pjsua2/using/endpoint.html
ou un peer SIP.

# Prologue: letting a script trust an inbound P-Asserted-Identity

A prerequisite, in the framework (`elixip2`), before the server entity itself.

Today an inbound PAI can never leave the node: `prepare_forwarded_request/2` strips
it on every forward and writes back only `sip_ctx.asserted_identity`
(DESIGN-AUTH.md, "P-Asserted-Identity"). The pieces to re-assert it already exist
but are not joined: `SIP.Msg.Ops.asserted_identity/1` reads the inbound PAI as a
`%SIP.Uri{}` (display name kept), and `SIP.Context.assert_identity/2` (FSL macro
`assert_identity/1`) records a `%SIP.Uri{}` as the identity to assert.

What to add:

- `SIP.Context.trust_asserted_identity(ctx, req)`: record the PAI of `req` as
  `asserted_identity`. A request with no parsable `sip:` PAI leaves the context
  unchanged: an identity proved earlier (a digest verdict) is not withdrawn by the
  absence; `assert_identity(nil)` remains the explicit withdrawal.
- The FSL macro `trust_asserted_identity(req)` next to `assert_identity/1` in
  `SIP.Context.__using__`, so a script writes
  `{_slug, _peer} -> trust_asserted_identity(req)` after `matches_server/1`.
- Tests in `msg_ops_b2bua_test.exs`: PAI taken with its display name; the forward
  then asserts it; no PAI keeps an earlier identity.
- DESIGN-AUTH.md §4.2: replace "it arrives as `[domain] trusted_peers`" with this
  verb. The trust decision is the script's, not configuration, and the guarantee
  holds: the inbound header still never crosses a leg boundary, and the only PAI
  that leaves is one recorded in the context.

The framework function must not name `Kelix.Mod.SipServers`: `elixip2` knows
nothing of kelixip.

# Prologue: letting the B2BUA skip a target known to be down

The second prerequisite in `elixip2`. `%SIP.B2bua.Peer{trunk_pid:}` is documented
"reserved, ignored in v1": a hunt tries a server the module already knows is down,
waits for its timeout, and only then moves to the backup.

What to add:

- Before trying a target of a peer whose `trunk_pid` is set, the B2BUA asks that
  process whether the target is reachable: one call, `{:reachable?, uri}`, answered
  `true` or `false`. The question is per target, not per peer: a server's primary and
  backup are up or down independently.
- `false` skips the target without sending anything: the hunt records
  `{:serial_not_reachable, uri, :down, at}` and moves to the next one, exactly as
  after a transport error. Every target down ends the hunt like an exhausted one.
- No answer (process dead, or no reply within 500 ms) counts as reachable: the
  hunt then behaves as it does today. A missing reachability source must not make
  a working server unreachable.
- Every target down before anything was sent fails the forward with `lasterr`
  `{:b2bua, :no_reachable_target}`; the script reads it like any failed forward.
- Targets handed out by a `provider` are not asked: the provider already chose
  them.
- `trunk_pid: nil` keeps the current behaviour; nothing changes for a peer built
  without it (registrar contacts, static lists, providers).
- Tests in the B2BUA suite: a target answered `false` is skipped with no INVITE
  sent; all targets down ends the hunt; a dead `trunk_pid` does not block the call.

This is a one-question contract: `elixip2` does not know what answers it. In kelixip
it is the server's process in `Kelix.Mod.SipServers`, whose state comes from OPTIONS
(and, for a trunk, its registration).

# Prologue: answering a challenge on the B2BUA's outbound leg

The third prerequisite in `elixip2`. The outbound leg cannot authenticate today: a
401/407 from the far end is an ordinary refusal to the hunt (`retry_on` defaults to
`400..599`), so the B2BUA moves to the next target or relays the challenge to the
caller, who cannot answer for the remote realm. Only `auth_invite/5` answers a
challenge, and only for a plain UAC call. A script or an SBB cannot fill the hole:
the hunt has already classified the 407 before a script sees anything.

What to add:

- A `credentials` field in `%SIP.B2bua.Peer{}`, `nil` by default (nothing changes).
  When set, it is a process answering one call, `{:authorize, code, challenge,
  method, digest_uri}`, with `{:ok, params}`: the ready `Authorization` /
  `Proxy-Authorization` parameters (the shape `SIP.Auth.build_auth_response/8`
  returns). The
  secret never reaches the framework: the HA1, its realm and its algorithm stay with
  whoever answers.
- On a 401/407 on the outbound leg of a peer with credentials, the B2BUA re-sends the
  same request once with that header: same SDP, CSeq + 1. A second challenge to the
  same request is an ordinary failure. A 401/407 is never relayed to the caller when
  the peer has credentials.
- Every request relayed onto the leg is covered, not just the initial INVITE:
  re-INVITE, UPDATE, BYE, MESSAGE. Some operators challenge BYE. The initial
  request is re-sent as a branch of the same dialog (`SIP.Dialog.fork_branch/3`,
  option `authorization:`, on that branch only); an in-dialog one as a new request,
  its digest computed over the Request-URI the dialog addresses it to
  (`SIP.Dialog.in_dialog_ruri/2`). A challenged BYE no longer leaves the dialog
  "closing", or the authenticated BYE would be refused as a second hangup.
- Not covered: a parallel rung (the dialog surfaces one response for the whole
  rung, and which branch it answers is lost), and requests the B2BUA originates
  itself rather than relays (the teardown BYE).
- Tests (`b2bua_outbound_auth_test.exs`): INVITE challenged then accepted; second
  challenge relayed as a failure; no credentials keeps today's behaviour; challenged
  UPDATE re-sent with the digest over the remote target; challenged BYE re-sent and
  the dialog ends.

In kelixip only a `sip-trunk` server sets `credentials`, answered by its process in
`Kelix.Mod.SipServers`.

# Objectifs

Pouvoir traiter les cas suivants :

- kelixip agit en tant que SIP proxy / registrar et interagit avec des serveur d'application
  SIP (ex : un ACD externe). Il peut envoyer et recevoir des appels vers / depuis ce serveur.
  Il peut tester si le serveur est debout en envoyant des OPTIONS.

- kelixip doit s'enregistrer auprès d'une infrastructure externe avec un compte identifié
  comme un trunk SIP individuel. Il peut envoyer des OPTIONS pour vérifier l'état et/ou 
  répondre à des OPTIONS envoyé par l'infra. On peut envoyer des appels, recevoir des appels
  présence et chat.

- kelixip agit en tant que serveur SIP et intéragit avec un proxy / registrar extérieur.
  par exemple, c'est un ACD qui traite des appels venant du proxy et renvoie les appels vers
  ce proxy.
  The external proxy is declared as a `sip-proxy` server: the type names what the
  remote host is, not which side holds the users.

# Nouvelles entités dans kelixip

L'entité centrale pour définir un serveur est : ̀ SIP.Server`

C'est une entité en mémoire mais persistée (comme les conférences pou le module MCU). Il est
défini par :

The source of truth is a persistence file owned by `Kelix.Mod.SipServers`, fed by
kelictl and the kelescope API, on the model of `Kelix.Mod.Mcu.Store`. Servers are
declared neither in `config.toml` nor in `domains.toml`: a server names its domain by
slug, and the node's configuration files never describe one.

- un slug qui doit être au format hostname
- une à trois SIP uri (primary_uri, backup_uri, tertiary_uri)
- source_networks : des réseaux CIDR d'où le serveur peut émettre (Microsoft Teams
  publie des plages, et ses noms ne résolvent chacun que vers un datacenter)
- use_dns_srv 
- send_keepalive
- ha_mode = failover | loadsharing
- initiate_connection = true | false # Qui initie la connexion dans le cas d'un transport connecté ?
- use_fqdn_contact = true | false # Le Contact des requêtes envoyées au serveur porte le domaine (Teams Direct Routing)

`use_dns_srv` and `backup_uri` do not overlap. SRV is failover *within* one provider
(each URI is resolved, its records become a serial list, as `%SIP.B2bua.Peer{use_srv:}`
already does); `backup_uri` is failover *across* providers. Both can be set.

`use_fqdn_contact` is for a server that identifies its peers by name: Teams Direct
Routing finds the SBC from the FQDN in the Contact, and drops the connection when it
reads an address. The name travels with the request as `%SIP.Uri{contact_host:}` on
the R-URI, and `SIP.Transport.add_contact_header/3` publishes it. It is set on the
OPTIONS and REGISTER of the server's process, and on the outbound leg of `forward/3`
through `%SIP.B2bua.Peer{contact_host:}`. The dialog copies it to the requests it
sends on that leg. The port is left out: the bound port of an outbound connection is
ephemeral, and the peer resolves a portless name to the port we listen on (RFC 3263).

Not covered: the responses to a request the server sent us, and the requests we send
in a dialog the server opened. Their Contact still names the address.

`ha_mode = loadsharing` in v1 is a round-robin: `forward/2` rotates the order of
`uris` on every call, so each call starts on the next server and still fails over to
the others. No framework change. In v2, with the session counters below, it becomes
*least used*: the server with the fewest active sessions comes first.

`max_sessions` is out of v1 and planned for v2: managing a remote server's capacity is
one of the reasons for declaring it. Counting sessions per server needs a start and
an end for every leg (answered, failed, crashed). The v2 direction:

- outbound: the `{:reachable?, uri}` question of the second prologue becomes
  `{:acquire, uri, pid}`, answered `:ok`, `:down` or `:full`; the server's process
  monitors `pid`, the B2BUA sends `{:release, uri, pid}` when the leg to that target
  ends, and a full server is skipped like a down one;
- inbound: `matches_server/1` recognises without accepting, so an explicit verb called
  by the script (`occupy(server)`) counts a call from the server.

Until then, an operator's channel limit answers 503, which moves the hunt to the next
server.


Il est typé :
- sip-appsrv 
- sip-proxy
- sip-trunk

On peut lui attacher des données d'identification
- `auth_username`
- `auth_realm`
- `auth_password` — write-only: accepted by kelictl and the API, stored as `auth_ha1`
  (one HA1 per algorithm, MD5 and SHA-256)

The password is never stored. kelictl and the API take it together with `auth_realm`
and keep only its HA1, one per algorithm (MD5 and SHA-256, computed at entry), in the
`{:ha1, algorithm, hex}` shape `Kelix.Mod.AuthDb` already uses; the answer to a
challenge picks the one the challenge names (`SIP.Auth.compute_auth_response_from_ha1`).

A HA1 is hashed, not encrypted, and it is password-equivalent for its realm: whoever
reads it can authenticate there. The persistence file is protected accordingly (mode
`0600`). What the HA1 buys is a narrower leak: one realm, never the password.

The realm must therefore be known in advance. A challenge for another realm cannot be
answered: the attempt fails and an alarm names the expected and received realms, and
the operator enters the password again with the right one.

Il a plusieurs états en mémoire

- remote IPs -> available (selons OPTIONS reçues / envoyées)
- registration_state

Il est attaché à un domaine. Ce n'est pas un objet global.

## Différences de comportements en fonction du type

| | sip-appsrv | sip-proxy | sip-trunk |
|---|---|---|---|
| R-URI to the remote host | rewritten (`:peer`) | kept (`:keep`) | rewritten (`:peer`) |
| Users belong to | our domain | either side (`ext_domain`, `ext_domain_aliases` when remote) | the operator (`ext_domain` optional) |
| Remote AORs, probing, presence | no | yes | no |
| From rewritten | no | no | yes, to the trunk account's identity |
| REGISTER, answers challenges | no | no | yes |

### sip-appsrv

Dans ce cas, le serveur agit comme un 'trusted' kamailio / un peer asterisk.
Attention, c'est le script du domaine qui va déterminer le comportement.
La ou les URI qui définisse le serveur n'ont pas de userpart

Pas de réécriture du From dans le cas d'un appel vers le sip application.

### sip-proxy

A priori, même comportement plus

The From is not rewritten on a call to a `sip-proxy`.

on peut définir des AOR attachés à ce proxy et demander à ce que ces AOR soient
sondés par des OPTIONS. Chacun des AOR se comporte alors un peu comme un AOR local.
propriété spéciale 

ext_domain = 
ext_domain_aliases = 
probe_remote_aors = true | false
probe_interval =

pour traduire modifier les requests URI et les To correctement.

Within one kelixip domain, at most one `sip-proxy` server per `ext_domain`: kelictl and
the API refuse a second one, as they refuse two servers sharing an IP.

Probing remote AORs (`probe_remote_aors`): an OPTIONS to `sip:aor@ext_domain`, sent
through the proxy, which relays it to the registered contact or answers itself. A 2xx
means reachable, anything else unreachable; that state feeds presence, which is what
makes a remote AOR behave like a local one. The load is N AORs per `probe_interval`
towards one proxy, so the probes are spread over the interval with jitter rather than
sent as a burst.

As implemented (L5): the probing is done by the server's process (`SipServers.Link`).
Each OPTIONS has the AOR as its Request-URI and To, and is sent to the first proxy URI
not known to be down, as a `ruri: :keep` peer is. One AOR per tick, a tick every
`probe_interval / N` seconds ±10 %. A 2xx is `open`; any other answer, none, or no proxy
to send it through is `closed`. The state is reported to `Kelix.Mod.Presence`
(`report/4`, source `sip_servers`) for the AOR's user part on the server's kelixip
domain: `alice@partner.net` attached to a proxy of `example.com` is the presence of
`alice` at `example.com`, the AOR a local user calls and watches. Only changes are
reported; an AOR removed, or probing turned off, has its state withdrawn, and a presence
module that restarts is told again on the next probe. `aor.list` shows each AOR's
`state` (`unknown`, `open`, `closed`, `none` when not probed).

`subscribe_presence` (subscribing to the presence of remote AORs) is out of v1 and
planned for v2: it needs the state of every outbound subscription, and the presence
layer only handles inbound ones today.

The P-Asserted-Identity is not a property of the type: sending or keeping one is the
script's decision for every type (see the first prologue).

### sip trunk

Il est défini par une URI complète : 

uri = sip:user@sip_server:port;transport=

S'il faut reformater car sip_server != domaine
on utilise 

ext_domain =

It is the only type that registers with the remote side. Registration is an internal
service of the module, not a script: one process per `sip-trunk` server, supervised by
`Kelix.Mod.SipServers`, built on `SIP.Session.RegisterUAC` (challenge answered, refresh
before expiry, retry with backoff on failure). It owns `registration_state`, which
`matches_server/1`, `forward/2` and trunk selection read. What varies is an attribute
of the server (`register_expires`, `register_retry`), never code.
C'est le seul qui répond automatiquemment à un challenge du distant: its peer carries
`credentials` (see the prologue on the outbound leg), the B2BUA answers, not an SBB.
La R-URI et le To sont remplacés

The From is rewritten to the trunk account's identity: the user part of the trunk URI,
at `ext_domain` when it is set, else at the trunk host. The caller's identity, when the
script asserts one, travels in the P-Asserted-Identity, not in the From.

As implemented (L4): registration lives in the server's process (`SipServers.Link`),
the same one that tracks reachability, written over `SIP.Transac` directly rather than
`SIP.Session.RegisterUAC`, which drives a dialog for a scenario. The REGISTER goes to
the primary URI without its user part (to `ext_domain`, sent where the URI resolved,
when it is set), From and To are the account, the Contact asks for `register_expires`.
A 2xx registers for the lifetime granted to our Contact (`SIP.Msg.Ops.granted_expires/3`),
refreshed at three quarters of it. A 401/407 is answered once from the HA1
(`SipServers.Credentials`); a second one, a challenge for a realm other than
`auth_realm` (logged as an error naming both), any other final response or no answer
is a failure: retry after `register_retry` seconds, doubled after each consecutive
failure up to an hour, on the next URI. Deleting the server, or stopping the node,
sends an un-REGISTER. The process is also the peers' `credentials` when the trunk has a
password, so a challenged INVITE or BYE is answered the same way. `server.show`
reports `registration` (`state`: `unregistered`, `registering`, `registered`,
`failed`, and the last `error`).

`register = false` is a trunk that does not register but answers the challenges of
the requests it sends (an INVITE challenged by the operator); its `registration` is
`null`. A remote host that authenticates us by our address alone, with no account,
is declared as a `sip-appsrv`, not as a trunk.


# Module et fonctions

Nouveau module kelixip chargeable `Kelix.Mod.SipServers`

## Management

- commandes kelictl, API

- de quoi construire une interface graphique de gestion des serveurs dans kelescope

## Functions

Every facade takes the script's context (or a domain name) first, as the other
modules' do: a server belongs to one domain, and `sip_ctx.domain` is the domain the
Router picked. So the functions below are, as implemented,
`matches_server(sip_ctx, req)`, `find_server(sip_ctx, req)` and
`forward(sip_ctx, req, slug)`; the latter returns `{newreq, peer}` or `{:error,
:not_found | :not_resolved}`.

A server is handed to the B2BUA as a `%SIP.B2bua.Peer{}` (`SIPSessionB2bua.ex`), the
struct the outbound leg already consumes; no new peer type is introduced.

| Server | `%SIP.B2bua.Peer{}` |
|---|---|
| `primary_uri`, `backup_uri` (`failover`) | `uris: [primary, backup]`, `fork: :serial` |
| `use_dns_srv` | `use_srv: true` |
| the server's process (reachability, registration) | `trunk_pid` |

The R-URI the remote host receives depends on the type:

- `sip-proxy`: `ruri: :keep`. The request goes to the proxy unchanged; the proxy
  routes it on its own R-URI.
- `sip-appsrv` and `sip-trunk`: `ruri: :peer`. The R-URI is rewritten to what
  the remote host expects: the user part of the request, the host, port and transport
  of the server (for a trunk, `ext_domain` as host when it is set). `forward/2` builds
  this target per call, so the dialled number is never lost to a server URI that has
  no user part.

### matches_server(req)

Cette fonction examine une requête entrante et détermine si elle vient d'un des serveur SIPs 
définis dans le domaine.

A server is recognised by the **source IP and transport** of the request, compared with
the addresses resolved for the server. The source port is not compared: over TCP, TLS
and WSS it is ephemeral, and many UDP peers do not send from their listening port. The
port of the server's URI is only used to reach it.

Resolved addresses expire with their DNS TTL: when the URI names a host (or
`use_dns_srv` is set), the module resolves it again once the TTL has elapsed, so an
operator changing its IP is followed without a restart.

Two servers of the same domain cannot share a resolved IP: kelictl and the API refuse
to create or modify a server whose addresses overlap another's, since IP and transport
could not tell them apart.

L1 refuses a host or literal address claimed twice (the hosts of the URIs, a proxy's
`ext_domain` and aliases); the overlap of *resolved* addresses is checked once
resolution exists, with L3.

The refusal only guards creation and modification. When a later resolution makes two
servers of a domain share an IP, `matches_server/1` answers `:no_match` for that IP and
raises an alarm naming both servers, rather than picking one.

Retourne { server-slug, %SIP.B2bua.Peer{} } ou :no_match

Routing is unchanged. `Kelix.Router` still picks the domain from the R-URI host
(else the To host), then the script; `matches_server/1` is a predicate the invoked
script calls afterwards, not a routing step. A request from a server must therefore
reach a declared domain first: a trunk calling `sip:+331…@<our IP>`, or with the
operator's domain in the R-URI, only finds one if that IP or domain is listed in the
domain's `aliases`. Otherwise the Router answers 404 before any script runs. This is
configuration, not code.

Recognising a server is not trusting it. `matches_server/1` says where a request
comes from; the script decides what that is worth: reject it, challenge it, accept
it, and whether the received P-Asserted-Identity is forwarded. The module grants
nothing by itself. Keeping a received PAI goes through an explicit framework verb
called by the script, since `prepare_forwarded_request/2` drops any inbound PAI by
default (DESIGN-AUTH.md, "Where the assertion comes from").

### forward(req, server)

The server name is mandatory. The dial-plan (`[[domain.call]]`) picks the script, and
the script names the server it forwards to.

### find_server(req)

Finds the server a request is addressed to, from the host of its R-URI, so a script can
name it to `forward/2` without hard-coding it. Candidates are the `sip-proxy` servers
(their `ext_domain` and `ext_domain_aliases`) and the `sip-appsrv` servers (the
host of their URIs); a `sip-trunk` is never found this way.

Returns the server slug or `:no_match`. A host designates at most one server of a
kelixip domain across both types: kelictl and the API refuse a server whose domain,
alias or URI host is already claimed, so the answer is never ambiguous.

Retourne { newreq,  %SIP.B2bua.Peer{} }

### SBB.forward(req, server-name)

Fait tout le boulot

Appelle B2BUA


## AOR et SIP proxy

Ajout des AOR par commande ou API  

```
kelictl sip_servers aor.add <domain> <slug> <aor>
kelictl sip_servers aor.rm <domain> <slug> <aor>
kelictl sip_servers aor.list <domain> <slug>
```

A module's commands are `kelictl <module> <command>`, and a server is named by its
domain and its slug (REST: `/modules/sip_servers/servers/:domain/:slug/aors`).


# When a server is down

- Outbound: a target the server's process reports down is skipped (second prologue).
  When every target is down, the hunt ends like an exhausted one and the script gets
  the failure; what the caller receives (a 503, another server, a message) is the
  script's decision.
- Inbound: any request received from a server is proof of life, not only an OPTIONS. A
  server marked down that sends an INVITE is marked up again.

As implemented (L3): each server has a process of its own (`SipServers.Link`), the
`trunk_pid` of its peers. With `send_keepalive` it sends an OPTIONS to each URI every
`keepalive_interval` seconds (`[module.sip_servers]`, default 30). Any final response
brings the URI up except `503`; no answer, or no transport, takes it down. A URI never
probed nor heard from is `unknown` and counts as reachable. The process never resolves
a name itself: every OPTIONS and REGISTER it sends carries the destination the service's
resolution found, and waits for it when there is none yet, so a slow DNS never holds up
the `{:reachable?, uri}` a B2BUA asks it. Proof of life on the
inbound side is a request `matches_server/2` recognised, and nothing else: the
script owns the keepalives. An OPTIONS from a server reaches a script through a
`[[domain.options]]` rule, and that script recognises it with `matches_server/2` and
answers it; without such a rule the node answers it (`Kelix.Options`) and the server is
not told anything. No core hook feeds the module behind the script's back: a server is
a declaration about the remote host, not about the node. `server.show` reports each
URI's state under `reachability`.

# Events and metrics (kelescope)

Events, pushed to kelescope:

- a server target (primary or backup) goes up or down;
- a trunk's `registration_state` changes;
- alarms: a challenge for an unexpected realm (expected and received realms named), a
  resolved IP shared by two servers (both servers named);
- a probed remote AOR changes state.

Metrics, per server: inbound and outbound calls, failures by response code, OPTIONS
response time.

Plan for L6, split in two:

**L6a — kelixip (`feat/sip-server-1.6.4`).**

- Push. `Kelix.Mod.SipServers.subscribe_sip_servers(pid, domain)` answers
  `{:ok, %{owner: pid, servers: [row]}}`, then `pid` receives
  `{:kelix_sip_servers, domain, {:upsert, row}}` and
  `{:kelix_sip_servers, domain, {:remove, slug}}`. `row` is what `server.show` returns
  (reachability, registration, remote AOR states, metrics, active alarms): the initial
  read and the push are one rendering, and every message carries the whole row, no
  diff. Any state change of a URI, a registration or a remote AOR pushes the row.
  Registration of the subscriber and the snapshot happen in one message of the
  service, so nothing slips between them. `unsubscribe_sip_servers(pid, domain)` ends
  it; a subscriber that dies is dropped.
- Alarms. `{:kelix_sip_servers, domain, {:alarm, alarm}}` for a challenge for an
  unexpected realm (server, expected and received realms) and for a resolved IP shared
  by two servers (both named). An active alarm is also part of the row, so a screen
  opened afterwards sees it; it clears when the cause goes (the password re-entered,
  the address no longer shared).
- Metrics, in the row. Inbound calls: INVITEs `matches_server/2` recognised. Outbound
  calls: INVITEs `forward/3` shaped. Failures by response code: the B2BUA tells the
  peer's `trunk_pid` the final outcome of each attempt it made on one of its targets
  (`{:call_result, target, code}`, a cast, a framework addition beside
  `{:reachable?, uri}`). OPTIONS response time: last and mean, measured by the
  server's process.
- `Kelix.Control.subscribe_sip_servers/2` and `unsubscribe_sip_servers/2`, the facade
  kelescope calls, as for the conferences; `owner: nil` and no row when the module is
  not loaded.

As implemented (L6a): each server's process publishes its status to the service
(`{:link_status, …}`) whenever it changes, at once for a state and at most once a
second for the metrics alone; the service keeps the last one, so `server.show`,
`aor.list` and the push read it without calling the process. A row adds to the
definition `reachability`, `registration`, `aor_states` (`aor => state`), `metrics`
and `alarms`. `metrics` is `calls_in`, `calls_out`, `answered`, `failures`
(`code => count`, `transport_error` included) and `options_rtt_ms` (`last`, `mean`),
counted since the process started. An alarm is a map with `kind`
(`realm_mismatch`: `expected`, `received`; `shared_address`: `address`, `servers`)
and the `server` it is shown on; a shared address is pushed once per server named.
The B2BUA casts `{:call_result, target, code}` from where it records each attempt's
outcome (`note_progress/2`), whether or not the peer asked for progress events.

**L6b — kelescope (`release/0.7.0`).** No screen of its own: the servers of a domain
are a section of the domain screen, beside its registrations and presence.
`DomainsLink` holds the subscription per expanded domain and relays it on a
`"kelixip:sip_servers:<domain>"` topic. The section lists the servers live (each URI's
state, the registration, the alarms, the metrics), with create, edit and delete
(through `module_command`, the password entered but never shown back) and a proxy's
remote AORs with their state. It is absent when the module is not loaded. A design
note in kelescope's `docs/conception/`, in French as the others.

# Persistence entry

One entry per server in the module's persistence file. Field names are snake_case
and are the names kelictl and the API use; an absent field takes its default.

| Field | Types | Meaning |
|---|---|---|
| `slug` | all | hostname-shaped, unique within the domain |
| `domain` | all | slug of the kelixip domain the server belongs to |
| `type` | all | `sip-appsrv` \| `sip-proxy` \| `sip-trunk` |
| `primary_uri`, `backup_uri`, `tertiary_uri` | all | tried in this order; a trunk's URIs carry the account's user part |
| `source_networks` | all | CIDR networks a request may come from, besides the resolved URIs; the transport must be one the URIs name |
| `use_dns_srv` | all | resolve each URI through SRV (default `false`) |
| `send_keepalive` | all | OPTIONS liveness (default `true`) |
| `initiate_connection` | all | who opens a connected transport (default `true`) |
| `ha_mode` | all | `failover` (default) \| `loadsharing` |
| `use_fqdn_contact` | all | the Contact of the requests sent to the server names the server's `domain` instead of the bound address, without a port (default `false`) |
| `ext_domain`, `ext_domain_aliases` | proxy, trunk | the remote domain (aliases: proxy only) |
| `probe_remote_aors`, `probe_interval` | proxy | AOR probing, interval in seconds |
| `aors` | proxy | remote AORs, managed by `kelictl server … aor` |
| `register` | trunk | register the account (default `true`); `false` only answers challenges |
| `register_expires`, `register_retry` | trunk | REGISTER lifetime and retry delay, seconds |
| `auth_username`, `auth_realm`, `auth_ha1` | trunk | credentials; `auth_ha1` is `[{algorithm, hex}]` |

```json
{ "slug": "acd", "domain": "kelix.example.com", "type": "sip-appsrv",
  "primary_uri": "sip:10.0.0.5:5060;transport=tcp",
  "send_keepalive": true, "initiate_connection": true }
```

```json
{ "slug": "partner-pbx", "domain": "kelix.example.com", "type": "sip-proxy",
  "primary_uri": "sip:proxy.partner.net", "use_dns_srv": true,
  "ext_domain": "partner.net", "ext_domain_aliases": ["sip.partner.net"],
  "probe_remote_aors": true, "probe_interval": 60,
  "aors": ["alice@partner.net", "bob@partner.net"] }
```

```json
{ "slug": "operator", "domain": "kelix.example.com", "type": "sip-trunk",
  "primary_uri": "sip:0123456789@sbc1.operator.net;transport=udp",
  "backup_uri": "sip:0123456789@sbc2.operator.net;transport=udp",
  "ext_domain": "operator.net", "ha_mode": "failover",
  "register": true, "register_expires": 600, "register_retry": 30,
  "auth_username": "0123456789", "auth_realm": "operator.net",
  "auth_ha1": [ {"algorithm": "MD5", "hex": "…"}, {"algorithm": "SHA-256", "hex": "…"} ] }
```

# Delivery

| Lot | Content |
|---|---|
| L0 | the three framework prologues: trusted PAI, `{:reachable?, uri}`, `credentials` |
| L1 | `Kelix.Mod.SipServers`, its store, the kelictl commands |
| L2 | `matches_server/1`, `find_server/1`, `forward/2` |
| L3 | OPTIONS liveness and up/down state |
| L4 | trunk registration and challenge answering |
| L5 | remote AOR probing (`sip-proxy`) |
| L6a | push subscription, alarms, metrics, `{:call_result, …}` in the B2BUA |
| L6b | kelescope: the servers section of the domain screen |
| L7 | documentation: `docs/kelixip/modules/sip_servers.md`; packaging: subpackage `kelixip-mod-sip_servers` / `kelixip-mod-sip-servers`, `[module.sip_servers]` in the shipped `config.toml` |
