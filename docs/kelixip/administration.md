# Administration with `kelictl`

`kelictl` is a command shipped **inside** the kelixip release, installed as
`/usr/sbin/kelictl`. It runs no SIP stack: it reaches the live node over Erlang
distribution and delegates to the control layer (`Kelix.Control`), then renders
the result as text.

**How it reaches the node.** The `bin/kelictl` overlay runs the CLI *inside* the
running release via `kelixip rpc`, so it shares the node's Erlang **cookie** — the
credential is the cookie, not a token. On a packaged install the cookie is the
per-host secret the post-install script generated in `releases/COOKIE`, and the target
node name comes from **`RELEASE_NODE`** in the environment file (default
`kelixip@127.0.0.1`) — `/etc/sysconfig/kelixip` on Alma Linux, `/etc/default/kelixip`
on Ubuntu/Debian, the same file the systemd unit reads.

> **Note.** `RELEASE_NODE` and `config.toml`'s `server.node_name` are **not
> auto-synced**: if you change `server.node_name`, set the matching `RELEASE_NODE`
> in the environment file too. There is now a single place to do it (the service
> and the CLI both read that file), but nothing yet derives the VM node name from
> the TOML at boot.

**Root is not required.** `kelictl` writes nothing, and everything it reads in the
release is world-readable — except one file: `releases/COOKIE`, 0640 `root:kelixip`.
That single permission is the whole gate. An operator runs the CLI either as root or
as a member of the `kelixip` group:

```bash
usermod -aG kelixip alice     # then open a new session
```

`/usr/sbin` is in every user's PATH on Alma Linux 9, so the command resolves without a
full path. A cookie that exists and cannot be read is reported by name, with what to
do about it — the release's own script would only say `cat: Permission denied`.

> **What the group grants.** The cookie is an Erlang distribution credential, not a
> read-only token: whoever holds it can run any code on the node, as the `kelixip`
> user. Adding someone to the group makes them a full operator of that server. To
> delegate less, expose the [REST control API](rest-api.md) with its own token and
> keep the group for the people who already administer the node.

## Core commands

| Command | R/W | Does |
|---|---|---|
| `kelictl status` | R | Version, uptime, counters, listeners, media pool, node state |
| `kelictl monitor` | R | Scenarios in progress: id, domain, function, **script**, account, FSM state/event/command, negotiated medias, media server, outbound destination (reuses the `--monitor` view) |
| `kelictl monitor continuous` | R | Same view, redrawn live as scenarios appear, change state or end — no polling. Runs until stdin closes (Ctrl+D) |
| `kelictl registration list [domain]` | R | Registrations, one list per domain — [registrar](modules/registrar.md#control-commands) |
| `kelictl registration show <domain> <aor>` | R | One AOR and its bindings, in detail — *idem* |
| `kelictl registration remove <domain> <aor> [contact]` | W | Drop a registration — *idem* |
| `kelictl domain list` | R | Served domains, their functions and live counters |
| `kelictl domain show <domain>` | R | One domain in detail (name **or** alias) |
| `kelictl domain reload-all` | W | Hot-reload `domains.toml` (atomic, scripts checked) |
| `kelictl domain create <domain> …` / `domain delete <domain>` | W | Create or delete a domain on the running node — [below](#editing-a-domain) |
| `kelictl domain <domain> set\|alias\|registrar\|presence\|call\|chat\|options …` | W | Edit one element of a domain — *idem* |
| `kelictl reload-all` | W | Reload everything that can be applied live: `domains.toml`, the scenario scripts, the module configs. What `systemctl reload` runs |
| `kelictl mediaserver list` | R | The media-server pool: adapter, URL, switch, health |
| `kelictl mediaserver show <name>` | R | One media server in detail, including what it says about itself |
| `kelictl mediaserver enable\|disable <name>` | W | Take a media server in/out of the pool |
| `kelictl stop <id>` | W | Cooperatively shut down one scenario (id from `monitor`) |
| `kelictl run <script> <domain> [key=value…]` | W | Start a script now, with no SIP request behind it; the pairs become its `run_args` — [REST](rest-api.md#running-a-script-on-demand) |
| `kelictl debug <id> on\|off` | W | Start the journal of a live scenario now, or write it now — [below](#the-journal-of-a-live-scenario) |
| `kelictl debug list` | R | The journals kept in memory |
| `kelictl debug show <id> [--full] [--format-puml]` | R | One journal, as a sngrep-like ladder (default) or PlantUML |
| `kelictl reload-script [--notify] <name…>` | W | Reload scenario script(s) |
| `kelictl module list` | R | Loaded modules: version, implementation, how many commands and facades each contributes |
| `kelictl module reload <name>` | W | Reload a module's config |
| `kelictl log-level <lvl>` | W | Change the log level at runtime (`debug\|info\|warning\|error`) |
| `kelictl drain` / `undrain` | W | Answer `503` / `200` to the upstream's OPTIONS probe, without touching what is in flight |
| `kelictl graceful-shutdown` | W | Drain scenarios, then shut the node down |
| `kelictl help [<topic>]` | — | The command list, or one topic in detail |

### Online help

`kelictl` documents itself, so the answer reaches the operator who is on the box
rather than only the reader of this page:

```console
$ kelictl help                    # the command list + the topics
$ kelictl help registration       # one topic, in detail
$ kelictl registration help       # the same text, in the order you were typing
$ kelictl mcu help conference.update   # a module command, from its own declaration
```

Topics: `registration`, `domain`, `mediaserver`, `module`, `debug`, `reload`, `drain`. Each
one prints its commands with **the REST route beside each** — the same
`[GET /path]` convention a module's declared help uses, so the two frontals are
read together. A bare `kelictl`, `-h` and `--help` all print the command list.

Help is answered **from the CLI's own text, with no call into the node**, and the
`bin/kelictl` overlay routes those forms through `kelixip eval` rather than
`kelixip rpc` — so they answer on a host whose service is **down**, which is when an
operator usually reaches for them. A module's own help (`kelictl <module> help`) is
the exception by nature: it is rendered from the declaration of a module that has to
be loaded to have one, so it needs the live node like any other module command.

### Shell completion

The package installs a bash completion for `kelictl` in
`/usr/share/bash-completion/completions/kelictl`. It is picked up in any new shell
where the `bash-completion` package is present, and completes:

```console
$ kelictl reg<TAB>                          registration
$ kelictl registration <TAB>                help  list  remove  show
$ kelictl registration show <TAB>           the served domains
$ kelictl registration show acme.tld <TAB>  the AORs registered in acme.tld
$ kelictl mcu <TAB>                         the commands the mcu module declares
$ kelictl mcu conference.create <TAB>       domain=  name=  layout=  …
$ kelictl stop <TAB>                        the ids of the scenarios in progress
$ kelictl debug <TAB>                       the same ids, and list / show / help
$ kelictl debug show <TAB>                  the ids that have a diagram kept
```

The script holds **no** command name: it calls `kelictl complete <words…>`, which
answers from the same command tree the CLI dispatches, plus what only the live node
knows — the commands each loaded module declares, the served domains, the pool
entries, the AORs, the scripts. A module gains a command and its completion follows,
with nothing to install.

Each `TAB` costs one short-lived VM, about half a second on a live node. Nothing is
cached: the first word is the only answer worth caching, and its module names are
exactly the half that goes stale when a module is loaded or reloaded.

When the node does not answer, completion falls back to the static half of the tree
— the core commands and their sub-commands — so it still helps on a box whose
service is down. And right after a **package upgrade**, before `systemctl restart
kelixip`, completion answers nothing at all: `kelictl` runs the CLI *inside* the
live node, which is still running the previous release.

### Examples

```console
$ kelictl status
node:            kelixip@127.0.0.1
version:         1.5.5
uptime:          0h0m1s
active calls:    0
listeners:       udp:0.0.0.0:5060, tcp:0.0.0.0:5060
domains version: 0
modules:
media pool:      (empty)

$ kelictl domain list
domain           aliases     functions         calls  regs  max
example.com      example.fr  registrar, calls  0      0     500
lab.example.net  -           registrar         0      0     -

$ kelictl domain show example.com
domain:        example.com
aliases:       example.fr
max calls:     500
active calls:  0
registrations: 0
registrar:     default_expires=3600 module=Registrar.Example.V1 script=registrar.exs version=1
presence:
  presence SUBSCRIBE -> presence-subscribe.exs  [Kelix.PresenceSubscribe.V1]
  presence PUBLISH   -> presence-publish.exs    [Kelix.PresencePublish.V1]
  dialog   SUBSCRIBE -> presence-subscribe.exs  [Kelix.PresenceSubscribe.V1]
  dialog   PUBLISH   -> (not served)
dial-plan:
  1. 0[1-9]XXXXXXXX -> user2pstn.exs  [User2Pstn.V1]
  2. (default)      -> catchall.exs   [Catchall.V3 — file changed since load]

$ kelictl domain show ghost.example.org
no such domain

$ kelictl monitor
id  domain       function   script         account       state       event     command     medias  mediaserver  outbound
3   example.com  calls      play.exs       +33970260233  in_call     ACK       media_play  AV      mcu1         sip:bob@10.0.0.5:5062
4   example.com  registrar  registrar.exs  alice         registered  REGISTER  reply 200   n/a     none         n/a

$ kelictl mediaserver list
server  adapter   url                   version  enabled  health  modules
mcu1    mendooze  http://10.0.0.1:8080  1.14.0   on       up      mcu=up
mcu2    mendooze  http://10.0.0.2:8080  -        on       down    mcu=down

$ kelictl mediaserver show mcu1
media server: mcu1
adapter:      mendooze
url:          http://10.0.0.1:8080
enabled:      on
health:       up (pool probe)

server:       mediaserver 1.14.0, up 3h12m5s (mcu-01, pid 4711)
ffmpeg:       5.1.10
audio decode: OPUS PCMU PCMA G722 AAC AMR-WB AMR SPEEX16 GSM
audio encode: OPUS PCMU PCMA G722 AAC AMR-WB AMR SPEEX16 GSM
video decode: H264 VP8 AV1 H263_1998 MPEG4 SORENSON VP6
video encode: H264 VP8 AV1 H263_1998 MPEG4 SORENSON
hardware:     VAAPI yes
text:         rfc4103 yes (redundancy yes), rfc8865 yes, websocket yes
bfcp:         yes
encryption:   none, sdes-srtp, dtls-srtp
sdes suites:  AES_CM_128_HMAC_SHA1_80 AES_CM_128_HMAC_SHA1_32
dtls:         AES_CM_128_HMAC_SHA1_80, fingerprint SHA-256 03:E9:E1:…
profiles:
  publicv4    bind * (every interface)  announced 203.0.113.9  (default)
  publicv6    bind 2001:db8::12         announced 2001:db8::12
  internalv4  unavailable
  internalv6  unavailable
rtp ports:    49152-65535
websocket:    wss://mcu-01.example.com:9090
event queues: 60 s without long-poll = destroyed
load:         conferences 2, participants 7, media sessions 3
mcu:          name mcu1, queue_id q-42, status up, url http://10.0.0.1:8080

$ kelictl mediaserver disable mcu1
ok

$ kelictl mediaserver disable ghost
error: :unknown

$ kelictl domain reload-all
ok
```

`monitor` joins two views on the instance `id` (the id `stop` takes): what the
pool knows — domain, function and the **script** `domains.toml` routed to — and
where the scenario's FSM sits: its state, the event that got it there, the last
command it issued. `account` is **who this instance serves**: a script that knows
the answer says so (the registrar shows the AOR it bound, an MCU call the DID of
the conference it joined), and until it does, the framework shows the identity the
inbound request asserts — its digest username, else the user part of
`P-Asserted-Identity`, else the one in `From`. A `-` means the column has no value
yet, not that it is unsupported.

The last three columns say what **shape** the call is. `medias` is what the two ends
settled on, read off the SDP answer: `A`, `AV`, `AVT`, any combination of the three,
`none` when the answer declined every media. `mediaserver` is the server carrying
them, by the name it is declared under in `[mediaserver.pool.<name>]` — the same word
`kelictl mediaserver list` prints. `outbound` is where a B2BUA call was placed: the
target being dialled, then the one that answered; a serial hunt walks several devices
and the column names the one the call is about, not the list. These three read `n/a`
or `none` rather than `-`: a registrar negotiates no media, connects to no media
server and dials nobody, and that is an answer rather than a missing value.

The **`registration`** commands are documented with the module whose store they
read — how an AOR is addressed, what a binding shows, and the matching REST routes:
**[modules/registrar.md](modules/registrar.md#control-commands)**. On the box, the
same text is `kelictl registration help`.

`reload-script` reports one line per script (`<name>: ok` / `<name>: error: …`).

`domain list` / `domain show` read the **live** `domains.toml` snapshot — what the
router is using right now, which after a rejected `domain reload-all` is *not* what
is on disk (the version is in `kelictl status`). `show` resolves its argument the
way inbound traffic is resolved, against the name **and** the aliases,
case-insensitively and wildcards included, so the host seen on the wire is a
valid argument — `domain show a.gw.out` answers for the `gw.out` domain whose
aliases hold `*.gw.out`. The
dial-plan is listed in file order and numbered, because it is first-match-wins:
rule *n* is only tried if rules *1…n-1* did not match. `functions` lists what the
domain actually serves (a function block present in the TOML = enabled), so an
empty column means every request to that domain is answered `404`.

`mediaserver list` / `mediaserver show` list the `[mediaserver.pool.*]` entries —
the node's only declaration of a media server — in config order, which is the
round-robin order. Two things that read alike are kept apart there:

* **`enabled`** is the operator switch, flipped by `mediaserver enable|disable`
  and by nothing else. Disabling stops **new** calls and conferences landing on
  that server; what is already running stays until it ends.
* **`health`** is the pool's own probe (a connect/disconnect on the
  point-to-point adapter's channel, every 30 s), and the `modules` column is what
  each module driving that server says about it — the `mcu` module holds a
  *different* control channel to the same box. `up` on one side and `down` on the
  other is a real state, not a contradiction: a server whose JSR-309 side is
  unreachable can serve conferences perfectly, and vice versa.

A server the pool does not declare is `error: :unknown` on `enable`/`disable` and
`no such media server` on `show`.

#### What the media server says about itself

Everything below the blank line in `mediaserver show` — and the `version` column
of `mediaserver list` — is **the media server's own answer**, read from its
`GET /status/general` endpoint on the same 30 s probe cycle as the addressing
profiles. Nothing there is configured on this side.

That is the whole point. A controller that cannot **ask** what a media server can
do ends up **declaring** it, and that copy drifts: kelixip once offered H.264 and
VP8 while the server had carried AV1 for months, and an AV1 ↔ AV1 call died on a
488 with perfect audio at both ends.

Read it with two things in mind:

* **`video decode` and `video encode` are not the same list**, and neither are
  the audio ones. `decode` is what the server can **receive**, `encode` what it
  can **emit**. VP6 is the standing example: it arrives in RTMP streams and no
  encoder for it exists anywhere. A call that needs the server to *produce* a
  codec must find it in the `encode` line.
* **A profile carries two addresses.** `bind` is the interface the socket takes,
  `announced` is what the peer sees in the SDP. They differ behind NAT, and that
  gap is why the table exists. `bind * (every interface)` is not a missing value:
  it is the nominal case of an announced address that lives on the router.

`server: unknown (this media server does not describe itself)` means the endpoint
answered 404 or something other than JSON — an older binary, or the `mockup`
adapter. Selection and health are unaffected; only this description is missing,
and the node says so rather than filling the fields with guesses. The same is
true field by field: a `-` is "the server did not state it".

The reference for the endpoint itself — every field, and what each one commits
to — is the mediaserver repository, `docs/reference/status-http.md`.

### The journal of a live scenario

A call that misbehaves can be traced while it runs, without restarting anything:

```console
$ kelictl monitor
id    domain       function  script     account  state    event  command  …
12    example.com  calls     relay.exs  alice    talking  ACK    -        …

$ kelictl debug 12 on
journal on for scenario 12: it is kept when the scenario ends, or now with `kelictl debug 12 off` — then `kelictl debug show 12`

$ kelictl monitor
id    domain       function  script     account  state    event  command  …
12 ●  example.com  calls     relay.exs  alice    talking  ACK    -        …

$ kelictl debug 12 off
journal of scenario 12 written — `kelictl debug show 12`

$ kelictl debug list
id  scenario  domain       script     written (UTC)        instance  SIP  size     kept for
12  Relay.V3  example.com  relay.exs  2026-09-28 14:02:11  running   9    14230 B  0h59m48s

$ kelictl debug show 12
Scenario : Relay.V3   (#PID<0.412.0>)
peer1: dev71.dev.ives.fr:443/wss — Call-ID 35739021077

            alice                     dev71.dev.ives.fr:443/wss
              |                                   |
  +0.000s     | journal on (talking)              |
  +4.210s     |<----------- BYE #3 ---------------|
  +4.211s     |----------- 200 OK / 3 BYE ------->|
  +4.212s     | talking -> hangup                 |
              |                                   |
```

- **`on`** takes effect at once, in the middle of whatever the scenario is
  waiting for. The journal opens with a note naming that state, and every SIP
  message the scenario's dialogs send or receive from then on is recorded, one
  column per Call-ID. The dialogs already open are included, both legs of a
  B2BUA too. The scenario itself sees nothing; the monitor marks its row `●`.
- **`off`**, or the end of the scenario, writes the journal. A scenario has
  **one** journal: once written, `on` is refused ("already written", exit
  code 4), and the scenario goes on untraced.
- **`debug show <id>`** draws the journal:
  - by default as a ladder, one column per peer and the media server, the way
    sngrep draws a call;
  - `--full` prints each SIP message after its arrow, with its body decoded
    when it was compressed (`deflate`, `gzip`);
  - `--format-puml` prints PlantUML instead, with the passwords of the
    scenario's configuration masked:
    `kelictl debug show 12 --format-puml > call-12.puml`.

The node keeps the journal itself, not a drawing of it. `kelictl` draws it as
above, and kelescope draws it in a popup. REST (`GET /traces/<id>`) answers
the journal as JSON ([rest-api.md](rest-api.md)).

Journals are kept **in memory only**, and a restart loses them. Three limits
apply, all set in [installation.md](installation.md):

- `[debug] trace_retention`: how long a journal is kept after it is written
  (one hour by default);
- `[debug] max_traces`: how many are kept (100), the oldest dropped first;
- `[debug] max_trace_bytes`: how much message text one journal keeps (1 MiB).
  Past it, the journal ends with "journal truncated".

Only messages that go through a transaction of the scenario's dialogs are
recorded. A stateless reply of the dialog layer, or an OPTIONS outside any
dialog, is not.

### Editing a domain

A domain is created, edited and deleted on the running node, one element per
command. Each command is a complete write: the node checks the result as it checks
`domains.toml` at boot, writes the file, and serves the new domain at once. No
reload, no restart.

```console
$ kelictl domain create example.com aliases=example.fr
domain example.com created (v2)

$ kelictl domain example.com call add default script=direct-call.exs
rule 1 added (v3)

$ kelictl domain example.com call add 0XXXXXXXXX script=direct-call.exs
rule 1 added (v4)

$ kelictl domain show example.com
domain:        example.com
aliases:       example.fr
max calls:     unlimited
active calls:  0
registrations: 0
version:       4
registrar:     (disabled)
presence:      (disabled)
dial-plan:
  1. 0XXXXXXXXX -> direct-call.exs  [Kelix.DirectCall.V1]
  2. (default)  -> direct-call.exs  [Kelix.DirectCall.V1]
chat:          (disabled)
options:       (core answer)
```

A script the node cannot serve is refused before anything is written, with the reason:

```console
$ kelictl domain example.com registrar set script=registrar.exs
1 script(s) rejected:
  - domain example.com [domain.registrar]: /usr/share/kelixip/registrar.exs declares uses_modules ["auth_db"], which is not loaded (no [module.<name>] block, or no .beam in module_dir); loaded: ["registrar"]
```

The commands:

```
domain create <d> [aliases=a,b] [max_calls=N]
domain delete <d>
domain <d> set max_calls=N|none
domain <d> alias add|remove <host>
domain <d> registrar set script=X [default_expires=N|none] [min_expires=N|none]
                                  [keepalive_period=N|none]
domain <d> registrar remove
domain <d> presence add <package> subscribe=X [publish=Y]
domain <d> presence set <package> [subscribe=X] [publish=Y|none]
domain <d> presence remove <package>
domain <d> call|chat|options add <rule> script=X [at=N]
domain <d> call|chat|options update <n> [pattern=P|default] [script=X]
domain <d> call|chat|options move <n> to=<m>
domain <d> call|chat|options remove <n>
domain <d> presence <package> subscribe add|update|move|remove …
domain <d> options keepalive set script=X
domain <d> options keepalive remove
```

- `<d>` is the domain's name, not an alias.
- `<rule>` is a dial pattern, or `default` for the catch-all.
- A chat rule also takes `idle_timeout=N`.
- `set` changes only the values it is given. `none` removes an optional value.
- `presence set <package> subscribe=X` replaces the SUBSCRIBE rules with the single
  script `X`. The `subscribe` commands edit them one by one.
- `kelictl domain help` prints the same list on the box.

The REST API has one route per command: see
[rest-api.md](rest-api.md#editing-domains).

#### Rules are addressed by number

`domain show` numbers every rule list in the order the router tries the rules.
`update`, `move` and `remove` take that number. A rule number changes when a rule is
added, moved or removed before it.

- `add` puts the new rule just before the catch-all, which stays last. `at=N` gives
  another place. The answer gives the number the rule took.
- In `options`, the keepalive is not a rule and has no number.
- A command that would leave the catch-all anywhere but last is refused.

**Use `--version`.** `domain show` prints the version of the domains. Pass it to the
next command:

```console
$ kelictl domain example.com call remove 2 --version 4
ok (v5)

$ kelictl domain example.com call remove 1 --version 4
the domains changed since the version given with --version, or while the command ran: read them again (kelictl domain show) and run the command again. Nothing was applied.
```

Without `--version`, the command applies to the domains as they are when it runs. If
another operator added a rule in between, `call remove 2` removes another rule than
the one you read.

#### Who asked

The node logs every write with the name of who asked:

```
domain call add 0XXXXXXXXX example.com by admin=alice: v4
domain delete example.com by admin=alice: v8, 3 scenario(s) asked to stop, purge presence=:not_loaded registrar={:ok, 12}
```

`kelictl` passes your Unix user name. `--admin NAME` gives another name.

#### Deleting a domain

`domain delete` is never refused because the domain is in use, and it asks for no
confirmation:

```console
$ kelictl domain delete example.com
domain example.com deleted (v8): 3 scenario(s) asked to stop
  presence: not loaded, nothing held
  registrar: 12 purged
```

- New requests for the domain are answered `404` at once.
- Its scenarios are asked to stop, as `kelictl stop` asks. A call in progress ends
  with its BYE. The command does not wait for them.
- Its registrations and its presence states are purged. A purge that fails is shown
  as `purge FAILED`; the domain is deleted anyway, and the leftovers are purged when
  a domain of that name is created again.
- `domain create` starts from nothing: whatever an older domain of that name left is
  purged first.
- A `domain reload-all` whose file no longer has a domain ends it in the same way.

#### The file

The node writes the domains to `domains.toml` (`/var/lib/kelixip/domains.toml` on a
packaged node). `kelictl status` says whether it can:

```console
domains file:    /var/lib/kelixip/domains.toml, writable
```

- **Comments do not survive a write.** The node writes the file from its data, with a
  generated header. The commented example is
  `/usr/share/doc/kelixip/domains.toml.example`.
- **`[module.registrar]`** is kept as it is. No command edits it.
- **A hand edit blocks the writes until it is reloaded.** The file can still be edited
  by hand. Until `kelictl domain reload-all` applies the edit, every write is
  refused, so that it does not erase the edit:

  ```console
  $ kelictl domain example.com set max_calls=100
  domains.toml was edited by hand and not reloaded, and a write would erase that edit: run `kelictl domain reload-all` first. Nothing was applied.
  ```

  A `reload-all` that fails keeps the block: fix the file and reload again.
- **A file the node cannot write.** The node still starts and serves the file, and
  logs a warning. Every write is refused with the path, the system reason and the
  user the node runs as:

  ```console
  $ kelictl domain example.com set max_calls=100
  the node cannot write /srv/domains.toml (permission denied, eacces, running as kelixip): give the file and its directory to kelixip, or point KELIXIP_DOMAINS to /var/lib/kelixip/domains.toml. Nothing was applied.
  ```

  The node checks again before every write: a fixed permission works without a
  restart.
- **Backups**: whatever saves `/etc/kelixip` must also save
  `/var/lib/kelixip/domains.toml`.
- **One file per node.** A domain created on one node does not exist on the others.

The exit codes are those of [below](#exit-codes): `3` for an unknown domain, alias,
package or rule number, `4` for a name that already exists, a conflict or a hand edit, `5` for a file the node
cannot write.

### Reloading a running node

```console
$ kelictl reload-all
domains.toml:  reloaded (v4)
scripts:       mcu.exs v2, registrar.exs v1
modules:       auth_db unchanged, mcu unchanged, registrar unchanged
```

`kelictl reload-all` is what `systemctl reload kelixip` runs. In one step it applies
`domains.toml` (`/var/lib/kelixip/domains.toml` on a packaged node: domains,
dial-plan, the registrar's block), re-reads the **scenario
scripts** whose file changed on disk, and applies the module blocks that can be
changed without interrupting anything.

It is **all-or-nothing on `domains.toml`**: the file is only accepted if it parses,
its dial-plan patterns compile, *and* every script it names is servable — present in
`script_dir`, compiling, and handling shutdown. One offender and the reload is
refused, naming the domain and the rule that points at it; the configuration that was
running stays exactly as it was, and nothing else is touched:

```console
$ kelictl reload-all
domains.toml:  REJECTED, still v4 — 1 script(s) rejected:
  - domain example.com [domain.registrar]: /etc/kelixip/scripts/registrar.exs does not
    handle cooperative shutdown (missing `on_shutdown` block): refused
scripts:       (none loaded)
modules:       (none configured)
```

The same check runs at **boot**: a `domains.toml` naming a script the node cannot
serve aborts the start, with the reason on stderr (so `systemctl status` and the
journal show it) rather than starting a server that answers every call to that domain
with a `500`.

Part of that check is that **two scripts may not declare the same module**. The module
name comes from the file's own `defmodule`, not from its name, so two copies of the
same scenario — the usual way a `record.exs` and a `play.exs` are born — compile to the
same module and the second load silently overwrites the first: both dial-plan rules
then run one body. Copying a script means renaming its module too, and a node that
finds a duplicate refuses the second script by name:

```console
$ kelictl reload-all
domains.toml:  REJECTED, still v4 — 1 script(s) rejected:
  - domain example.com call rule "900032222": /etc/kelixip/scripts/play.exs defines
    UAS.InviteExample (owned by record.exs); two scripts cannot share a module name —
    rename the module in one of them
```

### What is actually running

`kelictl domain show` prints, in brackets after each script, the **module** the BEAM
runs for it — the compiled truth, next to the file name you configured. The `.V<n>`
suffix is the load version: it goes up on every reload, and two rules showing the same
module mean the two scripts collided.

It also compares the loaded code against the file **right now**, without reloading
anything, and marks the difference: `— file changed since load` (an edit is waiting for
a `kelictl reload-script <name>`), `— file missing` (the file is gone; the loaded
version keeps serving), or `— file unstamped` (it could not be read at load time).
`[not loaded]` means no call has reached that rule yet and no reload has pre-loaded it.

What a reload deliberately does **not** do:

* **`config.toml`** — listeners, ports, media-server pool, control API, log target:
  read once at boot. Changing it means `systemctl restart kelixip`.
* **a module whose block changed but that cannot be reconfigured live** — reloading it
  means restarting it, which drops its live state (the conferences of `mcu`, the
  registrations of `registrar`). It is left running and reported
  `CHANGED, needs a restart`, so the choice of when to lose that state stays yours.

Narrower verbs remain, when that is what you want: `kelictl domain reload-all` for
`domains.toml` alone, `kelictl reload-script <name…>` for one script, and
`kelictl module reload <name>` to force one module's config through (a restart of that
module included).

### Exit codes

| Code | Means |
|---|---|
| `0` | ok |
| `1` | the command failed, unclassified (e.g. an unknown module) |
| `2` | usage, or an argument the command refused |
| `3` | no such object |
| `4` | conflict: it already exists, or is not empty |
| `5` | unavailable: the node, the module or its backend did not answer |

`3`/`4`/`5` apply to **module commands** and come from the failing command's own
declaration (the `errors:` map of its `describe_control/0` entry) — the same
declaration the REST frontal turns into `404`/`409`/`503`, so both frontals
classify a failure identically. A reason a module declares nothing for falls back
to `404` → `3` for `not_found`, `503` → `5` for a module that is absent or wedged,
and `400` → `2` otherwise.

Core commands use the same classes. A domain, registration, media server, scenario,
journal or module block that does not exist is `3`. A refused write to
`domains.toml` is `4` (`conflict`, `file_changed`) or `5` (the node cannot write the
file). A module name nothing loads stays `1`, as above: it is more often a mistyped
command than a missing object.

The code is the shell's `$?`, so a script can test it. A refused `systemctl reload`
also makes the unit's reload command fail, so systemd and the journal report it.

> `reload-script --notify` is **accepted but not yet active** — notifying
> in-progress instances of a reload is a roadmap refinement; today the flag is a
> no-op and the reload swaps the script version as usual.

## Module commands

Modules may contribute their own sub-commands, declared once per module
(`describe_control/0`):

```
kelictl <module> <command> [args…]
```

The positional `args…` are handed to the module's `handle_control/2` as
`%{"args" => [ ... ]}`; the convention is `name=value` tokens (`true`/`false` is a
boolean, digits an integer, a leading `{`/`[` is JSON). These share the same
cookie boundary as the core commands.

A bare token binds to the next declared argument the line did not name, in the
order `<module> help` lists them, as for the core commands:

```
kelictl presence list weshwesh.eu              # = domain=weshwesh.eu
kelictl presence show weshwesh.eu magali.buu   # = domain=… aor=…
```

A bare `user@domain` is an address: for a command declaring `aor` and `domain`, it
binds both. With the domain already given, it binds `aor` to the user part when
the two domains agree, and is kept whole otherwise.

```
kelictl presence show magali.buu@weshwesh.eu   # = domain=weshwesh.eu aor=magali.buu
```

A bare token spelling a declared argument's name stays a flag (`force` =
`force=true`).

**Quote a value that contains spaces** — `name='Sales weekly'`,
`layout='2x2 hd720p'` — and the quotes reach the module intact, JSON included
(`muted='{"audio":true}'`). Before 2026-08 the wrapper joined the argument line
into one string and re-split it, which silently dropped that quoting; if a value
with a space comes back as `unknown argument(s): <second word>`, the node is
running an older release than its `kelictl`.

**Ask the node what it serves** rather than reading the module's source — both
listings are rendered from the declaration itself, so they cannot drift:

```console
$ kelictl module list
module  version  implementation  commands  exports
mcu     1.0      Kelix.Mod.Mcu   9         16

kelictl <module> help lists what a module contributes

$ kelictl mcu help
mcu 1.0 (Kelix.Mod.Mcu)

commands:
  conference.create   [POST /modules/mcu/conferences]
      args: domain* name did mcu vad rate medias dtmf video layout logo max_participants destroy_when_empty
      Create a conference (allocates a DID when none is given)
      vad: voice activity detection: none | basic | full (or 0 | 1 | 2)
      layout: a mosaic, a size and/or auto|manual, in any order, spaces or commas
              mosaic: 1x1 2x2 3x3 3+4 1+7 1+5 1+1 pip1 pip3 4x4 1+4 2+8
              …
  conference.list     [GET /modules/mcu/conferences]
      args: domain did
      List the conferences, optionally filtered by domain and/or DID
  …

facades (import Kelix.Mod.Mcu):
  create_conference/2, ensure_conference/3, …

$ kelictl mcu help conference.update      # one command, in full
```

`*` marks a required argument; the bracketed route is the same command over REST
(`GET /modules` and `GET /modules/<name>` serve the same declarations as JSON).
`help` is therefore reserved on a module namespace, and so is
`<module> help <cmd>` — which narrows the listing to one command, since a whole
module's surface plus every vocabulary is a screenful.

An argument whose **value** has a vocabulary of its own (a mosaic name, an enum, a
compact syntax) is printed under the command, indented below its name. That text is
the module's, declared next to the parser that enforces it: the CLI has no idea what
a mosaic is, and cannot show one the module would refuse.

A module's whole namespace is its own: `kelictl mcu <cmd>` is the `mcu` module's
(`kelictl mcu conference.list`), and enabling or disabling a media server is
`kelictl mediaserver enable|disable <name>` — it acts on a `[mediaserver.pool.*]`
entry, of which the `mcu` module is only one consumer. `domain`, `mediaserver`
and `module` are core nouns and never reach a module, so a mistyped sub-command
prints their usage rather than "unknown module".

Of the shipped modules, [mcu](modules/mcu.md), [auth_db](modules/auth_db.md),
[presence](modules/presence.md), [mcu_presence](modules/mcu_presence.md),
[dialog_state](modules/dialog_state.md) and [sip_servers](modules/sip_servers.md)
contribute commands today;
[registrar](modules/registrar.md) contributes none — its registrations are a core
noun, addressed as a sub-resource of their domain. The mechanism is documented in
[modules/README.md](modules/README.md#module-administration-kelictl--rest-api).

## Parity with REST

Every `kelictl` command maps to a `Kelix.Control` function, and the REST frontal
(`Kelix.ControlAPI`) exposes the same functions — same operation, two frontals.
See [rest-api.md](rest-api.md).
