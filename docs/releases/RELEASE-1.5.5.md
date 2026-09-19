# Release 1.5.5

2026-09-19 — 22 commits since 1.5.4 (2026-09-10). Theme: **what the stack does
on the application's behalf, it says**. A server transaction that answers for a
silent application now tells it so, and it no longer ends a call that is merely
ringing. A refusal — no media server, no route, no matching rule — is named
where an operator reads it. The B2BUA gains early media, and a total
conversation call no longer dies on its text stream.

Most of these came out of one day of production traffic, 2026-09-16.

## A long ring is not a timeout

**An INVITE server transaction no longer carries timer F.** That timer answers a
different question — 64*T1 is how long a *client* waits for a non-INVITE final —
and armed on an IST it ended every call that rang longer than 32 s, whatever the
application was doing. The caller got a 408 while the callee was still ringing,
and the callee's 603 came back 48 s later with no transaction left to take it.

RFC 3261 §17.2.1 gives an IST no timeout of its own: how long a phone rings is
the application's decision. A bound is kept all the same, far above every
application-level one, because a server transaction is started unlinked and
nothing else would collect one whose application went silent.

| Knob | Where | Default |
|---|---|---|
| `:sip_timer_ist_ringing` | `:elixip2` app env | 600 000 ms |

**When the stack answers 408 for the application, the application is told.**
What the stack sent is not what the application decided, and only the
application can act on it: a B2BUA whose caller's INVITE has just been ended has
a callee still ringing for a call nobody can take, and must CANCEL it. The
transaction now notifies the dialog layer, which turns an unanswered *initial*
request into the one `{:dialog_terminated, …}` the application is owed. Without
it, `SBB.Call` stayed in `proceeding` for its full ring timeout after the
transaction under it had died.

**A 183 with no body is legal, and no longer raises.** Building it raised inside
the server transaction, which took the dialog and the whole call with it — over
a response the far end had every right to send. Only a 200 OK to an INVITE still
requires a session description (§13.3.1).

## B2BUA — early media

**`early_media:` is a new option of `{:mediaserver, opts}`, and it is off.** A
service placed in front of a gateway lives on what the gateway plays before
anyone picks up: the announcement, the network ringback. With a media server it
heard none of it — the callee's SDP was stripped from every 18x.

```elixir
@media {:mediaserver,
        inbound:  [webrtc: :no, media: :audio_video],
        outbound: [webrtc: :no, media: :audio_video],
        early_media: true}
```

With the option on, the framework plays the 2xx choreography one exchange
earlier: the callee's early answer goes to its endpoint, the legs are attached,
and the caller receives *our* answer. Nobody is told the call is answered, so no
RTP watchdog is armed on a leg still ringing. Stripping stays the default:
committing the caller's answer on a 1xx pins the call to the target that sent
it, which is what leaves a serial hunt free to move on.

**A provisional that carries an answer now also carries our Contact.** It
establishes an early dialog, and the Contact is the only thing telling the caller
where to send an UPDATE.

**A media path that cannot be built ends the attempt, instead of buying seconds
of a call that can never carry anything.** When the media server refuses the
callee's early description, or cannot bridge it, the branch in flight is
CANCELled and nothing is relayed. The 487 travels the ordinary path: a serial
hunt moves to the next target, and the caller gets a final response either way.

Reference: [B2BUA.md](../../B2BUA.md), and `DESIGN-FRAMEWORK.md` §7.4.

## Text over WebSocket

**A text medium no longer fails the bridge it is part of.** The MCU's
`EndpointSetRTPProperties` only knows audio and video; asked for anything else it
answers `Unknown media [2]`, and that error failed the *whole* attach — although
the server had just joined the two text streams. A total conversation call was
killed by its own early 183. T.140 loses nothing: there is no transcoder on that
path, so there is no numbering to preserve against.

The control protos gain the addressing `profile` of a leg on `StartSending` /
`StartReceiving` (`moteli_jsr309.proto`, `moteli_mcu.proto`). A medium with no
RTP session accepts it and applies nothing: its address is the server's
WebSocket listener.

## Identity — P-Asserted-Identity

- `SIP.Msg.Ops.asserted_identity/1` returns the whole `%SIP.Uri{}` a trusted
  upstream asserted, display name kept — what a B2BUA re-asserts on its outbound
  leg through `SIP.Context.assert_identity/2`. The inbound header itself still
  never crosses a leg boundary (RFC 3325 §5).
- The two comma-separated values of §9.1 are read apart, and a display name is
  still allowed to hold a comma.
- `tel:+33970260233, sip:a@b` asserted a number with a comma glued to it. Fixed.
- `SIP.Uri.parse/1` refuses a value whose `<` is never closed instead of
  mistaking the head for a display name and recursing on the tail.

## Addressing

- **`SIP.Uri.target_port/1`** — the port a URI designates, or its scheme's
  default (§19.1.2). `port` is nil on a URI built field by field, as a routing
  script writes one; such a destination travelled portless to
  `SIP.Transport.send_msg/4`, which takes an integer and nothing else. The INVITE
  never went out and the leg was answered 488.
- `has_tp_info/1` and the resolver guard both compared a possibly-nil port with
  `> 0`. An atom sorts above every number in Elixir, so `nil > 0` is true and the
  URI passed for fully routed.
- **A received request is marked with the transport it came in over**
  (`destproto` on the R-URI), asked of the transport itself — never the R-URI
  parameter nor the Via, which are declarative.

## kelixip

**Wildcard domain aliases.** An alias written `*.suffix` routes every host below
that suffix, at any depth:

```toml
[[domain]]
name    = "umbrella.com"
aliases = ["*.umbrella.out"]
```

A literal name or alias always wins over a wildcard, and among wildcards the
longest suffix wins. A `*` written anywhere else rejects the file: it is a typo,
not a pattern, and accepting it silently would route traffic an operator never
meant to serve.

**A routing refusal says why, in the operator's words.** Every reject used to
leave nothing but a metric, so "kelixip answers 404 to my INVITE" could not be
told from "kelixip answers 404 to my REGISTER for want of a `[domain.registrar]`
block" without reading `domains.toml` next to a capture. The log line names the
request and the missing block.

**User-Agent is `Kelixip/1.5.5`**, and `Elixipp-1.5.5` for the tool.

## Reference scenarios

**`webrtc-gw.exs` refuses the call with a 503 when there is no media server**,
before any handset rings. Both legs terminate their media on the server, so
without one there is nothing to answer the browser with. The verdict of
`media_connect()` is read straight after the call — it used to be read after
`b2bua_reply` had put `lasterr` back to `:ok`, so the log said "no media server:
`:ok`" — and the 503 is sent *before* the `goto`, because `goto` aborts the
scenario while `lasterr` is set.

`B2BUA.md`'s webrtc-gw listing is back in sync with the scenario it copies.

## Build, CI and tests

- **socket2 2.2.1**: the hardened WSS layer. What a fragmented WebSocket message
  accumulates is bounded, so a peer can no longer grow a connection's memory
  without end. The unused `socket` dependency is dropped.
- **The test job stops on the first failure** (`--max-failures 1 --raise`).
  Without it the run went to the end, the failure scrolled past under the
  compiler warnings, and the job log ended on a green "0 failures" line.
- **A tag publishes its RPMs**: the `publish` stage signs them, checks the
  signature is there, and rsyncs them to the repository.
- **Test logs go to `test.log`** instead of the console.
- **The two B2BUA media suites are back in CI.** They were tagged `:flaky` on a
  wrong diagnosis: they are deterministic, and read `:mediaserver_selector`,
  which `:kelixip` writes when the suite runs from the umbrella root. They now
  preserve and clear that key. Twelve tests that had not run in the pipeline
  since the day it was added.
- Three outdated design documents removed.

## Upgrading

Nothing to do beyond the usual install. No configuration key changed meaning,
none became mandatory, and no new key is exposed in `config.toml`.

| Change | Effect if you leave it alone |
|---|---|
| IST ringing bound (`:sip_timer_ist_ringing`, 600 000 ms) | calls that ring past 32 s survive; nothing else moves |
| `early_media:` on `{:mediaserver, opts}` | off — the 1.5.4 behaviour |
| `*.suffix` aliases in `domains.toml` | none until you write one |

A source build needs `mix deps.get`: the socket2 tag moved to 2.2.1.

The packages are **1.5.5-2**. Release 1 carried the same code, under a changelog
written before most of the release landed. A node already running 1.5.5-1 gains
nothing by the rebuild.
