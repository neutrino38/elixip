# Release 1.5.5

2026-09-19 — 22 commits since 1.5.4 (2026-09-10). Theme: WebRTC gateway,
183 Session Progress handling and fixed behavior on text over Websocket.

## A long ring is not a timeout

**An INVITE server transaction no longer carries timer F.**, the application
is the one responsible to control the ringing timeout on IST.

| Knob | Where | Default |
|---|---|---|
| `:sip_timer_ist_ringing` | `:elixip2` app env | 600 000 ms |

**When the stack answers 408 for the application, the application is notified.**
and the B2BUA cancels the outbound leg.

**A 183 with no body is accepted, and no longer raises.** 

## B2BUA — early media

Added a new option to process early media:  `{:mediaserver, opts}`.

```elixir
@media {:mediaserver,
        inbound:  [webrtc: :no, media: :audio_video],
        outbound: [webrtc: :no, media: :audio_video],
        early_media: true}
```

With the option on, the framework use the mediaserver to process it as it would
for a 200 OK with SDP except no RTP watchdog is armed.

**A provisional that carries an answer now also carries our Contact.** It
establishes an early dialog, and the Contact is the only thing telling the caller
where to send an UPDATE.

**A media path that cannot be built ends kill the call instead of buying seconds
of a call that can never carry anything.** When the media server refuses the
callee's early description, or cannot bridge it, the branch in flight is
CANCELled and nothing is relayed. The 487 travels the ordinary path: a serial
hunt moves to the next target, and the caller gets a final response either way.

Reference: [B2BUA.md](../../B2BUA.md), and `DESIGN-FRAMEWORK.md` §7.4.

## Text over WebSocket

if `EndpointSetRTPProperties` fails on text media, the call still continue
with audio and video.

## Identity — P-Asserted-Identity


added `SIP.Msg.Ops.asserted_identity/1` to enable PAI forwarding. Added tel:
URI support for PAI.


## Addressing

- surport for SIP.Uri with nil port meaning default port.
- **A received request is marked with the transport it came in over**
  (`destproto` on the R-URI).

## kelixip

Support for **Wildcard domain aliases.** An alias written `*.suffix` routes every host below
that suffix, at any depth:

```toml
[[domain]]
name    = "umbrella.com"
aliases = ["*.umbrella.out"]
```

Improved logs when initial request routing fails.

**User-Agent is `Kelixip/1.5.5`**, and `Elixipp-1.5.5` for the tool.

## Reference scenarios

**`webrtc-gw.exs`** has been improved and tested.


## Build, CI and tests

- **socket2 2.2.1**: the hardened WSS layer. What a fragmented WebSocket message
  accumulates is bounded, so a peer can no longer grow a connection's memory
  without end. 

- **The test job stops on the first failure** (`--max-failures 1 --raise`).
- **A tag publishes its RPMs**: the `publish` stage signs them, checks the
  signature is there, and rsyncs them to the repository.
- **Test logs go to `test.log`** instead of the console.
- **The two B2BUA media suites are back in CI.** They were tagged `:flaky` on a
  wrong diagnosis: they are deterministic.

## Upgrading


| Change | Effect if you leave it alone |
|---|---|
| IST ringing bound (`:sip_timer_ist_ringing`, 600 000 ms) | calls that ring past 32 s survive; nothing else moves |
| `early_media:` on `{:mediaserver, opts}` | off — the 1.5.4 behaviour |
| `*.suffix` aliases in `domains.toml` | none until you write one |

