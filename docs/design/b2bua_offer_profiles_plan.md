# P5 — offer profiles and fallback (§7.5): work plan

Only meaningful with `{:mediaserver, …}`. Choosing a profile means *generating*
an offer; without a media server the offer is the caller's, relayed verbatim, and
an AVP caller cannot be turned into a WebRTC one.

```elixir
%SIP.B2bua.Peer{profile: :webrtc_if_supported}
```

| profile | offered | on a fallback code |
|---|---|---|
| `:webrtc_required` | DTLS-SRTP / RTP-SAVPF, ICE, rtcp-mux | the attempt failed |
| `:webrtc_if_supported` | same | **fall back** one rung |
| `:avpf_required` | RTP/AVPF | the attempt failed |
| `:avpf_if_supported` | same | **fall back** one rung |
| `:avp` | plain RTP/AVP | the attempt failed (nothing below) |
| `nil` (default) | whatever `media_opts` say today | never |

The ladder is `webrtc → avpf → avp`. `nil` is not a rung of it: it means "P5 is
not in play", the outbound offer is built from the `{:mediaserver, outbound:}`
options exactly as P3 built it, and nothing in this document runs. Every
scenario written before P5 therefore behaves identically.

## Three things §7.5 could not know

§7.5 was written before P4 landed and before the media plane existed. Three of
its sentences need re-deciding against what is actually there.

### 1. The ladder is walked by the RUNG, not by one target

§7.5 says "a fallback is a retry of the same target, not the next one". With P4
the session never sees one target's final: the dialog withholds every branch
failure until the last branch of the rung falls and surfaces the aggregate
(§16.7). A per-target ladder would need per-branch profile bookkeeping in the
dialog and a way to tell "this branch 488ed, the others are still ringing" from
"the rung is over" — which is precisely the distinction P4 removed on purpose.

So: **the rung is re-dialled one profile down, whole.** For the single-URI peer
of the WebRTC-gateway case — the case §7.5 exists for — a rung *is* one target
and the two readings coincide. For a parallel rung of five contacts, a 488
aggregate means "none of these five liked this profile", and offering the whole
rung the profile below is the honest reading of that.

### 2. A fallback branch carries a NEW CSeq

§7.5 calls the fallback "another branch (§3.3) toward the same URI carrying a
different body". A branch is a new Via branch on the *same* Call-ID, From-tag and
CSeq — and that is exactly what must not be sent here.

RFC 3261 §8.2.2.2: a request whose From-tag, Call-ID and CSeq match an ongoing
transaction but which does not match that transaction is a **merged request**,
answered `482 Loop Detected`. The 488 we are reacting to has just been ACKed, so
the callee's INVITE server transaction is in Confirmed and lives on for timer I
(5 s on UDP) — the fallback lands squarely inside that window. Two rungs of the
ladder would produce a 482 from any conforming UAS.

So `fork_branch/2` grows opts, and the replacement offer comes with a **CSeq
bump**: `SIP.Dialog.fork_branch(pid, targets, body: sdp)` re-stamps the dialog's
stored request (body + `[cseq + 1, method]`) before arming the branches. The
branch machinery is otherwise untouched — same dialog, same leg, same
correlation — which is what makes the fallback invisible to everything the hunt
already does.

### 3. Regenerating the offer means REPLACING the outbound endpoint

A local description is a property of the endpoint: the ports, the DTLS
fingerprint, the ICE credentials and the profile of every `m=` line are fixed
when `create_peer_connection` runs. There is no "re-offer with another profile"
on a live endpoint.

So a fallback closes the outbound endpoint and creates another one in the SAME
media session (`bridge_with: :inbound`), which P3 already proved the Medooze
server accepts (dev71, 2026-08-09: a second `EndpointCreate` in an existing
`MediaSession`, and releasing one leg keeps the session). The inbound endpoint
and the caller's held answer are untouched — the caller is not part of this
negotiation and must not see it.

## Order of work

R1 → R2 → R3 → R4 → R5 → R6. R1-R2 are pure additions, R3-R4 are the two seams,
R5 is the ladder itself and R6 the proof.

### R1 — the profile vocabulary (`SIP.B2bua.Profile`)

One place that maps a profile atom to a ladder and a rung to media options.

```elixir
Profile.ladder(:webrtc_if_supported)  # => [:webrtc, :avpf, :avp]
Profile.ladder(:avpf_required)        # => [:avpf]
Profile.ladder(nil)                   # => []        (P5 not in play)
Profile.conn_opts(:webrtc)            # => [webrtc: :yes]
Profile.conn_opts(:avpf)              # => [webrtc: :no, rtp_profile: :avpf]
Profile.conn_opts(:avp)               # => [webrtc: :no, rtp_profile: :avp]
```

The rung's options are merged **over** the peer's `outbound:` options: a scenario
still says which medias and codecs it wants, the profile says how they are
carried.

### R2 — the AVPF rung in the adapters (`rtp_profile:`)

Today an offer is binary: `webrtc_support: :yes` gives DTLS + ICE + rtcp-mux +
SAVPF + rtcp-fb, anything else gives plain `RTP/AVP`. The middle rung —
`RTP/AVPF`, no encryption, no ICE, but the feedback profile — has no way to be
expressed.

New connection option `rtp_profile: :avp | :avpf` (default `:avp`), honoured by
both `MediaServer.Mendooze.Conn` and `MediaServer.Mockup`, and ignored when
`webrtc_support: :yes` (WebRTC already implies SAVPF). It reaches the SDP through
the two fields the builder already has: the `:protocol` override (`"RTP/AVPF"`)
and `rtcp_fb` on video. Nothing in the answer path changes — an answer mirrors
the offer's protocol, which is what it already did.

### R3 — regenerating the outbound offer (`Media.replace_peer_connection/3`)

A Media-layer primitive, because "close this leg's connection, create another
with these options and forget nothing else" is the media mixin's business:

```elixir
{sip_ctx, {:ok, offer}} = Media.replace_peer_connection(sip_ctx, :outbound, opts)
```

It closes the stored handle (best effort — a dead endpoint must not block a
fallback), drops it from the appdata, and lets `get_sdp_offer/4` create the next
one, which is the existing path. The B2BUA then stores the new offer as
`%MediaPlan{outbound_offer:}`, since that is what every branch is composed from.

### R4 — `fork_branch/3` carries the replacement offer

`SIP.Dialog.fork_branch(pid, targets, opts)` with `body: sdp`. In `DialogImpl`,
before arming: re-stamp `state.msg` with the new body and `[state.cseq, method]`,
bump `state.cseq`. `fork_branch/2` keeps its meaning exactly (no opts = no
re-stamp = a plain rung of the hunt), so P4's paths are unchanged.

### R5 — the ladder in the session layer

`%Peer{profile:, fallback_on:}` (`fallback_on` defaults to `[488]`; `415` and
`606` are the codes some equipment uses for the same thing, which is why it is a
list and not a constant). `%Leg{rungs_left:}` holds what is under the current
profile, and `%Leg{profile:}` the one in flight.

In `do_relay_reply/2`, the fallback is tried **before** the hunt:

```
fallback?      -> fall_back_one_rung   # same rung, next profile down
provider_hunt? -> ask_provider_next
next_rung?     -> try_next_rung
true           -> relay_reply
```

and `retryable?/2` must not see a fallback code while a rung is left, or the hunt
would move to the next target before the ladder has been walked. `hunting?/0`
answers true during a fallback: from the scenario's side it is the same fact —
the call is still being placed.

A profile that bottoms out is not special: the last rung's final response goes
through the ordinary path, so `retry_on` gets its usual say and the hunt moves to
the next target.

`profile:` with media `false` is refused at leg creation
(`{:b2bua, :profile_needs_media_server}`) rather than silently ignored: it asks
for something a signalling relay cannot do.

### R6 — the scenario and the tests

- `scenarios/b2bua_webrtc_gw.exs` — §12 use case (a), WebRTC-gateway variant: the
  `_media` scenario with `profile: :webrtc_if_supported`. A new file, never a
  flag on `b2bua_media.exs` (§12).
- `b2bua_offer_profile_test.exs`: the ladder walked rung by rung against a UDP
  mockup answering 488 twice and 200 on the third INVITE — asserting the three
  offers' transports (`UDP/TLS/RTP/SAVPF`, `RTP/AVPF`, `RTP/AVP`), the CSeq
  bump, and that the caller sees exactly one answer, ours, at the end;
  `:webrtc_required` giving up after one; `fallback_on` making a 415 do the same;
  and the ladder bottoming out handing the hunt its 488 so the next target is
  tried.
- Adapter-level tests for `rtp_profile:` in the Mockup and in
  `mendooze_conn_test.exs` (the fake JSR309 server).

## As built (2026-08-10)

Delivered in the order above. Two things the plan did not see, both found by
running the ladder through a real dialog rather than through the session layer
alone — which is the argument for having both test levels:

1. **A peer with a ladder has to declare `fork:` to the dialog, even with one
   target.** `forking` was computed from "are there untried targets or a
   provider", and a single-URI gateway peer answered no. A 488 then ended the
   *dialog*, not the branch, and the fallback found nothing left to arm itself
   on (`{:fork_branch, :leg_dead}`, which `abandon_ladder/6` correctly turned
   into "the 488 stands" — the failure was silent and looked like policy). The
   condition now includes `length(Profile.ladder(peer.profile)) > 1`, so a
   `_required` profile still changes nothing.

2. **The ladder restarts at the top for each new rung of targets**, which the
   plan had not decided at all. Carrying the descent across targets is not a
   conservative choice, it is a bug: a desk phone refusing WebRTC would leave the
   browser contact behind it an AVP offer it also refuses, with no rung left —
   one contact of an AOR unreachable because another was tried first.
   `restart_ladder/2` rebuilds the offer only when the ladder is not already at
   the top, so the ordinary hunt still reuses the one offer it always did.

Also, the scenario side needed nothing but the question a hunt already asks:
`b2bua_hunting?/0` before concluding on a `>= 300`. `scenarios/webrtc-gw.exs`
was concluding straight away, so it gained that check along with the profile —
and it is the only scenario change P5 made, since it is §12's use case (a),
WebRTC-gateway variant, and had been assuming the phone speaks plain RTP.

Tests: `b2bua_offer_profile_test.exs` (7, session layer — the three offers, the
CSeq bump, `fallback_on`, the `_required` profiles, the ladder bottoming out into
the hunt and restarting for the next target, and the refusals at leg creation),
`webrtc_gw_scenario_test.exs` (2, the shipped scenario end to end), and two in
`mendooze_conn_test.exs` for `rtp_profile:` against the fake JSR309 server.

## What this plan does not do

- **the `_media` siblings of use cases (b), (c) and (d)** (§12) — each is its own
  file and its own piece of work;
- **trunk processes** (`trunk_pid`) — a reachability feature, its own phase;
- **a fallback on an established call** — the ladder is walked while the outbound
  leg is being placed. Re-negotiating a live call's profile is a re-offer
  question (§R4.1b), not this one.
