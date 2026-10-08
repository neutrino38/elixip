# Screen sharing and Unified Plan

A browser sharing its screen next to its camera offers **two `m=video`
sections** in one SDP, grouped on one transport (`a=group:BUNDLE`, RFC 8843).
kelixip takes that offer as the browser sends it, with its default settings, on
both media paths:

- a **conference** (the `mcu` module): the screen is one more tile of the
  mosaic;
- a **point-to-point call through the media server** (JSR-309, the B2BUA
  scripts such as `direct-call-with-auth-and-media.exs`): the screen is relayed
  to the other leg.

There is nothing to configure and nothing to write in a script: a leg that
answers video takes every video section it is offered. It needs a **media
server 1.17.0 or later**: the `version` column of `kelictl mediaserver list`
says what each one runs. The design and its remaining lots are in
[`docs/conception/UNIFIED-PLAN/SPEC.md`](../conception/UNIFIED-PLAN/SPEC.md).

## What a call does

| The browser | kelixip |
|---|---|
| starts a share: a new `m=video` section, `a=sendonly`, usually `a=content:slides` | answers it `a=recvonly` on its port: a stream of its own, received only. kelixip never sends anything on it |
| stops the share: the **same** section turned `a=inactive` | answers `a=inactive` on its port. The stream is **paused**, not withdrawn |
| shares again: the same section back to `a=sendonly` | answers `a=recvonly`: the same stream resumes. No new stream, no new tile |
| withdraws the section: port 0 in a re-offer | deletes the stream |

A paused stream is never declined with port 0: that stops the browser's
transceiver (RFC 9429 §5.10), and the browser cannot share on that section
again. This is also what a browser answers another browser, with nothing in
between (reference traffic of 2026-10-08, Trix to Trix through
`direct-call-with-auth.exs`).

A re-offer, from either side, keeps the leg's ICE credentials: adding or
pausing a share is not an ICE restart.

### In a conference

- The screen takes **a tile of its own** in mosaic 0, named after the
  participant: `name (écran)`.
- In a VAD layout the tile is **pinned**: a screen never speaks, so without the
  pin the first speaker would push it out of the mosaic.
- The automatic layout (`layout_comp = "auto"`) counts **video sources**, not
  participants: one participant with a camera and a screen is two tiles.
- A withdrawn screen frees its tile; the end of the call removes everything.

### Through the B2BUA

- The screen is relayed to the other leg **as it is**, under the same `a=mid`,
  with exactly the codecs of the received stream. There is no transcoding of a
  shared screen: a peer that takes none of those codecs gets the section
  declined (port 0), and the call goes on with audio, camera and text.
- The relayed section follows its source: `a=inactive` while the share is
  paused, port 0 once withdrawn. The far browser mutes the remote track on
  `inactive` and drops it on port 0.
- Both directions work: the callee's share is re-offered to the caller with
  every section the caller's session already has, in the caller's order and
  under the caller's `mid`s.

## Limits

- A stream beyond the camera is **received only**. kelixip never offers a
  second video itself: a SIP endpoint called by kelixip is offered one camera.
- A second `m=audio` or `m=text` section is declined, as before.
- BUNDLE is taken **at the first offer** of the leg. A group offered only at a
  renegotiation is not taken, and the sections that exist only inside it
  (`a=bundle-only`, port 0) are declined. A browser with default settings
  bundles from its first offer, so this only shows with a client that changes
  its `bundlePolicy` mid-call.
- A partial group (some RTP sections outside the BUNDLE) is not taken: the
  sections outside it are declined.
- An extra video section encrypted with SDES alone is declined. Browsers use
  DTLS.
- No simulcast (`a=rid`, `a=simulcast`).
- No BFCP document sharing for a SIP endpoint (RFC 4582): the design covers
  it, the lot is not delivered.

## When it does not work

- **The screen never shows, the call is otherwise fine.** Read the answer in
  the journal: a screen section declined with port 0 on the first offer means
  the media server did not take the group, or has no `CreateVideoStream`. The
  node then serves the call unbundled, camera and audio only. A media server
  before 1.17.0 does exactly that: check the `version` column of `kelictl
  mediaserver list`.
- **The second share never arrives.** The browser gave up after a port 0
  answer to its first stop. A node before 1.6.4 answered that way; so does a
  peer that is not kelixip.
- **The SDP in the log has no screen section.** `/var/log/kamailio.log`
  truncates each line at 8 132 bytes, and a re-offer with four sections loses
  its last one. The journal keeps everything:

```sh
journalctl -u kelixip -o cat
```
