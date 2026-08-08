# Linphone H.264 interop: video never decodes when we replay a file

Investigation record, 2026-08-06 → 2026-08-08. Status: **cause isolated to the
Linphone client, not reproducible outside it, reported upstream.**

A call from Linphone Desktop to a scenario that replays an MP4 shows no video at
all. Audio is fine. Every keyframe we send is rejected by the client's decoder,
and the connection never recovers.

This document records the method, because the same trap will catch the next
person: several of *our own* defects sat on top of the client one and each
looked like the explanation until it was tested and eliminated.

## 1. Symptom, as the client reports it

Per call, in the Linphone log:

- one `DecodeFrame2 failed: 0x4` (dsBitstreamError) **per keyframe received** —
  the count matches exactly, across every test file;
- then a continuous stream of `DecodeFrame2 failed: 0x10` (dsNoParamSets), one
  per picture: no SPS was ever absorbed, so the P slices have no reference;
- no `First video frame decoded successfully`;
- the client asks for a keyframe by PLI, gets an intact one, and fails again.

Nothing is lost in transit. oRTP's own end-of-call counters, video session:

    received                                    221 packets / 217525 bytes
    incoming delivered to the app            217525 bytes
    incoming cumulative lost                      0 packets
    incoming received too late                    0 packets
    incoming discarded (queue overflow)           0 packets

The one exception that made the mechanism legible: a file that **changes
resolution mid-stream**. Its first keyframe is rejected like all the others, and
its second one — carrying a *different* SPS — decodes immediately. Recovery
happens only on a differing SPS; an identical SPS is rejected again, forever.

## 2. Our own defects, found on the way

They mattered because each masked or mimicked the client bug. All four are
fixed; the first two are the reason the client bug was invisible for so long.

| defect | effect | fixed in |
|---|---|---|
| `:ice_connected` was emitted per *connection*, on the first media to latch | the player started on the audio latch while the video leg was unlatched, so the opening keyframe went to the SDP address and was lost | `docs/design/media-connectivity.md` |
| `a=rtcp-fb` was answered only under an `…F` profile | Linphone offers `RTP/SAVP` while asking for `ccm fir`/`nack pli`; refusing them cost the call its keyframe-request path (it fell back to SIP INFO) | `MediaServerMendoozeConn.ex`, `mcu/adapter/conn.ex` |
| `play.exs` waited for `:player_stopped` | an event that does not exist in the contract, so end-of-file never hung up | `apps/elixip2/scenarios/play.exs` |
| a UAS could not originate an in-dialog request | the BYE at end of file raised, then addressed itself wrongly | `SIPDialogImpl.address_in_dialog/2` |

**The irony worth remembering**: fixing the NAT latch is what exposed the client
bug. Before it, the opening keyframe was thrown away by the NAT, the decoder
started on P slices, failed harmlessly, and absorbed the *next* keyframe. Every
playback that "worked" worked by accident.

## 3. Method: one variable per file

The failing keyframe in the original recording was simultaneously the largest,
the one carrying an SEI, and the one changing resolution. Nothing could be
concluded from it. Each hypothesis therefore got a file that isolates it, all
640x480 H.264 Constrained Baseline 3.1, 25 fps, one slice per picture, all
decoding cleanly under ffmpeg.

Files live in `~/diag-linphone-20260807/h264-tests/` and in
`/var/lib/kelixip/rec/` on the dev host.

| file | isolates | outcome |
|---|---|---|
| `A.mp4` | **access-unit size** — IDRs 8368→12021 B, constant resolution | fails |
| `A2.mp4` | **is anything playing at all** — `A` plus an audio track whose tone steps 100 Hz per second | control |
| `B.mp4` | **mid-stream resolution change** — 640x480 → 480x360 at 4 s, IDRs 3866 and 2737 B | 1st keyframe fails, 2nd decodes |
| `C.mp4` | **control**, constant resolution, IDRs 3866→5575 B | fails |
| `D.mp4` | **NAL size / FU-A** — `slice-max-size=1200`, no NAL above 1192 B, so **no FU-A at all** | fails |
| `E.mp4` | **pins a size threshold** — ten 2-second GOPs, keyframes shrinking 9019 → 3753 B | fails throughout |
| `F.mp4` | **the x264 SEI** — `C` with `filter_units=remove_types=6`, byte-identical otherwise | fails identically to `C` |

What each eliminated:

- **NAL size and FU-A** — `D` carries no fragmented NAL at all and fails just the
  same. The FU-A reassembly path is not the trigger.
- **Access-unit size** — `E` sweeps 9019 → 3753 B without ever decoding, while a
  4287 B access unit decoded in an earlier call. Non-monotonic, so not size.
  (This one cost three test rounds: the first six data points *were* monotonic
  and produced a plausible [4287, 4517] bracket. It was a coincidence.)
- **The SEI** — `F` versus `C`, identical failure.
- **Resolution and profile** — `B` and `C` carry byte-identical SPS
  (`67 42 c0 1f d9`); one recovers, the other never does.
- **Transport** — 0 loss, 0 reorder, 0 discard, marker bit and FU-A S/E bits and
  RTP timestamps all verified correct on the wire.

## 4. Harnesses

Three, in increasing fidelity. All in `~/diag-linphone-20260807/harness/`.

**(a) Whole-stream decode.** OpenH264's reference decoder (`h264dec`, built from
`cisco/openh264` v2.4.1) on the Annex-B extracted from each `.mp4`. `C.mp4`:
200 frames, 640x480, zero errors. Exonerates the file and the decoder.

**(b) Wire reassembly, in Python.** RTP payloads pulled from the capture with
`tshark`, then NAL reassembly following mediastreamer2's own
`NalUnpacker::feed` and `H264FuaAggregator::feed` — including its
`fu_header & 0x17` mask — then `MSOpenH264Decoder::nalusToFrame` (start-code
prefixing, the extra leading zero for the first NAL and for SEI/SPS/PPS). Output
`c_wire.264` decodes clean: 121 frames, zero errors. Exonerates the wire bytes
and the published depacketizer logic.

**(c) One access unit per `DecodeFrame2` call** — `harness.cpp`, the way
`MSOpenH264Decoder::feed` actually drives the decoder, with its init parameters
(`uiTargetDqLayer = -1`, `eEcActiveIdc = ERROR_CON_FRAME_COPY_CROSS_IDR`,
`eVideoBsType = VIDEO_BITSTREAM_AVC`), fed `c_aus.bin` — the real access units
from the capture:

    total AU=121   images out=120   errors=0

Identical with OpenH264 **2.1.1** and **2.4.1** (`harness211.cpp`), so the
bundled decoder version is not the variable either.

Rebuild:

    g++ -o harness harness.cpp -I <openh264> -I <openh264>/codec/api/wels \
        -L <openh264> -ldecoder -lcommon -lpthread

## 5. Where that leaves it

Every layer we can inspect is correct: our bitstream, our RTP, mediastreamer2's
published depacketizer, `nalusToFrame`, and OpenH264 across two versions. The
failure is in the binary Linphone Desktop ships — reproduced on **6.1.2** and
**6.2.0** (both bundling LinphoneSDK 5.5.9), never reproduced offline.

A Linphone-to-Linphone call never exercises this: the encoder caps every NAL at
`ms_factory_get_payload_max_size()` = `mtu - 60` = 1240 B by default
(`msopenh264enc.cpp`, `params.uiMaxNalSize`), so it never emits a fragmented NAL.
Only an external peer — a media server replaying a file, a gateway, a camera —
does. Browser and Electron clients decode the same streams without trouble.

Ticket drafted in `~/diag-linphone-20260807/UPSTREAM-TICKET.md`, to be filed on
`gitlab.linphone.org/BC/public/mediastreamer2` (the GitHub repositories are
read-only mirrors). Attachments assembled next to it: the capture, the four
Linphone logs, the seven test files, the harnesses.

## 6. Latent bug found while reading, not the cause

`mediastreamer2/src/videofilters/h26x/h264-nal-unpacker.cpp`,
`H264FuaAggregator::feed`:

```c
type = fu_header & 0x17;   // the NAL type field is 5 bits: should be 0x1F
```

The mask clears bit 3, so a fragmented NAL of type 8-15 is rebuilt with the wrong
type. Harmless for types 1 and 5, which is all our streams carry. Reported in the
same ticket, clearly separated.

## 7. If you pick this up again

- Do not trust a monotonic pattern over six points. Build the file that breaks
  it before building anything on top of it.
- Ask for the client log before designing the next test. The error *code*
  (`0x4` vs `0x10` vs none) says which layer dropped the frame, and it is one
  line to obtain.
- The count of `0x4` errors equals the number of keyframes received. That
  invariant held across every call and is the fastest way to confirm you are
  still looking at the same defect.
- Related records: `docs/design/media-connectivity.md` (the latch fix and the
  event contract), `docs/design/mcu_module.md` §6.3.1 (the `a=rtcp-fb` deviation).
