# Mendooze — Delegating SDP Negotiation to the Media Server

Implementation plan for aligning `MediaServer.Mendooze` with the **enriched
`EndpointStartReceiving` return value** of the JSR309 XML-RPC API
([`xmlrpc_jsr309_api.md`](https://github.com/neutrino38/mediaserver/blob/feat/alma_linux9/xmlrpc_jsr309_api.md),
branch `feat/alma_linux9`), so that codec/fmtp negotiation is driven by the
media server instead of hard-coded on the Elixir side.

Status: **plan only** — no code written yet.

---

## 1. What changed in the API (spec §5.2)

`EndpointStartReceiving` gains a second return element. Backward compatibility is
modelled on the "gap sourceName" pattern (API §6.1 — `EventQueueCreate` grew a
`sourceName` as `returnVal[1]`; tolerant clients read it if present, else fall
back).

```
returnVal = [
  int   recvPort,                       // unchanged — existing clients keep working
  struct {                              // NEW: fmtp per accepted payload type
    "<pt>": "<fmtp params>",            // e.g. "96": "profile-level-id=42801f;packetization-mode=1"
    ...
  }
]
```

Rules given by the spec:

- **Key** = payload type (string). **Value** = the fmtp parameters *only*
  (the string that goes after `a=fmtp:<pt> `).
- A proposed PT that is **not supported does not appear** — it was filtered out.
  The SIP controller derives the **actually accepted PTs** from `returnVal[1]`
  (*decision D*).
- A codec **without fmtp** (PCMU, T140…) is **absent from the struct**
  (*decision §8-E*).

The intent: the media server, which knows its own codec/transcoding
capabilities, becomes authoritative for **which payload types are accepted** and
for the **exact fmtp** to advertise (H264 `profile-level-id`/`packetization-mode`,
etc.). Elixip stops guessing these.

---

## 2. How the adapter behaves today (baseline)

- `MediaServer.Mendooze.Conn` builds both local ports and the local SDP:
  - `start_receiving_all/1` calls `EndpointStartReceiving`, keeps only
    `returnVal[0]` (`{:ok, [port | _]}`, `MediaServerMendoozeConn.ex:484`).
  - The offer/answer m= sections are built **entirely client-side** by
    `MediaServer.Mendooze.Sdp` from the local codec tables:
    - offered/accepted codecs come from `conn_opts` (`:audio_codec`,
      `:video_codec`, …) via `codecs/2`.
    - `rtpmap`/`fmtp` lines are synthesized locally: DTMF fmtp `0-16`
      (`Sdp.add_dtmf/2`), RED redundancy fmtp (`Sdp.add_red_fmtp/5`). **No
      H264/opus fmtp is emitted at all today.**
  - UAS answer codec selection is a client-side **codec-name intersection**
    (`Sdp.negotiate/3`).
- `XmlRpc.call/4` already returns the **full `returnVal` list**
  (`{:ok, vals}`), so `returnVal[1]` is available without touching the XML-RPC
  layer — only the callers ignore it.

Consequence today: for codecs that require fmtp (notably H264), the offer/answer
carries no fmtp, which the delegation is meant to fix.

---

## 3. Target behavior

For **each media**, after `EndpointStartReceiving`:

1. Read `recvPort = returnVal[0]` (as today).
2. If `returnVal[1]` is present → build the local m= section from the
   **server-accepted PT set** and attach, per PT, the **fmtp string returned by
   the server** verbatim.
3. If `returnVal[1]` is absent (older server) → **fall back to the current
   fully client-side construction** (no behavioral change).

This applies symmetrically to the offer (UAC, API §9.2 step 4→6) and the answer
(UAS, API §9.1 step 6→10). Because the receive `rtpMap` we send uses the PT
numbering we want published (our own PTs in an offer; the offerer's PTs in an
answer), the struct keys returned by the server are already the correct PT
numbers for the SDP we emit — RFC 3264 answer numbering is preserved for free.

---

## 4. Agreed contract — Option A (server lists every accepted PT)

**Decided (2026-07-15).** The server side (which we maintain) is being changed
so `returnVal[1]` lists **every accepted payload type**, with an **empty string**
for fmtp-less codecs:

```
"0": "", "8": "", "96": "profile-level-id=42801f;packetization-mode=1"
```

This resolves the *decision D* / *§8-E* tension in the cleanest way:

- *Decision D* becomes literally true — `returnVal[1]` **is** the authoritative
  accepted-PT set: **presence of a key = accepted** (fmtp empty or not),
  **absence = filtered**.
- *§8-E* is honored on the wire — an empty value means **no `a=fmtp:` line** is
  emitted for that PT, only its `a=rtpmap:`.

The client therefore needs **no simple/complex classification and no heuristics**:
`Sdp.accepted_pts/2` degenerates to "take the struct as-is". telephone-event and
RED fmtp are **owned by the server** (returned in the struct with server-consistent
PT numbering), so the client stops synthesizing them when the struct is present.

The server-side change is specified for the maintainer in a separate coding
prompt; this plan assumes that contract.

### Remaining client-side decision

- **Send rtpMap coupling**: `EndpointStartSending`'s `rtpMap` (what we send to
  the peer) is **restricted to the server-accepted receive set** — intersect the
  negotiated send map with `returnVal[1]`'s keys so we never send a codec the
  server just filtered on receive. (Symmetric-codec assumption, correct for a
  test tool.)

---

## 5. Module-by-module changes

### 5.1 `MediaServer.Mendooze.XmlRpc` — no change

`call/4` already returns the whole `returnVal`. `returnVal[1]` is reachable by
callers. (We do *not* add a specialized decoder — keep the envelope layer
generic.)

### 5.2 `MediaServer.Mendooze.Sdp` — new server-driven build path

New pure functions (unit-testable, the heart of the change):

- `accepted_pts(proposed_rtp_map, fmtp_struct) :: %{pt_string => fmtp_string} | nil`
  — with the Option A contract this is nearly identity on the struct: keep the
  accepted PTs with their (possibly empty) fmtp, dropping any key never present
  in `proposed_rtp_map` (defensive, logged). Returns `nil` when `fmtp_struct` is
  `nil` (older server → legacy path). `proposed_rtp_map` is passed only for that
  defensive check and to order the PTs (§9 Q3).

- `pt_encoding_info(kind, pt) :: {encoding, clock, channels} | :unknown`
  — reverse lookup PT → SDP rtpmap fields, from the existing codec tables. Used
  because the server returns fmtp only; the client still owns encoding names and
  clock rates. For an **answer**, the encoding is taken from the parsed offer
  (authoritative offerer numbering); for an **offer**, from our tables.

- Extend `media_spec` with an explicit, ordered `pts:` list and a
  `fmtp: %{pt => raw_string}` map, so `build_media/1` emits:
  - `a=rtpmap:<pt> <encoding>/<clock>[/<ch>]` for every accepted PT, and
  - `a=fmtp:<pt> <raw_string>` for every non-empty fmtp entry, using the
    **generic attribute tuple** `{"fmtp", "<pt> <raw>"}`.

  **Verified**: ExSDP serializes `{"fmtp", value}` as `a=fmtp:value`
  (`deps/ex_sdp/lib/ex_sdp/serializer.ex:42` →
  `maybe_serialize(type, {key, value}) -> "#{type}=#{key}:#{value}"`). The
  typed `ExSDP.Attribute.FMTP` struct has no opaque field, so we deliberately
  bypass it to forward the server string verbatim.

- `build_media/1` gains a branch: when `pts:`/`fmtp:` are provided
  (server-driven), use them; otherwise keep the current codec-table path
  (`add_codecs`, `add_dtmf`, `add_red_fmtp`) as the **backward-compat fallback**.

- `negotiate/3` (send-side): intersect the remote descriptor against the
  **server-accepted receive set** for this media rather than the static config
  list (§4 secondary Q3), so the send `rtpMap` never contains a filtered codec.

`local_rtp_map/3` stays as-is: it still builds the *proposed* receive `rtpMap`
(our full candidate set) that we pass to `EndpointStartReceiving`.

### 5.3 `MediaServer.Mendooze.Conn` — thread the fmtp struct through

- `start_receiving_all/1`: capture `returnVal[1]`. Change the match from
  `{:ok, [port | _]}` to bind the optional second element, store per media in a
  new state field `accepted: %{media => %{pt => fmtp}}` (result of
  `Sdp.accepted_pts/2`). Keep working when only `[port]` is returned (store
  `nil` → triggers the fallback).

- `offer_media_spec/2` (UAC): when `state.accepted[media]` is present, build the
  spec from it (`pts:`/`fmtp:`); else fall back to `codecs:` as today.

- `answer_media_spec/3` (UAS): same, but the rtpmap encoding/clock for each
  accepted PT comes from the **parsed offer** (`desc.rtp_map` / rtpmaps) to
  honor RFC 3264 numbering; fmtp from the server.

- `apply_remote_media/1`: derive the `EndpointStartSending` `rtpMap` from the
  intersection of the negotiated send map and `state.accepted[media]`.

- New state field documented in the `Conn` state map (§3.2 of
  `mendooze_interface.md` — update that doc too):
  `accepted: %{(:audio|:video|:text) => %{String.t() => String.t()} | nil}`.

### 5.4 Docs

- Update `docs/mendooze_interface.md` §4.4/§4.6 (offer/answer flows), §6.7 (note
  the enriched return), §8 (codec mapping — the client no longer owns fmtp), and
  the `Conn` state map.

---

## 6. Backward compatibility

Single detection rule, mirrored on the API's own "gap sourceName" tolerance:
**`returnVal[1]` present and a map ⇒ delegated path; absent ⇒ legacy client-side
path.** No config flag, no version negotiation. Both paths remain covered by
tests so a mixed fleet (old/new server) keeps working.

---

## 7. Testing

Pure-function tests (no server), the bulk of the value:

1. `Sdp.accepted_pts/2`
   - server lists a subset of the proposed PTs (mix of empty and non-empty
     fmtp) → exactly those kept, fmtp preserved.
   - `nil` struct → returns `nil` (legacy path).
   - key never present in the proposed rtpMap → ignored + logged.
2. `Sdp.build/1` server-driven:
   - H264 offer carries `a=fmtp:<pt> profile-level-id=…;packetization-mode=1`
     verbatim (round-trip parse asserts the exact string survives).
   - fmtp-less codec (PCMU) → `a=rtpmap` but **no** `a=fmtp` line.
   - audio+video, offer and answer, RFC 3264 answer PT numbering preserved.
3. Fallback: absent `returnVal[1]` reproduces today's output byte-for-byte
   (guard against regressions).

Fake-server integration (existing harness, `test/…mendooze…`):

4. `EndpointStartReceiving` stub returns `[port, fmtpStruct]`; assert the built
   offer/answer + that the `EndpointStartSending` `rtpMap` is restricted to the
   accepted set.

Real server E2E (`test/mendooze_integration_test.exs`, gated on `MENDOOZE_URL`):

5. H264 audio+video offer/answer loopback; assert media flows and the negotiated
   fmtp is the server's.

---

## 8. Phasing (each phase compiles + is committable)

1. **Sdp — accepted_pts + server-driven build path** (+ fallback), pure tests.
   The isolated §4 decision lives here. **DONE** (commit `e817710`).
2. **Conn — thread `returnVal[1]`** into `accepted`, wire offer/answer specs and
   the send-map intersection; fake-server tests. **DONE** — `proposed_recv`/
   `accepted` state fields, delegated offer/answer builders + `restrict_send_map`
   on `EndpointStartSending`; fake-server tests in `test/mendooze_conn_test.exs`.
3. **Docs** — update `mendooze_interface.md`; add the enriched return to the
   `EndpointStartReceiving` mapping.
4. **Real-server E2E** — H264 delegated negotiation behind `MENDOOZE_URL`.

---

## 9. Open questions

The design-defining question ("Option A vs B") is **resolved** — Option A, see §4.
The server-side contract (telephone-event and RED fmtp owned by the server, with
consistent PT numbering) is pinned in the maintainer's coding prompt. Only one
client-side detail remains:

- **Q (minor)**: PT ordering. XML-RPC structs are unordered, so the client
  imposes the m= `fmt` order from the **proposed rtpMap** (offer: our preference
  order; answer: the offerer's order) rather than from `returnVal[1]`'s key
  iteration. No server confirmation needed.
