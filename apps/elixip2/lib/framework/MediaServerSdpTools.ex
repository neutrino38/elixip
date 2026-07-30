defmodule MediaServer.SdpTools do
  @moduledoc """
  Adapter-neutral name for the SDP offer/answer helpers.

  The functions live in `MediaServer.Mendooze.Sdp` for historical reasons — they
  were written with the JSR-309 adapter — but nothing in them is JSR-309 specific:
  parsing an offer, intersecting codecs, building an answer and rendering ICE
  candidates are the same work for any adapter. The Medooze **MCU** adapter
  (`Kelix.Mod.Mcu.Adapter`) needs exactly these, and `alias
  MediaServer.Mendooze.Sdp` there would claim a dependency on the *other* API.

  So this is a rename with no move and no behaviour change (design
  `docs/design/mcu_module.md` §6.3): new adapters use this name, the JSR-309 one
  keeps calling its own module directly, and the codec tables stay in one place.

  Only the answerer-side subset is re-exported. Everything about the delegated
  negotiation of the JSR-309 path (`accepted_pts/2`, `restrict_send_map/3`) stays
  where it is used — the MCU API returns no accepted-PT struct yet (G1).
  """

  alias MediaServer.Mendooze.Sdp

  @doc "Parse a remote SDP into per-media descriptors. See `MediaServer.Mendooze.Sdp.parse/1`."
  defdelegate parse(sdp), to: Sdp

  @doc "Build an SDP (offer or answer) from a media spec list. See `MediaServer.Mendooze.Sdp.build/1`."
  defdelegate build(spec), to: Sdp

  @doc "Intersect a remote media descriptor with our codec list. See `MediaServer.Mendooze.Sdp.negotiate/3`."
  defdelegate negotiate(desc, our_names, want_dtmf), to: Sdp

  @doc "The `rtpMap` struct for our own payload-type numbering."
  defdelegate local_rtp_map(kind, codec_names, dtmf), to: Sdp

  @doc "Ordered answer `rtpmap` entries in the offerer's payload-type numbering (RFC 3264)."
  defdelegate answer_rtpmaps(media, negotiated), to: Sdp

  @doc "Local ICE host candidates for one media."
  defdelegate host_candidates(ip, port, rtcp_mux?), to: Sdp

  @doc "Answer-side `b=AS:` negotiation (cap ours to the offered value)."
  defdelegate negotiate_bandwidth(offered, ours), to: Sdp

  @doc "The direction an answer must declare for an offered direction (RFC 3264 §6.1)."
  defdelegate reverse_direction(direction), to: Sdp

  @doc "SDP `rtpmap` fields for a Medooze codec constant."
  defdelegate code_rtpmap(media, code), to: Sdp
end
