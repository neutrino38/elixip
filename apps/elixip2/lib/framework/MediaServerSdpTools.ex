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

  The **delegated negotiation** helpers are re-exported too since P8a: the MCU API now
  returns an accepted-PT struct of its own (`StartReceiving`'s `returnVal[2]`), so
  `accepted_pts/2` and `restrict_send_map/3` are no longer JSR-309-only. What is
  deliberately NOT re-exported is `negotiate/3`: intersecting codec lists is exactly
  the job that moved to the media server, and a conference has no list to intersect.
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

  @doc """
  Reduce the server's fmtp-by-payload-type struct to the accepted set.

  Presence of a key **is** the accept signal — a codec with no fmtp is present with an
  empty value, and an absent payload type was filtered. Returns `nil` when the struct
  is `nil` (a media server that predates the delegation), which is what selects the
  legacy client-side path.
  """
  defdelegate accepted_pts(proposed, fmtp_struct), to: Sdp

  @doc """
  Restrict a send `rtpMap` to what the server accepted on receive.

  Keeps us from sending a codec the server just filtered — the symmetric-codec
  assumption, which is what a conference mixer does anyway.
  """
  defdelegate restrict_send_map(send_map, proposed_recv, accepted), to: Sdp
end
