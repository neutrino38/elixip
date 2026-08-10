defmodule SIP.B2bua.Profile do
  @moduledoc """
  Offer profiles and the fallback ladder (design §7.5, P5).

  A profile says how the media we offer the callee is *carried* — WebRTC's
  DTLS-SRTP/SAVPF over ICE, the plain-RTP feedback profile, or plain RTP. It is
  only meaningful with `{:mediaserver, …}`: choosing a profile means generating
  an offer, and a signalling relay forwards the caller's.

      %SIP.B2bua.Peer{profile: :webrtc_if_supported}

  The ladder is `webrtc → avpf → avp`, and an `_if_supported` profile walks down
  it when the callee refuses (`%Peer{fallback_on:}`, 488 by default). A
  `_required` one has a single rung: its refusal is the attempt's answer.

  `nil` — the default — is **not** a rung. It means the ladder is not in play at
  all: the offer is built from the peer's `outbound:` media options exactly as it
  was before P5, which is what keeps every scenario written before it unchanged.
  """

  @type rung :: :webrtc | :avpf | :avp
  @type t ::
          nil
          | :webrtc_required
          | :webrtc_if_supported
          | :avpf_required
          | :avpf_if_supported
          | :avp

  @ladder [:webrtc, :avpf, :avp]

  @doc """
  The rungs a profile will try, in order. `[]` for `nil` (P5 not in play).

  A `_required` profile stops at its own rung; an `_if_supported` one continues
  down the ladder. `:avp` is the bottom, so it has nothing below it either way.
  """
  @spec ladder(t()) :: [rung()]
  def ladder(nil), do: []
  def ladder(:webrtc_required), do: [:webrtc]
  def ladder(:avpf_required), do: [:avpf]
  def ladder(:avp), do: [:avp]
  def ladder(:webrtc_if_supported), do: @ladder
  def ladder(:avpf_if_supported), do: [:avpf, :avp]
  def ladder(_other), do: []

  @doc """
  Is this a profile we know? Used at leg creation, so an unknown one is refused
  where it was written rather than silently offering something else.
  """
  @spec valid?(term()) :: boolean()
  def valid?(nil), do: true

  def valid?(profile) when is_atom(profile) do
    profile in [:webrtc_required, :webrtc_if_supported, :avpf_required, :avpf_if_supported, :avp]
  end

  def valid?(_other), do: false

  @doc """
  The media-connection options that produce this rung's offer.

  Merged **over** the peer's own `outbound:` options: the scenario says which
  medias and codecs it wants, the profile says how they are carried.
  """
  @spec conn_opts(rung()) :: keyword()
  def conn_opts(:webrtc), do: [webrtc: :yes]
  def conn_opts(:avpf), do: [webrtc: :no, rtp_profile: :avpf]
  def conn_opts(:avp), do: [webrtc: :no, rtp_profile: :avp]
end
