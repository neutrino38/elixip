defmodule MediaServer.Mendooze.Sdp do
  @moduledoc """
  SDP offer/answer helpers for the Mendooze JSR309 adapter.

  Pure functions bridging SDP (via `ExSDP`) and the JSR309 RPC arguments:

  - codec tables translating SDP `rtpmap` entries to Mendooze codec constants
    (`AudioCodec::Type` / `VideoCodec::Type` from `codecs.h`)
  - `local_rtp_map/3` — the `rtpMap` struct for `EndpointStartReceiving`
  - `build/1` — offer or answer SDP construction (RTP clear, SDES or DTLS+ICE)
  - `parse/1` — remote SDP decomposition into per-media descriptors
  - `negotiate/3` — codec intersection and the `rtpMap` for
    `EndpointStartSending` (remote payload type numbering)
  - `parse_media_candidate/1` — decode the `rtp://ip:port` string returned by
    `GetMediaCandidates`

  In a JSR309 `rtpMap`, each key is a payload type (string) and each value a
  Mendooze codec constant (integer); the receive map (what we accept) and the
  send map (what was negotiated) may differ.

  ## Delegated SDP negotiation

  Since the enriched `EndpointStartReceiving` return, the media server is
  authoritative for the accepted payload types and their fmtp parameters (see
  `docs/mendooze_sdp_delegation_plan.md`). `accepted_pts/2` reduces the server
  struct to the accepted set; `pt_rtpmap/2` / `code_rtpmap/2` resolve the SDP
  `rtpmap` fields for a payload type (the server returns fmtp only, so the
  encoding name and clock still come from the local codec tables); and the
  `:rtpmaps`/`:fmtp` variant of `media_spec` feeds `build/1` the server-driven
  codec section. `restrict_send_map/3` keeps the send map in sync with what the
  server accepted on receive.
  """

  require Logger
  import Bitwise

  # ── Codec tables ────────────────────────────────────────────────────────────
  # name => {default payload type for our offers, mendooze code, clock, channels}
  # For dynamic codecs the Mendooze constant doubles as our default PT.

  @audio_codecs %{
    "PCMU" => {0, 0, 8000, 1},
    "PCMA" => {8, 8, 8000, 1},
    "G722" => {9, 9, 8000, 1},
    "OPUS" => {98, 98, 48_000, 2}
  }

  @video_codecs %{
    "H264" => {99, 99, 90_000},
    "VP8" => {107, 107, 90_000}
  }

  @text_codecs %{
    "T140" => {106, 106, 1000},
    "T140RED" => {105, 105, 1000}
  }

  # RFC 3551 static payload types, usable without an a=rtpmap line
  @static_pt %{0 => "PCMU", 8 => "PCMA", 9 => "G722"}

  # telephone-event (RFC 4733): conventional PT 101, Mendooze TELEPHONE_EVENT
  @dtmf_pt 101
  @dtmf_code 100
  @dtmf_tones "0-16"

  @type codec_name :: String.t()
  @type rtp_map :: %{String.t() => integer()}

  @type crypto ::
          :none
          | {:dtls, setup :: :active | :passive | :actpass, hash :: String.t(),
             fingerprint :: String.t()}
          | {:sdes, suite :: String.t(), key :: String.t()}

  @typedoc """
  One ICE host candidate, as produced by `host_candidates/3` and rendered into
  an `a=candidate` line by `build/1`. Component 1 carries RTP, component 2 RTCP
  (only synthesized when rtcp-mux is not negotiated).
  """
  @type candidate :: %{
          foundation: String.t(),
          component: 1 | 2,
          protocol: :udp,
          priority: non_neg_integer(),
          ip: String.t(),
          port: non_neg_integer(),
          type: :host
        }

  @typedoc """
  One parsed `m=` section of a remote SDP.

  `rtp_map` maps the remote payload types (strings) to Mendooze codec codes —
  restricted to codecs we know. `dtmf_pts` maps each offered telephone-event
  clock rate to its payload type (Chrome offers one PT per clock, e.g.
  `%{48000 => 110, 8000 => 126}`); empty when none is offered. `bandwidth` is
  the `b=AS:` value in kb/s, if present.

  `supported?` is `true` for a media we can answer with real media (an
  `audio`/`video`/`text` section carried over an RTP profile). Sections we
  cannot answer — an unknown media type or a non-RTP transport — are returned
  as `supported?: false` stubs (G9), carrying only `type`, `port`, `protocol`
  and `raw_fmt` so the answerer can emit a port-0 rejection (RFC 3264 §6).
  `raw_fmt` is the offered format list verbatim, echoed back in that rejection.
  """
  @type media_desc :: %{
          supported?: true,
          type: :audio | :video | :text,
          ip: String.t() | nil,
          port: non_neg_integer(),
          protocol: String.t(),
          raw_fmt: [0..127] | String.t(),
          rtp_map: rtp_map(),
          codecs: [codec_name()],
          dtmf_pts: %{optional(non_neg_integer()) => non_neg_integer()},
          rtcp_mux: boolean(),
          direction: :sendrecv | :sendonly | :recvonly | :inactive,
          bandwidth: non_neg_integer() | nil,
          crypto: crypto(),
          ice: nil | %{ufrag: String.t(), pwd: String.t()},
          mid: String.t() | nil,
          rtcp_fb: %{optional(integer()) => [String.t()]},
          candidates: [String.t()]
        }

  @typedoc """
  A `supported?: false` stub for an `m=` section we cannot answer (G9): only the
  fields needed to echo a port-0 rejection are kept.
  """
  @type media_stub :: %{
          supported?: false,
          type: atom(),
          port: non_neg_integer(),
          protocol: String.t(),
          raw_fmt: [0..127] | String.t()
        }

  @typedoc """
  One `m=` section to build. `:crypto` carries the *local* material: the DTLS
  setup role (`:actpass` in an offer, `:active`/`:passive` in an answer), our
  fingerprint, or our SDES key. `:protocol` overrides the one derived from
  `:crypto` (useful in answers, to mirror the offer). `:bandwidth` emits a
  `b=AS:` line when positive; `:direction` defaults to `:sendrecv`.

  The codec section is given **either** by `:codecs` (legacy, client-side codec
  tables synthesize the `rtpmap`/`fmtp` lines) **or** by `:rtpmaps` + `:fmtp`
  (server-driven: the ordered `rtpmap` entries are emitted verbatim and each
  non-empty `:fmtp` string becomes an `a=fmtp:<pt> <string>` line). When both
  are present the server-driven fields win.

  A **rejection** spec (`:reject_fmt` present) renders `m=<type> 0 <protocol>
  <reject_fmt>` with no attributes (G9): a declined section that keeps the m=
  line count of the offer (RFC 3264 §6).
  """
  @type rtpmap_entry :: %{
          required(:pt) => non_neg_integer(),
          required(:encoding) => String.t(),
          required(:clock) => non_neg_integer(),
          optional(:channels) => non_neg_integer() | nil
        }

  @type media_spec :: %{
          required(:type) => :audio | :video | :text,
          required(:port) => non_neg_integer(),
          optional(:codecs) => [codec_name()],
          optional(:rtpmaps) => [rtpmap_entry()],
          optional(:fmtp) => %{optional(String.t()) => String.t()},
          optional(:dtmf) => boolean(),
          optional(:crypto) => crypto(),
          optional(:ice) => nil | %{ufrag: String.t(), pwd: String.t()},
          optional(:rtcp_mux) => boolean(),
          optional(:protocol) => String.t(),
          optional(:bandwidth) => non_neg_integer() | nil,
          optional(:direction) => :sendrecv | :sendonly | :recvonly | :inactive,
          optional(:mid) => String.t() | nil,
          optional(:candidates) => [candidate()],
          optional(:rtcp_fb) => boolean(),
          optional(:reject_fmt) => [0..127] | String.t()
        }

  # ── rtpMap for EndpointStartReceiving ───────────────────────────────────────

  @doc """
  Build the receive `rtpMap` (our payload-type numbering) for the given codec
  names. Raises on an unknown codec name — that is a configuration error.

      iex> MediaServer.Mendooze.Sdp.local_rtp_map(:audio, ["PCMU", "PCMA"], true)
      %{"0" => 0, "8" => 8, "101" => 100}
  """
  @spec local_rtp_map(:audio | :video | :text, [codec_name()], boolean()) :: rtp_map()
  def local_rtp_map(kind, codec_names, dtmf \\ false) do
    base =
      Map.new(codec_names, fn name ->
        {pt, code} = codec_pt_code(kind, name)
        {Integer.to_string(pt), code}
      end)

    if dtmf and kind == :audio do
      Map.put(base, Integer.to_string(@dtmf_pt), @dtmf_code)
    else
      base
    end
  end

  defp codec_pt_code(:audio, name) do
    case Map.fetch(@audio_codecs, String.upcase(name)) do
      {:ok, {pt, code, _clock, _ch}} -> {pt, code}
      :error -> raise ArgumentError, "unknown audio codec #{inspect(name)}"
    end
  end

  defp codec_pt_code(:video, name) do
    case Map.fetch(@video_codecs, String.upcase(name)) do
      {:ok, {pt, code, _clock}} -> {pt, code}
      :error -> raise ArgumentError, "unknown video codec #{inspect(name)}"
    end
  end

  defp codec_pt_code(:text, name) do
    case Map.fetch(@text_codecs, String.upcase(name)) do
      {:ok, {pt, code, _clock}} -> {pt, code}
      :error -> raise ArgumentError, "unknown text codec #{inspect(name)}"
    end
  end

  defp codec_code(:audio, name) do
    case Map.fetch(@audio_codecs, String.upcase(name)) do
      {:ok, {_pt, code, _clock, _ch}} -> {:ok, code}
      :error -> :error
    end
  end

  defp codec_code(:video, name) do
    case Map.fetch(@video_codecs, String.upcase(name)) do
      {:ok, {_pt, code, _clock}} -> {:ok, code}
      :error -> :error
    end
  end

  defp codec_code(:text, name) do
    case Map.fetch(@text_codecs, String.upcase(name)) do
      {:ok, {_pt, code, _clock}} -> {:ok, code}
      :error -> :error
    end
  end

  # ── SDP construction ────────────────────────────────────────────────────────

  @doc """
  Build an SDP (offer or answer — the difference lives in the `media_spec`
  crypto/protocol fields) and return it as a string.

  `ip` is the local media address, as returned by `GetMediaCandidates`
  (string) or as a tuple.
  """
  @spec build(%{
          required(:ip) => String.t() | :inet.ip_address(),
          required(:medias) => [media_spec()],
          optional(:ice_lite) => boolean()
        }) ::
          String.t()
  def build(%{ip: ip, medias: medias} = spec) do
    addr = to_addr(ip)

    cnx = %ExSDP.ConnectionData{
      ttl: nil,
      address_count: nil,
      network_type: "IN",
      address: addr
    }

    sdp =
      ExSDP.new(
        version: 0,
        username: "Elixip2",
        session_id: :erlang.unique_integer([:positive, :monotonic]),
        session_version: 1,
        address: addr
      )
      |> Map.put(:connection_data, cnx)
      |> add_ice_lite(Map.get(spec, :ice_lite, false))

    medias
    |> Enum.reduce(sdp, fn mspec, acc -> ExSDP.add_media(acc, build_media(mspec)) end)
    |> to_string()
  end

  # G9: a port-0 rejection echoes the offered transport and format list verbatim
  # (RFC 3264 §6). No connection/attributes/codec section — the peer just sees
  # the media declined while the answer keeps one m= line per offered m=.
  defp build_media(%{reject_fmt: fmt, type: type, protocol: protocol}) do
    %ExSDP.Media{type: type, port: 0, protocol: protocol, fmt: fmt}
  end

  # Server-driven codec section: emit the accepted rtpmap entries and the fmtp
  # strings returned by the media server verbatim.
  defp build_media(%{type: type, port: port, rtpmaps: rtpmaps} = mspec) do
    crypto = Map.get(mspec, :crypto, :none)
    protocol = Map.get(mspec, :protocol, protocol_for(crypto))
    fmtp = Map.get(mspec, :fmtp, %{})
    video_pts = if type == :video, do: Enum.map(rtpmaps, & &1.pt), else: []

    %ExSDP.Media{type: type, port: port, protocol: protocol, fmt: []}
    |> add_bandwidth(Map.get(mspec, :bandwidth))
    |> add_server_codecs(rtpmaps, fmtp)
    |> ExSDP.add_attribute(Map.get(mspec, :direction, :sendrecv))
    |> add_crypto(crypto)
    |> add_ice(Map.get(mspec, :ice))
    |> add_rtcp_mux(Map.get(mspec, :rtcp_mux, false))
    |> add_transport_plane(mspec, video_pts)
  end

  # Legacy client-side codec section (fallback when the server does not return
  # the enriched fmtp struct).
  defp build_media(%{type: type, port: port, codecs: codecs} = mspec) do
    crypto = Map.get(mspec, :crypto, :none)
    protocol = Map.get(mspec, :protocol, protocol_for(crypto))
    dtmf = Map.get(mspec, :dtmf, false) and type == :audio

    video_pts =
      if type == :video do
        Enum.map(codecs, fn name -> elem(codec_pt_code(type, name), 0) end)
      else
        []
      end

    %ExSDP.Media{type: type, port: port, protocol: protocol, fmt: []}
    |> add_bandwidth(Map.get(mspec, :bandwidth))
    |> add_codecs(type, codecs)
    |> add_dtmf(dtmf)
    |> ExSDP.add_attribute(Map.get(mspec, :direction, :sendrecv))
    |> add_crypto(crypto)
    |> add_ice(Map.get(mspec, :ice))
    |> add_rtcp_mux(Map.get(mspec, :rtcp_mux, false))
    |> add_transport_plane(mspec, video_pts)
  end

  # WebRTC transport-plane attributes shared by both codec-section branches:
  # a=mid (mirrored), a=candidate lines, and per-video-PT a=rtcp-fb.
  defp add_transport_plane(m, mspec, video_pts) do
    m
    |> add_mid(Map.get(mspec, :mid))
    |> add_candidates(Map.get(mspec, :candidates, []))
    |> add_rtcp_fb(Map.get(mspec, :rtcp_fb, false), video_pts)
  end

  defp add_mid(m, nil), do: m
  defp add_mid(m, mid), do: ExSDP.add_attribute(m, {:mid, to_string(mid)})

  defp add_candidates(m, candidates) do
    Enum.reduce(candidates, m, fn cand, acc ->
      ExSDP.add_attribute(acc, {"candidate", candidate_line(cand)})
    end)
  end

  # a=rtcp-fb: three feedback types per video payload type (nack, ccm fir,
  # goog-remb). Emitted verbatim as generic attributes so the wording matches
  # the browser-validated Java gateway exactly.
  defp add_rtcp_fb(m, false, _pts), do: m
  defp add_rtcp_fb(m, true, []), do: m

  defp add_rtcp_fb(m, true, pts) do
    Enum.reduce(pts, m, fn pt, acc ->
      acc
      |> ExSDP.add_attribute({"rtcp-fb", "#{pt} nack"})
      |> ExSDP.add_attribute({"rtcp-fb", "#{pt} ccm fir"})
      |> ExSDP.add_attribute({"rtcp-fb", "#{pt} goog-remb"})
    end)
  end

  defp add_ice_lite(sdp, false), do: sdp
  defp add_ice_lite(sdp, true), do: ExSDP.add_attribute(sdp, :ice_lite)

  defp add_server_codecs(m, rtpmaps, fmtp) do
    Enum.reduce(rtpmaps, m, fn entry, acc ->
      acc
      |> ExSDP.add_attribute(%ExSDP.Attribute.RTPMapping{
        payload_type: entry.pt,
        encoding: entry.encoding,
        clock_rate: entry.clock,
        params: Map.get(entry, :channels)
      })
      |> add_server_fmtp(entry.pt, Map.get(fmtp, Integer.to_string(entry.pt)))
      |> append_pt(entry.pt)
    end)
  end

  # A fmtp-less codec (empty string per decision §8-E, or missing) emits no
  # a=fmtp line; otherwise forward the server string verbatim (ExSDP renders a
  # {"fmtp", val} tuple as `a=fmtp:val`).
  defp add_server_fmtp(m, _pt, nil), do: m
  defp add_server_fmtp(m, _pt, ""), do: m
  defp add_server_fmtp(m, pt, params), do: ExSDP.add_attribute(m, {"fmtp", "#{pt} #{params}"})

  defp add_bandwidth(m, bw) when is_integer(bw) and bw > 0,
    do: Map.put(m, :bandwidth, [%ExSDP.Bandwidth{type: :AS, bandwidth: bw}])

  defp add_bandwidth(m, _), do: m

  # Default transport per security stack; answers should mirror the offer via
  # the :protocol override instead.
  defp protocol_for(:none), do: "RTP/AVP"
  defp protocol_for({:sdes, _, _}), do: "RTP/SAVP"
  # G4: JSEP requires UDP/TLS/RTP/SAVPF in WebRTC offers. Answers mirror the
  # offer's protocol string through the :protocol override instead.
  defp protocol_for({:dtls, _, _, _}), do: "UDP/TLS/RTP/SAVPF"

  defp add_codecs(m, type, codecs) do
    Enum.reduce(codecs, m, fn name, acc ->
      {pt, _code} = codec_pt_code(type, name)
      {encoding, clock, channels} = codec_sdp_info(type, name)

      acc
      |> ExSDP.add_attribute(%ExSDP.Attribute.RTPMapping{
        payload_type: pt,
        encoding: encoding,
        clock_rate: clock,
        params: channels
      })
      |> add_red_fmtp(type, name, pt, codecs)
      |> append_pt(pt)
    end)
  end

  # RFC 4103 §5: "red" needs an fmtp listing the generations, each referencing
  # the T.140 payload type (primary + 2 redundant). Skipped if T140 itself is
  # not advertised alongside.
  defp add_red_fmtp(m, :text, name, red_pt, codecs) do
    with "T140RED" <- String.upcase(name),
         true <- Enum.any?(codecs, &(String.upcase(&1) == "T140")) do
      {t140_pt, _code} = codec_pt_code(:text, "T140")

      ExSDP.add_attribute(m, %ExSDP.Attribute.FMTP{
        pt: red_pt,
        redundant_payloads: [t140_pt, t140_pt, t140_pt]
      })
    else
      _ -> m
    end
  end

  defp add_red_fmtp(m, _type, _name, _red_pt, _codecs), do: m

  defp codec_sdp_info(:audio, name) do
    {_pt, _code, clock, channels} = Map.fetch!(@audio_codecs, String.upcase(name))
    {sdp_encoding(name), clock, if(channels > 1, do: channels, else: nil)}
  end

  defp codec_sdp_info(:video, name) do
    {_pt, _code, clock} = Map.fetch!(@video_codecs, String.upcase(name))
    {sdp_encoding(name), clock, nil}
  end

  defp codec_sdp_info(:text, name) do
    {_pt, _code, clock} = Map.fetch!(@text_codecs, String.upcase(name))
    {sdp_encoding(name), clock, nil}
  end

  # Conventional SDP casing (matching is case-insensitive anyway); T140RED is
  # the Mendooze codec name, advertised as "red" per RFC 4103.
  defp sdp_encoding(name) do
    case String.upcase(name) do
      "OPUS" -> "opus"
      "T140" -> "t140"
      "T140RED" -> "red"
      other -> other
    end
  end

  defp add_dtmf(m, false), do: m

  defp add_dtmf(m, true) do
    m
    |> ExSDP.add_attribute(%ExSDP.Attribute.RTPMapping{
      payload_type: @dtmf_pt,
      encoding: "telephone-event",
      clock_rate: 8000
    })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{pt: @dtmf_pt, dtmf_tones: @dtmf_tones})
    |> append_pt(@dtmf_pt)
  end

  defp add_crypto(m, :none), do: m

  defp add_crypto(m, {:dtls, setup, hash, fingerprint}) do
    m
    |> ExSDP.add_attribute({:fingerprint, {hash_to_atom(hash), fingerprint}})
    |> ExSDP.add_attribute({:setup, setup})
  end

  defp add_crypto(m, {:sdes, suite, key}) do
    ExSDP.add_attribute(m, {"crypto", "1 #{suite} inline:#{key}"})
  end

  defp add_ice(m, nil), do: m

  defp add_ice(m, %{ufrag: ufrag, pwd: pwd}) do
    m
    |> ExSDP.add_attribute({:ice_ufrag, ufrag})
    |> ExSDP.add_attribute({:ice_pwd, pwd})
  end

  defp add_rtcp_mux(m, false), do: m
  defp add_rtcp_mux(m, true), do: ExSDP.add_attribute(m, :rtcp_mux)

  defp append_pt(m, pt), do: Map.put(m, :fmt, m.fmt ++ [pt])

  defp to_addr(ip) when is_tuple(ip), do: ip

  defp to_addr(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, addr} -> addr
      {:error, _} -> ip
    end
  end

  # ── SDP parsing ─────────────────────────────────────────────────────────────

  # RTP profiles we can answer with real media; anything else (TCP/WSS,
  # UDP/DTLS/SCTP, …) yields an unsupported stub (G9).
  @rtp_profiles ~w(RTP/AVP RTP/AVPF RTP/SAVP RTP/SAVPF UDP/TLS/RTP/SAVPF)

  @doc """
  Parse a remote SDP into per-media descriptors.

  Every `m=` section is returned in offer order (G9): `audio`/`video`/`text`
  sections carried over an RTP profile become full `media_desc/0` maps
  (`supported?: true`, session-level `c=`, crypto, ICE and direction inherited,
  media-level values winning); any other section — an unknown media type or a
  non-RTP transport — becomes a `media_stub/0` (`supported?: false`) so the
  answerer can echo a port-0 rejection.
  """
  @spec parse(String.t()) :: {:ok, [media_desc() | media_stub()]} | {:error, term()}
  def parse(sdp_str) do
    case ExSDP.parse(sdp_str) do
      {:ok, sdp} ->
        session_ip = connection_ip(sdp.connection_data)
        session_attrs = sdp.attributes
        medias = Enum.map(sdp.media, &parse_media_section(&1, session_ip, session_attrs))
        {:ok, medias}

      {:error, _reason} = err ->
        err
    end
  end

  defp parse_media_section(m, session_ip, session_attrs) do
    if m.type in [:audio, :video, :text] and m.protocol in @rtp_profiles do
      parse_media(m, session_ip, session_attrs)
    else
      %{supported?: false, type: m.type, port: m.port, protocol: m.protocol, raw_fmt: m.fmt}
    end
  end

  defp parse_media(m, session_ip, session_attrs) do
    attrs = m.attributes
    fmt = normalize_fmt(m.fmt)
    rtpmaps = for %ExSDP.Attribute.RTPMapping{} = rm <- attrs, do: rm
    {rtp_map, codecs, dtmf_pts} = remote_rtp_map(m.type, fmt, rtpmaps)

    %{
      supported?: true,
      type: m.type,
      ip: connection_ip(m.connection_data) || session_ip,
      port: m.port,
      protocol: m.protocol,
      raw_fmt: m.fmt,
      rtp_map: rtp_map,
      codecs: codecs,
      dtmf_pts: dtmf_pts,
      rtcp_mux: :rtcp_mux in attrs,
      direction: find_direction(attrs) || find_direction(session_attrs) || :sendrecv,
      bandwidth: as_bandwidth(m.bandwidth),
      crypto: find_crypto(attrs, session_attrs),
      ice: find_ice(attrs) || find_ice(session_attrs),
      mid: find_mid(attrs),
      rtcp_fb: parse_rtcp_fb(attrs),
      candidates: raw_candidates(attrs)
    }
  end

  defp find_mid(attrs) do
    Enum.find_value(attrs, fn
      {:mid, v} -> v
      _ -> nil
    end)
  end

  # a=candidate lines are kept verbatim (raw value, sans "a=candidate:" prefix)
  # for later B2BUA forwarding; the answerer does not use them for addressing.
  defp raw_candidates(attrs) do
    for {"candidate", v} <- attrs, do: v
  end

  # a=rtcp-fb:<pt> <type> → %{pt => ["nack", "ccm fir", ...]}; "*" maps to -1.
  # ExSDP parses these into %RTCPFeedback{}; reconstruct the SDP wording so the
  # map round-trips regardless of ExSDP's internal atoms.
  defp parse_rtcp_fb(attrs) do
    for %ExSDP.Attribute.RTCPFeedback{pt: pt, feedback_type: fb} <- attrs, reduce: %{} do
      acc ->
        key = if pt == :all, do: -1, else: pt
        Map.update(acc, key, [fb_to_string(fb)], &(&1 ++ [fb_to_string(fb)]))
    end
  end

  defp fb_to_string(:nack), do: "nack"
  defp fb_to_string(:fir), do: "ccm fir"
  defp fb_to_string(:pli), do: "nack pli"
  defp fb_to_string(:twcc), do: "transport-cc"
  defp fb_to_string(:remb), do: "goog-remb"
  defp fb_to_string(fb) when is_binary(fb), do: fb

  defp as_bandwidth(bws) when is_list(bws) do
    Enum.find_value(bws, fn
      %ExSDP.Bandwidth{type: :AS, bandwidth: bw} -> bw
      _ -> nil
    end)
  end

  defp as_bandwidth(_), do: nil

  # ExSDP only converts fmt entries to integers for some protocol strings
  # (e.g. "RTP/AVP" yes, "RTP/SAVPF" no) — normalize to integers here.
  defp normalize_fmt(fmt) when is_list(fmt), do: fmt

  defp normalize_fmt(fmt) when is_binary(fmt) do
    fmt
    |> String.split(" ", trim: true)
    |> Enum.flat_map(fn s ->
      case Integer.parse(s) do
        {pt, ""} -> [pt]
        _ -> []
      end
    end)
  end

  # Map each offered payload type to a Mendooze codec code, keeping only the
  # codecs we know. Static PTs are recognized without an a=rtpmap line.
  # Telephone-event PTs are collected by clock rate (G10) — Chrome offers one
  # per clock (110@48000, 126@8000).
  defp remote_rtp_map(type, fmt, rtpmaps) do
    by_pt = Map.new(rtpmaps, &{&1.payload_type, &1})

    Enum.reduce(fmt, {%{}, [], %{}}, fn pt, {map, codecs, dtmf_pts} ->
      case codec_name_for_pt(type, pt, Map.get(by_pt, pt)) do
        {:dtmf, clock} ->
          {Map.put(map, Integer.to_string(pt), @dtmf_code), codecs,
           Map.put_new(dtmf_pts, clock, pt)}

        {:ok, name, code} ->
          {Map.put(map, Integer.to_string(pt), code), codecs ++ [name], dtmf_pts}

        :unknown ->
          {map, codecs, dtmf_pts}
      end
    end)
  end

  # RFC 4103 names the T.140 redundancy format "red"; the codec tables use the
  # Mendooze name T140RED.
  defp normalize_codec_name(:text, "RED"), do: "T140RED"
  defp normalize_codec_name(_type, name), do: name

  defp codec_name_for_pt(type, pt, nil) do
    with :audio <- type,
         {:ok, name} <- Map.fetch(@static_pt, pt),
         {:ok, code} <- codec_code(:audio, name) do
      {:ok, name, code}
    else
      _ -> :unknown
    end
  end

  defp codec_name_for_pt(type, _pt, %ExSDP.Attribute.RTPMapping{
         encoding: encoding,
         clock_rate: clock
       }) do
    name = normalize_codec_name(type, String.upcase(encoding))

    cond do
      name == "TELEPHONE-EVENT" ->
        {:dtmf, clock}

      match?({:ok, _}, codec_code(type, name)) ->
        {:ok, code} = codec_code(type, name)
        {:ok, name, code}

      true ->
        :unknown
    end
  end

  defp connection_ip(nil), do: nil
  defp connection_ip([]), do: nil
  defp connection_ip([cnx | _]), do: connection_ip(cnx)
  defp connection_ip(%ExSDP.ConnectionData{address: addr}), do: addr_to_string(addr)

  defp addr_to_string(addr) when is_tuple(addr), do: to_string(:inet.ntoa(addr))
  defp addr_to_string(addr) when is_binary(addr), do: addr
  defp addr_to_string(_), do: nil

  defp find_direction(attrs),
    do: Enum.find(attrs, &(&1 in [:sendrecv, :sendonly, :recvonly, :inactive]))

  defp find_crypto(attrs, session_attrs) do
    fingerprint = find_fingerprint(attrs) || find_fingerprint(session_attrs)
    sdes = find_sdes(attrs) || find_sdes(session_attrs)

    cond do
      fingerprint != nil ->
        {hash, fp} = fingerprint
        setup = find_setup(attrs) || find_setup(session_attrs) || :actpass
        {:dtls, setup, hash_to_string(hash), fp}

      sdes != nil ->
        sdes

      true ->
        :none
    end
  end

  defp find_fingerprint(attrs) do
    Enum.find_value(attrs, fn
      {:fingerprint, {hash, fp}} -> {hash, fp}
      _ -> nil
    end)
  end

  defp find_setup(attrs) do
    Enum.find_value(attrs, fn
      {:setup, setup} -> setup
      _ -> nil
    end)
  end

  # a=crypto:<tag> <suite> inline:<key>[|lifetime|MKI] — keep the base64 key only
  defp find_sdes(attrs) do
    Enum.find_value(attrs, fn
      {"crypto", value} ->
        case String.split(value, " ", trim: true) do
          [_tag, suite, "inline:" <> keypart | _] ->
            {:sdes, suite, keypart |> String.split("|") |> hd()}

          _ ->
            nil
        end

      _ ->
        nil
    end)
  end

  defp find_ice(attrs) do
    ufrag =
      Enum.find_value(attrs, fn
        {:ice_ufrag, v} -> v
        _ -> nil
      end)

    pwd =
      Enum.find_value(attrs, fn
        {:ice_pwd, v} -> v
        _ -> nil
      end)

    if ufrag != nil and pwd != nil, do: %{ufrag: ufrag, pwd: pwd}, else: nil
  end

  defp hash_to_atom(hash) do
    case String.downcase(hash) do
      "sha-1" -> :sha1
      "sha-224" -> :sha224
      "sha-256" -> :sha256
      "sha-384" -> :sha384
      "sha-512" -> :sha512
    end
  end

  defp hash_to_string(atom) do
    case atom do
      :sha1 -> "sha-1"
      :sha224 -> "sha-224"
      :sha256 -> "sha-256"
      :sha384 -> "sha-384"
      :sha512 -> "sha-512"
    end
  end

  # ── Negotiation ─────────────────────────────────────────────────────────────

  @doc """
  Intersect a remote media descriptor with our supported codec names
  (preference order = `our_names` order).

  Returns the common codec names, whether telephone-event was retained, the
  selected telephone-event PT and its clock (`dtmf_pt`/`dtmf_clock`, nil when
  declined), and the `rtpMap` for `EndpointStartSending` — the remote
  payload-type numbering, since these are the PTs the remote peer expects to
  receive.
  """
  @spec negotiate(media_desc(), [codec_name()], boolean()) ::
          {:ok,
           %{
             codecs: [codec_name()],
             dtmf: boolean(),
             dtmf_pt: non_neg_integer() | nil,
             dtmf_clock: non_neg_integer() | nil,
             rtp_map: rtp_map()
           }}
          | {:error, :no_common_codec}
  def negotiate(desc, our_names, want_dtmf \\ true) do
    remote = MapSet.new(desc.codecs)
    common = Enum.filter(our_names, &MapSet.member?(remote, String.upcase(&1)))

    if common == [] do
      {:error, :no_common_codec}
    else
      {dtmf?, dtmf_pt, dtmf_clock} = select_dtmf(desc, common, want_dtmf)

      send_map =
        Map.filter(desc.rtp_map, fn {pt, code} ->
          Enum.any?(common, fn name ->
            {:ok, c} = codec_code(desc.type, name)
            c == code
          end) or (dtmf? and pt == Integer.to_string(dtmf_pt))
        end)

      {:ok,
       %{
         codecs: Enum.map(common, &String.upcase/1),
         dtmf: dtmf?,
         dtmf_pt: dtmf_pt,
         dtmf_clock: dtmf_clock,
         rtp_map: send_map
       }}
    end
  end

  # G10: pick the telephone-event PT whose clock matches the primary (preferred)
  # common audio codec — 8000 for G.711/G722, 48000 for OPUS — so DTMF rides at
  # the same rate. Falls back to the 8000 Hz PT, then to any offered one.
  defp select_dtmf(%{type: :audio, dtmf_pts: dtmf_pts}, [primary | _], true)
       when map_size(dtmf_pts) > 0 do
    clock = audio_clock(primary)
    pt = Map.get(dtmf_pts, clock) || Map.get(dtmf_pts, 8000) || dtmf_pts |> Map.values() |> hd()
    matched_clock = Enum.find_value(dtmf_pts, fn {c, p} -> if p == pt, do: c end)
    {true, pt, matched_clock}
  end

  defp select_dtmf(_desc, _common, _want_dtmf), do: {false, nil, nil}

  defp audio_clock(name) do
    {_pt, _code, clock, _ch} = Map.fetch!(@audio_codecs, String.upcase(name))
    clock
  end

  @doc """
  Answer-side `b=AS:` negotiation (kb/s): cap our configured receive bandwidth
  to the offered one. `offered` is nil when the offer carries no `b=AS:` line;
  `ours` is 0 when we have no configured cap. Returns 0 (no `b=` line) when
  neither side declares one.
  """
  @spec negotiate_bandwidth(non_neg_integer() | nil, non_neg_integer()) :: non_neg_integer()
  def negotiate_bandwidth(nil, ours), do: ours
  def negotiate_bandwidth(offered, 0), do: offered
  def negotiate_bandwidth(offered, ours), do: min(offered, ours)

  @doc """
  Direction an answer must declare in response to an offered direction
  (RFC 3264 §6.1): `sendonly` and `recvonly` are mirrored, `sendrecv` and
  `inactive` are kept.
  """
  @spec reverse_direction(:sendrecv | :sendonly | :recvonly | :inactive) ::
          :sendrecv | :sendonly | :recvonly | :inactive
  def reverse_direction(:sendonly), do: :recvonly
  def reverse_direction(:recvonly), do: :sendonly
  def reverse_direction(dir), do: dir

  # ── ICE host candidates ─────────────────────────────────────────────────────

  @doc """
  Build the local host candidate list for one media: one component-1 (RTP)
  candidate, plus a component-2 (RTCP, `port + 1`) candidate when rtcp-mux is
  not negotiated.

  Priorities follow RFC 8445 §5.1.2.1 with a host type preference of 126 and a
  local preference of 65535, i.e. `(126 <<< 24) + (65535 <<< 8) + (256 -
  component)` — `2130706431` for component 1, `2130706430` for component 2.

  The `port` is the `EndpointStartReceiving` return, inherited from the Java
  gateway workaround (D6): `GetMediaCandidates` historically did not return a
  usable per-media port.

      iex> MediaServer.Mendooze.Sdp.host_candidates("192.168.1.10", 22000, true)
      [%{foundation: "1", component: 1, protocol: :udp, priority: 2130706431,
         ip: "192.168.1.10", port: 22000, type: :host}]
  """
  @spec host_candidates(String.t(), non_neg_integer(), boolean()) :: [candidate()]
  def host_candidates(ip, port, rtcp_mux?) do
    rtp = %{
      foundation: "1",
      component: 1,
      protocol: :udp,
      priority: candidate_priority(1),
      ip: ip,
      port: port,
      type: :host
    }

    if rtcp_mux? do
      [rtp]
    else
      [rtp, %{rtp | component: 2, priority: candidate_priority(2), port: port + 1}]
    end
  end

  defp candidate_priority(component) do
    (126 <<< 24) + (65535 <<< 8) + (256 - component)
  end

  @doc """
  Render one `candidate/0` as the value of an `a=candidate` line (without the
  `a=candidate:` prefix), e.g. `"1 1 udp 2130706431 192.168.1.10 22000 typ host"`.
  """
  @spec candidate_line(candidate()) :: String.t()
  def candidate_line(%{
        foundation: f,
        component: c,
        protocol: :udp,
        priority: prio,
        ip: ip,
        port: port,
        type: :host
      }) do
    "#{f} #{c} udp #{prio} #{ip} #{port} typ host"
  end

  # ── Delegated SDP negotiation (enriched EndpointStartReceiving) ──────────────

  @doc """
  Reduce the media server's enriched `EndpointStartReceiving` return
  (`returnVal[1]`, the fmtp-per-payload-type struct) to the authoritative set of
  accepted payload types.

  `proposed` is the receive `rtpMap` we sent to `EndpointStartReceiving`; keys of
  the returned struct that were never proposed are dropped (defensive, logged).
  Presence of a key means the payload type was accepted (empty fmtp value =
  fmtp-less codec, decision §8-E); absence means it was filtered.

  Returns `nil` when `fmtp_struct` is `nil` — an older server that returned only
  the port, so the caller falls back to the client-side codec tables.

      iex> MediaServer.Mendooze.Sdp.accepted_pts(%{"0" => 0, "96" => 99},
      ...>   %{"0" => "", "96" => "profile-level-id=42801f"})
      %{"0" => "", "96" => "profile-level-id=42801f"}
  """
  @spec accepted_pts(rtp_map(), %{optional(String.t()) => String.t()} | nil) ::
          %{String.t() => String.t()} | nil
  def accepted_pts(_proposed, nil), do: nil

  def accepted_pts(proposed, fmtp_struct) when is_map(fmtp_struct) do
    fmtp_struct
    |> Map.new(fn {pt, fmtp} -> {to_string(pt), to_string(fmtp)} end)
    |> Map.filter(fn {pt, _fmtp} ->
      if Map.has_key?(proposed, pt) do
        true
      else
        Logger.warning("Mendooze.Sdp: server accepted unproposed payload type #{pt}, ignoring")
        false
      end
    end)
  end

  @doc """
  Resolve the SDP `rtpmap` fields for one of *our* offered payload types
  (`{encoding, clock, channels}`), or `:unknown`. Used on the offer side, where
  the payload-type numbering is ours (the codec-table defaults).
  """
  @spec pt_rtpmap(:audio | :video | :text, non_neg_integer()) ::
          {String.t(), non_neg_integer(), non_neg_integer() | nil} | :unknown
  def pt_rtpmap(:audio, @dtmf_pt), do: {"telephone-event", 8000, nil}

  def pt_rtpmap(:audio, pt) do
    case Enum.find(@audio_codecs, fn {_name, {p, _code, _clk, _ch}} -> p == pt end) do
      {name, {_p, _code, clock, ch}} -> {sdp_encoding(name), clock, channels(ch)}
      nil -> :unknown
    end
  end

  def pt_rtpmap(:video, pt) do
    case Enum.find(@video_codecs, fn {_name, {p, _code, _clk}} -> p == pt end) do
      {name, {_p, _code, clock}} -> {sdp_encoding(name), clock, nil}
      nil -> :unknown
    end
  end

  def pt_rtpmap(:text, pt) do
    case Enum.find(@text_codecs, fn {_name, {p, _code, _clk}} -> p == pt end) do
      {name, {_p, _code, clock}} -> {sdp_encoding(name), clock, nil}
      nil -> :unknown
    end
  end

  @doc """
  Resolve the SDP `rtpmap` fields (`{encoding, clock, channels}`) from a Mendooze
  codec code, or `:unknown`. Used on the answer side, where the payload-type
  numbering is the offerer's: we look the accepted PT's code up in the parsed
  offer, then derive the (numbering-independent) encoding and clock from it.
  """
  @spec code_rtpmap(:audio | :video | :text, non_neg_integer()) ::
          {String.t(), non_neg_integer(), non_neg_integer() | nil} | :unknown
  def code_rtpmap(:audio, @dtmf_code), do: {"telephone-event", 8000, nil}

  def code_rtpmap(:audio, code) do
    case Enum.find(@audio_codecs, fn {_name, {_p, c, _clk, _ch}} -> c == code end) do
      {name, {_p, _c, clock, ch}} -> {sdp_encoding(name), clock, channels(ch)}
      nil -> :unknown
    end
  end

  def code_rtpmap(:video, code) do
    case Enum.find(@video_codecs, fn {_name, {_p, c, _clk}} -> c == code end) do
      {name, {_p, _c, clock}} -> {sdp_encoding(name), clock, nil}
      nil -> :unknown
    end
  end

  def code_rtpmap(:text, code) do
    case Enum.find(@text_codecs, fn {_name, {_p, c, _clk}} -> c == code end) do
      {name, {_p, _c, clock}} -> {sdp_encoding(name), clock, nil}
      nil -> :unknown
    end
  end

  @doc """
  Build the ordered answer `rtpmap` entries from a `negotiate/3` result, in the
  offerer's payload-type numbering (RFC 3264). Shared by the delegated Mendooze
  answer path and the Mockup gateway answer.

  The telephone-event entry is emitted with the negotiated clock (G10), not the
  code table's fixed 8000 Hz, so answering OPUS keeps its 48 kHz DTMF PT.
  """
  @spec answer_rtpmaps(:audio | :video | :text, %{
          required(:rtp_map) => rtp_map(),
          optional(:dtmf_clock) => non_neg_integer() | nil
        }) :: [rtpmap_entry()]
  def answer_rtpmaps(media, %{rtp_map: send_map} = neg) do
    dtmf_clock = Map.get(neg, :dtmf_clock) || 8000

    send_map
    |> Enum.sort_by(fn {pt, _code} -> String.to_integer(pt) end)
    |> Enum.flat_map(fn {pt_str, code} ->
      pt = String.to_integer(pt_str)

      cond do
        code == @dtmf_code ->
          [%{pt: pt, encoding: "telephone-event", clock: dtmf_clock, channels: nil}]

        true ->
          case code_rtpmap(media, code) do
            :unknown -> []
            {enc, clock, ch} -> [%{pt: pt, encoding: enc, clock: clock, channels: ch}]
          end
      end
    end)
  end

  @doc """
  Restrict a send `rtpMap` (remote payload-type numbering → codec code) to the
  codecs the media server accepted on receive, so we never send a codec it just
  filtered. `proposed_recv` is the receive `rtpMap` we sent to
  `EndpointStartReceiving` (local numbering → code); `accepted` is the result of
  `accepted_pts/2`. When `accepted` is `nil` (older server) the send map is
  returned unchanged.
  """
  @spec restrict_send_map(rtp_map(), rtp_map(), %{String.t() => String.t()} | nil) :: rtp_map()
  def restrict_send_map(send_map, _proposed_recv, nil), do: send_map

  def restrict_send_map(send_map, proposed_recv, accepted) do
    codes =
      accepted
      |> Map.keys()
      |> Enum.flat_map(fn pt ->
        case Map.fetch(proposed_recv, pt) do
          {:ok, code} -> [code]
          :error -> []
        end
      end)
      |> MapSet.new()

    Map.filter(send_map, fn {_pt, code} -> MapSet.member?(codes, code) end)
  end

  defp channels(ch) when is_integer(ch) and ch > 1, do: ch
  defp channels(_), do: nil

  # ── GetMediaCandidates ──────────────────────────────────────────────────────

  @doc """
  Decode the candidate string returned by `GetMediaCandidates`, e.g.
  `"rtp://192.168.1.10:22000"` → `{:ok, "192.168.1.10", 22000}`.
  """
  @spec parse_media_candidate(String.t()) ::
          {:ok, String.t(), non_neg_integer()} | {:error, {:bad_candidate, String.t()}}
  def parse_media_candidate(candidate) do
    with [_scheme, hostport] <- String.split(candidate, "://", parts: 2),
         [host, port_str] <- split_host_port(hostport),
         {port, ""} <- Integer.parse(port_str) do
      {:ok, host, port}
    else
      _ -> {:error, {:bad_candidate, candidate}}
    end
  end

  # IPv6 candidates come as rtp://[::1]:22000
  defp split_host_port("[" <> rest) do
    case String.split(rest, "]:", parts: 2) do
      [host, port] -> [host, port]
      _ -> :error
    end
  end

  defp split_host_port(hostport) do
    case String.split(hostport, ":", parts: 2) do
      [host, port] -> [host, port]
      _ -> :error
    end
  end
end
