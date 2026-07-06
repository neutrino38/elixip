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
  """

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
  One parsed `m=` section of a remote SDP.

  `rtp_map` maps the remote payload types (strings) to Mendooze codec codes —
  restricted to codecs we know. `dtmf_pt` is the remote telephone-event
  payload type, if offered.
  """
  @type media_desc :: %{
          type: :audio | :video,
          ip: String.t() | nil,
          port: non_neg_integer(),
          protocol: String.t(),
          rtp_map: rtp_map(),
          codecs: [codec_name()],
          dtmf_pt: non_neg_integer() | nil,
          rtcp_mux: boolean(),
          direction: :sendrecv | :sendonly | :recvonly | :inactive,
          crypto: crypto(),
          ice: nil | %{ufrag: String.t(), pwd: String.t()}
        }

  @typedoc """
  One `m=` section to build. `:crypto` carries the *local* material: the DTLS
  setup role (`:actpass` in an offer, `:active`/`:passive` in an answer), our
  fingerprint, or our SDES key. `:protocol` overrides the one derived from
  `:crypto` (useful in answers, to mirror the offer).
  """
  @type media_spec :: %{
          required(:type) => :audio | :video,
          required(:port) => non_neg_integer(),
          required(:codecs) => [codec_name()],
          optional(:dtmf) => boolean(),
          optional(:crypto) => crypto(),
          optional(:ice) => nil | %{ufrag: String.t(), pwd: String.t()},
          optional(:rtcp_mux) => boolean(),
          optional(:protocol) => String.t()
        }

  # ── rtpMap for EndpointStartReceiving ───────────────────────────────────────

  @doc """
  Build the receive `rtpMap` (our payload-type numbering) for the given codec
  names. Raises on an unknown codec name — that is a configuration error.

      iex> MediaServer.Mendooze.Sdp.local_rtp_map(:audio, ["PCMU", "PCMA"], true)
      %{"0" => 0, "8" => 8, "101" => 100}
  """
  @spec local_rtp_map(:audio | :video, [codec_name()], boolean()) :: rtp_map()
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

  # ── SDP construction ────────────────────────────────────────────────────────

  @doc """
  Build an SDP (offer or answer — the difference lives in the `media_spec`
  crypto/protocol fields) and return it as a string.

  `ip` is the local media address, as returned by `GetMediaCandidates`
  (string) or as a tuple.
  """
  @spec build(%{
          required(:ip) => String.t() | :inet.ip_address(),
          required(:medias) => [media_spec()]
        }) ::
          String.t()
  def build(%{ip: ip, medias: medias}) do
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

    medias
    |> Enum.reduce(sdp, fn mspec, acc -> ExSDP.add_media(acc, build_media(mspec)) end)
    |> to_string()
  end

  defp build_media(%{type: type, port: port, codecs: codecs} = mspec) do
    crypto = Map.get(mspec, :crypto, :none)
    protocol = Map.get(mspec, :protocol, protocol_for(crypto))
    dtmf = Map.get(mspec, :dtmf, false) and type == :audio

    %ExSDP.Media{type: type, port: port, protocol: protocol, fmt: []}
    |> add_codecs(type, codecs)
    |> add_dtmf(dtmf)
    |> add_crypto(crypto)
    |> add_ice(Map.get(mspec, :ice))
    |> add_rtcp_mux(Map.get(mspec, :rtcp_mux, false))
  end

  # Default transport per security stack; answers should mirror the offer via
  # the :protocol override instead.
  defp protocol_for(:none), do: "RTP/AVP"
  defp protocol_for({:sdes, _, _}), do: "RTP/SAVP"
  defp protocol_for({:dtls, _, _, _}), do: "RTP/SAVPF"

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
      |> append_pt(pt)
    end)
  end

  defp codec_sdp_info(:audio, name) do
    {_pt, _code, clock, channels} = Map.fetch!(@audio_codecs, String.upcase(name))
    {sdp_encoding(name), clock, if(channels > 1, do: channels, else: nil)}
  end

  defp codec_sdp_info(:video, name) do
    {_pt, _code, clock} = Map.fetch!(@video_codecs, String.upcase(name))
    {sdp_encoding(name), clock, nil}
  end

  # Conventional SDP casing (matching is case-insensitive anyway)
  defp sdp_encoding(name) do
    case String.upcase(name) do
      "OPUS" -> "opus"
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

  @doc """
  Parse a remote SDP into per-media descriptors. Only `audio` and `video`
  sections are returned; session-level `c=`, crypto, ICE and direction
  attributes are inherited by each media (media-level values win).
  """
  @spec parse(String.t()) :: {:ok, [media_desc()]} | {:error, term()}
  def parse(sdp_str) do
    case ExSDP.parse(sdp_str) do
      {:ok, sdp} ->
        session_ip = connection_ip(sdp.connection_data)
        session_attrs = sdp.attributes

        medias =
          sdp.media
          |> Enum.filter(&(&1.type in [:audio, :video]))
          |> Enum.map(&parse_media(&1, session_ip, session_attrs))

        {:ok, medias}

      {:error, _reason} = err ->
        err
    end
  end

  defp parse_media(m, session_ip, session_attrs) do
    attrs = m.attributes
    fmt = normalize_fmt(m.fmt)
    rtpmaps = for %ExSDP.Attribute.RTPMapping{} = rm <- attrs, do: rm
    {rtp_map, codecs, dtmf_pt} = remote_rtp_map(m.type, fmt, rtpmaps)

    %{
      type: m.type,
      ip: connection_ip(m.connection_data) || session_ip,
      port: m.port,
      protocol: m.protocol,
      rtp_map: rtp_map,
      codecs: codecs,
      dtmf_pt: dtmf_pt,
      rtcp_mux: :rtcp_mux in attrs,
      direction: find_direction(attrs) || find_direction(session_attrs) || :sendrecv,
      crypto: find_crypto(attrs, session_attrs),
      ice: find_ice(attrs) || find_ice(session_attrs)
    }
  end

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
  defp remote_rtp_map(type, fmt, rtpmaps) do
    by_pt = Map.new(rtpmaps, &{&1.payload_type, &1})

    Enum.reduce(fmt, {%{}, [], nil}, fn pt, {map, codecs, dtmf_pt} ->
      case codec_name_for_pt(type, pt, Map.get(by_pt, pt)) do
        :dtmf ->
          {Map.put(map, Integer.to_string(pt), @dtmf_code), codecs, dtmf_pt || pt}

        {:ok, name, code} ->
          {Map.put(map, Integer.to_string(pt), code), codecs ++ [name], dtmf_pt}

        :unknown ->
          {map, codecs, dtmf_pt}
      end
    end)
  end

  defp codec_name_for_pt(type, pt, nil) do
    with :audio <- type,
         {:ok, name} <- Map.fetch(@static_pt, pt),
         {:ok, code} <- codec_code(:audio, name) do
      {:ok, name, code}
    else
      _ -> :unknown
    end
  end

  defp codec_name_for_pt(type, _pt, %ExSDP.Attribute.RTPMapping{encoding: encoding}) do
    name = String.upcase(encoding)

    cond do
      name == "TELEPHONE-EVENT" ->
        :dtmf

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

  Returns the common codec names, whether telephone-event was retained, and
  the `rtpMap` for `EndpointStartSending` — the remote payload-type numbering,
  since these are the PTs the remote peer expects to receive.
  """
  @spec negotiate(media_desc(), [codec_name()], boolean()) ::
          {:ok, %{codecs: [codec_name()], dtmf: boolean(), rtp_map: rtp_map()}}
          | {:error, :no_common_codec}
  def negotiate(desc, our_names, want_dtmf \\ true) do
    remote = MapSet.new(desc.codecs)
    common = Enum.filter(our_names, &MapSet.member?(remote, String.upcase(&1)))

    if common == [] do
      {:error, :no_common_codec}
    else
      dtmf = want_dtmf and desc.dtmf_pt != nil

      send_map =
        Map.filter(desc.rtp_map, fn {pt, code} ->
          Enum.any?(common, fn name ->
            {:ok, c} = codec_code(desc.type, name)
            c == code
          end) or (dtmf and pt == Integer.to_string(desc.dtmf_pt))
        end)

      {:ok, %{codecs: Enum.map(common, &String.upcase/1), dtmf: dtmf, rtp_map: send_map}}
    end
  end

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
