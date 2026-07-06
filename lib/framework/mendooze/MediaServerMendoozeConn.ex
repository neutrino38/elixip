defmodule MediaServer.Mendooze.Conn do
  @moduledoc """
  One peer connection of the Mendooze JSR309 adapter: a MediaSession plus
  an Endpoint, driven over XML-RPC following the call flows of the server
  documentation (§9): offer/answer in both directions, security material
  before any media start, and the RTP inactivity watchdog armed after the
  answer has been processed.

  Sub-resources (player, recorder, echo) are entries in this GenServer's
  state, not processes; their opaque handle is `{conn_pid, kind, ref}`.

  On any RPC failure during setup the server-side resources are torn down
  (per-media stops, EndpointDelete, MediaSessionDelete) before the error
  is returned, so nothing leaks on the media server.
  """

  use GenServer
  require Logger

  alias MediaServer.Mendooze
  alias MediaServer.Mendooze.{Sdp, XmlRpc}

  @call_timeout 30_000
  @default_rtp_timeout_ms 10_000

  # MediaFrame::Type wire values
  @media_int %{audio: 0, video: 1}
  # MediaFrame::MediaProtocol RTP
  @proto_rtp 0

  @default_audio_codecs ["PCMU", "PCMA"]
  @default_video_codecs ["VP8"]

  # ── API (called through the MediaServer.Mendooze facade) ───────────────────

  def start(server, event_sink, opts) do
    GenServer.start(__MODULE__, {server, event_sink, opts})
  end

  def get_local_offer(conn), do: GenServer.call(conn, :get_local_offer, @call_timeout)

  def set_remote_answer(conn, sdp),
    do: GenServer.call(conn, {:set_remote_answer, sdp}, @call_timeout)

  def set_remote_offer(conn, sdp),
    do: GenServer.call(conn, {:set_remote_offer, sdp}, @call_timeout)

  def add_remote_candidate(conn, candidate),
    do: GenServer.call(conn, {:add_remote_candidate, candidate}, @call_timeout)

  def close(conn) do
    GenServer.call(conn, :close, @call_timeout)
  catch
    # already stopped (e.g. torn down after a setup failure) — close is idempotent
    :exit, _ -> :ok
  end

  # ── Initialisation ──────────────────────────────────────────────────────────

  @impl true
  def init({server, event_sink, opts}) do
    %{base_url: base_url, queue_id: queue_id} = Mendooze.rpc_info(server)
    sess_tag = "cx-#{:erlang.unique_integer([:positive, :monotonic])}"
    medias = medias_from_opts(opts)

    state = %{
      server: server,
      event_sink: event_sink,
      base_url: base_url,
      opts: opts,
      sess_tag: sess_tag,
      sess_id: nil,
      endpoint_id: nil,
      medias: medias,
      # per-media local data filled by offer/answer processing
      local_ports: %{},
      local_ip: nil,
      local_crypto: :none,
      local_ice: nil,
      status: :init,
      # sub-resources (phase 6)
      players: %{},
      recorders: %{},
      echo: nil
    }

    with {:ok, sess_id} <-
           create(state, "MediaSessionCreate", [sess_tag, queue_id]),
         state = %{state | sess_id: sess_id},
         {:ok, endpoint_id} <-
           create(state, "EndpointCreate", [
             sess_id,
             sess_tag,
             :audio in medias,
             :video in medias,
             false
           ]) do
      :ok = Mendooze.register_conn(server, sess_tag, event_sink)
      {:ok, %{state | endpoint_id: endpoint_id}}
    else
      {:error, reason} ->
        # EndpointCreate may have failed with the session already created
        if state.sess_id, do: rpc(state, "MediaSessionDelete", [state.sess_id])
        {:stop, reason}
    end
  end

  defp medias_from_opts(opts) do
    case Keyword.get(opts, :media, :audio_video) do
      :audio -> [:audio]
      :video -> [:video]
      :audio_video -> [:audio, :video]
    end
  end

  # ── UAC flow: build the offer, then process the answer ─────────────────────

  @impl true
  def handle_call(:get_local_offer, _from, state) do
    with {:ok, state} <- setup_local_security(state),
         {:ok, state} <- start_receiving_all(state) do
      offer =
        Sdp.build(%{
          ip: state.local_ip,
          medias: Enum.map(state.medias, &offer_media_spec(state, &1))
        })

      {:reply, {:ok, offer}, state}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  def handle_call({:set_remote_answer, sdp}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp),
         {:ok, state} <- apply_remote_medias(state, descs) do
      send(state.event_sink, {:ms_event, self(), :ice_connected})
      {:reply, :ok, %{state | status: :active}}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  # ── UAS flow: process the offer and build the answer ───────────────────────

  def handle_call({:set_remote_offer, sdp}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp),
         descs = Enum.filter(descs, &(&1.type in state.medias)),
         :ok <- ensure_media_present(descs),
         # answer only what the offer contains
         state = %{state | medias: Enum.map(descs, & &1.type)},
         {:ok, state} <- setup_local_security_for_offer(state, descs),
         {:ok, state} <- start_receiving_all(state),
         {:ok, state, negotiated} <- apply_remote_medias_negotiated(state, descs) do
      answer =
        Sdp.build(%{
          ip: state.local_ip,
          medias: Enum.map(descs, &answer_media_spec(state, negotiated, &1))
        })

      send(state.event_sink, {:ms_event, self(), :ice_connected})
      {:reply, {:ok, answer}, %{state | status: :active}}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  def handle_call({:add_remote_candidate, candidate}, _from, state) do
    # media selection is not carried by the candidate line: apply to audio
    case rpc(state, "EndpointAddICECandidate", [
           state.sess_id,
           state.endpoint_id,
           @media_int.audio,
           candidate
         ]) do
      {:ok, _} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:close, _from, state) do
    state = teardown(state)
    {:stop, :normal, :ok, state}
  end

  # ── Server events routed by MediaServer.Mendooze ────────────────────────────

  @impl true
  def handle_info({:mendooze_event, event}, state) do
    handle_server_event(event, state)
  end

  defp handle_server_event({:endpoint_disconnected, _tag, _ep, media}, state) do
    Logger.warning("Mendooze.Conn #{state.sess_tag}: RTP timeout on #{media}")
    send(state.event_sink, {:ms_event, self(), :media_timeout})
    {:noreply, state}
  end

  defp handle_server_event({:external_fir, _tag, _ep, media}, state) do
    # remote peer asked for a full intra frame: forward the update request
    rpc(state, "EndpointRequestUpdate", [state.sess_id, state.endpoint_id, @media_int[media]])
    {:noreply, state}
  end

  defp handle_server_event(event, state) do
    # player / recorder events are handled by the sub-resource layer (phase 6)
    Logger.debug("Mendooze.Conn #{state.sess_tag}: unhandled event #{inspect(event)}")
    {:noreply, state}
  end

  @impl true
  def terminate(reason, state) do
    if reason != :normal and state.status != :closed do
      # crash path — still try to free the server-side resources
      teardown(state)
    end

    :ok
  end

  # ── Local side: security and receiving ──────────────────────────────────────

  # UAC: local security material derives from conn_opts only.
  defp setup_local_security(state) do
    if webrtc?(state) do
      setup_dtls_ice(state)
    else
      {:ok, state}
    end
  end

  # UAS: follow the offer — DTLS when the offer is DTLS (and we allow it).
  defp setup_local_security_for_offer(state, descs) do
    offer_dtls? = Enum.any?(descs, &match?({:dtls, _, _, _}, &1.crypto))

    cond do
      offer_dtls? and webrtc_allowed?(state) -> setup_dtls_ice(state)
      offer_dtls? -> {:error, :webrtc_not_supported}
      true -> {:ok, state}
    end
  end

  defp setup_dtls_ice(state) do
    with {:ok, [fingerprint | _]} <-
           rpc(state, "EndpointGetLocalCryptoDTLSFingerprint", ["sha-256"]),
         ice = %{ufrag: random_token(8), pwd: random_token(24)},
         :ok <- set_local_stun_all(state, ice) do
      {:ok, %{state | local_crypto: {:dtls, "sha-256", fingerprint}, local_ice: ice}}
    end
  end

  defp set_local_stun_all(state, ice) do
    Enum.reduce_while(state.medias, :ok, fn media, :ok ->
      case rpc(state, "EndpointSetLocalSTUNCredentials", [
             state.sess_id,
             state.endpoint_id,
             @media_int[media],
             ice.ufrag,
             ice.pwd
           ]) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp start_receiving_all(state) do
    Enum.reduce_while(state.medias, {:ok, state}, fn media, {:ok, st} ->
      rtp_map = Sdp.local_rtp_map(media, codecs(st, media), dtmf?(st, media))

      with {:ok, [port | _]} <-
             rpc(st, "EndpointStartReceiving", [
               st.sess_id,
               st.endpoint_id,
               @media_int[media],
               rtp_map
             ]),
           {:ok, [candidate | _]} <-
             rpc(st, "GetMediaCandidates", [
               st.sess_id,
               st.endpoint_id,
               @proto_rtp,
               @media_int[media]
             ]),
           {:ok, ip, _cport} <- Sdp.parse_media_candidate(candidate) do
        {:cont, {:ok, %{st | local_ports: Map.put(st.local_ports, media, port), local_ip: ip}}}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ── Remote side: security, sending, watchdog ───────────────────────────────

  defp apply_remote_medias(state, descs) do
    descs = Enum.filter(descs, &(&1.type in state.medias))

    with :ok <- ensure_media_present(descs),
         {:ok, state, _negotiated} <- apply_remote_medias_negotiated(state, descs) do
      {:ok, state}
    end
  end

  # Applies §9 steps for each remote media and returns the negotiation
  # results (%{media => %{codecs:, dtmf:, rtp_map:}}) for answer building.
  defp apply_remote_medias_negotiated(state, descs) do
    Enum.reduce_while(descs, {:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      case apply_remote_media(st, desc) do
        {:ok, st, negotiated} -> {:cont, {:ok, st, Map.put(acc, desc.type, negotiated)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp apply_remote_media(state, desc) do
    m = @media_int[desc.type]

    with {:ok, negotiated} <-
           Sdp.negotiate(desc, codecs(state, desc.type), dtmf?(state, desc.type)),
         :ok <- set_rtp_properties(state, m, desc),
         :ok <- set_remote_crypto(state, m, desc),
         {:ok, _} <-
           rpc(state, "EndpointStartSending", [
             state.sess_id,
             state.endpoint_id,
             m,
             desc.ip,
             desc.port,
             negotiated.rtp_map
           ]),
         # the watchdog is armed last, once the answer has been processed
         {:ok, _} <-
           rpc(state, "EndpointStartRTPTimeout", [
             state.sess_id,
             state.endpoint_id,
             m,
             rtp_timeout_ms()
           ]) do
      {:ok, state, negotiated}
    end
  end

  defp set_rtp_properties(state, m, %{rtcp_mux: true}) do
    case rpc(state, "EndpointSetRTPProperties", [
           state.sess_id,
           state.endpoint_id,
           m,
           %{"rtcp-mux" => "1"}
         ]) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp set_rtp_properties(_state, _m, _desc), do: :ok

  defp set_remote_crypto(state, m, desc) do
    crypto_calls =
      case desc.crypto do
        {:dtls, setup, hash, fingerprint} ->
          [{"EndpointSetRemoteCryptoDTLS", [to_string(setup), hash, fingerprint]}]

        {:sdes, suite, key} ->
          [{"EndpointSetRemoteCryptoSDES", [suite, key]}]

        :none ->
          []
      end

    ice_calls =
      case desc.ice do
        %{ufrag: ufrag, pwd: pwd} -> [{"EndpointSetRemoteSTUNCredentials", [ufrag, pwd]}]
        nil -> []
      end

    Enum.reduce_while(crypto_calls ++ ice_calls, :ok, fn {method, args}, :ok ->
      case rpc(state, method, [state.sess_id, state.endpoint_id, m | args]) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ── SDP spec builders ───────────────────────────────────────────────────────

  defp offer_media_spec(state, media) do
    %{
      type: media,
      port: Map.fetch!(state.local_ports, media),
      codecs: codecs(state, media),
      dtmf: dtmf?(state, media),
      crypto: local_crypto_spec(state, :actpass),
      ice: state.local_ice,
      rtcp_mux: false
    }
  end

  defp answer_media_spec(state, negotiated, desc) do
    %{codecs: codec_names, dtmf: dtmf} = Map.fetch!(negotiated, desc.type)

    %{
      type: desc.type,
      port: Map.fetch!(state.local_ports, desc.type),
      codecs: codec_names,
      dtmf: dtmf,
      crypto: local_crypto_spec(state, :active),
      ice: state.local_ice,
      rtcp_mux: desc.rtcp_mux,
      # mirror the transport of the offer
      protocol: desc.protocol
    }
  end

  defp local_crypto_spec(state, setup) do
    case state.local_crypto do
      {:dtls, hash, fingerprint} -> {:dtls, setup, hash, fingerprint}
      :none -> :none
    end
  end

  # ── Teardown (server doc §9.5) ──────────────────────────────────────────────

  defp teardown(%{status: :closed} = state), do: state

  defp teardown(state) do
    Enum.each(state.medias, fn media ->
      m = @media_int[media]
      rpc(state, "EndpointStopSending", [state.sess_id, state.endpoint_id, m])
      rpc(state, "EndpointStopReceiving", [state.sess_id, state.endpoint_id, m])
    end)

    if state.endpoint_id, do: rpc(state, "EndpointDelete", [state.sess_id, state.endpoint_id])
    if state.sess_id, do: rpc(state, "MediaSessionDelete", [state.sess_id])

    Mendooze.unregister_conn(state.server, state.sess_tag)
    send(state.event_sink, {:ms_event, self(), :closed})
    %{state | status: :closed}
  end

  # On a setup failure: free the server-side resources, reply with the error
  # and stop — a later close_peer_connection on this pid is a no-op.
  defp fail(state, reason) do
    Logger.error("Mendooze.Conn #{state.sess_tag}: setup failed: #{inspect(reason)}")
    state = teardown(state)
    {:stop, :normal, {:error, reason}, state}
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp rpc(state, method, params), do: XmlRpc.call(state.base_url, method, params)

  defp create(state, method, params), do: XmlRpc.created_id(rpc(state, method, params))

  defp codecs(state, :audio),
    do: List.wrap(Keyword.get(state.opts, :audio_codec, @default_audio_codecs))

  defp codecs(state, :video),
    do: List.wrap(Keyword.get(state.opts, :video_codec, @default_video_codecs))

  defp dtmf?(state, :audio), do: Keyword.get(state.opts, :dtmf, true)
  defp dtmf?(_state, :video), do: false

  defp webrtc?(state), do: Keyword.get(state.opts, :webrtc_support, :no) == :yes

  defp webrtc_allowed?(state),
    do: Keyword.get(state.opts, :webrtc_support, :no) in [:yes, :if_offered]

  defp ensure_media_present([]), do: {:error, :no_common_media}
  defp ensure_media_present(_descs), do: :ok

  defp rtp_timeout_ms() do
    Application.get_env(:elixip2, MediaServer.Mendooze, [])
    |> Keyword.get(:rtp_timeout_ms, @default_rtp_timeout_ms)
  end

  defp random_token(len) do
    :crypto.strong_rand_bytes(len)
    |> Base.url_encode64(padding: false)
    |> binary_part(0, len)
  end
end
