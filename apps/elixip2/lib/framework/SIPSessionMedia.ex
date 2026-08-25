defmodule SIP.Session.Media do
  @moduledoc """
  Media helpers mixin for SIP sessions.

  This module provides the `media_connect`, `media_play`, `media_record`,
  `media_start_echo`, `media_stop` and `media_cleanup_ressources` FSL macros
  (through `__using__/1`) plus the backing functions that drive the configured
  `MediaServer.Behaviour` adapter.
  """
  require Logger

  # NOTE: this mixin must be combined with a session module (e.g. SIP.Session.CallUAC)
  # that brings in `use SIP.Context` — the media macros rely on `var!(sip_ctx)`.
  defmacro __using__(_opts) do
    quote do
      defmacro media_connect(module, url) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_connect")

          var!(sip_ctx) =
            SIP.Session.Media.use_mediaserver(var!(sip_ctx), unquote(module), unquote(url))
        end
      end

      # Config-driven variant: the adapter and its URL come from the
      # :mediaserver application config (scenario `config` block, external
      # JSON header, or config.exs) instead of being hardcoded here.
      defmacro media_connect() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_connect")
          var!(sip_ctx) = SIP.Session.Media.use_mediaserver(var!(sip_ctx))
        end
      end

      defmacro media_start_echo(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_start_echo")
          var!(sip_ctx) = SIP.Session.Media.start_echo(var!(sip_ctx), unquote(opts))
        end
      end

      defmacro media_play(file_path, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_play")

          var!(sip_ctx) =
            SIP.Session.Media.start_player(var!(sip_ctx), unquote(file_path), unquote(opts))
        end
      end

      defmacro media_record(file_path, duration_ms, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_record")

          var!(sip_ctx) =
            SIP.Session.Media.start_recorder(
              var!(sip_ctx),
              unquote(file_path),
              unquote(duration_ms),
              unquote(opts)
            )
        end
      end

      defmacro media_stop(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_stop")
          var!(sip_ctx) = SIP.Session.Media.stop_media(var!(sip_ctx), unquote(opts))
        end
      end

      defmacro media_cleanup_ressources() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_cleanup_ressources")
          var!(sip_ctx) = SIP.Session.Media.media_cleanup_ressources(var!(sip_ctx))
        end
      end
    end
  end

  # ── Leg-scoped handles ──────────────────────────────────────────────────────
  #
  # A B2BUA call terminates media on the media server for BOTH of its SIP legs
  # (design docs/design/DESIGN-FRAMEWORK.md#57-media-modes), so the single-slot handles this
  # mixin started with are no longer enough. They become leg-scoped — with the
  # bare key kept as the `:inbound` alias, which is why nothing outside this
  # module changes: every existing scenario, the `reply_invite_with_sdp` path,
  # the MCU module and the suites that read `:mediapeerconnectionid` straight out
  # of the appdata all keep addressing the leg they always addressed.
  @default_leg :inbound

  # This module's own vocabulary; everything else in an `opts` list is the
  # adapter's (`create_peer_connection/3`, `create_player/3`, …).
  #
  # `:webrtc` and `:media` are ours even though the adapter has keys of its own
  # that mean the same thing: we translate them into the `webrtc_support:` and
  # `media:` we pass explicitly, so forwarding them again would put the same
  # decision in the list twice, under two spellings, with only `Keyword.get`
  # ordering deciding which one an adapter reads.
  @framework_opts [:leg, :bridge_with, :webrtc, :media]

  defp leg_of(opts), do: Keyword.get(opts, :leg, @default_leg)
  defp adapter_opts(opts), do: Keyword.drop(opts, @framework_opts)

  defp pc_key(@default_leg), do: :mediapeerconnectionid
  defp pc_key(leg), do: {:mediapeerconnectionid, leg}

  defp action_key(@default_leg), do: :mediaactionid
  defp action_key(leg), do: {:mediaactionid, leg}

  defp action_kind_key(@default_leg), do: :mediaaction
  defp action_kind_key(leg), do: {:mediaaction, leg}

  @doc "The media-server peer connection of `leg`, or nil when it has none."
  @spec peer_connection(%SIP.Context{}, atom()) :: term() | nil
  def peer_connection(sip_ctx = %SIP.Context{}, leg \\ @default_leg),
    do: SIP.Context.appdata_get(sip_ctx, pc_key(leg))

  @doc """
  The legs this context holds a peer connection for, in the order they were
  created. Empty when no media was ever negotiated.

  Kept explicitly rather than derived from the appdata keys: `media_cleanup_ressources/1`
  has to release every leg, and a map scan would have to guess which keys are
  media handles.
  """
  @spec media_legs(%SIP.Context{}) :: [atom()]
  def media_legs(sip_ctx = %SIP.Context{}),
    do: SIP.Context.appdata_get(sip_ctx, :medialegs) || []

  @doc """
  Close `leg`'s peer connection and forget its handle, so the next
  `get_sdp_offer/4` or `get_sdp_answer/3` creates another one.

  What an offer-profile fallback is made of (design §7.5): a local description is
  a property of the endpoint — its ports, its DTLS fingerprint, its ICE
  credentials and the profile of every `m=` line are fixed when the connection is
  created — so offering the same callee a *different* profile means another
  endpoint, not another offer on this one.

  Closing is best effort: an endpoint the server has already lost must not be
  what stops us from trying the rung below. Everything else the leg owns —
  above all the OTHER leg's connection and the media session they share — is
  untouched.
  """
  @spec drop_peer_connection(%SIP.Context{}, atom()) :: %SIP.Context{}
  def drop_peer_connection(sip_ctx = %SIP.Context{}, leg \\ @default_leg) do
    case SIP.Context.appdata_get(sip_ctx, pc_key(leg)) do
      nil ->
        sip_ctx

      cnx ->
        safe_ms_call(sip_ctx.mediaservermodule, :close_peer_connection, [cnx])
        SIP.Context.appdata_set(sip_ctx, pc_key(leg), nil)
    end
  end

  defp register_leg(sip_ctx, leg) do
    legs = media_legs(sip_ctx)
    if leg in legs, do: sip_ctx, else: SIP.Context.appdata_set(sip_ctx, :medialegs, legs ++ [leg])
  end

  # `bridge_with: :inbound` names the OTHER leg; the adapter needs its handle.
  # A value that is not a leg name is passed through untouched, so a caller that
  # already holds a handle can give it directly.
  defp resolve_bridge_with(opts, sip_ctx) do
    case Keyword.fetch(opts, :bridge_with) do
      {:ok, leg} when is_atom(leg) ->
        case peer_connection(sip_ctx, leg) do
          nil -> []
          cnx -> [bridge_with: cnx]
        end

      {:ok, handle} ->
        [bridge_with: handle]

      :error ->
        []
    end
  end

  @doc """
  Connect to the media server designated by the `:mediaserver` application
  config (`config :elixip2, :mediaserver, module: ..., url: ...`).

  The `:module` value is either a module or one of the `:mockup` /
  `:mendooze` shorthands usable from scenario `config` blocks and external
  JSON files. Defaults to `MediaServer.Mockup`.

  `module: :unavailable` is not a server but a **verdict**: whoever chose the media
  server for this call looked and found none. It is what `Kelix.MediaPool` reports
  through `:mediaserver_instance` when no pooled MCU is serviceable. Nothing is
  connected, `:lasterr` is set to `{:error, :no_media_server}`, and the scenario
  decides what to answer — a call that needs media and has none is the server's
  fault, so a `503` rather than the `488` a codec mismatch earns.
  """
  @spec use_mediaserver(%SIP.Context{}) :: %SIP.Context{}
  def use_mediaserver(sip_ctx = %SIP.Context{}) do
    cfg = ms_config(sip_ctx) |> normalize_ms_config()

    case Keyword.get(cfg, :module, :mockup) do
      :unavailable ->
        Logger.warning(
          module: __MODULE__,
          message:
            "media_connect: no media server available for this call; " <>
              "not connecting, and NOT falling back to a stub"
        )

        SIP.Context.set(sip_ctx, :lasterr, {:error, :no_media_server})

      module ->
        url = Keyword.get(cfg, :url, "sip:localhost:8080")

        sip_ctx
        |> SIP.Context.appdata_set(:mediaservername, Keyword.get(cfg, :name))
        |> use_mediaserver(resolve_ms_module(module), url)
    end
  end

  # A per-instance override (in the context appdata under `:mediaserver_instance`)
  # wins over the global `:mediaserver` app env. This lets a server like kelixip
  # pick a pool MCU *per call* without racing on the shared app env — the standalone
  # tool, which sets no such override, keeps its global-config behaviour unchanged.
  defp ms_config(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :mediaserver_instance) do
      nil -> Application.get_env(:elixip2, :mediaserver, [])
      override -> override
    end
  end

  defp normalize_ms_config(cfg) when is_map(cfg), do: Map.to_list(cfg)
  defp normalize_ms_config(cfg) when is_list(cfg), do: cfg

  defp resolve_ms_module(:mockup), do: MediaServer.Mockup
  defp resolve_ms_module(:mendooze), do: MediaServer.Mendooze
  defp resolve_ms_module(module) when is_atom(module), do: module

  def use_mediaserver(sip_ctx = %SIP.Context{}, module, url)
      when is_atom(module) and is_binary(url) do
    if not Code.ensure_loaded?(module) do
      raise "Media server module must be an Elixir module"
    end

    sip_ctx = SIP.Context.set(sip_ctx, :mediaservermodule, module)
    rez = apply(module, :connect, [url])

    sip_ctx =
      case rez do
        {:ok, pid} ->
          # The monitor names the server by the name it is DECLARED under
          # (`[mediaserver.pool.<name>]`), which the pool passes down in the
          # per-call override. A media server named nowhere — the two-argument
          # `media_connect(module, url)`, the global `:mediaserver` config of the
          # standalone tool — is shown by its url: still an answer to "which one",
          # and the only one there is.
          SIP.Scenario.Monitor.note_mediaserver(
            SIP.Context.appdata_get(sip_ctx, :mediaservername) || url
          )

          sip_ctx
          |> SIP.Context.set(:mediaserverpid, pid)
          |> SIP.Context.set(:lasterr, :ok)
          |> watch_media_server(pid)

        _ ->
          raise "Failed to connect to media server #{url}"
      end

    sip_ctx
  end

  @doc """
  Watch the media server process, so that it **dying** reaches the scenario as
  the same `:server_disconnected` it already gets when the server *disconnects*
  (design docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain, R8 item 1). One event, one meaning:
  the media plane is gone.

  A separate watcher process rather than a monitor in the scenario: a scenario
  already receives `{:DOWN, …}` for its sub-FSM children, so a `DOWN` clause in
  `on_events` would fire on those too — and it would have to be a clause, since
  `on_events` is a plain `receive` and cannot see what it does not match. The
  watcher converts the signal into the message shape everything downstream
  already understands, and misfires on nothing.

  Without it the gap is not theoretical: an adapter killed outright runs no
  `terminate/2` and announces nothing, so the scenario waits for media that
  cannot come until its own `after` fires, and only discovers the truth when its
  next media call exits `:noproc`.
  """
  @spec watch_media_server(%SIP.Context{}, pid()) :: %SIP.Context{}
  def watch_media_server(sip_ctx = %SIP.Context{}, server) when is_pid(server) do
    scenario = self()

    watcher =
      spawn(fn ->
        ref = Process.monitor(server)

        receive do
          {:DOWN, ^ref, :process, ^server, reason} ->
            # A normal stop is what `disconnect/2` does, and the scenario asked
            # for it — announcing that would turn every clean teardown into a
            # media failure.
            if reason not in [:normal, :shutdown] do
              send(scenario, {:ms_event, server, :server_disconnected})
            end

          :stop_watching ->
            :ok
        end
      end)

    SIP.Context.appdata_set(sip_ctx, :mediaserverwatcher, watcher)
  end

  @doc """
  Build a local SDP offer from the connected media server.

  Creates the peer connection on first call and stores its handle in the
  context appdata (`:mediapeerconnectionid` for the inbound leg,
  `{:mediapeerconnectionid, leg}` otherwise), so subsequent calls reuse it.
  Returns `{updated_ctx, sdp_offer}`.

  `opts` accepts `:leg` (default `:inbound`) and `:bridge_with` (the leg whose
  media session this one joins — see `ensure_peer_connection/5`); anything else
  is passed to the adapter when the connection is created.
  """
  @spec get_sdp_offer(%SIP.Context{}, atom(), MediaServer.media_kind(), keyword()) ::
          {%SIP.Context{}, binary()}
  def get_sdp_offer(sip_ctx = %SIP.Context{}, webrtc_support, medias, opts \\ [])
      when is_atom(webrtc_support) and is_list(opts) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    {sip_ctx, cnx} = ensure_peer_connection(sip_ctx, leg_of(opts), webrtc_support, medias, opts)

    offer =
      case apply(sip_ctx.mediaservermodule, :get_local_offer, [cnx]) do
        {:ok, offer} ->
          offer

        {:error, reason} ->
          raise "Media server failed to build the SDP offer: #{inspect(reason)}"
      end

    {sip_ctx, offer}
  end

  @doc """
  Accept an inbound remote SDP offer and negotiate the local SDP answer, the
  UAS-side counterpart of `get_sdp_offer/3`.

  Creates the peer connection on the first call and stores its handle in the
  context appdata (`:mediapeerconnectionid`), reusing it afterwards (so a
  re-INVITE renegotiates on the same connection). Returns
  `{updated_ctx, {:ok, answer}}` on success or `{updated_ctx, {:error, reason}}`
  when the media server rejects the offer — the caller
  (`reply_invite_with_sdp`) maps that error to a `500 Media Server Error`
  response. Raises when no media server is connected (the scenario must have
  called `media_connect()` first), mirroring `get_sdp_offer/3`.

  `opts` accepts `:webrtc` (default `:no`) and `:media` (default `:audio_video`)
  used only when the peer connection is created.
  """
  @spec get_sdp_answer(%SIP.Context{}, binary(), keyword()) ::
          {%SIP.Context{}, {:ok, binary()} | {:error, term()}}
  def get_sdp_answer(sip_ctx = %SIP.Context{}, remote_offer, opts \\ [])
      when is_binary(remote_offer) and is_list(opts) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    webrtc_support = Keyword.get(opts, :webrtc, :no)
    medias = Keyword.get(opts, :media, :audio_video)
    {sip_ctx, cnx} = ensure_peer_connection(sip_ctx, leg_of(opts), webrtc_support, medias, opts)

    {sip_ctx,
     note_negotiated(apply(sip_ctx.mediaservermodule, :set_remote_offer, [cnx, remote_offer]))}
  end

  # The monitor's `medias` column, from the one place each side of a negotiation
  # concludes: the answer we just built (here) and the answer we were just given
  # (`process_sdp_answer/3`). Reading it off the answer is what makes it true of
  # every adapter — Mockup, Mendooze and the MCU all answer with an SDP, and none
  # of them is asked what it put in it.
  defp note_negotiated({:ok, answer} = rez) when is_binary(answer) do
    SIP.Scenario.Monitor.note_medias(SIP.Msg.Ops.media_kinds(answer))
    rez
  end

  defp note_negotiated(rez), do: rez

  # Return {ctx, cnx}: reuse the stored peer connection of `leg`, creating one
  # (and stashing its handle) on first use. Shared by get_sdp_offer/4 (UAC) and
  # get_sdp_answer/3 (UAS). Raises when the media server cannot create it.
  #
  # `bridge_with:` names the leg whose media session this one must join. It is
  # not the same request as `bridge/3`: this one says WHERE the endpoint lives,
  # and it can only be answered at creation time — on a Medooze server two
  # endpoints are connectable only inside one MediaSession
  # (docs/design/notes/mediagw_b2bua_jsr309.md §2). Adapters with nothing to share
  # ignore it, which is why it is safe to pass unconditionally.
  defp ensure_peer_connection(sip_ctx = %SIP.Context{}, leg, webrtc_support, medias, opts) do
    case SIP.Context.appdata_get(sip_ctx, pc_key(leg)) do
      nil ->
        conn_opts =
          [webrtc_support: webrtc_support, media: medias] ++
            local_address_opts(sip_ctx, leg) ++
            extra_conn_opts(sip_ctx) ++
            resolve_bridge_with(opts, sip_ctx) ++ adapter_opts(opts)

        cnx =
          case apply(sip_ctx.mediaservermodule, :create_peer_connection, [
                 sip_ctx.mediaserverpid,
                 self(),
                 conn_opts
               ]) do
            {:ok, cnx} ->
              cnx

            {:error, reason} ->
              raise "Media server failed to create peer connection: #{inspect(reason)}"
          end

        {sip_ctx |> register_leg(leg) |> SIP.Context.appdata_set(pc_key(leg), cnx), cnx}

      cnx ->
        {sip_ctx, cnx}
    end
  end

  # `local_ip:` — the address of OURS that this peer reached, as an
  # `:inet.ip_address()` tuple. It is the same address
  # `SIP.Transport.build_contact_uri/2` writes into this leg's Contact, and it is
  # there for the same reason: of the addresses this node holds, it is one this
  # peer demonstrably has a route to. An adapter that must place media on an
  # interface has no other honest source for it — the node's configuration
  # describes every interface at once, and on a node bridging two of them that is
  # right for one leg and wrong for the other.
  #
  # Only the leg we ANSWER has it, and only it: the inbound request carries the
  # transport it arrived on (`ruri.tp_pid`, stamped by
  # `SIP.Transport.do_process_incoming_message/7`). A leg this node PLACES has no
  # transport until its request goes out — and on a B2BUA it faces the other side of
  # the network entirely, so lending it the inbound address would be worse than
  # saying nothing. The option is then absent rather than guessed, and every adapter
  # reads it with `Keyword.get/3`.
  defp local_address_opts(sip_ctx, @default_leg) do
    with %{ruri: %SIP.Uri{tp_pid: tp_pid}} when is_pid(tp_pid) <-
           SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
             SIP.Context.appdata_get(sip_ctx, :inbound_request),
         {:ok, local_ip, _local_port} <- SIP.Transport.get_local_ip_port(tp_pid) do
      [local_ip: local_ip]
    else
      _ -> []
    end
  end

  defp local_address_opts(_sip_ctx, _leg), do: []

  @doc """
  Per-call options a scenario adds to `create_peer_connection/3`, read from the
  context appdata key `:media_conn_opts` (a keyword list or a map).

  This is how a script passes an adapter *the context of this call* — which
  conference this leg joins, for instance — without the media macros having to know
  what that means. The macros' own keys (`:webrtc_support`, `:media`) come first and
  therefore win, since adapters read them with `Keyword.get/3`; an adapter that does
  not know an extra key ignores it, which is what makes this additive for every
  existing one.
  """
  @spec extra_conn_opts(%SIP.Context{}) :: keyword()
  def extra_conn_opts(sip_ctx = %SIP.Context{}) do
    case SIP.Context.appdata_get(sip_ctx, :media_conn_opts) do
      opts when is_list(opts) -> opts
      opts when is_map(opts) -> Map.to_list(opts)
      _ -> []
    end
  end

  @doc """
  Feed a remote SDP answer to the media server peer connection.
  Stores the result (`:ok` / `{:error, _}`) in `:lasterr` and returns the context.
  """
  @spec process_sdp_answer(%SIP.Context{}, binary(), keyword()) :: %SIP.Context{}
  def process_sdp_answer(sip_ctx = %SIP.Context{}, answer, opts \\ [])
      when is_binary(answer) and is_list(opts) do
    cnx = peer_connection!(sip_ctx, leg_of(opts))
    rez = apply(sip_ctx.mediaservermodule, :set_remote_answer, [cnx, answer])
    if rez == :ok, do: SIP.Scenario.Monitor.note_medias(SIP.Msg.Ops.media_kinds(answer))
    SIP.Context.set(sip_ctx, :lasterr, rez)
  end

  @doc """
  Tell the media server that the call is **answered** on `opts[:leg]` (every leg
  holding a peer connection when none is named): the peer may now be expected to
  send, and whatever watches for its absence starts from here.

  This is the framework's single statement of that moment. The media layer cannot
  derive it — an SDP is negotiated when the INVITE arrives or when a 183 comes
  back, both of them long before anyone picks up — so an adapter left to guess
  starts its RTP watchdog during the ringing and hangs up the calls that ring
  longest (traffic of 2026-08-13:
  `MediaServer.Behaviour.call_answered/1` carries the trace).

  Best-effort and idempotent: a call that is up must not fall over because its
  supervision could not be armed. Failures are logged; `:lasterr` is left alone.
  """
  @spec call_answered(%SIP.Context{}, keyword()) :: %SIP.Context{}
  def call_answered(sip_ctx = %SIP.Context{}, opts \\ []) when is_list(opts) do
    legs =
      case Keyword.fetch(opts, :leg) do
        {:ok, leg} -> [leg]
        :error -> [@default_leg | media_legs(sip_ctx)] |> Enum.uniq()
      end

    for leg <- legs, cnx = peer_connection(sip_ctx, leg) do
      case safe_ms_call(sip_ctx.mediaservermodule, :call_answered, [cnx]) do
        :ok ->
          :ok

        other ->
          Logger.warning(
            dialogpid: sip_ctx.dialogpid,
            module: __MODULE__,
            message:
              "media server refused the answered notification on leg #{leg} " <>
                "(#{inspect(other)}); this leg's media supervision is not armed"
          )
      end
    end

    sip_ctx
  end

  # The peer connection an action must run on, or a refusal that names what is
  # missing. One reading for every action below, which is what keeps them from
  # drifting apart as legs multiply.
  defp peer_connection!(sip_ctx, leg) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    case peer_connection(sip_ctx, leg) do
      nil -> raise "No media peer connection found in the session context for leg #{leg}"
      cnx -> cnx
    end
  end

  # An action is single-slot PER LEG: a connection plays, records or echoes, and
  # asking for a second one on the same leg is a scenario bug rather than a
  # request to stack them.
  defp action_busy?(sip_ctx, leg, what) do
    if is_nil(SIP.Context.appdata_get(sip_ctx, action_key(leg))) do
      false
    else
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "Media action already started on leg #{leg}, ignoring #{what} request"
      )

      true
    end
  end

  defp put_action(sip_ctx, leg, kind, handle) do
    sip_ctx
    |> SIP.Context.appdata_set(action_key(leg), handle)
    |> SIP.Context.appdata_set(action_kind_key(leg), kind)
  end

  def start_echo(sip_ctx = %SIP.Context{}, opts \\ []) do
    leg = leg_of(opts)
    cnx = peer_connection!(sip_ctx, leg)

    if action_busy?(sip_ctx, leg, "start_echo") do
      sip_ctx
    else
      {:ok, echo_pid} = apply(sip_ctx.mediaservermodule, :create_echo, [cnx])
      put_action(sip_ctx, leg, :echo, echo_pid)
    end
  end

  @doc """
  Create a media player from `file_path` on the session peer connection and
  start it, mirroring `start_echo/1`. The player handle becomes the current
  media action (`:mediaactionid` / `:mediaaction = :player`) and is released by
  `stop_media/1` and `media_cleanup_ressources/1`. `opts` is forwarded to the
  media server `create_player/3` callback (e.g. `loop: true`).
  """
  @spec start_player(%SIP.Context{}, binary(), keyword()) :: %SIP.Context{}
  def start_player(sip_ctx = %SIP.Context{}, file_path, opts \\ [])
      when is_binary(file_path) and is_list(opts) do
    leg = leg_of(opts)
    cnx = peer_connection!(sip_ctx, leg)

    if action_busy?(sip_ctx, leg, "start_player") do
      sip_ctx
    else
      {:ok, player_pid} =
        apply(sip_ctx.mediaservermodule, :create_player, [cnx, file_path, adapter_opts(opts)])

      :ok = apply(sip_ctx.mediaservermodule, :start_player, [player_pid])

      put_action(sip_ctx, leg, :player, player_pid)
    end
  end

  @doc """
  Create a recorder writing to `file_path` on the session peer connection and
  start it, mirroring `start_player/3`. The recorder stops on its own after
  `duration_ms` (the media server emits `{:recorder_stopped, :duration}`), on
  DTMF/silence, or when released. The recorder handle becomes the current media
  action (`:mediaactionid` / `:mediaaction = :recorder`) and is released by
  `stop_media/1` and `media_cleanup_ressources/1`. `opts` is forwarded to the
  media server `create_recorder/4` callback.
  """
  @spec start_recorder(%SIP.Context{}, binary(), non_neg_integer(), keyword()) :: %SIP.Context{}
  def start_recorder(sip_ctx = %SIP.Context{}, file_path, duration_ms, opts \\ [])
      when is_binary(file_path) and is_integer(duration_ms) and duration_ms >= 0 and
             is_list(opts) do
    leg = leg_of(opts)
    cnx = peer_connection!(sip_ctx, leg)

    if action_busy?(sip_ctx, leg, "start_recorder") do
      sip_ctx
    else
      {:ok, rec_pid} =
        apply(sip_ctx.mediaservermodule, :create_recorder, [
          cnx,
          file_path,
          duration_ms,
          adapter_opts(opts)
        ])

      :ok = apply(sip_ctx.mediaservermodule, :start_recorder, [rec_pid])

      put_action(sip_ctx, leg, :recorder, rec_pid)
    end
  end

  def stop_media(sip_ctx = %SIP.Context{}, opts \\ []) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    leg = leg_of(opts)
    action_pid = SIP.Context.appdata_get(sip_ctx, action_key(leg))

    if not is_nil(action_pid) do
      case SIP.Context.appdata_get(sip_ctx, action_kind_key(leg)) do
        :echo ->
          apply(sip_ctx.mediaservermodule, :stop_echo, [action_pid])

        :player ->
          apply(sip_ctx.mediaservermodule, :stop_player, [action_pid])

        :recorder ->
          apply(sip_ctx.mediaservermodule, :stop_recorder, [action_pid])

        other ->
          Logger.warning(
            dialogpid: self(),
            module: __MODULE__,
            message: "Unknown media action #{inspect(other)}, ignoring stop_media request"
          )
      end

      put_action(sip_ctx, leg, nil, nil)
    else
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "No media action started on leg #{leg}, ignoring stop_media request"
      )

      sip_ctx
    end
  end

  @doc """
  Release every media resource held by the context, in the proper teardown
  order: stop the in-progress action (echo/player/recorder) → close the peer
  connection → disconnect the media server. Clears the corresponding handles
  from the context and returns it.

  Idempotent and defensive: missing or already-released handles are skipped,
  so it is safe to call on a call-end notification (`{:dialog_terminated, …}`)
  even if `media_stop/1` was already invoked.
  """
  @spec media_cleanup_ressources(%SIP.Context{}) :: %SIP.Context{}
  def media_cleanup_ressources(sip_ctx = %SIP.Context{}) do
    # Every leg, not just the inbound one: a B2BUA holds two connections on one
    # server, and releasing the server while the second is still open leaks it
    # server-side. `:inbound` is always attempted — a context that never called
    # media_legs-registering code can still hold the bare key (a scenario that
    # set it by hand, the MCU module's path).
    legs = Enum.uniq([@default_leg | media_legs(sip_ctx)])

    legs
    |> Enum.reduce(sip_ctx, fn leg, ctx ->
      ctx |> cleanup_action(leg) |> cleanup_peer_connection(leg)
    end)
    |> SIP.Context.appdata_set(:medialegs, [])
    |> cleanup_media_server()
  end

  defp cleanup_action(sip_ctx, leg) do
    action_pid = SIP.Context.appdata_get(sip_ctx, action_key(leg))

    if is_nil(action_pid) do
      sip_ctx
    else
      case SIP.Context.appdata_get(sip_ctx, action_kind_key(leg)) do
        :echo ->
          safe_ms_call(sip_ctx.mediaservermodule, :stop_echo, [action_pid])

        :player ->
          safe_ms_call(sip_ctx.mediaservermodule, :stop_player, [action_pid])

        :recorder ->
          safe_ms_call(sip_ctx.mediaservermodule, :stop_recorder, [action_pid])

        other ->
          Logger.warning(
            dialogpid: self(),
            module: __MODULE__,
            message: "Cannot release unknown media action #{inspect(other)}"
          )
      end

      put_action(sip_ctx, leg, nil, nil)
    end
  end

  defp cleanup_peer_connection(sip_ctx, leg), do: drop_peer_connection(sip_ctx, leg)

  defp cleanup_media_server(sip_ctx) do
    # The watcher goes first: releasing the server is exactly the death it exists
    # to report, and reporting it into a scenario that is already tearing down
    # would be noise at best.
    sip_ctx = stop_watching(sip_ctx)

    if is_nil(sip_ctx.mediaserverpid) do
      sip_ctx
    else
      safe_ms_call(sip_ctx.mediaservermodule, :disconnect, [sip_ctx.mediaserverpid, []])
      SIP.Context.set(sip_ctx, :mediaserverpid, nil)
    end
  end

  defp stop_watching(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :mediaserverwatcher) do
      pid when is_pid(pid) ->
        send(pid, :stop_watching)
        SIP.Context.appdata_set(sip_ctx, :mediaserverwatcher, nil)

      _ ->
        sip_ctx
    end
  end

  # Call a media server callback defensively: skip dead pid handles and never
  # let a teardown error crash the caller (cleanup runs on the call-end path).
  defp safe_ms_call(module, fun, args = [handle | _]) do
    if is_pid(handle) and not Process.alive?(handle) do
      :ok
    else
      try do
        apply(module, fun, args)
      catch
        kind, reason ->
          Logger.warning(
            module: __MODULE__,
            message: "media #{fun} during cleanup raised #{kind}: #{inspect(reason)}"
          )

          :error
      end
    end
  end
end
