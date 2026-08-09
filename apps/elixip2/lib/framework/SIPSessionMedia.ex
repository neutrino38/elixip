defmodule SIP.Session.Media do
  @moduledoc """
  Media helpers mixin for SIP sessions.

  This module provides the `media_connect`, `media_play`, `media_record`,
  `media_start_echo`, `media_stop` and `media_cleanup_ressources` DSL macros
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
  # (design docs/design/b2bua_module.md §7), so the single-slot handles this
  # mixin started with are no longer enough. They become leg-scoped — with the
  # bare key kept as the `:inbound` alias, which is why nothing outside this
  # module changes: every existing scenario, the `reply_invite_with_sdp` path,
  # the MCU module and the suites that read `:mediapeerconnectionid` straight out
  # of the appdata all keep addressing the leg they always addressed.
  @default_leg :inbound

  # Options this module reads itself; everything else in an `opts` list is the
  # adapter's (`create_peer_connection/3`, `create_player/3`, …).
  @framework_opts [:leg, :bridge_with]

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
  """
  @spec use_mediaserver(%SIP.Context{}) :: %SIP.Context{}
  def use_mediaserver(sip_ctx = %SIP.Context{}) do
    cfg = ms_config(sip_ctx) |> normalize_ms_config()
    module = Keyword.get(cfg, :module, :mockup) |> resolve_ms_module()
    url = Keyword.get(cfg, :url, "sip:localhost:8080")
    use_mediaserver(sip_ctx, module, url)
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
        {:ok, pid} -> SIP.Context.set(sip_ctx, :mediaserverpid, pid)
        _ -> raise "Failed to connect to media server #{url}"
      end

    sip_ctx
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

    {sip_ctx, apply(sip_ctx.mediaservermodule, :set_remote_offer, [cnx, remote_offer])}
  end

  # Return {ctx, cnx}: reuse the stored peer connection of `leg`, creating one
  # (and stashing its handle) on first use. Shared by get_sdp_offer/4 (UAC) and
  # get_sdp_answer/3 (UAS). Raises when the media server cannot create it.
  #
  # `bridge_with:` names the leg whose media session this one must join. It is
  # not the same request as `bridge/3`: this one says WHERE the endpoint lives,
  # and it can only be answered at creation time — on a Medooze server two
  # endpoints are connectable only inside one MediaSession
  # (docs/design/mediagw_b2bua_jsr309.md §2). Adapters with nothing to share
  # ignore it, which is why it is safe to pass unconditionally.
  defp ensure_peer_connection(sip_ctx = %SIP.Context{}, leg, webrtc_support, medias, opts) do
    case SIP.Context.appdata_get(sip_ctx, pc_key(leg)) do
      nil ->
        conn_opts =
          [webrtc_support: webrtc_support, media: medias] ++
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
    SIP.Context.set(sip_ctx, :lasterr, rez)
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

  defp cleanup_peer_connection(sip_ctx, leg) do
    cnx = SIP.Context.appdata_get(sip_ctx, pc_key(leg))

    if is_nil(cnx) do
      sip_ctx
    else
      safe_ms_call(sip_ctx.mediaservermodule, :close_peer_connection, [cnx])
      SIP.Context.appdata_set(sip_ctx, pc_key(leg), nil)
    end
  end

  defp cleanup_media_server(sip_ctx) do
    if is_nil(sip_ctx.mediaserverpid) do
      sip_ctx
    else
      safe_ms_call(sip_ctx.mediaservermodule, :disconnect, [sip_ctx.mediaserverpid, []])
      SIP.Context.set(sip_ctx, :mediaserverpid, nil)
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
