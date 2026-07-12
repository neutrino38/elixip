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

      defmacro media_start_echo() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_start_echo")
          var!(sip_ctx) = SIP.Session.Media.start_echo(var!(sip_ctx))
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

      defmacro media_stop() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "media_stop")
          var!(sip_ctx) = SIP.Session.Media.stop_media(var!(sip_ctx))
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

  @doc """
  Connect to the media server designated by the `:mediaserver` application
  config (`config :elixip2, :mediaserver, module: ..., url: ...`).

  The `:module` value is either a module or one of the `:mockup` /
  `:mendooze` shorthands usable from scenario `config` blocks and external
  JSON files. Defaults to `MediaServer.Mockup`.
  """
  @spec use_mediaserver(%SIP.Context{}) :: %SIP.Context{}
  def use_mediaserver(sip_ctx = %SIP.Context{}) do
    cfg = Application.get_env(:elixip2, :mediaserver, []) |> normalize_ms_config()
    module = Keyword.get(cfg, :module, :mockup) |> resolve_ms_module()
    url = Keyword.get(cfg, :url, "sip:localhost:8080")
    use_mediaserver(sip_ctx, module, url)
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
  context appdata (`:mediapeerconnectionid`), so subsequent calls reuse it.
  Returns `{updated_ctx, sdp_offer}`.
  """
  @spec get_sdp_offer(%SIP.Context{}, atom(), atom()) :: {%SIP.Context{}, binary()}
  def get_sdp_offer(sip_ctx = %SIP.Context{}, webrtc_support, medias) when is_atom(webrtc_support) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    {sip_ctx, cnx} = ensure_peer_connection(sip_ctx, webrtc_support, medias)

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
    {sip_ctx, cnx} = ensure_peer_connection(sip_ctx, webrtc_support, medias)

    {sip_ctx, apply(sip_ctx.mediaservermodule, :set_remote_offer, [cnx, remote_offer])}
  end

  # Return {ctx, cnx}: reuse the stored peer connection, creating one (and
  # stashing its handle) on first use. Shared by get_sdp_offer/3 (UAC) and
  # get_sdp_answer/3 (UAS). Raises when the media server cannot create it.
  defp ensure_peer_connection(sip_ctx = %SIP.Context{}, webrtc_support, medias) do
    case SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) do
      nil ->
        cnx =
          case apply(sip_ctx.mediaservermodule, :create_peer_connection, [
                 sip_ctx.mediaserverpid,
                 self(),
                 [webrtc_support: webrtc_support, media: medias]
               ]) do
            {:ok, cnx} ->
              cnx

            {:error, reason} ->
              raise "Media server failed to create peer connection: #{inspect(reason)}"
          end

        {SIP.Context.appdata_set(sip_ctx, :mediapeerconnectionid, cnx), cnx}

      cnx ->
        {sip_ctx, cnx}
    end
  end

  @doc """
  Feed a remote SDP answer to the media server peer connection.
  Stores the result (`:ok` / `{:error, _}`) in `:lasterr` and returns the context.
  """
  @spec process_sdp_answer(%SIP.Context{}, binary()) :: %SIP.Context{}
  def process_sdp_answer(sip_ctx = %SIP.Context{}, answer) when is_binary(answer) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) do
      raise "No media peer connection found in the session context"
    end

    rez = apply(sip_ctx.mediaservermodule, :set_remote_answer, [cnx, answer])
    SIP.Context.set(sip_ctx, :lasterr, rez)
  end

  def start_echo(sip_ctx = %SIP.Context{}) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) do
      raise "No media peer connection found in the session context"
    end

    if not is_nil(SIP.Context.appdata_get(sip_ctx, :mediaactionid)) do
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "Media action already started, ignoring start_echo request"
      )

      sip_ctx
    else
      {:ok, echo_pid} = apply(sip_ctx.mediaservermodule, :create_echo, [cnx])

      SIP.Context.appdata_set(sip_ctx, :mediaactionid, echo_pid)
      |> SIP.Context.appdata_set(:mediaaction, :echo)
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
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) do
      raise "No media peer connection found in the session context"
    end

    if not is_nil(SIP.Context.appdata_get(sip_ctx, :mediaactionid)) do
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "Media action already started, ignoring start_player request"
      )

      sip_ctx
    else
      {:ok, player_pid} =
        apply(sip_ctx.mediaservermodule, :create_player, [cnx, file_path, opts])

      :ok = apply(sip_ctx.mediaservermodule, :start_player, [player_pid])

      SIP.Context.appdata_set(sip_ctx, :mediaactionid, player_pid)
      |> SIP.Context.appdata_set(:mediaaction, :player)
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
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) do
      raise "No media peer connection found in the session context"
    end

    if not is_nil(SIP.Context.appdata_get(sip_ctx, :mediaactionid)) do
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "Media action already started, ignoring start_recorder request"
      )

      sip_ctx
    else
      {:ok, rec_pid} =
        apply(sip_ctx.mediaservermodule, :create_recorder, [cnx, file_path, duration_ms, opts])

      :ok = apply(sip_ctx.mediaservermodule, :start_recorder, [rec_pid])

      SIP.Context.appdata_set(sip_ctx, :mediaactionid, rec_pid)
      |> SIP.Context.appdata_set(:mediaaction, :recorder)
    end
  end

  def stop_media(sip_ctx = %SIP.Context{}) do
    if not is_pid(sip_ctx.mediaserverpid) do
      raise "No media server connected to the session context"
    end

    action_pid = SIP.Context.appdata_get(sip_ctx, :mediaactionid)

    if not is_nil(action_pid) do
      case SIP.Context.appdata_get(sip_ctx, :mediaaction) do
        :echo ->
          apply(sip_ctx.mediaservermodule, :stop_echo, [action_pid])

        :player ->
          apply(sip_ctx.mediaservermodule, :stop_player, [action_pid])

        :recorder ->
          apply(sip_ctx.mediaservermodule, :stop_recorder, [action_pid])

        _ ->
          Logger.warning(
            dialogpid: self(),
            module: __MODULE__,
            message:
              "Unknown media action #{inspect(SIP.Context.appdata_get(sip_ctx, :mediaaction))}, ignoring stop_media request"
          )
      end

      SIP.Context.appdata_set(sip_ctx, :mediaactionid, nil)
      |> SIP.Context.appdata_set(:mediaaction, nil)
    else
      Logger.warning(
        dialogpid: self(),
        module: __MODULE__,
        message: "No media action started, ignoring stop_media request"
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
    sip_ctx
    |> cleanup_action()
    |> cleanup_peer_connection()
    |> cleanup_media_server()
  end

  defp cleanup_action(sip_ctx) do
    action_pid = SIP.Context.appdata_get(sip_ctx, :mediaactionid)

    if is_nil(action_pid) do
      sip_ctx
    else
      case SIP.Context.appdata_get(sip_ctx, :mediaaction) do
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

      SIP.Context.appdata_set(sip_ctx, :mediaactionid, nil)
      |> SIP.Context.appdata_set(:mediaaction, nil)
    end
  end

  defp cleanup_peer_connection(sip_ctx) do
    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) do
      sip_ctx
    else
      safe_ms_call(sip_ctx.mediaservermodule, :close_peer_connection, [cnx])
      SIP.Context.appdata_set(sip_ctx, :mediapeerconnectionid, nil)
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
