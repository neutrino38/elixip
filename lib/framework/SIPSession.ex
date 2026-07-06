defmodule SIP.Session do
  @moduledoc """
  This module defines an Agent and several behaviors.
  The behaviors are to be implemented by SIP apps in order to process requests and create processes if need.
  These behavors requires specialized callback that will be invoked when a dialog is created by a server transaction:
  eg. incoming calls, incoming registration (when implemebenting a registrar) or incoming presence / messaging

  Each of these callback function shall return a pid of an "application process" that will be bound to the dialog.
  This process will receive the various SIP requests and responses from the dialog layer. All the dirty details such
  as SIP retransmission, and refresh, etc will be handled by the dialog layer

  It is assumed by the dialog layer that the app process is processing requests as follow:

  on_event do
   { <method>, <req message>, <transaction_pid>, <dialog_pid> } ->

  e.g.

  on_event do
    { :BYE, <req message>, <transaction_pid>, <dialog_pid> } ->

  For SIP responses

  on_event do
    { <resp code>, <resp message>, <transaction_pid>, <dialog_pid> } ->

  """
  require Logger

  defp register_last_transaction(sip_ctx = %SIP.Context{}, method, transaction_pid)
       when is_pid(transaction_pid) and is_atom(method) do
    case method do
      :INVITE ->
        SIP.Context.appdata_set(sip_ctx, :last_uac_invite_tid, transaction_pid)

      :REGISTER ->
        SIP.Context.appdata_set(sip_ctx, :last_uac_register_tid, transaction_pid)

      :OPTIONS ->
        SIP.Context.appdata_set(sip_ctx, :last_uac_options_tid, transaction_pid)

      _ ->
        sip_ctx
    end
  end

  # After an outbound dialog is created, the dialog layer publishes the initial
  # UAC transaction pid as `{:onnewdialog, :ok, tid}` to this (the app) process
  # — see SIP.DialogImpl.init/1. The message is delivered synchronously during
  # dialog creation, so it is already in the mailbox by the time start_dialog/4
  # returns; consume it and store the transaction in the context, mirroring the
  # in-dialog request path. The timeout is only a safety net.
  defp register_initial_transaction(sip_ctx = %SIP.Context{}, method) when is_atom(method) do
    receive do
      {:onnewdialog, :ok, transaction_pid} ->
        register_last_transaction(sip_ctx, method, transaction_pid)
    after
      500 ->
        Logger.warning(
          module: __MODULE__,
          message:
            "No :onnewdialog received after creating dialog for #{method}; transaction not registered"
        )

        sip_ctx
    end
  end

  # Methods sent as standalone (out-of-dialog) transactions: keep-alive (OPTIONS),
  # registration (REGISTER) and presence (PUBLISH/SUBSCRIBE/MESSAGE). For these it
  # is safe to (re)start a fresh dialog when the previous one has terminated.
  # INVITE call dialogs (whose lifetime ends on BYE) are deliberately excluded:
  # in-dialog requests (BYE, ACK, re-INVITE, …) on a dead call dialog must NOT
  # silently recreate it — they return a clean error instead.
  @standalone_methods [:OPTIONS, :REGISTER, :PUBLISH, :SUBSCRIBE, :MESSAGE, :NOTIFY, :INFO]

  @doc """
  Send an outbound SIP request and create the dialog if needed
  Update the session sip_ctx accordingly
  """
  def send_sip_request(sip_ctx = %SIP.Context{}, req, timeout) when is_atom(req.method) do
    dialog_alive = is_pid(sip_ctx.dialogpid) and Process.alive?(sip_ctx.dialogpid)

    cond do
      dialog_alive ->
        # Send an in dialog request. Guard against the dialog terminating between
        # the liveness check above and the call (returns a clean error, no crash).

        try do
          case SIP.Dialog.new_request(sip_ctx.dialogpid, req) do
            {:ok, transaction_pid} ->
              register_last_transaction(sip_ctx, req.method, transaction_pid)
              |> SIP.Context.set(:lasterr, :ok)

            rez ->
              SIP.Context.set(sip_ctx, :lasterr, rez)
          end
        catch
          :exit, _reason -> SIP.Context.set(sip_ctx, :lasterr, :dialogterminated)
        end

      is_nil(sip_ctx.dialogpid) or req.method in @standalone_methods ->
        # No dialog yet (first request, e.g. the initial INVITE), or a standalone
        # method whose previous dialog has terminated (e.g. OPTIONS keep-alive):
        # start a fresh dialog / transaction.
        case SIP.Dialog.start_dialog(req, timeout, :outbound, sip_ctx.debug) do
          {:ok, dialog_pid, _dialog_id} ->
            # Dialog created: store its pid, clear the last error, then capture the
            # initial UAC transaction so the app can later ACK / CANCEL it (same
            # contract as the in-dialog branch above).
            SIP.Context.set(sip_ctx, :dialogpid, dialog_pid)
            |> SIP.Context.set(:lasterr, :ok)
            |> register_initial_transaction(req.method)

          {:error, err} ->
            SIP.Context.set(sip_ctx, :lasterr, err)
        end

      true ->
        # The dialog (e.g. an INVITE call dialog ended by BYE) has terminated and
        # this is an in-dialog request: do not implicitly recreate it.
        Logger.warning(
          module: __MODULE__,
          message:
            "Dialog #{inspect(sip_ctx.dialogpid)} terminated; dropping in-dialog #{req.method} request"
        )

        SIP.Context.set(sip_ctx, :lasterr, {:error, :dialogterminated})
    end
  end

  @doc """
  Dispatch a SIP reply to the per-method handler, based on the method carried in
  the response CSeq (`[seqno, method]`). INVITE, OPTIONS and REGISTER are routed
  to their respective handlers; replies to any other method are ignored and the
  context is returned unchanged. Backing function of the `process_sip_reply/2`
  macro.
  """
  @spec dispatch_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def dispatch_reply(sip_ctx = %SIP.Context{}, resp, transaction_id) when is_map(resp) do
    case resp.cseq do
      [_seqno, :INVITE] ->
        SIP.Session.CallUAC.process_invite_reply(sip_ctx, resp, transaction_id)

      [_seqno, :OPTIONS] ->
        SIP.Session.RegisterUAC.process_options_reply(sip_ctx, resp, transaction_id)

      [_seqno, :REGISTER] ->
        SIP.Session.RegisterUAC.process_register_reply(sip_ctx, resp, transaction_id)

      _ ->
        sip_ctx
    end
  end

  defmodule ConfigRegistry do
    defstruct callprocessing: nil,
              mainapppid: nil,
              registration: nil,
              presence: nil

    use Agent

    def start() do
      case Agent.start(fn -> %ConfigRegistry{} end, name: __MODULE__) do
        {:ok, pid} -> {:ok, pid}
        # Registry already running (e.g. started by a previous test module): reuse it
        {:error, {:already_started, pid}} -> {:ok, pid}
        err -> err
      end
    end

    @spec set_call_processing_module(module()) :: :ok
    @doc """
    Specify which call processing module will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_call_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{reg | callprocessing: module}
      end)
    end

    @spec set_registration_processing_module(module()) :: :ok
    @doc """
    Specify which registration processing will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_registration_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{reg | registration: module}
      end)
    end

    defp internal_dispatch(proc_atom, fun_atom, args, errormsg)
         when is_atom(fun_atom) and is_list(args) do
      # Get the module that is configured to process the request
      call_mod = Agent.get(__MODULE__, fn reg -> Map.get(reg, proc_atom) end)

      if call_mod == nil do
        # If no module is found, reject the request
        Logger.error("No processing module configured for #{proc_atom}.")
        {:reject, 500, errormsg}
      else
        # If a module is configured, call the callback in this module
        Logger.debug("Dispatched #{proc_atom} to  #{inspect(call_mod)}.#{fun_atom}().")
        apply(call_mod, fun_atom, args)
      end
    end

    @doc """
     Call this to dispatch the on_new_end callback of the call processing
    module
    """
    # Dispatch an initial inbound request to its processing module. The dialog
    # layer always provides the transaction pid that created the dialog; it is
    # forwarded to the registration callback (on_new_registration/3) but ignored
    # for INVITE (on_new_call/2 keeps its arity).
    def dispatch(dialog_id, req, _transaction_id) when is_map(req) and req.method == :INVITE do
      internal_dispatch(
        :callprocessing,
        :on_new_call,
        [dialog_id, req],
        "No call server defined"
      )
    end

    def dispatch(dialog_id, req, transaction_id) when is_map(req) and req.method == :REGISTER do
      internal_dispatch(
        :registration,
        :on_new_registration,
        [dialog_id, req, transaction_id],
        "No registration server defined"
      )
    end

    def dispatch(:on_call_end, dialog_id, app_id) when is_pid(app_id) do
      internal_dispatch(
        :callprocessing,
        :on_call_end,
        [dialog_id, app_id],
        "No call server defined"
      )
    end

    def dispatch(:on_registration_expired, dialog_id, app_pid) when is_pid(app_pid) do
      internal_dispatch(
        :registration,
        :on_registration_expired,
        [dialog_id, app_pid],
        "No registration server defined"
      )
    end
  end

  defmodule Media do
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
    @spec get_sdp_offer(%SIP.Context{}, atom()) :: {%SIP.Context{}, binary()}
    def get_sdp_offer(sip_ctx = %SIP.Context{}, webrtc_support) when is_atom(webrtc_support) do
      if not is_pid(sip_ctx.mediaserverpid) do
        raise "No media server connected to the session context"
      end

      {sip_ctx, cnx} =
        case SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) do
          nil ->
            # Create a new peer connection and store it in the session context
            {:ok, cnx} =
              apply(sip_ctx.mediaservermodule, :create_peer_connection, [
                sip_ctx.mediaserverpid,
                self(),
                [webrtc_support: webrtc_support]
              ])

            {SIP.Context.appdata_set(sip_ctx, :mediapeerconnectionid, cnx), cnx}

          cnx ->
            # Reuse the existing peer connection
            {sip_ctx, cnx}
        end

      {:ok, offer} = apply(sip_ctx.mediaservermodule, :get_local_offer, [cnx])
      {sip_ctx, offer}
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

  defmodule Common do
    require SIP.Dialog

    @doc "CANCEL an existing outbound request"
    def cancel(sip_ctx = %SIP.Context{}, transaction_id) when is_pid(transaction_id) do
      rc = SIP.Dialog.cancel(sip_ctx.dialogpid, transaction_id)
      SIP.Context.set(sip_ctx, :lasterr, rc)
    end

    defmacro send_CANCEL(transaction_id) do
      quote do
        SIP.Scenario.Monitor.note_command(:sip, "send_CANCEL")
        var!(sip_ctx) = SIP.Session.Common.cancel(var!(sip_ctx), unquote(transaction_id))
      end
    end
  end
end
