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
