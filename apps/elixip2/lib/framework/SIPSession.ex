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
  Reply to an inbound request on `dialog_pid`, recording the command for the
  scenario monitor.

  What a UAS scenario should call instead of `SIP.Dialog.reply/5`, so its response
  shows up in the `--monitor` view / `kelictl monitor`. `label` names the recorded
  command; it defaults to `"reply_<code>"`.
  """
  @spec reply(pid, map, integer, String.t() | nil, keyword | String.t(), String.t() | nil) :: any
  def reply(dialog_pid, req, code, reason, upd_fields \\ [], label \\ nil) do
    SIP.Scenario.Monitor.note_command(:sip, label || "reply_#{code}")
    SIP.Dialog.reply(dialog_pid, req, code, reason, upd_fields)
  end

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
              unsent_request(sip_ctx, req, rez)
          end
        catch
          :exit, _reason -> unsent_request(sip_ctx, req, :dialogterminated)
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

          # `{:error, reason}` for a dialog that refused to start, and the bare
          # `:error` start_dialog/5 answers when its own creation raised.
          {:error, err} ->
            unsent_request(sip_ctx, req, err)

          err ->
            unsent_request(sip_ctx, req, err)
        end

      true ->
        # The dialog (e.g. an INVITE call dialog ended by BYE) has terminated and
        # this is an in-dialog request: do not implicitly recreate it.
        unsent_request(sip_ctx, req, {:error, :dialogterminated})
    end
  end

  # A request that never left, whatever stopped it: no transport toward the
  # destination, a destination that does not resolve, a dialog that died under
  # us, a transaction that could not be created.
  #
  # RFC 3261 §8.1.3.1 says what the application is owed — a fatal transport error
  # is reported to the TU as a **503**, exactly as a transaction timeout is
  # reported as a 408 (the dialog layer does that half, `timeout_response/1`). It
  # used to be owed nothing at all: `lasterr` was set and nobody reads it, so the
  # scenario went on to its `on_events` and waited for a response that could not
  # come. An unreachable proxy then read as "the callee did not answer after 30
  # s", thirty seconds later, with a stack trace in the log as the only clue.
  #
  # Delivered as the response event the scenario already knows how to read, so
  # its `code in 400..699` clause ends the run — nothing new to write in a
  # scenario, and a retry-on-503 policy applies to it unchanged. There is no
  # transaction to name, and the dialog pid is whatever we had (nil for an
  # initial request).
  #
  # The reason phrase names what stopped the request, which is the one thing a
  # 503 the far end sent could not tell apart from this one. It never goes on
  # the wire, so it is free to say more than the §21.5.4 text; `lasterr` keeps
  # the same cause as an atom, for a scenario deciding on it.
  defp unsent_request(sip_ctx = %SIP.Context{}, req, reason) do
    cause = "#{inspect(reason)} sending #{req.method} to #{SIP.Uri.ruri_string(req.ruri)}"

    Logger.error(
      module: __MODULE__,
      message: "Request not sent: #{cause}. Reporting it to the scenario as a 503."
    )

    rsp = SIP.Msg.Ops.local_response(req, 503, "Service Unavailable (#{cause})")
    send(self(), {503, rsp, nil, sip_ctx.dialogpid})

    SIP.Context.set(sip_ctx, :lasterr, reason)
  end

  @doc """
  Dispatch a SIP reply to the per-method handler, based on the method carried in
  the response CSeq (`[seqno, method]`). INVITE, OPTIONS, REGISTER and SUBSCRIBE
  are routed to their respective handlers; replies to any other method are ignored
  and the context is returned unchanged. Backing function of the
  `process_sip_reply/2` macro.
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

      [_seqno, :SUBSCRIBE] ->
        SIP.Session.SubscribeUAC.process_subscribe_reply(sip_ctx, resp, transaction_id)

      _ ->
        sip_ctx
    end
  end

  @doc """
  Extract the SDP body from a SIP message, whether it is a bare binary body, a
  single-part `[%{data: ...}]` body, or a multipart list (picks the part whose
  Content-Type contains "sdp", falling back to the first part). Returns the SDP
  binary, or `nil` when the message carries no usable SDP.

  Shared by the UAC answer path (`CallUAC.process_sdp_resp/2`) and the UAS offer
  path (`CallUAS.do_reply_invite_with_sdp/3`).

  The reading itself lives in the message layer (`SIP.Msg.Ops.sdp_body/1`), where
  the B2BUA's re-offer classifier needs the same one; this name stays because
  half the stack calls it.
  """
  @spec extract_sdp(map()) :: binary() | nil
  defdelegate extract_sdp(msg), to: SIP.Msg.Ops, as: :sdp_body

  defmodule Options do
    @moduledoc """
    Behaviour for the module answering **out-of-dialog** OPTIONS (RFC 3261 §11.2:
    a capability query, and in practice the liveness ping a proxy or load balancer
    sends to decide whether this node still takes traffic).

    In-dialog OPTIONS are not concerned: the dialog answers those itself (keepalive).

    The callback runs **inside the server transaction process**, so it must neither
    reply itself (a `GenServer.call` on the transaction would be a call to self —
    the same trap the 481 path documents) nor block. It decides, and returns what to
    answer:

      * `{:reply, code, reason, fields}` — `fields` is a list of `{header, value}`
        pairs, e.g. `[{"Allow", "OPTIONS, REGISTER"}]`;
      * `:default` — answer 200 with no capability header.

    There is deliberately no framework-wide default answer: what a node supports
    depends on the application running on it, so an application that wants to be
    pingable registers a module (`ConfigRegistry.set_options_processing_module/1`).
    With no module registered, an out-of-dialog OPTIONS is answered 500 — no dialog
    is created for it either way.
    """
    @callback on_options(req :: map(), transaction_id :: pid()) ::
                {:reply, 100..699, binary(), list()} | :default
  end

  defmodule ConfigRegistry do
    defstruct callprocessing: nil,
              mainapppid: nil,
              registration: nil,
              presence: nil,
              chat: nil,
              options: nil

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

    @spec get_call_processing_module() :: module() | nil
    @doc """
    Return the currently configured call processing module (nil when none).
    """
    def get_call_processing_module() do
      Agent.get(__MODULE__, fn reg -> reg.callprocessing end)
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

    @spec set_presence_processing_module(module()) :: :ok
    @doc """
    Specify which module serves inbound SUBSCRIBE / PUBLISH (see
    `SIP.Session.Presence`). With none registered, such a request is answered 500
    — until now it fell through to the catch-all and was answered **501**, which
    told a watcher the stack did not implement SUBSCRIBE when in fact no
    application had claimed it.
    """
    def set_presence_processing_module(module) do
      Agent.update(__MODULE__, fn reg -> %ConfigRegistry{reg | presence: module} end)
    end

    @spec get_presence_processing_module() :: module() | nil
    @doc "Return the configured presence processing module (nil when none)."
    def get_presence_processing_module() do
      Agent.get(__MODULE__, fn reg -> reg.presence end)
    end

    @spec set_chat_processing_module(module()) :: :ok
    @doc """
    Specify which module serves inbound out-of-dialog MESSAGE (see
    `SIP.Session.Chat`). With none registered, such a request is answered 500.
    """
    def set_chat_processing_module(module) do
      Agent.update(__MODULE__, fn reg -> %ConfigRegistry{reg | chat: module} end)
    end

    @spec get_chat_processing_module() :: module() | nil
    @doc "Return the configured chat processing module (nil when none)."
    def get_chat_processing_module() do
      Agent.get(__MODULE__, fn reg -> reg.chat end)
    end

    @spec set_options_processing_module(module()) :: :ok
    @doc """
    Specify which module answers out-of-dialog OPTIONS (see `SIP.Session.Options`).
    An application that wants to be pingable registers one at start-up; with none,
    such an OPTIONS is answered 500.
    """
    def set_options_processing_module(module) do
      Agent.update(__MODULE__, fn reg -> %ConfigRegistry{reg | options: module} end)
    end

    @spec get_options_processing_module() :: module() | nil
    @doc "Return the configured OPTIONS processing module (nil when none)."
    def get_options_processing_module() do
      Agent.get(__MODULE__, fn reg -> reg.options end)
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
        call_callback(call_mod, fun_atom, args)
      end
    end

    # Half of the presence behaviour is `@optional_callbacks`, so a host that
    # implements none of it is a legal host — and calling one of them anyway is an
    # `:undef` raised inside `SIP.DialogImpl.init/1`, which kills the dialog before
    # the request is answered at all. The peer then retries, and the only trace is a
    # stack trace in the journal.
    #
    # Found on 2026-09-22 with a Linphone typing indicator: an out-of-dialog MESSAGE
    # reached `Kelix.Router.on_message/3`, which does not exist. 501 is what the
    # catch-all clause below already answers for a method no module handles, and it
    # is the same answer here: the host is not equipped for this request.
    defp call_callback(module, fun, args) do
      if Code.ensure_loaded?(module) and function_exported?(module, fun, length(args)) do
        apply(module, fun, args)
      else
        Logger.warning(
          "#{inspect(module)} does not implement the optional callback " <>
            "#{fun}/#{length(args)}: answering 501 Not Implemented."
        )

        {:reject, 501, "Not Implemented"}
      end
    end

    @doc """
     Call this to dispatch the on_new_end callback of the call processing
    module
    """
    # Dispatch an initial inbound request to its processing module. The dialog
    # layer always provides the transaction pid that created the dialog; it is
    # forwarded to both the registration callback (on_new_registration/3) and
    # the call callback (on_new_call/3).
    def dispatch(dialog_id, req, transaction_id) when is_map(req) and req.method == :INVITE do
      internal_dispatch(
        :callprocessing,
        :on_new_call,
        [dialog_id, req, transaction_id],
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

    # Event notification (RFC 6665) and publication (RFC 3903). Until P3 these
    # landed on the catch-all below and were answered 501 Not Implemented, whatever
    # application was running: `presence:` was a struct field with no setter and no
    # clause here.
    def dispatch(dialog_id, req, transaction_id) when is_map(req) and req.method == :SUBSCRIBE do
      internal_dispatch(
        :presence,
        :on_new_subscribe,
        [dialog_id, req, transaction_id],
        "No presence server defined"
      )
    end

    def dispatch(dialog_id, req, transaction_id) when is_map(req) and req.method == :PUBLISH do
      internal_dispatch(
        :presence,
        :on_new_publish,
        [dialog_id, req, transaction_id],
        "No presence server defined"
      )
    end

    # Page-mode messaging (RFC 3428) has a slot of its own: it used to share the
    # presence host's, so a MESSAGE landed on whatever served SUBSCRIBE.
    def dispatch(dialog_id, req, transaction_id) when is_map(req) and req.method == :MESSAGE do
      internal_dispatch(
        :chat,
        :on_message,
        [dialog_id, req, transaction_id],
        "No chat server defined"
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

    def dispatch(:on_subscription_expired, dialog_id, app_pid) when is_pid(app_pid) do
      internal_dispatch(
        :presence,
        :on_subscription_expired,
        [dialog_id, app_pid],
        "No presence server defined"
      )
    end

    # Any other initial request. There is no processing module for it, so say so
    # with a SIP code instead of raising: a function_clause here dies inside
    # SIP.DialogImpl.init/1, and the transaction layer turns any unrecognised
    # dialog-layer failure into "403 Denied" — which is what an out-of-dialog
    # OPTIONS used to get, telling the peer it was forbidden rather than
    # unimplemented. Reaching this clause is a gap in the stack, hence the log.
    def dispatch(dialog_id, req, _transaction_id) when is_map(req) do
      Logger.warning(
        "No processing module handles an initial #{req.method} " <>
          "(dialog #{inspect(dialog_id)}): answering 501 Not Implemented."
      )

      {:reject, 501, "Not Implemented"}
    end

    @doc """
    Ask the configured module what to answer to an out-of-dialog OPTIONS. Returns
    `{:reply, code, reason, fields}`; no module configured (or a module answering
    `:default`) yields a bare answer with no capability header.

    Called from the dialog layer *before* any dialog is created — an OPTIONS is not
    dialog-forming (RFC 3261 §12.1), and creating one per liveness ping left a
    60-second process behind for every ping a monitoring proxy sent.
    """
    @spec dispatch_options(map(), pid()) :: {:reply, 100..699, binary(), list()}
    def dispatch_options(req, transaction_id) when is_map(req) do
      case internal_dispatch(
             :options,
             :on_options,
             [req, transaction_id],
             "No OPTIONS handler defined"
           ) do
        {:reply, code, reason, fields} when is_integer(code) and is_list(fields) ->
          {:reply, code, reason, fields}

        :default ->
          {:reply, 200, "OK", []}

        # internal_dispatch's answer when the slot is empty.
        {:reject, code, reason} ->
          {:reply, code, reason, []}

        other ->
          Logger.error(
            "OPTIONS handler returned #{inspect(other)}; expected {:reply, code, reason, fields}."
          )

          {:reply, 500, "Internal Server Error", []}
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
