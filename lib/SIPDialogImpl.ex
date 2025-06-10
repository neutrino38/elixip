defmodule SIP.DialogImpl do
@moduledoc """
SIP module layer implementation. Do not use directy.
Use the API provided by SIP.Dialog module
"""
  use GenServer
  require Logger
  require SIP.Uri
  import SIP.Msg.Ops

  defstruct [
    msg: nil, # SIP message that created this dialog
    allows: [],
    routeset: [],
    direction: :outbound, # outbound means that dialog was created by an outbound request.
    curtrans: nil,  # Current transaction
    transactions: [],
    closing_transaction: nil, # PID of the transaction that should terminate the dialog
    app: nil, # PID of the application
    state: :inital,
    debuglog: true, # If we should output debug logs for this dialog
    expirationtimer: nil,
    keepalivetimer: nil,
    missedkeepalive: 0,
    cseq: 1,
    cseqin: 1,
    fromtag: nil,
    callid: nil,
    totag: nil,
    destip: nil,
    destport: 0
  ]

  defp on_new_transaction(state, req, _transact_id) when is_map(req) and req.method in [ :ACK, :CANCEL ] do
    # Specific case for ACK. Do not create a new transaction for these request
    { :nonewtrans, state }
  end

  defp on_new_transaction(state, _req, transact_id) do
    if Enum.count(state.transactions) < 4 do
      { :ok, Map.put(state, :transactions, List.insert_at(state.transactions, -1, transact_id)) }
    else
      { :toomanytransactions, state }
    end
  end


  defp allows(:REGISTER) do
    [ :REGISTER, :OPTIONS ]
  end

  defp allows(:INVITE) do
    [ :BYE, :UPDATE, :ACK, :MESSAGE, :INFO, :INVITE, :REFER ]
  end

  defp allows(:OPTIONS) do
    [ :OPTIONS ]
  end

  defp allows(prezreq) when prezreq in [ :PUBLISH, :SUBSCRIBE, :NOTIFY, :MESSAGE ] do
    [ :PUBLISH, :SUBSCRIBE, :NOTIFY, :MESSAGE ]
  end

  defp set_tag(req, h, tag ) when is_req(req) and h in [ :from, :to] do
    uri = Map.get(req, h)
    uri = if is_binary(uri) do
      { :ok, puri } = SIP.Uri.parse(uri)
      puri
    else
      uri
    end
    Map.put(req, h, SIP.Uri.set_uri_param(uri, "tag", tag))
  end

  # Apply fromtag, totag, callid and CSeq
  # Todo : fix route, request URI ...
  defp fix_outbound_request(state, req, is_initial \\ false) when is_req(req) do
    newreq = Map.put(req, :cseq, [ state.cseq, req.method ])
             |> Map.put( :callid, state.callid )
             |> set_tag(:from, state.fromtag)

    newreq = if not is_initial and not (req.method in [ :OPTIONS ]) do
      set_tag(newreq, :to, state.totag)
    else
      newreq
    end

    # Increment cseq for outbound and store modified request
    msg =  if state.msg == nil, do: newreq, else: state.msg
    newstate = %SIP.DialogImpl{ state | cseq: state.cseq + 1, msg: msg }
    { newstate, newreq }
  end

  def send_in_dialog_request(state = %SIP.DialogImpl{}, req) do
    if req.method in state.allows do
      if Enum.count(state.transactions) < 4 do
        { state, req } = fix_outbound_request(state, req)

        # Copy transport parameters from the request that opened the dialog into the RURI to reuse them
        o_ruri = state.msg.ruri
        ruri = %SIP.Uri{ req.ruri | destip: o_ruri.destip, destport: o_ruri.destport,
                         tp_module: o_ruri.tp_module, tp_pid: o_ruri.tp_pid }
        req = %{ req | ruri: ruri }
        # Create an UAC transaction to send the request out
        case SIP.Transac.start_uac_transaction( req, 15 ) do
          # Failed to send the message or create the transaction
          { code, nil } ->
            { code, state }

          { :ok, transaction_pid, _modmsg } ->
            # Add the transaction in the transaction list
            newstate = %SIP.DialogImpl{ state | transactions: List.insert_at(state.transactions, -1, transaction_pid) }

            # Handle expiration timer and closing transaction
            newstate = arm_expiration_timer(newstate, req) |> check_closing_transaction(req, transaction_pid)
            { :ok, newstate}

        end

      else
        # Cannot open too many transaction for dialog
        Logger.warning([ dialogpid: self(), module: __MODULE__,
                       message: "Too many open transaction for this dialog. Dropping request #{req.method}"])
        { :toomanytransactons, state}
      end
    else
      # Not allowed
      Logger.debug([ dialogpid: self(), module: __MODULE__,
                     message: "Method #{req.method} not allowed in this dialog"])
      { :methodnotallowed, state}
    end
  end

  # --------------------------- OPTIONS keepalive -------------------------
  @doc "arm the registration keepalive timer"
  def arm_options_keepalive_timer(state =%SIP.DialogImpl{}) do
    if state.keepalivetimer == nil and state.direction == :outbound do
      %SIP.DialogImpl{ state | keepalivetimer: :erlang.start_timer(15000, :optionskeepalive, self()) }
    else
      state
    end
  end

  def cancel_options_keepalive_timer(state =%SIP.DialogImpl{}) do
    if state.keepalivetimer != nil do
      :erlang.cancel_timer(state.keepalivetimer)
      %SIP.DialogImpl{ state | keepalivetimer: nil }
    end
  end

  def send_options_keepalive(state) do
    msg = %{
        "Accept" => "*/*",
        "Accept-Encoding" => "UTF-8",
        "Accept-Language" => "en",
        "Supported" => "OPTIONS, REGISTER",
        "Max-Forwards" => "70",
        method: :OPTIONS,
        ruri: state.msg.ruri,
        from: state.msg.from,
        to: state.msg.to,
        contact: state.msg.contact,
        useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
        callid: nil,
        contentlength: 0
      }

    case state.state do
      :confirmed ->
        # Send OPTIONS message
        { _rc, state } = send_in_dialog_request(state, msg)

        # Refresh timer
        arm_options_keepalive_timer(state)

      :terminated ->
        # Dialog is dead. Kill timer
        cancel_options_keepalive_timer(state)

      _ -> state
    end
  end

  # --------------------------- General expiration timer -------------------------
  def arm_expiration_timer(state =%SIP.DialogImpl{}, req) when req.method == :INVITE do
    expire = case Map.get(req, "Session-Expire", 1800) do
      1800 -> 1800
      exp -> String.to_integer(exp)
    end

    state = cancel_expiration_timer(state)
    %SIP.DialogImpl{ state | expirationtimer: :erlang.start_timer(expire*1000, :inviterefresh, self()) }
  end

  @doc """
  For dialogs created by REGISTER message, we have two cases: client REGISTER or server REGISTER

  - for client REGISTER, we arm a timer that is equal to half of the expiration time and send a refresh
    register automatically. We also send an OPTIONS message every 15 seconds to keep the NAT or the
    connectionfull co
  """
  def arm_expiration_timer(state =%SIP.DialogImpl{}, req) when req.method == :REGISTER do
    { expire, timeratom} = case SIP.Uri.get_uri_param(req.contact, "expires") do
      { :no_such_param, nil } -> { 1, :unregister }
      { :no_such_param, "0" } -> { 1, :unregister }
      { :ok, value } ->
        exp = String.to_integer(value)
        if state.direction == :inbound do
          { :registerexpire, exp }
        else
          { :registerrefresh, exp/2 }
        end
    end

    state = cancel_expiration_timer(state)

    %SIP.DialogImpl{ state | expirationtimer: :erlang.start_timer(expire*1000, timeratom, self()) }
  end

  # Default, do nothing
  def arm_expiration_timer(state =%SIP.DialogImpl{}, _req) do
    state
  end

  @doc "Cancels the dialog expiration timer"
  def cancel_expiration_timer(state =%SIP.DialogImpl{}) do
    if state.expirationtimer != nil do
      :erlang.cancel_timer(state.expirationtimer)
      %SIP.DialogImpl{ state | expirationtimer: nil }
    else
      state
    end
  end

  # -------- GenServer callbacks --------------------

  @impl true
  @spec init(
         { map(), :inbound | :outbound, pid(), integer(), boolean(), {any(), any(), any()}}
      ) ::

      { :ok, map() } | {:stop, atom() | {any(), any()}}

  def init({ req, :inbound, pid, timeout, debug, dialog_id }) when is_req(req) do
    { fromtag, callid, totag } = dialog_id
    # Generate totag if needed
    totag = if is_nil(totag), do: generate_from_or_to_tag(), else: totag

    state = %SIP.DialogImpl{ msg: req, direction: :inbound, app: nil, expirationtimer: timeout, debuglog: debug,
                  transactions: [ pid ], fromtag: fromtag, callid: callid, totag: totag,
                  allows: allows(req.method) }

    # Dispatch the initial request to the upper layer
    case SIP.Session.ConfigRegistry.dispatch(self(), req ) do
      { :accept, app_id } ->
        Logger.debug([
          dialogpid: "#{inspect(self())}", module: __MODULE__,
          message: "Bound dialog to app process #{inspect(app_id)}" ])

        # Send the message to the newly created app layer
        send( app_id, { req.method, req, pid, self() })
        { :ok, Map.put(state, :app, app_id ) }

      # Session has not been created. Abort dialog
      { :reject, code, reason } ->
        Logger.error([
          dialogpid: "#{inspect(self())}", module: __MODULE__,
          message: "Failed to create the app process. Err: #{code}. Aborting dialog creation." ])
        { :stop, :abnormal, reason }
    end
  end

  # Dialog started by an outbound request
  def init({ req, :outbound, pid, timeout, debug, dialog_id }) when is_req(req) do
    { fromtag, callid, _totag } = dialog_id


    state = %SIP.DialogImpl{ msg: req, direction: :outbound, app: pid, expirationtimer: timeout, debuglog: debug,
    transactions: [], fromtag: fromtag, callid: callid, totag: nil,
    allows: allows(req.method) }

    { state, req } = fix_outbound_request(state, req, true)
    try do
      #In case of an outbound dialog, start a, UAC transaction
      case SIP.Transac.start_uac_transaction( req, timeout ) do
        { :ok, transaction_pid, modmsg } ->
          send(state.apppid, { :onnewdialog, :ok, transaction_pid })
          newstate = %SIP.DialogImpl{ state | transactions: [ transaction_pid ], msg: modmsg }
            |> arm_expiration_timer(modmsg)
            |> check_closing_transaction(modmsg, transaction_pid)
          { :ok, newstate }

        { code, _extra } ->
          Logger.error([ module: __MODULE__, dialogpid: self(),
                      message: "Failed to create client transaction, err: #{code}."])
          { :stop, :abnormal, code }

        :no_transport_available ->
          Logger.debug([ module: __MODULE__, dialogpid: self(),
                      message: "Failed to create client transaction because we could not find / start a suitable transport."])
          { :stop, :no_transport_available }

      end
    rescue
      err ->
        Logger.error([ module: __MODULE__, dialogpid: self(),
                      message: "Failed to create client transaction. Exception occurred."])
        Logger.error(Exception.format(:error, err, __STACKTRACE__))
        { :stop, :transactionfailure }
    end
  end

  defp close_transaction(state, uas_t) do
    %SIP.DialogImpl{ state | transactions: List.delete(state.transactions, uas_t)}
  end

  @impl true
  def handle_call({ :setapppid, app_pid }, _from, state) do
    if state.direction == :inbound and state.app == nil do
      { :reply, :ok,  %SIP.DialogImpl{ state | app: app_pid } }
    else
      { :reply, :alreadybound, state }
    end
  end

  # Obtain the call ID of a given dialog
  def handle_call(:getdialogid, _from, state) do
    { :reply, { state.fromtag, state.callid, state.totag }, state }
  end

  # Reply to an in_dialog request
  def handle_call({:replyreq, req, resp_code, reason, realm}, _from, state) when resp_code in [ 401, 407 ] do
    auth = %{ realm: realm, algorithm: "SHA256", authproc: "Digest "}
    { ret, uas_t } = SIP.Transac.reply_req(req, resp_code, reason, auth, state.totag, state.transactions)

    { :reply, ret, add_totag(state, nil) |> close_transaction(uas_t) }
  end

  def handle_call({:replyreq, req, resp_code, reason, upd_field}, _from, state) do
    { ret, uas_t } = SIP.Transac.reply_req(req, resp_code, reason, upd_field, state.totag, state.transactions)
    state = case resp_code do
      100 -> state
      rc when rc in 101..199 -> add_totag(state, nil)
      rc when rc in 200..699 -> add_totag(state, nil) |> close_transaction(uas_t)
      _ -> raise "Unsupported response code #{resp_code}"
    end
    { :reply, ret, state }
  end

  @doc "Handle call to send out a new in-dialog request"
  def handle_call({ :newreq, req}, _from, state ) when is_req(req) do
    { rc, state } = send_in_dialog_request(state, req)
    { :reply, rc, state }
  end

  def handle_call({:cancel, transact_pid}, state ) do
    if transact_pid in state.transactions do
      reply = SIP.Transac.cancel_uac_transaction(transact_pid)
      { :reply, reply, state }
    else
      { :reply, :nosuchtransaction, state }
    end
  end

    def handle_call({:ack, transact_pid}, state ) do
    if transact_pid in state.transactions do
      reply = SIP.Transac.ack_uac_transaction(transact_pid)
      { :reply, reply, state }
    else
      { :reply, :nosuchtransaction, state }
    end
  end

  defp check_closing_transaction(state, msg, transact_pid) when msg.method in [ :BYE ] do
    { :ok, %SIP.DialogImpl{ state | closing_transaction: transact_pid } }
  end

  defp check_closing_transaction(state, _msg, _transact_pid) do
    { :ok, state }
  end

  defp check_allows(state, msg) do
    if msg.method in state.allows do
      { :ok, state }
    else
      { :notallowed, state }
    end
  end

  defp check_seqno(state, msg ) do
    [ seqno, _cmethod ] = msg.cseq
    if seqno > state.cseqin do
      { :ok, %SIP.DialogImpl{ state | cseqin: seqno } }
    else
      { :out_of_order, state }
    end
  end

  defp send_req_to_app(state, msg, transact_pid ) do
      # Forward request to app layer
      send(state.app, { msg.method, msg, transact_pid, self() })
      Logger.debug([ dialogpid: self(), module: __MODULE__,
              message: "Forwarded request to app process #{inspect(state.app)}"])
      { :ok, state }
  end

  # Invoked when dialog process receives sip request
  # sent by calling process_incoming_request(). Typically
  # from NIST or IST transaction processes. Also get

  @impl true
  def handle_cast({:sipmsg, msg, transact_pid}, state ) when is_req(msg) do
    Logger.debug([ dialogpid: self(), module: __MODULE__,
                   message: "Handing in-dialog SIP req #{msg.method}"])

    with  { :ok, state } <- on_new_transaction(state, msg, transact_pid),
      { :ok, state } <- check_allows(state, msg),
      { :ok, state } <- check_seqno(state, msg),
      { :ok, state } <- send_req_to_app(state, msg, transact_pid),
      { :ok, state } <- check_closing_transaction(state, msg, transact_pid) do

      { :noreply, arm_expiration_timer(state, msg) }

    else
      { :notallowed, state } ->
        SIP.Transac.reply(transact_pid, 405, "Method not allowed", [], state.totag)
        { :noreply, state }

      { :out_of_order, state } ->
        SIP.Transac.reply(transact_pid, 500, "Out of order", [], state.totag)
        { :noreply, state }

      { :toomanytransactions, state } ->
        Logger.error([ module: __MODULE__, dialogpid: self(), message: "Too many transactions open."])
        SIP.Transac.reply(transact_pid, 503, "Service Denied", nil, state.totag)
        { :noreply, state }

      { :nonewtrans, state } ->
        # ACK, CANCEL do not create new transactions
        # - rc returned by on_new_transaction
        { :noreply, state }
    end
  end

  defp add_totag(state, totag) do
    if is_nil(state.totag) and not is_nil(totag) do
      totag = if state.direction == :inbound do
        SIP.Msg.Ops.generate_from_or_to_tag()
      else
        if totag == nil, do: raise "Response does not contain totag"
        totag
      end
      # Case when the dialog has been created by an outbound request
      # Get the to tag from the first answer
      Registry.register(Registry.SIPDialog, { state.fromtag, state.callid, totag }, :completedialog)
      %SIP.DialogImpl{ state | totag: totag }
    else
      state
    end
  end

  defp handle_UAS_response(state, rsp, _transact_pid) when state.state == :initial and rsp.response in 200..202 do
    %{state | state: :established }
  end

  defp handle_UAS_response(state, rsp, _transact_pid) when state.state == :initial and rsp.response in 300..399 do
    Logger.debug(dialogpid: "#{inspect(self())}", module: __MODULE__,
                           message: "Redirected to #{rsp.contact}")
    %{state | state: :redirected }
  end

  defp handle_UAS_response(state, rsp, _transact_pid) when state.state == :initial and rsp.response in 400..699 do
    %{state | state: :terminated }
  end

  defp handle_UAS_response(state = %SIP.DialogImpl{}, rsp, transact_pid) when state.state == :established do
    if transact_pid == state.closing_transaction do
      # The closing transaction has been completed. Kill the dialog
      Logger.debug(dialogpid: "#{inspect(self())}", module: __MODULE__,
                   message: "Final dialog transaction completed by final anwswer #{rsp.response}")
      %{state | state: :terminated }
    else
      state
    end
  end

  defp handle_UAS_response(state, _rsp, _transact_pid) do
    state
  end

  @impl true
  @doc "Invoked when a dialog receives a SIP response from an UAC transaction"
  def handle_info({ :response, rsp, transact_pid }, state ) when is_resp(rsp) do
    state = if transact_pid in state.transactions do
      { _rc, totag } = SIP.Uri.get_uri_param(rsp.to, "tag")

      send(state.app, { rsp.response, rsp, transact_pid, self() })
      state = add_totag(state, totag)

      if rsp.response >= 200 do
        handle_UAS_response(state, rsp, transact_pid) |> close_transaction(transact_pid)
      else
        # Provisional responses.
        state
      end
    else
      Logger.warning([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "SIP response #{rsp.response} from a transaction #{inspect(transact_pid)} " <>
                 "that is not attached to the dialog." ])
      state
    end
    if state.state in [:initial, :confirmed, :redirected ] do
      { :noreply, state }
    else
      Logger.info([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "Terminating Dialog" ])
      { :stop, :normal, state }
    end
  end

  # ----------------------- handling expiration timer ------------------------------

  #
  def handle_info({ :timeout, _timerRef, :unregister }, state= %SIP.DialogImpl{}) do
    Logger.info([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "Terminating REGISTER Dialog" ])
    { :stop, :normal, state }
  end

  def handle_info({ :timeout, _timerRef, :registerexpire }, state= %SIP.DialogImpl{}) do
    Logger.info([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "Terminating REGISTER Dialog because no refresh REGISTER recevied" ])
    { :stop, :normal, state }
  end

  def handle_info({ :timeout, _timerRef, :registerrefresh }, state= %SIP.DialogImpl{}) do
    Logger.debug([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "Sending REFRESH register" ])

    # TODO send refresher
    { :noreply, state }
  end

  # ----------------------- transaction timers ------------------------------
  def handle_info({ :transaction_timeout, _timer, transact_pid, req, module }, state= %SIP.DialogImpl{}) when is_pid(transact_pid) do
    # Transaction expired -> remove it
    state = close_transaction(state, transact_pid)
    end_dialog = case req.method do
      :BYE -> module == SIP.ICT # true if this is a client transaction
      :REGISTER ->
        case SIP.Uri.get_uri_param(req.contact, "expires") do
          { :ok, "0" } -> module == SIP.ICT # true if this is a client transaction
          _ -> false
        end

      _ -> false
    end

    if end_dialog do
      { :stop, :normal, :state }
    else
      { :noreply, state }
    end
  end

end
