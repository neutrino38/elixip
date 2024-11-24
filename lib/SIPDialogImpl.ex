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
    app: nil, # PID of the application
    state: :inital,
    debuglog: true, # If we should output debug logs for this dialog
    expirationtimer: nil,
    cseq: 1,
    cseqin: 1,
    fromtag: nil,
    callid: nil,
    totag: nil
  ]


  defp on_new_transaction(state, _req, transact_id) do
    if Enum.count(state.transactions) < 4 do
      { :ok, Map.put(state, :transactions, List.insert_at(state.transactions, -1, transact_id)) }
    else
      Logger.error("Too many transactions open for this dialog #{inspect(self())}")
      SIP.Transac.reply(transact_id, 503, "Service Denied", nil, state.totag)
      { :toomanytransactions, state }
    end
  end


  defp allows(:REGISTER) do
    [ :REGISTER ]
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

  defp set_fromtag(req, fromtag ) when is_req(req) do
    Map.put(req, :from, SIP.Uri.set_uri_param(req.from, "tag", fromtag))
  end

  defp set_totag(req, totag ) when is_req(req) do
    Map.put(req, :to, SIP.Uri.set_uri_param(req.to, "tag", totag))
  end

  # Apply fromtag, totag, callid and CSeq
  # Todo : fix route, request URI ...
  defp fix_outbound_request(state, req) when is_req(req) do
    newreq = Map.put(req, :cseq, [ state.cseq, req.method ])
             |> Map.put( :callid, state.callid )
             |> set_fromtag(state.fromtag)
             |> set_totag(state.totag)

    # Increment cseq for outbound and store modified request
    msg =  if state.msg == nil, do: newreq, else: state.msg
    newstate = %SIP.DialogImpl{ state | cseq: state.cseq + 1, msg: msg }
    { newstate, newreq }
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
        { :stop, { code, reason }}
    end
  end

  # Dialog started by an outbound request
  def init({ req, :outbound, pid, timeout, debug, dialog_id }) when is_req(req) do
    { fromtag, callid, totag } = dialog_id
    # Generate totag if needed
    totag = if is_nil(totag), do: generate_from_or_to_tag(), else: totag

    state = %SIP.DialogImpl{ msg: req, direction: :outbound, app: pid, expirationtimer: timeout, debuglog: debug,
    transactions: [], fromtag: fromtag, callid: callid, totag: totag,
    allows: allows(req.method) }

    { state, req } = fix_outbound_request(state, req)
    try do
      #In case of an outbound dialog, start a, UAC transaction
      case SIP.Transac.start_uac_transaction( req, timeout ) do
        { :ok, transaction_pid } -> { :ok, %SIP.DialogImpl{ state | transactions: [ transaction_pid ] } }
        { code, _extra } ->
          Logger.error([ module: __MODULE__, dialogpid: self(),
                      message: "Failed to create client transaction."])
          { :stop, code }
      end
    rescue
      err ->
        Logger.error([ module: __MODULE__, dialogpid: self(),
                      message: "Failed to create client transaction. Exception occurred."])
        reraise err, __STACKTRACE__
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
    state = close_transaction(state, uas_t)
    { :reply, ret, state }
  end

  def handle_call({:replyreq, req, resp_code, reason, upd_field}, _from, state) do
    { ret, uas_t } = SIP.Transac.reply_req(req, resp_code, reason, upd_field, state.totag, state.transactions)
    state = if resp_code in [200..699], do: close_transaction(state, uas_t), else: state
    { :reply, ret, state }
  end

  @doc "Handle call to send out a new in-dialog request"
  def handle_call({ :newreq, req}, _from, state ) when is_req(req) do
    if req.method in state.allows do
      if Enum.count(state.transactions) < 4 do
        { state, req } = fix_outbound_request(state, req)

        # Create an UAC transaction to send the request out
        case SIP.Transac.start_uac_transaction( req, 15 ) do
          { :ok, transaction_pid } ->
            # Add the transaction in the transaction list
            { :reply, :ok, %SIP.DialogImpl{ state |
                               transactions: List.insert_at(state.transactions, -1, transaction_pid) }}

          # Failed to send the message or create the transaction
          { code, _extra } ->
            { :reply, code, state }
        end

      else
        # Cannot open too many transaction for dialog
        { :reply, :toomanytransactons, state}
      end
    else
      # Not allowed
      { :reply, :methodnotallowed, state}
    end
  end
  # Invoked when dialog process receives sip request
  # sent by calling process_incoming_request(). Typically
  # from NIST or IST transaction processes. Also get
  #
  @impl true
  def handle_cast({:sipmsg, msg, transact_pid}, state ) when is_req(msg) do
    state = case on_new_transaction(state, msg, transact_pid) do
      { :ok, state } ->
        if msg.method in state.allows do
          [ seqno, _cmethod ] = msg.cseq
          if seqno > state.cseqin do
            # Forward request to app layer
            send(state.app, { msg.method, msg, transact_pid, self() })
            %SIP.DialogImpl{ state | cseqin: seqno }
          else
            SIP.Transac.reply(transact_pid, 500, "Out of order", nil, state.totag)
            state
          end
        else
          SIP.Transac.reply(transact_pid, 405, "Method not allowed", nil, state.totag)
          state
        end


      _ -> state
    end

    { :noreply, state }
  end

  # For SIP response
  def handle_cast({:sipmsg, msg, transact_pid}, state ) when is_resp(msg) do
    if transact_pid in state.transactions do
      send(state.app, { msg.resp_code, msg, transact_pid, self() })
    else
      Logger.warning([
        dialogpid: "#{inspect(self())}",  module: __MODULE__,
        message: "SIP response #{msg.resp_code} from a transaction #{inspect(transact_pid)} " <>
                 "that is not attached to the dialog." ])
    end
    { :noreply, state }
  end

end
