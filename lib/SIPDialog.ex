defmodule SIP.Dialog do
@moduledoc "SIP module layer"
  require Logger
  require Registry
  require SIP.Uri
  import SIP.Msg.Ops
  use GenServer


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

  @spec start() :: :error | :ok
  @doc "Start the dialog layer"
  def start() do
    #Create the registry
    case Registry.start_link(keys: :unique, name: Registry.SIPDialog) do
      { :ok, pid } ->
        Logger.info("SIP dialog layer started with PID #{inspect(pid)}")
        :ok

      { code, _pid } ->
        Logger.error ("SIP dialog layer failed to start with error #{code}")
        code
    end
  end

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
    newstate = %SIP.Dialog{ state | cseq: state.cseq + 1, msg: msg }
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

    state = %SIP.Dialog{ msg: req, direction: :inbound, app: nil, expirationtimer: timeout, debuglog: debug,
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

    state = %SIP.Dialog{ msg: req, direction: :outbound, app: pid, expirationtimer: timeout, debuglog: debug,
    transactions: [], fromtag: fromtag, callid: callid, totag: totag,
    allows: allows(req.method) }

    { state, req } = fix_outbound_request(state, req)

    #In case of an outbound dialog, start a, UAC transaction
    case SIP.Transac.start_uac_transaction( req, timeout ) do
      { :ok, transaction_pid } -> { :ok, %SIP.Dialog{ state | transactions: [ transaction_pid ] } }
      { code, _extra } -> { :stop, code }
    end
  end

  defp close_transaction(state, uas_t) do
    %SIP.Dialog{ state | transactions: List.delete(state.transactions, uas_t)}
  end

  @impl true
  def handle_call({ :setapppid, app_pid }, _from, state) do
    if state.direction == :inbound and state.app == nil do
      { :reply, :ok,  %SIP.Dialog{ state | app: app_pid } }
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
            { :reply, :ok, %SIP.Dialog{ state |
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
            %SIP.Dialog{ state | cseqin: seqno }
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

  # -- send a new request out --
  # ---------------------- API ----------------------
  # Obtain the triplet that uniquely identify a dialog
  defp get_dialog_id(req) do
    { _code, fromtag } = SIP.Uri.get_uri_param(req.from, "tag")
    { _code, totag } = SIP.Uri.get_uri_param(req.to, "tag")
    { fromtag, req.callid, totag }
  end

  defp get_or_create_dialog_id( req ) do
    get_or_create_dialog_id( req, get_dialog_id(req) )
  end

  # Create call ID and add it to the request
  @spec get_or_create_dialog_id( map(), { binary(), nil, binary() } ) :: tuple()
  defp get_or_create_dialog_id( req, { fromtag, nil, totag }) do
    callid = generate_from_or_to_tag()
    req = Map.put(req, :callid, callid)
    get_or_create_dialog_id( req, { fromtag, callid, totag } )
  end

  # Create from TAG and add it the from URI
  defp get_or_create_dialog_id( req, { nil, callid , totag }) do
    fromtag = generate_from_or_to_tag()
    req = Map.put(req, :from, SIP.Uri.set_uri_param(req.from, "tag", fromtag))
    get_or_create_dialog_id( req, { fromtag, callid, totag } )
  end

  # At least from tag and callid are present, return them and end the recursion
  @spec get_or_create_dialog_id( map(), { binary(), binary(), binary() } ) :: tuple()
  defp get_or_create_dialog_id( req, { fromtag, callid , totag } )  when is_binary(fromtag) and is_binary(callid) do
    {req, { fromtag, callid , totag } }
  end

  def dlgid2string({ ftag, cid, nil}) do
    ftag <> "-" <> cid
  end

  def dlgid2string({ ftag, cid, totag}) do
    ftag <> "-" <> cid <> "-" <> totag
  end

  @doc "Start a dialog"
  @spec start_dialog(map(), integer(), :inbound | :outbound, boolean() ) :: {:error, any()} | {:ok, pid(), tuple() }
  def start_dialog(req, timeout, direction, debug) when is_integer(timeout) and is_atom(req.method) do

    # Obtain or create the dialog id { fromtag, callid, totag } that identify the SIP dialog according to RFC 3261
    # Using the recusion and pattern matching
    { req2, dialog_id } = get_or_create_dialog_id(req)
    name = {:via, Registry, {Registry.SIPDialog, dialog_id, :cast }}
    dialog_params = { req2, direction, self(), timeout, debug, dialog_id }

    case GenServer.start(SIP.Dialog, dialog_params, name: name ) do
      { :ok, dlg_pid } ->
        # Cause deadlock -- why ?
        # The GenServer.call() times out and caused the caller process to terminate.
        # As if the GenServer was not ready to process request at ths point
        # dialog_id = GenServer.call(dlg_pid, :getdialogid)
        Logger.info([ dialogpid: "#{inspect(dlg_pid)}", module: __MODULE__, message: "Created dialog." ])
        { :ok, dlg_pid, dialog_id }

      { :error, err } ->
        Logger.error([ module: __MODULE__, message: "Failed to create dialog Error: #{err}."])
        { :error, err }

      _ ->
        Logger.error([ module: __MODULE__, message: "Failed to create dialog."])
        :error
    end
  end

  @spec start_dialog_with_template(any(), any()) :: :ok
  def start_dialog_with_template(_req, _timeout, _direction \\ :outbound, _debug \\ false) do
    :ok
  end


  @spec process_incoming_request(map(), pid(), boolean()) :: {:error, any()} | {:ok, pid()} | atom() | { any, any }
  def process_incoming_request(req, transact_id, debug) when is_req(req) do
    { req2, dialog_id } = get_or_create_dialog_id(req)
    case Registry.lookup(Registry.SIPDialog, dialog_id) do
      # No such dialog - create it if the request
      [] ->
        case req.method do
          :INVITE ->
            # todo, add a timeout global parameter
            start_dialog(req2, 1800, :inbound, debug)

          :OPTIONS ->
            start_dialog(req2, 60, :inbound, false)

          :MESSAGE ->
            start_dialog(req2, 60, :inbound, debug)

          :ACK ->
            # to add error log - ACK should be in dialog
            :nomatchingdialog

          :PRACK ->
            # to add error log - ACK should be in dialog
            :nomatchingdialog

          :REFER ->
            SIP.Transac.reply(transact_id, 481, " Call/Transaction Does Not Exist")
            :no_matching_dialog

          :CANCEL -> :nomatchingdialog

          m when m in [ :PUBLISH, :REGISTER, :SUBSCRIBE ] ->
            #Todo compulte timeout from refresh contact period
            to = 600
            start_dialog(req2, to, :inbound, debug)

          :UPDATE ->
            SIP.Transac.reply(transact_id, 481, " Call/Transaction Does Not Exist")
            :no_matching_dialog

          :BYE ->
            SIP.Transac.reply(transact_id, 481, " Call/Transaction Does Not Exist")
            :no_matching_dialog

          _ ->
            SIP.Transac.reply(transact_id, 500, " Unsupported request")
            :no_matching_dialog
        end

      # Found a matching dialog.Forward the SIP msg to it
      # We do not use dispatch because we have already looked up the transaction list
      # Note that lookup() should always return a single transaction here

      [ { dialog_pid, _dialog_id } ] ->
        GenServer.cast(dialog_pid, {:sipmsg, req2, transact_id})
        { dialog_pid, req2 }

      _ ->
        raise "Inconsitent dialog list: serveral dialogs associated with #{ IO.inspect(dialog_id)}"
    end
  end

  @doc "Reply to an in dialog request"
  def reply(dialog_id, req, resp_code, reason, upd_fields) when is_pid(dialog_id) and is_req(req) do
    GenServer.call(dialog_id, { :replyreq, req, resp_code, reason, upd_fields})
  end


  def new_request(dialog_pid, req) when is_pid(dialog_pid) and is_req(req) do
    GenServer.call(dialog_pid, { :newreq, req })
  end

  def challenge(dialog_pid, req, resp_code, realm) when resp_code in [ 401, 407 ] and is_req(req) do
    reply(dialog_pid, req, resp_code, nil, realm)
  end
end
