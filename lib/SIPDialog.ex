defmodule SIP.Dialog do
@moduledoc "SIP module layer API"
  require Logger
  require Registry
  require SIP.Uri
  import SIP.Msg.Ops

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

    # ---------------------- Public API ----------------------

  @doc "Start a dialog"
  @spec start_dialog(map(), integer(), :inbound | :outbound, boolean() ) :: {:error, any()} | {:ok, pid(), tuple() }
  def start_dialog(req, timeout, direction, debug) when is_integer(timeout) and is_atom(req.method) do

    # Obtain or create the dialog id { fromtag, callid, totag } that identify the SIP dialog according to RFC 3261
    # Using the recusion and pattern matching
    { req2, dialog_id } = get_or_create_dialog_id(req)
    name = {:via, Registry, {Registry.SIPDialog, dialog_id, :cast }}
    dialog_params = { req2, direction, self(), timeout, debug, dialog_id }

    case GenServer.start(SIP.DialogImpl, dialog_params, name: name ) do
      { :ok, dlg_pid } ->
        # Cause deadlock -- why ?
        # The GenServer.call() times out and caused the caller process to terminate.
        # As if the GenServer was not ready to process request at ths point
        # dialog_id = GenServer.call(dlg_pid, :getdialogid)
        Logger.info([ dialogpid: "#{inspect(dlg_pid)}", module: __MODULE__, message: "Created dialog." ])
        { :ok, dlg_pid, dialog_id }

      { :error, err } ->
        Logger.error([ module: __MODULE__, message: "Failed to create dialog: #{inspect(err)}."])
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
