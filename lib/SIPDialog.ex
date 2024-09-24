defmodule SIP.Dialog do
@moduledoc "SIP module layer"
  require Logger
  require Registry
  require SIP.Uri
  use GenServer


  defstruct [
    msg: nil, # SIP message that created this dialog
    supported: [],
    routeset: [],
    direction: :outbound, # outbound means that dialog was created by an outbound request.
    curtrans: nil,  # Current transaction
    transactions: [],
    app: nil, # PID of the application
    state: :inital,
    debuglog: true, # If we should output debug logs for this dialog
    expirationtimer: nil,
    cseq: 1,
    fromtag: nil,
    callid: nil,
    totag: nil
  ]


  defmodule Listener do
    use Agent

    defstruct [
      app: nil,
      callhandlingmodule: nil,
      onnewregistration: nil,
    ]
    def start() do

    end
  end
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

  # -------- GenServer callbacks --------------------


  @impl true
  def init({ req, direction, pid, timeout, debug, dialog_id }) do
    { fromtag, callid, totag } = dialog_id
    # Generate totag if needed
    totag = if is_nil(totag), do: SIP.Msg.Ops.generate_from_or_to_tag(), else: totag

    if direction == :inbound do
      state = %SIP.Dialog{ msg: req, direction: direction, app: nil, expirationtimer: timeout, debuglog: debug,
                   transactions: [ pid ], fromtag: fromtag, callid: callid, totag: totag }

      # Dispatch the initial request to the upper layer
      case SIP.Session.ConfigRegistry.dispach(self(), req ) do
        { :accept, app_id } -> { :ok, Map.put(state, :app, app_id ) }

        # Session has not been created. Abort dialog
        { :reject, code, reason } -> { :stop, { code, reason }}
      end

    else
      state = %SIP.Dialog{ msg: req, direction: direction, app: pid, expirationtimer: timeout, debuglog: debug,
                   transactions: [], fromtag: fromtag, callid: callid, totag: totag }

      #In case of an outbound dialog, start a, UAC transaction
      case SIP.Transac.start_uac_transaction( req, timeout ) do
        { :ok, transaction_pid } -> { :ok, %SIP.Dialog{ state | transactions: [ transaction_pid ] } }
        { code, _extra } -> { :stop, code }
      end
    end
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
    { :reply, { state.fromtag, state.callid, state.totag } }
  end

  # Invoked when dialog process receives sip message
  # sent by calling process_incoming_request(). Typically
  # from NIST or IST transaction processes
  @impl true
  def handle_cast({:sipmsg, req, transact_pid} ) do

  end
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
  @spec get_or_create_dialog_id( map() ) :: map()
  defp get_or_create_dialog_id( req, { fromtag, nil, totag }) do
    callid = SIP.Msg.Ops.generate_from_or_to_tag()
    req = Map.put(req, :callid, callid)
    get_or_create_dialog_id( req, { fromtag, callid, totag } )
  end

  # Create from TAG and add it the from URI
  defp get_or_create_dialog_id( req, { nil, callid , totag }) do
    fromtag = SIP.Msg.Ops.generate_from_or_to_tag()
    req = Map.put(req, :from, SIP.Uri.set_uri_param(req.from, "tag", fromtag))
    get_or_create_dialog_id( req, { fromtag, callid, totag } )
  end

  # At least from tag and callid are present, return them and end the recursion
  defp get_or_create_dialog_id( req, { fromtag, callid , totag } )  when is_binary(fromtag) and is_binary(callid) do
    {req,  { fromtag, callid , totag } }
  end

  @spec start_dialog(map(), integer(), { :inbound | :outbound }, boolean() ) :: {:error, any()} | {:ok, pid()}
  @doc "Start a dialog"
  def start_dialog(req, timeout, direction \\ :outbound, debug \\ false) when is_atom(req.method) do
    # Obtain create the dialog id { fromtag, callid, totag } that identify the SIP dialog according to RFC 3261
    # Using the recusion and pattern matching
    { req2, dialog_id } = get_or_create_dialog_id(req)
    name = {:via, Registry, {Registry.SIPDialog, dialog_id, :cast }}
    dialog_params = { req2, direction, self(), timeout, debug, dialog_id }

    case GenServer.start_link(SIP.Dialog, dialog_params, name: name ) do
      { :ok, dlg_pid } ->
        Logger.debug([ dialogid: "#{inspect(dialog_id)}" , message: "Created dialog with PID #{inspect(dlg_pid)}." ])
        # Bind the outbound dialog to the caller process which is
        # assumed to be the application
        if direction == :outbound do
          GenServer.call(dlg_pid, { :setapppid, self() })
        end

        dialog_id = GenServer.call(dlg_pid, :getdialogid)
        { :ok, dlg_pid, dialog_id }

      { :error, err } ->
        Logger.error("Failed to create dialog Error: #{err}.")
        { :error, err }
    end
  end

  def start_dialog_with_template(_req, _timeout, _direction \\ :outbound, _debug \\ false) do
    :ok
  end


  @spec process_incoming_request(map(), pid(), boolean()) :: {:error, any()} | {:ok, pid()} | :nomatchingdialog
  def process_incoming_request(req, transact_pid, debug) when is_map(req) and is_atom(req.method) do
    { req2, dialog_id } = get_or_create_dialog_id(req)
    case Registry.lookup(Registry.Dialog, dialog_id) do
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

          m when m in [ :PUBLISH, :REGISTER, :SUBSCRIBE ] ->
            #Todo compulte timeout from refresh contact period
            to = 600
            start_dialog(req2, to, :inbound, debug)

          :UPDATE ->
            SIP.Transac.reply(transact_pid, 481, " Call/Transaction Does Not Exist")
            :no_matching_dialog

          :BYE ->
            SIP.Transac.reply(transact_pid, 481, " Call/Transaction Does Not Exist")
            :no_matching_dialog

          _ ->
            SIP.Transac.reply(transact_pid, 500, " Unsupported request")
            :no_matching_dialog
        end

      # Found a matching transaction. Dispatch the SIP msg to it
      # We do not use dispatch because we have already looked up the transaction list
      # Note that lookup() should always return a single transaction here
      dialog_list when is_list(dialog_list) ->
        pid = hd(dialog_list)
        GenServer.cast(pid, {:sipmsg, req2, transact_pid})
        { pid, req2 }
    end
  end
end
