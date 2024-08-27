defmodule SIP.Dialog do
@moduledoc "SIP module layer"
  require Logger
  require Registry
  require SIP.Uri


  defstruct [
    msg: nil, # SIP message that created this dialog
    supported: [],
    routeset: [],
    direction: :outbound, # outbound means that dialog was created by an outbound request.
    transactions: [],
    app: nil, # PID of the application
    state: :inital,
    debuglog: true, # If we should output debug logs for this dialog
    expirationtimer: nil
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


  # Obtain the triplet that uniquely identify a dialog
  defp get_dialog_id(req) do
    { _code, fromtag } = SIP.Uri.get_uri_param(req.from, "tag")
    callid = SIP.Uri.callid
    { _code, totag } = SIP.Uri.get_uri_param(req.to, "tag")
    { fromtag, callid, totag }
  end

  defp get_or_create_dialog_id( req ) do
    get_or_create_dialog_id( req, get_dialog_id(req) )
  end

  # Create call ID and add it to the request
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

  @doc "Start a dialog"
  def start_dialog(req, timeout, direction \\ :outbound, debug \\ false) do
    # Obtain create the dialog id { fromtag, callid, totag } that identify the SIP dialog according to RFC 3261
    # Using the recusion and pattern matching
    { req2, dialog_id } = get_or_create_dialog_id(req)
    name = {:via, Registry, {Registry.SIPDialog, dialog_id, :cast }}
    dialog_params = { req2, direction, self(), timeout, debug }

    case GenServer.start_link(SIP.Dialog, dialog_params, name: name ) do
      { :ok, dlg_pid } ->
        Logger.debug([ dialogid: "#{inspect(dialog_id)}" , message: "Created dialog with PID #{inspect(dlg_pid)}." ])
        { :ok, dlg_pid }

      { code, err } ->
        Logger.error("Failed to create dialog transaction. Error: #{code}.")
        { code, err }
    end
  end

  def start_dialog_with_template(req, timeout, direction \\ :outbound, debug \\ false) do
    raise "To be implemented later"
  end
end