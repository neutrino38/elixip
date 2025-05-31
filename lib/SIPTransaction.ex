defmodule SIP.Transac do
  @moduledoc "SIP Transaction Layer"
alias SIP.NetUtils

  require Logger
  require Registry
  require SIP.Transport.Selector
  require Application
  import SIP.Msg.Ops

  # Struct defining a transaction
  defstruct [
    msg: nil, # SIP message that created this transaction
    tmod: nil, # Transport module used by this transaction
    tpid: nil, # PID of the transport instance
    app: nil, # PID of the application / dialog layer using the transaction
    t_isreliable: false, #If the associated transport is reliable
    timeout: 30, # transaction overall timeout in sec
    destip: {127,0,0,1},
    destport: 5060,
    state: :inital,
    tB_ref: nil,
    timerk: nil,
    timerf: nil,
    debuglog: true, # If we should output debug logs for this transaction
    upperlayer: nil
  ]

  @spec start() :: :error | :ok
  @doc "Start the transaction layer"
  def start() do
    #Create the registry
    case Registry.start_link(keys: :unique, name: Registry.SIP.Transac) do
      { :ok, pid } ->
        Logger.info("SIP transaction layer started with PID #{inspect(pid)}")
        :ok

      { code, _pid } ->
        Logger.error ("SIP transaction layer failed to start with error #{code}")
        code
    end
  end

  # Common part of transaction start
  defp transaction_start_common(tc_mod, sipmsg, timeout) do
    # Generate the branch ID
    branch_id = SIP.Msg.Ops.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry


    # Get the transport name frm the module
    tp_module = sipmsg.ruri.tp_module
    tp_pid = sipmsg.ruri.tp_pid
    transport_str = apply(tp_module, :transport_str, [])

    # Get the local and IP port from the transport process
    { :ok, local_ip, local_port  } = GenServer.call(tp_pid, :getlocalipandport)
    local_ip_str = SIP.NetUtils.ip2string(local_ip)

    #Add the topmost via header
    sipmsg = SIP.Msg.Ops.add_via(sipmsg, { local_ip_str, local_port, transport_str }, branch_id)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    # The process created IS the transaction
    name = {:via, Registry, {Registry.SIP.Transac, branch_id, :cast }}
    transact_params = { sipmsg, self(), timeout }
    case GenServer.start_link(tc_mod, transact_params, name: name ) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: branch_id, message: "Created #{tc_mod} with PID #{inspect(trans_pid)}." ])
        { :ok, trans_pid, sipmsg }

      { code, err } ->
        Logger.error("Failed to create #{tc_mod} transaction. Error: #{code}.")
        { code, err }
    end
  end

  defp add_transport_info(sipmsg) when is_req(sipmsg) do
    case SIP.Transport.Selector.select_transport(sipmsg.ruri) do
      # URI resolved -> update ruri in SIP request with transport available
      ruri when is_map(ruri) -> Map.put(sipmsg, :ruri, ruri)

      # URI resolution failure
      err ->
        Logger.error(module: __MODULE__,
          message: "Failed to create transaction: #{err}. Cannot select transport for request URI #{sipmsg.ruri}.")
        :no_transport_available
    end
  end

  @spec start_uac_transaction_with_template(binary(), list(), (... -> any), map()) ::
    {:error, any()}  |
    :invalidtemplate |
    :no_transport_available |
    :missiingproxyconf |
    {:ok, pid()}
  @doc "Start a client transaction from a template"
  def start_uac_transaction_with_template(siptemplate, bindings, parse_error_cb, options) when is_map(options) do
    try do
      { headers, _body } = case String.split(siptemplate, "\r\n\r\n", parts: 2) do
        [ hs, bd ] ->
          { String.split(hs, "\r\n"), bd }

        [ _hs ] ->
          { String.split(siptemplate, "\r\n"), nil }
      end
      sipfirstline = SIP.MsgTemplate.apply_template(hd(headers), bindings)
      case String.split(sipfirstline, " ", parts: 3) do

				# This is a SIP response
				[ "SIP/2.0", _response_code, _reason ] ->
					raise "Cannot start an UAC transaction with SIP response"

				# This is a SIP request
				[ _req, sip_uri, "SIP/2.0" ] ->
            # Resolve URI and get local transport parameters
            case  SIP.Transport.Selector.select_transport(sip_uri) do
              ruri when is_map(ruri) ->
                { :ok, local_ip, local_port } = GenServer.call(ruri.tp_pid, :getlocalipandport)

                # Add local transport params to bindings
                bindings = bindings ++ [ local_ip: NetUtils.ip2string(local_ip), local_port: local_port ]

                # Apply the bindings to the template to create the SIP message
                msgstr = SIP.MsgTemplate.apply_template(siptemplate, bindings)

                # Create SIP message
                case SIPMsg.parse(msgstr, parse_error_cb) do
                  # Start transaction
                  { :ok, sipmsg } when is_req(sipmsg) -> start_uac_transaction(sipmsg, 600)

                  { :ok, sipmsg } when is_resp(sipmsg) -> raise "Cannot start an UAC transaction with SIP response"

                end

              _err ->
                # Add log
                raise "Invalid SIP template first line"
            end

      end
    rescue
      ArgumentError ->
        Logger.error("Transaction cannot be started with template without a specified destination or a proxy setting")
        Logger.info("Specify %{ desturi: <dest SIP uri> usesrv: false | true } in the option arguments or ")
        Logger.info("Specify a SIP proxy in config.exs. Add a section:\nconfig :elixp2   proxyuri: <SIP proxy URI>\n   usesrv: false | true")
        :missingproxyconf

      e -> reraise e, __STACKTRACE__
    end
  end


  @doc """
  Start an  client transaction (ICT)
  - first arg is the SIP message to send
  - second arg is the number of seconds the callshould be tried
  - it returns a pid that represent the transaction. The process is a GenServer
  """
  def start_uac_transaction(sipmsg, _timeout) when is_this_req(sipmsg, :ACK)  do
    Logger.error(module: __MODULE__, message: "SIP request " <> Atom.to_string(sipmsg.method) <> "cannot create transactions")
    { :req_cannot_create_trans, nil }
  end

  def start_uac_transaction(sipmsg, _timeout) when is_resp(sipmsg)  do
    Logger.error(module: __MODULE__, message: "SIP request " <> Atom.to_string(sipmsg.method) <> "cannot create transactions")
    { :req_cannot_create_trans, nil }
  end

  def start_uac_transaction(sipmsg, timeout) when is_req(sipmsg) and is_integer(timeout) do
    # Select the correct transaction module
    tc_mod = if sipmsg.method == :INVITE, do: SIP.ICT, else: SIP.NICT

    # If SIP message contains the resolved destination, just do it
    if SIP.Uri.has_tp_info(sipmsg.ruri) do
      transaction_start_common(tc_mod, sipmsg, timeout)
    else
      # Resolve R-URI
      case add_transport_info(sipmsg) do
        newmsg when is_req(newmsg) -> transaction_start_common(tc_mod, newmsg, timeout)
        err -> err
      end
    end
  end

  def start_uas_transaction(sipmsg, { local_ip, local_port, transport_str, t_mod, t_pid } , { remote_ip, remote_port }) when is_map(sipmsg) and sipmsg.method == :INVITE do
    # Generate the branch ID
    branch_id = SIP.Msg.Ops.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    sipmsg = SIP.Msg.Ops.add_via(sipmsg, { local_ip, local_port, transport_str }, branch_id)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    transact_params = { t_mod, t_pid, remote_ip, remote_port, sipmsg, self() }
    name = {:via, Registry, {Registry.SIP.Transac, branch_id, :cast }}
    case GenServer.start_link(SIP.IST, transact_params, name: name) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: branch_id, message: "Created non-invite client transaction with PID #{trans_pid}." ])
        { :ok, trans_pid }

        { code, err } ->
          Logger.error("Failed to create non-invite client transaction. Error: #{code}.")
          { code, err }
    end
  end

  def start_uas_transaction(sipmsg,
    { local_ip, local_port, transport_str, t_mod, t_pid, upperlayer },
    { remote_ip, remote_port }) when is_map(sipmsg) and sipmsg.method != :INVITE do

    # Generate the branch ID
    branch_id = SIP.Msg.Ops.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    sipmsg = SIP.Msg.Ops.add_via(sipmsg, { local_ip, local_port, transport_str }, branch_id)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    transact_params = { t_mod, t_pid, remote_ip, remote_port, sipmsg, upperlayer }
    name = {:via, Registry, {Registry.SIP.Transac, branch_id, :cast }}
    case GenServer.start_link(SIP.NIST, transact_params, name: name) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: branch_id, message: "Created non-invite client transaction with PID #{inspect(trans_pid)}." ])
        { :ok, trans_pid }

        { code, err } ->
          Logger.error("Failed to create non-invite client transaction. Error: #{code}.")
          { code, err }
    end
  end

  @spec process_sip_message(binary()) :: :ok | { :no_matching_transaction, map() } | atom()
  @doc "Process an incoming SIP message from the transport layer and dispatch it to the proper transaction"
  def process_sip_message(sipmsgstr, remoteip \\ nil, remoteport \\ nil) do

    trace_parse_err_fn =  fn code, errmsg, lineno, line ->
      Logger.error("Failed to parse SIP message: #{code}")
      Logger.info(errmsg)
      Logger.debug("Offending line #{lineno}: #{line}")
    end

    case SIPMsg.parse(sipmsgstr, trace_parse_err_fn) do
      { :ok, parsed_msg } ->
        case Registry.lookup(Registry.SIP.Transac, parsed_msg.transid) do
          # No such transction
          [] ->
            { :no_matching_transaction, parsed_msg }

          # Found a matching transaction. Dispatch the SIP msg to it
          # We do not use dispatch because we have already looked up the transaction list
          # Note that lookup() should always return a single transaction here
          transaction_list ->
            for {pid, _cast_in} <- transaction_list, do: GenServer.cast(pid, {:onsipmsg, parsed_msg, remoteip, remoteport})
            :ok

        end


      { code, _err } ->
        code
    end
  end

  @doc "Send an ACK message when a 2xx answer has been received for in an UAC transaction"
  @spec ack_uac_transaction(pid()) :: any()
  def ack_uac_transaction(uac_t) do
    GenServer.call(uac_t, :ack)
  end

  @doc "Send a response to an UAS transation"
  def reply(uas_t, resp_code, reason, upd_fields \\ [], totag \\ nil) when is_pid(uas_t) and is_integer(resp_code) do
    GenServer.call(uas_t, { resp_code, reason, upd_fields, totag } )
  end

  @doc "Transactionful reply to a request"
  def reply_req(req , resp_code, reason, upd_fields, totag, tr_list_filter) when is_map(req) and is_integer(resp_code) do
    [ {uas_t, _value} ] = Registry.lookup(Registry.SIP.Transac, req.transid)
    if uas_t in tr_list_filter or tr_list_filter == nil do
      retcode = reply(uas_t, resp_code, reason, upd_fields, totag)
      { retcode, uas_t }
    else
      :invalid_transaction
    end
  end
end
