defmodule SIP.Transac do
  @moduledoc "SIP Transaction Layer"

  require SIP.ICT
  require Logger

  @doc "Start the transaction layer"
  def start() do
    #Create the registry
    case Registry.start_link(keys: :unique, name: Registry.SIPTransaction) do
      { :ok, pid } ->
        Logger.info("SIP transaction layer started with PID #{inspect(pid)}")
        :ok

      { code, _pid } ->
        Logger.error ("SIP transaction layer failed to start with error #{code}")
        code
    end
  end

  @doc """
  Start an INVITE client transaction (ICT)
  - first arg is the SIP message to send
  - second arg is a function that will loopkup a transport process
  - it returns a pid that represent the transaction. The process is a GenServer
  """
  def start_uac_transaction(sipmsg, transport_selector_fn, ring_timeout) when is_map(sipmsg) and sipmsg.method == :INVITE do
    # Generate the branch ID
    branch_id = SIPMsgOps.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    # Use callback passed to select transport
    case transport_selector_fn.(sipmsg.ruri) do
      { :ok, t_mod, t_pid } ->
        # Get the transport name frm the module
        transport_str = apply(t_mod, :transport_str, [])

        # Get the local and IP port from the transport process
        { :ok, local_ip, local_port  } = GenServer.call(t_pid, :getlocalipandport)
        local_ip_str = SIP.NetUtils.ip2string(local_ip)

        #Add the topmost via header
        sipmsg = SIPMsgOps.add_via(sipmsg, { local_ip_str, local_port, transport_str }, branch_id)

        # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
        # The process created IS the transaction
        name = {:via, Registry, {Registry.SIPTransaction, branch_id, :cast }}
        transact_params = { t_mod, t_pid, sipmsg, self(), ring_timeout }
        case GenServer.start_link(SIP.ICT, transact_params, name: name ) do
          { :ok, trans_pid } ->
            Logger.debug([ transid: branch_id, message: "Created invite client transaction with PID #{inspect(trans_pid)}." ])
            { :ok, trans_pid }

          { code, err } ->
            Logger.error("Failed to create invite client transaction. Error: #{code}.")
            { code, err }
        end

      _ ->
        { _err, ruri_str } = SIP.Uri.serialize(sipmsg.ruri)
        Logger.error("Failed to select transport for request URI #{ruri_str}.")
        { :no_transport_available, nil }
    end
  end

  def start_uac_transaction(sipmsg, _transport_selector_fn) when is_map(sipmsg) and sipmsg.method == :ACK  do
    Logger.error("SIP request " <> Atom.to_string(sipmsg.method) <> "cannot create transactions")
    { :req_cannot_create_trans, nil }
  end

  def start_uac_transaction(sipmsg, transport_selector_fn) when is_map(sipmsg) and sipmsg.method != :INVITE do
    # Generate the branch ID
    branch_id = SIPMsgOps.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    # Use callback passed to select transport
    case transport_selector_fn.(sipmsg.ruri) do
      { :ok, local_ip, local_port, transport_str, t_mod, t_pid } ->
        sipmsg = SIPMsgOps.add_via(sipmsg, { local_ip, local_port, transport_str }, branch_id)

        # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
        name = { :via, Registry, {Registry.SIPTransaction, branch_id, :cast }}
        case GenServer.start_link(SIP.NICT, { sipmsg, t_mod, t_pid }, name: name) do
          { :ok, trans_pid } ->
            Logger.debug([ transid: branch_id, message: "Created non-invite client transaction with PID #{trans_pid}." ])
            { :ok, trans_pid }

          { code, err } ->
            Logger.error("Failed to create non-invite client transaction. Error: #{code}.")
            { code, err }
        end

      code ->
        ruri_str = SIP.Uri.serialize(sipmsg.ruri)
        Logger.error("Failed to select transport for request URI #{ruri_str}. Error = #{code}")
        { :no_transport_available, nil }
    end
  end

  def start_uas_transaction(sipmsg, { local_ip, local_port, transport_str, t_mod, t_pid } , { remote_ip, remote_port }) when is_map(sipmsg) and sipmsg.method == :INVITE do
    # Generate the branch ID
    branch_id = SIPMsgOps.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    sipmsg = SIPMsgOps.add_via(sipmsg, { local_ip, local_port, transport_str }, branch_id)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    transact_params = { t_mod, t_pid, remote_ip, remote_port, sipmsg, self() }
    name = {:via, Registry, {Registry.SIPTransaction, branch_id, :cast }}
    case GenServer.start_link(SIP.IST, transact_params, name: name) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: branch_id, message: "Created non-invite client transaction with PID #{trans_pid}." ])
        { :ok, trans_pid }

        { code, err } ->
          Logger.error("Failed to create non-invite client transaction. Error: #{code}.")
          { code, err }
    end
  end

  def start_uas_transaction(sipmsg, { local_ip, local_port, transport_str, t_mod, t_pid } , { remote_ip, remote_port }) when is_map(sipmsg) and sipmsg.method != :INVITE do
    # Generate the branch ID
    branch_id = SIPMsgOps.generate_branch_value()
    #Todo : check that branch ID is not already registered on the transaction registry

    sipmsg = SIPMsgOps.add_via(sipmsg, { local_ip, local_port, transport_str }, branch_id)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    transact_params = { t_mod, t_pid, remote_ip, remote_port, sipmsg, self() }
    name = {:via, Registry, {Registry.SIPTransaction, branch_id, :cast }}
    case GenServer.start_link(SIP.NIST, transact_params, name: name) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: branch_id, message: "Created non-invite client transaction with PID #{trans_pid}." ])
        { :ok, trans_pid }

        { code, err } ->
          Logger.error("Failed to create non-invite client transaction. Error: #{code}.")
          { code, err }
    end
  end

  @doc "Process an incoming SIP message from the transport layer and dispatch it to the proper transaction"
  def process_sip_message(sipmsgstr) do

    trace_parse_err_fn =  fn code, errmsg, lineno, line ->
      Logger.error("Failed to parse SIP message: #{code}")
      Logger.info(errmsg)
      Logger.debug("Offending line #{lineno}: #{line}")
    end

    case SIPMsg.parse(sipmsgstr, trace_parse_err_fn) do
      { :ok, parsed_msg } ->
        case Registry.lookup(Registry.SIPTransaction, parsed_msg.transid) do
          # No such transction
          [] ->
            :no_matching_transaction

          # Found a matching transaction. Dispatch the SIP msg to it
          # We do not use dispatch because we have already looked up the transaction list
          # Note that lookup() should always return a single transaction here
          transaction_list ->
            for {pid, _cast_in} <- transaction_list, do: GenServer.cast(pid, {:onsipmsg, parsed_msg})
            :ok

          end
      { code, _err } ->
        code
    end
  end
end
