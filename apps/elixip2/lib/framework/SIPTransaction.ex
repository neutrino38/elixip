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
    timer100_ref: nil,
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

      { :error, { :already_started, _pid } } ->
        # Layer already running (e.g. started by a previous test module): treat as success
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

    # Get the local and IP port from the transport process. Not a bare
    # GenServer.call: this is the first thing said to a transport whose pid may
    # have been cached minutes ago, and an exit here happens inside the DIALOG
    # process (it is the dialog that opens transactions), where it propagated to
    # the scenario's own call and skipped its entire teardown — §14.2 (b).
    # The Via's sent-by is where this transaction's responses come back to, so it
    # is published towards the peer like a Contact is: on a 1:1 NAT the address a
    # peer outside must answer to is not the one we are bound to. The peer is the
    # resolved destination of the request we are about to send.
    case SIP.Transport.local_ip_for_peer(tp_pid, sipmsg.ruri.destip) do
      { :ok, local_ip, local_port } ->
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

      _err ->
        Logger.warning(module: __MODULE__,
          message: "Transport #{inspect(tp_pid)} is gone; cannot create a #{tc_mod} transaction.")
        :no_transport_available
    end
  end

  # The transport a request should actually go out on.
  #
  # A resolved R-URI carries the transport pid it was resolved with, and that pid
  # is then cached for the life of a dialog — in `state.msg.ruri`, copied onto
  # every in-dialog request. Nothing ever asked again whether it was still alive,
  # so a transport that died took every dialog using it with it: the next request
  # exited on a dead pid (§14.2 (b)).
  #
  # A dead CONNECTIONLESS transport is re-resolved instead. That is the whole
  # recovery story and it is nearly free: a node has one UDP socket, named by its
  # protocol in Registry.SIPTransport, so re-selection relaunches that singleton
  # and the dialog carries on — the far end never learns anything happened.
  #
  # A dead CONNECTED one is not, and deliberately: re-resolving it would open a
  # NEW connection, which is a different flow with a different source port, not
  # the one the peer is expecting answers on. Toward a NATed client (an inbound
  # flow, §3.2) it cannot even be attempted — the binding is stale and the
  # registration is what has to be redone. Same decision as R4/R5: a lost
  # connection ends the dialogs riding it.
  defp usable_transport(sipmsg) do
    ruri = sipmsg.ruri

    cond do
      not SIP.Uri.has_tp_info(ruri) ->
        add_transport_info(sipmsg)

      Process.alive?(ruri.tp_pid) ->
        sipmsg

      apply(ruri.tp_module, :is_reliable, []) ->
        Logger.warning(module: __MODULE__,
          message: "Connected transport #{inspect(ruri.tp_module)} toward " <>
            "#{inspect(ruri.destip)}:#{ruri.destport} is gone; its flow cannot be reopened.")
        :no_transport_available

      true ->
        Logger.info(module: __MODULE__,
          message: "Connectionless transport #{inspect(ruri.tp_module)} is gone; re-selecting one.")
        add_transport_info(Map.put(sipmsg, :ruri, %SIP.Uri{ ruri | tp_pid: nil }))
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
    {:error, any()}  | :invalidtemplate |  :no_transport_available | :missingproxyconf |
    {:ok, pid()}
  @doc "Start a client transaction from a template"
  def start_uac_transaction_with_template(siptemplate, bindings, parse_error_cb, options) when is_map(options) do
    try do
      # Extract the first non-empty line, handling both \r\n and \n line endings
      sipfirstline_raw = siptemplate
        |> String.split(~r/\r?\n/)
        |> Enum.find("", fn line -> String.trim(line) != "" end)
      sipfirstline = SIP.MsgTemplate.apply_template(sipfirstline_raw, bindings)
      case String.split(sipfirstline, " ", parts: 3) do

				# This is a SIP response
				[ "SIP/2.0", _response_code, _reason ] ->
					raise "Cannot start an UAC transaction with SIP response"

				# This is a SIP request
				[ _req, sip_uri, "SIP/2.0" ] ->
            # Resolve URI and get local transport parameters
            case  SIP.Transport.Selector.select_transport(sip_uri) do
              ruri when is_map(ruri) ->
                { :ok, local_ip, local_port } = SIP.Transport.get_local_ip_port(ruri.tp_pid)

                # Add local transport params to bindings
                bindings = bindings ++ [ local_ip: NetUtils.ip2string(local_ip), local_port: local_port ]

                # Apply the bindings to the template to create the SIP message
                msgstr = SIP.MsgTemplate.apply_template(siptemplate, bindings)

                # Create SIP message
                case SIPMsg.parse(msgstr, parse_error_cb) do
                  # Start transaction
                  { :ok, sipmsg } when is_req(sipmsg) -> start_uac_transaction(sipmsg, Map.get(options, :timeout, 60))

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

    # Resolve the R-URI when it carries no transport, and re-resolve it when the
    # one it carries has died under us (see usable_transport/1).
    case usable_transport(sipmsg) do
      newmsg when is_req(newmsg) -> transaction_start_common(tc_mod, newmsg, timeout)
      err -> err
    end
  end

  # An ACK never creates a server transaction (RFC 3261 §17.2.3). Guard against
  # the transport routing one here (symmetric to the UAC-side ACK guard): the ACK
  # of a 2xx is dispatched straight to the dialog by the transport layer instead.
  def start_uas_transaction(sipmsg, _params) when is_this_req(sipmsg, :ACK) do
    Logger.error(module: __MODULE__, message: "SIP request ACK cannot create a server transaction")
    { :req_cannot_create_trans, nil }
  end

  def start_uas_transaction(sipmsg, { _local_ip, _local_port, _transport_str, upperlayer })
      when is_map(sipmsg) do

    # Get top most via branch ID. The UAS transaction is keyed on it (RFC 3261
    # §17.2.3) so retransmissions / CANCEL / ACK match. A UAS does NOT add a Via:
    # the request's Via list must be echoed unchanged in the response, otherwise
    # the response's top Via (hence its transaction id) no longer matches the
    # client transaction that originated the request.
    [_, ori_branchid ]= hd(sipmsg.via) |> String.split("branch=")
    ori_branchid =  String.split(ori_branchid, ";") |> hd()

    # Associate this transaction with the original top most via branch ID.
    sipmsg = Map.put(sipmsg, :transid, ori_branchid)

    # Start a new GenServer for each transaction and register it in Registry.SIPTransaction
    ruri = sipmsg.ruri
    transact_params = { ruri.tp_module, ruri.tp_pid, ruri.destip, ruri.destport, sipmsg, upperlayer }

    # Note that the UAS transaction is associated with the ORIGINAL top most via to handle
    # SIP retransmissions, CANCEL, UPDATE, ACK
    name = {:via, Registry, { Registry.SIP.Transac, ori_branchid, :cast }}
    transaction_module = if sipmsg.method == :INVITE do
      SIP.IST
    else
      SIP.NIST
    end
    case GenServer.start(transaction_module, transact_params, name: name) do
      { :ok, trans_pid } ->
        Logger.debug([ transid: ori_branchid, message: "Created an #{transaction_module} with PID #{inspect(trans_pid)}." ])
        { :ok, trans_pid }

        { code, err } ->
          Logger.error("Failed to create an #{transaction_module}. Error: #{code}.")
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
        # Optionally dump the raw bytes (inspected, so CRLF/empty frames are
        # visible) to diagnose what the transport delivered — e.g. a WebSocket
        # keep-alive (RFC 7118: ping "\r\n\r\n", pong "\r\n") or a peer sending
        # non-canonical SIP. Gated by :dump_unparsed_sip (off by default, noisy).
        if Application.get_env(:elixip2, :dump_unparsed_sip, false) do
          Logger.warning("Unparseable SIP message (#{code}), raw bytes: #{inspect(sipmsgstr)}")
        end

        code
    end
  end

  @doc "Send a response to an UAS transation"
  def reply(uas_t, resp_code, reason, upd_fields \\ [], totag \\ nil) when is_pid(uas_t) and is_integer(resp_code) do
    GenServer.call(uas_t, { resp_code, reason, upd_fields, totag } )
  end

  @doc "Get the transaction PID associated with a SIP request"
  def get_transaction_pid(req) when is_req(req) do
    # Map.get, not req.transid: a request built by the application rather than
    # parsed off the wire carries no transid at all, and `req.transid` raises a
    # KeyError on it — inside the dialog, which then dies. The B2BUA teardown
    # answers exactly such requests (§8, and R6's leg-death hook).
    case Registry.lookup(Registry.SIP.Transac, Map.get(req, :transid)) do
      [ {trans_pid, _value} ] -> trans_pid
      _ -> :invalid_transaction
    end
  end

  @doc """
  Transactionful reply to a request.

  Always answers `{code, uas_t}` — `{:invalid_transaction, nil}` when there is no
  transaction to reply on. It used to return the bare atom on both refusal paths,
  and every caller destructures `{ret, uas_t} = reply_req(…)`: a reply to a
  request whose transaction is gone raised a MatchError in the DIALOG, killing it
  (design §14). That is not a rare shape — it is what answering an orphan request
  looks like once its transaction has timed out.
  """
  def reply_req(req , resp_code, reason, upd_fields, totag, tr_list_filter) when is_map(req) and is_integer(resp_code) do
    case get_transaction_pid(req) do
      :invalid_transaction ->
        Logger.error(module: __MODULE__,
                     message: "Cannot reply to #{req.method}. Req transid #{inspect(Map.get(req, :transid))} is not associated with a real transaction" )
        { :invalid_transaction, nil }

      uas_t ->
        if uas_t in tr_list_filter or tr_list_filter == nil do
          retcode = reply(uas_t, resp_code, reason, upd_fields, totag)
          { retcode, uas_t }
        else
          { :invalid_transaction, nil }
        end
    end
  end

  @doc """
  Hand an INVITE server transaction the ACK that confirms its 2xx.

  The ACK of a 2xx is a transaction of its own (RFC 3261 §17.1.1.3): its top Via
  branch differs from the INVITE's, so the transport cannot route it to the IST.
  The dialog layer — the TU — receives it and calls this to stop the 2xx
  retransmissions (§13.3.1.4). A cast, and the pid may already be dead: an ACK
  arriving after timer H is a no-op, not an error.
  """
  @spec confirm_uas_transaction(pid(), map()) :: :ok
  def confirm_uas_transaction(uas_t, ack) when is_pid(uas_t) and is_req(ack) do
    GenServer.cast(uas_t, {:onsipmsg, ack, nil, nil})
  end

  @doc "Send an ACK message when a 2xx answer has been received for in an UAC transaction"
  @spec ack_uac_transaction(pid()) :: any()
  def ack_uac_transaction(uac_t) do
    GenServer.call(uac_t, :ack)
  end

  @doc "Cancel an UAC transaction"
  @spec cancel_uac_transaction(pid()) :: any()
  def cancel_uac_transaction(uac_t) do
    GenServer.call(uac_t, :cancel)
  end

end
