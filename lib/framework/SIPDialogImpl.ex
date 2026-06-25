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
    # SIP message that created this dialog
    msg: nil,
    allows: [],
    # Route set (Record-Route of the dialog-establishing response)
    routeset: [],
    # Remote target URI (Contact of the dialog-establishing response)
    remotetarget: nil,
    # outbound means that dialog was created by an outbound request.
    direction: :outbound,
    # Current transaction
    curtrans: nil,
    transactions: [],
    # PID of the transaction that should terminate the dialog
    closing_transaction: nil,
    # PID of the application
    app: nil,
    state: :initial,
    # If we should output debug logs for this dialog
    debuglog: true,
    expirationtimer: nil,
    dialogtimeout: 0,
    keepalivetimer: nil,
    missedkeepalive: 0,
    cseq: 1,
    cseqin: 1,
    fromtag: nil,
    callid: nil,
    totag: nil,
    destip: nil,
    destport: 0,
    # Map to store nonces and their expiration times
    nonce_map: %{}
  ]

  defp on_new_transaction(state, req, _transact_id)
       when is_map(req) and req.method in [:ACK, :CANCEL] do
    # Specific case for ACK. Do not create a new transaction for these request
    {:nonewtrans, state}
  end

  defp on_new_transaction(state, _req, transact_id) do
    if Enum.count(state.transactions) < 4 do
      {:ok, Map.put(state, :transactions, List.insert_at(state.transactions, -1, transact_id))}
    else
      {:toomanytransactions, state}
    end
  end

  defp allows(:REGISTER) do
    [:REGISTER, :OPTIONS]
  end

  defp allows(:INVITE) do
    [:BYE, :UPDATE, :ACK, :MESSAGE, :INFO, :INVITE, :REFER]
  end

  defp allows(:OPTIONS) do
    [:OPTIONS]
  end

  defp allows(prezreq) when prezreq in [:PUBLISH, :SUBSCRIBE, :NOTIFY, :MESSAGE] do
    [:PUBLISH, :SUBSCRIBE, :NOTIFY, :MESSAGE]
  end

  defp set_tag(req, h, tag) when is_req(req) and h in [:from, :to] do
    uri = Map.get(req, h)

    uri =
      if is_binary(uri) do
        {:ok, puri} = SIP.Uri.parse(uri)
        puri
      else
        uri
      end

    Map.put(req, h, SIP.Uri.set_uri_param(uri, "tag", tag))
  end

  # Apply fromtag, totag, callid and CSeq
  # Todo : fix route, request URI ...
  defp fix_outbound_request(state, req, is_initial \\ false) when is_req(req) do
    newreq =
      Map.put(req, :cseq, [state.cseq, req.method])
      |> Map.put(:callid, state.callid)
      |> set_tag(:from, state.fromtag)

    # True in-dialog requests (everything but the very first one) must be
    # addressed to the remote party: the To URI of the original request plus the
    # remote tag, sent to the remote target through the dialog route set
    # (RFC 3261 §12.2.1.1). Before a dialog-establishing response arrives, the
    # remote tag/target/route set are still unknown, so a request sent then (e.g.
    # an INVITE resubmitted after a 401/407 challenge) goes out unchanged.
    #
    # REGISTER and OPTIONS are NOT dialog-forming (RFC 3261 §10, §11): a REGISTER
    # refresh / OPTIONS keepalive reuses the registration's Call-ID + From-tag and
    # bumps the CSeq, but it keeps its own Request-URI (the registrar) and carries
    # NO To-tag. Re-targeting them would (wrongly) point the refresh at the
    # returned Contact binding and add a To-tag, which the registrar then sees as a
    # different dialog.
    newreq =
      if not is_initial and req.method not in [:OPTIONS, :REGISTER] do
        newreq
        |> route_to_remote_target(state)
        |> add_route_set(state)
        |> set_remote_totag(state)
      else
        newreq
      end

    # Increment cseq for outbound and store modified request
    msg = if state.msg == nil, do: newreq, else: state.msg
    newstate = %SIP.DialogImpl{state | cseq: state.cseq + 1, msg: msg}
    {newstate, newreq}
  end

  # Address the request to the remote party: To URI from the original request
  # and request URI set to the remote target learned from the establishing
  # response. Falls back to the request's own values when nothing is known yet.
  defp route_to_remote_target(req, state) do
    to_uri = if state.msg, do: state.msg.to, else: req.to
    ruri = state.remotetarget || req.ruri
    %{req | to: to_uri, ruri: ruri}
  end

  # Add the dialog route set (single Record-Route is stored verbatim).
  defp add_route_set(req, %SIP.DialogImpl{routeset: rs}) when is_binary(rs) and rs != "" do
    Map.put(req, :route, rs)
  end

  defp add_route_set(req, _state), do: req

  defp set_remote_totag(req, %SIP.DialogImpl{totag: totag}) when is_binary(totag) do
    set_tag(req, :to, totag)
  end

  defp set_remote_totag(req, _state), do: req

  def send_in_dialog_request(state = %SIP.DialogImpl{}, req) do
    if req.method in state.allows do
      if Enum.count(state.transactions) < 4 do
        {state, req} = fix_outbound_request(state, req)

        # Copy transport parameters from the request that opened the dialog into the RURI to reuse them
        o_ruri = state.msg.ruri

        ruri = %SIP.Uri{
          req.ruri
          | destip: o_ruri.destip,
            destport: o_ruri.destport,
            tp_module: o_ruri.tp_module,
            tp_pid: o_ruri.tp_pid
        }

        req = %{req | ruri: ruri}
        # Create an UAC transaction to send the request out
        case SIP.Transac.start_uac_transaction(req, 15) do
          # Failed to send the message or create the transaction
          {code, nil} ->
            {code, state}

          {:ok, transaction_pid, _modmsg} ->
            # Add the transaction in the transaction list
            newstate = %SIP.DialogImpl{
              state
              | transactions: List.insert_at(state.transactions, -1, transaction_pid)
            }

            # Handle expiration timer and closing transaction
            {:ok, newstate} =
              arm_expiration_timer(newstate, req)
              |> check_closing_transaction(req, transaction_pid)

            # Surface the client transaction pid to the caller (see SIP.Dialog.new_request/2).
            {{:ok, transaction_pid}, newstate}
        end
      else
        # Cannot open too many transaction for dialog
        Logger.warning(
          dialogpid: self(),
          module: __MODULE__,
          message: "Too many open transaction for this dialog. Dropping request #{req.method}"
        )

        {:toomanytransactons, state}
      end
    else
      # Not allowed
      Logger.debug(
        dialogpid: self(),
        module: __MODULE__,
        message: "Method #{req.method} not allowed in this dialog"
      )

      {:methodnotallowed, state}
    end
  end

  # --------------------------- OPTIONS keepalive -------------------------
  @doc "arm the registration keepalive timer"
  def arm_options_keepalive_timer(state = %SIP.DialogImpl{}) do
    if state.keepalivetimer == nil and state.direction == :outbound do
      %SIP.DialogImpl{
        state
        | keepalivetimer: :erlang.start_timer(15000, :optionskeepalive, self())
      }
    else
      state
    end
  end

  def cancel_options_keepalive_timer(state = %SIP.DialogImpl{}) do
    if state.keepalivetimer != nil do
      :erlang.cancel_timer(state.keepalivetimer)
      %SIP.DialogImpl{state | keepalivetimer: nil}
    end
  end

  def send_options_keepalive(state = %SIP.DialogImpl{}) do
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
      :established ->
        # Send OPTIONS message
        {_rc, state} = send_in_dialog_request(state, msg)

        # Refresh timer
        arm_options_keepalive_timer(state)

      :terminated ->
        # Dialog is dead. Kill timer
        cancel_options_keepalive_timer(state)

      _ ->
        state
    end
  end

  # --------------------------- General expiration timer -------------------------
  def arm_expiration_timer(state = %SIP.DialogImpl{}, req) when req.method == :INVITE do
    expire =
      case Map.get(req, "Session-Expire", 1800) do
        1800 -> 1800
        exp -> String.to_integer(exp)
      end

    state = cancel_expiration_timer(state)

    %SIP.DialogImpl{
      state
      | expirationtimer: :erlang.start_timer(expire * 1000, :inviterefresh, self())
    }
  end

  @doc """
  For dialogs created by REGISTER message, we have two cases: client REGISTER or server REGISTER

  - for client REGISTER, we arm a timer that is equal to half of the expiration time and send a refresh
    register automatically. We also send an OPTIONS message every 15 seconds to keep the NAT or the
    connectionfull co
  """
  def arm_expiration_timer(state = %SIP.DialogImpl{}, req) when req.method == :REGISTER do
    {expire, timeratom} =
      case SIP.Uri.get_uri_param(req.contact, "expires") do
        {:no_such_param, nil} ->
          {1, :unregister}

        {:no_such_param, "0"} ->
          {1, :unregister}

        {:ok, value} ->
          exp = String.to_integer(value)

          if state.direction == :inbound do
            {exp, :registerexpire}
          else
            {trunc(exp / 2), :registerrefresh}
          end
      end

    state = cancel_expiration_timer(state)

    %SIP.DialogImpl{
      state
      | expirationtimer: :erlang.start_timer(expire * 1000, timeratom, self())
    }
  end

  # Default, do nothing
  def arm_expiration_timer(state = %SIP.DialogImpl{}, _req) do
    state
  end

  @doc "Cancels the dialog expiration timer"
  def cancel_expiration_timer(state = %SIP.DialogImpl{}) do
    if state.expirationtimer != nil do
      :erlang.cancel_timer(state.expirationtimer)
      %SIP.DialogImpl{state | expirationtimer: nil}
    else
      state
    end
  end

  # -------- GenServer callbacks --------------------

  @impl true
  @spec init({map(), :inbound | :outbound, pid(), integer(), boolean(), {any(), any(), any()}}) ::
          {:ok, map()} | {:stop, atom() | {any(), any()}}

  def init({req, :inbound, pid, timeout, debug, dialog_id}) when is_req(req) do
    {fromtag, callid, totag} = dialog_id
    # Generate totag if needed
    totag = if is_nil(totag), do: generate_from_or_to_tag(), else: totag

    state = %SIP.DialogImpl{
      msg: req,
      direction: :inbound,
      app: nil,
      dialogtimeout: timeout,
      debuglog: debug,
      transactions: [pid],
      fromtag: fromtag,
      callid: callid,
      totag: totag,
      allows: allows(req.method)
    }

    # Dispatch the initial request to the upper layer. `pid` is the server
    # transaction that created this dialog; it is forwarded so the processing
    # module (e.g. a registrar) knows which transaction to reply on.
    case SIP.Session.ConfigRegistry.dispatch(self(), req, pid) do
      {:accept, app_id} ->
        Logger.debug(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Bound dialog to app process #{inspect(app_id)}"
        )

        # Send the message to the newly created app layer
        send(app_id, {req.method, req, pid, self()})
        {:ok, Map.put(state, :app, app_id)}

      # Session has not been created. Abort dialog
      {:reject, code, reason} ->
        Logger.error(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Failed to create the app process. Err: #{code}. Aborting dialog creation."
        )

        {:stop, :abnormal, reason}
    end
  end

  # Dialog started by an outbound request
  def init({req, :outbound, pid, timeout, debug, dialog_id}) when is_req(req) do
    {fromtag, callid, _totag} = dialog_id

    state = %SIP.DialogImpl{
      msg: req,
      direction: :outbound,
      app: pid,
      dialogtimeout: timeout,
      debuglog: debug,
      transactions: [],
      fromtag: fromtag,
      callid: callid,
      totag: nil,
      allows: allows(req.method)
    }

    {state, req} = fix_outbound_request(state, req, true)

    try do
      # In case of an outbound dialog, start a, UAC transaction
      case SIP.Transac.start_uac_transaction(req, timeout) do
        {:ok, transaction_pid, modmsg} ->
          send(state.app, {:onnewdialog, :ok, transaction_pid})

          %SIP.DialogImpl{state | transactions: [transaction_pid], msg: modmsg}
          |> arm_expiration_timer(modmsg)
          # This returns { :ok, newstate } as expected by init()
          |> check_closing_transaction(modmsg, transaction_pid)

        {code, _extra} ->
          Logger.error(
            module: __MODULE__,
            dialogpid: self(),
            message: "Failed to create client transaction, err: #{code}."
          )

          {:stop, :abnormal, code}

        :no_transport_available ->
          Logger.debug(
            module: __MODULE__,
            dialogpid: self(),
            message:
              "Failed to create client transaction because we could not find / start a suitable transport."
          )

          {:stop, :no_transport_available}
      end
    rescue
      err ->
        Logger.error(
          module: __MODULE__,
          dialogpid: self(),
          message: "Failed to create client transaction. Exception occurred."
        )

        Logger.error(Exception.format(:error, err, __STACKTRACE__))
        {:stop, :transactionfailure}
    end
  end

  defp check_expired_nonces(state) do
    now = DateTime.utc_now()

    new_nonce_map =
      Enum.reduce(state.nonce_map, %{}, fn {nonce, expiration_time}, acc ->
        if DateTime.compare(now, expiration_time) == :lt do
          Map.put(acc, nonce, expiration_time)
        else
          Logger.debug(
            dialogpid: self(),
            module: __MODULE__,
            message: "Nonce #{nonce} expired and removed from nonce_map"
          )

          acc
        end
      end)

    %SIP.DialogImpl{state | nonce_map: new_nonce_map}
  end

  defp add_new_nonce(state, nonce) do
    # Nonce valid for 30 seconds
    expiration_time = DateTime.utc_now() |> DateTime.add(30, :second)
    new_nonce_map = Map.put(state.nonce_map, nonce, expiration_time)
    # Arm a timer to check for expired nonces after 30 seconds
    Process.send_after(self(), :check_expired_nonces, 30100)
    %SIP.DialogImpl{state | nonce_map: new_nonce_map}
  end

  defp valid_nonce?(state, nonce) do
    case Map.get(state.nonce_map, nonce) do
      nil ->
        Logger.info(
          dialogpid: self(),
          module: __MODULE__,
          message: "Nonce #{nonce} is invalid or expired"
        )

        false

      expiration_time ->
        if DateTime.compare(DateTime.utc_now(), expiration_time) == :lt do
          true
        else
          Logger.info(
            dialogpid: self(),
            module: __MODULE__,
            message: "Nonce #{nonce} has expired"
          )

          false
        end
    end
  end

  @impl true
  @doc """
  Invoked when the dialog GenServer stops (end of call: BYE in either direction,
  timeout, or failure). Notifies the bound application process so it can release
  resources tied to the call lifetime (e.g. media). The dialog pid passed in the
  message is `self()` here, i.e. the same pid the app knows as its dialog.
  """
  def terminate(reason, state) do
    if is_pid(state.app) do
      send(state.app, {:dialog_terminated, self(), reason})
    end

    :ok
  end

  defp close_transaction(state, uas_t) do
    %SIP.DialogImpl{state | transactions: List.delete(state.transactions, uas_t)}
  end

  @impl true
  def handle_call({:setapppid, app_pid}, _from, state) do
    if state.direction == :inbound and state.app == nil do
      {:reply, :ok, %SIP.DialogImpl{state | app: app_pid}}
    else
      {:reply, :alreadybound, state}
    end
  end

  # Obtain the call ID of a given dialog
  def handle_call(:getdialogid, _from, state) do
    {:reply, {state.fromtag, state.callid, state.totag}, state}
  end

  # Reply to an in_dialog request
  def handle_call({:replyreq, req, resp_code, reason, realm}, _from, state)
      when resp_code in [401, 407] do
    auth = %{realm: realm, algorithm: "SHA256", authproc: "Digest"}

    {ret, uas_t} =
      SIP.Transac.reply_req(req, resp_code, reason, auth, state.totag, state.transactions)

    case ret do
      {:ok, nonce} ->
        # Store the nonce and its expiration time in the nonce_map
        new_state = add_new_nonce(state, nonce)
        {:reply, :ok, add_totag(new_state, nil) |> close_transaction(uas_t)}

      _ ->
        {:reply, ret, add_totag(state, nil) |> close_transaction(uas_t)}
    end
  end

  def handle_call({:replyreq, req, resp_code, reason, upd_field}, _from, state) do
    {ret, uas_t} =
      SIP.Transac.reply_req(req, resp_code, reason, upd_field, state.totag, state.transactions)

    state =
      case resp_code do
        100 -> state
        rc when rc in 101..199 -> add_totag(state, nil)
        rc when rc in 200..699 -> add_totag(state, nil) |> close_transaction(uas_t)
        _ -> raise "Unsupported response code #{resp_code}"
      end

    {:reply, ret, state}
  end

  @doc "Handle call to send out a new in-dialog request"
  def handle_call({:newreq, req}, _from, state) when is_req(req) do
    {rc, state} = send_in_dialog_request(state, req)
    {:reply, rc, state}
  end

  def handle_call({:cancel, transact_pid}, _from, state) do
    if transact_pid in state.transactions do
      reply = SIP.Transac.cancel_uac_transaction(transact_pid)
      {:reply, reply, state}
    else
      {:reply, :nosuchtransaction, state}
    end
  end

  # Handle call to send out an ACK for an INVITE request
  def handle_call({:ack, transact_pid}, _from, state) do
    if transact_pid in state.transactions do
      reply = SIP.Transac.ack_uac_transaction(transact_pid)
      # The INVITE client transaction is done once it has been ACKed; drop it
      # from the dialog so later in-dialog requests (BYE, re-INVITE…) start fresh.
      {:reply, reply, close_transaction(state, transact_pid)}
    else
      {:reply, :nosuchtransaction, state}
    end
  end

  # Handle call to check if a nonce is valid
  def handle_call({:checknonce, nonce}, _from, state) do
    is_valid = valid_nonce?(state, nonce)
    {:reply, is_valid, state}
  end

  defp check_closing_transaction(state, msg, transact_pid) when msg.method in [:BYE] do
    {:ok, %SIP.DialogImpl{state | closing_transaction: transact_pid}}
  end

  defp check_closing_transaction(state, _msg, _transact_pid) do
    {:ok, state}
  end

  defp check_allows(state, msg) do
    if msg.method in state.allows do
      {:ok, state}
    else
      {:notallowed, state}
    end
  end

  defp check_seqno(state, msg) do
    [seqno, _cmethod] = msg.cseq

    if seqno > state.cseqin do
      {:ok, %SIP.DialogImpl{state | cseqin: seqno}}
    else
      {:out_of_order, state}
    end
  end

  defp send_req_to_app(state, msg, transact_pid) do
    # Forward request to app layer
    send(state.app, {msg.method, msg, transact_pid, self()})

    Logger.debug(
      dialogpid: self(),
      module: __MODULE__,
      message: "Forwarded request to app process #{inspect(state.app)}"
    )

    {:ok, state}
  end

  # Invoked when dialog process receives sip request
  # sent by calling process_incoming_request(). Typically
  # from NIST or IST transaction processes. Also get

  @impl true
  def handle_cast({:sipmsg, msg, transact_pid}, state) when is_req(msg) do
    Logger.debug(
      dialogpid: self(),
      module: __MODULE__,
      message: "Handing in-dialog SIP req #{msg.method}"
    )

    with {:ok, state} <- on_new_transaction(state, msg, transact_pid),
         {:ok, state} <- check_allows(state, msg),
         {:ok, state} <- check_seqno(state, msg),
         {:ok, state} <- send_req_to_app(state, msg, transact_pid),
         {:ok, state} <- check_closing_transaction(state, msg, transact_pid) do
      {:noreply, arm_expiration_timer(state, msg)}
    else
      {:notallowed, state} ->
        SIP.Transac.reply(transact_pid, 405, "Method not allowed", [], state.totag)
        {:noreply, state}

      {:out_of_order, state} ->
        SIP.Transac.reply(transact_pid, 500, "Out of order", [], state.totag)
        {:noreply, state}

      {:toomanytransactions, state} ->
        Logger.error(
          module: __MODULE__,
          dialogpid: self(),
          message: "Too many transactions open."
        )

        SIP.Transac.reply(transact_pid, 503, "Service Denied", nil, state.totag)
        {:noreply, state}

      {:nonewtrans, state} ->
        # ACK, CANCEL do not create new transactions
        # - rc returned by on_new_transaction
        {:noreply, state}
    end
  end

  defp add_totag(state, totag) do
    if is_nil(state.totag) and not is_nil(totag) do
      totag =
        if state.direction == :inbound do
          SIP.Msg.Ops.generate_from_or_to_tag()
        else
          if totag == nil, do: raise("Response does not contain totag")
          totag
        end

      # Case when the dialog has been created by an outbound request
      # Get the to tag from the first answer
      Registry.register(Registry.SIPDialog, {state.fromtag, state.callid, totag}, :completedialog)
      %SIP.DialogImpl{state | totag: totag}
    else
      state
    end
  end

  defp handle_UAS_response(state, rsp, _transact_pid)
       when state.state in [:initial, :uac_challenged] and rsp.response in 200..202 do
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Outbound dialog established"
    )

    # Learn the remote target (Contact) and route set (Record-Route) so that
    # subsequent in-dialog requests (BYE, re-INVITE…) can be routed correctly.
    %{
      state
      | state: :established,
        remotetarget: Map.get(rsp, :contact),
        routeset: Map.get(rsp, :recordroute)
    }
  end

  defp handle_UAS_response(state, rsp, _transact_pid)
       when state.state == :initial and rsp.response in 300..399 do
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Redirected to #{rsp.contact}"
    )

    %{state | state: :redirected}
  end

  # An auth challenge (401/407) on the initial request — or a *re-challenge*
  # while we are already authenticating — keeps the dialog open so the app can
  # (re)send the authenticated request. A second 401/407 is not a rejection:
  # it happens e.g. when an unauthenticated request is re-sent in parallel, and
  # must not tear the dialog down (otherwise the in-flight authenticated request
  # would lose its dialog).
  defp handle_UAS_response(state, rsp, _transact_pid)
       when state.state in [:initial, :uac_challenged] and rsp.response in [401, 407] do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "challenged initial request with #{rsp.response}"
    )

    %{state | state: :uac_challenged}
  end

  defp handle_UAS_response(state, rsp, _transact_pid)
       when state.state in [:initial, :uac_challenged] and rsp.response in 400..699 do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "initial request reject with code #{rsp.response}"
    )

    %{state | state: :terminated}
  end

  defp handle_UAS_response(state = %SIP.DialogImpl{}, rsp, transact_pid)
       when state.state == :established and rsp.response in 300..399 do
    if transact_pid == state.closing_transaction do
      # Closing transaction was redirected. Need to resend a new req.
      Logger.debug(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: "Closing request redirected to #{rsp.contact}"
      )

      %{state | state: :redirected, closing_transaction: nil}
    else
      %{state | state: :redirected}
    end
  end

  defp handle_UAS_response(state = %SIP.DialogImpl{}, rsp, transact_pid)
       when state.state == :established do
    if transact_pid == state.closing_transaction and rsp.response not in [401, 407] do
      # The closing transaction has been completed. Kill the dialog
      Logger.debug(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: "Final dialog transaction completed by final anwswer #{rsp.response}"
      )

      %{state | state: :terminated}
    else
      state
    end
  end

  defp handle_UAS_response(state, _rsp, _transact_pid) do
    state
  end

  # Handle option keepalive timers: send an OPTIONS message
  @impl true
  def handle_info({:timeout, _tref, :optionskeepalive}, state) do
    newstate = send_options_keepalive(state)
    {:noreply, newstate}
  end

  # Handle timer for checking expired nonces
  def handle_info(:check_expired_nonces, state) do
    {:noreply, check_expired_nonces(state)}
  end

  # Invoked when a dialog receives a SIP response from an UAC transaction
  def handle_info({:response, rsp, transact_pid}, state) when is_resp(rsp) do
    state =
      if transact_pid in state.transactions do
        {_rc, totag} = SIP.Uri.get_uri_param(rsp.to, "tag")

        send(state.app, {rsp.response, rsp, transact_pid, self()})

        # Only dialog-establishing responses set the dialog's remote tag:
        # provisional (1xx with a to-tag) for early dialogs and 2xx for confirmed
        # ones. Non-2xx final responses — notably 401/407 auth challenges — do not
        # create a dialog (RFC 3261 §12.1), so their To-tag must be ignored.
        # Otherwise the re-sent authenticated request would carry a bogus to-tag
        # and be rejected by the proxy as an orphan in-dialog request.
        state =
          if rsp.response < 300 do
            add_totag(state, totag)
          else
            state
          end

        if rsp.response >= 200 do
          new_state = handle_UAS_response(state, rsp, transact_pid)

          # Keep an INVITE client transaction alive after a 2xx so the application
          # can still ACK it (RFC 3261 §13.2.2.4); it is removed once the ACK is
          # sent. Every other final response terminates the transaction now.
          if rsp.response < 300 and match?([_, :INVITE], rsp.cseq) do
            new_state
          else
            close_transaction(new_state, transact_pid)
          end
        else
          # Provisional responses.
          state
        end
      else
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message:
            "SIP response #{rsp.response} from a transaction #{inspect(transact_pid)} " <>
              "that is not attached to the dialog."
        )

        state
      end

    if state.state in [:initial, :established, :redirected, :uac_challenged, :uas_challenged] do
      {:noreply, state}
    else
      Logger.info(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: "Terminating Dialog. Final state: #{state.state}"
      )

      {:stop, :normal, state}
    end
  end

  # ----------------------- handling expiration timer ------------------------------

  #
  def handle_info({:timeout, _timerRef, :unregister}, state = %SIP.DialogImpl{}) do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Terminating REGISTER Dialog"
    )

    {:stop, :normal, state}
  end

  def handle_info({:timeout, _timerRef, :registerexpire}, state = %SIP.DialogImpl{}) do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Terminating REGISTER Dialog because no refresh REGISTER recevied"
    )

    {:stop, :normal, state}
  end

  def handle_info({:timeout, _timerRef, :registerrefresh}, state = %SIP.DialogImpl{}) do
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Sending REFRESH register"
    )

    # TODO send refresher
    {:noreply, state}
  end

  # ----------------------- transaction timers ------------------------------
  def handle_info(
        {:transaction_timeout, _timer, transact_pid, req, module},
        state = %SIP.DialogImpl{}
      )
      when is_pid(transact_pid) do
    # Transaction expired -> remove it
    state = close_transaction(state, transact_pid)

    end_dialog =
      case req.method do
        # true if this is a client transaction
        :BYE ->
          module == SIP.ICT

        :REGISTER ->
          case SIP.Uri.get_uri_param(req.contact, "expires") do
            # true if this is a client transaction
            {:ok, "0"} -> module == SIP.ICT
            _ -> false
          end

        _ ->
          false
      end

    if end_dialog do
      {:stop, :normal, :state}
    else
      {:noreply, state}
    end
  end

  # TCP connection closed: stop any dialog that was using this connection.
  # Dialogs on other transports or other TCP peers silently ignore this.
  def handle_info({:tcp_client_closed, closed_ip, closed_port}, state = %SIP.DialogImpl{}) do
    ruri = state.msg.ruri
    if ruri.tp_module == SIP.Transport.TCP and
       ruri.destip == closed_ip and ruri.destport == closed_port do
      if is_pid(state.app), do: send(state.app, {:dialog_terminated, self(), :tcp_closed})
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  def handle_info({:tls_client_closed, closed_ip, closed_port}, state = %SIP.DialogImpl{}) do
    ruri = state.msg.ruri
    if ruri.tp_module == SIP.Transport.TLS and
       ruri.destip == closed_ip and ruri.destport == closed_port do
      if is_pid(state.app), do: send(state.app, {:dialog_terminated, self(), :tls_closed})
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end
end
