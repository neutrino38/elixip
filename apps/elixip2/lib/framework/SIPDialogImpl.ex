defmodule SIP.DialogImpl do
  @moduledoc """
  SIP module layer implementation. Do not use directy.
  Use the API provided by SIP.Dialog module
  """
  use GenServer
  require Logger
  require SIP.Uri
  import SIP.Msg.Ops
  alias SIP.DialogImpl.KeepAlive

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
    # PID of the INVITE server transaction that answered 2xx and is still waiting
    # for the ACK. RFC 3261 §17.2.3: the ACK of a 2xx matches no transaction (a
    # proxy re-branches it), so it reaches this layer — the TU — and nothing else.
    # Kept here so we can tell that IST to stop retransmitting the 2xx (§13.3.1.4).
    ist_awaiting_ack: nil,
    # PID of the application
    app: nil,
    # Event tag: when set (an atom), every message delivered to the app is
    # wrapped as {tag, msg} — see SIP.Dialog.start_dialog/5 and send_to_app/2.
    # nil (the default) delivers bare messages.
    tag: nil,
    # Forking (kamailio TM model, docs/design/b2bua_module.md §3.3): the initial
    # request may be sent to several targets as several client transactions of
    # THIS dialog — same Call-ID, From tag and CSeq, one fresh Via branch each.
    # `branches` maps each such transaction to the target it went to; `forking`
    # says the hunt is on, which is what keeps the dialog alive when a branch
    # comes back with a non-2xx final (there may be another target to try).
    branches: %{},
    forking: false,
    state: :initial,
    # If we should output debug logs for this dialog
    debuglog: true,
    expirationtimer: nil,
    dialogtimeout: 0,
    keepalivetimer: nil,
    # Who sends the OPTIONS keepalives on this dialog: :dialog (this layer, the
    # default) or :app (the application drives them and handles the responses).
    # Exactly one owner, decided before the first OPTIONS goes out — with both
    # running, two OPTIONS went out per period and the spare response poisoned the
    # application's mailbox (see SIP.Session.RegisterUAC.process_register_reply/3).
    keepalive_owner: :dialog,
    missedkeepalive: 0,
    cseq: 1,
    cseqin: 1,
    fromtag: nil,
    callid: nil,
    totag: nil,
    destip: nil,
    destport: 0
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
    # :NOTIFY — implicit subscription of a REFER (RFC 3515).
    # :OPTIONS — in-dialog keepalive.
    [:BYE, :UPDATE, :ACK, :MESSAGE, :INFO, :INVITE, :REFER, :NOTIFY, :OPTIONS]
  end

  # Outbound only: an OPTIONS *we* send out of dialog still gets a dialog to carry
  # its transaction (SIP.Session.RegisterUAC.send_options/2 relies on it). An
  # *inbound* out-of-dialog OPTIONS no longer creates one — it is answered straight
  # from SIP.Dialog.process_incoming_request/3, since OPTIONS is not dialog-forming
  # (RFC 3261 §12.1) and one process per liveness ping is a leak.
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
        |> address_in_dialog(state)
        |> add_route_set(state)
      else
        set_tag(newreq, :from, state.fromtag)
      end

    # Increment cseq for outbound and store modified request
    msg = if state.msg == nil, do: newreq, else: state.msg
    newstate = %SIP.DialogImpl{state | cseq: state.cseq + 1, msg: msg}
    {newstate, newreq}
  end

  @doc false
  # Address a request WE originate inside the dialog (RFC 3261 §12.2.1.1): local
  # identity in From with the local tag, remote identity in To with the remote
  # tag, sent to the remote target.
  #
  # Which side is "local" depends on who created the dialog. On an OUTBOUND
  # dialog we are the original From and `fromtag` is ours; on an INBOUND one we
  # are the original To and `totag` is ours — the roles swap wholesale. Getting
  # this wrong is not cosmetic: a BYE that names the callee in both From and To
  # matches no dialog at the far end. Public only as a test seam.
  def address_in_dialog(req, %SIP.DialogImpl{direction: :inbound, msg: msg} = state)
      when not is_nil(msg) do
    %{req | from: msg.to, to: msg.from, ruri: state.remotetarget || req.ruri}
    |> set_tag(:from, state.totag)
    |> set_tag(:to, state.fromtag)
  end

  def address_in_dialog(req, state) do
    # BOTH ends come from the dialog, exactly as in the inbound clause above.
    # Taking the From from the request as given was an asymmetry, not a
    # shorthand: RFC 3261 §12.2.1.1 fixes the From of an in-dialog request to the
    # dialog's local URI, so there is nothing for a caller to decide — and a
    # caller with no identity to offer (a UAS instance, a B2BUA leg: their
    # identity lives in the dialog, not in a context) passed the placeholder URI
    # that `SIP.Session.CallInDialog` builds. That From has no domain, serializes
    # to nothing, and takes the whole message down in SIPMsg.serialize_one_header/2.
    {from_uri, to_uri} =
      if state.msg, do: {state.msg.from, state.msg.to}, else: {req.from, req.to}

    %{req | from: from_uri, to: to_uri, ruri: state.remotetarget || req.ruri}
    |> set_tag(:from, state.fromtag)
    |> set_remote_totag(state)
  end

  @doc false
  # Add the dialog route set (RFC 3261 §12.2.1.1) to in-dialog requests. A single
  # Record-Route is stored as a binary; a proxy chain (several Record-Route
  # headers, e.g. kamailio + the WebRTC gateway) is stored as a list. Both must
  # be copied verbatim onto the request — same value the transaction puts on the
  # ACK — otherwise the request (BYE, re-INVITE…) bypasses the proxies and never
  # reaches the far end. Public only as a test seam.
  def add_route_set(req, %SIP.DialogImpl{routeset: rs}) when is_binary(rs) and rs != "" do
    Map.put(req, :route, rs)
  end

  def add_route_set(req, %SIP.DialogImpl{routeset: rs}) when is_list(rs) and rs != [] do
    Map.put(req, :route, rs)
  end

  def add_route_set(req, _state), do: req

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

  # One more branch of the initial request, toward `target`. Backs
  # `handle_call({:fork_branch, …})`; see SIP.Dialog.fork_branch/2 for the why.
  defp start_branch(state = %SIP.DialogImpl{}, target) do
    req = %{state.msg | ruri: target}

    case SIP.Transac.start_uac_transaction(req, state.dialogtimeout) do
      {:ok, trans_pid, _modmsg} ->
        newstate = %SIP.DialogImpl{
          state
          | forking: true,
            transactions: [trans_pid | state.transactions],
            branches: Map.put(state.branches, trans_pid, target)
        }

        {:reply, {:ok, trans_pid}, newstate}

      {code, _extra} ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Failed to start a fork branch toward #{target}: #{inspect(code)}"
        )

        {:reply, {:error, code}, state}

      err ->
        {:reply, {:error, err}, state}
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
      | expirationtimer: :erlang.start_timer(expire * 1000, self(), :inviterefresh)
    }
  end

  @doc """
  Arm the lifetime of a REGISTER dialog, in both directions: it lives as long as the
  registration it carries, and every REGISTER flowing through it re-arms the timer.
  When the lifetime lapses with no refresh, the dialog terminates
  (`:registerexpire`); an explicit expiry of 0 is an un-registration and tears it
  down right away (`:unregister`).

  Sending the refreshes is **not** this layer's job — the session layer arms
  `:register_refresh` at half the granted lifetime and the application re-sends
  (and re-authenticates) the REGISTER. This timer is the safety net behind it.

  The periodic OPTIONS keepalive (NAT / connection liveness) *is* this layer's,
  armed separately by `SIP.Dialog.start_options_keepalive/1`.
  """
  def arm_expiration_timer(state = %SIP.DialogImpl{}, req) when req.method == :REGISTER do
    requested = SIP.Msg.Ops.requested_expires(req)

    {expire, timeratom} =
      case requested do
        0 ->
          {1, :unregister}

        # Both directions arm the same thing: the dialog lives as long as the
        # registration it carries, and every REGISTER that flows through it (an
        # inbound refresh, or one we send out) re-arms it. When the lifetime lapses
        # with no refresh, the dialog terminates.
        #
        # Outbound used to arm a `:registerrefresh` timer at half the lifetime whose
        # handler was a `# TODO send refresher` no-op — a timer that fired, logged
        # "Sending REFRESH register" and did nothing. Sending the refresh is the
        # session layer's job (`process_register_reply/3` arms `:register_refresh` at
        # half the *granted* lifetime and hands it to the scenario, which
        # re-authenticates it — credentials live in %SIP.Context{}, not here). What
        # this layer owes is the safety net: expire if that refresh never comes. At
        # half the lifetime it would race the refresh it is meant to catch, so it
        # runs for the full lifetime — the moment the binding actually lapses.
        exp ->
          {exp, :registerexpire}
      end

    # Say which lifetime was read and from where. A registration that quietly
    # evaporates is otherwise indistinguishable from one the peer never asked to
    # keep, and the two have opposite fixes.
    # `charlists: :as_lists` or the per-contact list is unreadable: a single 60 s
    # binding inspects as ~c"<" (60 is the codepoint of "<"), which is precisely
    # what this log exists to make obvious.
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message:
        "REGISTER lifetime #{requested}s (per-contact: " <>
          "#{inspect(SIP.Msg.Ops.contact_lifetimes(req), charlists: :as_lists)}, " <>
          "Expires header: #{inspect(SIP.Msg.Ops.expires_header(req))}) " <>
          "-> #{timeratom} in #{expire}s"
    )

    state = cancel_expiration_timer(state)

    %SIP.DialogImpl{
      state
      | expirationtimer: :erlang.start_timer(expire * 1000, self(), timeratom)
    }
  end

  # Default, do nothing
  def arm_expiration_timer(state = %SIP.DialogImpl{}, _req) do
    state
  end

  # The lifetime a REGISTER asks for is read by SIP.Msg.Ops.requested_expires/2 —
  # the framework's single implementation of the RFC 3261 §10.2.4 precedence (see
  # CLAUDE.md, Message Layer). The dialog only decides what to do with it: follow
  # the longest-lived binding, and treat 0 as an un-registration.

  # A 3xx response may carry several Contact targets; make them loggable.
  defp contacts_to_string(contact) do
    contact |> List.wrap() |> Enum.map_join(", ", &to_string/1)
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

  # Deliver a message to the bound application process, wrapped in the dialog's
  # event tag when one was set at creation ({tag, msg} — how a B2BUA leg's
  # events are told apart, design docs/design/b2bua_module.md §2). Untagged
  # dialogs (the default) deliver the bare message: existing apps are untouched.
  defp send_to_app(state, msg) do
    if is_pid(state.app), do: send(state.app, wrap_tag(state.tag, msg))
    :ok
  end

  defp wrap_tag(nil, msg), do: msg
  defp wrap_tag(tag, msg) when is_atom(tag), do: {tag, msg}

  @impl true
  @spec init(
          {map(), :inbound | :outbound, pid(), integer(), boolean(), {any(), any(), any()},
           atom() | nil, boolean()}
        ) :: {:ok, map()} | {:stop, atom() | {any(), any()}}

  def init({req, :inbound, pid, timeout, debug, dialog_id, tag, _forking}) when is_req(req) do
    {fromtag, callid, totag} = dialog_id
    # Generate totag if needed
    totag = if is_nil(totag), do: generate_from_or_to_tag(), else: totag

    # The GenServer :via name only registered the id derived from the initial
    # request, which carries no To tag: {fromtag, callid, nil}. Also register
    # the complete dialog id so in-dialog requests bearing our totag (ACK of a
    # 2xx, BYE, re-INVITE…) can be matched back to this dialog (RFC 3261 §12).
    if is_nil(elem(dialog_id, 2)) do
      Registry.register(Registry.SIPDialog, {fromtag, callid, totag}, :completedialog)
    end

    state = %SIP.DialogImpl{
      msg: req,
      direction: :inbound,
      app: nil,
      tag: tag,
      dialogtimeout: timeout,
      debuglog: debug,
      transactions: [pid],
      fromtag: fromtag,
      callid: callid,
      totag: totag,
      # An outbound dialog learns these from the establishing RESPONSE
      # (handle_UAC_response). An inbound one has them in the request that
      # created it, and nothing else will ever supply them — without this, an
      # in-dialog request we originate (BYE at end of media, re-INVITE) has no
      # remote target to be routed to.
      remotetarget: Map.get(req, :contact),
      routeset: Map.get(req, :recordroute, []),
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
        send(app_id, wrap_tag(state.tag, {req.method, req, pid, self()}))
        {:ok, Map.put(state, :app, app_id)}

      # Session has not been created. Abort dialog and propagate the requested
      # SIP status. The stop reason is the 4-tuple {:reject, code, reason, totag}
      # — a VALID GenServer.init/1 stop return — which SIP.Dialog.start_dialog and
      # process_incoming_request map back to a SIP response on the server
      # transaction (registrar quota 503, UAS domain control 604, …). The totag
      # (generated above) is embedded because a reply with code > 100 needs one.
      {:reject, code, reason} ->
        Logger.info(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "App rejected the request with #{code} #{reason}. Aborting dialog creation."
        )

        {:stop, {:reject, code, reason, state.totag}}
    end
  end

  # Dialog started by an outbound request
  def init({req, :outbound, pid, timeout, debug, dialog_id, tag, forking}) when is_req(req) do
    {fromtag, callid, _totag} = dialog_id

    state = %SIP.DialogImpl{
      msg: req,
      direction: :outbound,
      app: pid,
      tag: tag,
      # Declared up front: the first branch goes out with the dialog, so its
      # failure must not tear the dialog down when more targets are waiting.
      forking: forking,
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
          send_to_app(state, {:onnewdialog, :ok, transaction_pid})

          branches =
            if forking, do: %{transaction_pid => modmsg.ruri}, else: state.branches

          %SIP.DialogImpl{
            state
            | transactions: [transaction_pid],
              msg: modmsg,
              branches: branches
          }
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

  @impl true
  @doc """
  Invoked when the dialog GenServer stops (end of call: BYE in either direction,
  timeout, or failure). Notifies the bound application process so it can release
  resources tied to the call lifetime (e.g. media). The dialog pid passed in the
  message is `self()` here, i.e. the same pid the app knows as its dialog.
  """
  def terminate(reason, state) do
    # Unwrap {:shutdown, r} (used e.g. for a clean CANCEL teardown) so the app
    # sees the bare reason it expects, preserving the {:dialog_terminated, _, r}
    # contract. Bare-atom reasons (:normal, :tcp_closed, …) pass through.
    reason =
      case reason do
        {:shutdown, r} -> r
        r -> r
      end

    send_to_app(state, {:dialog_terminated, self(), reason})

    :ok
  end

  defp close_transaction(state, uas_t) do
    # A transaction that is gone can no longer be told about the ACK (it dies on
    # timer H). Clearing the field here means the 2xx path must record the IST
    # *after* calling this, which is what it does.
    ist = if state.ist_awaiting_ack == uas_t, do: nil, else: state.ist_awaiting_ack

    %SIP.DialogImpl{
      state
      | transactions: List.delete(state.transactions, uas_t),
        ist_awaiting_ack: ist
    }
  end

  # Remember the INVITE server transaction that just answered 2xx: only the ACK
  # stops its retransmissions, and the ACK is delivered here, not to it.
  defp await_ack(state, req, resp_code, uas_t)
       when req.method == :INVITE and resp_code in 200..299 and is_pid(uas_t) do
    %SIP.DialogImpl{state | ist_awaiting_ack: uas_t}
  end

  defp await_ack(state, _req, _resp_code, _uas_t), do: state

  # Counterpart of await_ack/4: the ACK arrived, so release the IST. Cast once —
  # the transaction ignores the ACK retransmissions that follow, and it may
  # already have died on timer H.
  defp confirm_ist(state, ack) do
    if is_pid(state.ist_awaiting_ack) do
      SIP.Transac.confirm_uas_transaction(state.ist_awaiting_ack, ack)
      %SIP.DialogImpl{state | ist_awaiting_ack: nil}
    else
      state
    end
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

  # Digest algorithm advertised by the short-path challenge below.
  #
  # MD5, for the same reason kelixip settled on it (`Kelix.Auth`): the algorithm
  # must be one the *verifier* can reproduce, and a UAC holds a single HA1 computed
  # once from its `ctx.algorithm` (default MD5) — the clear password is not kept, so
  # it cannot re-derive an HA1 for another algorithm. Challenging SHA256 here made
  # every elixip UAC answer with an MD5 HA1 hashed as SHA256, i.e. a digest that can
  # only ever be wrong (a plain 403, with nothing in the logs pointing at the
  # algorithm). It is also the broadest client support.
  @default_challenge_algorithm "MD5"

  # Reply to an in_dialog request with a 401/407 challenge.
  #
  # Short path — the 5th arg is a **binary realm**: the framework builds the digest
  # challenge itself, minting a stateless `SIP.Auth.Nonce` for that realm. Nothing
  # is stored: the application validates the nonce it gets back with
  # `SIP.Auth.Nonce.validate/3` (see `scenarios/uas_register.exs`). Pass
  # `{realm, algorithm}` to advertise something else than the default above
  # (`challenge_registration(…, algorithm: …)`).
  #
  # A 401/407 whose 5th arg is a keyword list (e.g. `[wwwauthenticate: params]`)
  # falls through to the generic clause below, which sends the response with the
  # caller-built header verbatim. kelixip uses that one to add `qop=auth` /
  # `stale` (design §7.3) via `Kelix.Auth`.
  def handle_call({:replyreq, req, resp_code, reason, realm}, from, state)
      when resp_code in [401, 407] and is_binary(realm) do
    handle_call(
      {:replyreq, req, resp_code, reason, {realm, @default_challenge_algorithm}},
      from,
      state
    )
  end

  def handle_call({:replyreq, req, resp_code, reason, {realm, algorithm}}, _from, state)
      when resp_code in [401, 407] and is_binary(realm) and is_binary(algorithm) do
    auth = %{realm: realm, algorithm: algorithm, authproc: "Digest"}

    {ret, uas_t} =
      SIP.Transac.reply_req(req, resp_code, reason, auth, state.totag, state.transactions)

    # reply_req/6 answers {:ok, nonce} on the challenge path; the nonce needs no
    # bookkeeping now, so normalize it to the usual :ok.
    ret = if match?({:ok, _nonce}, ret), do: :ok, else: ret
    {:reply, ret, add_totag(state, nil) |> close_transaction(uas_t)}
  end

  def handle_call({:replyreq, req, resp_code, reason, upd_field}, _from, state) do
    {ret, uas_t} =
      SIP.Transac.reply_req(req, resp_code, reason, upd_field, state.totag, state.transactions)

    state =
      case resp_code do
        100 ->
          state

        rc when rc in 101..199 ->
          add_totag(state, nil)

        rc when rc in 200..699 ->
          # await_ack/4 after close_transaction/2: the latter clears the field.
          add_totag(state, nil)
          |> close_transaction(uas_t)
          |> await_ack(req, resp_code, uas_t)

        _ ->
          raise "Unsupported response code #{resp_code}"
      end

    {:reply, ret, state}
  end

  # Send the dialog's INITIAL request to one more target, as another branch of
  # this dialog (RFC 3261 §16.6 / kamailio TM). The dialog-forming fields are
  # shared verbatim — Call-ID, From tag and CSeq all come from `state.msg`, which
  # `fix_outbound_request/3` already fixed — and only the Request-URI differs;
  # the fresh Via branch comes free, since a client transaction mints its own.
  #
  # Deliberately NOT subject to the four-transaction cap of
  # `send_in_dialog_request/2`: that cap bounds in-dialog traffic, while these are
  # attempts at the *same* request, and a hunt down a long contact list is exactly
  # what it must not truncate.
  def handle_call({:fork_branch, target}, _from, state) do
    cond do
      state.direction != :outbound ->
        {:reply, {:error, :not_outbound}, state}

      # A dialog exists once a branch answered 2xx; there is nothing left to hunt.
      state.state not in [:initial, :uac_challenged] ->
        {:reply, {:error, :already_established}, state}

      is_nil(state.msg) ->
        {:reply, {:error, :no_initial_request}, state}

      true ->
        start_branch(state, target)
    end
  end

  @doc "Handle call to send out a new in-dialog request"
  def handle_call({:newreq, req}, _from, state) when is_req(req) do
    # An app-initiated OPTIONS supersedes the automatic dialog keepalive: disarm it
    # so both don't run in parallel and so the OPTIONS responses flow back up to the
    # app (see KeepAlive.response?/2 gating in the {:response, ...} path). The
    # ownership is recorded, so a later start_options_keepalive/1 declines instead of
    # quietly re-arming a second sender.
    state =
      if req.method == :OPTIONS do
        %SIP.DialogImpl{KeepAlive.cancel(state) | keepalive_owner: :app}
      else
        state
      end

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
      Logger.warning(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message:
          "Cannot ACK transaction #{inspect(transact_pid)}: not attached to the dialog " <>
            "(already terminated?). ACK not sent."
      )

      {:reply, :nosuchtransaction, state}
    end
  end

  # The application announces that *it* drives the OPTIONS keepalive: stand down.
  # Called before any OPTIONS is sent, so the two mechanisms never overlap — even
  # for one period, which was enough to leave a stray response behind.
  def handle_call(:app_drives_keepalive, _from, state) do
    {:reply, :ok, %SIP.DialogImpl{KeepAlive.cancel(state) | keepalive_owner: :app}}
  end

  # Handle call to start options keepalive
  def handle_call(:option_keepalive, _from, state) do
    cond do
      state.keepalive_owner == :app ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message:
            "OPTIONS keepalive already driven by the application on this dialog: " <>
              "not arming the dialog one (they are exclusive)."
        )

        {:reply, {:error, :app_driven}, state}

      state.msg.method == :REGISTER ->
        {:reply, :ok, KeepAlive.arm(state)}

      true ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Cannot start OPTIONS keepalive on an #{state.msg.method} dialog"
        )

        {:reply, :baddialogtype, state}
    end
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
    send_to_app(state, {msg.method, msg, transact_pid, self()})

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

  # ACK to a 2xx: it carries no transaction (RFC 3261 §17.2.3) and reuses the
  # INVITE CSeq, so it must bypass the generic in-dialog pipeline (on_new_transaction
  # would drop it and check_seqno would reject it). Forward it as an app event;
  # its body may carry a delayed SDP offer. Nothing to reply to an ACK (pid nil).
  #
  # It is also the *only* place the INVITE server transaction can learn that its
  # 2xx got through: the ACK of a 2xx carries a fresh top Via branch (a proxy
  # re-branches it — it is a transaction of its own, §17.1.1.3), so it never
  # matches the IST in Registry.SIP.Transac and is dispatched straight here. Left
  # unaware, the IST retransmitted the 200 OK every T1..T2 until timer H fired 32 s
  # later — on a call that was up and talking. Hand it the ACK so it terminates.
  @impl true
  def handle_cast({:sipmsg, msg, _transact_pid}, state) when is_req(msg) and msg.method == :ACK do
    state = confirm_ist(state, msg)
    send_to_app(state, {:ACK, msg, nil, self()})
    {:noreply, state}
  end

  # CANCEL: the IST has already replied 200 (CANCEL) + 487 (INVITE) and then
  # notified us. Surface the CANCEL to the app and tear the early dialog down;
  # terminate/2 will follow with {:dialog_terminated, _, :cancelled}. The
  # {:shutdown, _} reason avoids a spurious GenServer crash report.
  # NB: this also fires if an outbound (UAC) dialog receives a CANCEL — a rare
  # case where tearing down on {:shutdown, :cancelled} is equally acceptable.
  def handle_cast({:sipmsg, msg, transact_pid}, state)
      when is_req(msg) and msg.method == :CANCEL do
    send_to_app(state, {:CANCEL, msg, transact_pid, self()})
    {:stop, {:shutdown, :cancelled}, state}
  end

  # An in-dialog OPTIONS is a keepalive (RFC 3261 §11): the dialog answers it
  # itself with a 200 OK instead of forwarding it to the app. This keeps
  # registrar / call scenarios free of keepalive plumbing — they no longer need
  # to intercept {:OPTIONS, …} just to bounce back a 200 OK. The request still
  # runs through the transaction / allow / sequence-number checks so a stale
  # retransmit or an out-of-order OPTIONS is rejected like any other in-dialog
  # request.
  def handle_cast({:sipmsg, msg, transact_pid}, state)
      when is_req(msg) and msg.method == :OPTIONS do
    with {:ok, state} <- on_new_transaction(state, msg, transact_pid),
         {:ok, state} <- check_allows(state, msg),
         {:ok, state} <- check_seqno(state, msg) do
      {_ret, uas_t} = SIP.Transac.reply_req(msg, 200, "OK", [], state.totag, state.transactions)
      {:noreply, add_totag(state, nil) |> close_transaction(uas_t)}
    else
      {:notallowed, state} ->
        SIP.Transac.reply(transact_pid, 405, "Method not allowed", [], state.totag)
        {:noreply, state}

      {:out_of_order, state} ->
        SIP.Transac.reply(transact_pid, 500, "Out of order", [], state.totag)
        {:noreply, state}

      {:toomanytransactions, state} ->
        SIP.Transac.reply(transact_pid, 503, "Service Denied", nil, state.totag)
        {:noreply, state}
    end
  end

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

  defp adopts_totag?(%SIP.DialogImpl{forking: true}, rsp), do: rsp.response in 200..299
  defp adopts_totag?(_state, rsp), do: rsp.response < 300

  # A branch answered 2xx: it IS the dialog now. Cancel whatever else is still
  # ringing (RFC 3261 §16.7 / kamailio t_cancel_branches) and pin the winner's
  # target onto the initial request — `send_in_dialog_request/2` reads the
  # transport parameters off `state.msg.ruri`, so a BYE would otherwise be sent
  # to the first target tried rather than the one that answered.
  #
  # A no-op on an unforked dialog, where `branches` is empty.
  defp adopt_winning_branch(%SIP.DialogImpl{branches: b} = state, _winner) when map_size(b) == 0,
    do: state

  defp adopt_winning_branch(state, winner) do
    losers = state.branches |> Map.keys() |> List.delete(winner)

    Enum.each(losers, fn pid ->
      Logger.debug(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: "Cancelling losing fork branch #{inspect(pid)}"
      )

      SIP.Transac.cancel_uac_transaction(pid)
    end)

    msg =
      case Map.get(state.branches, winner) do
        %SIP.Uri{} = target -> %{state.msg | ruri: target}
        _ -> state.msg
      end

    %SIP.DialogImpl{state | forking: false, branches: %{}, msg: msg}
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

  defp handle_UAS_response(state, rsp, transact_pid)
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
    |> adopt_winning_branch(transact_pid)
  end

  defp handle_UAS_response(state, rsp, _transact_pid)
       when state.state == :initial and rsp.response in 300..399 do
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Redirected to #{contacts_to_string(rsp.contact)}"
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

  # A branch of a hunt came back with a non-2xx final. That ends the BRANCH, not
  # the dialog: there may be another target to try, and the application decides
  # (it owns the target list and the retry policy — design §3.1). Terminating
  # here would take the dialog down before the application, which only learns of
  # the failure from the message we just sent it, could ask for the next branch.
  #
  # The application ends the hunt by closing the leg — its teardown does
  # (SIP.Session.B2bua.release_legs/1) — or wins it with a 2xx.
  defp handle_UAS_response(state = %SIP.DialogImpl{forking: true}, rsp, transact_pid)
       when state.state in [:initial, :uac_challenged] and rsp.response in 300..699 do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "fork branch rejected with #{rsp.response}; dialog kept for the next target"
    )

    %SIP.DialogImpl{state | branches: Map.delete(state.branches, transact_pid)}
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
        message: "Closing request redirected to #{contacts_to_string(rsp.contact)}"
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

  # Handle option keepalive timers: send an OPTIONS message or tear the dialog
  # down when the peer stopped answering (see SIP.DialogImpl.KeepAlive).
  @impl true
  def handle_info({:timeout, _tref, :optionskeepalive}, state) do
    KeepAlive.on_timeout(state)
  end

  # Invoked when a dialog receives a SIP response from an UAC transaction
  def handle_info({:response, rsp, transact_pid}, state) when is_resp(rsp) do
    state =
      if transact_pid in state.transactions do
        {_rc, totag} = SIP.Uri.get_uri_param(rsp.to, "tag")

        # A response to our own OPTIONS keepalive is dialog-internal: the peer
        # is alive, so reset the missed-keepalive counter and do NOT surface the
        # response to the app. Any other response is forwarded as usual. In both
        # cases the transaction is still cleaned up below.
        state =
          if KeepAlive.response?(state, rsp) do
            %SIP.DialogImpl{state | missedkeepalive: 0}
          else
            send_to_app(state, {rsp.response, rsp, transact_pid, self()})
            state
          end

        # Only dialog-establishing responses set the dialog's remote tag:
        # provisional (1xx with a to-tag) for early dialogs and 2xx for confirmed
        # ones. Non-2xx final responses — notably 401/407 auth challenges — do not
        # create a dialog (RFC 3261 §12.1), so their To-tag must be ignored.
        # Otherwise the re-sent authenticated request would carry a bogus to-tag
        # and be rejected by the proxy as an orphan in-dialog request.
        # Which response is allowed to give the dialog its remote tag.
        #
        # Unforked: provisional (a 1xx with a tag — an early dialog) or 2xx, as
        # before. A non-2xx final creates no dialog (RFC 3261 §12.1), so its tag
        # must be ignored — otherwise a re-sent authenticated request carries a
        # bogus to-tag and the proxy rejects it as an orphan.
        #
        # Forked: only a 2xx. Every branch answers with a to-tag of its own, and
        # the single slot latches the FIRST one it is offered — so a 180 from a
        # branch that goes on to fail would take the tag the winning 2xx needs,
        # and every later in-dialog request would name a callee that never
        # answered.
        state =
          if adopts_totag?(state, rsp) do
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
          # An un-REGISTER we sent ourselves ends the dialog once its transaction
          # completes. Read through SIP.Msg.Ops so the header counts: this test used
          # to look at the Contact `expires` parameter alone, so our own
          # `Expires: 0` un-REGISTER (no parameter — the shape every real UA sends)
          # read as "not an un-registration" and left the dialog behind.
          SIP.Msg.Ops.unregister?(req) and module == SIP.ICT

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
      send_to_app(state, {:dialog_terminated, self(), :tcp_closed})
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  def handle_info({:tls_client_closed, closed_ip, closed_port}, state = %SIP.DialogImpl{}) do
    ruri = state.msg.ruri

    if ruri.tp_module == SIP.Transport.TLS and
         ruri.destip == closed_ip and ruri.destport == closed_port do
      send_to_app(state, {:dialog_terminated, self(), :tls_closed})
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  def handle_info({:wss_client_closed, closed_ip, closed_port}, state = %SIP.DialogImpl{}) do
    ruri = state.msg.ruri

    if ruri.tp_module == SIP.Transport.WSS and
         ruri.destip == closed_ip and ruri.destport == closed_port do
      send_to_app(state, {:dialog_terminated, self(), :wss_closed})
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end
end
