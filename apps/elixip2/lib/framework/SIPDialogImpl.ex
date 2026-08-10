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
    # The transactions this dialog owns: `pid => %{req: request, module: module}`.
    #
    # A bare pid list was enough while a transaction only ever ended by saying so.
    # It no longer is: a transaction that CRASHES says nothing, and to hand the
    # application the synthetic 408 it is owed (design §14.4, R1) the dialog must
    # be able to name the request that died with it — `timeout_response/1` reads
    # the Call-ID, CSeq and both identities off it — and to tell a client
    # transaction from a server one, since only the former's failure is the
    # application's business.
    transactions: %{},
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
    # The branches we CANCELled: the losers of a fork that has already produced
    # its answer, and whatever was still ringing when a 6xx ended the hunt. What
    # comes back from them is ours to clean up — a 487, or a 2xx that crossed our
    # CANCEL (RFC 3261 §16.7) — and never the application's business.
    fork_losers: MapSet.new(),
    # The best final response withheld while other branches of the same rung were
    # still pending (§16.7 aggregation). `nil` while nothing has been withheld,
    # which is the serial case: one live branch, its final surfaced as it arrives.
    fork_best: nil,
    # Transactions this dialog runs for ITSELF — the BYE that buries a late 2xx.
    # Their responses are dialog-internal and never surface either.
    internal_trans: MapSet.new(),
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

  defp on_new_transaction(state, req, transact_id) do
    if map_size(state.transactions) < 4 do
      {:ok, add_transaction(state, transact_id, req, uas_module(req))}
    else
      {:toomanytransactions, state}
    end
  end

  # Remember a transaction and what it carries. `nil` is tolerated so the callers
  # that may not have a transaction (a reply on a request the transport routed
  # here directly) need no guard of their own.
  defp add_transaction(state, nil, _req, _module), do: state

  defp add_transaction(state, trans_pid, req, module) when is_pid(trans_pid) do
    %SIP.DialogImpl{
      state
      | transactions: Map.put(state.transactions, trans_pid, %{req: req, module: module})
    }
  end

  # Which state machine runs a transaction, derived from the method and the side
  # we are on. Both are known at the point every transaction is recorded, and
  # keeping them out of the state is what lets `client_transaction?/1` stay a
  # single test rather than a role flag to keep in sync.
  defp uac_module(req), do: if(req.method == :INVITE, do: SIP.ICT, else: SIP.NICT)
  defp uas_module(req), do: if(req.method == :INVITE, do: SIP.IST, else: SIP.NIST)

  defp client_transaction?(module), do: module in [SIP.ICT, SIP.NICT]

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
      if map_size(state.transactions) < 4 do
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

          # A bare atom — no transport could be found or started for this request
          # (`:no_transport_available`). It matched neither clause below, so it
          # raised a CaseClause inside the dialog, which R3 makes reachable far
          # more often: every in-dialog request sent over a transport that has
          # since died lands here first.
          code when is_atom(code) ->
            Logger.warning(
              dialogpid: "#{inspect(self())}",
              module: __MODULE__,
              message: "Cannot send #{req.method}: #{code}"
            )

            {code, state}

          {:ok, transaction_pid, modmsg} ->
            # Add the transaction in the transaction list
            newstate = add_transaction(state, transaction_pid, modmsg, uac_module(modmsg))

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

  # The rest of a PARALLEL rung (`fork: [uri, …]`), armed from inside init/1.
  #
  # It cannot be left to the application: between the dialog starting and the
  # application's `fork_branch/2` call, the first branch's own response may
  # already have arrived and been surfaced — a rung whose siblings do not exist
  # yet is a rung whose first failure looks final. init/1 runs before any message
  # is handled, so arming here is the only placement that closes that window.
  #
  # Each branch is announced, since the application correlates on transaction pids.
  defp arm_initial_rung(state, targets) when is_list(targets) do
    Enum.reduce(targets, state, fn target, st ->
      case arm_branch(st, target) do
        {{:ok, trans_pid}, st} ->
          send_to_app(st, {:onnewbranch, :ok, trans_pid})
          st

        {{:error, reason}, st} ->
          send_to_app(st, {:onnewbranch, :error, reason})
          st
      end
    end)
  end

  defp arm_initial_rung(state, _forking), do: state

  # One more branch of the initial request, toward `target`. Backs
  # `handle_call({:fork_branch, …})`; see SIP.Dialog.fork_branch/2 for the why.
  #
  # `fork_best` is cleared here: arming a branch opens a new rung, and the finals
  # withheld while the previous one was running have been surfaced already (the
  # rung ended, which is what let the application ask for this one).
  defp arm_branch(state = %SIP.DialogImpl{}, target) do
    req = %{state.msg | ruri: target}

    case SIP.Transac.start_uac_transaction(req, state.dialogtimeout) do
      {:ok, trans_pid, modmsg} ->
        newstate =
          %SIP.DialogImpl{
            state
            | forking: true,
              fork_best: nil,
              branches: Map.put(state.branches, trans_pid, target)
          }
          |> add_transaction(trans_pid, modmsg, uac_module(modmsg))

        {{:ok, trans_pid}, newstate}

      {code, _extra} ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Failed to start a fork branch toward #{target}: #{inspect(code)}"
        )

        {{:error, code}, state}

      err ->
        {{:error, err}, state}
    end
  end

  # A branch set asked with a REPLACEMENT BODY (the offer-profile fallback of
  # b2bua_module.md §7.5): re-stamp the stored initial request, which is the
  # template `arm_branch/2` composes every branch from, and move the CSeq on.
  #
  # The CSeq is what makes this more than a body swap. Branches share a CSeq
  # because they are one request asked of several places; two different bodies
  # under one CSeq are two different requests, and the second is a merged request
  # under RFC 3261 §8.2.2.2 — answered 482 Loop Detected by any UAS whose server
  # transaction is still alive, which after a just-ACKed refusal it is (timer I).
  #
  # `state.msg` is also what the BYE and the transport-failure paths read, so
  # re-stamping it — rather than passing a body down to arm_branch/2 — is what
  # keeps the dialog's idea of its own request true.
  defp restamp_initial_request(state, opts) do
    case Keyword.get(opts, :body) do
      nil ->
        state

      body ->
        [_seqno, method] = state.msg.cseq

        msg =
          state.msg
          |> Map.put(:cseq, [state.cseq, method])
          |> SIP.Msg.Ops.update_sip_msg({:body, normalize_body(body)})

        %SIP.DialogImpl{state | msg: msg, cseq: state.cseq + 1}
    end
  end

  # A replacement body is given as an SDP string (the ordinary case) or as the
  # body list the message layer stores.
  defp normalize_body(sdp) when is_binary(sdp),
    do: [%{contenttype: "application/sdp", data: sdp}]

  defp normalize_body(body) when is_list(body), do: body

  defp arm_rung(state, target) do
    cond do
      is_list(target) ->
        {results, state} = Enum.map_reduce(target, state, fn t, st -> arm_branch(st, t) end)

        case Enum.split_with(results, &match?({:ok, _}, &1)) do
          {[], [{:error, reason} | _]} -> {:reply, {:error, reason}, state}
          {armed, _failed} -> {:reply, {:ok, Enum.map(armed, fn {:ok, pid} -> pid end)}, state}
        end

      true ->
        {ret, state} = arm_branch(state, target)
        {:reply, ret, state}
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

  # Client transactions are `start_link`ed from this process. Until this flag was
  # set, one of them crashing killed the dialog by exit signal — which does NOT
  # run `terminate/2`, so the application was never sent the
  # `{:dialog_terminated, …}` its whole cleanup hangs off, and a B2BUA leg simply
  # went quiet (design §14.2, path (a)).
  #
  # Trapping turns that signal into a message `handle_info({:EXIT, …})` acts on,
  # and — the reason it is the first decision of §14.4 — makes `terminate/2` run
  # on EVERY exit path, which is what promotes the dialog-terminated contract from
  # a convention to an invariant.
  defp trap_transaction_exits, do: Process.flag(:trap_exit, true)

  @impl true
  @spec init(
          {map(), :inbound | :outbound, pid(), integer(), boolean(), {any(), any(), any()},
           atom() | nil, boolean()}
        ) :: {:ok, map()} | {:stop, atom() | {any(), any()}}

  def init({req, :inbound, pid, timeout, debug, dialog_id, tag, _forking}) when is_req(req) do
    trap_transaction_exits()
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
      transactions: %{},
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

    # `pid` is the server transaction that created this dialog — recorded like
    # every other one, with the request it carries.
    state = add_transaction(state, pid, req, uas_module(req))

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
    trap_transaction_exits()
    {fromtag, callid, _totag} = dialog_id

    state = %SIP.DialogImpl{
      msg: req,
      direction: :outbound,
      app: pid,
      tag: tag,
      # Declared up front: the first branch goes out with the dialog, so its
      # failure must not tear the dialog down when more targets are waiting.
      forking: forking != false,
      dialogtimeout: timeout,
      debuglog: debug,
      transactions: %{},
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
            if forking != false, do: %{transaction_pid => modmsg.ruri}, else: state.branches

          %SIP.DialogImpl{state | msg: modmsg, branches: branches}
          |> add_transaction(transaction_pid, modmsg, uac_module(modmsg))
          |> arm_expiration_timer(modmsg)
          |> arm_initial_rung(forking)
          # This returns { :ok, newstate } as expected by init()
          |> check_closing_transaction(modmsg, transaction_pid)

        {code, _extra} ->
          Logger.error(
            module: __MODULE__,
            dialogpid: self(),
            message: "Failed to create client transaction, err: #{code}."
          )

          # `{:stop, reason}` — the 2-tuple init/1 actually accepts. The 3-tuple
          # that stood here is not a valid init return, so GenServer answered the
          # caller {:error, {:bad_return_value, …}} and the real error code, the
          # one worth reporting, never reached it.
          {:stop, code}

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

    stop_client_transactions(state)
    send_to_app(state, {:dialog_terminated, self(), reason})

    :ok
  end

  # Take the dialog's client transactions down with it.
  #
  # They are linked to us, but a dialog stopping `:normal` propagates a signal
  # they ignore — so an ICT whose dialog just died kept retransmitting its INVITE
  # every T1..T2 until timer B, on the wire, for a call nobody was following any
  # more (design §14.2, defect c-4).
  #
  # SERVER transactions are deliberately left alone: an IST that answered 2xx is
  # still retransmitting it until the ACK comes back, and that ACK is the last
  # thing the far end owes us — killing it would strand a call that did connect.
  defp stop_client_transactions(state) do
    for {pid, %{module: module}} <- transactions_of(state),
        client_transaction?(module) and Process.alive?(pid) do
      Process.exit(pid, :shutdown)
    end

    :ok
  end

  # `terminate/2` may be handed a state that never became one (an init that
  # stopped early), so read the field defensively — this is the one path that
  # must not raise.
  defp transactions_of(%SIP.DialogImpl{transactions: t}) when is_map(t), do: t
  defp transactions_of(_state), do: %{}

  defp close_transaction(state, uas_t) do
    # A transaction that is gone can no longer be told about the ACK (it dies on
    # timer H). Clearing the field here means the 2xx path must record the IST
    # *after* calling this, which is what it does.
    ist = if state.ist_awaiting_ack == uas_t, do: nil, else: state.ist_awaiting_ack

    %SIP.DialogImpl{
      state
      | transactions: Map.delete(state.transactions, uas_t),
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
      SIP.Transac.reply_req(
        req,
        resp_code,
        reason,
        auth,
        state.totag,
        Map.keys(state.transactions)
      )

    # reply_req/6 answers {:ok, nonce} on the challenge path; the nonce needs no
    # bookkeeping now, so normalize it to the usual :ok.
    ret = if match?({:ok, _nonce}, ret), do: :ok, else: ret
    {:reply, ret, add_totag(state, nil) |> close_transaction(uas_t)}
  end

  def handle_call({:replyreq, req, resp_code, reason, upd_field}, _from, state) do
    {ret, uas_t} =
      SIP.Transac.reply_req(
        req,
        resp_code,
        reason,
        upd_field,
        state.totag,
        Map.keys(state.transactions)
      )

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
  # A LIST of targets arms them all in one call, and that atomicity is the point:
  # a parallel rung armed one target at a time races its own first branch. A 404
  # arriving between two arms finds an empty branch table, reads as "the last
  # branch died", and is relayed to the caller while two more phones are about to
  # ring. Inside one handle_call nothing can interleave.
  def handle_call({:fork_branch, target, opts}, _from, state) do
    cond do
      state.direction != :outbound ->
        {:reply, {:error, :not_outbound}, state}

      # A dialog exists once a branch answered 2xx; there is nothing left to hunt.
      state.state not in [:initial, :uac_challenged] ->
        {:reply, {:error, :already_established}, state}

      is_nil(state.msg) ->
        {:reply, {:error, :no_initial_request}, state}

      true ->
        arm_rung(restamp_initial_request(state, opts), target)
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
    if Map.has_key?(state.transactions, transact_pid) do
      reply = SIP.Transac.cancel_uac_transaction(transact_pid)
      {:reply, reply, state}
    else
      {:reply, :nosuchtransaction, state}
    end
  end

  # Handle call to send out an ACK for an INVITE request
  def handle_call({:ack, transact_pid}, _from, state) do
    if Map.has_key?(state.transactions, transact_pid) do
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
      {_ret, uas_t} =
        SIP.Transac.reply_req(msg, 200, "OK", [], state.totag, Map.keys(state.transactions))

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

  # Only a CLIENT transaction is reported: a server transaction timing out means
  # the application never answered, which it hardly needs telling. The keepalive
  # OPTIONS we send ourselves stay dialog-internal too — an unanswered one is
  # counted by SIP.DialogImpl.KeepAlive, which tears the dialog down after
  # several, and surfacing it here would put a 408 in the application's mailbox
  # for a request it never sent.
  # Through the same door as a response off the wire — which is what makes a
  # branch dying on timer B an ordinary branch failure: withheld while its
  # siblings are still ringing, aggregated with them, absorbed if it belongs to a
  # branch we had already cancelled.
  defp notify_transaction_timeout(state, req, transact_pid, module)
       when module in [SIP.ICT, SIP.NICT] do
    deliver_response(state, timeout_response(req), transact_pid)
  end

  defp notify_transaction_timeout(state, _req, _transact_pid, _module), do: state

  # A 408 the stack makes up for a request that was never answered. It is a local
  # notification and never goes on the wire, so it carries only what a reader of
  # a response needs: the status, and the dialog/CSeq coordinates that say WHICH
  # request went unanswered (`SIP.Session.dispatch_reply/3` routes on the CSeq
  # method, and the B2BUA correlates on the transaction pid delivered alongside).
  defp timeout_response(req) do
    %{
      method: false,
      response: 408,
      reason: "Request Timeout",
      callid: Map.get(req, :callid),
      cseq: Map.get(req, :cseq),
      from: Map.get(req, :from),
      to: Map.get(req, :to),
      contentlength: 0,
      body: []
    }
  end

  defp adopts_totag?(%SIP.DialogImpl{forking: true}, rsp), do: rsp.response in 200..299
  defp adopts_totag?(_state, rsp), do: rsp.response < 300

  # ── Fork responses: what the application sees (design §3.3, RFC 3261 §16.7) ──

  # The single door responses leave by. Forking decides WHAT the application is
  # owed — a branch's own final, the whole rung's best, or nothing at all — and
  # the keepalive filter decides whether it is told anything.
  defp deliver_response(state, rsp, tid) do
    {state, delivery} = fork_delivery(state, rsp, tid)

    case delivery do
      :withhold ->
        state

      {:send, out} ->
        if KeepAlive.response?(state, rsp) do
          # A response to our own OPTIONS keepalive is dialog-internal: the peer
          # is alive, so reset the missed-keepalive counter and say nothing.
          %SIP.DialogImpl{state | missedkeepalive: 0}
        else
          send_to_app(state, {out.response, out, tid, self()})
          state
        end
    end
  end

  # An unforked dialog has no branches and falls straight through to {:send, rsp},
  # which is what it has always done.
  defp fork_delivery(state, rsp, tid) do
    cond do
      # Our own BYE burying a late 2xx: what it answers is nobody's business.
      MapSet.member?(state.internal_trans, tid) ->
        {state, :withhold}

      MapSet.member?(state.fork_losers, tid) ->
        late_branch_response(state, rsp, tid)

      not Map.has_key?(state.branches, tid) ->
        {state, {:send, rsp}}

      # Provisionals go up from every branch as they are: a B2BUA collapses them
      # into its single inbound dialog (§3.2), and a 180 says something true
      # about the call even when another branch ends up winning it.
      rsp.response < 200 ->
        {state, {:send, rsp}}

      # The winner. Cancelling the rest is `adopt_winning_branch/2`, one layer
      # down, where the dialog also adopts the to-tag and the target.
      rsp.response in 200..299 ->
        {state, {:send, rsp}}

      # A global refusal ends the hunt on the spot (RFC 3261 §16.7): whatever is
      # still ringing is cancelled and the 6xx goes up as it stands.
      rsp.response >= 600 ->
        {cancel_losing_branches(state, tid), {:send, rsp}}

      true ->
        rest = Map.delete(state.branches, tid)

        if map_size(rest) == 0 do
          # The rung is over. With nothing withheld — the serial case, one live
          # branch — this is that branch's own final, verbatim; otherwise the
          # caller gets the best the rung produced.
          {%SIP.DialogImpl{state | branches: rest, fork_best: nil},
           {:send, best_final(state.fork_best, rsp)}}
        else
          {%SIP.DialogImpl{
             state
             | branches: rest,
               fork_best: best_final(state.fork_best, rsp)
           }, :withhold}
        end
    end
  end

  # A branch we cancelled speaking up. A provisional says nothing — it is still
  # winding down. A non-2xx final is the 487 our CANCEL asked for. A 2xx is the
  # race RFC 3261 §16.7 leaves to the UAC: the callee picked up as our CANCEL
  # crossed the network, and someone owes them an ACK and a BYE. A proxy cannot
  # do it (its caller does); a B2BUA must, and it stays invisible above.
  defp late_branch_response(state, rsp, tid) do
    cond do
      rsp.response < 200 ->
        {state, :withhold}

      rsp.response in 200..299 and match?([_, :INVITE], rsp.cseq) ->
        {state |> forget_loser(tid) |> bury_late_answer(rsp, tid), :withhold}

      true ->
        {forget_loser(state, tid), :withhold}
    end
  end

  defp forget_loser(state, tid),
    do: %SIP.DialogImpl{state | fork_losers: MapSet.delete(state.fork_losers, tid)}

  defp bury_late_answer(state, rsp, tid) do
    Logger.info(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Branch #{inspect(tid)} answered #{rsp.response} after losing the fork: ACK + BYE"
    )

    protect(fn -> SIP.Transac.ack_uac_transaction(tid) end)
    send_late_bye(state, rsp, tid)
  end

  # The BYE of a call we never told anyone about, so it is deliberately NOT a
  # dialog: nothing above knows this callee, nothing will ever send anything else
  # to them, and a second dialog process would only be there to be torn down. A
  # bare client transaction, its answer swallowed.
  defp send_late_bye(state, rsp, tid) do
    bye = late_bye_request(state, rsp, tid)
    state = %SIP.DialogImpl{state | cseq: state.cseq + 1}

    case SIP.Transac.start_uac_transaction(bye, 15) do
      {:ok, trans_pid, modmsg} ->
        %SIP.DialogImpl{state | internal_trans: MapSet.put(state.internal_trans, trans_pid)}
        |> add_transaction(trans_pid, modmsg, uac_module(modmsg))

      other ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message: "Could not BYE a late 2xx: #{inspect(other)}"
        )

        state
    end
  end

  # Built from the INVITE we sent — same Call-ID, From and From-tag, next CSeq —
  # and from the late answer for everything that identifies the callee: their
  # To-tag, their Contact, their route set.
  defp late_bye_request(state, rsp, tid) do
    base =
      state.msg
      |> Map.merge(%{
        method: :BYE,
        ruri: late_target(state, rsp, tid),
        to: rsp.to,
        cseq: [state.cseq, :BYE],
        body: [],
        contentlength: 0
      })
      |> Map.delete(:contenttype)

    case Map.get(rsp, :recordroute) do
      rs when is_binary(rs) and rs != "" -> Map.put(base, :route, rs)
      [_ | _] = rs -> Map.put(base, :route, rs)
      _ -> Map.delete(base, :route)
    end
  end

  # Where that BYE goes: the Contact of the late 2xx (RFC 3261 §12.1.2) reached
  # over the flow the branch used. The Contact carries an identity and no
  # destination; the branch's request carries the RESOLVED one, which for a
  # registered contact behind NAT is the only address that works.
  defp late_target(state, rsp, tid) do
    branch_ruri =
      case Map.get(state.transactions, tid) do
        %{req: %{ruri: %SIP.Uri{} = ruri}} -> ruri
        _ -> state.msg.ruri
      end

    case Map.get(rsp, :contact) do
      %SIP.Uri{} = uri -> stamp_flow(uri, branch_ruri)
      [%SIP.Uri{} = uri | _] -> stamp_flow(uri, branch_ruri)
      _ -> branch_ruri
    end
  end

  defp stamp_flow(uri, %SIP.Uri{} = flow) do
    %SIP.Uri{
      uri
      | destip: flow.destip,
        destport: flow.destport,
        tp_module: flow.tp_module,
        tp_pid: flow.tp_pid
    }
  end

  # Which of two finals answers the caller better (RFC 3261 §16.7 step 6): a 6xx
  # first — a global refusal outranks anything a single device said — then the
  # lowest code, except among 4xx where the ones that ASK FOR SOMETHING
  # (credentials, a media type, an extension, another address) are preferred:
  # a caller can act on those, and cannot act on "486 Busy Here".
  @actionable_4xx [401, 407, 415, 420, 484]

  defp best_final(nil, rsp), do: rsp
  defp best_final(rsp, nil), do: rsp

  defp best_final(a, b) do
    cond do
      global?(a) and not global?(b) -> a
      global?(b) and not global?(a) -> b
      class_of(a) == 4 and class_of(b) == 4 -> best_4xx(a, b)
      a.response <= b.response -> a
      true -> b
    end
  end

  defp best_4xx(a, b) do
    cond do
      a.response in @actionable_4xx and b.response not in @actionable_4xx -> a
      b.response in @actionable_4xx and a.response not in @actionable_4xx -> b
      a.response <= b.response -> a
      true -> b
    end
  end

  defp global?(rsp), do: rsp.response >= 600
  defp class_of(rsp), do: div(rsp.response, 100)

  # Talking to a transaction that is, by construction, in a race with us: it may
  # already be gone, and its exit must not become the dialog's.
  defp protect(fun) do
    fun.()
  catch
    :exit, reason ->
      Logger.debug(module: __MODULE__, message: "transaction call failed: #{inspect(reason)}")
      :error
  end

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
    msg =
      case Map.get(state.branches, winner) do
        %SIP.Uri{} = target -> %{state.msg | ruri: target}
        _ -> state.msg
      end

    %SIP.DialogImpl{cancel_losing_branches(state, winner) | forking: false, msg: msg}
  end

  # CANCEL every branch but `keep` and remember them: a cancelled branch still
  # owes us a final (a 487, or the 2xx that crossed our CANCEL), and that final
  # is ours to absorb rather than the application's to read.
  defp cancel_losing_branches(state, keep) do
    losers = state.branches |> Map.keys() |> List.delete(keep)

    Enum.each(losers, fn pid ->
      Logger.debug(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: "Cancelling losing fork branch #{inspect(pid)}"
      )

      protect(fn -> SIP.Transac.cancel_uac_transaction(pid) end)
    end)

    %SIP.DialogImpl{
      state
      | branches: %{},
        fork_best: nil,
        fork_losers: Enum.into(losers, state.fork_losers)
    }
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

  # The dialog states in which the dialog goes on living. Anything else is a
  # dialog that has said its last word and must stop — the single reading of that
  # question, used by every path that ends a transaction.
  @live_states [:initial, :established, :redirected, :uac_challenged, :uas_challenged]

  # A client transaction ended with no final response — it timed out (timer B/F),
  # or it crashed. Both mean the same thing one layer up, so both land here.
  #
  # The synthetic 408 is then run through `handle_UAS_response/3`, exactly as a
  # 408 arriving off the wire would be. That is the whole point of synthesizing a
  # response rather than inventing a private failure path, and it was the one
  # thing the timeout handler did not do: it notified the application and left the
  # dialog in `:initial` for ever. A failed outbound INVITE therefore left its
  # dialog process alive for the full 1800 s expiration — one leaked dialog per
  # unanswered call, which for a B2BUA is one per failed leg.
  #
  # Routing it through that function also gets the fork case right for free: its
  # `forking: true` clause ends the BRANCH and keeps the dialog for the next
  # target, which is precisely what a hunt needs when a branch dies without
  # answering.
  defp unanswered_request(state, req, transact_pid, module) do
    state = report_unanswered(state, req, transact_pid, module)

    if state.state in @live_states do
      {:noreply, state}
    else
      # `state`, not the atom `:state` that stood here. terminate/2 was handed
      # an atom, `state.app` raised on it, and the dialog died of that error
      # instead of stopping — so the application was never sent
      # {:dialog_terminated, …} on the one path meant to end a dialog cleanly.
      {:stop, :normal, state}
    end
  end

  # The state half of the above, so a caller with several dead transactions to
  # report (a transport taking its whole flow down, R4/R5) can fold over them and
  # decide the dialog's fate once.
  defp report_unanswered(state, req, transact_pid, module) do
    state =
      notify_transaction_timeout(state, req, transact_pid, module)
      |> close_transaction(transact_pid)

    # A SERVER transaction that ends unanswered says nothing about the dialog:
    # it means the application never replied, and handle_UAS_response/3 reads
    # responses we RECEIVED. Leave the dialog alone.
    if client_transaction?(module) do
      handle_UAS_response(state, timeout_response(req), transact_pid)
      |> end_on_unregister(req)
    else
      state
    end
  end

  # An un-REGISTER we sent ourselves ends the dialog once its transaction is over,
  # answered or not — the registration is gone either way. It needs saying here
  # because a REGISTER dialog has no closing transaction for handle_UAS_response/3
  # to recognize (only a BYE sets one).
  #
  # Read through SIP.Msg.Ops so the header counts: this test used to look at the
  # Contact `expires` parameter alone, so our own `Expires: 0` un-REGISTER (no
  # parameter — the shape every real UA sends) read as "not an un-registration"
  # and left the dialog behind.
  defp end_on_unregister(state, req) do
    if req.method == :REGISTER and SIP.Msg.Ops.unregister?(req) do
      %SIP.DialogImpl{state | state: :terminated}
    else
      state
    end
  end

  # Our client transactions whose request was travelling over that flow.
  #
  # Matched on the request stored with each transaction, whose R-URI is the
  # RESOLVED one the transaction layer handed back — the branch table holds the
  # target as asked for, which may still be a name.
  defp transactions_on_flow(state, tp_module, ip, port) do
    Enum.filter(state.transactions, fn {_pid, %{req: req, module: module}} ->
      client_transaction?(module) and on_flow?(req, tp_module, ip, port)
    end)
  end

  defp on_flow?(%{ruri: %SIP.Uri{} = ruri}, tp_module, ip, port) do
    ruri.tp_module == tp_module and ruri.destip == ip and ruri.destport == port
  end

  defp on_flow?(_msg, _tp_module, _ip, _port), do: false

  # Handle option keepalive timers: send an OPTIONS message or tear the dialog
  # down when the peer stopped answering (see SIP.DialogImpl.KeepAlive).
  @impl true
  def handle_info({:timeout, _tref, :optionskeepalive}, state) do
    KeepAlive.on_timeout(state)
  end

  # Invoked when a dialog receives a SIP response from an UAC transaction
  def handle_info({:response, rsp, transact_pid}, state) when is_resp(rsp) do
    state =
      if Map.has_key?(state.transactions, transact_pid) do
        {_rc, totag} = SIP.Uri.get_uri_param(rsp.to, "tag")

        # What the application is owed, decided in one place (`deliver_response/3`):
        # a keepalive answer is dialog-internal, and so is everything a fork
        # withholds or absorbs. The transaction is still cleaned up below either
        # way.
        state = deliver_response(state, rsp, transact_pid)

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

    if state.state in @live_states do
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
    # Tell the application before forgetting the transaction. RFC 3261 §17.1.1.2
    # and §8.1.3.1: a client transaction that times out informs the TU, which
    # treats it exactly as a 408 — so that is what the application is handed.
    #
    # Nothing was said at all until now: a request that got no answer left the
    # scenario waiting on its own `after` clause with no idea why, and a B2BUA
    # hunting an unreachable device never moved on to the next one. A synthetic
    # 408 also needs no new plumbing anywhere above: it flows through
    # `process_sip_reply`, `b2bua_forward_reply` and a hunt's retry-on list like
    # any other final.
    unanswered_request(state, req, transact_pid, module)
  end

  # A transaction of ours died. Trapping exits (see `trap_transaction_exits/0`)
  # is what turns the signal that used to kill this dialog outright — silently,
  # without running `terminate/2` — into something we can act on (design §14.4,
  # R1).
  #
  # A `:normal` exit is bookkeeping: the transaction finished (timer K, a final
  # response, a timeout that already sent `{:transaction_timeout, …}`) and
  # whatever had to be said has been said. A CRASH said nothing at all, and the
  # application is waiting on an answer that will now never come — so it gets the
  # same synthetic 408 an unanswered request gets, and for the same reason
  # (RFC 3261 §17.1.1.2: a client transaction that fails informs the TU, which
  # treats it as a 408). A hunt then walks to its next target, a scenario stops
  # waiting on its `after`, and none of it needs plumbing of its own.
  def handle_info({:EXIT, trans_pid, reason}, state = %SIP.DialogImpl{}) do
    case Map.get(state.transactions, trans_pid) do
      # Not ours, or already closed by the path that ended it.
      nil ->
        {:noreply, state}

      %{} when reason in [:normal, :shutdown] ->
        {:noreply, close_transaction(state, trans_pid)}

      %{req: req, module: module} ->
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message:
            "#{inspect(module)} #{inspect(trans_pid)} carrying #{req.method} crashed " <>
              "(#{inspect(reason)}); reporting it as a 408"
        )

        unanswered_request(state, req, trans_pid, module)
    end
  end

  # A connected transport is gone (design §14.4, R4/R5). Broadcast to every
  # dialog, so the first job is deciding whether it concerns us at all.
  #
  # One clause where there were three, one per protocol — they differed only in
  # the module they compared and the reason atom they invented (`:tcp_closed`,
  # `:tls_closed`, `:wss_closed`), which said which wire broke rather than what
  # happened to the call. `:transport_down` is the fact; the module is carried
  # alongside for whoever wants it.
  def handle_info({:transport_down, tp_module, dead_ip, dead_port}, state = %SIP.DialogImpl{}) do
    dead = transactions_on_flow(state, tp_module, dead_ip, dead_port)

    # Every request in flight on that connection has lost its answer. Reported as
    # the 408 it amounts to, which is what a hunt reads to move on and what the
    # application reads to stop waiting.
    state =
      Enum.reduce(dead, state, fn {pid, %{req: req, module: module}}, st ->
        report_unanswered(st, req, pid, module)
      end)

    cond do
      # R5 — a hunt was riding it: what died is the BRANCH, not the call. The
      # dialog stays so the next target can be armed at once, instead of the
      # search stalling until timer B (64×T1) noticed. This is what the old
      # per-protocol clauses could not do: they compared the closed connection to
      # `state.msg.ruri`, which stays the FIRST target until a branch wins, so a
      # disconnect under any later branch went unseen entirely.
      state.forking and dead != [] ->
        {:noreply, state}

      # Our own flow died, or what died took the dialog's last word with it.
      on_flow?(state.msg, tp_module, dead_ip, dead_port) or state.state not in @live_states ->
        # {:shutdown, reason} rather than a hand-rolled send: terminate/2 unwraps
        # it and delivers the ONE {:dialog_terminated, …} the application expects.
        # Doing both — announcing here and stopping — left a second, spurious
        # `:normal` notification in the mailbox, which a later state could match
        # against the OTHER leg's termination.
        {:stop, {:shutdown, :transport_down}, state}

      true ->
        {:noreply, state}
    end
  end

  # Anything else is logged and ignored rather than fatal.
  #
  # `use GenServer` provides such a fallback, but a module that defines its own
  # `handle_info/2` replaces it wholesale — so until now an unrecognized message
  # raised a FunctionClause and took the dialog with it. `SIP.Dialog.broadcast/1`
  # makes that a live hazard rather than a theoretical one: it sends to EVERY
  # dialog, so a message shape one of them does not know is a message that kills
  # all of them.
  def handle_info(msg, state) do
    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message: "Ignoring unexpected message #{inspect(msg)}"
    )

    {:noreply, state}
  end
end
