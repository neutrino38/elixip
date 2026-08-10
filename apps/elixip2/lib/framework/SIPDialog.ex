defmodule SIP.Dialog do
  @moduledoc "SIP module layer API"
  alias SIP.Transac
  require Logger
  require Registry
  require SIP.Uri
  import SIP.Msg.Ops

  @spec start() :: :error | :ok
  @doc "Start the dialog layer"
  def start() do
    # Create the registry
    case Registry.start_link(keys: :unique, name: Registry.SIPDialog) do
      {:ok, pid} ->
        Logger.info("SIP dialog layer started with PID #{inspect(pid)}")
        :ok

      {:error, {:already_started, _pid}} ->
        # Layer already running (e.g. started by a previous test module): treat as success
        :ok

      {code, _pid} ->
        Logger.error("SIP dialog layer failed to start with error #{code}")
        code
    end
  end

  # Obtain the triplet that uniquely identify a dialog
  defp get_dialog_id(req) do
    {_code, fromtag} = SIP.Uri.get_uri_param(req.from, "tag")
    {_code, totag} = SIP.Uri.get_uri_param(req.to, "tag")
    {fromtag, req.callid, totag}
  end

  defp get_or_create_dialog_id(req) do
    get_or_create_dialog_id(req, get_dialog_id(req))
  end

  # Create call ID and add it to the request
  @spec get_or_create_dialog_id(map(), {binary(), nil, binary()}) :: tuple()
  defp get_or_create_dialog_id(req, {fromtag, nil, totag}) do
    callid = generate_from_or_to_tag()
    req = Map.put(req, :callid, callid)
    get_or_create_dialog_id(req, {fromtag, callid, totag})
  end

  # Create from TAG and add it the from URI
  defp get_or_create_dialog_id(req, {nil, callid, totag}) do
    fromtag = generate_from_or_to_tag()
    req = Map.put(req, :from, SIP.Uri.set_uri_param(req.from, "tag", fromtag))
    get_or_create_dialog_id(req, {fromtag, callid, totag})
  end

  # At least from tag and callid are present, return them and end the recursion
  @spec get_or_create_dialog_id(map(), {binary(), binary(), binary()}) :: tuple()
  defp get_or_create_dialog_id(req, {fromtag, callid, totag})
       when is_binary(fromtag) and is_binary(callid) do
    {req, {fromtag, callid, totag}}
  end

  def dlgid2string({ftag, cid, nil}) do
    ftag <> "-" <> cid
  end

  def dlgid2string({ftag, cid, totag}) do
    ftag <> "-" <> cid <> "-" <> totag
  end

  # ---------------------- Public API ----------------------

  @doc """
  Start a dialog.

  Options:

    * `:tag` — event tag of the dialog (an atom). When set, every message the
      dialog delivers to its application process is wrapped as `{tag, msg}` —
      requests, responses, `:onnewdialog` and `:dialog_terminated` alike. This
      is how a B2BUA scenario tells its outbound leg's events apart from the
      inbound ones (design docs/design/b2bua_module.md §2). Default `nil`:
      bare messages, the historical behaviour.

    * `:fork` — `true` when this request is the first branch of a hunt with more
      targets behind it. A non-2xx final then ends the BRANCH, not the dialog,
      so the caller can arm the next target (`fork_branch/2`). It has to be
      declared here rather than inferred from the first `fork_branch/2`: the
      first branch goes out with the dialog, and its failure would otherwise
      have torn the dialog down before anyone could ask for a second.

      A **list of targets** means the same thing and arms them as well: the rest
      of a parallel rung, sent from inside the dialog's `init/1`. Passing them
      here rather than calling `fork_branch/2` right after is not a shortcut —
      a branch armed from the outside races the first branch's own response, and
      a final arriving in between finds a rung of one and is relayed as the
      answer while the other phones are about to ring. Each extra branch is
      announced as `{:onnewbranch, :ok, transaction_pid}`.
  """
  @spec start_dialog(map(), integer(), :inbound | :outbound, boolean(), keyword()) ::
          {:error, any()} | {:ok, pid(), tuple()}
  def start_dialog(req, timeout, direction, debug, opts \\ [])
      when is_integer(timeout) and is_atom(req.method) do
    # Obtain or create the dialog id { fromtag, callid, totag } that identify the SIP dialog according to RFC 3261
    # Using the recusion and pattern matching
    {req2, dialog_id} = get_or_create_dialog_id(req)
    name = {:via, Registry, {Registry.SIPDialog, dialog_id, :cast}}
    tag = Keyword.get(opts, :tag)
    forking = Keyword.get(opts, :fork, false)
    dialog_params = {req2, direction, self(), timeout, debug, dialog_id, tag, forking}

    case GenServer.start(SIP.DialogImpl, dialog_params, name: name) do
      {:ok, dlg_pid} ->
        # Cause deadlock -- why ?
        # The GenServer.call() times out and caused the caller process to terminate.
        # As if the GenServer was not ready to process request at ths point
        # dialog_id = GenServer.call(dlg_pid, :getdialogid)
        Logger.info(
          dialogpid: "#{inspect(dlg_pid)}",
          module: __MODULE__,
          message: "Created dialog #{inspect(dialog_id)}."
        )

        {:ok, dlg_pid, dialog_id}

      # Application rejected the request in DialogImpl.init/1 (nominal refusal,
      # not a failure): propagate the reject tuple verbatim. process_incoming_request
      # turns it into the requested SIP status. Logged at info, not error.
      {:error, {:reject, code, reason, totag}} ->
        Logger.info(
          module: __MODULE__,
          message: "Dialog creation rejected by app: #{code} #{reason}."
        )

        {:error, {:reject, code, reason, totag}}

      {:error, err} when is_exception(err) ->
        Logger.error(module: __MODULE__, message: "Failed to create dialog: exception raised")
        Logger.error(Exception.format(:error, err))
        :error

      {:error, err} ->
        Logger.error(module: __MODULE__, message: "Failed to create dialog: #{inspect(err)}.")
        {:error, err}

      _ ->
        Logger.error(module: __MODULE__, message: "Failed to create dialog.")
        :error
    end
  end

  @spec start_dialog_with_template(any(), any()) :: :ok
  def start_dialog_with_template(_req, _timeout, _direction \\ :outbound, _debug \\ false) do
    :ok
  end

  # transact_id is nil when the request created no server transaction (the ACK of
  # a 2xx, RFC 3261 §17.2.3, routed straight to the dialog by the transport).
  @spec process_incoming_request(map(), pid() | nil, boolean()) ::
          {:error, any()} | {:ok, pid()} | atom() | {any, any}
  def process_incoming_request(req, transact_id, debug) when is_req(req) do
    {req2, dialog_id} = get_or_create_dialog_id(req)

    # A request received in-dialog carries the tags in the opposite order to how
    # a dialog we initiated (UAC) is registered: its To-tag is our local tag and
    # its From-tag is the remote tag. Look the dialog up with both orderings
    # before concluding that there is no matching dialog (RFC 3261 §12.2.2).
    matches =
      Registry.lookup(Registry.SIPDialog, dialog_id) ++
        Registry.lookup(Registry.SIPDialog, swap_dialog_id(dialog_id))

    case matches do
      # No such dialog - create it if the request
      [] ->
        cond do
          # An ACK is never answered (RFC 3261 §17.1.1.3), so a dialog that is gone
          # gets silence, not a 481.
          req.method == :ACK ->
            :nomatchingdialog

          # RFC 3261 §12.2.2 — a request carrying a To tag claims to belong to an
          # established dialog. When none matches, the answer is 481, whatever the
          # method, and no dialog is created for it.
          #
          # Without this, an OPTIONS keepalive arriving after its dialog expired was
          # taken for a brand-new dialog: SIP.Session.ConfigRegistry.dispatch/3 has
          # no clause for :OPTIONS, so it raised a function_clause, the dialog died
          # in init/1 and the peer was told "403 Denied" — for a request that was
          # perfectly valid until its registration lapsed.
          in_dialog_request?(dialog_id) ->
            {:error, {481, "Call/Transaction Does Not Exist", dialog_id}}

          # A capability query / liveness ping (RFC 3261 §11.2). Answered here, by the
          # module the application registered (SIP.Session.Options), and WITHOUT
          # creating a dialog: an OPTIONS is not dialog-forming (§12.1), and the
          # dialog this used to create lived 60 s — one lingering process per ping
          # from a monitoring proxy.
          req.method == :OPTIONS ->
            {:reply, code, reason, fields} =
              SIP.Session.ConfigRegistry.dispatch_options(req2, transact_id)

            {:answered, code, reason, fields}

          true ->
            start_new_dialog_for(req2, dialog_id, debug)
        end

      # Found a matching dialog.Forward the SIP msg to it
      # We do not use dispatch because we have already looked up the transaction list
      # Note that lookup() should always return a single transaction here

      [{dialog_pid, _value} | _] ->
        GenServer.cast(dialog_pid, {:sipmsg, req2, transact_id})
        {:ok, dialog_pid, dialog_id}
    end
  end

  # A request bearing a To tag was sent inside a dialog (only an initial request
  # has none — get_or_create_dialog_id/1 fills in a missing Call-ID or From-tag,
  # never a To tag).
  defp in_dialog_request?({_fromtag, _callid, totag}), do: not is_nil(totag)

  # Initial (out-of-dialog) request: create the dialog its method calls for.
  # (:OPTIONS is absent on purpose — it is answered above without a dialog.)
  defp start_new_dialog_for(req, dialog_id, debug) do
    case req.method do
      :INVITE ->
        # todo, add a timeout global parameter
        start_inbound_dialog(req, 1800, debug, dialog_id)

      :MESSAGE ->
        start_inbound_dialog(req, 60, debug, dialog_id)

      :PRACK ->
        # to add error log - PRACK should be in dialog
        :nomatchingdialog

      m when m in [:PUBLISH, :REGISTER, :SUBSCRIBE] ->
        # Todo compulte timeout from refresh contact period
        start_inbound_dialog(req, 600, debug, dialog_id)

      m when m in [:REFER, :CANCEL, :UPDATE, :BYE] ->
        # In-dialog-only request with no matching dialog: answer 481. Do NOT use
        # SIP.Transac.reply/3 here — this function runs inside the server
        # transaction process (via process_UAS_request), so a GenServer.call on
        # transact_id would be a call to self. Returning the error tuple lets
        # process_UAS_request send the response on its own transaction. (Such a
        # request normally carries a To tag and is already answered 481 by the
        # caller; this covers the ones that arrive without one.)
        {:error, {481, "Call/Transaction Does Not Exist", dialog_id}}

      _ ->
        {:error, {500, "Unsupported request", dialog_id}}
    end
  end

  # Create an inbound dialog and, when the app rejected it in DialogImpl.init/1,
  # map the {:reject, code, reason, totag} error to the {:error, {code, reason,
  # dialog_id}} shape that process_UAS_request turns into a SIP response on the
  # server transaction (registrar quota → 503, UAS domain control → 604, …).
  # Any other start_dialog outcome (including generic errors → 403) is unchanged.
  defp start_inbound_dialog(req, timeout, debug, {fromtag, callid, _totag}) do
    case start_dialog(req, timeout, :inbound, debug) do
      {:error, {:reject, code, reason, totag}} ->
        {:error, {code, reason, {fromtag, callid, totag}}}

      other ->
        other
    end
  end

  # Swap the from/to tags of a dialog id. Used to match an in-dialog request
  # received on a dialog we initiated, where the tag roles are reversed.
  defp swap_dialog_id({fromtag, callid, totag}), do: {totag, callid, fromtag}

  @doc """
  Reply to an in dialog request.

  A scenario replies through the instrumented `SIP.Session.*` helpers instead
  (`SIP.Session.Registrar.reply/6`, the `reply_*` macros); this layer records
  nothing.
  """
  def reply(dialog_id, req, resp_code, reason, upd_fields)
      when is_pid(dialog_id) and is_req(req) do
    GenServer.call(dialog_id, {:replyreq, req, resp_code, reason, upd_fields})
  end

  @doc """
  Send a new in-dialog request out. On success returns `{ :ok, transaction_pid }`
  where `transaction_pid` is the freshly created UAC transaction (usable to ACK or
  CANCEL the request). On failure returns the bare error code (e.g.
  `:methodnotallowed`, `:toomanytransactons`, or a transport error code).
  """
  def new_request(dialog_pid, req) when is_pid(dialog_pid) and is_req(req) do
    GenServer.call(dialog_pid, {:newreq, req})
  end

  @doc """
  Send this dialog's **initial** request to one more target, as another branch of
  the same dialog (RFC 3261 §16.6, the kamailio TM model — design
  docs/design/b2bua_module.md §3.3).

  Call-ID, From tag and CSeq are shared with the branches already sent; only the
  Request-URI differs, and the client transaction mints a fresh Via branch. The
  first branch to answer 2xx becomes the dialog and the others are CANCELled;
  until then a non-2xx final ends only that branch, so the caller can arm the
  next target.

  Returns `{:ok, transaction_pid}`, or `{:error, reason}` — notably
  `:already_established` once a branch has won, since there is then nothing left
  to hunt.

  A **list** of targets is a parallel rung and is armed in one go, answering
  `{:ok, [transaction_pid]}`. That atomicity is the point: branches armed one
  call at a time race their own first response, and a final arriving in between
  finds a rung of one and is read as the rung's answer. `{:error, reason}` comes
  back only when not one of them could be armed.

  Who calls it: the session layer, which owns the target list and the retry
  policy (`%SIP.B2bua.Peer{}`). This layer owns only the branch set.
  """
  @spec fork_branch(pid(), SIP.Uri.t() | [SIP.Uri.t()]) ::
          {:ok, pid()} | {:ok, [pid()]} | {:error, any()}
  def fork_branch(dialog_pid, target) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, {:fork_branch, target})
  end

  @spec challenge(pid(), map(), 401 | 407, any()) :: any()
  def challenge(dialog_pid, req, resp_code, realm) when resp_code in [401, 407] and is_req(req) do
    reply(dialog_pid, req, resp_code, nil, realm)
  end

  @doc "Cancel a request"
  @spec cancel(pid(), pid()) :: any()
  def cancel(dialog_pid, transac_pid) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, {:cancel, transac_pid})
  end

  @doc """
  ACK an INVITE SIP request.
  """
  @spec ack(pid() | map(), pid()) :: any()
  def ack(dialog_pid, req) when is_req(req) when req.method in [:INVITE] do
    case Transac.get_transaction_pid(req) do
      :invalid_transaction -> :invalid_transaction
      ctrans_pid when is_pid(ctrans_pid) -> ack(dialog_pid, ctrans_pid)
    end
  end

  def ack(dialog_pid, transac_pid) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, {:ack, transac_pid})
  end

  @doc """
  Let the dialog layer send the periodic OPTIONS keepalives (NAT / connection
  liveness) on this REGISTER dialog, and tear it down after several unanswered ones.

  Returns `{:error, :app_driven}` when the application already drives the OPTIONS
  itself: the two are exclusive. Running both sent two OPTIONS per period and left
  the spare response in the application's mailbox, where every later state read the
  previous request's answer.
  """
  @spec start_options_keepalive(atom() | pid()) :: any()
  def start_options_keepalive(dialog_pid) do
    GenServer.call(dialog_pid, :option_keepalive)
  end

  @doc """
  Announce that the application sends the OPTIONS keepalives itself: the dialog
  stands down and a later `start_options_keepalive/1` on it declines. Call it before
  the first OPTIONS, so the two never overlap.
  """
  @spec app_drives_keepalive(pid()) :: :ok
  def app_drives_keepalive(dialog_pid) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, :app_drives_keepalive)
  end

  def broadcast(msg_to_send) do
    # récupérer l'ensemble des PID
    pids = Registry.select(Registry.SIPDialog, [{{:_, :"$1", :_}, [], [:"$1"]}])

    for pid <- pids do
      send(pid, msg_to_send)
    end
  end

  def dump() do
    for {k, p, _} <-
          Registry.select(Registry.SIPDialog, [
            {{:"$1", :"$2", :"$3"}, [], [{{:"$1", :"$2", :"$3"}}]}
          ]) do
      Logger.debug("callid: #{inspect(k)} -> #{inspect(p)}")
    end
  end

  # check_nonce/2 is gone with the per-dialog nonce map: a nonce carries its own
  # proof now, so validate it directly with SIP.Auth.Nonce.validate/3 — no dialog
  # round trip, and it also works across dialogs/nodes (design §7.5).

  @doc "Start sending OPTIONS keepalive - only available for REGISTER dialog"
  def start_keepalive(dialog_pid) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, :start_keepalive)
  end

  @doc "Stopn sending keepalive"
  def stop_keepalive(dialog_pid) when is_pid(dialog_pid) do
    GenServer.call(dialog_pid, :stop_keepalive)
  end
end
