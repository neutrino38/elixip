# B2BUA session layer: two call legs driven by one scenario FSM.
# Design: docs/design/b2bua_module.md. Part of the SIP.Session namespace; see
# SIPSession.ex for the common core.

defmodule SIP.B2bua.Peer do
  @moduledoc """
  A SIP peer: where an outbound leg is sent, and how.

  `uris` is an ordered target list (binaries or `%SIP.Uri{}`, possibly already
  carrying their destination — the registrar case, §3.2). The three sources of
  fork targets converge here: a single URI resolved through DNS SRV, an explicit
  list, or the live contacts of an AOR.

    * `use_srv`  — resolve each target through SRV (RFC 3263). SRV multiplicity
      is a failover list, always serial, whatever `fork` says.
    * `fork`     — `:none` (v1) | `:serial` (P2) | `:parallel` (P4). Forking
      creates branches *inside* the leg dialog, never extra legs (§3.3).
    * `ruri`     — `:peer` rewrites the forwarded R-URI to the target (kamailio
      `$ru`; mandatory to reach a registered contact), `:keep` preserves the
      original R-URI and only routes to the target (kamailio `$du`; the
      trunk/SBC case).
    * `outbound_proxy` — per-peer next hop; `nil` falls back to the global
      `:proxyuri` application env. (P2 — the global one is honoured today.)
    * `trunk_pid` — reserved for the future trunk process holding reachability
      state. Ignored in v1.
  """
  defstruct uris: [],
            use_srv: false,
            fork: :none,
            ruri: :peer,
            outbound_proxy: nil,
            trunk_pid: nil
end

defmodule SIP.B2bua.Leg do
  @moduledoc "One call leg of a B2BUA scenario (the outbound one; see SIP.B2bua.State)."
  # `local_uri` / `remote_uri` are the From and To of the request that opened the
  # leg. Kept because a request this layer originates later (the teardown BYE)
  # must carry the dialog's own identity, and `SIP.DialogImpl.address_in_dialog/2`
  # restores only the To on an outbound dialog — the From is taken from the
  # request as given (see the open question in docs/design/b2bua_module.md §12).
  defstruct tag: nil,
            dialogpid: nil,
            peer: nil,
            target: nil,
            method: nil,
            local_uri: nil,
            remote_uri: nil,
            initial_trans: nil,
            media: false
end

defmodule SIP.B2bua.Pending do
  @moduledoc """
  A request relayed onto another leg, awaiting its response. Keyed by the
  **client transaction pid** of the forwarded request — the correlation the
  design settles on (§5): the transaction pid is known at forward time and comes
  back on every response event, so nothing has to be re-derived from the message.
  """
  defstruct orig_req: nil, orig_leg: :inbound, method: nil
end

defmodule SIP.B2bua.State do
  @moduledoc "B2BUA bookkeeping, stored in the scenario context appdata under `:__b2bua__`."
  defstruct legs: %{}, pending: %{}
end

defmodule SIP.Session.B2bua do
  @moduledoc """
  B2BUA primitives for the scenario DSL: create a second (outbound) call leg,
  relay requests and responses between the legs, and answer locally.

  Pulled in by `use SIP.Scenario`, so every scenario has the `b2bua_*` macros.
  The inbound leg stays `sip_ctx.dialogpid` — every existing macro
  (`reply_invite*`, `send_BYE`, …) keeps its inbound meaning; the outbound leg
  is tagged, so its events arrive wrapped as `{:outbound, evt}` and are told
  apart syntactically in `on_events` patterns.

  What is framework here: rewriting (through `SIP.Msg.Ops`), correlation, and
  the leg bookkeeping the automatic teardown reads. What stays the scenario's:
  the relay **policy** — what to relay, when, and what to answer locally.

  Design: docs/design/b2bua_module.md §3-§6.
  """
  require Logger

  alias SIP.B2bua.{Leg, Peer, Pending, State}

  @appdata_key :__b2bua__
  @outbound_tag :outbound

  # Dialog lifetime (seconds) of an outbound leg, by method. Mirrors the inbound
  # values SIP.Dialog.start_new_dialog_for/3 uses.
  @default_timeouts %{INVITE: 1800, MESSAGE: 60, REGISTER: 600, SUBSCRIBE: 600, PUBLISH: 600}

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Create the outbound leg: forward `req` to `peer`, attaching the resulting
      dialog to this scenario. `media` is `false` (pure signaling relay, P1) —
      `{:mediaserver, opts}` and `{:rtpengine, opts}` are P3/P4.

      Options: `:timeout` (dialog lifetime, seconds), `:useragent`.
      """
      defmacro b2bua_forward(req, peer, media, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_create_leg(
              var!(sip_ctx),
              unquote(req),
              unquote(peer),
              unquote(media),
              unquote(opts)
            )
        end
      end

      @doc """
      Relay `req` to the *other* leg. The direction is inferred from the event
      the enclosing `on_events` clause matched: a request received untagged
      (inbound) goes out on the outbound leg and vice versa. ACK and CANCEL are
      translated onto the correlated INVITE transaction rather than re-sent.
      """
      defmacro b2bua_forward(req) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward")

          var!(sip_ctx) = SIP.Session.B2bua.do_relay_request(var!(sip_ctx), unquote(req))
        end
      end

      @doc """
      Relay `resp` back onto the leg its request came from, found through the
      correlation established when that request was forwarded.
      """
      defmacro b2bua_forward_reply(resp) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward_reply #{unquote(resp).response}")

          var!(sip_ctx) = SIP.Session.B2bua.do_relay_reply(var!(sip_ctx), unquote(resp))
        end
      end

      @doc """
      Answer `req` locally — without relaying it — on the leg the current event
      came from (inbound when there is none, e.g. in an `after` clause).
      """
      defmacro b2bua_reply(req, code, reason \\ nil, upd_fields \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_reply #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_local_reply(
              var!(sip_ctx),
              unquote(req),
              unquote(code),
              unquote(reason),
              unquote(upd_fields)
            )
        end
      end

      @doc "The outbound leg (a `%SIP.B2bua.Leg{}`), or nil when none was created."
      defmacro b2bua_outbound_leg() do
        quote do
          SIP.Session.B2bua.outbound_leg(var!(sip_ctx))
        end
      end
    end
  end

  # ── Current-event bookkeeping (set by the on_events instrumentation) ────────

  @doc """
  Record which leg the matched event came from and which transaction it carries,
  so `b2bua_forward/1` / `b2bua_forward_reply/1` / `b2bua_reply/3` need no
  direction argument. Called for every `on_events` clause, next to the event-type
  inference it mirrors (process dictionary, same lifetime).
  """
  @spec note_event(term()) :: :ok
  def note_event(evt) do
    {leg, inner} = split_tag(evt)
    Process.put(:scenario_event_leg, leg)
    Process.put(:scenario_event_tid, event_transaction(inner))
    :ok
  end

  @doc "Forget the current event (called when a state is entered)."
  @spec forget_event() :: :ok
  def forget_event do
    Process.delete(:scenario_event_leg)
    Process.delete(:scenario_event_tid)
    :ok
  end

  @doc """
  Split a possibly tagged event into `{leg, event}`. A tagged event is the
  nested 2-tuple the dialog layer produces (`{:outbound, {…}}`); everything else
  belongs to the untagged inbound leg. Public because `auto_store/2` needs the
  same reading.
  """
  @spec split_tag(term()) :: {atom(), term()}
  def split_tag({tag, inner}) when is_atom(tag) and is_tuple(inner), do: {tag, inner}
  def split_tag(evt), do: {:inbound, evt}

  # The transaction pid an event carries: 3rd element of a request/response
  # event. Media, scenario and lifecycle events carry none.
  defp event_transaction({_first, _msg, tid, _dlg}) when is_pid(tid), do: tid
  defp event_transaction(_evt), do: nil

  defp current_leg, do: Process.get(:scenario_event_leg, :inbound)
  defp current_tid, do: Process.get(:scenario_event_tid)

  # ── Leg creation ────────────────────────────────────────────────────────────

  @doc false
  @spec do_create_leg(%SIP.Context{}, map(), term(), term(), keyword()) :: %SIP.Context{}
  def do_create_leg(sip_ctx = %SIP.Context{}, req, peer, media, opts \\ []) do
    peer = normalize_peer(peer)

    cond do
      not dialog_forming?(req) ->
        fail(sip_ctx, {:b2bua, :not_dialog_forming, Map.get(req, :method)})

      leg_alive?(outbound_leg(sip_ctx)) ->
        fail(sip_ctx, {:b2bua, :outbound_leg_exists})

      media != false ->
        # {:mediaserver, _} is P3 (it needs leg-qualified media handles and a
        # bridge/2 callback in MediaServer.Behaviour), {:rtpengine, _} is P4.
        fail(sip_ctx, {:b2bua, :media_mode_not_implemented, media})

      peer.uris == [] ->
        fail(sip_ctx, {:b2bua, :no_target})

      true ->
        create_leg(sip_ctx, req, peer, media, opts)
    end
  end

  defp create_leg(sip_ctx, req, peer, media, opts) do
    case SIP.Msg.Ops.prepare_forwarded_request(req, opts) do
      {:error, reason} ->
        fail(sip_ctx, {:b2bua, reason})

      {:ok, fwd} ->
        # v1 uses the head of the target list; the branch orchestration that
        # walks the rest is P2/P4 (§3.3) and lands inside the dialog, not here.
        target = peer.uris |> hd() |> normalize_uri()

        case apply_ruri_policy(fwd, target, peer.ruri) do
          {:error, reason} ->
            fail(sip_ctx, {:b2bua, reason})

          {:ok, fwd} ->
            start_outbound_dialog(sip_ctx, req, fwd, peer, target, media, opts)
        end
    end
  end

  defp start_outbound_dialog(sip_ctx, orig_req, fwd, peer, target, media, opts) do
    timeout = Keyword.get(opts, :timeout, Map.get(@default_timeouts, fwd.method, 60))

    # NOT SIP.Session.send_sip_request/3: that one routes through
    # sip_ctx.dialogpid, which is the INBOUND leg.
    case SIP.Dialog.start_dialog(fwd, timeout, :outbound, sip_ctx.debug, tag: @outbound_tag) do
      {:ok, dialog_pid, _dialog_id} ->
        trans_pid = await_initial_transaction()

        leg = %Leg{
          tag: @outbound_tag,
          dialogpid: dialog_pid,
          peer: peer,
          target: target,
          method: fwd.method,
          local_uri: Map.get(fwd, :from),
          remote_uri: Map.get(fwd, :to),
          initial_trans: trans_pid,
          media: media
        }

        sip_ctx
        |> put_leg(@outbound_tag, leg)
        |> add_pending(trans_pid, orig_req, :inbound, fwd.method)
        |> SIP.Context.set(:lasterr, :ok)

      {:error, reason} ->
        fail(sip_ctx, {:b2bua, :leg_creation_failed, reason})

      other ->
        fail(sip_ctx, {:b2bua, :leg_creation_failed, other})
    end
  end

  # The dialog publishes its initial UAC transaction as {:onnewdialog, :ok, tid}
  # — tagged, like everything else it sends us. Delivered during dialog creation,
  # so it is already in the mailbox; the timeout is only a safety net (same
  # contract as SIP.Session.register_initial_transaction/2).
  defp await_initial_transaction do
    receive do
      {@outbound_tag, {:onnewdialog, :ok, trans_pid}} ->
        trans_pid
    after
      500 ->
        Logger.warning(
          module: __MODULE__,
          message: "No :onnewdialog from the outbound leg; its initial transaction is unknown"
        )

        nil
    end
  end

  # `:peer` — the forwarded request asks for the target itself (kamailio $ru).
  # `:keep` — the request keeps asking for what it asked for, and is merely SENT
  # to the target (kamailio $du): resolve the target and copy its routing onto
  # the original R-URI, which prepare_forwarded_request/2 has already stripped of
  # the inbound leg's routing.
  defp apply_ruri_policy(req, target, :peer), do: {:ok, %{req | ruri: target}}

  defp apply_ruri_policy(req, target, :keep) do
    case resolve(target) do
      %SIP.Uri{} = resolved ->
        ruri = %SIP.Uri{
          req.ruri
          | destip: resolved.destip,
            destport: resolved.destport,
            destproto: resolved.destproto,
            tp_module: resolved.tp_module,
            tp_pid: resolved.tp_pid
        }

        {:ok, %{req | ruri: ruri}}

      err ->
        {:error, {:cannot_route_to, target, err}}
    end
  end

  defp apply_ruri_policy(_req, _target, other), do: {:error, {:bad_ruri_policy, other}}

  # A target that already carries its destination (a registrar contact, §3.2) is
  # taken as is — that is the whole point of storing the registration flow.
  defp resolve(%SIP.Uri{} = uri) do
    if SIP.Uri.has_tp_info(uri), do: uri, else: SIP.Transport.Selector.select_transport(uri)
  end

  # ── Relaying requests ───────────────────────────────────────────────────────

  @doc false
  @spec do_relay_request(%SIP.Context{}, map()) :: %SIP.Context{}
  def do_relay_request(sip_ctx = %SIP.Context{}, req) when is_map(req) do
    from_leg = current_leg()

    case other_leg_pid(sip_ctx, from_leg) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_leg_to_relay_to, from_leg})

      target_pid ->
        relay_request(sip_ctx, req, from_leg, target_pid)
    end
  end

  # An ACK matches no transaction of its own (RFC 3261 §17.2.3): it confirms the
  # 2xx of the INVITE we forwarded, so it is translated onto that transaction
  # rather than re-sent as a request.
  defp relay_request(sip_ctx, %{method: :ACK}, from_leg, _target_pid) do
    case correlated_invite(sip_ctx, from_leg) do
      {dialog_pid, trans_pid} when is_pid(trans_pid) ->
        rc = SIP.Dialog.ack(dialog_pid, trans_pid)
        SIP.Context.set(sip_ctx, :lasterr, ack_lasterr(rc))

      _ ->
        Logger.warning(
          module: __MODULE__,
          message: "Nothing to ACK on the other leg (no correlated INVITE transaction)"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  # Likewise a CANCEL cancels the INVITE we forwarded. The inbound dialog has
  # already auto-answered the CANCEL and is tearing down; all we owe the callee
  # is the CANCEL of its own INVITE.
  defp relay_request(sip_ctx, %{method: :CANCEL}, from_leg, _target_pid) do
    case correlated_invite(sip_ctx, from_leg) do
      {dialog_pid, trans_pid} when is_pid(trans_pid) ->
        rc = SIP.Dialog.cancel(dialog_pid, trans_pid)
        SIP.Context.set(sip_ctx, :lasterr, ack_lasterr(rc))

      _ ->
        Logger.warning(
          module: __MODULE__,
          message: "Nothing to CANCEL on the other leg (no correlated INVITE transaction)"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  defp relay_request(sip_ctx, req, from_leg, target_pid) do
    case SIP.Msg.Ops.prepare_forwarded_request(req) do
      {:error, reason} ->
        fail(sip_ctx, {:b2bua, reason})

      {:ok, fwd} ->
        # The dialog layer re-addresses the request wholesale (Call-ID, CSeq,
        # tags, route set, remote target — fix_outbound_request/3), so what the
        # purge above contributes is dropping the hop-scoped headers and the
        # inbound leg's routing.
        case SIP.Dialog.new_request(target_pid, fwd) do
          {:ok, trans_pid} ->
            sip_ctx
            |> add_pending(trans_pid, req, from_leg, req.method)
            |> SIP.Context.set(:lasterr, :ok)

          err ->
            fail(sip_ctx, {:b2bua, :relay_failed, req.method, err})
        end
    end
  end

  # The INVITE transaction of the leg opposite `from_leg`: what an ACK or a
  # CANCEL arriving on `from_leg` acts upon.
  defp correlated_invite(sip_ctx, :inbound) do
    case outbound_leg(sip_ctx) do
      %Leg{dialogpid: dialog_pid, initial_trans: trans_pid} -> {dialog_pid, trans_pid}
      _ -> nil
    end
  end

  # An ACK/CANCEL arriving on the outbound leg acts on the inbound INVITE, whose
  # server transaction the scenario answers through the dialog: nothing to
  # translate (the inbound side is a UAS, it has no client transaction to ACK).
  defp correlated_invite(_sip_ctx, _outbound), do: nil

  # ── Relaying responses ──────────────────────────────────────────────────────

  @doc false
  @spec do_relay_reply(%SIP.Context{}, map()) :: %SIP.Context{}
  def do_relay_reply(sip_ctx = %SIP.Context{}, resp) when is_map(resp) do
    tid = current_tid()
    state = state(sip_ctx)

    case Map.get(state.pending, tid) do
      %Pending{} = pending ->
        relay_reply(sip_ctx, resp, pending, tid)

      nil ->
        # A retransmitted final, or a response to something this scenario never
        # forwarded. Neither is fatal: say so and carry on.
        Logger.warning(
          module: __MODULE__,
          message:
            "No forwarded request correlates with the #{resp.response} on transaction " <>
              "#{inspect(tid)}; not relaying it"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  defp relay_reply(sip_ctx, resp, %Pending{} = pending, tid) do
    case leg_pid(sip_ctx, pending.orig_leg) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_leg_to_reply_on, pending.orig_leg})

      dialog_pid ->
        fields = SIP.Msg.Ops.forwarded_reply_fields(resp)
        fields = maybe_add_contact(fields, sip_ctx, pending, resp)

        rc = SIP.Dialog.reply(dialog_pid, pending.orig_req, resp.response, resp.reason, fields)

        # A final response closes the correlation; provisionals may be relayed
        # again (goto loop).
        sip_ctx = if resp.response >= 200, do: drop_pending(sip_ctx, tid), else: sip_ctx
        SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
    end
  end

  # A 2xx/3xx answering an INVITE or UPDATE needs a Contact, and it must be OURS
  # — forwarded_reply_fields/1 deliberately left the far end's behind.
  defp maybe_add_contact(fields, sip_ctx, %Pending{method: method}, resp)
       when method in [:INVITE, :UPDATE] do
    if resp.response in 200..399 do
      Keyword.put_new(fields, :contact, local_contact(sip_ctx))
    else
      fields
    end
  end

  defp maybe_add_contact(fields, _sip_ctx, _pending, _resp), do: fields

  # Mirrors SIP.Session.CallUAS.local_contact/1: the transport layer rewrites the
  # placeholder host with the actual bound address.
  defp local_contact(sip_ctx) do
    %SIP.Uri{
      userpart: SIP.Context.get(sip_ctx, :username) || "b2bua",
      domain: "0.0.0.0",
      params: %{}
    }
  end

  # ── Local replies ───────────────────────────────────────────────────────────

  @doc false
  @spec do_local_reply(%SIP.Context{}, map(), integer(), binary() | nil, keyword()) ::
          %SIP.Context{}
  def do_local_reply(sip_ctx = %SIP.Context{}, req, code, reason, upd_fields)
      when is_integer(code) do
    case leg_pid(sip_ctx, current_leg()) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_leg_to_reply_on, current_leg()})

      dialog_pid ->
        rc = SIP.Session.reply(dialog_pid, req, code, reason, upd_fields, "b2bua_reply #{code}")
        SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
    end
  end

  # ── Teardown ────────────────────────────────────────────────────────────────

  @doc """
  Wind down every leg this scenario created, whatever the exit path (success,
  failure, abort, exception). Called by `SIP.Scenario.Runner.finalize/4` before
  the media is released — the media of a leg outlives nothing, but a leg left
  behind holds a call up at the far end for as long as its session timer runs.

  Three things are owed at this point (§8):

    * an initial request still awaiting its final response is CANCELled — the
      callee is ringing for a call nobody will take;
    * an established INVITE leg gets a BYE;
    * every request relayed onto a leg and still unanswered gets a final
      response on the leg it came from, so no transaction is left hanging
      (487 for an INVITE, whose attempt we just terminated; 408 otherwise).

  Returns the context with the leg bookkeeping cleared, so a second call is a
  no-op. Never raises: a leg that dies underneath us is exactly the state we
  were trying to reach.
  """
  @spec release_legs(%SIP.Context{}) :: %SIP.Context{}
  def release_legs(sip_ctx = %SIP.Context{}) do
    state = state(sip_ctx)

    if state.legs == %{} and state.pending == %{} do
      sip_ctx
    else
      Enum.each(Map.values(state.legs), &wind_down_leg(&1, state))
      Enum.each(state.pending, fn {_tid, pending} -> answer_orphan(sip_ctx, pending) end)
      put_state(sip_ctx, %State{})
    end
  end

  defp wind_down_leg(%Leg{} = leg, state) do
    cond do
      not leg_alive?(leg) ->
        :ok

      # The initial request is still in `pending`: it never got a final answer,
      # so the leg is an attempt in progress, not a session.
      Map.has_key?(state.pending, leg.initial_trans) ->
        protect("CANCEL leg #{inspect(leg.dialogpid)}", fn ->
          SIP.Dialog.cancel(leg.dialogpid, leg.initial_trans)
        end)

      leg.method == :INVITE and established?(leg) ->
        protect("BYE leg #{inspect(leg.dialogpid)}", fn ->
          SIP.Dialog.new_request(leg.dialogpid, bye_request(leg))
        end)

      # A leg carrying anything else (MESSAGE, SUBSCRIBE…) has no teardown
      # request of its own: it expires with its dialog.
      true ->
        :ok
    end
  end

  # Did this leg ever become a session? "Its initial transaction is over" does
  # NOT answer that: it is equally true of an INVITE answered 486 Busy, and
  # BYEing *that* dialog sends a BYE with no remote target (RFC 3261 §12.1
  # — a non-2xx final establishes no dialog, so nothing was learned from it).
  #
  # The dialog's remote tag is the honest signal: `add_totag/2` sets it only for
  # a dialog-establishing response (< 300). An early dialog has one too, but a
  # leg still ringing was already caught by the CANCEL branch above.
  defp established?(%Leg{dialogpid: pid}) do
    case protect("read dialog id", fn -> GenServer.call(pid, :getdialogid) end) do
      {_fromtag, _callid, totag} -> is_binary(totag)
      _ -> false
    end
  end

  defp answer_orphan(sip_ctx, %Pending{orig_req: req, orig_leg: leg, method: method}) do
    case leg_pid(sip_ctx, leg) do
      nil ->
        :ok

      dialog_pid ->
        {code, reason} =
          if method == :INVITE,
            do: {487, "Request Terminated"},
            else: {408, "Request Timeout"}

        protect("answer orphan #{method} with #{code}", fn ->
          SIP.Dialog.reply(dialog_pid, req, code, reason, [])
        end)
    end
  end

  # The teardown BYE. The dialog layer fills in Call-ID, CSeq, the tags, the
  # route set and the remote target (fix_outbound_request/3), so the R-URI and
  # the To are placeholders — but the From is NOT one: on an outbound dialog
  # `address_in_dialog/2` only restores the To, and a From with no domain
  # serializes to nothing and takes the whole message down. Hence the leg's own
  # identity, captured when it was created.
  defp bye_request(%Leg{} = leg) do
    local = leg.local_uri || %SIP.Uri{userpart: nil, domain: nil}
    remote = leg.remote_uri || local

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: remote,
      from: local,
      to: remote,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end

  # Teardown runs on the way out, often while the far end is already gone: a
  # dialog that dies between the liveness check and the call must not turn a
  # finished scenario into a crash.
  defp protect(what, fun) do
    fun.()
  rescue
    err ->
      Logger.debug(
        module: __MODULE__,
        message: "b2bua teardown: #{what} — #{Exception.message(err)}"
      )

      :ok
  catch
    :exit, reason ->
      Logger.debug(module: __MODULE__, message: "b2bua teardown: #{what} — #{inspect(reason)}")
      :ok
  end

  # ── Leg / correlation state ─────────────────────────────────────────────────

  @doc "The B2BUA state of a scenario context (empty when it created no leg)."
  @spec state(%SIP.Context{}) :: %State{}
  def state(sip_ctx = %SIP.Context{}) do
    SIP.Context.appdata_get(sip_ctx, @appdata_key) || %State{}
  end

  @doc "The outbound leg, or nil."
  @spec outbound_leg(%SIP.Context{}) :: %Leg{} | nil
  def outbound_leg(sip_ctx), do: state(sip_ctx).legs |> Map.get(@outbound_tag)

  @doc "Every live leg of this scenario (the inbound one excluded — it is sip_ctx.dialogpid)."
  @spec legs(%SIP.Context{}) :: [%Leg{}]
  def legs(sip_ctx), do: state(sip_ctx).legs |> Map.values() |> Enum.filter(&leg_alive?/1)

  @doc "Requests relayed on a leg and still awaiting their response."
  @spec pending(%SIP.Context{}) :: [{pid(), %Pending{}}]
  def pending(sip_ctx), do: state(sip_ctx).pending |> Map.to_list()

  @doc false
  def leg_alive?(%Leg{dialogpid: pid}), do: is_pid(pid) and Process.alive?(pid)
  def leg_alive?(_), do: false

  defp put_state(sip_ctx, state), do: SIP.Context.appdata_set(sip_ctx, @appdata_key, state)

  defp put_leg(sip_ctx, tag, leg) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | legs: Map.put(state.legs, tag, leg)})
  end

  defp add_pending(sip_ctx, nil, _req, _leg, _method), do: sip_ctx

  defp add_pending(sip_ctx, trans_pid, req, leg, method) do
    state = state(sip_ctx)
    entry = %Pending{orig_req: req, orig_leg: leg, method: method}
    put_state(sip_ctx, %State{state | pending: Map.put(state.pending, trans_pid, entry)})
  end

  @doc false
  def drop_pending(sip_ctx, trans_pid) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | pending: Map.delete(state.pending, trans_pid)})
  end

  # The dialog pid of a named leg: the inbound leg is the scenario's own dialog,
  # every other one lives in the leg map.
  defp leg_pid(sip_ctx, :inbound), do: sip_ctx.dialogpid

  defp leg_pid(sip_ctx, tag) do
    case Map.get(state(sip_ctx).legs, tag) do
      %Leg{dialogpid: pid} -> pid
      _ -> nil
    end
  end

  defp other_leg_pid(sip_ctx, :inbound) do
    case outbound_leg(sip_ctx) do
      %Leg{dialogpid: pid} -> pid
      _ -> nil
    end
  end

  defp other_leg_pid(sip_ctx, _outbound), do: sip_ctx.dialogpid

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp normalize_peer(%Peer{} = peer), do: peer
  defp normalize_peer(uri) when is_binary(uri), do: %Peer{uris: [uri]}
  defp normalize_peer(%SIP.Uri{} = uri), do: %Peer{uris: [uri]}
  defp normalize_peer(uris) when is_list(uris), do: %Peer{uris: uris}

  defp normalize_uri(%SIP.Uri{} = uri), do: uri

  defp normalize_uri(uri) when is_binary(uri) do
    case SIP.Uri.parse(uri) do
      {:ok, parsed} -> parsed
      err -> raise "b2bua_forward: invalid target URI #{inspect(uri)}: #{inspect(err)}"
    end
  end

  # Only a request that can create a dialog can create a leg (RFC 3261 §12.1).
  defp dialog_forming?(req) when is_map(req) do
    Map.get(req, :method) in [:INVITE, :MESSAGE, :REGISTER, :SUBSCRIBE, :PUBLISH, :NOTIFY]
  end

  defp dialog_forming?(_), do: false

  defp fail(sip_ctx, reason) do
    Logger.warning(module: __MODULE__, message: "b2bua: #{inspect(reason)}")
    SIP.Context.set(sip_ctx, :lasterr, reason)
  end

  defp reply_lasterr(:ok), do: :ok
  defp reply_lasterr(:ignore), do: :ok
  defp reply_lasterr(other), do: other

  defp ack_lasterr(:ok), do: :ok
  defp ack_lasterr(other), do: other
end
