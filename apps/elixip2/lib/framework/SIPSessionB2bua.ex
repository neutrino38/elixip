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
    * `provider` — `{module, server}` (or a bare `module` registered under its
      own name) handing out targets one at a time instead of a static `uris`
      list: the call-queue case, see `SIP.B2bua.TargetProvider`. Exclusive with
      `uris`.
    * `retry_on` — which final responses make a `:serial` hunt move on to the
      next target: a list of codes and/or ranges, or `nil` for the default.
    * `notify_progress` — surface `{:outbound, {:serial_*, …}}` events as the
      hunt walks its targets (design §3.6). Off by default: a hunt is otherwise
      silent, and a scenario that did not ask should not receive framework
      bookkeeping it might relay.
    * `outbound_proxy` — per-peer next hop; `nil` falls back to the global
      `:proxyuri` application env. (P2b-3 — the global one is honoured today.)
    * `trunk_pid` — reserved for the future trunk process holding reachability
      state. Ignored in v1.
  """
  defstruct uris: [],
            use_srv: false,
            fork: :none,
            ruri: :peer,
            provider: nil,
            retry_on: nil,
            notify_progress: false,
            outbound_proxy: nil,
            trunk_pid: nil
end

defmodule SIP.B2bua.Hunt do
  @moduledoc """
  A search for a target driven by a `SIP.B2bua.TargetProvider` (design §3.4).

  It outlives the leg in both directions: it exists before one, because a
  provider may answer `{:wait, ms}` to the very first ask — the caller is queued
  and nothing has been dialled yet — and it carries what creating that leg will
  need when a target finally comes.

  `call_ref` is the identity the provider holds its reservation against, stable
  for the whole search.
  """
  defstruct provider: nil,
            call_ref: nil,
            peer: nil,
            orig_req: nil,
            media: false,
            opts: [],
            waiting: false,
            ring_timeout: nil
end

defmodule SIP.B2bua.Leg do
  @moduledoc "One call leg of a B2BUA scenario (the outbound one; see SIP.B2bua.State)."
  # `target` is the one currently being tried and `untried` those left after it,
  # in the order the peer gave them (for a registrar peer, descending q). A
  # serial hunt walks that list; each attempt is a branch of the SAME dialog, so
  # the leg — and everything keyed on it — never changes.
  defstruct tag: nil,
            dialogpid: nil,
            peer: nil,
            target: nil,
            untried: [],
            method: nil,
            initial_trans: nil,
            # Set by b2bua_cancel_forward/0: the search was told to stop, as
            # opposed to having run out of targets. It is what keeps
            # `hunting?/1` from reading the attempt still being cancelled as a
            # hunt in progress.
            cancelled: false,
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
  defstruct legs: %{}, pending: %{}, hunt: nil
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

  alias SIP.B2bua.{Hunt, Leg, Peer, Pending, State}

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

      @doc """
      Hang up the outbound leg on our own initiative — not a relay: no BYE was
      received. For the policies where the B2BUA decides the call is over
      (no ACK from the caller, a session timer, an administrative hangup).
      """
      defmacro b2bua_send_BYE() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_send_BYE")

          var!(sip_ctx) = SIP.Session.B2bua.do_send_bye(var!(sip_ctx))
        end
      end

      @doc """
      Give up on the target being tried and ask for the next one.

      What a ring timeout acts on — "ring this agent 15 s, then take the next" —
      and what resumes a search a provider parked with `{:wait, ms}`. The
      attempt in flight, if any, is CANCELled and reported to the provider as
      `:no_answer`.

      Only meaningful with a `%Peer{provider:}`: a static list needs nothing,
      its failures already walk it.
      """
      defmacro b2bua_try_next() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_try_next")

          var!(sip_ctx) = SIP.Session.B2bua.do_try_next(var!(sip_ctx))
        end
      end

      @doc """
      How long the provider asked for this target to be rung, in milliseconds,
      or nil when it said nothing. Meant to be read straight into an `after`:

          after
            b2bua_ring_timeout() || 20_000 -> b2bua_try_next(); goto loop
      """
      defmacro b2bua_ring_timeout() do
        quote do
          SIP.Session.B2bua.ring_timeout(var!(sip_ctx))
        end
      end

      @doc """
      Stop hunting. CANCELs the attempt in flight if one is ringing, drops the
      targets not yet tried, and arms nothing more.

      Distinct from relaying the caller's CANCEL, and both are usually wanted:
      `b2bua_forward(req)` tells the *callee* to stop ringing,
      `b2bua_cancel_forward()` tells the *search* to stop looking. Relaying alone
      leaves it running.
      """
      defmacro b2bua_cancel_forward() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_cancel_forward")

          var!(sip_ctx) = SIP.Session.B2bua.do_cancel_forward(var!(sip_ctx))
        end
      end

      @doc """
      True while a serial hunt is still running: the target that just answered
      refused, and the next one is being tried. What tells "this device said no"
      from "the call is over" after a `b2bua_forward_reply/1`.
      """
      defmacro b2bua_hunting?() do
        quote do
          SIP.Session.B2bua.hunting?(var!(sip_ctx))
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

      # A peer names its targets one way or the other. With a provider `uris` is
      # empty by construction — the provider IS the list (§3.4).
      peer.uris == [] and provider_of(peer) == nil ->
        fail(sip_ctx, {:b2bua, :no_target})

      true ->
        case provider_of(peer) do
          nil ->
            create_leg(sip_ctx, req, peer, media, opts)

          provider ->
            # The targets are not knowable up front: keep what creating the leg
            # will need, and ask. The leg itself waits for a target — with a
            # queue there may be none yet (§3.4).
            hunt = %Hunt{
              provider: provider,
              call_ref: make_ref(),
              peer: peer,
              orig_req: req,
              media: media,
              opts: opts
            }

            sip_ctx |> put_hunt(hunt) |> ask_provider_and_arm(hunt)
        end
    end
  end

  # ── The provider (§3.4) ─────────────────────────────────────────────────────

  # `{module, server}`, or a bare module registered under its own name — the
  # kelixip module pattern. A bare pid cannot work: the callbacks have to be
  # dispatched somewhere, and only the module says where.
  defp provider_of(%Peer{provider: nil}), do: nil
  defp provider_of(%Peer{provider: {mod, server}}) when is_atom(mod), do: {mod, server}
  defp provider_of(%Peer{provider: mod}) when is_atom(mod), do: {mod, mod}
  defp provider_of(_peer), do: nil

  # Ask for a target and act on the answer. The one place that decides what each
  # reply means, so `b2bua_forward/3` and `b2bua_try_next/0` cannot drift.
  defp ask_provider_and_arm(sip_ctx, hunt, on_exhausted \\ &Function.identity/1)

  defp ask_provider_and_arm(sip_ctx, %Hunt{} = hunt, on_exhausted) do
    case ask(hunt.provider, hunt.call_ref, hunt.orig_req) do
      {:ok, uri} ->
        arm_target(sip_ctx, hunt, normalize_uri(uri), [])

      {:ok, uri, opts} when is_list(opts) ->
        arm_target(sip_ctx, hunt, normalize_uri(uri), opts)

      {:wait, ms} when is_integer(ms) and ms >= 0 ->
        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: true})
        |> note_progress({:serial_waiting, ms, now()})
        |> SIP.Context.set(:lasterr, :ok)

      :exhausted ->
        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()

      {:error, reason} ->
        Logger.warning(module: __MODULE__, message: "b2bua: provider failed: #{inspect(reason)}")

        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()

      other ->
        Logger.error(
          module: __MODULE__,
          message: "b2bua: provider returned #{inspect(other)}; treating it as exhausted"
        )

        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()
    end
  end

  # The first target creates the leg; every later one is another branch of it.
  defp arm_target(sip_ctx, %Hunt{} = hunt, uri, opts) do
    hunt = %Hunt{hunt | waiting: false, ring_timeout: Keyword.get(opts, :ring_timeout)}
    sip_ctx = put_hunt(sip_ctx, hunt)

    case outbound_leg(sip_ctx) do
      nil ->
        # A peer of one target, so the static machinery below builds the leg;
        # the provider stays on it, which is what later asks read.
        sip_ctx
        |> create_leg(hunt.orig_req, %Peer{hunt.peer | uris: [uri]}, hunt.media, hunt.opts)
        |> note_progress({:serial_attempting, uri, now()})

      %Leg{} = leg ->
        case SIP.Dialog.fork_branch(leg.dialogpid, uri) do
          {:ok, new_trans} ->
            sip_ctx
            |> move_correlation(leg.initial_trans, new_trans)
            |> put_leg(@outbound_tag, %Leg{leg | target: uri, initial_trans: new_trans})
            |> note_progress({:serial_attempting, uri, now()})
            |> SIP.Context.set(:lasterr, :ok)

          {:error, reason} ->
            Logger.warning(
              module: __MODULE__,
              message: "b2bua: cannot try #{uri} (#{inspect(reason)}); the search stops"
            )

            sip_ctx
            |> note_progress({:serial_not_reachable, uri, :transport_error, now()})
            |> note_progress({:serial_exhausted, now()})
            |> SIP.Context.set(:lasterr, :ok)
        end
    end
  end

  # The caller is still waiting for an answer to the SAME request; only the
  # branch that will provide it changed.
  defp move_correlation(sip_ctx, from_tid, to_tid) do
    case Map.get(state(sip_ctx).pending, from_tid) do
      %Pending{} = pending ->
        sip_ctx
        |> drop_pending(from_tid)
        |> add_pending(to_tid, pending.orig_req, pending.orig_leg, pending.method)

      nil ->
        sip_ctx
    end
  end

  defp ask({mod, server}, call_ref, req) do
    mod.next_target(server, call_ref, req)
  rescue
    err -> {:error, {:provider_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, {:provider_down, reason}}
  end

  # Tell the provider how the attempt it handed out ended, so the reservation it
  # is holding is released. Never lets the provider's trouble become the call's.
  defp report_outcome(sip_ctx, outcome) do
    case hunt(sip_ctx) do
      %Hunt{provider: {mod, server}, call_ref: ref} ->
        protect("report #{inspect(outcome)} to the provider", fn ->
          mod.attempt_ended(server, ref, outcome)
        end)

      _ ->
        :ok
    end

    sip_ctx
  end

  defp create_leg(sip_ctx, req, peer, media, opts) do
    case SIP.Msg.Ops.prepare_forwarded_request(req, opts) do
      {:error, reason} ->
        fail(sip_ctx, {:b2bua, reason})

      {:ok, fwd} ->
        # The first target is dialled now; the rest are kept on the leg for a
        # serial hunt to walk (§3.1). `fork: :none` keeps them unused.
        [target | rest] = Enum.map(peer.uris, &normalize_uri/1)
        untried = if peer.fork == :serial, do: rest, else: []

        case apply_target(fwd, target, peer) do
          {:error, reason} ->
            fail(sip_ctx, {:b2bua, reason})

          {:ok, fwd} ->
            start_outbound_dialog(sip_ctx, req, fwd, peer, target, untried, media, opts)
        end
    end
  end

  defp start_outbound_dialog(sip_ctx, orig_req, fwd, peer, target, untried, media, opts) do
    timeout = Keyword.get(opts, :timeout, Map.get(@default_timeouts, fwd.method, 60))

    # NOT SIP.Session.send_sip_request/3: that one routes through
    # sip_ctx.dialogpid, which is the INBOUND leg.
    #
    # `fork:` is declared here, not on the first fork_branch/2: this very request
    # is the first branch, and with more targets behind it its failure must end
    # the branch rather than the dialog.
    dialog_opts = [tag: @outbound_tag, fork: untried != [] or provider_of(peer) != nil]

    case SIP.Dialog.start_dialog(fwd, timeout, :outbound, sip_ctx.debug, dialog_opts) do
      {:ok, dialog_pid, _dialog_id} ->
        trans_pid = await_initial_transaction()

        leg = %Leg{
          tag: @outbound_tag,
          dialogpid: dialog_pid,
          peer: peer,
          target: target,
          untried: untried,
          method: fwd.method,
          initial_trans: trans_pid,
          media: media
        }

        sip_ctx
        |> put_leg(@outbound_tag, leg)
        |> add_pending(trans_pid, orig_req, :inbound, fwd.method)
        |> note_progress({:serial_attempting, target, now()})
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

  # Two separate questions, answered in order: WHAT the forwarded request asks
  # for (the R-URI policy) and WHERE it is sent (the peer's outbound proxy, when
  # it has one). They are orthogonal, which is the whole reason %SIP.Uri{} keeps
  # its routing next to its identity.
  defp apply_target(req, target, %Peer{} = peer) do
    with {:ok, req} <- apply_ruri_policy(req, target, peer.ruri) do
      route_via(req, peer.outbound_proxy)
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
        {:ok, %{req | ruri: stamp_destination(req.ruri, resolved)}}

      err ->
        {:error, {:cannot_route_to, target, err}}
    end
  end

  defp apply_ruri_policy(_req, _target, other), do: {:error, {:bad_ruri_policy, other}}

  # This peer's own next hop. The global `:proxyuri` application env is still
  # honoured underneath (SIP.Resolver.resolve_and_add_dest/1 applies it when
  # nothing here does), but it is process-global: one next hop for the whole
  # node, which is fine for elixipp and wrong for a server whose peers sit behind
  # different gateways. Set here, it wins — including over the destination a
  # `:keep` policy just stamped, since the proxy IS where the request goes.
  defp route_via(req, nil), do: {:ok, req}

  defp route_via(req, proxy) do
    case resolve(normalize_uri(proxy)) do
      %SIP.Uri{} = resolved ->
        {:ok, %{req | ruri: stamp_destination(req.ruri, resolved)}}

      err ->
        {:error, {:cannot_route_via_proxy, proxy, err}}
    end
  end

  # Copy the routing of `from` onto `uri`, leaving what the URI *says* alone.
  defp stamp_destination(%SIP.Uri{} = uri, %SIP.Uri{} = from) do
    %SIP.Uri{
      uri
      | destip: from.destip,
        destport: from.destport,
        destproto: from.destproto,
        tp_module: from.tp_module,
        tp_pid: from.tp_pid
    }
  end

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
        # A refusal from one target of a serial hunt is not the answer to the
        # call — it is the answer of one device. Try the next one instead of
        # telling the caller the call failed.
        cond do
          provider_hunt?(sip_ctx, resp, tid) ->
            ask_provider_next(sip_ctx, resp, pending, tid)

          next_target(sip_ctx, resp, tid) ->
            try_next_target(sip_ctx, resp, pending, tid)

          true ->
            relay_reply(sip_ctx, resp, pending, tid)
        end

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

  # ── Serial hunt (§3.1, §3.3) ────────────────────────────────────────────────

  # Which final responses make a hunt move on. The default is any 4xx or 5xx:
  # the device refused, timed out or broke, and another one may still answer.
  #
  # NOT 6xx — a 6xx is a global refusal ("Decline", "Does Not Exist Anywhere")
  # and RFC 3261 §16.7 stops the search on it; ringing the user's other phones
  # after they pressed Decline is exactly what they asked not to happen.
  # NOT 3xx — a redirect names new targets, which is its own handling (P4).
  # NOT 487 either, whatever the peer asks for — see @never_retry.
  @default_retry_on [400..599]

  # Is this final one the PROVIDER should be asked about, rather than the end of
  # the call? Same test as the static hunt, minus the untried list — the provider
  # is the list.
  defp provider_hunt?(sip_ctx, resp, tid) do
    with %Leg{initial_trans: ^tid, cancelled: false, peer: peer} <- outbound_leg(sip_ctx),
         %Hunt{} <- hunt(sip_ctx),
         :serial <- peer.fork,
         true <- resp.response >= 300 and retryable?(peer, resp.response) do
      true
    else
      _ -> false
    end
  end

  # Report the refusal, then ask for another target. If the provider has none
  # left, the response the caller has been waiting for is relayed after all —
  # that is what `on_exhausted` carries.
  defp ask_provider_next(sip_ctx, resp, %Pending{} = pending, tid) do
    leg = outbound_leg(sip_ctx)

    sip_ctx
    |> note_progress({:serial_not_reachable, leg.target, resp.response, now()})
    |> report_outcome({:rejected, leg.target, resp.response})
    |> ask_provider_and_arm(hunt(sip_ctx), &relay_reply(&1, resp, pending, tid))
  end

  # The next target to try, or nil when this response ends the hunt. Only the
  # leg's *current* initial transaction is a hunt candidate: a response to some
  # in-dialog request relayed later has nothing to do with it.
  defp next_target(sip_ctx, resp, tid) do
    with %Leg{initial_trans: ^tid, untried: [next | _], peer: peer} <- outbound_leg(sip_ctx),
         :serial <- peer.fork,
         true <- resp.response >= 300 and retryable?(peer, resp.response) do
      next
    else
      _ -> nil
    end
  end

  defp try_next_target(sip_ctx, resp, %Pending{} = pending, tid) do
    leg = outbound_leg(sip_ctx)
    [next | rest] = leg.untried

    case SIP.Dialog.fork_branch(leg.dialogpid, next) do
      {:ok, new_trans} ->
        Logger.info(
          module: __MODULE__,
          message:
            "b2bua: #{leg.target} answered #{resp.response}; trying #{next} " <>
              "(#{length(rest)} target(s) left)"
        )

        # The correlation moves with the hunt: the caller is still waiting for an
        # answer to the SAME request, it is just a different branch that will
        # provide it now.
        sip_ctx
        |> drop_pending(tid)
        |> add_pending(new_trans, pending.orig_req, pending.orig_leg, pending.method)
        |> put_leg(@outbound_tag, %Leg{
          leg
          | target: next,
            untried: rest,
            initial_trans: new_trans
        })
        |> note_progress({:serial_not_reachable, leg.target, resp.response, now()})
        |> note_progress({:serial_attempting, next, now()})
        |> SIP.Context.set(:lasterr, :ok)

      {:error, reason} ->
        # The hunt cannot go on (the dialog is gone, the transport failed…).
        # Relay what we have: the caller learns something rather than waiting
        # for an answer that will never come. Clearing `untried` first stops
        # this from being retried on the next response.
        Logger.warning(
          module: __MODULE__,
          message: "b2bua: cannot try #{next} (#{inspect(reason)}); relaying #{resp.response}"
        )

        sip_ctx
        |> put_leg(@outbound_tag, %Leg{leg | untried: []})
        |> note_progress({:serial_not_reachable, next, :transport_error, now()})
        |> relay_reply(resp, pending, tid)
    end
  end

  # Codes that never continue a hunt, whatever `retry_on` says.
  #
  # 487 answers an INVITE *we* terminated — a branch we cancelled, and we cancel
  # a branch because the CALLER gave up or because a better target won. Reading
  # it as "this device refused" makes the caller's own CANCEL ring the next
  # agent: they hung up, and a second phone starts ringing.
  @never_retry [487]

  defp retryable?(_peer, code) when code in @never_retry, do: false
  defp retryable?(%Peer{retry_on: nil}, code), do: matches_any?(@default_retry_on, code)
  defp retryable?(%Peer{retry_on: specs}, code) when is_list(specs), do: matches_any?(specs, code)
  defp retryable?(%Peer{retry_on: %Range{} = r}, code), do: code in r
  defp retryable?(_peer, _code), do: false

  defp matches_any?(specs, code) do
    Enum.any?(specs, fn
      %Range{} = range -> code in range
      wanted when is_integer(wanted) -> wanted == code
      _ -> false
    end)
  end

  @doc """
  Is a hunt still running on the outbound leg — i.e. did the last final response
  send us to another target rather than end the call?

  What a scenario asks after relaying a failure, to tell "this device refused,
  another is ringing" from "the call is over".
  """
  @spec hunting?(%SIP.Context{}) :: boolean()
  def hunting?(sip_ctx = %SIP.Context{}) do
    cond do
      match?(%Leg{cancelled: true}, outbound_leg(sip_ctx)) -> false
      # Parked on {:wait, ms}: nothing is ringing, and the search is very much on.
      match?(%Hunt{waiting: true}, hunt(sip_ctx)) -> true
      true -> attempt_in_flight?(sip_ctx)
    end
  end

  defp attempt_in_flight?(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{initial_trans: tid} -> Map.has_key?(state(sip_ctx).pending, tid)
      _ -> false
    end
  end

  @doc "How long the provider asked for the current target to be rung, or nil."
  @spec ring_timeout(%SIP.Context{}) :: non_neg_integer() | nil
  def ring_timeout(sip_ctx) do
    case hunt(sip_ctx) do
      %Hunt{ring_timeout: ms} -> ms
      _ -> nil
    end
  end

  @doc """
  Give up on the target being tried and ask the provider for the next one.
  Backs the `b2bua_try_next` macro (design §3.4).

  The attempt in flight is CANCELled and reported as `:no_answer` — which is
  what it is, whether a ring timeout fired or the scenario simply moved on. With
  no provider there is nothing to ask, and the call is left alone.
  """
  @spec do_try_next(%SIP.Context{}) :: %SIP.Context{}
  def do_try_next(sip_ctx = %SIP.Context{}) do
    case hunt(sip_ctx) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_provider_to_ask})

      %Hunt{} = hunt ->
        sip_ctx
        |> cancel_attempt_in_flight()
        |> report_outcome(attempt_outcome(sip_ctx))
        |> ask_provider_and_arm(hunt)
    end
  end

  # What to tell the provider about the attempt we are abandoning. No leg yet
  # means the search was parked on `{:wait, ms}` and nothing was ever tried.
  defp attempt_outcome(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{target: target} when not is_nil(target) -> {:no_answer, target}
      _ -> :abandoned
    end
  end

  # CANCEL whatever branch is ringing, if one is. Silent when there is none —
  # the hunt may be parked, or the attempt already finished.
  defp cancel_attempt_in_flight(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{} = leg ->
        if leg_alive?(leg) and Map.has_key?(state(sip_ctx).pending, leg.initial_trans) do
          protect("cancel the attempt toward #{leg.target}", fn ->
            SIP.Dialog.cancel(leg.dialogpid, leg.initial_trans)
          end)
        end

      _ ->
        :ok
    end

    sip_ctx
  end

  @doc """
  Stop the hunt: CANCEL the attempt in flight, drop the untried targets, arm
  nothing more. Backs the `b2bua_cancel_forward` macro (design §3.5).

  The correlation is deliberately **kept**. The caller's INVITE still owes a
  final response, and leaving the entry in place is what gets them one — the
  branch's 487 relayed through, or failing that the §8 teardown's. Dropping it
  would leave their server transaction to time out.
  """
  @spec do_cancel_forward(%SIP.Context{}) :: %SIP.Context{}
  def do_cancel_forward(sip_ctx = %SIP.Context{}) do
    case outbound_leg(sip_ctx) do
      nil ->
        # No leg — but there may be a search parked on {:wait, ms}, whose
        # reservation still has to be released. Otherwise a no-op: a scenario
        # may say this defensively.
        sip_ctx
        |> report_outcome(:abandoned)
        |> put_hunt(nil)
        |> SIP.Context.set(:lasterr, :ok)

      %Leg{} = leg ->
        sip_ctx
        |> cancel_attempt_in_flight()
        |> report_outcome(:abandoned)
        |> put_hunt(nil)
        |> put_leg(@outbound_tag, %Leg{leg | untried: [], cancelled: true})
        |> SIP.Context.set(:lasterr, :ok)
    end
  end

  # ── Progress events (§3.6) ──────────────────────────────────────────────────

  # A final that is about to be relayed rather than hunted on: the attempt the
  # caller is finally told about. Only for the leg's CURRENT initial transaction
  # — a 200 answering some relayed BYE is not a hunt outcome.
  defp note_attempt_outcome(sip_ctx, resp, tid) do
    case outbound_leg(sip_ctx) do
      %Leg{initial_trans: ^tid, target: target} when resp.response in 200..299 ->
        note_progress(sip_ctx, {:serial_connected, target, now()})

      %Leg{initial_trans: ^tid, target: target} when resp.response >= 300 ->
        sip_ctx
        |> note_progress({:serial_not_reachable, target, resp.response, now()})
        |> note_progress({:serial_exhausted, now()})

      _ ->
        sip_ctx
    end
  end

  # Put a progress event in our own mailbox, wrapped in the leg's tag like
  # everything else that leg produces — so a scenario matches it exactly where it
  # matches the traffic. Silent unless the peer asked (`notify_progress`).
  #
  # Ordering against the traffic of the next branch is not guaranteed: these come
  # from us, those from the dialog. What is exact is the timestamp, which is what
  # a record of the hunt is built from.
  defp note_progress(sip_ctx, event) do
    # From the leg, or from the hunt when there is not one yet — a provider can
    # park a caller on {:wait, ms} before anything has been dialled.
    peer =
      case outbound_leg(sip_ctx) do
        %Leg{peer: %Peer{} = peer} ->
          peer

        _ ->
          case hunt(sip_ctx) do
            %Hunt{peer: %Peer{} = peer} -> peer
            _ -> nil
          end
      end

    if match?(%Peer{notify_progress: true}, peer), do: send(self(), {@outbound_tag, event})

    sip_ctx
  end

  # Wall clock, because what these feed is a record of WHEN things happened. A
  # duration taken between two of them inherits the clock's jumps; somewhere
  # precise enough to care, use System.monotonic_time/0.
  defp now, do: DateTime.utc_now()

  defp relay_reply(sip_ctx, resp, %Pending{} = pending, tid) do
    sip_ctx = note_attempt_outcome(sip_ctx, resp, tid)

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

  # ── Originating on a leg ────────────────────────────────────────────────────

  @doc false
  @spec do_send_bye(%SIP.Context{}) :: %SIP.Context{}
  def do_send_bye(sip_ctx = %SIP.Context{}) do
    case outbound_leg(sip_ctx) do
      %Leg{} = leg ->
        if leg_alive?(leg) do
          case SIP.Dialog.new_request(leg.dialogpid, bye_request()) do
            {:ok, _trans_pid} -> SIP.Context.set(sip_ctx, :lasterr, :ok)
            err -> fail(sip_ctx, {:b2bua, :bye_failed, err})
          end
        else
          # Already gone: what we wanted has happened.
          SIP.Context.set(sip_ctx, :lasterr, :ok)
        end

      nil ->
        fail(sip_ctx, {:b2bua, :no_outbound_leg})
    end
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

    if state.legs == %{} and state.pending == %{} and is_nil(state.hunt) do
      sip_ctx
    else
      # Release whatever a provider is holding for this call before anything
      # else: an agent reserved for a call that no longer exists is an agent the
      # queue believes is busy for good (§3.4).
      report_outcome(sip_ctx, :abandoned)
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
          SIP.Dialog.new_request(leg.dialogpid, bye_request())
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

  # The teardown BYE. Every addressing field is a placeholder: the dialog layer
  # fills in Call-ID, CSeq, both identities, their tags, the route set and the
  # remote target (fix_outbound_request/3 -> address_in_dialog/2). Same shape
  # `SIP.Session.CallInDialog` builds for a scenario-sent BYE.
  defp bye_request do
    uri = %SIP.Uri{userpart: nil, domain: nil}

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: uri,
      from: uri,
      to: uri,
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

  @doc "The provider-driven search in progress, or nil."
  @spec hunt(%SIP.Context{}) :: %Hunt{} | nil
  def hunt(sip_ctx), do: state(sip_ctx).hunt

  defp put_hunt(sip_ctx, hunt) do
    put_state(sip_ctx, %State{state(sip_ctx) | hunt: hunt})
  end

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
