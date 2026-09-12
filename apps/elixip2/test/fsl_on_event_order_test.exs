defmodule SIP.Test.FSL.OnEventOrder do
  @moduledoc """
  The three per-event hooks `on_events` instruments into every clause, and the
  order they run in.

      SIP.Session.B2bua.note_event(evt)          # which leg, which transaction
      sip_ctx = SIP.Session.B2bua.note_leg_event(sip_ctx, evt)   # a dead leg's debts
      sip_ctx = SIP.Session.CallUAS.auto_store(sip_ctx, evt)     # stash the request
      <the scenario's own clause body>

  They collapse into one `c:on_event/2` callback
  (finite-state-language/elixir/docs/extraction-plan.md §4.3), which is the
  point of writing them as one function — the order becomes readable instead of
  living in the expansion of a macro.

  What each one buys:

    * **`note_event` first.** It is what the b2bua verbs read to know which leg
      to act on (`current_leg/0`), so a clause replying to the event it just
      matched needs it already written. A clause is not asked for a direction.
    * **`note_leg_event` before the clause body.** A leg that has just died owes
      answers it will never send. They are given *before* the scenario decides
      anything, so the caller is answered the moment its callee goes rather than
      at the teardown (R6).
    * **`auto_store` last**, on the context `note_leg_event` produced: it binds
      `dialogpid` and fills the inbound request slot the reply macros serve.

  **How much of that is observable, and where.** Each hook's effect is read from
  inside a clause body — the one place downstream of all three — so "before the
  clause" is what those assertions actually check, and a hook dropped by the
  collapse fails one of them.

  Their relative *order*, though, is invisible at runtime today: the three act
  on disjoint classes of event (a tagged response, a dead leg, an inbound
  request of a stored method), so no event reaches two of them and no
  observation can tell which ran first. That is a property of today's events,
  not a guarantee — an event both would classify is all it would take — so the
  order is pinned where it is actually written: in the expansion of `on_events`,
  by the last test of this file. That is also the artefact `c:on_event/2`
  replaces, which is the right thing to be watching.
  """
  use ExUnit.Case

  alias SIP.B2bua.{Pending, State}

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok
  end

  setup do
    SIP.Session.B2bua.forget_event()
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{stub: stub}
  end

  # An inbound INVITE, parsed from the captured fixture: `auto_store` guards on
  # `is_map(req)` and the reply path on `is_req/1`, so a hand-made map would not
  # travel the same road.
  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  # ── The scenario ────────────────────────────────────────────────────────────

  # One wait, one clause per event shape under test. Each clause reports what the
  # three hooks had already done by the time it ran, and nothing else: the
  # assertions are all in the test.
  defmodule Observer do
    use SIP.Scenario

    state initial_state do
      # The bookkeeping a b2bua verb would have left: one request relayed from
      # the inbound leg onto the outbound one, still unanswered. Written by hand
      # (`:__b2bua__` is SIP.Session.B2bua's own appdata key) so this suite needs
      # no transport.
      ctx_set(:dialogpid, appdata_get(:dialog))
      appdata_set(:__b2bua__, appdata_get(:b2bua_state) || %SIP.B2bua.State{})
      goto(waiting)
    end

    state waiting do
      on_events do
        # A dead leg. note_event says which one; note_leg_event pays its debts.
        {:outbound, {:dialog_terminated, _dlg, _reason}} ->
          send(
            appdata_get(:probe),
            {:observed,
             %{
               leg: Process.get(:scenario_event_leg),
               tid: Process.get(:scenario_event_tid),
               pending: SIP.Session.B2bua.pending(sip_ctx),
               stored_req: appdata_get(:last_uas_req)
             }}
          )

          scenario_success("saw the leg die")

        # An inbound request of a stored method: auto_store binds the dialog and
        # fills the slot the reply macros serve.
        {:INVITE, _req, trans, _dlg} ->
          send(
            appdata_get(:probe),
            {:observed,
             %{
               leg: Process.get(:scenario_event_leg),
               tid: Process.get(:scenario_event_tid),
               expected_tid: trans,
               stored_req: appdata_get(:last_uas_req),
               stored_tid: appdata_get(:last_uas_req_tid),
               dialogpid: sip_ctx.dialogpid
             }}
          )

          scenario_success("saw the request")

        # A tagged response: note_event reads the leg AND the transaction off it.
        {:outbound, {200, _rsp, trans, _dlg}} ->
          send(appdata_get(:probe), {:observed,
           %{
             leg: Process.get(:scenario_event_leg),
             tid: Process.get(:scenario_event_tid),
             expected_tid: trans,
             # A tagged event must NOT land in the inbound slot: the slot is
             # what reply_invite answers.
             stored_req: appdata_get(:last_uas_req)
           }})

          scenario_success("saw the response")
      after
        5_000 -> scenario_failure("nothing matched")
      end
    end
  end

  defp run(appdata) do
    test_pid = self()
    appdata = Map.put(appdata, :probe, test_pid)

    spawn(fn ->
      send(test_pid, {:done, SIP.Scenario.Runner.run_instance(Observer, appdata: appdata)})
    end)
  end

  # ── note_event ──────────────────────────────────────────────────────────────

  test "the leg and the transaction are noted before the clause body runs", %{stub: stub} do
    pid = run(%{dialog: stub})
    trans = self()
    send(pid, {:outbound, {200, %{response: 200}, trans, stub}})

    assert_receive {:observed, obs}, 5_000
    assert obs.leg == :outbound
    assert obs.tid == trans
    assert obs.tid == obs.expected_tid
    # A tagged event belongs to the other leg: storing it would silently
    # redirect every subsequent inbound reply onto the callee.
    assert obs.stored_req == nil

    assert_receive {:done, :ok}, 5_000
  end

  # ── note_leg_event ──────────────────────────────────────────────────────────

  test "a dead leg's debts are paid before the clause body runs", %{stub: stub} do
    req = inbound_invite()
    trans = self()

    state = %State{
      pending: %{trans => %Pending{orig_req: req, orig_leg: :inbound, method: :INVITE}}
    }

    pid = run(%{dialog: stub, b2bua_state: state})
    send(pid, {:outbound, {:dialog_terminated, stub, :transport_down}})

    # The caller was answered — and it was answered BEFORE the clause body ran,
    # which is what the two `assert_receive` in this order read: the stub sends
    # from inside the GenServer.call the scenario is blocked on, so its message
    # is enqueued before the scenario can send its own.
    assert_receive {:replied, 487, "Request Terminated", ^req, []}, 5_000
    assert_receive {:observed, obs}, 5_000

    # note_event ran first: the clause knows which leg died.
    assert obs.leg == :outbound

    # …and the context the body received is the one note_leg_event produced, not
    # the one the wait was holding: the orphan is no longer pending.
    assert obs.pending == []

    assert_receive {:done, :ok}, 5_000
  end

  # ── auto_store ──────────────────────────────────────────────────────────────

  test "an inbound request is stored, with its transaction and its dialog", %{stub: stub} do
    req = inbound_invite()
    trans = self()

    pid = run(%{dialog: stub})
    send(pid, {:INVITE, req, trans, stub})

    assert_receive {:observed, obs}, 5_000
    assert obs.stored_req == req
    assert obs.stored_tid == trans
    # auto_store binds the dialog pid too: a UAS instance spawned before the
    # dialog exists has no other way to learn it.
    assert obs.dialogpid == stub
    # …and note_event had already run: an untagged event is the inbound leg.
    assert obs.leg == :inbound
    assert obs.tid == trans

    assert_receive {:done, :ok}, 5_000
  end

  # ── the state-entry mirror ──────────────────────────────────────────────────

  # `forget_event/0` on state entry is the other half of the contract: an
  # `after` body acts on the inbound leg, not on whatever the previous state
  # matched. It becomes `c:on_state_enter/1` (§4.3).
  defmodule Forgets do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:outbound, {200, _rsp, _t, _d}} -> goto(checking)
      after
        5_000 -> scenario_failure("no event")
      end
    end

    state checking do
      send(appdata_get(:probe), {:on_entry, Process.get(:scenario_event_leg)})
      scenario_success("forgotten")
    end
  end

  test "the current event is forgotten when a state is entered" do
    test_pid = self()

    pid =
      spawn(fn ->
        send(
          test_pid,
          {:done, SIP.Scenario.Runner.run_instance(Forgets, appdata: %{probe: test_pid})}
        )
      end)

    send(pid, {:outbound, {200, %{response: 200}, self(), self()}})

    assert_receive {:on_entry, nil}, 5_000
    assert_receive {:done, :ok}, 5_000
  end

  # ── the order, where it is written ──────────────────────────────────────────

  # The three hooks act on disjoint event classes, so no runtime observation can
  # order them (see the moduledoc). The order lives in the macro expansion, and
  # that is what `c:on_event/2` replaces — so it is read there, from a module
  # that expands one `on_events` at compile time and keeps the result.
  defmodule Expansion do
    use SIP.Scenario

    expanded =
      Macro.expand_once(
        quote do
          on_events do
            {:INVITE, _req, _t, _d} -> goto(initial_state)
          end
        end,
        __ENV__
      )

    @expansion Macro.to_string(expanded)
    def expansion, do: @expansion

    state initial_state do
      scenario_success("x")
    end
  end

  describe "the instrumented clause" do
    setup do
      %{src: Expansion.expansion()}
    end

    test "carries the three hooks, in the documented order", %{src: src} do
      at = fn needle ->
        case :binary.match(src, needle) do
          {pos, _len} -> pos
          :nomatch -> flunk("#{needle} is not in the expansion:\n#{src}")
        end
      end

      # The inferred type is stored first: the trailing transition reads it back.
      assert at.("Process.put(:scenario_event_type") <
               at.("SIP.Session.B2bua.note_event")

      assert at.("SIP.Session.B2bua.note_event") <
               at.("SIP.Session.B2bua.note_leg_event")

      assert at.("SIP.Session.B2bua.note_leg_event") <
               at.("SIP.Session.CallUAS.auto_store")
    end

    test "threads the context through the two hooks that produce one", %{src: src} do
      # note_event returns :ok and is called for its effect; the other two
      # rebind the context, and each must be given the previous one's output.
      assert src =~ "var!(sip_ctx) = SIP.Session.B2bua.note_leg_event(var!(sip_ctx), evt)"
      assert src =~ "var!(sip_ctx) = SIP.Session.CallUAS.auto_store(var!(sip_ctx), evt)"
    end

    # The clauses `on_events` injects are instrumented like any other: a media
    # death or a shutdown request is an event the host gets to see, not a side
    # door around the per-event hooks.
    test "injected clauses are instrumented too", %{src: src} do
      for clause <- [
            "{:ms_event, _ref, :server_disconnected}",
            "{:scenario_ctl, :shutdown, _reason}"
          ] do
        assert src =~ clause
      end

      # Three clauses in this wait (two injected, one the scenario's own), three
      # copies of each hook.
      assert length(String.split(src, "SIP.Session.B2bua.note_event")) - 1 == 3
      assert length(String.split(src, "SIP.Session.CallUAS.auto_store")) - 1 == 3
    end
  end
end
