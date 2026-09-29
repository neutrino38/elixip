defmodule SIP.Test.FSL.OnEventOrder do
  @moduledoc """
  What SIP does with every event the machine receives, before the scenario's own
  clause runs, and the order it does it in.

      SIP.FSL.Host.on_event(sip_ctx, evt)
        SIP.Session.B2bua.note_event(evt)          # which leg, which transaction
        |> SIP.Session.B2bua.note_leg_event(evt)   # a dead leg's debts
        |> SIP.Session.CallUAS.auto_store(evt)     # stash the request
      <the scenario's own clause body>

  The three used to be three calls injected into every `on_events` clause; they
  are one `c:FSL.Host.on_event/2` now
  (finite-state-language/elixir/docs/extraction-plan.md §4.3). That is the whole
  point of writing them as one function: the order becomes three statements a
  reader can see, instead of living in the expansion of a macro.

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

  Their relative *order*, though, is invisible at runtime: the three act on
  disjoint classes of event (a tagged response, a dead leg, an inbound request
  of a stored method), so no event reaches two of them and no observation can
  tell which ran first. That is a property of today's events and not a guarantee
  — an event both would classify is all it would take — which is exactly why it
  matters that the order is now written in one function rather than spread
  across a macro expansion. The last blocks of this file check the two halves of
  that: the host is called once per clause and its result threaded, and each of
  its three steps has happened by the time it returns.
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

  # ── what the expansion carries ──────────────────────────────────────────────

  # One hook per clause, and the host named at compile time. Read off a module
  # that expands one `on_events` while it is being compiled and keeps the
  # result, because that is the only place an instrumented clause exists.
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

    test "calls the scenario's own host once, and threads the context", %{src: src} do
      # The variable reads `sip_ctx` and not `var!(sip_ctx)` because the name is
      # a parameter of the binding now: the expansion carries the variable
      # itself — `Macro.var(:sip_ctx, nil)`, which is what `var!/1` produces —
      # rather than a `var!` call left to expand later.
      assert src =~ "sip_ctx = FSL.Host.hook(SIP.FSL.Host, :on_event, [sip_ctx, evt], sip_ctx)"

      # …and the host was resolved while compiling, not looked up per event.
      refute src =~ "__fsl_host__"
    end

    test "stores the inferred type before handing the event over", %{src: src} do
      at = fn needle ->
        case :binary.match(src, needle) do
          {pos, _len} -> pos
          :nomatch -> flunk("#{needle} is not in the expansion:\n#{src}")
        end
      end

      # The trailing transition reads the type back, so it has to be written
      # before anything in the clause can transition.
      assert at.("Process.put(:scenario_event_type") < at.("FSL.Host.hook")
    end

    # The clauses `on_events` injects are instrumented like any other: a media
    # death or a shutdown request is an event the binding gets to see, not a side
    # door around the per-event hook.
    test "injected clauses are instrumented too", %{src: src} do
      for clause <- [
            "{:ms_event, _ref, :server_disconnected}",
            "{:conversation, :idle}",
            "{:conversation, :transport_down}",
            "{:scenario_ctl, :shutdown, _reason}"
          ] do
        assert src =~ clause
      end

      # Five clauses in this wait — four injected, one the scenario's own — and
      # one hook each.
      assert length(String.split(src, ":on_event")) - 1 == 5
    end
  end

  # ── the three steps, on the host itself ─────────────────────────────────────

  # `on_event/2` is an ordinary function now, so each of its steps can be asked
  # for directly. That is what the collapse bought: the unit under test is the
  # binding's reading of an event, not the shape of a macro expansion.
  describe "SIP.FSL.Host.on_event/2" do
    test "step 1: records which leg the event came from, and its transaction", %{stub: stub} do
      SIP.Session.B2bua.forget_event()
      tid = self()

      SIP.FSL.Host.on_event(%SIP.Context{dialogpid: stub}, {:outbound, {200, %{}, tid, stub}})

      assert Process.get(:scenario_event_leg) == :outbound
      assert Process.get(:scenario_event_tid) == tid
    end

    test "step 2: answers what a leg that has just died owes", %{stub: stub} do
      req = inbound_invite()
      tid = self()

      ctx =
        FSL.Context.appdata_set(%SIP.Context{dialogpid: stub}, :__b2bua__, %State{
          pending: %{tid => %Pending{orig_req: req, orig_leg: :inbound, method: :INVITE}}
        })

      ctx = SIP.FSL.Host.on_event(ctx, {:outbound, {:dialog_terminated, stub, :transport_down}})

      assert_receive {:replied, 487, "Request Terminated", ^req, []}, 2_000
      # …and the context it hands back has forgotten the request it just answered.
      assert SIP.Session.B2bua.pending(ctx) == []
    end

    test "step 3: stashes an inbound request, with its transaction and dialog", %{stub: stub} do
      req = inbound_invite()
      tid = self()

      ctx = SIP.FSL.Host.on_event(%SIP.Context{}, {:INVITE, req, tid, stub})

      assert FSL.Context.appdata_get(ctx, :last_uas_req) == req
      assert FSL.Context.appdata_get(ctx, :last_uas_req_tid) == tid
      assert ctx.dialogpid == stub
    end

    test "a tagged event is not stashed: the slot is what reply_invite answers", %{stub: stub} do
      event = {:outbound, {:INVITE, inbound_invite(), self(), stub}}
      ctx = SIP.FSL.Host.on_event(%SIP.Context{}, event)

      assert FSL.Context.appdata_get(ctx, :last_uas_req) == nil
    end
  end

  describe "SIP.FSL.Host.on_state_enter/1" do
    test "forgets the leg and the transaction of the matched event", %{stub: stub} do
      SIP.FSL.Host.on_event(%SIP.Context{}, {:outbound, {200, %{}, self(), stub}})
      assert Process.get(:scenario_event_leg) == :outbound

      assert SIP.FSL.Host.on_state_enter(%SIP.Context{}) == %SIP.Context{}
      assert Process.get(:scenario_event_leg) == nil
      assert Process.get(:scenario_event_tid) == nil
    end
  end
end
