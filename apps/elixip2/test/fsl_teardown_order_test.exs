defmodule SIP.Test.FSL.TeardownOrder do
  @moduledoc """
  The five steps of `SIP.Scenario.Runner`'s termination, **as an order**.

      children  →  B2BUA legs  →  media  →  cleanup/1  →  the parent

  Nothing asserted that order. It is reconstructed from `finalize/4`'s body
  today, and splitting the middle two out into `c:finalize/1`
  (finite-state-language/elixir/docs/extraction-plan.md §4.6) is exactly the
  change that could reorder them silently. Each step is given something
  observable to do — a message to the test process — and the timeline is read
  back as one sequence.

  Why each neighbour pair matters, since a test that only says "in this order"
  invites someone to decide the order is arbitrary:

    * **children before everything.** A child holds resources of its own and
      may be using the parent's dialog; releasing ours first leaves it acting on
      a call that is gone.
    * **legs before media.** A leg left behind holds the call up at the far end,
      and it is the leg that carries the media the server is about to stop
      serving. Releasing the media first gives the far end a live call with no
      media — worse than a call that ends.
    * **both before `cleanup/1`.** The scenario's own hook runs last among the
      releases, so it can still read a context whose handles the framework has
      not yet invalidated.
    * **the parent last.** `{:child_exit, …}` is the parent's signal that this
      instance is done with everything it held. Sent earlier, the parent may
      reuse a resource we have not released.

  Also pinned here, from §5.2 of the same plan: `release_media` accepting the
  **tagged** `{:outbound, {:dialog_terminated, …}}` (getting that wrong costs
  five seconds per teardown and no error), and `cleanup/1` + the parent
  notification running on *every* outcome, not only on success.
  """
  use ExUnit.Case

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok
  end

  # ── Probes ──────────────────────────────────────────────────────────────────

  # A media adapter whose only job is to say when it was released. `disconnect/2`
  # takes no context, so the test pid travels the only way left: the dictionary
  # of the scenario process, which is where SIP.Session.Media calls it.
  defmodule ProbeMediaServer do
    def disconnect(_server, _opts) do
      send(Process.get(:fsl_test_pid), {:step, :media})
      :ok
    end
  end

  # Stands in for the scenario's own (inbound) dialog: established, so the B2BUA
  # teardown owes the caller a BYE, and reporting that BYE is what makes the
  # "legs" step visible. A stub rather than a real dialog because this suite is
  # about the ORDER of the steps, not about what each one puts on the wire.
  defmodule ProbeDialog do
    use GenServer

    def start_link(test_pid), do: GenServer.start_link(__MODULE__, test_pid)

    @impl true
    def init(test_pid), do: {:ok, test_pid}

    @impl true
    def handle_call(:established?, _from, test_pid), do: {:reply, true, test_pid}

    def handle_call({:newreq, req}, _from, test_pid) do
      send(test_pid, {:step, {:legs, Map.get(req, :method)}})
      {:reply, {:ok, self()}, test_pid}
    end
  end

  # ── Scenario fixtures ───────────────────────────────────────────────────────

  # Waits until its parent asks it to stop, then says so. Its wind-down is the
  # first step of the parent's teardown.
  defmodule Child do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:parent_msg, :never} -> scenario_success("unreachable")
      after
        30_000 -> scenario_failure("never asked to stop")
      end
    end

    on_shutdown do
      # A child is its own process, so it learns the test pid the way a child
      # learns anything: from the `args` its parent spawned it with.
      send(appdata_get(:probe), {:step, :children})
      scenario_aborted("parent terminated")
    end
  end

  # Holds all four kinds of resource, then ends on the outcome its appdata names.
  # Everything it sets by hand is what a real scenario gets from its verbs; set
  # here directly so the timeline does not depend on a live stack.
  defmodule Holder do
    use SIP.Scenario

    state initial_state do
      spawn_fsm(Child, as: :kid, args: %{probe: appdata_get(:probe)})
      goto(arming)
    end

    state arming do
      # The media handles a `media_connect` would have left behind.
      ctx_set(:mediaservermodule, SIP.Test.FSL.TeardownOrder.ProbeMediaServer)
      ctx_set(:mediaserverpid, appdata_get(:fake_server))

      # The B2BUA bookkeeping a `b2bua_*` verb would have left behind: an empty
      # state (so the scenario counts as a B2BUA at all) over an established
      # inbound dialog, which is what the teardown owes a BYE.
      #
      # `:__b2bua__` is SIP.Session.B2bua's own appdata key, written here rather
      # than reached through a verb so that this suite needs no transport.
      ctx_set(:dialogpid, appdata_get(:dialog))
      appdata_set(:__b2bua__, %SIP.B2bua.State{})

      goto(ending)
    end

    state ending do
      # The dialog-end event `release_media` waits for. Posted to ourselves in
      # the shape this run is testing, and consumed by nothing before the
      # teardown: the receives in between are all selective.
      case appdata_get(:dialog_end) do
        nil -> :ok
        msg -> send(self(), msg)
      end

      case appdata_get(:outcome) do
        :success -> scenario_success("done")
        :failure -> scenario_failure("boom")
        :aborted -> scenario_aborted("stopped")
      end
    end

    def cleanup(sip_ctx) do
      send(SIP.Context.appdata_get(sip_ctx, :probe), {:step, :cleanup})
      :ok
    end
  end

  # ── Harness ─────────────────────────────────────────────────────────────────

  # Run `Holder` in its own process, with the test as its parent (so
  # `{:child_exit, …}` lands in the test mailbox) and as the recipient of every
  # probe. Returns the scenario pid.
  defp run(opts) do
    test_pid = self()
    {:ok, dialog} = ProbeDialog.start_link(test_pid)
    on_exit(fn -> if Process.alive?(dialog), do: GenServer.stop(dialog) end)

    # A live process standing in for the media server handle: `safe_ms_call/3`
    # skips a dead one, which would skip the step we are timing.
    server = spawn(fn -> Process.sleep(:infinity) end)
    on_exit(fn -> Process.exit(server, :kill) end)

    appdata =
      %{dialog: dialog, fake_server: server, outcome: :success, probe: test_pid}
      |> Map.merge(Map.new(opts))

    spawn(fn ->
      Process.put(:fsl_test_pid, test_pid)

      send(
        test_pid,
        {:done,
         SIP.Scenario.Runner.run_instance(Holder,
           parent_pid: test_pid,
           self_name: :holder,
           appdata: appdata
         )}
      )
    end)
  end

  # The next `n` messages **in arrival order**.
  #
  # `assert_receive/2` cannot be used to read an order: it scans the whole
  # mailbox for a pattern, so a sequence of `assert_receive` calls passes
  # whatever order the messages actually arrived in — which is exactly the
  # mistake this file exists to catch. A bare `receive` takes the head.
  defp timeline(n) do
    Enum.map(1..n, fn i ->
      receive do
        msg -> msg
      after
        5_000 -> flunk("only #{i - 1} of #{n} steps arrived")
      end
    end)
  end

  # ── The order ───────────────────────────────────────────────────────────────

  test "the five steps run in order: children, legs, media, cleanup, parent" do
    run(dialog_end: {:dialog_terminated, self(), :normal})

    assert timeline(6) == [
             {:step, :children},
             {:step, {:legs, :BYE}},
             {:step, :media},
             {:step, :cleanup},
             {:child_exit, :holder, :success, "done"},
             {:done, :ok}
           ]

    # Nothing ran twice.
    refute_receive {:step, _}, 200
  end

  # ── release_media's bounded wait ────────────────────────────────────────────

  describe "release_media/1 waits for the dialog to end" do
    # The failure mode this guards: five seconds per teardown and no error. A
    # tagged event says just as much about the call being over as a bare one, and
    # a `release_media` that only matched the bare shape would stall for the full
    # timeout on every B2BUA outbound leg.
    test "the bare {:dialog_terminated, …} is accepted" do
      assert media_released_within(dialog_end: {:dialog_terminated, self(), :normal}) < 2_000
    end

    test "the tagged {:outbound, {:dialog_terminated, …}} is accepted too" do
      assert media_released_within(
               dialog_end: {:outbound, {:dialog_terminated, self(), :transport_down}}
             ) < 2_000
    end

    defp media_released_within(opts) do
      started = System.monotonic_time(:millisecond)
      run(opts)
      assert_receive {:step, :media}, 8_000
      System.monotonic_time(:millisecond) - started
    end
  end

  # ── every outcome ──────────────────────────────────────────────────────────

  describe "cleanup/1 and the parent notification" do
    # Covered for success by scenario_engine_test; the other two outcomes were
    # not, and they are the ones a scenario reaches when something went wrong —
    # precisely when a resource left behind matters.
    test "run on a failure" do
      run(outcome: :failure, dialog_end: {:dialog_terminated, self(), :normal})

      assert_receive {:step, :cleanup}, 5_000
      assert_receive {:child_exit, :holder, :failure, "boom"}, 5_000
      assert_receive {:done, {:error, "boom"}}, 5_000
    end

    test "run on an abort" do
      run(outcome: :aborted, dialog_end: {:dialog_terminated, self(), :normal})

      assert_receive {:step, :cleanup}, 5_000
      assert_receive {:child_exit, :holder, :aborted, "stopped"}, 5_000
      assert_receive {:done, {:aborted, "stopped"}}, 5_000
    end

    # …and the releases still happen, in the same order, on a failure. The
    # outcome decides what is reported, never what is freed.
    test "the order is the same whatever the outcome" do
      run(outcome: :failure, dialog_end: {:dialog_terminated, self(), :normal})

      assert timeline(6) == [
               {:step, :children},
               {:step, {:legs, :BYE}},
               {:step, :media},
               {:step, :cleanup},
               {:child_exit, :holder, :failure, "boom"},
               {:done, {:error, "boom"}}
             ]
    end
  end
end
