defmodule SIP.Test.FSL.EventTypeInference do
  @moduledoc """
  Event-type inference, one assertion per **pattern shape**.

  `on_events` classifies each of its clauses at macro-expansion time, from the
  shape of the pattern alone, and stores the verdict in `:scenario_event_type`
  so the trailing transition carries it to the monitor and to the sequence
  diagram. `scenario_engine_test` asserts one inference end to end; this is the
  whole table, which the extraction is about to split in two
  (finite-state-language/elixir/docs/extraction-plan.md §4.4):

  | First element of the pattern | Type | Whose, after the split |
  |---|---|---|
  | `:parent_msg` / `:child_msg` / `:child_exit` | `:scenario` | FSL |
  | `:scenario_ctl` | `:control` | FSL |
  | a declared SBB namespace (3-tuple) | `:scenario` | FSL |
  | `:ms_event` | `:media` | the host (`c:event_type/1`) |
  | any other atom, an integer, a bound variable | `:sip` | the host |
  | anything else (a non-tuple pattern) | `nil` | FSL |

  `:sip` as the fallback for anything unrecognised is what makes an unknown
  leading atom draw an arrow "from the peer" in the diagram, which is only
  meaningful when there is a peer — so it is a host decision and must not
  survive into FSL. Pinned here, on this side of the split.
  """
  use ExUnit.Case

  # One state, one clause per shape. Each clause reports the type the expansion
  # inferred — read from the process dictionary, which is where the
  # instrumentation puts it before the clause body runs — and `stay`s, so the
  # whole table is walked in one run.
  defmodule Table do
    use SIP.Scenario

    config(username: "alice", domain: "example.com")

    # What a face module's `__using__` does for the blocks a scenario calls. A
    # block's return starts with the namespace its author chose, so no table in
    # the framework can list them.
    SIP.Scenario.register_namespace(__MODULE__, :myblock)

    state initial_state do
      on_events do
        # ── FSL's own vocabulary ──────────────────────────────────────────────
        {:parent_msg, _payload} ->
          report()
          stay

        {:child_msg, _name, _payload} ->
          report()
          stay

        {:child_exit, _name, _outcome, _reason} ->
          report()
          stay

        {:scenario_ctl, :ping, _reason} ->
          report()
          stay

        # A block's return: {namespace, outcome, data}, the namespace declared
        # above. It came from nobody, so it is NOT an arrow from the peer.
        {:myblock, _outcome, _data} ->
          report()
          stay

        # ── the host's ────────────────────────────────────────────────────────
        {:ms_event, _ref, _event} ->
          report()
          stay

        # A method atom.
        {:INVITE, _req, _trans, _dlg} ->
          report()
          stay

        # A status code.
        {200, _rsp, _trans, _dlg} ->
          report()
          stay

        # A bound variable as the first element — a catch-all over tagged
        # events, which a B2BUA scenario writes.
        {_tag, _inner} ->
          report()
          stay

        # ── neither ───────────────────────────────────────────────────────────
        # Not a tuple at all: nothing to classify.
        :bare_atom ->
          report()
          stay

        :done ->
          scenario_success("table walked")
      after
        5_000 -> scenario_failure("the table was not walked")
      end
    end

    # A one-liner with no SIP meaning: reports the type the expansion inferred
    # for the clause it sits in.
    defp report do
      send(Process.get(:fsl_test_pid), {:inferred, Process.get(:scenario_event_type)})
    end
  end

  defp run(module) do
    test_pid = self()

    spawn(fn ->
      Process.put(:fsl_test_pid, test_pid)
      send(test_pid, {:done, SIP.Scenario.Runner.run_instance(module, [])})
    end)
  end

  # Each row: the event to send, and the type the expansion must have inferred
  # for the clause that matches it.
  @table [
    {{:parent_msg, :hello}, :scenario},
    {{:child_msg, :kid, :hello}, :scenario},
    {{:child_exit, :kid, :success, "done"}, :scenario},
    {{:scenario_ctl, :ping, nil}, :control},
    {{:myblock, :ok, %{}}, :scenario},
    {{:ms_event, :ref, :ice_connected}, :media},
    {{:INVITE, %{method: :INVITE}, nil, nil}, :sip},
    {{200, %{response: 200}, nil, nil}, :sip},
    {{:outbound, {:whatever}}, :sip},
    {:bare_atom, nil}
  ]

  test "every pattern shape is classified as the table says" do
    pid = run(Table)

    for {event, expected} <- @table do
      send(pid, event)

      assert_receive {:inferred, ^expected},
                     2_000,
                     "expected #{inspect(event)} to be typed #{inspect(expected)}"
    end

    send(pid, :done)
    assert_receive {:done, :ok}, 2_000
  end

  # The same reading, taken one clause at a time: a pattern the expansion cannot
  # classify leaves the slot empty rather than guessing, and a state body that
  # runs outside any clause starts from a cleared slot (`Process.delete/1` on
  # state entry) so a `goto` there is untyped.
  defmodule Untyped do
    use SIP.Scenario

    state initial_state do
      send(Process.get(:fsl_test_pid), {:on_entry, Process.get(:scenario_event_type)})
      goto(waiting)
    end

    state waiting do
      on_events do
        {:parent_msg, :go} -> goto(checking)
      after
        5_000 -> scenario_failure("no go")
      end
    end

    # Entered from a clause that DID set a type: the slot must be cleared again
    # on entry, or this state's own transition would inherit it.
    state checking do
      send(Process.get(:fsl_test_pid), {:on_entry, Process.get(:scenario_event_type)})
      scenario_success("cleared")
    end
  end

  test "the inferred type is cleared on every state entry" do
    pid = run(Untyped)

    assert_receive {:on_entry, nil}, 2_000
    send(pid, {:parent_msg, :go})
    assert_receive {:on_entry, nil}, 2_000
    assert_receive {:done, :ok}, 2_000
  end
end
