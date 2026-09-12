defmodule SIP.Test.SpawnFsm do
  @moduledoc """
  What SIP adds to a spawned child: `c:FSL.Host.spawn_child/2`.

  A `:uas_invite` child does not act on its own — it waits for an inbound
  INVITE — so spawning one registers it with `SIP.Scenario.CallDispatcher` and
  installs that as the call-processing module, unless the application already
  configured one. The kind is opaque to the language: `uas :invite` is a SIP
  annotation, and FSL hands whatever is in the slot to the host without looking
  (extraction plan §4.11).

  The language's own half of `spawn_fsm` — the message families, cooperative
  shutdown, path resolution, the deprecated event shapes — is tested in the
  package (`test/spawn_fsm_test.exs`).
  """
  use ExUnit.Case

  # A UAS call scenario child: waits for the inbound INVITE routed to it by the
  # call dispatcher installed by spawn_fsm.
  defmodule UasChild do
    use SIP.Scenario

    uas(:invite)
    config(domain: "example.com")

    state initial_state do
      on_events do
        {:INVITE, _req, _t, _dlg} -> scenario_success("got INVITE")
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end
  end

  defmodule SomeOtherCallServer do
  end

  describe "spawn_fsm of a :uas_invite scenario" do
    # The ConfigRegistry is a global Agent shared across test modules: save and
    # restore the call processing module so these tests neither depend on nor
    # disturb the others.
    setup do
      {:ok, _} = SIP.Session.ConfigRegistry.start()
      prev = SIP.Session.ConfigRegistry.get_call_processing_module()
      :ok = SIP.Session.ConfigRegistry.set_call_processing_module(nil)
      on_exit(fn -> SIP.Session.ConfigRegistry.set_call_processing_module(prev) end)
      :ok
    end

    test "installs the call dispatcher and routes one INVITE to the waiting child" do
      ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
      %FSL.Child{pid: child_pid} = ctx.appdata[:__children__][:callee]

      assert SIP.Session.ConfigRegistry.get_call_processing_module() ==
               SIP.Scenario.CallDispatcher

      # The first INVITE is bound to the waiting child…
      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:accept, child_pid}

      # …and with no child left the next one is rejected 486.
      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:reject, 486, "Busy Here"}

      # Deliver the INVITE (as the dialog layer would after :accept) so the
      # child runs to completion.
      send(child_pid, {:INVITE, %{method: :INVITE, body: []}, self(), self()})
      assert_receive {:child_exit, :callee, :success, _}, 1_000
    end

    test "does not override an already configured call processing module" do
      :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SomeOtherCallServer)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
          %FSL.Child{pid: child_pid} = ctx.appdata[:__children__][:callee]

          # Wind the child down so it does not sit in its 5s INVITE wait.
          send(child_pid, {:scenario_ctl, :shutdown, :test})
          assert_receive {:child_exit, :callee, :aborted, _}, 1_000
        end)

      assert log =~ "already configured"
      assert SIP.Session.ConfigRegistry.get_call_processing_module() == SomeOtherCallServer
    end

    test "a dead waiting child is purged from the dispatcher queue" do
      ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
      %FSL.Child{pid: child_pid, ref: ref} = ctx.appdata[:__children__][:callee]

      Process.exit(child_pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^child_pid, :killed}, 1_000
      # The dispatcher's own :DOWN is processed before our next call (same mailbox).
      _ = :sys.get_state(SIP.Scenario.CallDispatcher)

      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:reject, 486, "Busy Here"}
    end
  end
end
