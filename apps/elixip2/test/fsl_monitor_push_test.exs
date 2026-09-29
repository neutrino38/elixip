defmodule SIP.Test.FSL.MonitorPush do
  @moduledoc """
  The monitor's **push protocol**, end to end on this link of the chain:

      FSL.Monitor  ──{:fsl_monitor, {:updated | :cleared, …}}──▶  a subscriber

  Two things here were renames no compiler could verify, and both happened in P2
  (finite-state-language/elixir/docs/extraction-plan.md §4.7): the registered
  name, `SIP.Scenario.Monitor` -> `FSL.Monitor`, and the message tag,
  `{:sip_scenario_monitor, …}` -> `{:fsl_monitor, …}`. A `handle_info/2` clause
  is not compile-checked — a missed one is a message that falls through and a live view
  that silently stops updating, which is how the kelescope monitor would be
  discovered to be broken. So the tag and the payload shapes are asserted
  literally, on both halves of the chain: this file for the monitor's own push,
  and `apps/kelixip/test/control_test.exs` for the join onto
  `{:kelix_monitor, …}` that consumes it.

  Also pinned: **whose columns are whose, and that the row is flat.**

  `scenario`, `state`, `event`, `event_type`, `command`, `command_type` and
  `account` are the machine's — the last one because "who this run serves" is a
  generic question even though only the embedding can answer it. `medias`,
  `mediaserver` and `outbound` are SIP's, declared with their defaults when the
  monitor is started (`SIP.FSL.Host.monitor_columns/0`), and the registry never
  learns which keys are which.

  And `row.medias`, not `row.extra.medias`. That is the decision of §4.7 and
  §8.4, and it is what keeps `ElixippCLI` (which declares its table by plain
  key) and `Kelix.InstancePool` (which declares its key list the same way)
  untouched by the extraction. A host's defaults travel with its columns because
  they mean something: `"n/a"` and `"none"` say "this call negotiated nothing",
  where a blank cell would read as "nobody measured".
  """
  use ExUnit.Case, async: false

  alias FSL.Monitor

  setup context do
    # A monitor started with no columns holds the machine's own and nothing else,
    # which is what a machine with no protocol gets. The describe block that
    # tests SIP's columns declares them, as its host does.
    columns = if context[:sip_columns], do: SIP.FSL.Host.monitor_columns(), else: []

    # The monitor is a named singleton and its columns are fixed at start, so a
    # test that wants a different set has to start its own. Stopped rather than
    # reused: `start/1` answers `:already_started` as success, which is what lets
    # everything else share one.
    if pid = Process.whereis(Monitor), do: GenServer.stop(pid)
    {:ok, _pid} = Monitor.start(columns: columns)
    slot = System.unique_integer([:positive])
    on_exit(fn -> Monitor.unsubscribe(self()) end)
    on_exit(fn -> Monitor.clear(slot) end)
    {:ok, slot: slot}
  end

  describe "the push messages" do
    test "a reported change pushes {:updated, slot, row}", %{slot: slot} do
      assert Monitor.subscribe(self()) == []

      Monitor.report(slot, "My.Scenario", "alice", "waiting", "send_INVITE", :sip)

      assert_receive {:fsl_monitor, {:updated, ^slot, row}}, 2_000

      assert row.scenario == "My.Scenario"
      assert row.account == "alice"
      assert row.state == "waiting"
      assert row.event == "send_INVITE"
      assert row.event_type == :sip
      assert row.slot == slot
      assert row.depth == 0
    end

    test "a cleared slot pushes {:cleared, slot}", %{slot: slot} do
      Monitor.subscribe(self())
      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, _row}}, 2_000

      Monitor.clear(slot)
      assert_receive {:fsl_monitor, {:cleared, ^slot}}, 2_000
    end

    test "a command pushes an update too", %{slot: slot} do
      Monitor.subscribe(self())
      Process.put(:scenario_slot_id, slot)
      on_exit(fn -> Process.delete(:scenario_slot_id) end)

      Monitor.note_command(:media, "media_connect")

      assert_receive {:fsl_monitor, {:updated, ^slot, row}}, 2_000
      assert row.command == "media_connect"
      assert row.command_type == :media
    end

    test "unsubscribe/1 stops the pushes", %{slot: slot} do
      Monitor.subscribe(self())
      assert Monitor.unsubscribe(self()) == :ok

      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)
      refute_receive {:fsl_monitor, _}, 300
    end

    test "a non-subscriber is told nothing", %{slot: slot} do
      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)
      refute_receive {:fsl_monitor, _}, 300
    end
  end

  describe "the row" do
    test "started with no columns, holds the machine's own and nothing else", %{slot: slot} do
      Monitor.subscribe(self())
      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)

      assert_receive {:fsl_monitor, {:updated, ^slot, row}}, 2_000

      assert Enum.sort(Map.keys(row)) ==
               Enum.sort([
                 :scenario,
                 :account,
                 :command,
                 :command_type,
                 :state,
                 :event,
                 :event_type,
                 :depth,
                 :slot
               ])

      # A column nobody declared is not invented.
      refute Map.has_key?(row, :medias)
    end

    @tag :sip_columns
    test "started with SIP's columns, carries them and their defaults", %{slot: slot} do
      Monitor.subscribe(self())
      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)

      assert_receive {:fsl_monitor, {:updated, ^slot, row}}, 2_000

      # The exact key set a consumer may read by plain key.
      assert Enum.sort(Map.keys(row)) ==
               Enum.sort([
                 :scenario,
                 :account,
                 :command,
                 :command_type,
                 :state,
                 :event,
                 :event_type,
                 :medias,
                 :mediaserver,
                 :outbound,
                 :traced,
                 :depth,
                 :slot
               ])

      # …with no nesting: this is what §4.7 keeps, and why the two consumers of
      # these rows do not change when the module moves.
      refute Map.has_key?(row, :extra)

      # "this call negotiated nothing", not "nobody measured".
      assert row.medias == "n/a"
      assert row.mediaserver == "none"
      assert row.outbound == "n/a"
      # not journalled until someone asks (kelictl debug <id> on)
      assert row.traced == false
    end

    @tag :sip_columns
    test "the three call-shape columns are written by name", %{slot: slot} do
      Monitor.subscribe(self())
      Process.put(:scenario_slot_id, slot)
      on_exit(fn -> Process.delete(:scenario_slot_id) end)

      Monitor.report(slot, "My.Scenario", "alice", "talking", "answered", :sip)
      assert_receive {:fsl_monitor, {:updated, ^slot, _}}, 2_000

      # The three call-shape helpers are SIP's — a list of media kinds rendered
      # as letters, a server's declared name, a URI rendered as a request target
      # — so they live on SIP's side of the seam and write through the generic
      # `FSL.Monitor.note/2` (extraction plan §2.2, §4.7).
      SIP.Scenario.Monitor.note_medias([:audio, :video])
      assert_receive {:fsl_monitor, {:updated, ^slot, %{medias: "AV"}}}, 2_000

      SIP.Scenario.Monitor.note_mediaserver("mcu1")
      assert_receive {:fsl_monitor, {:updated, ^slot, %{mediaserver: "mcu1"}}}, 2_000

      # A %SIP.Uri{} is rendered as a request target — the one SIP value this
      # column carries, and the one computation that stays in Elixip (§2.2).
      uri = %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "example.com"}
      SIP.Scenario.Monitor.note_outbound(uri)

      assert_receive {:fsl_monitor, {:updated, ^slot, %{outbound: "sip:bob@example.com"}}},
                     2_000

      # An answer that carried none of the three is "none", not "".
      SIP.Scenario.Monitor.note_medias([])
      assert_receive {:fsl_monitor, {:updated, ^slot, %{medias: "none"}}}, 2_000
    end

    @tag :sip_columns
    test "note/2 writes any declared column, and the registry asks no questions",
         %{slot: slot} do
      Monitor.subscribe(self())
      Process.put(:scenario_slot_id, slot)
      on_exit(fn -> Process.delete(:scenario_slot_id) end)

      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, _}}, 2_000

      Monitor.note(:medias, "AVT")
      assert_receive {:fsl_monitor, {:updated, ^slot, %{medias: "AVT"}}}, 2_000
    end

    test "note_account/1 overwrites the account, and a blank report preserves it", %{slot: slot} do
      Monitor.subscribe(self())
      Process.put(:scenario_slot_id, slot)
      on_exit(fn -> Process.delete(:scenario_slot_id) end)

      Monitor.report(slot, "My.Scenario", "", "waiting", "start", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, %{account: ""}}}, 2_000

      Monitor.note_account("alice@example.com")

      assert_receive {:fsl_monitor, {:updated, ^slot, %{account: "alice@example.com"}}},
                     2_000

      # An empty username is how the monitor is told "keep what you have" — a
      # UAS instance reports nothing after the first row, so the AOR a registrar
      # noted is not clobbered on every transition.
      Monitor.report(slot, "My.Scenario", "", "authenticating", "401", :sip)

      assert_receive {:fsl_monitor,
                      {:updated, ^slot, %{account: "alice@example.com", state: "authenticating"}}},
                     2_000
    end
  end

  describe "subscription bookkeeping" do
    # §4.12: `Kelix.Control.subscribe_monitor/1` subscribes and THEN takes the
    # snapshot, and that order is the only correct one — a change landing
    # between the two arrives as a push *and* in the snapshot (a duplicate
    # `upsert`, idempotent and harmless), where snapshot-first would lose it
    # entirely and leave the row stale until the call happened to change again.
    #
    # The plan closes that window by making `subscribe/1` return the snapshot
    # itself, taken inside the call that registers the subscriber. Today it
    # returns `:ok` and the snapshot is a second call; asserted so the change is
    # made on purpose rather than noticed later.
    test "subscribe/1 returns the snapshot, taken in the same call", %{slot: slot} do
      # A row that already exists before anyone subscribes.
      Monitor.report(slot, "Already.Running", "alice", "waiting", "start", nil)
      assert [%{slot: ^slot, scenario: "Already.Running"}] = Monitor.subscribe(self())

      # …and the subscription is live from that same call on.
      Monitor.report(slot, "Already.Running", "alice", "talking", "answered", :sip)
      assert_receive {:fsl_monitor, {:updated, ^slot, %{state: "talking"}}}, 2_000
    end

    test "an empty registry answers an empty snapshot, not nil" do
      assert Monitor.subscribe(self()) == []
    end

    # The window §4.12 is about: a subscriber needs the rows that exist AND the
    # changes from now on. Two calls leave a gap, and only one of the two orders
    # survives it — subscribe-then-snapshot turns a change landing in between
    # into a duplicate `upsert`, which is idempotent; snapshot-first loses the row
    # until the call happens to change again. One call has no order to get wrong.
    test "re-subscribing is idempotent and still answers the snapshot", %{slot: slot} do
      assert Monitor.subscribe(self()) == []
      Monitor.report(slot, "S", "alice", "waiting", "start", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, _}}, 2_000

      assert [%{slot: ^slot}] = Monitor.subscribe(self())

      # Not subscribed twice: one change, one push.
      Monitor.report(slot, "S", "alice", "talking", "ok", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, %{state: "talking"}}}, 2_000
      refute_receive {:fsl_monitor, {:updated, ^slot, %{state: "talking"}}}, 200
    end

    # §4.7's first defect. Invisible while the only in-tree subscriber was a
    # supervised singleton; not invisible in a package, where subscribing is the
    # normal way to use the thing and a set that only grows means every later
    # change is sent into the void.
    test "a subscriber that dies is dropped, with no unsubscribe", %{slot: slot} do
      test_pid = self()

      sub =
        spawn(fn ->
          Monitor.subscribe(self())
          send(test_pid, :subscribed)

          receive do
            msg -> send(test_pid, {:forwarded, msg})
          end
        end)

      assert_receive :subscribed, 2_000

      # It is really subscribed…
      Monitor.report(slot, "S", "alice", "waiting", "start", nil)
      assert_receive {:forwarded, {:fsl_monitor, {:updated, ^slot, _}}}, 2_000

      # …then it goes away, and the registry forgets it rather than pushing into
      # a dead mailbox for the life of the node.
      ref = Process.monitor(sub)
      Process.exit(sub, :kill)
      assert_receive {:DOWN, ^ref, :process, ^sub, _}, 2_000

      # Give the :DOWN time to reach the registry, then check it is gone by
      # asking the one thing that observes the set: a further change must not
      # raise, and the registry must still be alive and serving.
      Monitor.report(slot, "S", "alice", "talking", "ok", nil)
      assert [%{state: "talking"}] = Monitor.calls()
      assert Process.alive?(Process.whereis(Monitor))
      assert Monitor.subscribe(self()) != nil
    end

    test "unsubscribe/1 on a pid that never subscribed is a no-op" do
      assert Monitor.unsubscribe(self()) == :ok
    end

    test "the snapshot and the pushes agree on the row", %{slot: slot} do
      Monitor.subscribe(self())
      Monitor.report(slot, "My.Scenario", "alice", "waiting", "start", nil)

      assert_receive {:fsl_monitor, {:updated, ^slot, pushed}}, 2_000
      assert Enum.find(Monitor.calls(), &(&1.slot == slot)) == pushed
    end

    # A sub-FSM is keyed {parent_slot, name} and clearing the parent recycles the
    # child rows too — one `{:cleared, parent}` push, not one per row, which is
    # the shape `Kelix.InstancePool` reads (it forwards only integer slots).
    test "clearing a parent slot also clears its children", %{slot: slot} do
      child = {slot, :kid}
      Monitor.subscribe(self())

      Monitor.report(slot, "Parent", "alice", "waiting", "start", nil)
      Monitor.report(child, "Parent", "alice", "waiting", "start", nil)
      assert_receive {:fsl_monitor, {:updated, ^slot, _}}, 2_000
      assert_receive {:fsl_monitor, {:updated, ^child, %{depth: 1}}}, 2_000

      Monitor.clear(slot)
      assert_receive {:fsl_monitor, {:cleared, ^slot}}, 2_000

      assert Enum.find(Monitor.calls(), &(&1.slot == slot)) == nil
      assert Enum.find(Monitor.calls(), &(&1.slot == child)) == nil
    end
  end
end
