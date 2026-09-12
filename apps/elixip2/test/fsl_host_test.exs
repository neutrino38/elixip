defmodule SIP.Test.FSL.HostTest do
  @moduledoc """
  The host seam: a scenario names its embedding, the runner reads it back off
  the module, and the two first callbacks — `c:bootstrap/0` and
  `c:build_context/1` — are asked of it rather than hardcoded.

  Named at `use` time and recorded on the module, deliberately not read from a
  configuration key: two hosts then coexist in one VM, which is what makes the
  language testable with a trivial host of its own and what a published package
  needs (extraction plan §4, §4.6). The test of the seam is not that SIP still
  works — it will, whatever we do — but that a host FSL never heard of answers
  the same questions and gets the same engine.

  So every machine here says `use FSL.Machine, host: …`, which brings the
  language and nothing else: no SIP verbs, no `sip_ctx`, no stack to start. That
  is the spelling a second binding uses, and the one a published package has to
  make work.
  """
  use ExUnit.Case

  # A host that is not SIP's: it starts nothing, and reads the config block its
  # own way. Roughly what FSL.Test.Host becomes when the package has a suite of
  # its own (§5.3).
  defmodule Probe do
    @behaviour FSL.Host

    @impl true
    def bootstrap do
      send(Process.get(:fsl_test_pid), {:host, :bootstrap})
      :ok
    end

    @impl true
    def build_context(config) do
      send(Process.get(:fsl_test_pid), {:host, {:build_context, config}})
      # Its own reading of the block: everything under one key, which is a
      # perfectly good answer and not the one SIP gives.
      %FSL.Context{}
      |> FSL.Context.appdata_set(:settings, Map.new(config))
      |> FSL.Context.appdata_set(:probe, Process.get(:fsl_test_pid))
    end
  end

  # `use FSL.Machine` and not `use SIP.Scenario`: a machine of another binding
  # gets the language and nothing else — no SIP verbs, no `sip_ctx`, no stack.
  # After P2 that is spellable, and it is the path a published package needs to
  # work.
  defmodule Machine do
    use FSL.Machine, host: Probe

    config(colour: "blue", size: 3)

    state initial_state do
      send(appdata_get(:probe), {:settings, appdata_get(:settings)})
      scenario_success("done")
    end
  end

  defmodule PlainSip do
    use SIP.Scenario

    config(username: "alice", domain: "example.com")

    state initial_state do
      scenario_success("done")
    end
  end

  describe "which host a scenario runs against" do
    test "the one it named at use time" do
      assert FSL.Host.of(Machine) == Probe
      assert Machine.__fsl_host__() == Probe
    end

    test "SIP.FSL.Host by default, because SIP.Scenario says so" do
      assert FSL.Host.of(PlainSip) == SIP.FSL.Host
    end

    test "FSL.Host.Default for a module that declares none at all" do
      defmodule NoHost do
        def __scenario_states__, do: [:initial_state]
      end

      assert FSL.Host.of(NoHost) == FSL.Host.Default
    end

    # Two bindings in one VM, which is the property the whole arrangement buys.
    test "two scenarios in one VM answer to two different hosts" do
      assert FSL.Host.of(Machine) != FSL.Host.of(PlainSip)
    end
  end

  describe "c:build_context/1" do
    test "the scenario's own host builds its context" do
      test_pid = self()

      spawn(fn ->
        Process.put(:fsl_test_pid, test_pid)

        send(
          test_pid,
          {:done, SIP.Scenario.Runner.run_instance(Machine, appdata: %{probe: test_pid})}
        )
      end)

      assert_receive {:host, {:build_context, config}}, 2_000
      assert Keyword.equal?(config, colour: "blue", size: 3)

      # …and the context the machine runs on is the one that host produced,
      # not a %SIP.Context{} the runner decided on.
      assert_receive {:settings, %{colour: "blue", size: 3}}, 2_000
      assert_receive {:done, :ok}, 2_000
    end

    test "SIP's routes each kind of key to its own destination" do
      # The full routing table is pinned in fsl_build_context_test; what this
      # asserts is that it is the HOST that holds it now.
      ctx = SIP.FSL.Host.build_context(username: "bob", domain: "example.com", other: 1)

      assert %SIP.Context{username: "bob", domain: "example.com"} = ctx
      assert FSL.Context.appdata_get(ctx, :other) == 1
      assert SIP.Scenario.Runner.build_context(username: "bob").username == "bob"
    end

    test "the default host puts everything in appdata" do
      ctx = FSL.Host.Default.build_context(username: "bob", anything: %{a: 1})

      assert %FSL.Context{} = ctx
      assert FSL.Context.appdata_get(ctx, :username) == "bob"
      assert FSL.Context.appdata_get(ctx, :anything) == %{a: 1}
    end
  end

  describe "c:bootstrap/0" do
    test "run/2 starts what the scenario's own host starts" do
      test_pid = self()

      spawn(fn ->
        Process.put(:fsl_test_pid, test_pid)
        send(test_pid, {:done, Machine.run(true)})
      end)

      assert_receive {:host, :bootstrap}, 2_000
      assert_receive {:done, :ok}, 2_000
    end

    test "SIP's starts the SIP layers, and says :ok twice in a row" do
      assert SIP.FSL.Host.bootstrap() == :ok
      assert SIP.FSL.Host.bootstrap() == :ok
      assert Process.whereis(Registry.SIP.Transac)
      assert Process.whereis(Registry.SIPDialog)

      # The old spellings still work: three apps and half a dozen tests call them.
      assert SIP.Scenario.Runner.bootstrap_stack() == :ok
      assert SIP.Scenario.start_stack() == :ok
    end

    test "the default host starts nothing" do
      assert FSL.Host.Default.bootstrap() == :ok
    end
  end

  describe "FSL.Host.call/4" do
    # A binding implements what it needs and no more: every callback is
    # optional, so a machine with no protocol runs with no host written.
    test "falls back to the given default when the host does not implement it" do
      defmodule Silent do
        def __fsl_host__, do: __MODULE__
      end

      assert FSL.Host.call(Silent, :bootstrap, [], :nothing_to_start) == :nothing_to_start
      assert FSL.Host.call(Silent, :build_context, [[]], %FSL.Context{}) == %FSL.Context{}
    end
  end

  describe "c:apply_run_opts/2" do
    # FSL owns :parent_pid, :self_name, :appdata, :slot_id and
    # :config_overrides; everything else at run_instance/2 names something only
    # the binding understands.
    test "the binding's own run options reach its host, and FSL's do not" do
      test_pid = self()

      defmodule OptsHost do
        @behaviour FSL.Host

        @impl true
        def build_context(_config), do: %FSL.Context{}

        @impl true
        def apply_run_opts(ctx, opts) do
          FSL.Context.appdata_set(ctx, :seen_opts, opts)
        end
      end

      defmodule TakesOpts do
        use FSL.Machine, host: OptsHost

        state initial_state do
          send(appdata_get(:probe), {:seen, appdata_get(:seen_opts), fsl_ctx.parent_pid})
          scenario_success("done")
        end
      end

      spawn(fn ->
        SIP.Scenario.Runner.run_instance(TakesOpts,
          parent_pid: test_pid,
          self_name: :kid,
          appdata: %{probe: test_pid},
          my_own_option: :interesting
        )
      end)

      assert_receive {:seen, opts, parent}, 2_000
      # Only the binding's key was handed over…
      assert opts == [my_own_option: :interesting]
      # …and FSL applied its own itself.
      assert parent == test_pid
    end

    test "SIP's reads the dialog and the request an inbound instance was given" do
      dialog = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(dialog, :kill) end)
      req = %{method: :REGISTER, ruri: nil}

      ctx = SIP.FSL.Host.apply_run_opts(%SIP.Context{}, dialog_pid: dialog, inbound_request: req)

      assert ctx.dialogpid == dialog
      assert FSL.Context.appdata_get(ctx, :inbound_request) == req
    end
  end

  describe "c:account/2" do
    # The full SIP reading is pinned in scenario_monitor_account_test; what this
    # asserts is that it is the host that answers now, and that a host with
    # nothing to say leaves the column empty.
    test "SIP's names the config account for a UAC and the asserted one for a UAS" do
      uac = %SIP.Context{username: "alice"}
      assert SIP.FSL.Host.account(uac, :initial) == "alice"
      assert SIP.FSL.Host.account(uac, :subsequent) == "alice"
    end

    test "a host that implements none leaves the column empty" do
      defmodule Accountless do
        def __fsl_host__, do: __MODULE__
      end

      assert FSL.Host.call(Accountless, :account, [%FSL.Context{}, :initial], "") == ""
    end
  end

  describe "c:finalize/1" do
    # The order of the five teardown steps is pinned in fsl_teardown_order_test.
    # What matters here is that the middle one is the host's, whole: the
    # B2BUA-before-media ordering and the bounded wait are one rule and must stay
    # in one place.
    test "SIP's releases the legs then the media, and is a no-op with neither" do
      ctx = %SIP.Context{}
      assert SIP.FSL.Host.finalize(ctx) == ctx
    end

    test "a host that implements none leaves the context untouched" do
      defmodule Untidy do
        def __fsl_host__, do: __MODULE__
      end

      ctx = %FSL.Context{appdata: %{a: 1}}
      assert FSL.Host.call(Untidy, :finalize, [ctx], ctx) == ctx
    end
  end

  describe "c:spawn_child/2" do
    # The kind is opaque to FSL (§4.11): `uas :register` is a SIP annotation, and
    # the language has no business knowing the role names of a protocol.
    test "the kind is passed through untouched, whatever it is" do
      defmodule ChildHost do
        def __fsl_host__, do: __MODULE__
        def spawn_child(kind, pid), do: send(pid, {:child_kind, kind})
      end

      FSL.Host.call(ChildHost, :spawn_child, [:something_only_a_binding_knows, self()], :ok)
      assert_receive {:child_kind, :something_only_a_binding_knows}
    end
  end

  # ── The three compile-time hooks ────────────────────────────────────────────

  # A binding FSL has never heard of: it names its own event type, and it wants
  # a clause of its own in every wait. This is the yardstick of §4.10 — the test
  # of whether a seam is cut in the right place is not "does SIP still work" but
  # whether a second binding could be written without touching FSL.
  defmodule MatrixHost do
    @behaviour FSL.Host

    @impl true
    def build_context(config) do
      Enum.reduce(config, %FSL.Context{}, fn {k, v}, ctx ->
        FSL.Context.appdata_set(ctx, k, v)
      end)
    end

    # `:matrix` is a type FSL has no table entry for, and it must survive to the
    # monitor and to the diagram exactly as `:sip` does.
    @impl true
    def event_type(:room_event), do: :matrix
    def event_type(_element), do: nil

    # Its own failure domain: the homeserver going away.
    @impl true
    def injected_clauses(ctx) do
      [
        {:server_gone,
         quote do
           {:homeserver, :gone} ->
             {:goto, :__shutdown__, "homeserver gone", :matrix, unquote(ctx)}
         end
         |> hd()}
      ]
    end

    @impl true
    def clause_covers?(:server_gone, {:homeserver, _any}), do: true
    def clause_covers?(_name, _pattern), do: false
  end

  defmodule MatrixBot do
    use FSL.Machine, host: MatrixHost

    state initial_state do
      on_events do
        {:room_event, _payload} ->
          send(appdata_get(:probe), {:typed, Process.get(:scenario_event_type)})
          scenario_success("read the room")
      after
        5_000 -> scenario_failure("nothing came")
      end
    end
  end

  # Handles the homeserver itself, so the host's clause must not be injected
  # ahead of it.
  defmodule MatrixAware do
    use FSL.Machine, host: MatrixHost

    state initial_state do
      on_events do
        {:homeserver, what} -> scenario_success("mine: #{inspect(what)}")
      after
        5_000 -> scenario_failure("clause never ran")
      end
    end
  end

  defp run_bot(module) do
    test_pid = self()

    spawn(fn ->
      send(
        test_pid,
        {:done, SIP.Scenario.Runner.run_instance(module, appdata: %{probe: test_pid})}
      )
    end)
  end

  describe "c:event_type/1" do
    test "a type the language has no table entry for survives" do
      pid = run_bot(MatrixBot)
      send(pid, {:room_event, %{}})

      assert_receive {:typed, :matrix}, 5_000
      assert_receive {:done, :ok}, 5_000
    end

    test "what the language owns, the language answers — with no host at all" do
      # :parent_msg / :child_msg / :child_exit are :scenario and :scenario_ctl is
      # :control whatever the binding is, so a host that answers nothing still
      # gets its inter-FSM messages typed.
      assert SIP.FSL.Host.event_type(:ms_event) == :media
      assert SIP.FSL.Host.event_type(:INVITE) == :sip
      assert SIP.FSL.Host.event_type(200) == :sip
      # A bound variable in the pattern, as quoted AST.
      assert SIP.FSL.Host.event_type({:tag, [], nil}) == :sip
      assert SIP.FSL.Host.event_type("not a pattern element") == nil
    end
  end

  describe "c:injected_clauses/1 and c:clause_covers?/2" do
    test "the host's own clause is injected, and ends the run" do
      pid = run_bot(MatrixBot)
      send(pid, {:homeserver, :gone})

      # Aborted, not failed: nothing went wrong with the machine, its
      # homeserver went away — the same reading SIP gives a dead media server.
      assert_receive {:done, {:aborted, _reason}}, 5_000
    end

    test "…unless the scenario already covers it" do
      pid = run_bot(MatrixAware)
      send(pid, {:homeserver, :gone})

      assert_receive {:done, :ok}, 5_000
    end

    test "a host with no clauses of its own adds none" do
      assert FSL.Host.hook(FSL.Host.Default, :injected_clauses, [Macro.var(:ctx, nil)], []) == []
      assert FSL.Host.hook(FSL.Host.Default, :clause_covers?, [:whatever, nil], false) == false
    end

    test "SIP's clause is the media server going away, generously suppressed" do
      assert [{:media_down, clause}] =
               SIP.FSL.Host.injected_clauses(Macro.var(:sip_ctx, nil))

      assert Macro.to_string(clause) =~ ":server_disconnected"
      assert Macro.to_string(clause) =~ "media server down"

      # The generosity, clause by clause (the end-to-end rule is pinned in
      # fsl_injected_clause_suppression_test).
      covers? = &SIP.FSL.Host.clause_covers?(:media_down, &1)

      assert covers?.({:{}, [], [:ms_event, {:_, [], nil}, :server_disconnected]})
      assert covers?.({:{}, [], [:ms_event, {:_, [], nil}, {:evt, [], nil}]})
      assert covers?.({:event, [], nil})
      refute covers?.({:{}, [], [:ms_event, {:_, [], nil}, :ice_connected]})
      # …and it says nothing about a clause it was not asked about.
      refute SIP.FSL.Host.clause_covers?(:something_else, {:event, [], nil})
    end
  end
end
