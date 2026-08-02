defmodule Kelix.ControlTest do
  # Kelix.Control verbs (design §10.1). The :kelixip app is running, so the
  # surfaces (InstancePool, MediaPool, Domains, ScriptRegistry, ModuleRegistry)
  # are live singletons — empty at boot.
  use ExUnit.Case, async: false

  alias Kelix.Control

  # a valid registrar script that stays alive until told to shut down
  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")

  # a module exposing a control command, and one without a control surface
  defmodule FakeCtl do
    def handle_control("ping", _args), do: {:ok, :pong}
    def handle_control(_cmd, _args), do: {:error, :unknown_cmd}
  end

  defmodule BareMod do
  end

  describe "module-contributed commands" do
    test "module_command/3 routes to the module's handle_control/2" do
      Kelix.ModuleRegistry.register("fake", FakeCtl, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("fake") end)

      assert Control.module_command("fake", "ping", %{}) == {:ok, :pong}
      assert Control.module_command("fake", "nope", %{}) == {:error, :unknown_cmd}
    end

    test "module_command/3 on a module without a control surface" do
      Kelix.ModuleRegistry.register("bare", BareMod, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("bare") end)

      assert Control.module_command("bare", "x", %{}) == {:error, :no_command_surface}
    end

    test "module_reload/1 on an unconfigured module" do
      assert Control.module_reload("registrar") == {:error, :not_configured}
    end
  end

  describe "module status (generic, the core names no module)" do
    defmodule Reporting do
      def status(), do: %{conferences: 2, participants: 5}
    end

    defmodule Quiet do
      def describe(), do: %{version: "1.0", exports: []}
    end

    setup do
      Kelix.ModuleRegistry.register("reporting", Reporting, %{})
      Kelix.ModuleRegistry.register("quiet", Quiet, %{})

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("reporting")
        Kelix.ModuleRegistry.unregister("quiet")
      end)

      :ok
    end

    test "status/0 carries what each module reports, and nothing for the silent ones" do
      status = Control.status().module_status

      assert status["reporting"] == %{conferences: 2, participants: 5}
      refute Map.has_key?(status, "quiet")
    end

    test "kelictl renders one line per reporting module" do
      {0, text} = Kelix.Control.CLI.run(["status"], node())

      assert text =~ "reporting:"
      assert text =~ "conferences 2"
      refute text =~ "quiet:"
    end
  end

  describe "domains/0 + domain/1" do
    @domains_toml """
    [[domain]]
    name = "ctl.example.com"
    aliases = ["ctl.example.fr"]
    max_calls = 500

    [domain.registrar]
    script = "registrar-example.exs"
    default_expires = 3600

    [[domain.call]]
    pattern = "0[1-9]XXXXXXXX"
    script = "user2pstn.exs"

    [[domain.call]]
    default = true
    script = "catchall.exs"

    [[domain]]
    name = "bare.example.net"
    """

    setup do
      path =
        Path.join(System.tmp_dir!(), "ctl_domains_#{System.unique_integer([:positive])}.toml")

      File.write!(path, @domains_toml)
      assert :ok = Kelix.Domains.reload(path)

      # the singleton is shared with the rest of the suite: leave it empty again
      on_exit(fn ->
        empty = path <> ".empty"
        File.write!(empty, "")
        Kelix.Domains.reload(empty)
        File.rm(path)
        File.rm(empty)
      end)

      :ok
    end

    test "domains/0 lists every served domain, in domains.toml order" do
      assert [first, second] = Control.domains()
      assert first.name == "ctl.example.com"
      assert second.name == "bare.example.net"
    end

    test "domains/0 carries the properties and the live counters" do
      [d, bare] = Control.domains()

      assert d.aliases == ["ctl.example.fr"]
      assert d.max_calls == 500
      assert d.functions == [:registrar, :calls]
      assert d.registrar == %{script: "registrar-example.exs", default_expires: 3600}
      assert d.presence == nil
      assert d.active_calls == 0
      assert d.registrations == 0

      # a domain with no function block serves nothing — and says so
      assert bare.functions == []
      assert bare.max_calls == nil
      assert bare.dial_plan == []
    end

    test "the dial-plan keeps its order, the catch-all marked as such" do
      [d, _bare] = Control.domains()

      assert d.dial_plan == [
               %{pattern: "0[1-9]XXXXXXXX", default: false, script: "user2pstn.exs"},
               %{pattern: nil, default: true, script: "catchall.exs"}
             ]
    end

    test "domain/1 resolves a name or an alias, case-insensitively" do
      assert {:ok, d} = Control.domain("ctl.example.com")
      assert d.name == "ctl.example.com"

      # an operator sees the alias on the wire, so `show` must answer for it
      assert {:ok, ^d} = Control.domain("CTL.EXAMPLE.FR")
      assert Control.domain("unknown.example.org") == {:error, :not_found}
    end

    test "domain/1 counts the calls in progress on that domain only" do
      spawn_watched("ctl.example.com")

      assert {:ok, d} = Control.domain("ctl.example.com")
      assert d.active_calls == 1
      assert {:ok, %{active_calls: 0}} = Control.domain("bare.example.net")
    end
  end

  describe "registrations/1 + registration/1" do
    @reg_domains """
    [[domain]]
    name = "reg.example.com"

    [[domain]]
    name = "other.example.net"
    """

    # The registrar is a loadable module, absent from the core: Control reaches it
    # through the module registry, so a fake exporting `all/1` is all it takes. The
    # bindings are plain maps — Control matches them structurally for that reason.
    defmodule FakeRegistrar do
      @uri %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "10.0.0.9", port: 5060}

      # fixed by the setup, so two reads of the same binding are the same binding
      def all("reg.example.com") do
        %{
          "alice" => [
            %{
              contact: @uri,
              expires_at: Application.get_env(:kelixip, :fake_reg_expires_at),
              # behind a NAT this is *not* what the contact URI says
              received: {"udp", {10, 0, 0, 9}, 45_112},
              flow_module: SIP.Transport.UDP,
              instance: "<urn:uuid:f81d4fae>",
              reg_id: "1",
              methods: nil
            }
          ]
        }
      end

      # the same user-part, registered in a second domain
      def all("other.example.net"),
        do: %{"alice" => [%{contact: @uri, expires_at: nil}]}

      def all(_domain), do: %{}
    end

    setup do
      path = Path.join(System.tmp_dir!(), "ctl_regs_#{System.unique_integer([:positive])}.toml")
      File.write!(path, @reg_domains)
      assert :ok = Kelix.Domains.reload(path)
      Kelix.ModuleRegistry.register("registrar", FakeRegistrar, %{})
      Application.put_env(:kelixip, :fake_reg_expires_at, DateTime.add(DateTime.utc_now(), 340))

      on_exit(fn ->
        Application.delete_env(:kelixip, :fake_reg_expires_at)
        Kelix.ModuleRegistry.unregister("registrar")
        empty = path <> ".empty"
        File.write!(empty, "")
        Kelix.Domains.reload(empty)
        File.rm(path)
        File.rm(empty)
      end)

      :ok
    end

    test "registrations/1 renders each binding with what the registrar stored" do
      assert [%{domain: "reg.example.com", aor: "alice", contacts: [c]} | _] =
               Control.registrations("alice@reg.example.com")

      # the default port is not spelled out — this is the stack's own serialization
      assert c.uri == "sip:alice@10.0.0.9"
      # the operator question is the remaining time, not an absolute instant
      assert c.expires_in in 339..340
      assert c.source == "udp 10.0.0.9:45112"
      assert c.transport == "udp"
      assert c.instance == "<urn:uuid:f81d4fae>"
      assert c.reg_id == "1"
      assert c.methods == nil
    end

    test "registration/1 answers for every domain a bare user-part is in" do
      assert {:ok, rows} = Control.registration("alice")
      assert Enum.map(rows, & &1.domain) == ["reg.example.com", "other.example.net"]

      # …and `user@domain` narrows it to one, with the same row as the list holds
      # (bar `expires_in`, which counts down between the two reads)
      assert {:ok, [row]} = Control.registration("alice@reg.example.com")
      assert stable(row) == stable(hd(Control.registrations("alice@reg.example.com")))
    end

    test "registration/1 on an unregistered AOR" do
      assert Control.registration("ghost@reg.example.com") == {:error, :not_found}
    end

    defp stable(row),
      do: %{row | contacts: Enum.map(row.contacts, &Map.drop(&1, [:expires_in]))}

    test "a binding with no expiry does not crash the rendering" do
      assert {:ok, [%{contacts: [c]}]} = Control.registration("alice@other.example.net")
      assert c.expires_in == nil
      assert c.source == nil
      assert c.transport == nil
    end
  end

  describe "mediaservers/0 + mediaserver/1" do
    # entries as Kelix.Config decodes them (the pool no longer parses TOML)
    @pool [
      %{name: "mcu1", module: :mockup, url: "http://10.0.0.1:8080", enabled: true},
      %{name: "mcu2", module: :mendooze, url: "http://10.0.0.2:8080", enabled: false}
    ]

    # A module that drives media servers, i.e. one exporting `mediaserver/1` — the
    # mcu module does, and holds a control channel whose health is not the pool's.
    defmodule FakeMcu do
      def mediaserver("mcu1"),
        do: {:ok, %{name: "mcu1", status: :up, queue_id: "q-1", client: self()}}

      def mediaserver(_name), do: :error
    end

    setup do
      # The app runs an (empty) Kelix.MediaPool singleton and Control reads it by
      # name: stand a populated one in its place for the duration of the test.
      :ok = Supervisor.terminate_child(Kelix.Supervisor, Kelix.MediaPool)
      on_exit(fn -> Supervisor.restart_child(Kelix.Supervisor, Kelix.MediaPool) end)

      start_supervised!(
        {Kelix.MediaPool,
         pool: @pool, probe: fn e -> e.name == "mcu1" end, first_check_ms: 60_000}
      )

      # deterministic health: probe now rather than waiting for the periodic tick
      :ok = Kelix.MediaPool.check_health()
      :ok
    end

    test "mediaservers/0 lists the pool in order, with the switch and the probe" do
      assert [mcu1, mcu2] = Control.mediaservers()

      assert %{
               name: "mcu1",
               module: :mockup,
               url: "http://10.0.0.1:8080",
               enabled: true,
               healthy: true
             } = mcu1

      # disabled by config, and down as far as the pool's own probe is concerned
      assert %{name: "mcu2", module: :mendooze, enabled: false, healthy: false} = mcu2
    end

    test "mediaserver/1 returns exactly what the list holds for that entry" do
      assert {:ok, mcu1} = Control.mediaserver("mcu1")
      assert mcu1 == hd(Control.mediaservers())
      assert Control.mediaserver("ghost") == {:error, :not_found}
    end

    test "a module driving the server contributes its own view of it" do
      Kelix.ModuleRegistry.register("fakemcu", FakeMcu, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("fakemcu") end)

      assert {:ok, %{modules: modules}} = Control.mediaserver("mcu1")
      # the module's shape, minus what means nothing outside the node (`client`)
      assert modules == %{"fakemcu" => %{name: "mcu1", status: :up, queue_id: "q-1"}}

      # a server that module does not drive: no entry rather than a fabricated one
      assert {:ok, %{modules: %{}}} = Control.mediaserver("mcu2")
    end
  end

  describe "read + simple verbs" do
    test "status/0 aggregates node + surfaces" do
      s = Control.status()
      assert s.node == node()
      assert is_integer(s.uptime_ms)
      assert is_map(s.instances)
      assert is_list(s.media_pool)
      assert is_list(s.modules)
    end

    # It used to read SIP.Scenario.Monitor — elixipp's --monitor store, which the
    # server never starts — so it was always empty and `kelictl stop <id>` had no
    # way to learn an id.
    # Instances of neighbouring tests may still be draining (the pool frees a slot
    # on an async :DOWN), so every assertion here is scoped to its own domain.
    defp spawn_watched(domain) do
      route = %{domain: domain, function: :registrar, script: @waiter, max_calls: nil}
      assert {:accept, pid} = Kelix.InstancePool.accept(route, nil, %{method: :REGISTER})
      on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
      pid
    end

    defp row_for(domain), do: Enum.find(Control.monitor(), &(&1.domain == domain))

    # The FSM store is fed by casts, so let the first transition land.
    defp await_state(domain) do
      Enum.reduce_while(1..50, nil, fn _i, _acc ->
        case row_for(domain) do
          %{state: s} = row when s != "" -> {:halt, row}
          _ -> Process.sleep(20) && {:cont, nil}
        end
      end)
    end

    test "monitor/0 lists the running instances, with the id `stop` takes" do
      pid = spawn_watched("mon.test")

      assert row = await_state("mon.test")
      assert row.function == :registrar
      assert is_integer(row.id)
      assert row.pid == pid

      # …joined with the FSM view: which state the scenario sits in, and on what
      # event. Reading that is the point of a DSL-driven server.
      assert row.state == "initial_state"
      assert row.scenario != ""

      # the id is usable as advertised
      assert Control.shutdown_scenario(row.id) == :ok
    end

    test "monitor/0 degrades to empty FSM columns rather than failing" do
      spawn_watched("nofsm.test")
      assert row = await_state("nofsm.test")

      # drop the FSM row: the pool still knows the instance, the join must not care
      SIP.Scenario.Monitor.clear(row.id)

      assert row = row_for("nofsm.test")
      assert row.state == ""
      assert row.command == ""
    end

    test "set_log_level/1 applies a valid level and rejects a bad one" do
      prev = Logger.level()
      on_exit(fn -> Logger.configure(level: prev) end)

      assert Control.set_log_level("debug") == :ok
      assert Logger.level() == :debug
      assert Control.set_log_level("nope") == {:error, :invalid_level}
    end

    test "reload_domains/0 needs a configured path" do
      prev = Application.get_env(:kelixip, :domains_path)
      Application.delete_env(:kelixip, :domains_path)
      on_exit(fn -> if prev, do: Application.put_env(:kelixip, :domains_path, prev) end)

      assert Control.reload_domains() == {:error, :no_domains_path}
    end

    test "reload_script/2 reports a per-name result" do
      res = Control.reload_script(["does-not-exist"])
      assert match?({:error, _}, res["does-not-exist"])
    end

    test "shutdown_scenario/1 on an unknown id" do
      assert Control.shutdown_scenario(999_999) == {:error, :not_found}
    end

    test "mediaserver_toggle/2 on an unknown MCU" do
      assert Control.mediaserver_toggle("ghost", false) == {:error, :unknown}
    end

    test "graceful_shutdown/0 drains without stopping the VM when suppressed" do
      Application.put_env(:kelixip, :graceful_stop, false)
      # 0 keeps the whole sequence synchronous (and leaves no Task sleeping through
      # the rest of the suite); the drain window is exercised in its own test below.
      Application.put_env(:kelixip, :drain_wait_ms, 0)

      on_exit(fn ->
        Application.delete_env(:kelixip, :graceful_stop)
        Application.delete_env(:kelixip, :drain_wait_ms)
        Control.undrain()
      end)

      assert Control.graceful_shutdown() == :ok
      # The node took itself out of the upstream rotation before tearing anything down.
      assert Control.draining?()
    end

    test "drain/0 and undrain/0 flip what the OPTIONS ping is answered" do
      on_exit(fn -> Control.undrain() end)

      refute Control.draining?()
      assert {:reply, 200, _, _} = Kelix.Options.on_options(%{method: :OPTIONS}, self())

      assert Control.drain() == :ok
      assert Control.draining?()

      # This is the whole point of draining: upstream stops sending, nothing in flight
      # is touched.
      assert {:reply, 503, _, []} = Kelix.Options.on_options(%{method: :OPTIONS}, self())

      assert Control.undrain() == :ok
      assert {:reply, 200, _, _} = Kelix.Options.on_options(%{method: :OPTIONS}, self())
    end

    test "module_command/3 on an unknown module" do
      assert Control.module_command("ghost", "do", %{}) == {:error, :unknown_module}
    end
  end
end
