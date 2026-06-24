defmodule SIP.Test.UASRegister do
  use ExUnit.Case
  require Logger

  # The reference UAS REGISTER scenario, compiled once from its .exs file. It is
  # the real application code under test (challenge / accept helpers live in it).
  @scenario SIP.Scenario.Loader.load_file!("scenarios/uas_register.exs")

  # A scenario that simply blocks (until cooperatively shut down), to test the
  # registrar concurrency quota without relying on real SIP traffic. It needs no
  # REGISTER reply helpers, so it is a plain :uas_register scenario.
  defmodule Fixture.Blocking do
    use SIP.Scenario
    uas(:register)
    config(domain: "test")

    state initial_state do
      on_events do
        {:never, _} -> goto(loop)
      after
        60_000 -> scenario_success("timeout")
      end
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp restart_registrar(module, max) do
    case Process.whereis(Elixip.RegistrarUAS) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    {:ok, _pid} = Elixip.RegistrarUAS.start_link(scenario_module: module, max_instances: max)
    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.RegistrarUAS)
  end

  # Parse a REGISTER message file, mark it for the mockup transport, inject it as
  # an inbound message and arrange for SIP responses to come back to the test.
  defp inject_register(file) do
    {:ok, msg} = File.read(file)

    {:ok, parsed} =
      SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
        IO.puts("#{errmsg}\nline #{lineno}: #{line}\ncode #{code}")
      end)

    upd_uri = SIP.Uri.set_uri_param(parsed.ruri, "unittest", "1")
    parsed = SIP.Msg.Ops.update_sip_msg(parsed, {:ruri, upd_uri})
    routed = SIP.Transport.Selector.select_transport(upd_uri)

    # Route UAS responses back to this test process.
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    send(routed.tp_pid, {:recv, parsed})
    routed.tp_pid
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  # ── Type annotation / loader ─────────────────────────────────────────────────

  test "uas annotation sets the scenario type" do
    assert @scenario.__scenario_type__() == :uas_register
    assert SIP.Scenario.Loader.scenario_type(@scenario) == :uas_register
  end

  test "a plain UAC scenario defaults to :uac" do
    defmodule Fixture.PlainUAC do
      use SIP.Scenario
      config(username: "x", domain: "y")

      state initial_state do
        scenario_success("noop")
      end
    end

    assert SIP.Scenario.Loader.scenario_type(Fixture.PlainUAC) == :uac
  end

  # ── End-to-end via the mockup transport ───────────────────────────────────────

  test "unauthenticated REGISTER is challenged with 401" do
    restart_registrar(@scenario, 5)

    # SIP-REGISTER-LVP.txt carries no Authorization header.
    inject_register("test/SIP-REGISTER-LVP.txt")

    assert_receive {:uas_response, 401, _resp}, 2_000
  end

  test "REGISTER carrying credentials is accepted with 200" do
    restart_registrar(@scenario, 5)

    # SIP-REGISTER-AUTH.txt carries an Authorization (Digest) header: with no
    # configured password the UAS accepts it.
    inject_register("test/SIP-REGISTER-AUTH.txt")

    assert_receive {:uas_response, 200, _resp}, 2_000
  end

  # ── Concurrency quota ─────────────────────────────────────────────────────────

  test "registrar enforces the max_instances quota with 503" do
    restart_registrar(Fixture.Blocking, 1)

    fake_dialog = self()
    req = %{method: :REGISTER}

    assert {:accept, pid1} = Elixip.RegistrarUAS.on_new_registration(fake_dialog, req, self())
    assert {:reject, 503, _} = Elixip.RegistrarUAS.on_new_registration(fake_dialog, req, self())

    stats = Elixip.RegistrarUAS.stats()
    assert stats.active == 1
    assert stats.total_started == 1
    assert stats.total_rejected_quota == 1

    # Cooperatively shut the blocking instance down and confirm the slot frees.
    send(pid1, {:scenario_ctl, :shutdown, :test})
    wait_until(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000)
    assert Elixip.RegistrarUAS.stats().active == 0
  end

  defp wait_until(_fun, remaining) when remaining <= 0, do: :timeout

  defp wait_until(fun, remaining) do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      wait_until(fun, remaining - 20)
    end
  end
end
