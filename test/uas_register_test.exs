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

  defp restart_registrar(module, max, overrides \\ []) do
    case Process.whereis(Elixip.RegistrarUAS) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid)
        catch
          :exit, _ -> :ok
        end
    end

    {:ok, _pid} =
      Elixip.RegistrarUAS.start_link(
        scenario_module: module,
        max_instances: max,
        scenario_overrides: overrides
      )

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

    parsed =
      SIP.Msg.Ops.update_sip_msg(parsed, {:ruri, upd_uri}) |> uniq_callid() |> fresh_branch()

    routed = SIP.Transport.Selector.select_transport(upd_uri)

    # Route UAS responses back to this test process.
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    send(routed.tp_pid, {:recv, parsed})
    parsed.callid
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
    cid = inject_register("test/SIP-REGISTER-LVP.txt")

    assert_receive {:uas_response, 401, %{callid: ^cid}}, 2_000
  end

  test "REGISTER with credentials for a stale nonce / foreign realm is rejected" do
    restart_registrar(@scenario, 5, password: "toto")

    # SIP-REGISTER-AUTH.txt carries an Authorization whose nonce was never issued
    # by us (and whose realm is not example.com): the strict checks refuse it.
    cid = inject_register("test/SIP-REGISTER-AUTH.txt")

    assert_receive {:uas_response, 403, %{callid: ^cid}}, 2_000
  end

  test "authenticated REGISTER (real challenge/response) is accepted with 200" do
    restart_registrar(@scenario, 5, password: "toto")

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, req} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(req.ruri, "unittest", "1")
    req = SIP.Msg.Ops.update_sip_msg(req, {:ruri, upd_uri}) |> uniq_callid()
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    tp = routed.tp_pid

    cid = req.callid

    # 1. Unauthenticated REGISTER → 401 with a nonce we issued for our realm.
    #    Fresh Via branch so we never collide with a lingering transaction from
    #    another test that reused this canned message's branch.
    send(tp, {:recv, fresh_branch(req)})
    assert_receive {:uas_response, 401, %{callid: ^cid} = resp401}, 2_000
    nonce = resp401.wwwauthenticate["nonce"]
    assert is_binary(nonce)

    # 2. Authenticated retry on the SAME dialog (same From-tag/Call-ID, no To-tag):
    #    a new transaction (fresh Via branch) carrying a digest computed against
    #    our nonce, realm "example.com" and the configured password "toto".
    authparams = %{"realm" => "example.com", "nonce" => nonce, "algorithm" => "SHA256"}

    req2 =
      SIP.Msg.Ops.add_authorization_to_req(
        req,
        authparams,
        :wwwauthenticate,
        "5430",
        "toto",
        :plain
      )

    [top | rest] = req2.via

    newtop =
      String.replace(top, ~r/branch=[^;]+/, "branch=z9hG4bK#{System.unique_integer([:positive])}")

    req2 = Map.put(req2, :via, [newtop | rest])

    send(tp, {:recv, req2})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000
  end

  test "registered dialog answers OPTIONS keepalives and handles un-REGISTER" do
    # Lenient mode (no password): any well-formed Authorization is accepted, so we
    # can focus on the dialog routing of in-dialog OPTIONS / un-REGISTER.
    restart_registrar(@scenario, 5)

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, base} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "1")
    base = SIP.Msg.Ops.update_sip_msg(base, {:ruri, upd_uri}) |> uniq_callid() |> with_cseq(1)
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    tp = routed.tp_pid

    auth = %{"realm" => "example.com", "nonce" => "n0"}
    cid = base.callid

    # 1. REGISTER (no auth) → challenged.
    send(tp, {:recv, fresh_branch(base)})
    assert_receive {:uas_response, 401, %{callid: ^cid}}, 2_000

    # 2. REGISTER (authenticated) → accepted, dialog now "registered".
    reg = base |> with_auth(auth) |> with_cseq(2) |> fresh_branch()
    send(tp, {:recv, reg})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    # 3. In-dialog OPTIONS keepalive → 200 OK.
    opt = base |> Map.put(:method, :OPTIONS) |> with_cseq(3, :OPTIONS) |> fresh_branch()
    send(tp, {:recv, opt})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    # 4. In-dialog un-REGISTER (Expires 0) → 200 OK and the instance ends.
    unreg = base |> Map.put(:expires, 0) |> with_auth(auth) |> with_cseq(4) |> fresh_branch()
    send(tp, {:recv, unreg})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    assert wait_until(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000) == :ok
  end

  # Replace the topmost Via branch so each injected message is a new transaction.
  defp fresh_branch(req) do
    [top | rest] = req.via

    new =
      String.replace(top, ~r/branch=[^;]+/, "branch=z9hG4bK#{System.unique_integer([:positive])}")

    Map.put(req, :via, [new | rest])
  end

  defp with_cseq(req, n, method \\ :REGISTER), do: Map.put(req, :cseq, [n, method])

  # Give a message a unique Call-ID so each test uses a distinct dialog (dialogs
  # live ~600 s; without this, tests reusing the same canned message would match a
  # lingering dialog from a previous test instead of creating a fresh one).
  defp uniq_callid(req),
    do: Map.put(req, :callid, "uastest-#{System.unique_integer([:positive])}")

  # Add an Authorization header (overriding the CSeq bump add_authorization_to_req
  # applies, which the caller sets explicitly afterwards).
  defp with_auth(req, authparams) do
    SIP.Msg.Ops.add_authorization_to_req(
      req,
      authparams,
      :wwwauthenticate,
      "5430",
      "secret",
      :plain
    )
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
