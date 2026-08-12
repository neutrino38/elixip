defmodule SIP.Test.UASRegister do
  use ExUnit.Case
  import SIP.Test.Wait
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

  # `Elixip.RegistrarUAS` is a named singleton linked to the test process, so the
  # previous test's instance may still be dying when the next one starts. Take the
  # name over deterministically: stop whoever holds it, wait for its DOWN, retry.
  defp restart_registrar(module, max, overrides \\ [], attempts \\ 10) do
    opts = [scenario_module: module, max_instances: max, scenario_overrides: overrides]

    case Elixip.RegistrarUAS.start_link(opts) do
      {:ok, _pid} ->
        :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.RegistrarUAS)

      {:error, {:already_started, pid}} when attempts > 0 ->
        stop_and_await(pid)
        restart_registrar(module, max, overrides, attempts - 1)
    end
  end

  defp stop_and_await(pid) do
    ref = Process.monitor(pid)

    try do
      GenServer.stop(pid)
    catch
      :exit, _ -> :ok
    end

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
    after
      1_000 -> Process.demonitor(ref, [:flush])
    end
  end

  # Parse a REGISTER message file, mark it for the mockup transport, inject it as
  # an inbound message and arrange for SIP responses to come back to the test.
  defp inject_register(file) do
    {:ok, msg} = File.read(file)

    {:ok, parsed} =
      SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
        IO.puts("#{errmsg}\nline #{lineno}: #{line}\ncode #{code}")
      end)

    upd_uri = SIP.Uri.set_uri_param(parsed.ruri, "unittest", "uas_register")

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

  test "a forged nonce is rejected even with a valid digest and the right realm" do
    # What the stateless nonce buys: the digest below is computed correctly with
    # the configured password, and the realm matches — only the nonce is made up.
    # The MAC does not verify, so it is refused. The former
    # sha256("ElixSIP-day:hour:minute") nonce was keyless and could be recomputed
    # by anyone with a clock, making this exact forgery succeed.
    restart_registrar(@scenario, 5, password: "toto")

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, base} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "uas_register")
    base = SIP.Msg.Ops.update_sip_msg(base, {:ruri, upd_uri}) |> uniq_callid()
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    cid = base.callid

    # right length (ts+rand+mac), wrong MAC
    forged = Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false)

    authparams = %{"realm" => "example.com", "nonce" => forged, "algorithm" => "SHA256"}

    req =
      SIP.Msg.Ops.add_authorization_to_req(
        base,
        authparams,
        :wwwauthenticate,
        "5430",
        "toto",
        :plain
      )
      |> fresh_branch()

    send(routed.tp_pid, {:recv, req})
    assert_receive {:uas_response, 403, %{callid: ^cid}}, 2_000
  end

  test "authenticated REGISTER (real challenge/response) is accepted with 200" do
    restart_registrar(@scenario, 5, password: "toto")

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, req} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(req.ruri, "unittest", "uas_register")
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

    # The advertised algorithm must be one a UAC can actually answer with: it holds
    # a single HA1, derived from its own `ctx.algorithm` (default MD5) with the clear
    # password already discarded. Hardcoding the algorithm here instead of reading
    # the challenge is what let the framework advertise SHA256 for months while no
    # elixip UAC could ever produce a matching digest.
    algorithm = resp401.wwwauthenticate["algorithm"]
    assert algorithm == %SIP.Context{}.algorithm

    # 2. Authenticated retry on the SAME dialog (same From-tag/Call-ID, no To-tag):
    #    a new transaction (fresh Via branch) carrying a digest computed against
    #    our nonce, realm "example.com" and the configured password "toto".
    authparams = %{"realm" => "example.com", "nonce" => nonce, "algorithm" => algorithm}

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
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "uas_register")
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

    assert until(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000)
  end

  test "a rebinding REGISTER refreshes the registration instead of ending it" do
    # The shape a handset sends when it moves: drop the old binding
    # (`Contact ;expires=0`), add the new one whose lifetime is in the `Expires`
    # header only. Reading the header first — as this scenario used to, against
    # RFC 3261 §10.2.4 — resolves the whole request to 0 and de-registers the user
    # who was merely rebinding. The un-REGISTER test above cannot catch it: its
    # Contact carries no `expires` parameter, so both readings agree there.
    restart_registrar(@scenario, 5)

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, base} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "uas_register")
    base = SIP.Msg.Ops.update_sip_msg(base, {:ruri, upd_uri}) |> uniq_callid() |> with_cseq(1)
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)
    tp = routed.tp_pid

    auth = %{"realm" => "example.com", "nonce" => "n0"}
    cid = base.callid

    send(tp, {:recv, fresh_branch(base)})
    assert_receive {:uas_response, 401, %{callid: ^cid}}, 2_000

    reg = base |> with_auth(auth) |> with_cseq(2) |> fresh_branch()
    send(tp, {:recv, reg})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    old = SIP.Uri.set_header_param(List.first(List.wrap(base.contact)), "expires", "0")
    {:ok, new} = SIP.Uri.parse("sip:5430@103.145.13.102:5191")

    rebind =
      base
      |> Map.put(:contact, [old, new])
      |> Map.put(:expires, 600)
      |> with_auth(auth)
      |> with_cseq(3)
      |> fresh_branch()

    send(tp, {:recv, rebind})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    # Still registered: the instance must not have taken this for a goodbye.
    Process.sleep(200)
    assert Elixip.RegistrarUAS.stats().active == 1

    # …and leave nothing behind: the factory is a named singleton shared with the
    # other UAS test files, so an instance left registered here leaks into them.
    Elixip.RegistrarUAS.shutdown_all(:test_cleanup)
    assert until(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000)
  end

  # A REGISTER accepted on the request that CREATES the dialog — no 401 in between,
  # which is what a client pre-authenticating with a cached nonce sends on every
  # refresh. The dialog used to arm its expiration timer only on the *in-dialog*
  # path, so this shape produced a dialog with no lifetime at all: immortal over a
  # connected transport until the connection dropped, immortal outright over UDP,
  # with its registrar session sitting in `kelictl monitor` for ever. Two of them
  # were found alive on 2026-08-11 for a single Linphone binding.
  #
  # sip_dialog_register_expiry_test.exs proves what `arm_expiration_timer/2`
  # computes; it passed throughout, because nothing called it here.
  test "a REGISTER accepted on the very first request still arms the dialog lifetime" do
    restart_registrar(@scenario, 5)

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, base} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "uas_register")
    base = SIP.Msg.Ops.update_sip_msg(base, {:ruri, upd_uri}) |> uniq_callid() |> with_cseq(1)
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)

    cid = base.callid

    # Lenient mode (no password): the very first REGISTER already carries an
    # Authorization, so the scenario accepts it instead of challenging.
    auth = %{"realm" => "example.com", "nonce" => "n0"}
    send(routed.tp_pid, {:recv, base |> with_auth(auth) |> fresh_branch()})
    assert_receive {:uas_response, 200, %{callid: ^cid}}, 2_000

    timer = :sys.get_state(dialog_of(cid)).expirationtimer
    assert timer != nil, "the dialog-creating REGISTER left the dialog with no lifetime"

    # The full lifetime the REGISTER asked for (Expires: 1800), not the ~1 s
    # teardown an un-registration gets.
    assert_in_delta :erlang.read_timer(timer) / 1000, 1800, 30

    Elixip.RegistrarUAS.shutdown_all(:test_cleanup)
    assert until(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000)
  end

  # The dialog serving `callid`. An inbound dialog registers itself twice — under
  # the id the initial request yields ({fromtag, callid, nil}) and under the
  # complete one, once it has generated its To tag — so the same pid comes back
  # twice.
  defp dialog_of(callid) do
    Registry.select(Registry.SIPDialog, [{{{:_, callid, :_}, :"$1", :_}, [], [:"$1"]}])
    |> Enum.uniq()
    |> case do
      [pid] -> pid
      other -> flunk("expected exactly one dialog for #{callid}, got #{inspect(other)}")
    end
  end

  # RFC 3261 §12.2.2. This is what a client sees when its registration lapsed while
  # it kept sending in-dialog keepalives: the dialog is gone, so the request matches
  # nothing. It used to be treated as a brand-new dialog, whose dispatch had no
  # clause for the method — a function_clause, and the transaction layer turned that
  # into "403 Denied". A 403 tells a client it is unwelcome; 481 tells it to
  # re-register, which is the actionable truth.
  test "an in-dialog request whose dialog is gone is answered 481, not 403" do
    restart_registrar(@scenario, 5)

    {:ok, msg} = File.read("test/SIP-REGISTER-LVP.txt")
    {:ok, base} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)
    upd_uri = SIP.Uri.set_uri_param(base.ruri, "unittest", "uas_register")
    base = SIP.Msg.Ops.update_sip_msg(base, {:ruri, upd_uri}) |> uniq_callid()
    routed = SIP.Transport.Selector.select_transport(upd_uri)
    :ok = GenServer.call(routed.tp_pid, :settestapp)

    cid = base.callid

    # An OPTIONS bearing a To tag — i.e. sent inside a dialog — for a dialog that
    # does not exist (this Call-ID was never registered).
    orphan =
      base
      |> Map.put(:method, :OPTIONS)
      |> Map.put(:to, "sip:5430@example.com;tag=ghost")
      |> with_cseq(9, :OPTIONS)
      |> fresh_branch()

    send(routed.tp_pid, {:recv, orphan})
    assert_receive {:uas_response, 481, %{callid: ^cid}}, 2_000
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
    until!(fn -> Elixip.RegistrarUAS.stats().active == 0 end, 2_000)
    assert Elixip.RegistrarUAS.stats().active == 0
  end
end
