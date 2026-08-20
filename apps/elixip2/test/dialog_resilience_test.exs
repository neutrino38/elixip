defmodule SIP.Test.DialogResilience do
  @moduledoc """
  What a dialog does when the layers under it fail — design
  docs/design/DESIGN-SIPSTACK.md#57-resilience, decisions R1 and R2.

  These are failure-injection tests: nothing here waits for a timer, every case
  kills a process outright. That is the point. The behaviours below all used to
  be reachable only through a crash, which is exactly why none of them was
  covered and all of them were wrong.

  The two assertions that matter are the same in every test — **the application
  is told**, and **nothing is left running** — because those are the two things
  the whole B2BUA teardown is built on.
  """
  use ExUnit.Case

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
  end

  # This test's own peer (`;unittest=<name>` gives one mockup process per name),
  # with the calling process registered as its test app.
  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp invite_to(name) do
    %{
      "Max-Forwards" => "70",
      method: :INVITE,
      ruri: target(name),
      from: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"},
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "example.com"},
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0", params: %{}},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }
  end

  defp start_call(name, opts \\ [tag: :outbound]) do
    {:ok, dlg, _id} = SIP.Dialog.start_dialog(invite_to(name), 60, :outbound, false, opts)
    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 2_000
    {dlg, tid}
  end

  # `refute Process.alive?/1` is a race against a process that has already
  # decided to stop: terminate/2 sends its notification and the exit completes
  # afterwards, so the check can run in between. A monitor cannot miss it — it
  # fires immediately for a pid that is already gone.
  defp assert_dies(pid) do
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 2_000
  end

  # ── R1: a transaction that crashes ──────────────────────────────────────────

  # The path that had no name: a client transaction is start_link'ed from the
  # dialog, so its crash used to cross the link and kill the dialog by SIGNAL —
  # which does not run terminate/2. The application was never sent
  # {:dialog_terminated, …}, so a B2BUA leg simply went quiet and its scenario
  # sat on its `after` clause with nothing to read.
  test "a client transaction that crashes is reported to the application as a 408" do
    _silent = peer!("rs1")
    {dlg, tid} = start_call("rs1")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Process.exit(tid, :kill)

    assert_receive {:outbound, {408, rsp, ^tid, ^dlg}}, 2_000
    assert rsp.response == 408
    # It says WHICH request died with it — what SIP.Session.dispatch_reply/3
    # routes on and what the B2BUA correlates against.
    assert match?([_, :INVITE], rsp.cseq)
  end

  # A crashed branch is one target fewer, not the end of the call: the dialog
  # must survive so the hunt can arm the next one. This is the forking clause of
  # handle_UAS_response/3 doing its job on a synthetic 408, which is the reason
  # the 408 is routed through it rather than sent straight to the application.
  test "a branch whose transaction crashes ends the branch, not the hunt" do
    _a = peer!("rs2a")
    _b = peer!("rs2b")

    {dlg, tid1} = start_call("rs2a", tag: :outbound, fork: true)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 2_000

    Process.exit(tid1, :kill)
    assert_receive {:outbound, {408, _rsp, ^tid1, ^dlg}}, 2_000

    # Still there, and still willing to try somewhere else.
    Process.sleep(100)
    assert Process.alive?(dlg)
    assert {:ok, _tid2} = SIP.Dialog.fork_branch(dlg, target("rs2b"))
  end

  # …and the counterpart: with no hunt behind it, a dead initial request IS the
  # end of the call, so the dialog must go. It used to stay in `:initial` for the
  # full 1800 s expiration — one leaked dialog per failed call, which for a B2BUA
  # is one per failed leg.
  test "an unforked initial request that dies takes its dialog with it, and says so" do
    _silent = peer!("rs3")
    {dlg, tid} = start_call("rs3")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Process.exit(tid, :kill)

    assert_receive {:outbound, {408, _rsp, ^tid, ^dlg}}, 2_000
    assert_receive {:outbound, {:dialog_terminated, ^dlg, _reason}}, 2_000
    assert_dies(dlg)
  end

  # Our own BYE going unanswered ends the dialog (RFC 3261 §15: a UAC that has
  # sent a BYE considers the session over whatever comes back).
  #
  # Two bugs lived here, and they hid each other. The test asked
  # `module == SIP.ICT` — but a BYE is answered by a NICT, never an ICT, so the
  # branch could not run at any time. Had it run, it stopped with the ATOM
  # `:state` instead of the state: terminate/2 would have raised on `state.app`
  # and the dialog would have died of that error, sending no
  # {:dialog_terminated, …} at all. On the one path that exists to end a dialog
  # cleanly.
  test "a BYE that goes unanswered ends the dialog and the application is told" do
    peer = peer!("rs4")
    {dlg, _tid} = start_call("rs4")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(peer, 200, 50)
    assert_receive {:outbound, {200, _ok, _t, ^dlg}}, 3_000

    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: %SIP.Uri{userpart: nil, domain: nil},
      from: %SIP.Uri{userpart: nil, domain: nil},
      to: %SIP.Uri{userpart: nil, domain: nil},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }

    assert {:ok, bye_tid} = SIP.Dialog.new_request(dlg, bye)

    # Nobody answers it — here by killing its transaction, which reaches the same
    # place timer F would have reached, without the 32 s wait.
    Process.exit(bye_tid, :kill)

    assert_receive {:outbound, {:dialog_terminated, ^dlg, _reason}}, 2_000
    assert_dies(dlg)
  end

  # A dialog stopping `:normal` propagates a signal its linked transactions
  # ignore, so an ICT whose dialog had died kept retransmitting its INVITE every
  # T1..T2 until timer B — on the wire, for a call nobody was following.
  test "a dialog takes its client transactions down with it" do
    _silent = peer!("rs5")
    {dlg, tid} = start_call("rs5")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000
    assert Process.alive?(tid)

    :ok = GenServer.stop(dlg, :normal)
    assert_dies(tid)
  end

  # ── R4/R5: a connected transport going away ─────────────────────────────────

  # `{:transport_down, …}` is broadcast to EVERY dialog, so these drive the
  # dialog's side of it directly. The mockup is connectionless, which does not
  # matter here: what is under test is what a dialog does with the message, and
  # the rule that only connected transports SEND it lives in the transports.
  defp transport_down(dlg) do
    send(dlg, {:transport_down, SIP.Test.Transport.Mockup, {1, 2, 3, 4}, 5080})
  end

  # One notification, not two. The old per-protocol clauses sent
  # {:dialog_terminated, …, :tcp_closed} themselves AND stopped `:normal`, so
  # terminate/2 sent a second one — which a later state could match against the
  # OTHER leg's termination.
  test "a transport going down terminates the dialog riding it, exactly once" do
    peer = peer!("rs7")
    {dlg, _tid} = start_call("rs7")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(peer, 200, 50)
    assert_receive {:outbound, {200, _ok, _t, ^dlg}}, 3_000

    transport_down(dlg)

    assert_receive {:outbound, {:dialog_terminated, ^dlg, :transport_down}}, 2_000
    assert_dies(dlg)

    # The reason also says what happened to the CALL, where `:tcp_closed` said
    # which wire broke.
    refute_receive {:outbound, {:dialog_terminated, ^dlg, _}}, 300
  end

  test "a dialog on another flow ignores it" do
    _peer = peer!("rs8")
    {dlg, _tid} = start_call("rs8")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    send(dlg, {:transport_down, SIP.Transport.TCP, {9, 9, 9, 9}, 5060})

    Process.sleep(100)
    assert Process.alive?(dlg)
  end

  # R5. The old clauses compared the closed connection to `state.msg.ruri`, which
  # stays the FIRST target until a branch wins — so a disconnect under a later
  # branch went unseen, and the hunt only moved on when timer B fired 64×T1
  # later. And when it WAS seen, it killed the dialog: the call ended because one
  # of several targets became unreachable.
  test "a transport going down under a hunting branch ends the branch, not the call" do
    _a = peer!("rs9a")
    _b = peer!("rs9b")

    {dlg, tid1} = start_call("rs9a", tag: :outbound, fork: true)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 2_000

    transport_down(dlg)

    # The branch is reported as unreachable, in the shape a hunt already reads.
    assert_receive {:outbound, {408, _rsp, ^tid1, ^dlg}}, 2_000

    # …and the search goes on.
    Process.sleep(100)
    assert Process.alive?(dlg)
    assert {:ok, _tid2} = SIP.Dialog.fork_branch(dlg, target("rs9b"))
  end

  # ── R4: where the announcement comes from ───────────────────────────────────

  # The two above drive the dialog with a message written by hand. These two
  # drive a REAL TCP transport and watch what it says on the way out, which is
  # the half that moved: the announcement left the close handlers for
  # `terminate/2`, so that a transport dying of a crash says as much as one
  # closing cleanly. Before, a crashed transport said nothing and its dialogs
  # waited for timer B — 32 s of silence instead of an immediate failover.
  #
  # `SIP.Dialog.broadcast/1` sends to whatever is registered in
  # Registry.SIPDialog, so the test process registers itself and reads the
  # broadcast directly.
  defp listen_and_connect do
    {:ok, listener} = GenServer.start(SIP.Transport.TCPListener, {:all, 0, []})
    {:ok, _ip, port} = GenServer.call(listener, :getlocalipandport)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)

    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])

    conn =
      Enum.reduce_while(1..50, nil, fn _, _ ->
        case :sys.get_state(listener).connections |> Map.values() do
          [{_ip, _port, pid} | _] -> {:halt, pid}
          [] -> Process.sleep(20) && {:cont, nil}
        end
      end)

    assert is_pid(conn)
    Registry.register(Registry.SIPDialog, {"resilience", "tp-#{inspect(conn)}", nil}, :test)
    {socket, conn}
  end

  test "a connected transport closing announces it to the dialogs" do
    {socket, _conn} = listen_and_connect()

    :gen_tcp.close(socket)

    assert_receive {:transport_down, SIP.Transport.TCP, _ip, _port}, 2_000
  end

  test "…and so does one that dies abnormally, which is the point of moving it" do
    {_socket, conn} = listen_and_connect()

    # An abnormal stop, which is the reason terminate/2 receives on a crash. The
    # transport is unlinked from us, so this returns rather than exiting here.
    GenServer.stop(conn, :boom)

    assert_receive {:transport_down, SIP.Transport.TCP, _ip, _port}, 2_000
  end

  # ── R3: a transport that dies under a live dialog ───────────────────────────

  # The recovery R3 promises, and the whole of it. A resolved R-URI carries the
  # transport pid it was resolved with, and a dialog caches that pid for its
  # lifetime — nothing ever asked again whether it was alive, so the next
  # in-dialog request exited on a dead pid, inside the dialog, inside the
  # scenario's own GenServer.call (§14.2 (b)).
  #
  # A node has ONE connectionless socket, named by its protocol in
  # Registry.SIPTransport, so re-selecting relaunches that singleton and the call
  # carries on. The far end never learns anything happened.
  test "a connectionless transport that dies is re-selected, and the call goes on" do
    peer = peer!("rs10")
    {dlg, _tid} = start_call("rs10")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(peer, 200, 50)
    assert_receive {:outbound, {200, _ok, _t, ^dlg}}, 3_000

    Process.exit(peer, :kill)
    assert_dies(peer)

    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: %SIP.Uri{userpart: nil, domain: nil},
      from: %SIP.Uri{userpart: nil, domain: nil},
      to: %SIP.Uri{userpart: nil, domain: nil},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }

    # Before R3 this exited on the dead pid rather than returning anything.
    assert {:ok, _bye_tid} = SIP.Dialog.new_request(dlg, bye)

    # …and it went out over a NEW instance of the same transport.
    revived = SIP.Transport.Selector.select_transport(target("rs10")).tp_pid
    assert is_pid(revived)
    refute revived == peer
  end

  # The counterpart, and the reason the rule is "connectionless", not "any dead
  # transport": re-resolving a connected one would open a NEW connection — a
  # different flow, with a different source port, not the one the peer is
  # answering on. Toward a NATed client it cannot even be attempted. Same
  # decision as R4/R5: a lost connection ends the dialogs riding it.
  test "a dead connected transport is not silently reopened on another flow" do
    dead = spawn(fn -> :ok end)
    assert_dies(dead)

    req = %{
      "Max-Forwards" => "70",
      method: :MESSAGE,
      ruri: %SIP.Uri{
        scheme: "sip:",
        userpart: "bob",
        domain: "example.com",
        destip: {127, 0, 0, 1},
        destport: 5060,
        destproto: "TCP",
        tp_module: SIP.Transport.TCP,
        tp_pid: dead
      },
      from: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"},
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "example.com"},
      useragent: "Elixipp-test",
      callid: "rs11",
      contentlength: 0
    }

    assert SIP.Transac.start_uac_transaction(req, 5) == :no_transport_available
  end

  # The other half of R3, under everything above: a call toward a transport is a
  # GenServer.call on a cached pid, and an exit there happens inside a
  # transaction (linked to its dialog) or inside a dialog (answering the
  # scenario). It is answered as a send failure — a code every caller of a
  # transport already reads, because a send can always fail.
  test "talking to a dead transport is a transport error, not an exit" do
    dead = spawn(fn -> :ok end)
    assert_dies(dead)

    assert SIP.Transport.send_msg(dead, "OPTIONS sip:x SIP/2.0\r\n\r\n", {1, 2, 3, 4}, 5080) ==
             :transporterror

    assert SIP.Transport.get_local_ip_port(dead) == :transporterror

    # And nothing is stamped on a message we cannot address.
    assert SIP.Transport.build_contact_uri(SIP.Transport.UDP, dead) == nil
  end

  # ── Asked to end from the outside ───────────────────────────────────────────

  # `SIP.Dialog.terminate/2` — the same two assertions as every failure above, for
  # a dialog nothing under it is going to end. The registrar needs it for a
  # REGISTER dialog it has superseded (the same binding re-registered under
  # another Call-ID): stale, with no BYE, no expiry and no dropped connection to
  # notice it. The reason must reach the application verbatim, since that is how
  # a scenario tells this apart from a client that went away.
  test "a dialog told to terminate says why and dies" do
    _silent = peer!("rs7")
    {dlg, _tid} = start_call("rs7")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    :ok = SIP.Dialog.terminate(dlg, :superseded)

    assert_receive {:outbound, {:dialog_terminated, ^dlg, :superseded}}, 2_000
    assert_dies(dlg)
  end

  # The registrar casts it from inside its own GenServer, on a pid it monitors: a
  # dialog that died between the two must not take the store down with it.
  test "terminating a dialog that is already gone is a no-op" do
    _silent = peer!("rs8")
    {dlg, _tid} = start_call("rs8")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Process.exit(dlg, :kill)
    assert_dies(dlg)

    assert :ok = SIP.Dialog.terminate(dlg, :superseded)
  end

  # ── A 2xx that arrives after its application is gone ────────────────────────

  # The ACK of a 2xx belongs to the UAC core — the application — in a transaction
  # of its own (RFC 3261 §13.2.2.4), which is why the dialog keeps the client
  # transaction alive after a 2xx instead of closing it. With no application left
  # the ACK never comes, and the callee is stranded: it retransmits its 200 until
  # it gives up, off-hook in a call nobody is in.
  #
  # The way to get here in production (2026-08-11): the caller cancels, the answer
  # crosses the CANCEL on the wire — §16.7, cancelling asks, it does not decide —
  # and the B2BUA scenario has already ended on `scenario_aborted("caller
  # cancelled")` by the time the 200 lands. The dialog outlives its scenario, so
  # it is still there to do the only lawful thing: ACK, then BYE (§15).
  test "a 2xx no application is left to ACK is acknowledged and hung up" do
    tp = peer!("orphan2xx")
    parent = self()

    # An application that places the call and then ends normally, exactly as a
    # scenario instance does on the caller's CANCEL.
    app =
      spawn(fn ->
        {:ok, dlg, _id} =
          SIP.Dialog.start_dialog(invite_to("orphan2xx"), 60, :outbound, false, [])

        send(parent, {:dialog, dlg})

        receive do
          :end_scenario -> :ok
        end
      end)

    assert_receive {:dialog, dlg}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    ref = Process.monitor(app)
    send(app, :end_scenario)
    assert_receive {:DOWN, ^ref, :process, ^app, :normal}, 2_000

    # The callee picks up anyway.
    Manual.simulate(tp, 200, 0)

    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 2_000

    # The dialog is not linked to its application (GenServer.start, not
    # start_link), which is what let it still be here to clean up.
    assert Process.alive?(dlg)
  end

  # The catch-all handle_info/2. `use GenServer` provides one, but a module that
  # defines its own clauses replaces it wholesale — so an unrecognized message
  # raised a FunctionClause and took the dialog with it. SIP.Dialog.broadcast/1
  # makes that a live hazard: it sends to EVERY dialog, so one shape a dialog
  # does not know is a message that kills all of them.
  test "a message the dialog does not recognize does not kill it" do
    _silent = peer!("rs6")
    {dlg, _tid} = start_call("rs6")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    send(dlg, {:some_future_broadcast, :with, "arguments"})

    Process.sleep(100)
    assert Process.alive?(dlg)
    # Still working, not merely still breathing.
    assert {_ftag, _cid, _totag} = GenServer.call(dlg, :getdialogid)
  end
end
