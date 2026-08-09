defmodule SIP.Test.DialogResilience do
  @moduledoc """
  What a dialog does when the layers under it fail — design
  docs/design/b2bua_module.md §14, decisions R1 and R2.

  These are failure-injection tests: nothing here waits for a timer, every case
  kills a process outright. That is the point. The behaviours below all used to
  be reachable only through a crash, which is exactly why none of them was
  covered and all of them were wrong.

  The two assertions that matter are the same in every test — **the application
  is told**, and **nothing is left running** — because those are the two things
  the whole B2BUA teardown is built on.
  """
  use ExUnit.Case

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
    :ok = GenServer.call(tp, :settestapp)
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
    assert_receive {:invite_sent, _req}, 2_000

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
    assert_receive {:invite_sent, _first}, 2_000

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
    assert_receive {:invite_sent, _req}, 2_000

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
    assert_receive {:invite_sent, _req}, 2_000

    GenServer.cast(peer, {:simulate, 200, 50})
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
    assert_receive {:invite_sent, _req}, 2_000
    assert Process.alive?(tid)

    :ok = GenServer.stop(dlg, :normal)
    assert_dies(tid)
  end

  # The catch-all handle_info/2. `use GenServer` provides one, but a module that
  # defines its own clauses replaces it wholesale — so an unrecognized message
  # raised a FunctionClause and took the dialog with it. SIP.Dialog.broadcast/1
  # makes that a live hazard: it sends to EVERY dialog, so one shape a dialog
  # does not know is a message that kills all of them.
  test "a message the dialog does not recognize does not kill it" do
    _silent = peer!("rs6")
    {dlg, _tid} = start_call("rs6")
    assert_receive {:invite_sent, _req}, 2_000

    send(dlg, {:some_future_broadcast, :with, "arguments"})

    Process.sleep(100)
    assert Process.alive?(dlg)
    # Still working, not merely still breathing.
    assert {_ftag, _cid, _totag} = GenServer.call(dlg, :getdialogid)
  end
end
