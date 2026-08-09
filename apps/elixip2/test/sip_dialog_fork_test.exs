defmodule SIP.Test.DialogFork do
  @moduledoc """
  Forking in the dialog layer (`SIP.Dialog.fork_branch/2`, design
  docs/design/b2bua_module.md §3.3): the kamailio TM model — ONE dialog, N
  branches. Each branch is the same initial request sent to another target, as
  another client transaction of the same dialog: Call-ID, From tag and CSeq
  shared, one fresh Via branch each.

  What that buys the layer above: the leg abstraction survives forking. A B2BUA
  hunting down an AOR's contacts still has exactly one outbound leg, so its
  event tag, its correlation map and its teardown are untouched by how many
  targets it tried.

  Every test gets peers of its own (`;unittest=<name>`, one mockup process per
  name), so no test inherits another's current request or canned scenario.
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

  # This test's peer `name`, with the calling process registered as its test app.
  # Returns the transport pid, which every later call uses directly: looking the
  # instance up again could race a restart and hand back a different process.
  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = GenServer.call(tp, :settestapp)
    tp
  end

  # An outbound INVITE dialog whose first branch goes to `first`.
  defp start_call(first) do
    aor = %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}

    invite = %{
      "Max-Forwards" => "70",
      method: :INVITE,
      ruri: target(first),
      from: aor,
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "example.com"},
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0", params: %{}},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }

    {:ok, dlg, _dlg_id} = SIP.Dialog.start_dialog(invite, 60, :outbound, false, tag: :outbound)
    assert_receive {:outbound, {:onnewdialog, :ok, tid1}}, 2_000
    {dlg, tid1}
  end

  test "a second branch shares the dialog identity and only changes the target" do
    _a = peer!("fk1a")
    _b = peer!("fk1b")

    {dlg, tid1} = start_call("fk1a")
    assert_receive {:invite_sent, first}, 2_000

    assert {:ok, tid2} = SIP.Dialog.fork_branch(dlg, target("fk1b"))
    refute tid2 == tid1

    assert_receive {:invite_sent, second}, 2_000

    # Same request, another target: what a fork IS (RFC 3261 §16.6).
    assert second.callid == first.callid
    assert second.cseq == first.cseq
    assert SIP.Uri.get_uri_param(second.from, "tag") == SIP.Uri.get_uri_param(first.from, "tag")
    assert first.ruri.domain == "fk1a.example.com"
    assert second.ruri.domain == "fk1b.example.com"

    # …but its own transaction, hence its own Via branch — the one thing that
    # must differ, or the far end takes it for a retransmission.
    refute second.transid == first.transid
  end

  test "the hunt survives a branch that fails: the dialog is still there for the next target" do
    a = peer!("fk2a")
    _b = peer!("fk2b")

    {dlg, _tid1} = start_call("fk2a")
    assert_receive {:invite_sent, _first}, 2_000

    assert {:ok, _tid2} = SIP.Dialog.fork_branch(dlg, target("fk2b"))
    assert_receive {:invite_sent, _second}, 2_000

    # The first target refuses.
    GenServer.cast(a, {:simulate, 486, 100})
    assert_receive {:outbound, {486, _rsp, _tid, ^dlg}}, 3_000

    # The dialog is still alive to try the next one. Before forking, a non-2xx
    # final on the initial request terminated it outright, so the application
    # learned of the failure from a message whose dialog was already gone.
    Process.sleep(200)
    assert Process.alive?(dlg)
    assert {:ok, _tid3} = SIP.Dialog.fork_branch(dlg, target("fk2c"))
  end

  test "a branch that answers 2xx becomes the dialog" do
    _a = peer!("fk3a")
    b = peer!("fk3b")

    {dlg, _tid1} = start_call("fk3a")
    assert_receive {:invite_sent, _first}, 2_000
    assert {:ok, _tid2} = SIP.Dialog.fork_branch(dlg, target("fk3b"))
    assert_receive {:invite_sent, _second}, 2_000

    GenServer.cast(b, {:simulate, 200, 100})
    assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 3_000

    # The dialog now has the winner's remote tag, so it is addressable.
    {_ftag, _cid, totag} = GenServer.call(dlg, :getdialogid)
    assert is_binary(totag)

    # And the hunt is over: nothing left to try.
    assert {:error, :already_established} = SIP.Dialog.fork_branch(dlg, target("fk3c"))
  end

  # The trap the single to-tag slot sets: it latches the FIRST tag offered. With
  # branches, a 180 from a target that goes on to fail would take the slot the
  # winning 2xx needs, and every later in-dialog request would name a callee that
  # never answered.
  test "a provisional from a losing branch does not take the dialog's to-tag" do
    a = peer!("fk4a")
    b = peer!("fk4b")

    {dlg, _tid1} = start_call("fk4a")
    assert_receive {:invite_sent, _first}, 2_000
    assert {:ok, _tid2} = SIP.Dialog.fork_branch(dlg, target("fk4b"))
    assert_receive {:invite_sent, _second}, 2_000

    # fk4a rings — its 180 carries a to-tag of its own.
    GenServer.cast(a, {:simulate, 180, 50})
    assert_receive {:outbound, {180, ringing, _t, ^dlg}}, 3_000
    {:ok, ringing_tag} = SIP.Uri.get_uri_param(ringing.to, "tag")

    # The dialog has NOT taken it.
    {_f, _c, totag_after_180} = GenServer.call(dlg, :getdialogid)
    assert is_nil(totag_after_180)

    # fk4b answers; its tag is the one that sticks.
    GenServer.cast(b, {:simulate, 200, 100})
    assert_receive {:outbound, {200, ok, _t2, ^dlg}}, 3_000
    {:ok, winner_tag} = SIP.Uri.get_uri_param(ok.to, "tag")

    {_f2, _c2, final_totag} = GenServer.call(dlg, :getdialogid)
    assert final_totag == winner_tag
    refute final_totag == ringing_tag
  end

  test "an unforked dialog still takes an early dialog's to-tag, as it always did" do
    a = peer!("fk5")

    {dlg, _tid} = start_call("fk5")
    assert_receive {:invite_sent, _req}, 2_000

    GenServer.cast(a, {:simulate, 180, 50})
    assert_receive {:outbound, {180, ringing, _t, ^dlg}}, 3_000
    {:ok, early_tag} = SIP.Uri.get_uri_param(ringing.to, "tag")

    {_f, _c, totag} = GenServer.call(dlg, :getdialogid)
    assert totag == early_tag
  end

  test "forking is refused on a dialog we did not originate" do
    # An inbound dialog has nothing to fork: the request came to us.
    state = %SIP.DialogImpl{direction: :inbound}

    assert {:reply, {:error, :not_outbound}, ^state} =
             SIP.DialogImpl.handle_call({:fork_branch, target("nope")}, self(), state)
  end
end
