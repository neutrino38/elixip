defmodule SIP.Test.DialogParallelFork do
  @moduledoc """
  Parallel forking in the dialog layer (design docs/design/b2bua_module.md §3.3,
  RFC 3261 §16.6/§16.7): one dialog, a **rung** of branches ringing at once.

  What serial forking never had to answer, and this does: N branches produce N
  finals, and the caller is owed exactly one. The rule is that a non-2xx final is
  withheld while a sibling is still ringing and the best of the rung is surfaced
  when the last one falls (§16.7). The serial case is the same rule with a rung
  of one — its single branch is always the last, so its final goes up verbatim,
  which is what `b2bua_serial_fork_test.exs` keeps asserting.

  Every test gets peers of its own (`;unittest=<name>`, one mockup process per
  name), so no test inherits another's current request, canned scenario or BYE.
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

  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  # An outbound INVITE dialog whose first branch goes to `first` and whose rung
  # holds `rest` — all of them armed inside init/1, which is the point of passing
  # them here rather than calling fork_branch/2 afterwards.
  defp start_rung(first, rest) do
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

    fork = if rest == [], do: true, else: Enum.map(rest, &target/1)

    {:ok, dlg, _id} =
      SIP.Dialog.start_dialog(invite, 60, :outbound, false, tag: :outbound, fork: fork)

    assert_receive {:outbound, {:onnewdialog, :ok, tid1}}, 2_000
    {dlg, tid1}
  end

  # The INVITE each peer received, gathered by target domain: the rung goes out
  # in one burst and nothing orders the notifications.
  defp collect_invites(n) do
    for _ <- 1..n, into: %{} do
      assert_receive {:sip_mockup, {:request_sent, :INVITE, req}}, 2_000
      {req.ruri.domain, req}
    end
  end

  test "a rung leaves in one call: every target of the group is rung" do
    _a = peer!("pf1a")
    _b = peer!("pf1b")
    _c = peer!("pf1c")

    {_dlg, tid1} = start_rung("pf1a", ["pf1b", "pf1c"])

    # The two extra branches are announced, since the layer above correlates on
    # transaction pids and would otherwise have no name for them.
    assert_receive {:outbound, {:onnewbranch, :ok, tid2}}, 2_000
    assert_receive {:outbound, {:onnewbranch, :ok, tid3}}, 2_000
    assert Enum.uniq([tid1, tid2, tid3]) |> length() == 3

    invites = collect_invites(3)

    assert Map.keys(invites) |> Enum.sort() ==
             ~w(pf1a.example.com pf1b.example.com pf1c.example.com)

    # One request, three targets: same dialog identity, one Via branch each.
    [first | others] = Map.values(invites)

    for req <- others do
      assert req.callid == first.callid
      assert req.cseq == first.cseq
      assert SIP.Uri.get_uri_param(req.from, "tag") == SIP.Uri.get_uri_param(first.from, "tag")
      refute req.transid == first.transid
    end
  end

  test "a branch failing while its sibling still rings says nothing; the rung's best is surfaced" do
    a = peer!("pf2a")
    b = peer!("pf2b")

    {dlg, _tid} = start_rung("pf2a", ["pf2b"])
    _ = collect_invites(2)

    # One device is busy. The caller must NOT hear it: the other is still ringing,
    # and a 486 relayed now is a call ended while a phone is in someone's hand.
    Manual.simulate(a, 486, 50)
    refute_receive {:outbound, {486, _, _, _}}, 500

    # The rung is over when the last one falls, and only then.
    Manual.simulate(b, 404, 50)
    assert_receive {:outbound, {code, _rsp, _tid, ^dlg}}, 3_000

    # 404 over 486: the lowest code of the rung (RFC 3261 §16.7 step 6).
    assert code == 404
  end

  test "among 4xx the rung prefers the one the caller can act on" do
    a = peer!("pf3a")
    b = peer!("pf3b")

    {dlg, _tid} = start_rung("pf3a", ["pf3b"])
    _ = collect_invites(2)

    Manual.simulate(a, 486, 50)
    Manual.simulate(b, 407, 100)

    # 407 loses on the numbers and wins on the rule: "authenticate" is something
    # a caller can do, "busy here" is not.
    assert_receive {:outbound, {407, _rsp, _tid, ^dlg}}, 3_000
  end

  test "a 6xx ends the hunt on the spot and cancels whatever is still ringing" do
    a = peer!("pf4a")
    _b = peer!("pf4b")

    {dlg, _tid} = start_rung("pf4a", ["pf4b"])
    _ = collect_invites(2)

    # A global refusal is not one device's opinion (RFC 3261 §16.7): it goes up
    # immediately, without waiting for the sibling and without aggregation.
    Manual.simulate(a, 603, 50)
    assert_receive {:outbound, {603, _rsp, _tid, ^dlg}}, 3_000

    # The sibling was CANCELled: it is only forgotten once its 487 comes back, so
    # an empty loser set is the proof the CANCEL went out and was answered.
    assert eventually(fn -> MapSet.size(:sys.get_state(dlg).fork_losers) == 0 end)

    # …and that 487 was ours to absorb, not the application's to read.
    refute_receive {:outbound, {487, _, _, _}}, 300
  end

  test "the first 2xx wins the rung and the losing branch is cancelled and absorbed" do
    _a = peer!("pf5a")
    b = peer!("pf5b")

    {dlg, _tid} = start_rung("pf5a", ["pf5b"])
    _ = collect_invites(2)

    Manual.simulate(b, 200, 50)
    assert_receive {:outbound, {200, rsp, _tid, ^dlg}}, 3_000

    # The winner's tag is the dialog's (a 18x from a loser must never have taken
    # that slot — sip_dialog_fork_test covers the unforked half of that rule).
    {:ok, winner_tag} = SIP.Uri.get_uri_param(rsp.to, "tag")
    {_f, _c, totag} = GenServer.call(dlg, :getdialogid)
    assert totag == winner_tag

    assert eventually(fn -> MapSet.size(:sys.get_state(dlg).fork_losers) == 0 end)
    refute_receive {:outbound, {487, _, _, _}}, 300
  end

  # The race RFC 3261 §16.7 leaves to the UAC: our CANCEL and their 200 cross on
  # the wire. A proxy cannot clean it up (its caller does); a B2BUA must, and the
  # scenario above must never learn that a second callee picked up.
  test "a loser that answers 2xx anyway is ACKed and BYEd behind the application's back" do
    _a = peer!("pf6a")
    b = peer!("pf6b")

    {dlg, _tid} = start_rung("pf6a", ["pf6b"])
    invites = collect_invites(2)

    Manual.simulate(b, 200, 50)
    assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 3_000

    # The loser answers before the CANCEL reaches it. Injected rather than
    # simulated: the mockup answers a CANCEL with the 487 it is supposed to, and
    # the point here is the answer that crosses it.
    sdp = %{
      contenttype: "application/sdp",
      data:
        "v=0\r\no=- 1 1 IN IP4 212.83.152.250\r\ns=-\r\nc=IN IP4 212.83.152.250\r\n" <>
          "t=0 0\r\nm=audio 7344 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    }

    late =
      SIP.Msg.Ops.reply_to_request(
        invites["pf6a.example.com"],
        200,
        "OK",
        [body: [sdp], contact: "<sip:bob@pf6a.example.com:5060>"],
        "late-answer-tag"
      )

    SIP.Transac.process_sip_message(SIPMsg.serialize(late))

    # That callee is hung up on — the BYE goes out on the branch's own flow.
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 3_000

    # And the application heard exactly one 200: the winner's.
    refute_receive {:outbound, {200, _, _, _}}, 500
  end

  test "a rung of one still surfaces its own final, which is what serial forking is" do
    a = peer!("pf7a")

    {dlg, _tid} = start_rung("pf7a", [])
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    # No sibling to wait for, nothing withheld, no aggregation: the caller gets
    # the very response the branch gave, and the dialog stays up for the next
    # target the application may arm.
    Manual.simulate(a, 486, 50)
    assert_receive {:outbound, {486, _rsp, _tid, ^dlg}}, 3_000
    assert Process.alive?(dlg)
  end

  defp eventually(fun, retries \\ 40) do
    cond do
      fun.() -> true
      retries == 0 -> false
      true -> Process.sleep(25) && eventually(fun, retries - 1)
    end
  end
end
