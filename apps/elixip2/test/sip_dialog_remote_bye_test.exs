defmodule SIP.Test.DialogRemoteBye do
  @moduledoc """
  A BYE the FAR END sends ends the dialog that receives it (RFC 3261 §15.1.2).

  Our own BYE has always ended it — `closing_transaction` is matched against the
  response we get back. The other direction was never read: a dialog that
  received a BYE, answered it 200 and had nothing more to say stayed
  `:established` until its expiration timer (1800 s for an INVITE dialog:
  `arm_expiration_timer/2` is a no-op for a BYE), and its application was never
  sent `{:dialog_terminated, …}`.

  Found on 2026-08-12 with `direct-call-with-auth.exs`, when the callee hung up:
  the B2BUA teardown asks the dialog whether it is still established
  (`SIP.Session.B2bua.release_legs/1` → `wind_down_leg/2`), got "yes" for a leg
  the callee had just closed, and sent it a second BYE — answered 481
  Call/Transaction Does Not Exist, on every single call ended by the callee.
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

  # A peer of this suite's own: `;unittest=<name>` gives one mockup process per
  # name, so no other suite's traffic lands in this test's mailbox.
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

  # A call up and acknowledged, on a leg tagged like a B2BUA's outbound one.
  # Returns the dialog and the 200 it was established by — the only place the
  # far end's To tag can be read from, which is what a BYE of its own needs.
  defp established_call(name) do
    tp = peer!(name)

    {:ok, dlg, _id} =
      SIP.Dialog.start_dialog(invite_to(name), 60, :outbound, false, tag: :outbound)

    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(tp, 200, 0)
    assert_receive {:outbound, {200, resp, ^tid, ^dlg}}, 5_000
    :ok = SIP.Dialog.ack(dlg, tid)

    {tp, dlg, resp}
  end

  # The BYE the callee sends us: its own identity (and tag) on From, ours on To,
  # our Call-ID, a CSeq space of its own, a fresh Via branch.
  defp callee_bye(resp) do
    branch = SIP.Msg.Ops.generate_branch_value()

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "1.2.3.4", port: 5080},
      from: resp.to,
      to: resp.from,
      useragent: "Linphone-test",
      callid: resp.callid,
      transid: branch,
      # The far end numbers its own in-dialog requests (RFC 3261 §12.2.2). Not 1:
      # `cseqin` defaults to 1 rather than to "empty", so a first remote request
      # bearing CSeq 1 is answered 500 Out of order — a separate defect, and not
      # what this test is about.
      cseq: [21, :BYE],
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      contentlength: 0
    }
  end

  test "the dialog terminates once the BYE it received is answered 2xx" do
    {tp, dlg, resp} = established_call("remotebye1")
    ref = Process.monitor(dlg)

    Mockup.inject(tp, callee_bye(resp))

    # The BYE reaches the application on the leg it came in on.
    assert_receive {:outbound, {:BYE, bye, bye_tid, ^dlg}}, 5_000
    assert bye.method == :BYE
    assert is_pid(bye_tid)

    # Answering it is what ends the dialog — and the application is told, which
    # is how a B2BUA scenario learns the call is over and how the media is
    # released (SIP.Scenario.Runner.release_media/1 waits for this very message).
    :ok = SIP.Dialog.reply(dlg, bye, 200, "OK", [])

    assert_receive {:outbound, {:dialog_terminated, ^dlg, :normal}}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^dlg, _reason}, 5_000
  end

  test "the far end is never asked to hang up a dialog it has just closed" do
    {tp, dlg, resp} = established_call("remotebye2")

    Mockup.inject(tp, callee_bye(resp))
    assert_receive {:outbound, {:BYE, bye, _tid, ^dlg}}, 5_000
    :ok = SIP.Dialog.reply(dlg, bye, 200, "OK", [])
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :normal}}, 5_000

    # What the B2BUA teardown asks of a leg before BYEing it (`established?/1`):
    # a dialog that is gone cannot answer, so nothing is sent — the 481 the
    # callee used to answer is not reachable any more.
    refute Process.alive?(dlg)
    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 1_000
  end
end
