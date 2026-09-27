defmodule SIP.Test.EventsUAS do
  @behaviour SIP.Session.Call

  # Rings at once, answers when the test says so, and hands the test the dialog
  # and the application it created — the way SIP.Test.DyingUAS does.
  @impl true
  def on_new_call(dialog_pid, _req, transaction_id) when is_pid(transaction_id) do
    probe = Process.whereis(:dialog_events_probe)

    app =
      spawn(fn ->
        receive do
          {:INVITE, req, _trans, dlg} ->
            :ok = SIP.Dialog.reply(dlg, req, 180, "Ringing", [])

            receive do
              :answer ->
                body = [
                  %{contenttype: "application/sdp", data: "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"}
                ]

                contact = %SIP.Uri{userpart: "bob", domain: "1.2.3.4", port: 5060}
                :ok = SIP.Dialog.reply(dlg, req, 200, "OK", [{:body, body}, {:contact, contact}])
            end

            # Whatever comes next on the dialog is the test's to read.
            forward_to(probe)
        end
      end)

    send(probe, {:inbound_dialog, dialog_pid, app})
    {:accept, app}
  end

  @impl true
  def on_call_end(_dialog_pid, _app_pid), do: nil

  defp forward_to(probe) do
    receive do
      msg ->
        send(probe, msg)
        forward_to(probe)
    end
  end
end

defmodule SIP.Test.DialogEvents do
  @moduledoc """
  The call state of a STAMPED dialog reaches whoever subscribed to
  `SIP.Dialog.Events` (docs/design/dialog-state-plan.md, DS1); an unstamped one
  says nothing to anyone.
  """
  use ExUnit.Case

  alias SIP.Dialog.Events
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @aor %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    :ok = Events.subscribe()
    on_exit(fn -> Events.unsubscribe() end)
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

  defp start_call(name, opts) do
    {:ok, dlg, _id} = SIP.Dialog.start_dialog(invite_to(name), 60, :outbound, false, opts)
    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000
    {dlg, tid}
  end

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
      cseq: [21, :BYE],
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      contentlength: 0
    }
  end

  describe "an outbound dialog stamped at creation" do
    test "pushes trying, early, confirmed, then terminated by the far end's BYE" do
      tp = peer!("ev1")
      {dlg, tid} = start_call("ev1", tag: :outbound, remote_aor: @aor)

      assert_receive {:sip_dialog, ^dlg,
                      %{state: :trying, remote_aor: @aor, direction: :outbound}}

      Manual.simulate(tp, 180, 0)
      assert_receive {:sip_dialog, ^dlg, %{state: :early, totag: totag}}, 2_000
      assert is_binary(totag)

      Manual.simulate(tp, 200, 0)
      assert_receive {:outbound, {200, resp, ^tid, ^dlg}}, 5_000
      :ok = SIP.Dialog.ack(dlg, tid)
      assert_receive {:sip_dialog, ^dlg, %{state: :confirmed, confirmed_at: %DateTime{}}}, 2_000

      Mockup.inject(tp, callee_bye(resp))
      assert_receive {:outbound, {:BYE, bye, _tid, ^dlg}}, 5_000
      :ok = SIP.Dialog.reply(dlg, bye, 200, "OK", [])

      assert_receive {:sip_dialog, ^dlg, %{state: :terminated, event: :remote_bye}}, 5_000
      assert_receive {:outbound, {:dialog_terminated, ^dlg, :normal}}, 5_000
    end

    test "a refused call ends rejected, never confirmed" do
      tp = peer!("ev2")
      {dlg, _tid} = start_call("ev2", tag: :outbound, remote_aor: @aor)
      assert_receive {:sip_dialog, ^dlg, %{state: :trying}}

      Manual.simulate(tp, 486, 0)
      assert_receive {:sip_dialog, ^dlg, %{state: :terminated, event: :rejected}}, 5_000
      refute_received {:sip_dialog, ^dlg, %{state: :confirmed}}
    end

    test "info/1 reads the same state on demand" do
      _tp = peer!("ev3")
      {dlg, _tid} = start_call("ev3", tag: :outbound, remote_aor: @aor)

      assert %{state: :trying, remote_aor: @aor, method: :INVITE, callid: callid} =
               SIP.Dialog.info(dlg)

      assert is_binary(callid)
    end
  end

  describe "an outbound dialog stamped later" do
    test "starts its subscriber from the state it is in" do
      tp = peer!("ev4")
      {dlg, _tid} = start_call("ev4", tag: :outbound)

      Manual.simulate(tp, 180, 0)
      refute_receive {:sip_dialog, ^dlg, _}, 500

      :ok = SIP.Dialog.set_remote_aor(dlg, @aor)
      assert_receive {:sip_dialog, ^dlg, %{state: :early, remote_aor: @aor}}, 2_000
    end
  end

  describe "a dialog nobody stamped" do
    test "pushes nothing, whatever happens to it" do
      tp = peer!("ev5")
      {dlg, tid} = start_call("ev5", tag: :outbound)

      Manual.simulate(tp, 180, 0)
      Manual.simulate(tp, 200, 100)
      assert_receive {:outbound, {200, _resp, ^tid, ^dlg}}, 5_000
      :ok = SIP.Dialog.ack(dlg, tid)

      refute_receive {:sip_dialog, ^dlg, _}, 500
    end
  end

  describe "a stamped dialog that is killed" do
    test "pushes no terminated: the subscriber's monitor is what fires" do
      _tp = peer!("ev6")
      {dlg, _tid} = start_call("ev6", tag: :outbound, remote_aor: @aor)
      assert_receive {:sip_dialog, ^dlg, %{state: :trying}}
      ref = Process.monitor(dlg)

      Process.exit(dlg, :kill)

      assert_receive {:DOWN, ^ref, :process, ^dlg, :killed}, 2_000
      refute_receive {:sip_dialog, ^dlg, %{state: :terminated}}, 500
    end
  end

  # An inbound INVITE off the wire, through the transport and the transaction
  # layer, as a real call arrives.
  defp inject_invite(name) do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, parsed} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> :ok end)

    parsed = Map.put(parsed, :callid, "#{name}-#{System.unique_integer([:positive])}")
    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    parsed = SIP.Msg.Ops.add_via(parsed, {{2, 2, 2, 2}, 5090, "UDP"}, branch)

    routed =
      parsed.ruri
      |> SIP.Uri.set_uri_param("unittest", name)
      |> SIP.Transport.Selector.select_transport()

    parsed = SIP.Msg.Ops.update_sip_msg(parsed, {:ruri, routed})

    # The far end answers what we send it — the BYE the dialog sends when its
    # application dies is what ends it (`answer_nobody_awaits/2`).
    :ok = Mockup.set_peer(routed.tp_pid, Manual)
    :ok = Mockup.attach_probe(routed.tp_pid)
    Mockup.inject(routed.tp_pid, parsed)
    parsed
  end

  describe "an inbound dialog" do
    setup do
      previous = SIP.Session.ConfigRegistry.get_call_processing_module()
      :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SIP.Test.EventsUAS)
      on_exit(fn -> SIP.Session.ConfigRegistry.set_call_processing_module(previous) end)
      Process.register(self(), :dialog_events_probe)
      :ok
    end

    test "stamped after it rang, it starts at early and goes on to confirmed" do
      invite = inject_invite("ev7")
      assert_receive {:inbound_dialog, dlg, app}, 2_000
      assert_receive {:sip_mockup, {:response_sent, 180, _}}, 2_000
      refute_received {:sip_dialog, ^dlg, _}

      :ok = SIP.Dialog.set_remote_aor(dlg, @aor)
      assert_receive {:sip_dialog, ^dlg, %{state: :early, direction: :inbound}}, 2_000

      send(app, :answer)
      assert_receive {:sip_dialog, ^dlg, %{state: :confirmed, totag: totag}}, 2_000
      assert_receive {:sip_mockup, {:response_sent, 200, _}}, 2_000

      # The caller hangs up: the BYE reaches the application, which answers it.
      inject_bye(invite, totag)
      assert_receive {:BYE, bye, _tid, ^dlg}, 5_000
      :ok = SIP.Dialog.reply(dlg, bye, 200, "OK", [])
      assert_receive {:sip_dialog, ^dlg, %{state: :terminated, event: :remote_bye}}, 5_000
    end
  end

  # The caller's BYE, in the dialog the INVITE above created: its tag on From,
  # ours on To, routed to the same mockup instance.
  defp inject_bye(invite, totag) do
    branch = SIP.Msg.Ops.generate_branch_value()
    {:ok, from} = SIP.Uri.parse(invite.from)
    {:ok, to} = SIP.Uri.parse(invite.to)

    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: invite.ruri,
      from: from,
      to: SIP.Uri.set_header_param(to, "tag", totag),
      useragent: "LiveVideoPlugin-test",
      callid: invite.callid,
      transid: branch,
      cseq: [9679, :BYE],
      via: ["SIP/2.0/UDP 2.2.2.2:5090;branch=#{branch}"],
      contentlength: 0
    }

    Mockup.inject(invite.ruri.tp_pid, bye)
  end
end
