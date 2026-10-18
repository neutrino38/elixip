# Answers an inbound INVITE 200 OK, after naming the host its Contact publishes
# when the test asked for one, then hangs up when the test says so.
defmodule SIP.Test.ContactHostUAS do
  @behaviour SIP.Session.Call

  @impl true
  def on_new_call(_dialog_pid, _req, transaction_id) when is_pid(transaction_id) do
    probe = Process.whereis(:contact_host_probe)

    app =
      spawn(fn ->
        receive do
          {:INVITE, req, _trans, dlg} ->
            send(probe, {:inbound_dialog, dlg, self()})

            receive do
              {:contact_host, host} ->
                send(probe, {:set_contact_host, SIP.Dialog.set_contact_host(dlg, host)})
            end

            # the offer stands in for an answer: the test reads the Contact, not the SDP
            SIP.Dialog.reply(dlg, req, 200, "OK",
              body: req.body,
              contact: %SIP.Uri{userpart: "bob", domain: "0.0.0.0", params: %{}}
            )

            receive do
              :hangup ->
                ctx = %SIP.Context{dialogpid: dlg, username: "bob", domain: "example.com"}
                SIP.Session.CallInDialog.do_send_bye(ctx, nil)
                receive do: (:never -> :ok)
            end
        after
          2_000 -> :ok
        end
      end)

    {:accept, app}
  end

  @impl true
  def on_call_end(_dialog_pid, _app_pid), do: nil
end

defmodule SIP.Test.DialogContactHost do
  @moduledoc """
  `SIP.Dialog.set_contact_host/2`: on a dialog the far end opened, the Contact of
  our 2xx and of the requests we send in it names the host we were given, without
  a port — what a Teams Direct Routing hub requires of the SBC it calls
  (docs/design/sip-server-specs.md, `use_fqdn_contact`).
  """
  use ExUnit.Case

  alias SIP.Test.Transport.Mockup

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    previous = SIP.Session.ConfigRegistry.get_call_processing_module()
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SIP.Test.ContactHostUAS)
    on_exit(fn -> SIP.Session.ConfigRegistry.set_call_processing_module(previous) end)

    # gone with the test process: nothing to undo
    Process.register(self(), :contact_host_probe)
    :ok
  end

  test "the 2xx and our BYE name the host, without a port" do
    invite = inject_invite("fqdn_contact")
    {dlg, app} = answer(invite, "sbc.example.com")

    assert_receive {:sip_mockup, {:response_sent, 200, resp}}, 2_000
    assert resp.contact.domain == "sbc.example.com"
    assert SIP.Uri.get_transport(resp.contact) == "UDP"
    # what carried the name is routing, not a header
    refute SIPMsg.serialize(resp) =~ ~r/contact.?host/i
    assert SIPMsg.serialize(resp) =~ ~r/^Contact: <sip:[^>]*@sbc\.example\.com;transport=udp>/m

    ack_2xx(invite, dlg)
    send(app, :hangup)

    assert_receive {:sip_mockup, {:request_sent, :BYE, bye}}, 2_000
    assert bye.contact.domain == "sbc.example.com"
    assert SIPMsg.serialize(bye) =~ ~r/^Contact: <sip:([^>@]*@)?sbc\.example\.com;transport=udp>/m
  end

  test "nil keeps the bound address" do
    invite = inject_invite("addr_contact")
    {_dlg, _app} = answer(invite, nil)

    assert_receive {:sip_mockup, {:response_sent, 200, resp}}, 2_000
    assert resp.contact.domain != "sbc.example.com"
    assert SIPMsg.serialize(resp) =~ ~r/^Contact: <sip:bob@\d+\.\d+\.\d+\.\d+[:;]/m
  end

  defp answer(_invite, host) do
    assert_receive {:inbound_dialog, dlg, app}, 2_000
    send(app, {:contact_host, host})
    assert_receive {:set_contact_host, :ok}, 2_000
    {dlg, app}
  end

  # An inbound INVITE off the wire, through the transport and the transaction
  # layer, exactly as a real call arrives.
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

    :ok = Mockup.attach_probe(routed.tp_pid)
    Mockup.inject(routed.tp_pid, parsed)
    parsed
  end

  # ACK the 2xx as a UAC does: the dialog's To tag and a fresh Via branch, so it
  # reaches the dialog rather than the server transaction.
  defp ack_2xx(invite, dlg) do
    {_fromtag, _callid, totag} = GenServer.call(dlg, :getdialogid)
    {:ok, to} = SIP.Uri.parse(invite.to)
    branch = "z9hG4bK#{System.unique_integer([:positive])}"

    ack =
      SIP.Msg.Ops.ack_request(invite, %SIP.Uri{domain: "2.2.2.2", port: 5090})
      |> Map.put(:to, SIP.Uri.set_header_param(to, "tag", totag))

    ack =
      ack
      |> Map.put(:via, Regex.replace(~r/branch=[^;]+/, ack.via, "branch=#{branch}"))
      |> Map.put(:transid, branch)

    Mockup.inject(invite.ruri.tp_pid, ack)
  end
end
