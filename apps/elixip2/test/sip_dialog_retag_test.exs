defmodule SIP.Test.DialogRetag do
  @moduledoc """
  The 2xx that establishes an outbound dialog names its remote tag (RFC 3261
  §12.1.2, §13.2.2.4), even when a 1xx gave the early dialog another one.

  The Microsoft PSTN hub answers one INVITE with a 180 from one leg and a 200 from
  another, two To-tags. The dialog kept the 180's, so it was registered under a key
  no in-dialog request named: the hub's re-INVITE completing ICE got a 481 and the
  hub hung up eight seconds into the call (capture of 2026-10-19).
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

  # `SIPMsg.parse/2` leaves From and To as the raw header values they arrived as.
  defp tag_of(%SIP.Uri{} = uri), do: SIP.Uri.get_header_param(uri, "tag")

  defp tag_of(value) when is_binary(value) do
    {:ok, uri} = SIP.Uri.parse(value)
    tag_of(uri)
  end

  test "a 200 with another To-tag than the 180's moves the dialog to the 200's" do
    tp = SIP.Transport.Selector.select_transport(target("retag1")).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    {:ok, dlg, _id} = SIP.Dialog.start_dialog(invite_to("retag1"), 60, :outbound, false)
    assert_receive {:onnewdialog, :ok, tid}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(tp, 180, 0)
    assert_receive {180, ringing, ^tid, ^dlg}, 5_000

    Manual.retag(tp, "answering-leg")
    Manual.simulate(tp, 200, 0)
    assert_receive {200, ok, ^tid, ^dlg}, 5_000
    refute tag_of(ringing.to) == tag_of(ok.to)
    :ok = SIP.Dialog.ack(dlg, tid)

    # The far end's in-dialog request names the 200's tag: it must reach the
    # application instead of being answered 481 by the stack.
    Manual.hangup(tp)
    assert_receive {:BYE, bye, _bye_tid, ^dlg}, 5_000
    refute_received {:sip_mockup, {:response_sent, 481, _}}
    assert {:ok, "answering-leg"} = tag_of(bye.from)
  end
end
