defmodule SIP.Test.DialogTag do
  @moduledoc """
  The dialog event tag (`SIP.Dialog.start_dialog/5` option `:tag`, design
  docs/design/DESIGN-FRAMEWORK.md#52-telling-the-legs-apart): a dialog created with `tag: :outbound`
  wraps EVERY message it delivers to its application process as
  `{:outbound, msg}` — `:onnewdialog`, responses and `:dialog_terminated`
  alike — while an untagged dialog keeps delivering bare messages (the
  historical contract, asserted by every other suite).

  Driven through the in-process UDP mockup transport, on an outbound REGISTER
  dialog (the same harness as the keepalive suite): registration is the
  simplest dialog whose full lifecycle — creation, final response,
  expiry-driven termination — can be exercised without a peer.
  """
  use ExUnit.Case
  require SIP.Dialog

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  defp register_request() do
    ruri =
      %SIP.Uri{scheme: "sip:", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "dialog_tag")
      |> SIP.Transport.Selector.select_transport()

    :ok = Mockup.set_peer(ruri.tp_pid, Manual)

    aor = %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}

    %{
      "Max-Forwards" => "70",
      method: :REGISTER,
      ruri: ruri,
      from: aor,
      to: aor,
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0", params: %{"expires" => "1"}},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }
  end

  test "a tagged dialog wraps every app event; lifecycle covered end to end" do
    register = register_request()
    tp_pid = register.ruri.tp_pid

    {:ok, dlg_pid, _dlg_id} =
      SIP.Dialog.start_dialog(register, 600, :outbound, false, tag: :outbound)

    # Creation: the initial client transaction arrives wrapped.
    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 1_000
    assert is_pid(tid)

    # Final response: wrapped too.
    Manual.simulate(tp_pid, 200, 200)
    assert_receive {:outbound, {200, rsp, _tid, ^dlg_pid}}, 1_000
    assert rsp.response == 200

    # Termination (the 1 s registration lapses with no refresh): wrapped too.
    assert_receive {:outbound, {:dialog_terminated, ^dlg_pid, _reason}}, 3_000

    # Nothing from this dialog ever arrived bare.
    refute_received {:onnewdialog, _, _}
    refute_received {200, _, _, ^dlg_pid}
    refute_received {:dialog_terminated, ^dlg_pid, _}
  end

  test "an untagged dialog keeps the bare-message contract" do
    register = register_request()
    tp_pid = register.ruri.tp_pid

    {:ok, dlg_pid, _dlg_id} = SIP.Dialog.start_dialog(register, 600, :outbound, false)

    assert_receive {:onnewdialog, :ok, _tid}, 1_000
    Manual.simulate(tp_pid, 200, 200)
    assert_receive {200, _rsp, _tid, ^dlg_pid}, 1_000
  end
end
