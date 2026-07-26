defmodule SIP.Test.Keepalive do
  @moduledoc """
  Exercises the native OPTIONS keepalive implemented in SIP.DialogImpl:

  - `SIP.Dialog.start_options_keepalive/1` arms a periodic OPTIONS on an
    established outbound REGISTER dialog;
  - responses to those keepalive OPTIONS stay dialog-internal (they are NOT
    forwarded to the application);
  - a peer that stops answering the keepalives triggers a dialog teardown with
    reason `:keepalive_timeout` after `@max_missed_keepalive` misses.

  The dialog is driven through the in-process UDP mockup transport
  (`SIP.Test.Transport.UDPMockup`), which captures sent OPTIONS, forwards them to
  the test process and (optionally) auto-replies 200 OK.
  """
  use ExUnit.Case
  require SIP.Dialog
  require SIP.Uri

  alias SIP.Test.Transport.UDPMockup

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    # Shorten the keepalive period so the test does not wait 15 s per tick.
    prev = Application.get_env(:elixip2, :optionkeepaliveperiod)
    Application.put_env(:elixip2, :optionkeepaliveperiod, 1)
    on_exit(fn -> Application.put_env(:elixip2, :optionkeepaliveperiod, prev) end)
    :ok
  end

  # Create an outbound REGISTER dialog, route it through the UDP mockup and drive
  # it to the :established state with a 200 OK. Returns {dialog_pid, transport_pid}.
  # `drop_options?` sets whether the mockup will answer the keepalive OPTIONS.
  defp establish_register_dialog(drop_options?) do
    ruri =
      %SIP.Uri{scheme: "sip:", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "1")
      |> SIP.Transport.Selector.select_transport()

    tp_pid = ruri.tp_pid
    assert is_pid(tp_pid)

    # The test process becomes the mockup's "test app" (receives {:options_sent,…})
    # and we reset the shared instance's keepalive-answering behaviour.
    :ok = GenServer.call(tp_pid, :settestapp)
    UDPMockup.drop_options(tp_pid, drop_options?)

    aor = %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}

    register = %{
      "Max-Forwards" => "70",
      method: :REGISTER,
      ruri: ruri,
      from: aor,
      to: aor,
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0", params: %{"expires" => "600"}},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }

    {:ok, dlg_pid, _dlg_id} = SIP.Dialog.start_dialog(register, 600, :outbound, false)

    # The dialog signals creation and the initial client transaction.
    assert_receive {:onnewdialog, :ok, _tid}, 1_000

    # Answer the REGISTER with a 200 OK to confirm the dialog. Going through the
    # :successfulregister scenario also sets the mockup's :scenario field, which
    # its response-logging path relies on.
    UDPMockup.simulate_successful_register(tp_pid)
    assert_receive {200, _rsp, _tid, ^dlg_pid}, 1_000

    {dlg_pid, tp_pid}
  end

  test "keepalive OPTIONS are sent periodically and their replies stay internal" do
    {dlg_pid, _tp_pid} = establish_register_dialog(false)

    assert :ok = SIP.Dialog.start_options_keepalive(dlg_pid)

    # A first keepalive OPTIONS goes out about one period later...
    assert_receive {:options_sent, opt1}, 2_000
    assert opt1.method == :OPTIONS

    # ...and a second one, proving the timer re-arms itself (regression guard:
    # the timer ref used to never be cleared, so it fired only once).
    assert_receive {:options_sent, _opt2}, 2_000

    # The mockup answers each OPTIONS with a 200 OK. While the keepalive is
    # active those responses must NOT be surfaced to the application.
    refute_receive {_code, %{cseq: [_, :OPTIONS]}, _tid, ^dlg_pid}, 500
  end

  test "an app-initiated OPTIONS disarms the automatic keepalive" do
    {dlg_pid, _tp_pid} = establish_register_dialog(false)

    assert :ok = SIP.Dialog.start_options_keepalive(dlg_pid)
    assert_receive {:options_sent, _opt}, 2_000

    # The app sends its own OPTIONS: this disarms the keepalive, so from now on
    # OPTIONS responses flow back up to the app as normal traffic.
    options = %{
      "Max-Forwards" => "70",
      method: :OPTIONS,
      ruri: %SIP.Uri{scheme: "sip:", domain: "example.com"},
      from: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"},
      to: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }

    assert {:ok, _tid} = SIP.Dialog.new_request(dlg_pid, options)

    # The response to the app-initiated OPTIONS is now delivered to the app.
    assert_receive {200, %{cseq: [_, :OPTIONS]}, _tid2, ^dlg_pid}, 2_000
  end

  test "an unresponsive peer tears the dialog down after missed keepalives" do
    {dlg_pid, _tp_pid} = establish_register_dialog(true)

    assert :ok = SIP.Dialog.start_options_keepalive(dlg_pid)

    # With a 1 s period and @max_missed_keepalive = 3, teardown happens on the
    # 4th tick (~4 s). terminate/2 reports the reason to the app.
    assert_receive {:dialog_terminated, ^dlg_pid, :keepalive_timeout}, 6_000
    refute Process.alive?(dlg_pid)
  end
end
