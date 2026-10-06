defmodule SessionTimerTestCallUAS do
  @moduledoc false
  # Accepts every call and says so: the 422 tests assert the application is NOT
  # reached when the session interval is refused.
  @behaviour SIP.Session.Call

  @impl true
  def on_new_call(_dialog_pid, _req, _transaction_id) do
    if probe = Process.whereis(:session_timer_probe), do: send(probe, :call_dispatched)
    {:accept, spawn(fn -> Process.sleep(5_000) end)}
  end

  @impl true
  def on_call_end(_dialog_pid, _app_pid), do: nil
end

defmodule SIP.Test.SessionTimerDialog do
  @moduledoc """
  RFC 4028 session timers, UAS side, as the dialog keeps them
  (`SIP.DialogImpl.SessionTimer`).

  The calls are outbound dialogs — a B2BUA's callee leg — so it is the FAR END
  that refreshes with an UPDATE and this dialog that answers it: the dialog states
  the timer on the 2xx whoever composed it, and holds the far end to it.
  """
  use ExUnit.Case

  alias SIP.Msg.Ops
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

  setup context do
    previous = Application.fetch_env(:elixip2, :session_timer)

    case context[:session_timer] do
      nil -> Application.delete_env(:elixip2, :session_timer)
      cfg -> Application.put_env(:elixip2, :session_timer, cfg)
    end

    on_exit(fn ->
      case previous do
        {:ok, v} -> Application.put_env(:elixip2, :session_timer, v)
        :error -> Application.delete_env(:elixip2, :session_timer)
      end
    end)

    :ok
  end

  @enabled [enabled: true, expires: 1800, min_se: 90]

  # ── Negotiation on the 2xx ──────────────────────────────────────────────────

  test "disabled (the default), a 2xx says nothing about a session timer" do
    {tp, dlg, _resp} = established_call("st_off")

    resp = refresh_and_answer(tp, dlg, %{"Session-Expires" => "90;refresher=uac"})
    assert Ops.session_expires(resp) == nil
    refute "timer" in Ops.required_extensions(resp)
  end

  @tag session_timer: @enabled
  test "the interval and the refresher the peer asked for are kept" do
    {tp, dlg, _resp} = established_call("st_kept")

    resp =
      refresh_and_answer(tp, dlg, %{
        "Session-Expires" => "90;refresher=uac",
        :supported => ["timer"]
      })

    assert Ops.session_expires(resp) == {90, :uac}
    assert "timer" in Ops.required_extensions(resp)
  end

  @tag session_timer: @enabled
  test "an interval above ours is brought down to ours" do
    {tp, dlg, _resp} = established_call("st_capped")

    resp =
      refresh_and_answer(tp, dlg, %{"Session-Expires" => "7200", :supported => ["timer"]})

    assert {1800, _} = Ops.session_expires(resp)
  end

  @tag session_timer: @enabled
  test "a peer leaving the choice to us is told we refresh" do
    {tp, dlg, _resp} = established_call("st_choice")

    resp = refresh_and_answer(tp, dlg, %{"Session-Expires" => "600", :supported => ["timer"]})
    assert Ops.session_expires(resp) == {600, :uas}
  end

  @tag session_timer: Keyword.put(@enabled, :refresher, :remote)
  test "…or that it refreshes, when that is the configured choice" do
    {tp, dlg, _resp} = established_call("st_remote")

    resp = refresh_and_answer(tp, dlg, %{"Session-Expires" => "600", :supported => ["timer"]})
    assert Ops.session_expires(resp) == {600, :uac}
  end

  @tag session_timer: Keyword.put(@enabled, :refresher, :remote)
  test "a peer that does not support timers cannot refresh: we do, and require nothing" do
    {tp, dlg, _resp} = established_call("st_unsupported")

    resp = refresh_and_answer(tp, dlg, %{})
    assert Ops.session_expires(resp) == {1800, :uas}
    refute "timer" in Ops.required_extensions(resp)
  end

  # ── 422 Session Interval Too Small (RFC 4028 §8.1) ──────────────────────────

  @tag session_timer: @enabled
  test "a refresh asking for less than our floor is refused 422, before the application" do
    {tp, dlg, _resp} = established_call("st_422_update")

    Manual.refresh_session(tp, %{"Session-Expires" => "30", :supported => ["timer"]})

    assert_receive {:sip_mockup, {:response_sent, 422, resp}}, 2_000
    assert Ops.min_se(resp) == 90
    refute_receive {:outbound, {:UPDATE, _req, _tid, ^dlg}}, 300
  end

  @tag session_timer: @enabled
  test "an INVITE asking for less than our floor never creates a call" do
    Process.register(self(), :session_timer_probe)
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SessionTimerTestCallUAS)

    invite = inject_invite("st_422_invite", %{"Session-Expires" => "30"})

    assert_receive {:sip_mockup, {:response_sent, 422, resp}}, 2_000
    assert Ops.min_se(resp) == 90
    refute_received :call_dispatched

    ack_final(invite)
  end

  # ── Expiry (RFC 4028 §10) ───────────────────────────────────────────────────

  # Short enough to be waited for: a 3 s interval expires 1 s early (a third of
  # it, below the 32 s cap), so the BYE goes out at 2 s.
  @short [enabled: true, expires: 3, min_se: 1]

  @tag session_timer: @short
  test "a peer that stops refreshing is hung up, and the application told why" do
    {tp, dlg, _resp} = established_call("st_expiry")

    resp =
      refresh_and_answer(tp, dlg, %{
        "Session-Expires" => "3;refresher=uac",
        :supported => ["timer"]
      })

    assert Ops.session_expires(resp) == {3, :uac}

    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 1_500
    assert_receive {:sip_mockup, {:request_sent, :BYE, bye}}, 1_500
    assert Map.get(bye, "Reason") =~ "Session Timer Expired"

    # The far end answers that BYE (Manual does on its own); the answer is the
    # dialog's, and what reaches the application is the end of its call.
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 3_000
    refute_received {:outbound, {200, %{cseq: [_, :BYE]}, _tid, ^dlg}}
  end

  @tag session_timer: @short
  test "each refresh starts a new interval" do
    {tp, dlg, _resp} = established_call("st_rearm")
    headers = %{"Session-Expires" => "3;refresher=uac", :supported => ["timer"]}

    refresh_and_answer(tp, dlg, headers)
    Process.sleep(1_500)
    refresh_and_answer(tp, dlg, headers)

    # 2.5 s after the first refresh — past its expiry — and still up.
    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 1_000
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 2_000
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 3_000
  end

  @tag session_timer: @short
  test "when we are the refresher, the peer is not waited for" do
    {tp, dlg, _resp} = established_call("st_local")

    resp =
      refresh_and_answer(tp, dlg, %{
        "Session-Expires" => "3;refresher=uas",
        :supported => ["timer"]
      })

    assert Ops.session_expires(resp) == {3, :uas}
    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 3_000
    assert Process.alive?(dlg)
    SIP.Dialog.terminate(dlg, :normal)
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp target(name) do
    %SIP.Uri{
      scheme: "sip:",
      userpart: "bob",
      domain: "#{String.replace(name, "_", "-")}.example.com",
      port: 5060
    }
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

  # A call up and acknowledged, on a leg tagged like a B2BUA's outbound one.
  defp established_call(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    {:ok, dlg, _id} =
      SIP.Dialog.start_dialog(invite_to(name), 60, :outbound, false, tag: :outbound)

    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000

    Manual.simulate(tp, 200, 0)
    assert_receive {:outbound, {200, resp, ^tid, ^dlg}}, 5_000
    :ok = SIP.Dialog.ack(dlg, tid)

    {tp, dlg, resp}
  end

  # The far end refreshes; the application answers a bare 200, as a B2BUA does
  # (`b2bua_reply_reoffer/1`). Returns the 200 as it went on the wire.
  defp refresh_and_answer(tp, dlg, headers) do
    Manual.refresh_session(tp, headers)
    assert_receive {:outbound, {:UPDATE, update, _tid, ^dlg}}, 2_000

    :ok =
      SIP.Dialog.reply(dlg, update, 200, "OK",
        contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0"}
      )

    assert_receive {:sip_mockup, {:response_sent, 200, resp}}, 2_000
    resp
  end

  defp inject_invite(name, headers) do
    {:ok, msg} = File.read("test/SIP-INVITE-LVP.txt")
    {:ok, parsed} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)

    parsed =
      parsed
      |> Map.put(:callid, "#{name}-#{System.unique_integer([:positive])}")
      |> Map.merge(headers)

    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    parsed = Ops.add_via(parsed, {{2, 2, 2, 2}, 5090, "UDP"}, branch)

    routed =
      SIP.Transport.Selector.select_transport(
        SIP.Uri.set_uri_param(parsed.ruri, "unittest", name)
      )

    parsed = Ops.update_sip_msg(parsed, {:ruri, routed})

    :ok = Mockup.attach_probe(routed.tp_pid)
    Mockup.inject(routed.tp_pid, parsed)
    parsed
  end

  # ACK the non-2xx final so the IST stops resending it into the next tests.
  defp ack_final(invite) do
    ack =
      Ops.ack_request(invite, %SIP.Uri{domain: "2.2.2.2", port: 5090})
      |> Map.put(:transid, invite.transid)

    Mockup.inject(invite.ruri.tp_pid, ack)
    :ok
  end
end
