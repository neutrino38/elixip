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

    previous_t1 = Application.fetch_env(:elixip2, :sip_timer_T1)
    if t1 = context[:t1], do: Application.put_env(:elixip2, :sip_timer_T1, t1)

    on_exit(fn ->
      case previous do
        {:ok, v} -> Application.put_env(:elixip2, :session_timer, v)
        :error -> Application.delete_env(:elixip2, :session_timer)
      end

      case previous_t1 do
        {:ok, v} -> Application.put_env(:elixip2, :sip_timer_T1, v)
        :error -> Application.delete_env(:elixip2, :sip_timer_T1)
      end
    end)

    :ok
  end

  @enabled [enabled: true, expires: 1800, min_se: 90]

  @offer "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n" <>
           "m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"

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

  # ── The UAC side (RFC 4028 §7) ──────────────────────────────────────────────

  test "disabled, the INVITE says nothing about a session timer" do
    {_tp, _dlg, _tid, invite} = start_call("st_uac_off")

    assert Ops.session_expires(invite) == nil
    assert Ops.min_se(invite) == nil
    refute "timer" in Ops.supported_extensions(invite)
  end

  @tag session_timer: @enabled
  test "the INVITE asks for our interval and offers to refresh it" do
    {_tp, _dlg, _tid, invite} = start_call("st_uac_invite")

    assert Ops.session_expires(invite) == {1800, :uac}
    assert Ops.min_se(invite) == 90
    assert "timer" in Ops.supported_extensions(invite)
  end

  @tag session_timer: Keyword.put(@enabled, :refresher, :remote)
  test "…and leaves the refresher to the far end when that is the configured choice" do
    {_tp, _dlg, _tid, invite} = start_call("st_uac_choice")
    assert Ops.session_expires(invite) == {1800, nil}
  end

  @tag session_timer: @short
  test "a far end that refreshes and stops is hung up" do
    {_tp, dlg, _resp} =
      established_call("st_uac_expiry", %{"Session-Expires" => "3;refresher=uas"})

    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 1_500
    assert_receive {:sip_mockup, {:request_sent, :BYE, bye}}, 1_500
    assert Map.get(bye, "Reason") =~ "Session Timer Expired"
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 3_000
  end

  @tag session_timer: @short
  test "a 2xx naming us the refresher leaves no one to wait for" do
    {_tp, dlg, _resp} =
      established_call("st_uac_local", %{"Session-Expires" => "3;refresher=uac"})

    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 3_000
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "a 2xx stating no timer turns it off" do
    {_tp, dlg, _resp} = established_call("st_uac_none")

    refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 3_000
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @enabled
  test "every re-offer we send restates the timer in force" do
    {_tp, dlg, _resp} =
      established_call("st_uac_restate", %{"Session-Expires" => "600;refresher=uas"})

    {:ok, _tid} = SIP.Dialog.new_request(dlg, update_request())
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, update}}, 2_000

    # The far end refreshes, so from our side of THIS transaction it is the UAS.
    assert Ops.session_expires(update) == {600, :uas}
    assert "timer" in Ops.supported_extensions(update)
  end

  # ── 422 to a request we sent (RFC 4028 §7.3) ────────────────────────────────

  @tag session_timer: @enabled
  test "an INVITE refused 422 goes again with the far end's floor, out of sight" do
    {tp, dlg, tid, invite} = start_call("st_uac_422")
    [first_cseq, :INVITE] = invite.cseq

    Manual.simulate(tp, 422, 0, %{"Min-SE" => "2000"})

    # The 422 is acknowledged by its own transaction (RFC 3261 §17.1.1.3).
    assert_receive {:sip_mockup, {:request_sent, :ACK, %{cseq: [^first_cseq, :ACK]}}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, retry}}, 2_000
    assert Ops.session_expires(retry) == {2000, :uac}
    assert Ops.min_se(retry) == 2000
    assert [cseq, :INVITE] = retry.cseq
    assert cseq > first_cseq
    assert retry.callid == invite.callid
    refute_received {:outbound, {422, _resp, _tid, ^dlg}}

    # Answered — and known to the application by the transaction it already had,
    # down to the ACK it asks for.
    Manual.simulate(tp, 200, 0, %{"Session-Expires" => "2000;refresher=uac"})
    assert_receive {:outbound, {200, _resp, ^tid, ^dlg}}, 5_000
    :ok = SIP.Dialog.ack(dlg, tid)
    assert_receive {:sip_mockup, {:request_sent, :ACK, ack}}, 2_000
    assert [^cseq, :ACK] = ack.cseq
  end

  @tag session_timer: @enabled
  test "a far end answering 422 again is not asked forever" do
    {tp, dlg, tid, _invite} = start_call("st_uac_422_twice")

    Manual.simulate(tp, 422, 0, %{"Min-SE" => "2000"})
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _retry}}, 2_000

    Manual.simulate(tp, 422, 0, %{"Min-SE" => "2000"})
    assert_receive {:outbound, {422, _resp, ^tid, ^dlg}}, 2_000
    refute_receive {:sip_mockup, {:request_sent, :INVITE, _}}, 500
  end

  @tag session_timer: @enabled
  test "a refresh refused 422 goes again too, and is answered under its own name" do
    {tp, dlg, _resp} =
      established_call("st_uac_422_update", %{"Session-Expires" => "600;refresher=uas"})

    {:ok, update_tid} = SIP.Dialog.new_request(dlg, update_request())
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _update}}, 2_000

    Manual.simulate(tp, 422, 0, %{"Min-SE" => "2000"})
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, retry}}, 2_000
    assert Ops.session_expires(retry) == {2000, :uas}

    Manual.simulate(tp, 200, 0, %{"Session-Expires" => "2000;refresher=uas"})
    assert_receive {:outbound, {200, _resp, ^update_tid, ^dlg}}, 2_000
  end

  # ── Our refreshes (RFC 4028 §7.4, §10) ──────────────────────────────────────

  # A refresh is due at half the 3 s interval.
  @refresh_due 1_500

  @tag session_timer: @short
  test "we refresh at half the interval, with an UPDATE the application never hears of" do
    {tp, dlg, _resp} =
      established_call("st_ref_update", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, update}}, @refresh_due + 500
    assert Ops.session_expires(update) == {3, :uac}
    assert Ops.sdp_body(update) == nil

    Manual.simulate(tp, 200, 0, %{"Session-Expires" => "3;refresher=uac"})
    refute_receive {:outbound, {200, _resp, _tid, ^dlg}}, 300

    # …and again, the 2xx having started a new interval.
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "a far end refusing UPDATE is refreshed with a re-INVITE of our unchanged offer" do
    {tp, dlg, _resp} =
      established_call("st_ref_reinvite", %{"Session-Expires" => "3;refresher=uac"}, sdp: true)

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 405, 0)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, reinvite}}, 1_000
    assert Ops.sdp_body(reinvite) == @offer
    assert Ops.session_expires(reinvite) == {3, :uac}

    # Its 2xx is acknowledged by the dialog: nobody else sent it.
    Manual.simulate(tp, 200, 0, %{"Session-Expires" => "3;refresher=uac"})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 1_000
    refute_received {:outbound, {200, _resp, _tid, ^dlg}}

    # The next refresh is a re-INVITE straight away.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _}}, @refresh_due + 500
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "a far end refusing UPDATE, with nothing of ours to re-offer, is not refreshed" do
    {tp, dlg, _resp} =
      established_call("st_ref_nosdp", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 501, 0)

    refute_receive {:sip_mockup, {:request_sent, :INVITE, _}}, 1_000
    assert Process.alive?(dlg)
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "a refresh answered 481 ends the call, with no BYE to a dialog the far end lost" do
    {tp, dlg, _resp} = established_call("st_ref_481", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 481, 0)

    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 2_000
    refute_received {:sip_mockup, {:request_sent, :BYE, _}}
  end

  @tag session_timer: @short
  test "a refresh answered 408 hangs the call up" do
    {tp, dlg, _resp} = established_call("st_ref_408", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 408, 0)

    assert_receive {:sip_mockup, {:request_sent, :BYE, bye}}, 1_000
    assert Map.get(bye, "Reason") =~ "Session Timer Expired"
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 2_000
  end

  @tag session_timer: @short, t1: 10
  test "a refresh nobody answers hangs the call up" do
    {_tp, dlg, _resp} =
      established_call("st_ref_timeout", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500

    # Timer F at 64*T1 = 640 ms; the far end answers nothing at all.
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 2_000
    assert_receive {:outbound, {:dialog_terminated, ^dlg, :session_expired}}, 3_000
  end

  @tag session_timer: @short
  test "a refresh crossing the far end's offer (491) goes again after a while" do
    {tp, dlg, _resp} = established_call("st_ref_491", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 491, 0)

    # RFC 3261 §14.1: 2.1 to 4 s for the owner of the Call-ID.
    refute_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, 2_500
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "a refresh refused for another reason is tried once more, ahead of the deadline" do
    {tp, dlg, _resp} = established_call("st_ref_500", %{"Session-Expires" => "3;refresher=uac"})

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, @refresh_due + 500
    Manual.simulate(tp, 500, 0)

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, _}}, 1_000
    assert Process.alive?(dlg)
    SIP.Dialog.terminate(dlg, :normal)
  end

  @tag session_timer: @short
  test "inbound, a peer that leaves the refresh to us is refreshed by us" do
    {tp, dlg, _resp} = established_call("st_ref_uas")

    resp =
      refresh_and_answer(tp, dlg, %{
        "Session-Expires" => "3;refresher=uas",
        :supported => ["timer"]
      })

    assert Ops.session_expires(resp) == {3, :uas}

    # Our side of the next transaction is the UAC's.
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, update}}, @refresh_due + 500
    assert Ops.session_expires(update) == {3, :uac}
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
  # `headers` go on the callee's 200.
  defp established_call(name, headers \\ %{}, opts \\ []) do
    {tp, dlg, tid, _invite} = start_call(name, opts)
    resp = answer_call(tp, dlg, tid, headers)
    {tp, dlg, resp}
  end

  defp start_call(name, opts \\ []) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    invite =
      if opts[:sdp],
        do:
          Ops.update_sip_msg(
            invite_to(name),
            {:body, [%{contenttype: "application/sdp", data: @offer}]}
          ),
        else: invite_to(name)

    {:ok, dlg, _id} = SIP.Dialog.start_dialog(invite, 60, :outbound, false, tag: :outbound)

    assert_receive {:outbound, {:onnewdialog, :ok, tid}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, invite}}, 2_000
    {tp, dlg, tid, invite}
  end

  defp answer_call(tp, dlg, tid, headers) do
    Manual.simulate(tp, 200, 0, headers)
    assert_receive {:outbound, {200, resp, ^tid, ^dlg}}, 5_000
    :ok = SIP.Dialog.ack(dlg, tid)
    assert_receive {:sip_mockup, {:request_sent, :ACK, _ack}}, 2_000
    resp
  end

  # An in-dialog request as an application hands it to the dialog: every
  # addressing field is filled in by `send_in_dialog_request/2`.
  defp update_request do
    uri = %SIP.Uri{userpart: nil, domain: nil}

    %{
      "Max-Forwards" => "70",
      method: :UPDATE,
      ruri: uri,
      from: uri,
      to: uri,
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0"},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }
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
