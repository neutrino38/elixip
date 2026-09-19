# How long an INVITE server transaction lets its TU ring, and what it says when
# it stops waiting.
#
# Two facts, both learnt from the traffic of 2026-09-16, where a B2BUA answered
# its caller 408 at 32 s while the callee was still ringing and then had nothing
# left to relay the callee's 603 to:
#
#   * an IST does NOT end a call at 64*T1. RFC 3261 §17.2.1 gives it no timeout:
#     how long a phone rings is the TU's decision, and timer F answers a
#     different question;
#   * when it does give up, it tells the layer above. The application is working
#     for that caller — a B2BUA is ringing a callee for them — and the only thing
#     that stops it is hearing that the caller's INVITE is over.

defmodule ISTRingingFixture.RingForever do
  use SIP.Scenario
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        reply_invite(180, "Ringing")
        goto(ringing, "ringing")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end

  # Rings and answers nothing else, so only the stack can end this call.
  state ringing do
    on_events do
      {:dialog_terminated, _dlg, reason} ->
        send(Process.whereis(:ist_ringing_probe), {:told, reason})
        scenario_success("the stack said the caller is gone")
    after
      20_000 -> scenario_failure("never told the caller's INVITE was over")
    end
  end
end

defmodule ISTRingingCallUAS do
  @behaviour SIP.Session.Call

  @impl true
  def on_new_call(dialog_pid, req, transaction_id) when is_pid(transaction_id) do
    pid =
      spawn(fn ->
        SIP.Scenario.Runner.run_instance(ISTRingingFixture.RingForever,
          dialog_pid: dialog_pid,
          inbound_request: req
        )
      end)

    {:accept, pid}
  end

  @impl true
  def on_call_end(_dialog_pid, _app_pid), do: nil
end

defmodule SIP.Test.ISTRinging do
  use ExUnit.Case

  alias SIP.Test.Transport.Mockup

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(ISTRingingCallUAS)
    :ok
  end

  # T1 = 10 ms puts timer F — what used to bound this transaction — at 640 ms, so
  # anything asserted past that second is asserted against the old behaviour.
  setup context do
    put_env(:sip_timer_T1, 10)
    put_env(:sip_timer_ist_ringing, context[:ringing_ms] || 2_500)
    Process.register(self(), :ist_ringing_probe)
    :ok
  end

  test "a ringing call outlives 64*T1" do
    invite = inject_invite()
    assert_receive {:sip_mockup, {:response_sent, 180, _}}, 2_000

    # Timer F would have fired at 640 ms. Nothing else may answer for the TU
    # while it is still entitled to ring.
    refute_receive {:sip_mockup, {:response_sent, 408, _}}, 1_500

    ack_final(invite)
  end

  @tag ringing_ms: 700
  test "when the stack does answer 408, the application is told the call is over" do
    invite = inject_invite()
    assert_receive {:sip_mockup, {:response_sent, 180, _}}, 2_000

    assert_receive {:sip_mockup, {:response_sent, 408, _}}, 3_000

    # The point of the whole exercise: the scenario hears it, so a B2BUA in its
    # place can CANCEL the leg it was ringing.
    assert_receive {:told, _reason}, 3_000

    ack_final(invite)
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp put_env(key, value) do
    previous = Application.fetch_env(:elixip2, key)
    Application.put_env(:elixip2, key, value)

    on_exit(fn ->
      case previous do
        {:ok, v} -> Application.put_env(:elixip2, key, v)
        :error -> Application.delete_env(:elixip2, key)
      end
    end)
  end

  defp inject_invite do
    {:ok, msg} = File.read("test/SIP-INVITE-LVP.txt")
    {:ok, parsed} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)

    parsed = Map.put(parsed, :callid, "istring-#{System.unique_integer([:positive])}")
    upd_uri = SIP.Uri.set_uri_param(parsed.ruri, "unittest", "ist_ringing")

    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    parsed = SIP.Msg.Ops.add_via(parsed, {{2, 2, 2, 2}, 5090, "UDP"}, branch)

    routed = SIP.Transport.Selector.select_transport(upd_uri)
    parsed = SIP.Msg.Ops.update_sip_msg(parsed, {:ruri, routed})

    :ok = Mockup.attach_probe(routed.tp_pid)
    Mockup.inject(routed.tp_pid, parsed)
    parsed
  end

  # ACK the non-2xx final so the IST reaches :terminated instead of resending it
  # into the tests that follow.
  defp ack_final(invite) do
    ack =
      SIP.Msg.Ops.ack_request(invite, %SIP.Uri{domain: "2.2.2.2", port: 5090})
      |> Map.put(:transid, invite.transid)

    Mockup.inject(invite.ruri.tp_pid, ack)
    :ok
  end
end
