defmodule TestCall do
  # use SIP.Session.Call
  require Logger
  @behaviour SIP.Session.Call

  # Forward an app-side event to the current test process when it registered
  # itself as :sip_call_probe. Lets a test assert on events that reach the app
  # (CANCEL, ACK, dialog termination) rather than the wire. No-op otherwise.
  defp notify_probe(msg) do
    case Process.whereis(:sip_call_probe) do
      nil -> :ok
      pid -> send(pid, msg)
    end
  end

  defp send_bye(state) do
    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: state.req.contact,
      from: state.req.from,
      to: state.req.to,
      useragent: "Elixipp/0.1",
      callid: nil,
      contentlength: 0
    }
    # new_request/2 returns {:ok, transaction_pid} on success. Asserting the shape
    # here guards the contract: this runs on the answered-call BYE path which the
    # "let the call end" test exercises end to end.
    {:ok, transaction_pid} = SIP.Dialog.new_request(state.dlg_id, bye)
    true = is_pid(transaction_pid)
    :ok
  end

  defp answer_call(state) do
    sdp = """
v=0
o=Elixip2 1 678901 IN IP4 <%= local_ip %>
s=-
c=IN IP4 <%= local_ip %>
t=0 0
a=tcap:1 RTP/AVPF
m=audio 7344 RTP/AVP 9 8 111 0 101
a=ptime:20
a=silenceSupp:off - - - -
a=rtpmap:9 G722/8000/1
a=rtpmap:8 PCMA/8000/1
a=rtpmap:111 opus/48000/2
a=fmtp:111 maxplaybackrate=48000; sprop-maxcapturerate=16000; stereo=0; sprop-stereo=0; useinbandfec=0; usedtx=0
a=rtpmap:0 PCMU/8000/1
a=rtpmap:101 telephone-event/8000/1
a=fmtp:101 0-16
a=pcfg:1 t=1
a=rtcp-fb:* nack
a=sendrecv
a=rtcp-mux
a=ssrc:3202199976 cname:LVP_8088975@djanah.com
a=ssrc:3202199976 mslabel:6994f7d1-6ce9-4fbd-acfd-84e5131ca2e2
a=ssrc:3202199976 label:LiveVideoPlugin@audio
m=video 7346 RTP/AVP 96
b=AS:520
b=TIAS:520000
a=rtpmap:96 H264/90000
a=fmtp:96 profile-level-id=420016; packetization-mode=1;max-br=520
a=pcfg:1 t=1
a=rtcp-fb:* ccm fir
a=rtcp-fb:* ccm tmmbr
a=rtcp-fb:* nack
a=rtcp-fb:* nack pli
a=rtcp-fb:* goog-remb
a=sendrecv
a=rtcp-mux
a=ssrc:3202204423 cname:LVP_8088976@djanah.com
a=ssrc:3202204423 mslabel:6994f7d1-6ce9-4fbd-acfd-84e5131ca2e2
a=ssrc:3202204423 label:LiveVideoPlugin@video
m=text 7348 RTP/AVP 98 99
a=rtpmap:98 t140/1000
a=fmtp:98 cps=30
a=rtpmap:99 red/1000
a=fmtp:99 98/98/98
a=pcfg:1 t=1
a=sendrecv
a=rtcp-mux
"""
    contact_uri = %SIP.Uri{ userpart: "bob", domain: "0.0.0.0" }
     Logger.info("CALLSERVER: answering call")
    SIP.Dialog.reply(state.dlg_id, state.req, 200, "OK",
                    [ body: sdp, contact: contact_uri, contenttype: "application/sdp" ])
  end

  # Call simulator: answered call scenario
  defp answered_call_handling_process_loop(state) do

    receive do
      { :INVITE, req, _trans_pid, dialog_pid } ->

        Logger.info("CALLSERVER: processing call")
        # No reply(100): the IST now emits 100 Trying automatically (RFC 3261 §17.2.1).
        :erlang.start_timer(100, self(), :ringing)
        answered_call_handling_process_loop(%{state | dlg_id: dialog_pid, state: :proceeding, req: req })

      # ACK of our 2xx forwarded by the dialog layer (pid nil, nothing to reply).
      { :ACK, _ack, _trans_pid, _dialog_pid } ->
        Logger.info("CALLSERVER: received ACK")
        notify_probe(:got_ack)
        answered_call_handling_process_loop(state)

      { :timeout, _timerRef, :ringing } ->
        SIP.Dialog.reply(state.dlg_id, state.req, 180, "Ringing", [])
        :erlang.start_timer(1000, self(), :answer)
        answered_call_handling_process_loop(%{state | state: :ringing})

      { :timeout, _timerRef, :answer } ->
        answer_call(state)
        :erlang.start_timer(5000, self(), :hangup)
        answered_call_handling_process_loop(%{state | state: :confirmed})

      { :timeout, _timerRef, :hangup } ->
        if state.state == :confirmed do
          Logger.info("Hanging up answered call")
          send_bye(state)
          :erlang.start_timer(1000, self(), :stop)
          answered_call_handling_process_loop(%{state | state: :hangingup})
        else
          if state.state != :idle do
            Logger.info("Hanging up proceeding/ringing call")
            SIP.Dialog.reply(state.dlg_id, state.req, 486, "Busy", [])
          else
            Logger.info("Ignoring hangup in idle call")
            answered_call_handling_process_loop(state)
          end
        end

      # 200 OK answer from BYE
      { 200, _rsp, _trans_pid, _dialog_pid } ->
        if state.state == :hangingup do
          Logger.info("Hangup complete")
        else
          Logger.warning("Ignoring unexpected 200 OK")
          answered_call_handling_process_loop(state)
        end

      # Received BYE
      { :BYE, bye, _trans_pid, dialog_pid } ->
        if state.state == :confirmed do
          SIP.Dialog.reply(dialog_pid, bye, 200, "OK", [])
          Logger.info("Terminating call because received bye")
        else
          Logger.warning("Ignoring unexpected BYE")
          answered_call_handling_process_loop(state)
        end

      :stop ->
        # Kill process
        nil
    end
  end


    # Call simulator: answered call scenario
  defp timeout_call_handling_process_loop(state) do

    state = receive do
      { :INVITE, req, _trans_pid, dialog_pid } ->

        Logger.info("CALLSERVER: processing call - will not answer")
        # No reply(100): the IST emits 100 Trying automatically now.
        :erlang.start_timer(100, self(), :ringing)
        %{state | dlg_id: dialog_pid, state: :proceeding, req: req }

      { :timeout, _timerRef, :ringing } ->
        SIP.Dialog.reply(state.dlg_id, state.req, 180, "Ringing", [])
        :erlang.start_timer(5000, self(), :noanswer)
        %{state | state: :ringing}

      { :timeout, _timerRef, :noanswer } ->
        SIP.Dialog.reply(state.dlg_id, state.req, 408, "Timeout", [])
        :erlang.start_timer(500, self(), :waitabit)
        %{state | state: :waitabit}

      { :timeout, _timerRef, :waitabit } ->
        %{state | state: :end}

      # Received CANCEL forwarded by the dialog layer. The IST already answered
      # 200 to the CANCEL and 487 to the INVITE, so there is nothing to reply
      # here — just surface the event to the test. The dialog then tears down and
      # {:dialog_terminated, _, :cancelled} follows.
      { :CANCEL, _cancel, _trans_pid, _dialog_pid } ->
        Logger.info("CALLSERVER: received CANCEL")
        notify_probe(:got_cancel)
        %{state | state: :cancelling}

      # Dialog terminated (here: after a CANCEL). End the scenario.
      { :dialog_terminated, _dialog_pid, reason } ->
        Logger.info("CALLSERVER: dialog terminated (#{inspect(reason)})")
        notify_probe({:got_terminated, reason})
        %{state | state: :end}

      :stop ->
        # Kill process
        %{state | state: :end}
    end
    case state.state do
      # End process
      :end -> nil

      # Continue pro essing
      _ -> timeout_call_handling_process_loop(state)
    end
  end


  @impl true
  def on_new_call(dialog_id, req, transaction_id) do
    Logger.info("on_new_call called in test")
    # transaction_id is the server transaction that created the dialog (arity 3,
    # aligned on on_new_registration/3); replies go through the dialog so it is
    # only asserted to be a pid here.
    true = is_pid(transaction_id)
    state = %{ state: :idle, dlg_id: dialog_id, req: req }
    case SIP.Uri.get_uri_param(req.ruri, "scenario") do
      { :ok, "answered_call" } ->
        pid = spawn_link(fn -> answered_call_handling_process_loop(state) end)
        { :accept, pid }

      { :ok, "timeout_call" } ->
        # Trap exits: this fixture is spawn_link'd to the dialog (unlike the real
        # spawn_monitor'd UAS instances). On a CANCEL the dialog stops with
        # {:shutdown, :cancelled}; without trapping, that exit signal would kill
        # this process before it drains the queued {:CANCEL}/{:dialog_terminated}
        # events. Trapping turns the signal into an (ignored) {:EXIT, …} message.
        pid = spawn_link(fn ->
          Process.flag(:trap_exit, true)
          timeout_call_handling_process_loop(state)
        end)
        { :accept, pid }

      # Application-level reject: the requested SIP status must reach the wire
      # (validates the reject propagation of phase 1: {:reject, code, reason} →
      # DialogImpl.init stop → SIP response). 604 mimics the future UAS domain
      # control ("Does Not Exist Anywhere").
      { :ok, "reject_604" } ->
        Logger.info("on_new_call: rejecting call with 604")
        { :reject, 604, "Does Not Exist Anywhere" }

        { :ok, truc } ->
          Logger.info("on_new_call: unsupported scenario #{truc}")
          { :reject, 404, "unsupported scenario #{truc}" }

        { :nosuchparam, nil } ->
          Logger.info("on_new_call: no scenario specified in RURI")
          { :reject, 404, "no scenario specified in RURI" }

    end
  end

  @impl true
  def on_call_end(_dialog_pid, app_pid) do
    send(app_pid, :stop)
  end
end


defmodule SIP.Test.Call do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Session.Call

    # Account to use for tests (centralized in config/test.exs)
  @proxy Application.compile_env(:elixip2, :test_account).proxy

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    { :ok, _config_pid } = SIP.Session.ConfigRegistry.start()

    # Force SIP proxy / registrar
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, scheme: "sip:", port: 5060 })
    Application.put_env(:elixip2, :proxyusesrv, false)

    # Register the Call processing module
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(TestCall)

    :ok
  end

  defp simulate_remote_invite(scenario) do
    # Load a INVITE message from a file
    { code, msg } = File.read("test/SIP-INVITE-LVP.txt")
    assert code == :ok

    # Parse it
    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    # Randomize Call-ID so each test gets a distinct dialog key in Registry.SIPDialog.
    # Without this, all tests share the same {from_tag, call_id, nil} key and
    # GenServer.start fails with {:already_started, pid} for tests 2-4.
    parsed_msg = Map.put(parsed_msg, :callid, SIP.Msg.Ops.generate_branch_value())

    # Add unittest param to RURI to trigger UDP mockeup transport selection
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "1")
    upd_uri = SIP.Uri.set_uri_param(upd_uri, "scenario", scenario)
    branch_id = SIP.Msg.Ops.generate_branch_value()
    parsed_msg = SIP.Msg.Ops.add_via(parsed_msg, { {2,2,2,2}, 5090, "UDP" }, branch_id)
    upd_uri = SIP.Transport.Selector.select_transport(upd_uri)
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    # Indicate our test PID to receive events
    GenServer.call(upd_uri.tp_pid, :settestapp)

    # Simulate a received INVITE by UDP mockeup transport
    send(upd_uri.tp_pid, { :recv, parsed_msg})
    { parsed_msg, branch_id }
  end

  defp simulate_remote_ack(invite, branch_id) do
    ack = SIP.Msg.Ops.ack_request(invite, %SIP.Uri{ domain: "2.2.2.2", port: 5090 })
          |> Map.put( :transid, branch_id)
    send(invite.ruri.tp_pid, { :recv, ack })
    ack
  end


  defp simulate_remote_cancel(invite, branch_id) do
    ack = SIP.Msg.Ops.cancel_request(invite)
          |> Map.put( :transid, branch_id)
    send(invite.ruri.tp_pid, { :recv, ack })
    ack
  end


  defp simulate_remote_bye(parsed_msg) do
    branch_id = SIP.Msg.Ops.generate_branch_value()
    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: %SIP.Uri{ parsed_msg.ruri | destip: {1,2,3,4}, destport: 5080 },
      from: parsed_msg.from,
      to: parsed_msg.to,
      useragent: "Elixipp/0.1",
      callid: parsed_msg.callid,
      transid: branch_id,
      cseq: [
        hd(parsed_msg.cseq) + 1,
        :BYE
      ],
      via: ["SIP/2.0/UDP 87.98.205.4;branch=#{branch_id};i=4612"],
      contentlength: 0
    }

    send(parsed_msg.ruri.tp_pid, { :recv, bye })
  end

  test "Simulating an answered call and let the call end" do
    { parsed_msg, branch_id } = simulate_remote_invite("answered_call")
    # The IST emits 100 Trying automatically (RFC 3261 §17.2.1); the scenario
    # never sends it.
    assert_receive(100, 2000, "Failed to receive the automatic 100 Trying")
    assert_receive(180, 2000, "Failed to receive 180 Ringing on time")
    assert_receive(200, 2000, "Failed to receive 200 OK on time")
    Process.sleep(1000)

    #Simulate ACK sending
    _ack = simulate_remote_ack(parsed_msg, branch_id)

    #Wait for BYE
    assert_receive(:BYE, 6000, "Failed to receive BYE")

    # Wait for BYE transaction to die out
    Process.sleep(6000)
  end

  test "Simulating an answered call then hangup the call" do
    { parsed_msg, branch_id } = simulate_remote_invite("answered_call")
    assert_receive(180, 2000, "Failed to receive 180 Ringing on time")
    assert_receive(200, 2000, "Failed to receive 200 OK on time")
    Process.sleep(100)

    #Simulate ACK sending
    _ack = simulate_remote_ack(parsed_msg, branch_id)
    Process.sleep(500)
    simulate_remote_bye(parsed_msg)
    # Wait for BYE transaction to die out
    Process.sleep(6000)
  end

  test "Simulating an call without answser" do
    { parsed_msg, branch_id } = simulate_remote_invite("timeout_call")
    assert_receive(180, 2000, "Failed to receive 180 Ringing on time")
    assert_receive(408, 6000, "Failed to receive 408 Timeout ")
    Process.sleep(100)

    #Simulate ACK sending
    _ack = simulate_remote_ack(parsed_msg, branch_id)
    Process.sleep(1000)
  end

  test "Simulating an abandonned call" do
    # Register as the probe so the app forwards the CANCEL / dialog termination.
    Process.register(self(), :sip_call_probe)
    { parsed_msg, branch_id } = simulate_remote_invite("timeout_call")
    assert_receive(180, 2000, "Failed to receive 180 Ringing on time")
    Process.sleep(100)
    simulate_remote_cancel(parsed_msg, branch_id)
    # The IST answers 487 to the INVITE automatically...
    assert_receive(487, 1000, "Failed to receive 487 Request interrupted ")
    # ...and (phase 1) the CANCEL is now surfaced to the app, which then sees the
    # dialog terminate with reason :cancelled.
    assert_receive(:got_cancel, 1000, "App did not receive the CANCEL event")
    assert_receive({:got_terminated, :cancelled}, 1000, "App did not receive dialog_terminated :cancelled")
    Process.sleep(100)
    Process.unregister(:sip_call_probe)
  end

  test "Rejecting an incoming call maps the reject code to the wire" do
    # on_new_call returns {:reject, 604, ...}; phase 1 propagates it as a real
    # 604 SIP response (before the fix any reject was rewritten to 403).
    { _parsed_msg, _branch_id } = simulate_remote_invite("reject_604")
    assert_receive(604, 2000, "Failed to receive 604 rejection on the wire")
  end

end
