defmodule TestCall do
  use SIP.Session.Registrar
  require Logger
  @behaviour SIP.Session.Call

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
    SIP.Dialog.new_request(state.dlg_id, bye)
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
        SIP.Dialog.reply(dialog_pid, req, 100, "Trying", [])
        :erlang.start_timer(100, self(), :ringing)
        answered_call_handling_process_loop(%{state | dlg_id: dialog_pid, state: :proceeding, req: req })

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
      { BYE, _req, _trans_pid, _dialog_pid } ->
        if state.state == :confirmed do
          SIP.Dialog.reply(state.dlg_id, state.req, 200, "OK", [])
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

  @impl true
  def on_new_call(dialog_id, req) do
    Logger.info("on_new_call called in test")
    state = %{ state: :idle, dlg_id: dialog_id, req: req }
    pid = spawn_link(fn -> answered_call_handling_process_loop(state) end)
    { :accept, pid }
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

    # Account to use for tests
  @proxy "testsip.djanah.com"

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    { :ok, _config_pid } = SIP.Session.ConfigRegistry.start()

    # Force SIP proxy / registrar
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, scheme: "sip:", port: 5060 })
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

test "Simulating an answered call" do
    # Define module as registrar module
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(TestCall)

    # Load a REGISTER message from a file
    { code, msg } = File.read("test/SIP-INVITE-LVP.txt")
    assert code == :ok

    # Parse it
    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    # Add unittest param to RURI to trigger UDP mockeup transport selection
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "1")
    upd_uri = SIP.Uri.set_uri_param(upd_uri, "scenario", "answered_call")
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    upd_uri = SIP.Transport.Selector.select_transport(upd_uri)

    # Indicate our test PID to receive events
    GenServer.call(upd_uri.tp_pid, :settestapp)

    # Simulate a received INVITE by UDP mockeup transport
    send(upd_uri.tp_pid, { :recv, parsed_msg})

    assert_receive(200, 2000, "Failed to receive 200 OK on time")
    assert_receive(:BYE, 6000, "Failed to receive BYE")

    # Wait for BYE transaction to die out
    Process.sleep(6000)
  end

end
