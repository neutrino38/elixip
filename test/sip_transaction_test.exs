
IO.puts("Répertoire de travail : #{File.cwd!()}")

defmodule SIP.Test.Transact do
  use ExUnit.Case
  require SIP.Transac
  doctest SIP.Transac

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok
  end

  test "Arms timer A and check that it fires" do
    # Start fake transport layer
    { :ok, t_pid } = GenServer.start_link(SIP.Test.Transport.UDPMockup, { {1,2,3,4}, 5080 })
    { code, msg } = File.read("test/SIP-INVITE-BASIC-AUDIO.txt")
    assert code == :ok
    state = %{ state: :sending, t_isreliable: false, msgstr: msg,
               tmod: SIP.Test.Transport.UDPMockup, tpid: t_pid, destip: {1,2,3,4}, destport: 5080 }
    state = SIP.Trans.Timer.schedule_timer_A(state)
    state = receive do
      { :timerA, ms } ->
        # Timer has fired - handle it and check that it refires
        assert ms == 500
        { :noreply, st } =  SIP.Trans.Timer.handle_timer({:timerA, ms}, state)
        # Emulate a provisional response
        %{ st | state: :proceeding }
      _ ->
        IO.puts("incorrect message received")
        assert false
    after
      1_000 ->
        IO.puts("No message received")
        assert false
    end

    assert state.state == :proceeding

    receive do
      { :timerA, ms } ->
        # Timer has fired - handle it and check that it refires
        assert ms == 1000
        { :noreply, _st } =  SIP.Trans.Timer.handle_timer({:timerA, ms}, state)

      _ ->
        IO.puts("incorrect message received")
        assert false
    after
      1_500 ->
        IO.puts("No message received")
        assert false
    end

    receive do
        _ ->
        IO.puts("incorrect message received")
        assert false

    after
      2_500 ->
        GenServer.stop(state.tpid)
        assert true
    end
  end

  test "Arms timer B and check that it fires" do
    { code, msg } = File.read("test/SIP-INVITE-BASIC-AUDIO.txt")
    assert code == :ok

		{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    state = %{ state: :proceeding, t_isreliable: false, msgstr: msg,
               msg: parsed_msg, tmod: SIP.Test.Transport.UDPMockup, app: self() }
    state = SIP.Trans.Timer.schedule_timer_B(state, 200)
    receive do
      { :timeout, _tref, timer } ->
        # Timer has fired - handle it and check that it requires transaction termination
        case SIP.Trans.Timer.handle_timer(timer, state, SIP.ICT) do
          { :stop, :transaction_timeout, newstate } ->
            assert true
            newstate

          _ ->
            # Should reply with 'stop'
            IO.puts("Unexpected answer from hande_timer()")
            assert false
        end

      msg ->
        IO.puts("Unexpected message received.")
        IO.inspect(msg)
        assert false

    after
      1_000 ->
        IO.puts("Timer B has not fired")
        assert false
    end

    # Process the timer message sent to the app layer
    assert_receive( {:transaction_timeout, :timerB, _transpid, _msg, SIP.ICT }, 1000, "Did not received timemout layer message")
  end


  test "Check that get_localip() works" do
    assert is_bitstring( SIP.NetUtils.get_local_ipv4() )
  end

  defp create_sdp_body( ) do
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
    sdp
  end

  defp create_invite_template() do
    invite_msg_str =
"""
INVITE sip:90901@visio5.visioassistance.net:5090;unittest=1 SIP/2.0
P-Asserted-Identity: sip:+33970260233@visioassistance.net
From: "Site%20Arras%20POLE%20EMPLOI"<sip:+33970260233@visioassistance.net>;tag=8075639
To: <sip:90901@visioassistance.net>
Contact: <sip:33970260233@<%= local_ip %>:<%= local_port %>>
Call-ID: 32645600-4c01-bc8f-670c-deac31158db8
CSeq: 9678 INVITE
Content-Type: application/sdp
Content-Length: <%= content_length %>
Max-Forwards: 16
User-Agent: Elixip 0.2.0

"""
    invite_msg_str <> create_sdp_body()
  end

  test "Cree un message INVITE à partir d'un modèle" do
    bindings = [ local_ip: "172.21.100.2", local_port: 5060 ]
    msgstr = SIP.MsgTemplate.apply_template(create_invite_template(), bindings)

    { :ok, invitemsg } = SIPMsg.parse(msgstr, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)

    assert invitemsg.method == :INVITE
  end

  test "Selectionne le transport mockup" do
    newuri = SIP.Transport.Selector.select_transport("sip:90901@visio5.visioassistance.net:5090;unittest=1")
    assert newuri.tp_module == SIP.Test.Transport.UDPMockup
    assert newuri.destip == {1,2,3,4}
    assert newuri.destport == 5080
  end

  @tag :live
  test "Selectionne le transport TCP et ajoute un contact" do
    # Le SIP proxy doit etre joignable pour que cela fonctionne
    newuri = SIP.Transport.Selector.select_transport("sip:90901@testsip.djanah.com:5060;transport=TCP")
    assert newuri != :invalidtransport
    assert is_map(newuri)
    assert newuri.tp_module == SIP.Transport.TCP
    assert newuri.destport == 5060
    msg = %{ contact: newuri }
    msg = SIP.Transport.add_contact_header(newuri.tp_module, newuri.tp_pid, msg)
    assert msg.contact.proto == "TCP"
  end

   @tag :live
  test "Selectionne le transport TLS et ajoute un contact" do
    # Le SIP proxy doit etre joignable pour que cela fonctionne
    newuri = SIP.Transport.Selector.select_transport("sip:90901@testsip.djanah.com:5061;transport=TLS")
    assert newuri != :invalidtransport
    assert is_map(newuri)
    assert newuri.tp_module == SIP.Transport.TLS
    assert newuri.destport == 5061
    msg = %{ contact: newuri }
    msg = SIP.Transport.add_contact_header(newuri.tp_module, newuri.tp_pid, msg)
    assert msg.contact.proto == "TLS"
  end

  # Big transaction test
  @tag :toto
  test "Transaction SIP client INVITE - appel reussi" do
    { :ok, uac_t, _modmsg } = SIP.Transac.start_uac_transaction_with_template(
                              create_invite_template(), [],
                              fn code, errmsg, lineno, line ->
                                IO.puts("\n" <> errmsg)
                                IO.puts("Offending line #{lineno}: #{line}")
                                IO.puts("Error code #{code}")
                                end,
                                %{ desturi: "sip:1.2.3.4:5060;unittest=1", usesrv: false, ringtimeout: 90 }
      )

    { _t_mod, t_pid } = GenServer.call(uac_t, :gettransport)
    SIP.Test.Transport.UDPMockup.simulate_successful_answer(t_pid)

    # Expect a 180 ringing after 200 mss
    receive do
      {:response, resp, _transact_pid} ->
        assert resp.response == 180
        #IO.puts("TEST: Received 180 Ringing on time")

      { :transaction_timeout, :timerB, _transpid, _msg, SIP.ICT } ->
        assert(false,"timerB expired before 180 Ringing")

      _bla ->
        assert(false, "Received unexpected bla")

    after
      500 -> assert(false,"We did not received the 180 Ringing on time")
    end


    receive do
      {:response, resp, _transact_pid} ->
        assert resp.response == 200
        #IO.puts("TEST: Received 200 Ringing on time")
        SIP.Transac.ack_uac_transaction(uac_t)


      { :transaction_timeout, :timerB, _transpid, _msg, SIP.ICT } ->
        assert(false, "timerB expired before 200 OK")

      bla ->
        assert(false, "Received unexpected #{inspect(bla)}")

    after
      5_000 -> assert(false, "We did not receive the 200 OK on time")
    end

  end

  @tag :toto
  test "Transaction SIP client INVITE - appel occcupé" do
    { :ok, uac_t, _modmsg } = SIP.Transac.start_uac_transaction_with_template(
                              create_invite_template(), [],
                              fn code, errmsg, lineno, line ->
                                IO.puts("\n" <> errmsg)
                                IO.puts("Offending line #{lineno}: #{line}")
                                IO.puts("Error code #{code}")
                                end,
                                %{ desturi: "sip:1.2.3.4:5060;unittest=1", usesrv: false, ringtimeout: 90 }
      )

    { _t_mod, t_pid } = GenServer.call(uac_t, :gettransport)
    SIP.Test.Transport.UDPMockup.simulate_busy_answer(t_pid)

   # Expect a 180 ringing after 200 mss
   receive do
    {:response, resp, _transact_pid} ->
      assert resp.response == 180
      #IO.puts("TEST: Received 180 Ringing on time")

    { :transaction_timeout, :timerB, _transpid, _msg, SIP.ICT } ->
      IO.puts("timerB expired before 180 Ringing")
      assert false

    bla ->
      IO.puts("TEST: Received #{bla}")
      assert false
    after
      500 -> assert false # We did not received the 180 Ringing on time
    end

    # Expect a 486 Busy after 200 mss
    receive do
      {:response, resp, _transact_pid} ->
        assert resp.response == 486
        Process.sleep(500)

      { :transaction_timeout, :timerB, _transpid, _msg, SIP.ICT } ->
        IO.puts("timerB expired before 486 Ringing")
        assert false

      bla ->
        IO.puts("TEST: Received #{inspect(bla)}")
        assert false
    after
      3000 -> assert false # We did not received the 180 Ringing on time
    end
  end

  test "Transaction SIP client INVITE - proxy ne répond pas" do
    { :ok, uac_t, _modmsg } = SIP.Transac.start_uac_transaction_with_template(
                              create_invite_template(), [],
                              fn code, errmsg, lineno, line ->
                                IO.puts("\n" <> errmsg)
                                IO.puts("Offending line #{lineno}: #{line}")
                                IO.puts("Error code #{code}")
                                end,
                                %{ desturi: "sip:1.2.3.4:5060;unittest=1", usesrv: false, timeout: 1 }
      )

    { _t_mod, _t_pid } = GenServer.call(uac_t, :gettransport)

    #receive do
    #  bla -> assert false, "Received #{inspect(bla)}"
    #after
    #  3000 -> assert false, "did not receive anything after 3s"
    #end
    # Expect that timer B fires
    assert_receive({:transaction_timeout, :timerB, _tpid, _req, SIP.ICT }, 2000, "Timer B should have fired")
  end

  test "Outbound register" do
    { code, msg } = File.read("test/SIP-REGISTER-LVP.txt")
    assert code == :ok

    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    # Add unittest param to RURI to trigger UDP mockeup transport
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "1")
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    # Send REGISTER
    { :ok, uac_t, _modmsg } = SIP.Transac.start_uac_transaction(parsed_msg, 30)

    { _t_mod, t_pid } = GenServer.call(uac_t, :gettransport)
    SIP.Test.Transport.UDPMockup.simulate_challenge(t_pid)

    receive do
      {:response, resp, _transact_pid} ->
        assert resp.response == 401
        auth_req = SIP.Msg.Ops.add_authorization_to_req(
          parsed_msg, resp.wwwauthenticate, :wwwauthenticate,
          "manu", "buu", :plain)

        # send authenticated register
        { :ok, _uac_t, _modmsg } = SIP.Transac.start_uac_transaction(auth_req, 30)

        # Simulate successful registration
        SIP.Test.Transport.UDPMockup.simulate_successful_register(t_pid)


      bla ->
        IO.puts("TEST: Received #{bla}")
        assert false
      after
        500 -> assert false # We did not received the 401 Athentication required on time
    end

    receive do
      {:response, resp, _transact_pid} -> assert resp.response == 200

      bla ->
        IO.puts("TEST: Received #{bla}")
        assert false
      after
        500 -> assert false # We did not received the 200 OK on time
    end
  end

  test "Outbound register - proxy not responding" do
    # Motify timer T1
    # Timer F will be 64 * 10 = 640 ms
    Application.put_env(:elixip2, :sip_timer_T1, 10)
    { code, msg } = File.read("test/SIP-REGISTER-LVP.txt")
    assert code == :ok

    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    # Add unittest param to RURI to trigger UDP mockeup transport
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "1")
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    # Send REGISTER
    { :ok, _uac_t, _modmsg } = SIP.Transac.start_uac_transaction(parsed_msg, 30)

    # Expect timer F timeout
    assert_receive({:transaction_timeout, :timerF, _tpid, _req, SIP.NICT }, 1000, "Timer F should have fired")
  end
end
