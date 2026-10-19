defmodule Kelix.Mod.McuDialOutTest do
  @moduledoc """
  A conference leg we PLACE — dial-out, L6 of `docs/design/DESIGN-MCU.md`.

  Driven through the module and the adapter directly, like `McuSecureTest`: the test
  process stands in for the scenario instance, owns the participant, and reads both
  the SDP and the exact RPC sequence. What is pinned down here:

    * the offer is built from the server's VERDICT on the codec vocabulary — what the
      server does not accept is not offered;
    * the answer is recorded in the shape the answer path leaves, so `attach/1` sends
      on the answer's address and payload types, and nothing leaves before it;
    * SDES: our key in the offer, the peer's key taken from the line echoing our tag,
      and an answer that drops SRTP refused.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @callee "sip:+33977190504@pstn.example.net"
  @rec_port 52_014
  @media_ip "203.0.113.12"
  @peer_key "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"

  # The server's verdict on our menu, per media: audio takes PCMA, PCMU and
  # telephone-event, video H.264 alone with its own fmtp. Everything else we proposed
  # (G722, OPUS, SPEEX, VP8, AV1) is refused, and must therefore not be offered.
  defp start_receiving([_conf, _part, 0 | _]),
    do: {:ok, [@rec_port, @media_ip, %{"8" => "", "0" => "", "101" => "0-16"}]}

  defp start_receiving([_conf, _part, 1 | _]),
    do:
      {:ok, [@rec_port + 2, @media_ip, %{"99" => "profile-level-id=42e01f;packetization-mode=1"}]}

  # What a server carrying addressing profiles answers `GetNetworkProfiles` (§6.7):
  # the case where a profile asked late re-binds the sockets.
  @profiles [
    %{
      "name" => "publicv4",
      "available" => true,
      "announced" => @media_ip,
      "bind" => "",
      "default" => true
    },
    %{
      "name" => "publicv6",
      "available" => false,
      "announced" => "",
      "bind" => "",
      "default" => false
    }
  ]

  setup context do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009"})

    returns =
      if context[:profiles],
        do: %{"StartReceiving" => &start_receiving/1, "GetNetworkProfiles" => {:ok, @profiles}},
        else: %{"StartReceiving" => &start_receiving/1}

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), returns),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()
    {:ok, %{uid: uid, did: did}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
    _setup_rpcs = TestStub.rpc_order()

    %{uid: uid, did: did}
  end

  defp wait_for_client(attempts \\ 100) do
    case Mcu.mediaserver("mcu1") do
      {:ok, %{status: :up, client: pid}} when is_pid(pid) ->
        :ok

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_for_client(attempts - 1)

      _ ->
        flunk("the mcu1 client never came up")
    end
  end

  defp leg(did, opts) do
    {:ok, conf, part} = Mcu.dial_out(@domain, did, @callee)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(client, self(), [mcu_participant: part] ++ opts)

    on_exit(fn -> Adapter.close(conn) end)
    {conn, part}
  end

  defp answer(lines) do
    Enum.join(
      [
        "v=0",
        "o=- 1 1 IN IP4 198.51.100.7",
        "s=-",
        "c=IN IP4 198.51.100.7",
        "t=0 0"
      ] ++ lines ++ [""],
      "\r\n"
    )
  end

  describe "the participant of a dial-out" do
    test "is named after the callee, and shows its number", ctx do
      {:ok, _conf, part} = Mcu.dial_out(@domain, ctx.did, @callee)

      assert part.from == "+33977190504@pstn.example.net"
      assert part.display_name == "+33977190504"
      assert part.state == :ringing
    end

    test "an unknown conference and a callee that is not a URI are refused" do
      assert {:error, :no_such_conference} = Mcu.dial_out(@domain, "9999", @callee)
      assert {:error, :bad_callee} = Mcu.dial_out(@domain, "8000", "not a uri")
    end

    test "the context form wires the leg for an INVITE we send", ctx do
      sip_ctx = %SIP.Context{domain: @domain, username: "mcu"}
      sip_ctx = Mcu.dial_out(sip_ctx, @domain, ctx.did, @callee, [])

      assert sip_ctx.lasterr == :ok
      # our identity stays the script's: the DID is not who places the call
      assert sip_ctx.username == "mcu"

      assert [mcu_participant: %{conf_uid: uid}] =
               SIP.Context.appdata_get(sip_ctx, :media_conn_opts)

      assert uid == ctx.uid
      # no ACK will reach a leg we place: the conference block attaches on entry
      assert SIP.Context.appdata_get(sip_ctx, :mcu_leg_phase) == :attach_pending
    end
  end

  describe "admit/3 with did:" do
    defp invite(user) do
      %{
        method: :INVITE,
        ruri: %SIP.Uri{userpart: user, domain: @domain},
        from: %SIP.Uri{userpart: "gw", domain: "gateway.example.com"},
        to: %SIP.Uri{userpart: user, domain: @domain}
      }
    end

    test "joins the room the script names, not the R-URI's", ctx do
      req = invite("+3397719#{ctx.did}")

      assert {:error, :no_such_conference} = Mcu.admit(@domain, req)
      assert {:ok, conf, _part} = Mcu.admit(@domain, req, did: ctx.did)
      assert conf.uid == ctx.uid
    end

    test "without did: the R-URI still names the room", ctx do
      assert {:ok, conf, _part} = Mcu.admit(@domain, invite(ctx.did))
      assert conf.uid == ctx.uid
    end

    test "a did that is not a non-empty string is refused", ctx do
      for bad <- [nil, "", 8000] do
        assert {:error, :bad_did} = Mcu.admit(@domain, invite(ctx.did), did: bad)
      end
    end
  end

  describe "the offer" do
    test "lists what the server accepted, in our order, and nothing else", ctx do
      {conn, _part} = leg(ctx.did, media: :audio_video)
      assert {:ok, offer} = Adapter.get_local_offer(conn)

      assert offer =~ "c=IN IP4 #{@media_ip}"
      # the vocabulary's order (the tables', alphabetical), filtered by the verdict
      assert offer =~ "m=audio #{@rec_port} RTP/AVP 8 0 101"
      assert offer =~ "a=fmtp:101 0-16"
      assert offer =~ "m=video #{@rec_port + 2} RTP/AVP 99"
      assert offer =~ "a=fmtp:99 profile-level-id=42e01f;packetization-mode=1"
      refute offer =~ ~r/opus|VP8|AV1|G722|speex/i
      refute offer =~ "a=crypto"
    end

    test "the whole vocabulary is proposed to the server, and nothing is sent", ctx do
      {conn, _part} = leg(ctx.did, media: :audio)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)

      calls = TestStub.rpc_calls()
      assert [rtp_map] = for({"StartReceiving", [_, _, 0, map | _]} <- calls, do: map)
      # every audio name the tables carry, plus telephone-event
      assert Map.keys(rtp_map) |> Enum.sort() == ~w(0 101 117 8 9 98)
      refute Enum.any?(calls, fn {method, _} -> method == "StartSending" end)
    end

    test "codec_order puts the script's choice first", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, codec_order: [audio: ["pcmu"]])
      assert {:ok, offer} = Adapter.get_local_offer(conn)
      assert offer =~ "m=audio #{@rec_port} RTP/AVP 0 8 101"
    end

    test "srtp: :sdes offers RTP/SAVP with our key, pushed before StartReceiving", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, srtp: :sdes)
      assert {:ok, offer} = Adapter.get_local_offer(conn)

      assert offer =~ "m=audio #{@rec_port} RTP/SAVP"

      assert [key] =
               Regex.run(~r/a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:(\S+)/, offer,
                 capture: :all_but_first
               )

      assert byte_size(Base.decode64!(key)) == 30

      assert TestStub.rpc_order() == ["CreateParticipant", "SetLocalCryptoSDES", "StartReceiving"]
    end

    # Teams Direct Routing runs full ICE with rtcp-mux and SDES: the offer then carries
    # what this leg already answers such a peer with — ICE-lite, our credentials keyed
    # before StartReceiving, one host candidate, rtcp-mux.
    test "ice: :lite offers ICE-lite, and the answer's credentials are pushed", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, srtp: :sdes, ice: :lite)
      assert {:ok, offer} = Adapter.get_local_offer(conn)

      assert offer =~ "a=ice-lite"
      assert [_, ufrag] = Regex.run(~r/a=ice-ufrag:(\S+)/, offer)
      assert offer =~ "a=ice-pwd:"
      assert offer =~ "a=rtcp-mux"
      assert offer =~ "a=candidate:1 1 udp 2130706431 #{@media_ip} #{@rec_port} typ host"

      assert TestStub.rpc_order() == [
               "CreateParticipant",
               "SetLocalCryptoSDES",
               "SetLocalSTUNCredentials",
               "StartReceiving"
             ]

      # the hub's own shape: SDES with a key lifetime, full ICE, rtcp-mux
      answer =
        answer([
          "m=audio 49444 RTP/SAVP 8 101",
          "a=rtcp:49445",
          "a=ice-ufrag:cRNV",
          "a=ice-pwd:kdjpUoa70pLn+g44T889ucqp",
          "a=rtcp-mux",
          "a=candidate:1 1 UDP 2130706431 52.115.132.96 49444 typ srflx raddr 10.0.18.9 rport 49444",
          "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:#{@peer_key}|2^31",
          "a=sendrecv",
          "a=rtpmap:8 PCMA/8000",
          "a=rtpmap:101 telephone-event/8000",
          "a=fmtp:101 0-16"
        ])

      assert :ok = Adapter.set_remote_answer(conn, answer)

      calls = TestStub.rpc_calls()

      assert {"SetRemoteCryptoSDES", [42, 7, 0, "AES_CM_128_HMAC_SHA1_80", @peer_key, 0, 0]} in calls

      assert {"SetRemoteSTUNCredentials", [42, 7, 0, "cRNV", "kdjpUoa70pLn+g44T889ucqp", 0]} in calls

      assert Enum.any?(
               calls,
               &match?({"SetRTPProperties", [42, 7, 0, %{"rtcp-mux" => "1"}, 0]}, &1)
             )

      assert ufrag != "cRNV"
    end

    test "a WebRTC offer is not something this leg makes", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, webrtc_support: :yes)

      capture_log(fn ->
        assert {:error, :webrtc_offer_not_supported} = Adapter.get_local_offer(conn)
      end)
    end

    test "a second offer from our side is refused", ctx do
      {conn, _part} = leg(ctx.did, media: :audio)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)
      assert {:error, {:already_negotiated, :offered}} = Adapter.get_local_offer(conn)
    end
  end

  describe "the answer, then the mix" do
    test "attach sends on the answer's address and payload type, then joins", ctx do
      {conn, _part} = leg(ctx.did, media: :audio_video)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)
      _ = TestStub.rpc_order()

      answer =
        answer([
          "m=audio 30000 RTP/AVP 8 101",
          "a=rtpmap:8 PCMA/8000",
          "a=rtpmap:101 telephone-event/8000",
          "a=sendrecv",
          # declined: the far end does not do video
          "m=video 0 RTP/AVP 99"
        ])

      assert :ok = Adapter.set_remote_answer(conn, answer)
      # the declined media stops receiving at once; nothing is sent yet
      assert [{"StopReceiving", [42, 7, 1, 0]}] =
               Enum.filter(TestStub.rpc_calls(), fn {m, _} -> m != "SetRTPProperties" end)

      assert {:ok, summary} = Adapter.attach(conn)
      assert summary.audio.codec == "PCMA"
      refute Map.has_key?(summary, :video)

      calls = TestStub.rpc_calls()
      assert {"SetAudioCodec", [42, 7, 8]} in calls

      assert {"StartSending", [42, 7, 0, "198.51.100.7", 30_000, send_map, 0]} =
               Enum.find(calls, &match?({"StartSending", _}, &1))

      assert send_map == %{"8" => 8, "101" => 100}
      assert {"AddSidebarParticipant", [42, 0, 7]} in calls
      refute Enum.any?(calls, &match?({"AddMosaicParticipant", _}, &1))
    end

    test "SDES: the key of the line echoing our tag is pushed", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, srtp: :sdes)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)

      answer =
        answer([
          "m=audio 30000 RTP/SAVP 0",
          "a=rtpmap:0 PCMU/8000",
          "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:#{@peer_key}",
          "a=sendrecv"
        ])

      assert :ok = Adapter.set_remote_answer(conn, answer)

      assert_received {:rpc, "SetRemoteCryptoSDES",
                       [42, 7, 0, "AES_CM_128_HMAC_SHA1_80", @peer_key, 0, 0]}
    end

    test "SDES offered and answered in the clear is refused", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, srtp: :sdes)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)

      answer = answer(["m=audio 30000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000", "a=sendrecv"])

      capture_log(fn ->
        assert {:error, {:sdes_not_answered, :audio}} = Adapter.set_remote_answer(conn, answer)
      end)
    end

    test "an answer every media of which is declined is refused", ctx do
      {conn, _part} = leg(ctx.did, media: :audio)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)

      capture_log(fn ->
        assert {:error, :no_common_codec} =
                 Adapter.set_remote_answer(conn, answer(["m=audio 0 RTP/AVP 0"]))
      end)
    end

    # A profile asked for after an offer made on the server's default re-binds the
    # sockets: a new port. The hub's ICE re-INVITE moved our audio from 13442 to 13536
    # while the hub went on sending to 13442 (capture of 2026-10-19).
    @tag profiles: true
    test "a leg offered on the server's default never asks for a profile later", ctx do
      {conn, _part} = leg(ctx.did, media: :audio, srtp: :sdes, ice: :lite)
      assert {:ok, _offer} = Adapter.get_local_offer(conn)

      hub_sdp = fn version ->
        answer([
          "m=audio 52244 RTP/SAVP 9 8 0 101",
          "a=ice-ufrag:lqRH",
          "a=ice-pwd:EffbWkWqbEeM4bNXk8yjMRLb",
          "a=rtcp-mux",
          "a=candidate:1 1 UDP 2130705918 52.112.235.104 52244 typ srflx raddr 10.0.16.182 rport 52244",
          "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:#{@peer_key}|2^31",
          "a=sendrecv",
          "a=rtpmap:8 PCMA/8000",
          "a=rtpmap:0 PCMU/8000",
          "a=rtpmap:101 telephone-event/8000"
        ])
        |> String.replace("o=- 1 1", "o=- 1 #{version}")
      end

      assert :ok = Adapter.set_remote_answer(conn, hub_sdp.(1))
      assert {:ok, _} = Adapter.attach(conn)
      # the hub's re-INVITE confirming the pair ICE validated
      assert {:ok, reanswer} = Adapter.set_remote_offer(conn, hub_sdp.(2))
      assert reanswer =~ "m=audio #{@rec_port} "

      calls = TestStub.rpc_calls()
      receives = for {"StartReceiving", args} <- calls, do: args
      assert length(receives) == 2
      # no 8th argument: no profile, so no re-bind, so the port the hub validated stays
      assert Enum.all?(receives, &(length(&1) == 7))

      assert [send_args] = for({"StartSending", args} <- calls, do: args)
      assert length(send_args) == 7
    end

    test "an answer with no offer pending is refused", ctx do
      {conn, _part} = leg(ctx.did, media: :audio)

      assert {:error, {:no_offer_pending, :created}} =
               Adapter.set_remote_answer(conn, answer(["m=audio 30000 RTP/AVP 0"]))
    end
  end
end
