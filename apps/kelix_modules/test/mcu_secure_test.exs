defmodule Kelix.Mod.McuSecureTest do
  @moduledoc """
  The security plane of a conference leg: SDES-SRTP and DTLS-SRTP + ICE-lite
  (design `docs/design/DESIGN-MCU.md` point 3, §3.5, §6.3 rules 3-6).

  Driven through the adapter directly rather than through `mcu.exs`: what matters
  here is **which secret comes from where** and **in what order it is pushed**, and
  the test process stands in for the scenario instance so it can read both the answer
  SDP and the exact RPC sequence.

  The rule §2 insists on: for SDES the *controller* generates the local key, for ICE
  the *controller* generates ufrag/pwd, and only the DTLS fingerprint comes from the
  server — server-wide, hence fetched once and cached.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @rec_port 52_014
  # the address the media server itself reports on StartReceiving (§16.5) —
  # what the answer must advertise, and no longer a config value
  @media_ip "203.0.113.12"
  @fingerprint "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:" <>
                 "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"

  defp offer(opts) do
    crypto = Keyword.fetch!(opts, :crypto)
    protocol = Keyword.get(opts, :protocol, "RTP/SAVP")
    extra = Keyword.get(opts, :extra, [])

    Enum.join(
      [
        "v=0",
        "o=- 1 1 IN IP4 192.168.1.50",
        "s=-",
        "c=IN IP4 192.168.1.50",
        "t=0 0",
        "m=audio 40000 #{protocol} 8",
        "a=rtpmap:8 PCMA/8000"
      ] ++ crypto ++ extra ++ ["a=sendrecv", ""],
      "\r\n"
    )
  end

  @sdes_key "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"

  defp sdes_offer(suite \\ "AES_CM_128_HMAC_SHA1_80"),
    do: offer(crypto: ["a=crypto:1 #{suite} inline:#{@sdes_key}"])

  defp dtls_offer(opts \\ []) do
    setup = Keyword.get(opts, :setup, "actpass")
    ice = Keyword.get(opts, :ice, true)
    mux = Keyword.get(opts, :rtcp_mux, true)

    offer(
      protocol: "UDP/TLS/RTP/SAVPF",
      crypto: ["a=fingerprint:sha-256 AA:BB:CC:DD", "a=setup:#{setup}"],
      extra:
        if(ice, do: ["a=ice-ufrag:abcd", "a=ice-pwd:0123456789abcdef"], else: []) ++
          if(mux, do: ["a=rtcp-mux"], else: [])
    )
  end

  setup do
    {:ok, config} =
      Config.parse(%{
        "did_range" => "8000-8009"
      })

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{"StartReceiving" => {:ok, [@rec_port, @media_ip]}}),
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

  # Admit a leg the way the script does, then open its peer connection. The test
  # process is the "scenario": it owns the participant and receives its events.
  defp leg(did, opts \\ []) do
    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "gw", domain: "gateway.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain}
    }

    {:ok, conf, part} = Mcu.admit(@domain, req)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(
        client,
        self(),
        [mcu_participant: part, media: :audio] ++ opts
      )

    on_exit(fn -> Adapter.close(conn) end)
    {conn, part}
  end

  describe "SDES-SRTP (§2 point 3: the controller generates the local key)" do
    test "the answer carries OUR key, and the offered suite is mirrored", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, sdes_offer())

      assert [key] =
               Regex.run(~r/a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:(\S+)/, answer,
                 capture: :all_but_first
               )

      # our key, not the peer's: each direction is keyed by its sender
      refute key == @sdes_key
      # 16-byte key + 14-byte salt, base64 (RFC 4568 §6.1)
      assert byte_size(Base.decode64!(key)) == 30
      # the transport of the offer is mirrored (§6.3 rule 4)
      assert answer =~ "m=audio #{@rec_port} RTP/SAVP"
    end

    # This used to answer "a suite we do know" and hand the server the key of the line
    # we did NOT accept — a call that established and decrypted nothing. RFC 4568 §6.2
    # leaves an answerer two options, take one offered line or refuse; inventing a
    # third is what produced silent one-way SRTP.
    test "an offer whose every suite is unknown is refused, not half-keyed", ctx do
      {conn, _part} = leg(ctx.did)

      assert capture_log(fn ->
               assert {:error, :no_common_sdes_suite} =
                        Adapter.set_remote_offer(conn, sdes_offer("F8_128_HMAC_SHA1_80"))
             end) =~ "offers no SDES suite we support"
    end

    # Linphone 6.2 offers four lines, `AEAD_AES_128_GCM` first — a suite this mixer does
    # not implement. The answerer takes the first line it *can* honour, echoes that
    # line's tag, and keys the remote direction with that line's key.
    test "the supported line is selected, its tag echoed and its key pushed", ctx do
      {conn, _part} = leg(ctx.did)

      offer =
        offer(
          crypto: [
            "a=crypto:1 AEAD_AES_128_GCM inline:SCFAW7LH8WVTcjfQFVBErzFCrpgfcSEXP0rsug==",
            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:#{@sdes_key}",
            "a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:eP9kHri2wJ9sjh+O51WbrTsqkux2Zp8T"
          ]
        )

      assert {:ok, answer} = Adapter.set_remote_offer(conn, offer)

      # tag 2, the line we accepted — not tag 1, whose key belongs to the GCM suite
      assert answer =~ "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"
      refute answer =~ "AEAD_AES_128_GCM"

      # and the remote key is the one published on THAT line
      assert_received {:rpc, "SetRemoteCryptoSDES",
                       [42, 7, 0, "AES_CM_128_HMAC_SHA1_80", @sdes_key, 0, 0]}
    end

    test "local before StartReceiving, remote after (§6.2)", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, _answer} = Adapter.set_remote_offer(conn, sdes_offer())

      assert TestStub.rpc_order() == [
               "CreateParticipant",
               "SetLocalCryptoSDES",
               "StartReceiving",
               "SetRemoteCryptoSDES"
             ]
    end

    test "the peer's key is pushed verbatim, ours is what we generated", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, sdes_offer())

      assert_received {:rpc, "SetLocalCryptoSDES", [42, 7, 0, suite, our_key, 0]}
      assert suite == "AES_CM_128_HMAC_SHA1_80"
      assert answer =~ "inline:#{our_key}"

      # seven arguments: `(iiissii)` — role AND keyRank (MCU-API `SetRemoteCryptoSDES`).
      # Six was the one arity the server has no format string for: it answered a parse
      # fault, kelixip turned it into a 500, and Linphone hung up.
      assert_received {:rpc, "SetRemoteCryptoSDES", [42, 7, 0, ^suite, @sdes_key, 0, 0]}
    end

    # The real Linphone 6.2.0 offer of 2026-08-06 (`linphone.pcap`), kept verbatim: four
    # crypto lines per media, GCM first, and a media list this mixer only partly serves
    # (speex, G.729, AV1). It is the offer that found both SDES defects at once.
    test "the captured Linphone 6.2 offer is answered, keyed on its second line", ctx do
      {conn, _part} = leg(ctx.did, media: :audio_video)

      offer =
        File.read!(Path.expand("fixtures/SDP-linphone-620-srtp-offer.txt", __DIR__))

      assert {:ok, answer} = Adapter.set_remote_offer(conn, offer)

      # audio and video each keyed on their own tag-2 line, with our own keys
      assert answer =~ "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"
      refute answer =~ "AEAD_AES"
      # the offer's transport is mirrored (§6.3 rule 4)
      assert answer =~ "RTP/SAVP "

      # the peer's audio key is the one on ITS tag-2 line, pushed with role and keyRank
      assert_received {:rpc, "SetRemoteCryptoSDES",
                       [
                         42,
                         7,
                         0,
                         "AES_CM_128_HMAC_SHA1_80",
                         "gYwkkzbCwvqlHH+Bcq1FQGTanPHdh9z/F/3Co35r",
                         0,
                         0
                       ]}
    end

    test "an SDES leg needs no WebRTC permission: it is what a SIP phone offers", ctx do
      {conn, _part} = leg(ctx.did, webrtc_support: :no)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, sdes_offer())
      assert answer =~ "a=crypto:1 "
    end
  end

  describe "DTLS-SRTP + ICE-lite" do
    test "the answer states the server's fingerprint, our ICE credentials, ice-lite", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer())

      # the only secret we do not generate (§2 point 3), advertised under SHA-256
      assert answer =~ "a=fingerprint:sha-256 #{@fingerprint}"
      # §6.3 rule 5: we answer ice-lite and never gather reflexive candidates
      assert answer =~ "a=ice-lite"
      assert [ufrag] = Regex.run(~r/a=ice-ufrag:(\S+)/, answer, capture: :all_but_first)
      assert [pwd] = Regex.run(~r/a=ice-pwd:(\S+)/, answer, capture: :all_but_first)
      refute ufrag == "abcd"
      refute pwd == "0123456789abcdef"

      # §6.3 rule 3: one host candidate on the receive port, from configuration (G2),
      # and no component 2 because the offer asked for rtcp-mux
      assert answer =~ "a=candidate:1 1 udp 2130706431 203.0.113.12 #{@rec_port} typ host"
      refute answer =~ "a=candidate:1 2 "
      assert answer =~ "a=rtcp-mux"
    end

    test "without rtcp-mux the RTCP component is advertised too (as mcuGold)", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer(rtcp_mux: false))

      assert answer =~ "a=candidate:1 1 udp 2130706431 203.0.113.12 #{@rec_port} typ host"
      assert answer =~ "a=candidate:1 2 udp 2130706430 203.0.113.12 #{@rec_port + 1} typ host"
    end

    test "the RPC order is local ICE, StartReceiving, then the peer's material", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, _answer} = Adapter.set_remote_offer(conn, dtls_offer())

      assert TestStub.rpc_order() == [
               "CreateParticipant",
               "GetLocalCryptoDTLSFingerprint",
               "SetLocalSTUNCredentials",
               "StartReceiving",
               "SetRemoteCryptoDTLS",
               "SetRemoteSTUNCredentials",
               "SetRTPProperties"
             ]
    end

    test "natLatch is never volunteered: the script has to ask for it", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, _answer} = Adapter.set_remote_offer(conn, dtls_offer())

      # this leg was opened without `nat_latch:`, so the properties call carries the
      # transport hints and nothing else — following the source address is the
      # deployment's decision, not this adapter's
      assert_received {:rpc, "SetRTPProperties", [42, 7, 0, props, 0]}
      refute Map.has_key?(props, "natLatch")
    end

    test "the credentials pushed to the server are the ones the answer states", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer())

      assert_received {:rpc, "SetLocalSTUNCredentials", [42, 7, 0, ufrag, pwd, 0]}
      assert answer =~ "a=ice-ufrag:#{ufrag}"
      assert answer =~ "a=ice-pwd:#{pwd}"

      # the peer's, verbatim
      assert_received {:rpc, "SetRemoteSTUNCredentials",
                       [42, 7, 0, "abcd", "0123456789abcdef", 0]}
    end

    test "an offer with a fingerprint but no ICE gets DTLS and no ICE lines", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer(ice: false))

      assert answer =~ "a=fingerprint:sha-256 "
      refute answer =~ "a=ice-ufrag:"
      refute answer =~ "a=ice-lite"
      refute answer =~ "a=candidate:"

      order = TestStub.rpc_order()
      refute "SetLocalSTUNCredentials" in order
      refute "SetRemoteSTUNCredentials" in order
    end
  end

  describe "the DTLS role (§6.3 rule 6, settled 2026-07-30)" do
    test "actpass is answered passive: the MCU is the DTLS server", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer(setup: "actpass"))
      assert answer =~ "a=setup:passive"

      # and the server is told the peer's *resolved* role, never the literal actpass:
      # the two must not disagree about who initiates the handshake
      assert_received {:rpc, "SetRemoteCryptoDTLS",
                       [42, 7, 0, 0, "active", "sha-256", "AA:BB:CC:DD"]}
    end

    test "an offer that already committed is mirrored, which is not a choice", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer(setup: "active"))
      assert answer =~ "a=setup:passive"
      assert_received {:rpc, "SetRemoteCryptoDTLS", [42, 7, 0, 0, "active", _hash, _fp]}
    end

    test "a passive offer makes us the client", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, dtls_offer(setup: "passive"))
      assert answer =~ "a=setup:active"
      assert_received {:rpc, "SetRemoteCryptoDTLS", [42, 7, 0, 0, "passive", _hash, _fp]}
    end
  end

  describe "policy and limits" do
    test "the fingerprint is server-wide: fetched once, cached for every later leg", ctx do
      {conn_a, _part_a} = leg(ctx.did)
      assert {:ok, _} = Adapter.set_remote_offer(conn_a, dtls_offer())
      assert Enum.count(TestStub.rpc_order(), &(&1 == "GetLocalCryptoDTLSFingerprint")) == 1

      {conn_b, _part_b} = leg(ctx.did)
      assert {:ok, _} = Adapter.set_remote_offer(conn_b, dtls_offer())
      refute "GetLocalCryptoDTLSFingerprint" in TestStub.rpc_order()
    end

    test "`webrtc_support: :no` refuses a DTLS leg instead of answering it in the clear", ctx do
      {conn, _part} = leg(ctx.did, webrtc_support: :no)
      assert {:error, :secure_not_supported} = Adapter.set_remote_offer(conn, dtls_offer())
    end

    test "trickle ICE is accepted and dropped (G5), never an error the script must handle", ctx do
      {conn, _part} = leg(ctx.did)
      assert {:ok, _} = Adapter.set_remote_offer(conn, dtls_offer())
      assert :ok = Adapter.add_remote_candidate(conn, "1 1 udp 2130706431 1.2.3.4 5000 typ host")
    end

    test "a clear-RTP offer still gets no crypto and no ICE", ctx do
      {conn, _part} = leg(ctx.did)

      assert {:ok, answer} =
               Adapter.set_remote_offer(conn, offer(crypto: [], protocol: "RTP/AVP"))

      refute answer =~ "a=crypto:"
      refute answer =~ "a=fingerprint:"
      refute answer =~ "a=ice-"
      assert TestStub.rpc_order() == ["CreateParticipant", "StartReceiving"]
    end
  end
end
