defmodule Kelix.Mod.McuCallTest do
  @moduledoc """
  The call path end to end: the reference `mcu.exs` driven by a spawned scenario
  instance, the real adapter, and a recording MCU transport (design
  `docs/design/mcu_module.md` §13, "Integration" + "Unit, mocked MCU").

  What it pins down is the part §2 says must be transcribed faithfully: the **RPC
  order** of an inbound call and the **answer-time / ACK-time split** — a caller that
  never ACKs must never enter the mix.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config, Conference}

  @domain "example.com"
  @rec_port 52_014

  # A plain-RTP audio offer from a SIP phone, plus a video section it will not get.
  @offer """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8 0 101\r
  a=rtpmap:8 PCMA/8000\r
  a=rtpmap:0 PCMU/8000\r
  a=rtpmap:101 telephone-event/8000\r
  a=sendrecv\r
  m=video 40002 RTP/AVP 99\r
  a=rtpmap:99 H264/90000\r
  a=sendrecv\r
  """

  # An offer with no codec the conference accepts (G.729 only).
  @offer_no_codec """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 18\r
  a=rtpmap:18 G729/8000\r
  a=sendrecv\r
  """

  # A WebRTC-style DTLS offer: refused until P4 rather than answered in the clear.
  @offer_secure """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 UDP/TLS/RTP/SAVPF 111\r
  a=rtpmap:111 opus/48000/2\r
  a=fingerprint:sha-256 AA:BB:CC\r
  a=setup:actpass\r
  a=ice-ufrag:abcd\r
  a=ice-pwd:0123456789abcdef\r
  a=sendrecv\r
  """

  defmodule MockDialog do
    @moduledoc "Captures the SIP replies the script composes, like the registrar test."
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    # send_BYE goes through the dialog too; acknowledge it and report it
    def handle_call({:sendreq, req}, _from, test) do
      send(test, {:sent, Map.get(req, :method)})
      {:reply, :ok, test}
    end

    def handle_call(msg, _from, test) do
      send(test, {:dialog_call, msg})
      {:reply, :ok, test}
    end

    def handle_cast(_msg, test), do: {:noreply, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    %{
      scenario:
        SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/mcu.exs", __DIR__))
    }
  end

  setup do
    {:ok, config} =
      Config.parse(%{
        "did_range" => "8000-8009",
        "audio_codecs" => ["OPUS", "PCMA", "PCMU", "TELEPHONE-EVENT"],
        "mediaserver" => %{
          "mcu1" => %{
            "url" => "http://127.0.0.1:18080",
            "rtp_ip" => "10.0.0.12",
            "public_ip" => "203.0.113.12"
          }
        }
      })

    start_supervised!({Mcu, config: config, module_name: "mcu"})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{"StartReceiving" => {:ok, [@rec_port]}}),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()

    {:ok, %{uid: uid, did: did}} =
      Mcu.handle_control("conference.create", %{"domain" => @domain, "name" => "Weekly"})

    # drain the setup RPCs (queue creation + conference creation) so each test reads
    # the call's own sequence off its mailbox
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

  # ── SIP fixtures ─────────────────────────────────────────────────────────────

  defp invite(did, opts \\ []) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain},
      callid: "call-#{System.unique_integer([:positive])}",
      cseq: [1, :INVITE],
      body: Keyword.get(opts, :sdp, @offer),
      contenttype: "application/sdp"
    }
  end

  defp spawn_call(scenario, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(scenario,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  defp start_call(scenario, req) do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(scenario, dialog, req)
    send(pid, {:INVITE, req, nil, dialog})
    {pid, dialog}
  end

  defp participants(uid) do
    {:ok, conf} = Mcu.conference(uid)
    Conference.participants(conf)
  end

  defp wait_for(fun, attempts \\ 200) do
    case fun.() do
      nil when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      false when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      value ->
        value
    end
  end

  # ── the script as kelixip loads it ───────────────────────────────────────────

  describe "the reference script's contract" do
    test "it is a :uas_invite scenario, handles shutdown, and declares the mcu module", ctx do
      assert ctx.scenario.__scenario_type__() == :uas_invite
      # a script that cannot be told to wind down is refused at load (§5.3)
      assert function_exported?(ctx.scenario, :__state___shutdown__, 1)

      Kelix.ModuleRegistry.register("mcu", Mcu, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("mcu") end)

      # `config(uses_modules: [:mcu])` is what turns "the module is not installed"
      # from a dead instance on the first INVITE into a load-time error
      assert :ok = Kelix.ScriptRegistry.check_declared_modules(ctx.scenario, "mcu.exs")
    end
  end

  # ── the happy path ───────────────────────────────────────────────────────────

  describe "a SIP phone joins the conference" do
    test "180, then a 200 whose SDP answers audio and declines video", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))

      assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      # §6.3 rule 3: the c= line is the configured public_ip (G2), not the MCU's own
      assert answer =~ "c=IN IP4 203.0.113.12"
      # the receive port StartReceiving returned
      assert answer =~ "m=audio #{@rec_port} RTP/AVP"
      # rule 1: the offer's payload-type numbering is reused verbatim
      assert answer =~ "a=rtpmap:8 PCMA/8000"
      assert answer =~ "a=rtpmap:101 telephone-event/8000"
      assert answer =~ "a=fmtp:101 0-16"
      # rule 2: no video in this increment ⇒ port 0, and the call goes on
      assert answer =~ "m=video 0 RTP/AVP 99"
      # the mixed participant is sendrecv (rule 7)
      assert answer =~ "a=sendrecv"
    end

    test "the RPC order follows §6.2 and splits at the ACK", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # answer time: the participant exists and receives, but sends nothing yet
      answer_time = TestStub.rpc_order()
      assert answer_time == ["CreateParticipant", "StartReceiving"]

      # ACK time: codec, sending, and only then the mixer
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      ack_time = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert ack_time == ["SetAudioCodec", "StartSending", "AddSidebarParticipant"]
    end

    test "CreateParticipant and StartSending carry the right arguments", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # name from the From header, RTP participant, default mosaic and sidebar (§3.3)
      assert_received {:rpc, "CreateParticipant", [42, "alice@phone_example_com", 0, 0, 0]}
      # audio (0), the offered PT numbering, main role, RTP protocol
      assert_received {:rpc, "StartReceiving", [42, 7, 0, rtp_map, 0, 0]}
      assert rtp_map == %{"8" => 8, "0" => 0, "101" => 100}

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # the mixer sends PCMA (the first codec common to offer and conference) to the
      # address and port the offer advertised
      assert_receive {:rpc, "SetAudioCodec", [42, 7, 8]}, 2000
      assert_receive {:rpc, "StartSending", [42, 7, 0, "192.168.1.50", 40_000, _map, 0]}, 2000
      assert_receive {:rpc, "AddSidebarParticipant", [42, 0, 7]}, 2000
    end

    test "the participant row tracks ringing → connected", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # the slot is taken from admit/2 onwards — a ringing leg holds one
      [part] = participants(ctx.uid)
      assert part.state == :ringing
      assert part.name == "alice@phone_example_com"
      # bound by the adapter once CreateParticipant answered
      assert part.part_id == 7
      assert is_pid(part.conn)

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      connected = wait_for(fn -> Enum.find(participants(ctx.uid), &(&1.state == :connected)) end)
      assert connected.medias.audio.codec == "PCMA"
      assert connected.medias.audio.rec_port == @rec_port
      assert connected.joined_at
    end

    test "BYE tears the leg down: the MCU side is released and the slot freed", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000
      _drain = TestStub.rpc_order()

      send(pid, {:BYE, %{method: :BYE}, nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000

      teardown = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert "StopSending" in teardown
      assert "StopReceiving" in teardown
      assert "DeleteParticipant" in teardown

      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end
  end

  # ── the caller that never ACKs, and the rejections ───────────────────────────

  describe "the answer-time / ACK-time split (§2, point 2)" do
    test "a caller that never ACKs never enters the mix", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      order = TestStub.rpc_order()
      refute "StartSending" in order
      refute "AddSidebarParticipant" in order
      # …and it still holds its slot, which is what the quota is for
      assert [%{state: :ringing}] = participants(ctx.uid)
    end
  end

  describe "rejections (§6.5)" do
    test "an unknown DID is a 404 and creates no participant", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite("9999"))

      assert_receive {:replied, 404, "Not Found", _fields, _req}, 2000
      assert participants(ctx.uid) == []
      assert TestStub.rpc_order() == []
    end

    test "a full conference is a 486", ctx do
      {:ok, %{uid: uid, did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8100",
          "max_participants" => 1
        })

      {_pid, _dialog} = start_call(ctx.scenario, invite(did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      assert length(participants(uid)) == 1

      {:ok, dialog2} = MockDialog.start_link(self())
      req2 = invite(did)
      pid2 = spawn_call(ctx.scenario, dialog2, req2)
      send(pid2, {:INVITE, req2, nil, dialog2})

      assert_receive {:replied, 486, "Busy Here", _fields, _req}, 2000
      # the second caller took no slot
      assert length(participants(uid)) == 1
    end

    test "no codec in common is a 488, and the slot is released", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_no_codec))

      assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
      assert_receive {:replied, 488, "Not Acceptable Here", _fields, _req}, 2000

      # the participant was created MCU-side (the offer is only read afterwards) and
      # must be deleted again — nothing may leak on a refused call (§9.1)
      order = wait_for(fn -> if "DeleteParticipant" in TestStub.rpc_order(), do: true end)
      assert order
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "a secure offer is refused with a 488 until P4, not answered in the clear", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_secure))

      assert_receive {:replied, 488, "Not Acceptable Here", _fields, _req}, 2000
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "a conference whose MCU is down is a 503", ctx do
      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert wait_for(fn -> match?({:ok, %{status: :down}}, Mcu.mediaserver("mcu1")) end)

      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 503, "Service Unavailable", _fields, _req}, 2000
    end
  end

  # ── the safety nets ──────────────────────────────────────────────────────────

  describe "teardown paths" do
    test "a crashed instance is reaped: slot freed and MCU side released (§9.3)", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000
      _drain = TestStub.rpc_order()

      Process.exit(pid, :kill)

      assert wait_for(fn -> participants(ctx.uid) == [] end)
      teardown = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert "DeleteParticipant" in teardown
    end

    test "CANCEL before the answer releases the slot", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      send(pid, {:CANCEL, %{method: :CANCEL}, nil, dialog})
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "an auto-destroying conference goes away with its last participant", ctx do
      {:ok, %{uid: uid, did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8200",
          "destroy_when_empty" => true
        })

      {pid, dialog} = start_call(ctx.scenario, invite(did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      send(pid, {:BYE, %{method: :BYE}, nil, dialog})
      assert wait_for(fn -> Mcu.conference(uid) == :error end)
      # …and its DID is free again
      assert Mcu.lookup_did(@domain, did) == :error
    end

    test "losing the media server ends the call: the script BYEs and the slot frees", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      # the mixer is gone (§9.2): a leg with no media must not hold its slot for the
      # hours the SIP-only idle timeout would take (G3)
      send(Mcu, {:mcu_event_stream_down, "mcu1"})

      # the slot is freed and the MCU-side participant released; the instance then
      # waits in `hanging_up` for the 200 to its BYE (the mock never sends one)
      assert wait_for(fn -> participants(ctx.uid) == [] end)
      assert wait_for(fn -> if "DeleteParticipant" in TestStub.rpc_order(), do: true end)
    end

    test "an FPU request reaches the owning scenario, keeping the call up", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      [part] = participants(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:fpu_requested, 42, ctx.uid, part.part_id}})

      # P3 turns it into an INFO; for now the instance must simply survive it rather
      # than leave it to rot in its mailbox
      Process.sleep(50)
      assert Process.alive?(pid)
      assert [%{state: :connected}] = participants(ctx.uid)
    end

    test "leave/2 is idempotent: a second call is a no-op, not an error", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      [part] = participants(ctx.uid)
      assert :ok = Mcu.leave(part, :bye)
      assert :ok = Mcu.leave(part, :bye)
      assert participants(ctx.uid) == []
    end
  end

  defp non_empty([]), do: nil
  defp non_empty(list), do: list
end
