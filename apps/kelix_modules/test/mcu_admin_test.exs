defmodule Kelix.Mod.McuAdminTest do
  @moduledoc """
  The administrative half of the module (design `docs/design/mcu_module.md` P5):
  `conference.update`, the `participant.*` resources, `kelictl status`, the §11
  metrics, and the two recovery paths of §9 — an MCU that restarts (§9.2) and the
  conferences a dead kelixip left behind (§9.4).

  Participants are created the way the call path does — `admit/2` then the adapter —
  so the rows under test are the real ones, with the test process standing in for the
  scenario instance.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Conference, Config}

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @rec_port 52_014
  # the address the media server itself reports on StartReceiving (§16.5) —
  # what the answer must advertise, and no longer a config value
  @media_ip "203.0.113.12"

  @offer """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  """

  setup do
    start_mcu()
  end

  defp start_mcu(opts \\ []) do
    block =
      Map.merge(
        %{
          "did_range" => "8000-8009"
        },
        Keyword.get(opts, :block, %{})
      )

    {:ok, config} = Config.parse(block)
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    returns =
      Map.merge(
        %{"StartReceiving" => {:ok, [@rec_port, @media_ip]}},
        Keyword.get(opts, :returns, %{})
      )

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), returns),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_until(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)

    {:ok, %{uid: uid, did: did}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
    # the GC tests read the start-up sweep off their own mailbox, so they keep it
    if Keyword.get(opts, :drain, true), do: TestStub.rpc_order()

    %{uid: uid, did: did}
  end

  defp wait_until(fun, attempts \\ 200) do
    case fun.() do
      truthy when truthy not in [nil, false] ->
        truthy

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_until(fun, attempts - 1)

      _ ->
        flunk("condition never became true")
    end
  end

  # A real participant: admitted, then attached through the adapter, so its row
  # carries a part_id, a live connection and the negotiated medias.
  defp join(uid) do
    {:ok, conf} = Mcu.conference(uid)

    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"},
      to: %SIP.Uri{userpart: conf.did, domain: @domain}
    }

    {:ok, ^conf, part} = Mcu.admit(@domain, req)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(client, self(), mcu_participant: part, media: :audio)

    {:ok, _answer} = Adapter.set_remote_offer(conn, @offer)
    :ok = Mcu.attach(part)
    _rpcs = TestStub.rpc_order()

    part
  end

  # ── conference.update (§8.3.3) ───────────────────────────────────────────────

  describe "conference.update" do
    test "merges what is given and leaves the rest untouched", ctx do
      assert {:ok, %{uid: uid, changed: [:name]}} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "name" => "Renamed"})

      assert {:ok, conf} = Mcu.conference(uid)
      assert conf.name == "Renamed"
      # a PUT never resets an omitted field to its default (§8.3.3)
      assert conf.vad == 1
      assert conf.rate == 32_000
      assert conf.max_participants == 20
      # a purely local change needs no RPC
      assert TestStub.rpc_order() == []
    end

    test "vad and rate go to the mixer, in one UpdateConference", ctx do
      assert {:ok, %{changed: [:rate, :vad]}} =
               Mcu.handle_control("conference.update", %{
                 "uid" => ctx.uid,
                 "vad" => 2,
                 "rate" => 48_000
               })

      assert_received {:rpc, "UpdateConference", [42, 2, 48_000]}
      assert {:ok, %{vad: 2, rate: 48_000}} = Mcu.conference(ctx.uid)
    end

    test "a rate change alone keeps the current vad", ctx do
      assert {:ok, _} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "rate" => 8000})

      assert_received {:rpc, "UpdateConference", [42, 1, 8000]}
    end

    test "layout goes to SetCompositionType and is merged, not replaced", ctx do
      assert {:ok, _} =
               Mcu.handle_control("conference.update", %{
                 "uid" => ctx.uid,
                 "layout" => %{"comp" => 9}
               })

      # `size` and `auto` survive a partial layout update
      assert_received {:rpc, "SetCompositionType", [42, 0, 9, 6]}
      assert {:ok, %{layout: %{comp: 9, size: 6, auto: true}}} = Mcu.conference(ctx.uid)
    end

    test "video and max_participants are local, and apply to new participants (L7)", ctx do
      assert {:ok, _} =
               Mcu.handle_control("conference.update", %{
                 "uid" => ctx.uid,
                 "video" => %{"bitrate" => 2048},
                 "max_participants" => 2
               })

      assert {:ok, conf} = Mcu.conference(ctx.uid)
      assert conf.video == %{size: 6, fps: 15, bitrate: 2048, intra_period: 300}
      assert conf.max_participants == 2
      assert TestStub.rpc_order() == []
    end

    test "lowering max_participants below the current count disconnects nobody", ctx do
      part = join(ctx.uid)

      assert {:ok, _} =
               Mcu.handle_control("conference.update", %{
                 "uid" => ctx.uid,
                 "max_participants" => 0
               })

      assert {:ok, %{part_id: 7}} = Mcu.participant(part)
      # …but the next caller is refused
      {:ok, conf} = Mcu.conference(ctx.uid)

      assert {:error, :full} =
               Mcu.admit(@domain, %{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
                 from: %SIP.Uri{userpart: "bob", domain: "phone.example.com"}
               })
    end

    test "an unknown field is a 400-shaped error, a read-only one is named as such", ctx do
      assert {:error, msg} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "vadd" => 1})

      assert msg =~ "unknown argument(s): vadd"

      for field <- ~w(conf_id created_at participants did domain mcu) do
        assert {:error, msg} =
                 Mcu.handle_control("conference.update", %{"uid" => ctx.uid, field => "x"})

        assert msg =~ "read-only field(s): #{field}"
      end
    end

    test "an unknown conference is :not_found", _ctx do
      assert {:error, :not_found} =
               Mcu.handle_control("conference.update", %{"uid" => "c-ghost", "name" => "x"})
    end

    test "a bad value is refused before anything is pushed", ctx do
      assert {:error, msg} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "rate" => 44_100})

      assert msg =~ "rate must be one of"
      assert TestStub.rpc_order() == []
    end
  end

  # ── participant.* (§8.3.3) ───────────────────────────────────────────────────

  describe "participant.list / show" do
    test "list returns the operator-facing view, not the internals", ctx do
      _part = join(ctx.uid)

      assert {:ok, [row]} = Mcu.handle_control("participant.list", %{"uid" => ctx.uid})
      assert row.part_id == 7
      assert row.name == "alice@phone_example_com"
      assert row.state == :connected
      assert row.medias.audio.codec == "PCMA"
      # pids and refs are not an API
      refute Map.has_key?(row, :conn)
      refute Map.has_key?(row, :scenario)
      refute Map.has_key?(row, :ref)
    end

    test "show adds the media server's own statistics (§3.3)", ctx do
      _part = join(ctx.uid)

      assert {:ok, shown} =
               Mcu.handle_control("participant.show", %{"uid" => ctx.uid, "part_id" => "7"})

      assert shown.part_id == 7
      assert_received {:rpc, "GetParticipantStatistics", [42, 7]}

      # decoded per media, with the server's own field order named (its `isReceiving`
      # comes before `isSending`, the reverse of the order §3.3 lists them in)
      assert shown.stats == %{
               "audio" => %{
                 receiving: true,
                 sending: true,
                 lost_recv_packets: 0,
                 num_recv_packets: 100,
                 num_send_packets: 90,
                 total_recv_bytes: 16_000,
                 total_send_bytes: 14_400
               }
             }

      refute Map.has_key?(shown, :stats_error)
    end

    test "a statistics failure is reported, not hidden behind zeros", ctx do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)

      ctx2 =
        start_mcu(
          returns: %{"GetParticipantStatistics" => {:error, {:mcu_error, "no such part"}}}
        )

      _part = join(ctx2.uid)

      assert {:ok, shown} =
               Mcu.handle_control("participant.show", %{"uid" => ctx2.uid, "part_id" => "7"})

      assert shown.stats == %{}
      # the reason is the module's bounded label; the server's message is in the log
      assert shown.stats_error == :rpc_error
    end

    test "an unknown participant or conference is :not_found", ctx do
      assert {:error, :not_found} =
               Mcu.handle_control("participant.show", %{"uid" => ctx.uid, "part_id" => "99"})

      assert {:error, :not_found} =
               Mcu.handle_control("participant.list", %{"uid" => "c-ghost"})
    end

    test "a malformed part_id is refused", ctx do
      assert {:error, msg} =
               Mcu.handle_control("participant.show", %{"uid" => ctx.uid, "part_id" => "seven"})

      assert msg =~ "part_id must be a non-negative integer"
    end
  end

  describe "participant.update (the former `mute`)" do
    test "mutes the medias given, and only those", ctx do
      _part = join(ctx.uid)

      assert {:ok, %{part_id: 7, changed: [:audio]}} =
               Mcu.handle_control("participant.update", %{
                 "uid" => ctx.uid,
                 "part_id" => "7",
                 "muted" => %{"audio" => true}
               })

      # SetMute(confId, partId, media, muted) — audio is 0, muted is 1 (§3.3)
      assert_received {:rpc, "SetMute", [42, 7, 0, 1]}
      refute_received {:rpc, "SetMute", [42, 7, 1, _]}
    end

    test "unmuting is the same call with 0", ctx do
      _part = join(ctx.uid)

      assert {:ok, _} =
               Mcu.handle_control("participant.update", %{
                 "uid" => ctx.uid,
                 "part_id" => "7",
                 "muted" => %{"audio" => false}
               })

      assert_received {:rpc, "SetMute", [42, 7, 0, 0]}
    end

    test "the facade `mute/3` is the same path, for a script that moderates", ctx do
      part = join(ctx.uid)

      assert :ok = Mcu.mute(part, :audio, true)
      assert_received {:rpc, "SetMute", [42, 7, 0, 1]}

      assert {:error, :no_such_participant} =
               Mcu.mute(%{conf_uid: ctx.uid, ref: make_ref()}, :audio, true)
    end

    test "a bad muted map is refused", ctx do
      _part = join(ctx.uid)

      assert {:error, msg} =
               Mcu.handle_control("participant.update", %{
                 "uid" => ctx.uid,
                 "part_id" => "7",
                 "muted" => %{"sound" => true}
               })

      assert msg =~ "muted: unknown media"

      assert {:error, msg} =
               Mcu.handle_control("participant.update", %{
                 "uid" => ctx.uid,
                 "part_id" => "7",
                 "muted" => %{"audio" => "yes"}
               })

      assert msg =~ "muted.audio must be a boolean"
    end
  end

  describe "participant.delete (the former `kick`)" do
    test "asks the scenario to wind down: BYE and teardown are its own path", ctx do
      _part = join(ctx.uid)

      assert {:ok, %{part_id: 7}} =
               Mcu.handle_control("participant.delete", %{"uid" => ctx.uid, "part_id" => "7"})

      # the test process stands in for the scenario, so it receives the shutdown
      assert_received {:scenario_ctl, :shutdown, :kicked}
    end

    test "deleting one mid-teardown is 200, not an error (§8.3.3)", ctx do
      _part = join(ctx.uid)

      # the scenario has been told to wind down but has not finished; a second delete
      # must not turn an in-flight teardown into a failure
      assert {:ok, %{part_id: 7}} =
               Mcu.handle_control("participant.delete", %{"uid" => ctx.uid, "part_id" => "7"})

      assert {:ok, %{part_id: 7}} =
               Mcu.handle_control("participant.delete", %{"uid" => ctx.uid, "part_id" => "7"})
    end

    test "deleting an already-gone participant is :not_found", ctx do
      assert {:error, :not_found} =
               Mcu.handle_control("participant.delete", %{"uid" => ctx.uid, "part_id" => "7"})
    end

    test "the facade `kick/2` is the same path", ctx do
      _part = join(ctx.uid)

      assert :ok = Mcu.kick(ctx.uid, 7)
      assert_received {:scenario_ctl, :shutdown, :kicked}
      assert {:error, :not_found} = Mcu.kick(ctx.uid, 99)
    end
  end

  # ── status and metrics (§11) ─────────────────────────────────────────────────

  describe "status/0 and poll_metrics/0" do
    test "status/0 is what `kelictl status` prints", ctx do
      _part = join(ctx.uid)

      assert %{conferences: 1, participants: 1, mediaservers: "1/1 up", stale: 0} = Mcu.status()
    end

    test "Kelix.Control.status/0 picks it up through the registry, naming no module", ctx do
      Kelix.ModuleRegistry.register("mcu", Mcu, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("mcu") end)
      _part = join(ctx.uid)

      assert %{"mcu" => %{conferences: 1, participants: 1}} = Kelix.Control.status().module_status

      # …and the CLI renders it as one line per module
      {0, text} = Kelix.Control.CLI.run(["status"], node())
      assert text =~ "mcu:"
      assert text =~ "conferences 1"
    end

    test "poll_metrics/0 emits one gauge per server and per conference", ctx do
      _part = join(ctx.uid)

      handler =
        attach_telemetry([
          [:kelix, :poll, :mcu_conferences],
          [:kelix, :poll, :mcu_participants],
          [:kelix, :poll, :mcu_up]
        ])

      on_exit(fn -> :telemetry.detach(handler) end)

      assert :ok = Mcu.poll_metrics()

      assert_received {:telemetry, [:kelix, :poll, :mcu_up], %{up: 1}, %{mcu: "mcu1"}}
      assert_received {:telemetry, [:kelix, :poll, :mcu_conferences], %{count: 1}, %{mcu: "mcu1"}}

      assert_received {:telemetry, [:kelix, :poll, :mcu_participants], %{count: 1},
                       %{mcu: "mcu1", conference: uid}}

      assert uid == ctx.uid
    end

    test "the call funnel counts a join and a rejection by its SIP code", ctx do
      handler = attach_telemetry([[:kelix, :mcu, :call]])
      on_exit(fn -> :telemetry.detach(handler) end)

      _part = join(ctx.uid)
      assert_received {:telemetry, [:kelix, :mcu, :call], %{count: 1}, %{result: "joined"}}

      assert {:error, :no_such_conference} =
               Mcu.admit(@domain, %{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: "9999", domain: @domain},
                 from: %SIP.Uri{userpart: "bob", domain: "phone.example.com"}
               })

      assert_received {:telemetry, [:kelix, :mcu, :call], %{count: 1}, %{result: "404"}}
    end

    test "every RPC is timed, and a failure is labelled by a bounded reason", ctx do
      handler = attach_telemetry([[:kelix, :mcu, :rpc], [:kelix, :mcu, :rpc_error]])
      on_exit(fn -> :telemetry.detach(handler) end)

      assert {:ok, _} = Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "vad" => 0})

      assert_received {:telemetry, [:kelix, :mcu, :rpc], %{duration: d},
                       %{method: "UpdateConference"}}

      assert is_integer(d) and d >= 0
    end

    test "a failed RPC is labelled by its reason's shape, never the server's message" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      ctx = start_mcu(returns: %{"UpdateConference" => {:error, {:mcu_error, "nope"}}})

      handler = attach_telemetry([[:kelix, :mcu, :rpc_error]])
      on_exit(fn -> :telemetry.detach(handler) end)

      assert {:error, :rpc_error} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "vad" => 0})

      # `mcu_error`, not "nope": a label carrying the server's text would give the
      # metric unbounded cardinality
      assert_received {:telemetry, [:kelix, :mcu, :rpc_error], %{count: 1},
                       %{method: "UpdateConference", reason: "mcu_error"}}
    end
  end

  defp attach_telemetry(events) do
    test = self()
    handler = "mcu-test-#{System.unique_integer([:positive])}"

    :telemetry.attach_many(
      handler,
      events,
      fn event, measurements, metadata, _cfg ->
        send(test, {:telemetry, event, measurements, metadata})
      end,
      nil
    )

    handler
  end

  # ── §9.2 MCU restart, §9.4 orphan collection ─────────────────────────────────

  describe "an MCU that goes away and comes back (§9.2)" do
    test "the conference is marked stale, then recreated with the same uid", ctx do
      part = join(ctx.uid)
      {:ok, before} = Mcu.conference(ctx.uid)
      assert before.conf_id == 42

      # the event stream dying is what tells us the server restarted
      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert wait_until(fn -> match?({:ok, %{stale: true}}, Mcu.conference(ctx.uid)) end)

      # the row and its DID survive; conf_id does not, and new calls are refused
      assert {:ok, %{did: did, conf_id: nil}} = Mcu.conference(ctx.uid)
      assert {:ok, _} = Mcu.lookup_did(@domain, did)
      assert {:error, :mcu_down} = Mcu.admit(@domain, invite(did))
      # the live participant's scenario was told the mix is gone
      assert_received {:mcu_event, :server_disconnected}
      assert part.conf_uid == ctx.uid

      # the server comes back: same uid, new conf_id (the MCU stub answers 42 again,
      # so assert on the recreation itself)
      _drain = TestStub.rpc_order()
      send(Mcu, {:mcu_client, "mcu1", client_pid(), :up, %{queue_id: 7}})

      assert wait_until(fn -> match?({:ok, %{stale: false}}, Mcu.conference(ctx.uid)) end)
      assert_received {:rpc, "CreateConference", [uid, 1, 32_000, 7]}
      assert uid == ctx.uid
      # …and the DID answers again
      assert {:ok, _conf, _part} = Mcu.admit(@domain, invite(did))
    end

    test "recreation happens before the orphan sweep, so it is not swept away", ctx do
      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert wait_until(fn -> match?({:ok, %{stale: true}}, Mcu.conference(ctx.uid)) end)
      _drain = TestStub.rpc_order()

      send(Mcu, {:mcu_client, "mcu1", client_pid(), :up, %{queue_id: 7}})
      assert wait_until(fn -> match?({:ok, %{stale: false}}, Mcu.conference(ctx.uid)) end)

      order = TestStub.rpc_order()

      assert Enum.find_index(order, &(&1 == "CreateConference")) <
               Enum.find_index(order, &(&1 == "GetConferences"))
    end
  end

  describe "orphan collection (§9.4)" do
    test "a conference the server holds and we do not is deleted at start" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)

      # the leftovers of a kelixip that died: two conferences, no controller
      _ctx =
        start_mcu(
          drain: false,
          returns: %{"GetConferences" => {:ok, [[7, "c-leftover", 0], [8, "c-other", 2]]}}
        )

      assert_receive {:rpc, "GetConferences", []}, 2000
      # both are gone, and nothing else was touched
      assert_receive {:rpc, "DeleteConference", [7]}, 2000
      assert_receive {:rpc, "DeleteConference", [8]}, 2000
    end

    test "ours is kept and the stranger's is dropped, in the same sweep", ctx do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)

      # The server reports whatever the registry holds, plus one conference that is
      # not ours. Answered dynamically because the sweep also runs at start-up, when
      # no conference exists yet.
      reported = fn _params ->
        ours = Enum.map(Mcu.conferences(), fn c -> [c.conf_id, c.uid, 0] end)
        {:ok, [[99, "c-stranger", 0] | ours]}
      end

      ctx2 = start_mcu(drain: false, returns: %{"GetConferences" => reported})
      config = GenServer.call(Mcu, :config)
      {:ok, entry} = Mcu.mediaserver("mcu1")

      assert :ok = Mcu.gc_orphans(config, entry)

      assert_receive {:rpc, "DeleteConference", [99]}, 2000
      refute_receive {:rpc, "DeleteConference", [42]}, 200
      assert {:ok, _} = Mcu.conference(ctx2.uid)
      # the conference of the setup's registry is gone with it; what matters is that
      # the sweep kept the one this registry knows and dropped the one it does not
      refute ctx2.uid == ctx.uid
    end

    test "a truncated tag does not make the sweep delete our own conferences", ctx do
      # what an unpatched media server reports: the tag cut to its first character
      # (a std::wstring handed to xmlrpc-c's %s). Keyed on the tag, this sweep would
      # delete the conference we hold; keyed on the id, it leaves it alone.
      {:ok, conf} = Mcu.conference(ctx.uid)
      ours = conf.conf_id
      config = GenServer.call(Mcu, :config)
      {:ok, entry} = Mcu.mediaserver("mcu1")

      stop_supervised!(:client_mcu1)

      start_supervised!(
        {Client,
         name: "mcu1",
         base_url: "http://127.0.0.1:18080",
         transport:
           TestStub.transport(self(), %{
             "GetConferences" => {:ok, [[ours, "c", 0], [99, "c", 0]]}
           }),
         register: {Mcu, "mcu1"},
         reconnect_ms: 0},
        id: :client_mcu3
      )

      assert wait_until(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
      {:ok, entry} = {:ok, %{entry | client: elem(Mcu.mediaserver("mcu1"), 1).client}}

      assert :ok = Mcu.gc_orphans(config, entry)

      assert_receive {:rpc, "DeleteConference", [99]}, 2000
      refute_receive {:rpc, "DeleteConference", [^ours]}, 200
      assert {:ok, _} = Mcu.conference(ctx.uid)
    end

    test "an unreadable GetConferences deletes nothing at all" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)

      # a shape we cannot decode with confidence: deleting on a guess would destroy
      # live conferences rather than leak dead ones
      # a row shape we cannot decode: the sweep must not guess at it
      _ctx = start_mcu(drain: false, returns: %{"GetConferences" => {:ok, ["not-a-row"]}})

      assert_receive {:rpc, "GetConferences", []}, 2000
      refute_receive {:rpc, "DeleteConference", _params}, 200
    end

    test "`gc_orphans = false` skips the sweep entirely" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)

      _ctx =
        start_mcu(
          drain: false,
          block: %{"gc_orphans" => false},
          returns: %{"GetConferences" => {:ok, [[7, "c-leftover", 0]]}}
        )

      refute_receive {:rpc, "GetConferences", _params}, 300
      refute_receive {:rpc, "DeleteConference", _params}, 100
    end
  end

  defp invite(did) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "carol", domain: "phone.example.com"}
    }
  end

  defp client_pid() do
    {:ok, entry} = Mcu.mediaserver("mcu1")
    entry.client
  end
end
