defmodule Kelix.Mod.McuTest do
  # The conference registry and its control surface (docs/design/mcu_module.md
  # §5, §8.3.3), driven through `handle_control/2` — the same entry point REST and
  # kelictl use — against a recording MCU transport.
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config}

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"

  defp start_mcu(opts \\ []) do
    block =
      Map.merge(
        %{
          "did_range" => "8000-8002"
        },
        Keyword.get(opts, :block, %{})
      )

    {:ok, config} = Config.parse(block)

    start_supervised!(
      {Mcu,
       [config: config, module_name: "mcu", mediaservers: @mediaservers] ++
         Keyword.take(opts, [:pool])}
    )

    transport = TestStub.transport(self(), Keyword.get(opts, :returns, %{}))

    client =
      start_supervised!(
        {Client,
         name: "mcu1",
         base_url: "http://127.0.0.1:18080",
         transport: transport,
         register: {Mcu, "mcu1"},
         reconnect_ms: 0},
        id: :client_mcu1
      )

    # the client announces itself to the registry; wait until the entry is usable
    wait_until(fn ->
      match?({:ok, %{status: :up, client: pid}} when is_pid(pid), Mcu.mediaserver("mcu1"))
    end)

    %{client: client}
  end

  defp wait_until(fun, attempts \\ 100) do
    if fun.() do
      :ok
    else
      if attempts == 0 do
        flunk("condition never became true")
      else
        Process.sleep(10)
        wait_until(fun, attempts - 1)
      end
    end
  end

  defp create(args \\ %{"domain" => @domain}), do: Mcu.handle_control("conference.create", args)

  # Two servers, both up: what a create with no `mcu` has to choose between.
  defp start_two_mcus(opts \\ []) do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009"})

    servers = [
      %{name: "mcu1", url: "http://127.0.0.1:18080"},
      %{name: "mcu2", url: "http://127.0.0.1:18081"}
    ]

    start_supervised!(
      {Mcu,
       [config: config, module_name: "mcu", mediaservers: servers] ++
         Keyword.take(opts, [:pool])}
    )

    for %{name: name, url: url} <- servers do
      start_supervised!(
        {Client,
         name: name,
         base_url: url,
         transport: TestStub.transport(self()),
         register: {Mcu, name},
         reconnect_ms: 0},
        id: {:client, name}
      )

      wait_until(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver(name)) end)
    end

    :ok
  end

  describe "conference.create" do
    setup do: start_mcu()

    test "allocates the lowest free DID and registers the conference" do
      assert {:ok, %{uid: uid, did: "8000", conf_id: 42, mcu: "mcu1"}} = create()

      assert {:ok, conf} = Mcu.conference(uid)
      assert conf.domain == @domain
      assert conf.did == "8000"
      assert conf.mcu == "mcu1"
      # the MCU tag is the uid: that is how an event maps back (§3.2, §5.3)
      assert {:ok, ^conf} = Mcu.lookup_did(@domain, "8000")

      # defaults applied from the config block
      assert conf.vad == 1
      assert conf.rate == 32_000
      # what it answers, not which codecs: the media server arbitrates those (P8a)
      assert conf.medias == [:audio, :video, :text]
      assert conf.dtmf == true
      assert conf.layout == %{comp: 1, size: 6, auto: true}
    end

    test "the RPC order is CreateConference then SetCompositionType" do
      # drain what the channel coming up did: create its event queue, then sweep the
      # server's orphan conferences (§9.4)
      assert ["EventQueueCreate", "GetConferences"] = TestStub.rpc_order()

      assert {:ok, _} = create()
      assert ["CreateConference", "SetCompositionType"] = TestStub.rpc_order()
    end

    test "CreateConference carries the tag, vad, rate and the client's queueId" do
      assert {:ok, %{uid: uid}} = create()
      assert_received {:rpc, "EventQueueCreate", []}
      assert_received {:rpc, "CreateConference", [^uid, 1, 32_000, 7]}
      # the default mosaic is the only one this increment drives (decision 6b)
      assert_received {:rpc, "SetCompositionType", [42, 0, 1, 6]}
    end

    test "allocation walks up the range and reports exhaustion" do
      assert {:ok, %{did: "8000"}} = create()
      assert {:ok, %{did: "8001"}} = create()
      assert {:ok, %{did: "8002"}} = create()
      assert {:error, :no_did_available} = create()
    end

    test "a freed DID is allocated again (lowest free, not next)" do
      assert {:ok, %{uid: uid, did: "8000"}} = create()
      assert {:ok, %{did: "8001"}} = create()

      assert {:ok, _} = Mcu.handle_control("conference.delete", %{"uid" => uid})
      assert {:ok, %{did: "8000"}} = create()
    end

    test "an explicit DID outside the range is honoured (§5.3)" do
      assert {:ok, %{did: "1234"}} = create(%{"domain" => @domain, "did" => "1234"})
      assert {:ok, _} = Mcu.lookup_did(@domain, "1234")
    end

    test "a duplicate (domain, did) is refused, the same DID on another domain is not" do
      assert {:ok, _} = create(%{"domain" => @domain, "did" => "8001"})
      assert {:error, :did_in_use} = create(%{"domain" => @domain, "did" => "8001"})
      assert {:ok, _} = create(%{"domain" => "other.example.com", "did" => "8001"})
    end

    test "concurrent creates never share a DID" do
      results =
        1..3
        |> Task.async_stream(fn _ -> create() end, max_concurrency: 3)
        |> Enum.map(fn {:ok, result} -> result end)

      dids = for {:ok, %{did: did}} <- results, do: did
      assert Enum.sort(dids) == ["8000", "8001", "8002"]
    end

    test "explicit fields override the configured defaults" do
      assert {:ok, %{uid: uid}} =
               create(%{
                 "domain" => @domain,
                 "name" => "Sales weekly",
                 "vad" => 2,
                 "rate" => 16_000,
                 "medias" => ["audio", "video"],
                 "dtmf" => false,
                 "max_participants" => 4,
                 "destroy_when_empty" => true,
                 "video" => %{"fps" => 25},
                 "layout" => %{"comp" => 6, "size" => 2}
               })

      assert {:ok, conf} = Mcu.conference(uid)
      assert conf.name == "Sales weekly"
      assert conf.vad == 2
      assert conf.rate == 16_000
      assert conf.medias == [:audio, :video]
      assert conf.dtmf == false
      assert conf.max_participants == 4
      assert conf.destroy_when_empty == true
      # a partial video override keeps the rest of the profile
      assert conf.video == %{size: 6, fps: 25, bitrate: 1024, intra_period: 300}

      # the mosaic keeps the requested composition but NOT a canvas size of its own: the
      # canvas is the encoded picture, so it follows `video.size` (hd720p here, the
      # configured default this create did not override)
      assert conf.layout == %{comp: 6, size: 6, auto: true}
      assert_received {:rpc, "CreateConference", [^uid, 2, 16_000, 7]}
      assert_received {:rpc, "SetCompositionType", [42, 0, 6, 6]}
    end

    test "the human forms create the same conference (§8.3.7)" do
      assert {:ok, %{uid: uid}} =
               create(%{
                 "domain" => @domain,
                 "vad" => "full",
                 "video" => %{"size" => "vga"},
                 "layout" => "1+1,720p"
               })

      assert {:ok, conf} = Mcu.conference(uid)
      assert conf.vad == 2
      assert conf.video.size == 2
      # `1+1` implies manual: an operator who names a mosaic at create time means it.
      # `720p` in the layout is a canvas size, so it is dropped for `video.size` (vga
      # here) — composing and encoding at two geometries is what stretched the mosaic.
      assert conf.layout == %{comp: 6, size: 2, auto: false}
      assert_received {:rpc, "CreateConference", [^uid, 2, 32_000, 7]}
      assert_received {:rpc, "SetCompositionType", [42, 0, 6, 2]}
    end

    test "an unknown or badly typed argument is refused, and nothing is created" do
      assert {:error, msg} = create(%{"domain" => @domain, "max_participant" => 4})
      assert msg =~ "unknown argument(s)"

      assert {:error, _} = create(%{"domain" => @domain, "vad" => 9})
      assert {:error, "domain is required"} = create(%{})
      assert Mcu.conferences() == []
    end

    test "an unknown mcu name is refused" do
      assert {:error, :unknown_mcu} = create(%{"domain" => @domain, "mcu" => "ghost"})
    end

    # §8.4: the REST body of a client we do not own may still carry them. Ignored with
    # a warning, never a 400 — the same tolerance the config block gives them.
    test "the retired codec arguments are ignored with a warning" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, %{uid: uid}} =
                   create(%{
                     "domain" => @domain,
                     "audio_codecs" => ["pcma"],
                     "video_codecs" => ["h264"]
                   })

          assert {:ok, conf} = Mcu.conference(uid)
          assert conf.medias == [:audio, :video, :text]
          assert conf.dtmf == true
        end)

      assert log =~ "conference.create: `audio_codecs` is no longer honoured"
      assert log =~ "conference.create: `video_codecs` is no longer honoured"
    end

    test "the CLI arg shape reaches the same place" do
      assert {:ok, %{did: "8001"}} =
               Mcu.handle_control("conference.create", %{
                 "args" => ["domain=#{@domain}", "did=8001", "name=Weekly"]
               })
    end
  end

  describe "conference.create rollback (§9.1)" do
    setup do
      start_mcu(returns: %{"SetCompositionType" => {:error, {:mcu_error, "bad mosaic"}}})
    end

    test "a failure after CreateConference deletes it and registers nothing" do
      assert {:error, :rpc_error} = create()

      assert Mcu.conferences() == []
      assert Mcu.lookup_did(@domain, "8000") == :error

      assert TestStub.rpc_order() == [
               "EventQueueCreate",
               "GetConferences",
               "CreateConference",
               "SetCompositionType",
               "DeleteConference"
             ]
    end

    test "the DID is not consumed by a failed create" do
      assert {:error, :rpc_error} = create()
      # the range still starts at 8000: a failed create must not burn a number
      assert {:error, :rpc_error} = create()
      assert_received {:rpc, "EventQueueCreate", []}
      assert_received {:rpc, "CreateConference", [_uid, _vad, _rate, _queue]}
    end
  end

  describe "conference.create when the media server is unreachable" do
    setup do
      {:ok, config} =
        Config.parse(%{
          "did_range" => "8000-8002"
        })

      start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

      transport = TestStub.transport(self(), %{"EventQueueCreate" => {:error, :timeout}})

      start_supervised!(
        {Client,
         name: "mcu1",
         base_url: "http://127.0.0.1:18080",
         transport: transport,
         register: {Mcu, "mcu1"},
         reconnect_ms: 0},
        id: :client_mcu1
      )

      wait_until(fn ->
        match?({:ok, %{client: pid}} when is_pid(pid), Mcu.mediaserver("mcu1"))
      end)

      :ok
    end

    test "the entry exists but is down, so create is refused with a 503 reason" do
      assert {:ok, %{status: :down}} = Mcu.mediaserver("mcu1")
      assert {:error, :mcu_down} = create()
      assert {:error, :mcu_down} = create(%{"domain" => @domain, "mcu" => "mcu1"})
    end
  end

  describe "which media server a create lands on (§8.4)" do
    setup do: start_two_mcus()

    test "no `mcu` given: the servers are taken in turn" do
      assert {:ok, %{mcu: first}} = create(%{"domain" => @domain})
      assert {:ok, %{mcu: second}} = create(%{"domain" => @domain})
      assert {:ok, %{mcu: third}} = create(%{"domain" => @domain})

      assert Enum.sort([first, second]) == ["mcu1", "mcu2"]
      # the cursor wraps rather than sticking to the last one
      assert third == first
    end

    test "an explicit `mcu` is always honoured — a conference is pinned" do
      assert {:ok, %{mcu: "mcu2"}} = create(%{"domain" => @domain, "mcu" => "mcu2"})
      assert {:ok, %{mcu: "mcu2"}} = create(%{"domain" => @domain, "mcu" => "mcu2"})
    end
  end

  describe "a media server the pool disabled (§8.4)" do
    setup do
      # a test-owned pool next to the node's (empty) singleton, so the module reads
      # an `enabled` flag we control
      pool =
        for name <- ["mcu1", "mcu2"] do
          %{name: name, module: :mendooze, url: "http://127.0.0.1:18080", enabled: true}
        end

      mp = :"mp_#{System.unique_integer([:positive])}"

      start_supervised!(
        {Kelix.MediaPool, name: mp, pool: pool, probe: fn _ -> true end, first_check_ms: 60_000}
      )

      start_two_mcus(pool: mp)
      :ok = Kelix.MediaPool.toggle("mcu2", false, mp)
      :ok
    end

    test "takes no new conference, but stays reachable by name" do
      assert {:ok, %{mcu: "mcu1"}} = create(%{"domain" => @domain})
      assert {:ok, %{mcu: "mcu1"}} = create(%{"domain" => @domain})
      # disabled means "no new conference here", not "unusable": a conference is
      # pinned, so an explicit name still works
      assert {:ok, %{mcu: "mcu2"}} = create(%{"domain" => @domain, "mcu" => "mcu2"})
    end
  end

  describe "mediaservers_from_pool/1" do
    test "keeps the mendooze entries and leaves the others to their own adapter" do
      entries = [
        %{name: "mcu1", module: :mendooze, url: "http://10.0.0.12:8080", enabled: true},
        %{name: "fake", module: :mockup, url: "http://10.0.0.99:8080", enabled: true},
        %{name: "other", module: MediaServer.Mockup, url: "http://10.0.0.98:8080", enabled: true}
      ]

      assert Mcu.mediaservers_from_pool(entries) == [
               %{name: "mcu1", url: "http://10.0.0.12:8080"}
             ]
    end

    test "an empty pool yields no control channel" do
      assert Mcu.mediaservers_from_pool([]) == []
    end
  end

  describe "conference.create with no media server configured" do
    setup do
      # an empty [mediaserver.pool] — nothing for the module to drive
      {:ok, config} = Config.parse(%{"did_range" => "8000-8002"})
      start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: []})
      :ok
    end

    test "is refused rather than pretending" do
      assert {:error, :no_mediaserver} = create()
    end
  end

  describe "conference.create with no allocation range" do
    # `did_range` absent from both keys ⇒ `did` is mandatory (§8.4)
    setup do: start_mcu(block: %{"did_range" => nil})

    test "the DID becomes mandatory, and an explicit one still works" do
      assert {:error, :did_required} = create()
      assert {:ok, %{did: "8001"}} = create(%{"domain" => @domain, "did" => "8001"})
    end
  end

  describe "conference.list / show" do
    setup do: start_mcu()

    test "list is filterable by domain and by DID" do
      assert {:ok, %{uid: uid_a}} = create(%{"domain" => @domain, "did" => "8001"})
      assert {:ok, _} = create(%{"domain" => "other.example.com", "did" => "9001"})

      assert {:ok, all} = Mcu.handle_control("conference.list", %{})
      assert length(all) == 2

      assert {:ok, [row]} = Mcu.handle_control("conference.list", %{"domain" => @domain})
      assert row.uid == uid_a
      assert row.did == "8001"
      # the row is a view, not the struct: no participant map, no pids
      assert row.participants == 0

      assert {:ok, [_]} = Mcu.handle_control("conference.list", %{"did" => "9001"})
      assert {:ok, []} = Mcu.handle_control("conference.list", %{"did" => "7000"})
    end

    test "show returns the conference and its (empty) participant list" do
      assert {:ok, %{uid: uid}} = create()
      assert {:ok, shown} = Mcu.handle_control("conference.show", %{"uid" => uid})

      assert shown.uid == uid
      assert shown.conf_id == 42
      assert shown.participants == []
    end

    test "show on an unknown uid is :not_found (the frontal maps it to 404)" do
      assert {:error, :not_found} = Mcu.handle_control("conference.show", %{"uid" => "c-ghost"})
    end
  end

  describe "conference.delete" do
    setup do: start_mcu()

    test "deletes MCU-side and drops both index entries" do
      assert {:ok, %{uid: uid}} = create()

      assert {:ok, %{uid: ^uid, disconnected: 0}} =
               Mcu.handle_control("conference.delete", %{"uid" => uid})

      assert Mcu.conference(uid) == :error
      assert Mcu.lookup_did(@domain, "8000") == :error
      assert_received {:rpc, "DeleteConference", [42]}
    end

    test "an unknown uid is :not_found" do
      assert {:error, :not_found} = Mcu.handle_control("conference.delete", %{"uid" => "c-ghost"})
    end

    test "the CLI `force` flag is accepted as a bare token" do
      assert {:ok, %{uid: uid}} = create()

      assert {:ok, _} =
               Mcu.handle_control("conference.delete", %{"args" => ["uid=#{uid}", "force"]})
    end
  end

  describe "control surface" do
    setup do: start_mcu()

    test "every declared command answers (no unknown_command)" do
      for %{name: name} <- Mcu.describe_control() do
        result = Mcu.handle_control(name, %{})
        refute result == {:error, :unknown_command}, "#{name} is declared but not handled"
      end
    end

    test "an undeclared command is refused" do
      assert {:error, :unknown_command} = Mcu.handle_control("conference.explode", %{})
    end

    test "the declared commands are the whole surface of §8.3.3 and §8.3.8" do
      names = Enum.map(Mcu.describe_control(), & &1.name)

      assert Enum.sort(names) == [
               "conference.create",
               "conference.delete",
               "conference.list",
               "conference.show",
               "conference.update",
               "participant.delete",
               "participant.list",
               "participant.show",
               "participant.update",
               # the inspection surface of §8.3.8
               "recording.show",
               "recording.start",
               "recording.stop",
               "slot.list",
               "slot.update"
             ]

      # `mute` and `kick` are not verbs of their own: muting is participant.update,
      # kicking is participant.delete (§8.3.3, the one simplification the resource
      # shape buys us)
      refute "mute" in names
      refute "kick" in names
    end

    test "create declares 201 + Location + the error statuses FW-4 derives" do
      create_cmd = Enum.find(Mcu.describe_control(), &(&1.name == "conference.create"))

      assert create_cmd.rest == {:post, "/conferences"}
      assert create_cmd.status == 201
      assert create_cmd.location == "/conferences/:uid"
      assert create_cmd.errors[:no_did_available] == 409
      assert create_cmd.errors[:mcu_down] == 503
      # the declared command set must be routable (FW-4 refuses ambiguity)
      assert :ok = Kelix.Control.Route.check_conflicts(Mcu.describe_control())
    end
  end

  describe "dial-plan drift (§6.1)" do
    setup do
      dir = Path.join(System.tmp_dir!(), "kelix_mcu_#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      path = Path.join(dir, "domains.toml")
      empty = Path.join(dir, "empty.toml")
      File.write!(empty, "")

      File.write!(path, """
      [[domain]]
      name = "#{@domain}"

        [[domain.call]]
        pattern = "8XXX"
        script  = "mcu.exs"
      """)

      :ok = Kelix.Domains.reload(path)
      on_exit(fn -> Kelix.Domains.reload(empty) && File.rm_rf(dir) end)

      start_mcu()
    end

    test "a DID the dial plan routes creates no warning" do
      assert {:ok, reply} = create()
      assert reply.did == "8000"
      refute Map.has_key?(reply, :warning)
    end

    test "a DID no call rule matches is reported: the module allocates, it does not route" do
      assert {:ok, reply} = create(%{"domain" => @domain, "did" => "1234"})
      assert reply.warning =~ "matches no call rule"
      # the conference is still created — the operator's dial plan is theirs to fix
      assert {:ok, _} = Mcu.lookup_did(@domain, "1234")
    end
  end

  # This module's control channel is permanent, so it sees a media server die within
  # its reconnect cycle where the pool's periodic probe may be a cycle away (§9). Each
  # transition is pushed to the pool, which otherwise keeps handing the MCU out to the
  # router for point-to-point calls — those go through the pool, not through here.
  describe "MCU health → media pool" do
    setup do
      test = self()

      # A probe that never answers: what the pool believes is then exactly what the
      # module's hint told it, with no probe verdict racing the assertions.
      pool = [%{name: "mcu1", module: :mendooze, url: "http://127.0.0.1:18080", enabled: true}]
      mp = :"mp_#{System.unique_integer([:positive])}"

      probe = fn e ->
        send(test, {:probing, e.name})

        receive do
          :answer -> true
        after
          5_000 -> false
        end
      end

      start_supervised!(
        {Kelix.MediaPool, name: mp, pool: pool, probe: probe, first_check_ms: 60_000}
      )

      start_mcu(pool: mp)
      %{pool: mp}
    end

    test "a lost event stream takes the entry out of the pool as well", %{pool: mp} do
      assert {:ok, %{name: "mcu1"}} = Kelix.MediaPool.checkout(mp)

      send(Mcu, {:mcu_event_stream_down, "mcu1"})

      wait_until(fn -> match?([%{healthy: false}], Kelix.MediaPool.status(mp)) end)
      assert Kelix.MediaPool.checkout(mp) == {:error, :no_mcu}
    end

    test "the hint reaches the pool named in the module's options, not the singleton",
         %{pool: mp} do
      # the node's own (empty) pool must be untouched by a test-owned module
      send(Mcu, {:mcu_event_stream_down, "mcu1"})

      wait_until(fn -> match?([%{healthy: false}], Kelix.MediaPool.status(mp)) end)
      assert Kelix.MediaPool.status() == []
    end
  end

  describe "MCU health" do
    setup do: start_mcu()

    test "a lost event stream marks the entry down, so new conferences are refused" do
      assert {:ok, %{status: :up}} = Mcu.mediaserver("mcu1")

      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      wait_until(fn -> match?({:ok, %{status: :down}}, Mcu.mediaserver("mcu1")) end)

      assert {:error, :mcu_down} = create()
    end

    # A restarted media server answers control RPCs as if nothing happened while
    # 404ing the queue it no longer knows — only the poller sees it, and it says so
    # through renew_queue/2. Without this the poller retried a dead id for ever and
    # the module went deaf to every event.
    test "a queue the server has forgotten is replaced" do
      assert {:ok, %{client: client, status: :up}} = Mcu.mediaserver("mcu1")
      stale = Client.queue_id(client)
      assert is_integer(stale)
      _ = TestStub.rpc_order()

      :ok = Client.renew_queue(client, stale)

      wait_until(fn -> "EventQueueCreate" in TestStub.rpc_order() end)
      # and it went through :down, so the owner knows the conferences it held on
      # that server are gone too
      assert {:ok, %{status: :up}} = Mcu.mediaserver("mcu1")
    end

    test "renewing an id that is not the current one changes nothing" do
      assert {:ok, %{client: client}} = Mcu.mediaserver("mcu1")
      _ = TestStub.rpc_order()

      # the poller asking twice about the same dead id while the replacement is in
      # flight must not create a queue per attempt
      :ok = Client.renew_queue(client, Client.queue_id(client) + 1_000)

      # a round-trip through the client proves the cast has been processed
      assert is_integer(Client.queue_id(client))
      refute "EventQueueCreate" in TestStub.rpc_order()
    end
  end

  describe "MCU events (§3.7)" do
    setup do: start_mcu()

    test "an event is routed by its tag; an unknown tag is dropped, not crashed" do
      assert {:ok, %{uid: uid}} = create()

      send(Mcu, {:mcu_event, "mcu1", {:fpu_requested, 42, uid, 7}})
      send(Mcu, {:mcu_event, "mcu1", {:fpu_requested, 42, "c-ghost", 7}})

      # the registry survives both and still answers
      assert {:ok, _} = Mcu.conference(uid)
    end
  end
end
