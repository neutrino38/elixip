defmodule Kelix.Mod.McuLifecycleTest do
  @moduledoc """
  P5b: driving a conference's lifetime from a scenario (design
  `docs/design/mcu_module.md` §17, test plan §17.7).

  Three things are worth pinning down here, and the rest follows from P1's coverage:
  **ownership** (a creator that dies takes an empty conference with it and leaves a
  populated one alone), **atomicity** of `ensure_conference/3`, and **parity** — a
  conference a script created must be indistinguishable from one REST created, or the
  two paths will drift.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

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
    {:ok, config} =
      Config.parse(
        Map.merge(
          %{
            "did_range" => "8000-8002"
          },
          Keyword.get(opts, :block, %{})
        )
      )

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport:
         TestStub.transport(
           self(),
           Map.merge(
             %{"StartReceiving" => {:ok, [@rec_port, @media_ip]}},
             Keyword.get(opts, :returns, %{})
           )
         ),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    until!(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
    _setup_rpcs = TestStub.rpc_order()
    :ok
  end

  # Run `fun` in a throwaway process standing in for a scenario instance, and hand
  # back both its result and its pid so a test can kill it.
  defp as_instance(fun) do
    test = self()

    pid =
      spawn(fn ->
        send(test, {:result, self(), fun.()})
        # stay alive: the point of these tests is what happens when this process
        # dies, and it must not die before the test says so
        Process.sleep(:infinity)
      end)

    assert_receive {:result, ^pid, result}, 2000
    {pid, result}
  end

  defp join(conf) do
    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"}
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

  # ── create_conference/2 ──────────────────────────────────────────────────────

  describe "create_conference/2" do
    test "creates the same conference the REST command does, from atom keys" do
      # keep it out of the caller's ownership so the two are compared like for like
      assert {:ok, conf} =
               Mcu.create_conference(@domain,
                 name: "From a script",
                 vad: 2,
                 rate: 16_000,
                 medias: [:audio, :video],
                 video: %{fps: 25},
                 layout: %{comp: 6},
                 max_participants: 4,
                 destroy_when_empty: true,
                 owner: :none
               )

      assert conf.name == "From a script"
      assert conf.vad == 2
      assert conf.rate == 16_000
      assert conf.medias == [:audio, :video]
      # a nested atom-keyed map is levelled and merged, like its JSON counterpart
      assert conf.video == %{size: 6, fps: 25, bitrate: 1500, intra_period: 300}

      assert conf.layout == %{comp: 6, size: 6, auto: true}
      assert conf.max_participants == 4
      assert conf.destroy_when_empty == true

      # …and it went to the media server the same way
      assert_received {:rpc, "CreateConference", [uid, 2, 16_000, 7]}
      assert uid == conf.uid
      assert_received {:rpc, "SetCompositionType", [42, 0, 6, 6]}
    end

    test "allocates a DID, and honours an explicit one" do
      assert {:ok, %{did: "8000"}} = Mcu.create_conference(@domain, owner: :none)
      assert {:ok, %{did: "9999"}} = Mcu.create_conference(@domain, did: "9999", owner: :none)
    end

    test "the same validation as the REST body, with the same messages" do
      assert {:error, msg} = Mcu.create_conference(@domain, vad: 9)
      # the vocabulary of §8.3.7 answers with the names, not with the wire ids
      assert msg =~ "vad: 9 is not a vad mode id — one of none, basic, full"

      # `medias` is the vocabulary that survived P8a, and it is enforced here too:
      # a conference answering a media nothing can mix is a call that fails later
      assert {:error, msg} = Mcu.create_conference(@domain, medias: [:slides])
      assert msg =~ "unknown media(s) slides"

      assert {:error, msg} = Mcu.create_conference(@domain, nam: "typo")
      assert msg =~ "unknown argument(s): nam"

      assert {:error, msg} = Mcu.create_conference(@domain, owner: :somebody)
      assert msg =~ "owner must be :caller or :none"

      assert Mcu.conferences() == []
    end

    # §8.4: a script written against the codec lists must keep working for one release.
    # They decide nothing (the media server arbitrates), so they are dropped with a
    # warning naming the replacement — never a 400, which would break a script we do
    # not own on an upgrade.
    test "the retired codec arguments are ignored with a warning, not refused" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, conf} =
                   Mcu.create_conference(@domain,
                     audio_codecs: ["pcma"],
                     text_codecs: [],
                     video_fmtp: "profile-level-id=42801f",
                     owner: :none
                   )

          # nothing they used to imply happened: text is still answered, DTMF still on
          assert conf.medias == [:audio, :video, :text]
          assert conf.dtmf == true
          refute Map.has_key?(conf.video, :fmtp)
        end)

      assert log =~ "create_conference: `audio_codecs` is no longer honoured"
      assert log =~ "create_conference: `text_codecs` is no longer honoured"
      assert log =~ "create_conference: `video_fmtp` is no longer honoured"
    end

    test "the resource errors reach the script unchanged" do
      assert {:error, :unknown_mcu} = Mcu.create_conference(@domain, mcu: "ghost")

      for _ <- 1..3, do: Mcu.create_conference(@domain, owner: :none)
      assert {:error, :no_did_available} = Mcu.create_conference(@domain, owner: :none)
    end

    test "a failure after CreateConference leaves nothing behind (§9.1)" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      start_mcu(returns: %{"SetCompositionType" => {:error, {:mcu_error, "nope"}}})

      assert {:error, :rpc_error} = Mcu.create_conference(@domain, owner: :none)
      assert Mcu.conferences() == []
      assert_receive {:rpc, "DeleteConference", [42]}, 2000
    end

    test "parity with REST: the two rows differ only by their identity" do
      assert {:ok, from_script} = Mcu.create_conference(@domain, name: "X", owner: :none)

      {:ok, %{uid: rest_uid}} =
        Mcu.handle_control("conference.create", %{"domain" => @domain, "name" => "X"})

      {:ok, from_rest} = Mcu.conference(rest_uid)

      drop = [:uid, :did, :created_at, :conf_id, :participants]

      assert Map.drop(Map.from_struct(from_script), drop) ==
               Map.drop(Map.from_struct(from_rest), drop)
    end
  end

  # ── ownership (§17.3) ────────────────────────────────────────────────────────

  describe "ownership" do
    test "an empty conference dies with the instance that created it" do
      {pid, {:ok, conf}} = as_instance(fn -> Mcu.create_conference(@domain) end)
      assert {:ok, _} = Mcu.conference(conf.uid)
      _rpcs = TestStub.rpc_order()

      Process.exit(pid, :kill)

      assert until(fn -> Mcu.conference(conf.uid) == :error end)
      assert_receive {:rpc, "DeleteConference", [42]}, 2000
      # …and its DID is free again
      assert Mcu.lookup_did(@domain, conf.did) == :error
    end

    test "a populated conference survives its creator: it was only the first to arrive" do
      {pid, {:ok, conf}} = as_instance(fn -> Mcu.create_conference(@domain) end)
      _part = join(conf)

      Process.exit(pid, :kill)
      # give the reaper time to make the wrong decision, if it were going to
      Process.sleep(150)

      assert {:ok, kept} = Mcu.conference(conf.uid)
      assert Conference.count(kept) == 1
      refute_received {:rpc, "DeleteConference", _params}
    end

    test "`owner: :none` survives its creator either way" do
      {pid, {:ok, conf}} = as_instance(fn -> Mcu.create_conference(@domain, owner: :none) end)

      Process.exit(pid, :kill)
      Process.sleep(150)

      assert {:ok, _} = Mcu.conference(conf.uid)
      refute_received {:rpc, "DeleteConference", _params}
    end

    test "a conference destroyed by another path stops being watched" do
      {pid, {:ok, conf}} = as_instance(fn -> Mcu.create_conference(@domain) end)
      assert :ok = Mcu.destroy_conference(conf.uid)
      _rpcs = TestStub.rpc_order()

      # the creator's death must not look for a row that is already gone
      Process.exit(pid, :kill)
      Process.sleep(150)

      refute_received {:rpc, "DeleteConference", _params}
      # the registry is still answering
      assert {:ok, _} = Mcu.create_conference(@domain, owner: :none)
    end

    test "REST-created conferences are never owned by the request that made them" do
      # `owner: :caller` from REST would destroy the conference as the response is sent
      {:ok, %{uid: uid}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
      Process.sleep(100)
      assert {:ok, _} = Mcu.conference(uid)

      # and the option is not reachable from there
      assert {:error, msg} =
               Mcu.handle_control("conference.create", %{"domain" => @domain, "owner" => "caller"})

      assert msg =~ "unknown argument(s): owner"
    end
  end

  # ── ensure_conference/3 (§17.4) ──────────────────────────────────────────────

  describe "ensure_conference/3" do
    test "creates on first arrival, then returns the same one" do
      assert {:ok, first, :created} = Mcu.ensure_conference(@domain, "8042", owner: :none)
      assert first.did == "8042"

      assert {:ok, second, :existing} = Mcu.ensure_conference(@domain, "8042", owner: :none)
      assert second.uid == first.uid
      # the second call created nothing
      assert Enum.count(Mcu.conferences(), &(&1.did == "8042")) == 1
    end

    test "an explicit DID outside the allocation range is honoured" do
      assert {:ok, conf, :created} = Mcu.ensure_conference(@domain, "1234", owner: :none)
      assert conf.did == "1234"
    end

    test "concurrent callers on the same unknown DID get one conference" do
      results =
        1..8
        |> Task.async_stream(fn _ -> Mcu.ensure_conference(@domain, "8042", owner: :none) end,
          max_concurrency: 8
        )
        |> Enum.map(fn {:ok, result} -> result end)

      uids = for {:ok, conf, _origin} <- results, do: conf.uid
      assert length(uids) == 8
      # every caller agrees on which conference it is…
      assert Enum.uniq(uids) |> length() == 1
      # …exactly one of them created it, and the registry holds one row
      assert Enum.count(results, &match?({:ok, _conf, :created}, &1)) == 1
      assert Enum.count(Mcu.conferences(), &(&1.did == "8042")) == 1
    end

    test "an existing conference is not adopted by whoever found it" do
      {:ok, conf} = Mcu.create_conference(@domain, did: "8042", owner: :none)

      {pid, {:ok, found, :existing}} =
        as_instance(fn -> Mcu.ensure_conference(@domain, "8042", owner: :caller) end)

      assert found.uid == conf.uid

      Process.exit(pid, :kill)
      Process.sleep(150)

      # it outlived nothing of that instance's: still there
      assert {:ok, _} = Mcu.conference(conf.uid)
    end

    test "a creation failure surfaces, and finding an existing one needs no media server" do
      {:ok, conf} = Mcu.create_conference(@domain, did: "8042", owner: :none)

      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert until(fn -> match?({:ok, %{status: :down}}, Mcu.mediaserver("mcu1")) end)

      # the room exists: no RPC needed to say so
      assert {:ok, found, :existing} = Mcu.ensure_conference(@domain, "8042", owner: :none)
      assert found.uid == conf.uid

      # a new one cannot be created while the server is unreachable
      assert {:error, :mcu_down} = Mcu.ensure_conference(@domain, "8043", owner: :none)
    end
  end

  # ── update / destroy / list ──────────────────────────────────────────────────

  describe "update_conference/2 and destroy_conference/2" do
    setup do
      {:ok, conf} = Mcu.create_conference(@domain, owner: :none)
      _rpcs = TestStub.rpc_order()
      %{conf: conf}
    end

    test "update merges and reports what changed", %{conf: conf} do
      assert {:ok, changed} = Mcu.update_conference(conf.uid, name: "Renamed", vad: 0)
      assert Enum.sort(changed) == [:name, :vad]

      assert {:ok, updated} = Mcu.conference(conf.uid)
      assert updated.name == "Renamed"
      assert updated.vad == 0
      # untouched by an update that did not mention them (§8.3.3)
      assert updated.rate == conf.rate
      assert_received {:rpc, "UpdateConference", [42, 0, 32_000]}
    end

    test "update refuses what REST refuses", %{conf: conf} do
      assert {:error, msg} = Mcu.update_conference(conf.uid, conf_id: 7)
      assert msg =~ "read-only field(s): conf_id"

      assert {:error, msg} = Mcu.update_conference(conf.uid, rate: 44_100)
      assert msg =~ "rate must be one of"

      assert {:error, :not_found} = Mcu.update_conference("c-ghost", name: "x")
    end

    test "destroy removes it MCU-side and frees its DID", %{conf: conf} do
      assert :ok = Mcu.destroy_conference(conf.uid)
      assert_received {:rpc, "DeleteConference", [42]}
      assert Mcu.conference(conf.uid) == :error
      assert Mcu.lookup_did(@domain, conf.did) == :error
    end

    test "destroy refuses a populated conference unless forced", %{conf: conf} do
      _part = join(conf)

      assert {:error, :not_empty} = Mcu.destroy_conference(conf.uid)
      assert {:ok, _} = Mcu.conference(conf.uid)

      assert :ok = Mcu.destroy_conference(conf.uid, force: true)
      assert Mcu.conference(conf.uid) == :error
    end

    test "destroying an unknown conference is :not_found" do
      assert {:error, :not_found} = Mcu.destroy_conference("c-ghost")
    end
  end

  describe "conferences/1" do
    test "lists one domain's conferences" do
      {:ok, _} = Mcu.create_conference(@domain, owner: :none)
      {:ok, _} = Mcu.create_conference("other.example.com", did: "7001", owner: :none)

      assert [%{domain: @domain}] = Mcu.conferences(@domain)
      assert length(Mcu.conferences()) == 2
      assert Mcu.conferences("nobody.example.com") == []
    end
  end

  # ── the declared surface ─────────────────────────────────────────────────────

  test "the lifecycle functions are declared as exports (§8.1)" do
    exports = Mcu.describe().exports

    for {name, arity} <- [
          create_conference: 2,
          ensure_conference: 3,
          update_conference: 2,
          destroy_conference: 2,
          conferences: 1
        ] do
      assert {name, arity} in exports, "#{name}/#{arity} is not declared"
      assert function_exported?(Mcu, name, arity)
    end
  end
end
