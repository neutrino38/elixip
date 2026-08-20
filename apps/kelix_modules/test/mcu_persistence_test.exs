defmodule Kelix.Mod.McuPersistenceTest do
  @moduledoc """
  The conference definitions on disk (design `docs/design/DESIGN-MCU.md` §4.1).

  What matters here is not the file format but the two invariants around it: what a
  restart brings back (a **room**, never a call — and never an ad-hoc room), and what a
  restart must never destroy (an operator's file, when it cannot be read).

  The recreation itself is not retested: a restored row is `stale` with no `conf_id`,
  which is exactly the state §9.2 already recovers from — `mcu_admin_test.exs` owns
  that path. What is asserted here is that the restored rows *enter* it.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Conference, Config, Store}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"

  setup context do
    path =
      Path.join(System.tmp_dir!(), "kelix-conferences-#{System.unique_integer([:positive])}.json")

    on_exit(fn -> File.rm_rf!(path) end)

    if body = context[:content], do: File.write!(path, body)

    start_mcu(path)
    %{path: path}
  end

  defp start_mcu(path) do
    start_registry(path)
    start_client()
  end

  defp start_registry(path) do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009", "conference_file" => path})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})
    :ok
  end

  # Started apart from the registry, because that is the order a node boots in: the
  # definitions are restored first and the media server comes up afterwards.
  defp start_client() do
    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{}),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    until!(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
    _drain = TestStub.rpc_order()
    :ok
  end

  # A restart of kelixip, as far as this module is concerned: the registry and its ETS
  # tables go, the file stays.
  defp restart(path) do
    stop_supervised!(:client_mcu1)
    stop_supervised!(Mcu)
    start_mcu(path)
  end

  defp create(args) do
    {:ok, result} = Mcu.handle_control("conference.create", Map.put(args, "domain", @domain))
    result
  end

  defp read(path) do
    path |> File.read!() |> Jason.decode!()
  end

  # ── what is written ──────────────────────────────────────────────────────────

  describe "the definition file" do
    test "a REST create is written, with the definition and nothing of the runtime", ctx do
      %{uid: uid} = create(%{"name" => "Weekly", "preferred_video_codec" => "vp8"})

      assert %{"version" => 1, "conferences" => [row]} = read(ctx.path)
      assert row["uid"] == uid
      assert row["name"] == "Weekly"
      assert row["domain"] == @domain
      assert row["did"] == "8000"
      assert row["mcu"] == "mcu1"
      assert row["preferred_video_codec"] == "VP8"
      assert row["video"] == %{"size" => 6, "fps" => 30, "bitrate" => 1500, "intra_period" => 300}

      # the runtime half of a conference has no business surviving a restart
      for key <- ~w(conf_id participants stale recording persistent) do
        refute Map.has_key?(row, key), "#{key} must not be in the definition file"
      end
    end

    test "an update rewrites it and a delete removes the row", ctx do
      %{uid: uid} = create(%{})

      {:ok, _} =
        Mcu.handle_control("conference.update", %{
          "uid" => uid,
          "name" => "Renamed",
          "video" => "vga 25fps"
        })

      assert %{"conferences" => [row]} = read(ctx.path)
      assert row["name"] == "Renamed"
      assert row["video"]["size"] == 2
      assert row["video"]["fps"] == 25

      {:ok, _} = Mcu.handle_control("conference.delete", %{"uid" => uid})
      assert read(ctx.path)["conferences"] == []
    end

    test "a pinned mosaic slot is part of the definition", ctx do
      %{uid: uid} = create(%{})

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => uid, "slot" => 0, "holds" => "locked"})

      assert %{"conferences" => [row]} = read(ctx.path)
      assert row["slots"] == %{"0" => -1}
      # pinning implied `manual`, and that travels with it
      assert row["layout"]["auto"] == false
    end

    # §17.3: `owner: :caller` is a room made for one call. Bringing it back at every
    # boot would be a room nobody asked for — and a conference per call would mean a
    # file write per call.
    test "an ad-hoc conference (owner: :caller) is not written", ctx do
      parent = self()

      instance =
        spawn(fn ->
          {:ok, conf} = Mcu.create_conference(@domain, name: "Ad hoc")
          send(parent, {:created, conf.uid})
          receive do: (:stop -> :ok)
        end)

      assert_receive {:created, uid}
      assert {:ok, %{persistent: false}} = Mcu.conference(uid)
      refute File.exists?(ctx.path)

      send(instance, :stop)
    end

    test "a script asking for a persistent room gets one written", ctx do
      parent = self()

      spawn(fn ->
        {:ok, conf} = Mcu.create_conference(@domain, name: "Standing", owner: :none)
        send(parent, {:created, conf.uid})
      end)

      assert_receive {:created, uid}
      assert until(fn -> match?(%{"conferences" => [_row]}, read(ctx.path)) end)
      assert [%{"uid" => ^uid, "name" => "Standing"}] = read(ctx.path)["conferences"]
    end
  end

  # ── what is read ─────────────────────────────────────────────────────────────

  describe "a restart" do
    test "brings the room back, with its DID, ready for the §9.2 recovery", ctx do
      %{uid: uid} = create(%{"name" => "Weekly", "preferred_video_codec" => "h264"})

      # the registry alone first: a restored room exists before any media server does
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      start_registry(ctx.path)

      assert {:ok, conf} = Mcu.conference(uid)
      assert conf.name == "Weekly"
      assert conf.preferred_video_codec == "H264"
      assert conf.persistent
      # a room, not a call: no participant, no MCU-side id — which is precisely the
      # state the recovery of §9.2 recreates from
      assert conf.participants == %{}
      assert conf.stale
      assert conf.conf_id == nil

      # its DID answers again, and the recreation happens when the media server does
      assert {:ok, %{uid: ^uid}} = Mcu.lookup_did(@domain, conf.did)
      start_client()
      assert until(fn -> match?({:ok, %{stale: false}}, Mcu.conference(uid)) end)
      assert {:ok, %{conf_id: 42}} = Mcu.conference(uid)
    end

    test "does not reuse the DID of a restored conference", ctx do
      %{uid: _uid, did: did} = create(%{})
      restart(ctx.path)

      assert %{did: other} = create(%{})
      assert other != did
    end

    test "an ad-hoc room does not come back", ctx do
      parent = self()

      instance =
        spawn(fn ->
          {:ok, conf} = Mcu.create_conference(@domain, name: "Ad hoc")
          send(parent, {:created, conf.uid})
          receive do: (:stop -> :ok)
        end)

      assert_receive {:created, uid}
      send(instance, :stop)

      restart(ctx.path)
      assert Mcu.conference(uid) == :error
    end

    # A file an operator wrote by hand: the values may be the names the CLI takes,
    # since the same vocabularies read both.
    @tag content: """
         {"version": 1, "conferences": [
           {"uid": "c-standing", "domain": "example.com", "did": "8500",
            "name": "Standing room", "mcu": "mcu1", "vad": "full",
            "video": {"size": "vga"}, "layout": {"comp": "3x3", "auto": false},
            "preferred_video_codec": "av1", "medias": ["audio", "video"]}
         ]}
         """
    test "reads a hand-written file, names and all" do
      assert {:ok, conf} = Mcu.conference("c-standing")
      assert conf.vad == 2
      assert conf.video.size == 2
      assert conf.layout == %{comp: 2, size: 6, auto: false}
      assert conf.preferred_video_codec == "AV1"
      assert conf.medias == [:audio, :video]
      assert {:ok, %{uid: "c-standing"}} = Mcu.lookup_did(@domain, "8500")
    end

    @tag content: """
         {"version": 1, "conferences": [
           {"uid": "c-good", "domain": "example.com", "did": "8500"},
           {"uid": "c-bad", "domain": "example.com", "did": "8500"},
           {"uid": "c-broken", "domain": "example.com", "did": "8501", "vad": "loud"}
         ]}
         """
    test "loads what it can: a duplicate DID and a bad value cost their own row only" do
      assert {:ok, _} = Mcu.conference("c-good")
      assert Mcu.conference("c-bad") == :error
      assert Mcu.conference("c-broken") == :error
    end

    # The failure that must never be answered by a write: an operator's file we cannot
    # parse. Restoring nothing is recoverable; overwriting it is not.
    @tag content: "{ this is not json"
    test "an unreadable file disables persistence and is left untouched", ctx do
      assert Mcu.conferences() == []

      %{uid: uid} = create(%{})
      assert {:ok, _} = Mcu.conference(uid)
      assert File.read!(ctx.path) == "{ this is not json"
    end

    @tag content: ~s({"version": 99, "conferences": []})
    test "a file from a newer version is refused whole, not half-read", ctx do
      %{uid: _uid} = create(%{})
      assert File.read!(ctx.path) == ~s({"version": 99, "conferences": []})
    end
  end

  # ── the store on its own ─────────────────────────────────────────────────────

  describe "Store.save/2 + Store.load/1" do
    test "round-trip a definition", ctx do
      conf = %Conference{
        uid: "c-1",
        domain: @domain,
        did: "8000",
        name: "Weekly",
        mcu: "mcu1",
        vad: 2,
        rate: 16_000,
        medias: [:audio, :text],
        dtmf: false,
        video: %{size: 2, fps: 25, bitrate: 900, intra_period: 100},
        preferred_video_codec: "VP8",
        layout: %{comp: 6, size: 2, auto: false},
        logo: "ives.png",
        slots: %{0 => -2, 3 => 7},
        max_participants: 4,
        destroy_when_empty: true,
        created_at: ~U[2026-08-20 10:00:00Z],
        persistent: true,
        # the runtime half, which must not survive
        conf_id: 42,
        stale: false,
        recording: %{file: "x.mp4"},
        participants: %{make_ref() => %{}}
      }

      assert :ok = Store.save(ctx.path, [conf])
      assert {:ok, [back]} = Store.load(ctx.path)

      assert back.uid == "c-1"
      assert back.vad == 2
      assert back.rate == 16_000
      assert back.medias == [:audio, :text]
      assert back.dtmf == false
      assert back.video == conf.video
      assert back.preferred_video_codec == "VP8"
      assert back.layout == conf.layout
      assert back.logo == "ives.png"
      assert back.slots == %{0 => -2, 3 => 7}
      assert back.max_participants == 4
      assert back.destroy_when_empty
      assert back.created_at == conf.created_at

      assert back.persistent
      assert back.stale
      assert back.conf_id == nil
      assert back.recording == nil
      assert back.participants == %{}
    end

    test "a missing file is an empty set, not an error", ctx do
      assert Store.load(ctx.path <> ".absent") == {:ok, []}
    end

    test "the write is atomic: no .tmp is left behind", ctx do
      assert :ok = Store.save(ctx.path, [])
      refute File.exists?(ctx.path <> ".tmp")
    end
  end
end
