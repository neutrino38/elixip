defmodule Kelix.Mod.McuInspectionTest do
  @moduledoc """
  The inspection surface of design `docs/design/mcu_module.md` §8.3.8 (P9): the mix
  recording, the mosaic slot map and the empty-slot logo — what makes the media-server
  tests 5, 6 and 7 runnable from `kelictl` alone.

  Driven against the recording stub, so the **exact RPC and its arguments** are what is
  asserted: the resolved path a client never gets to choose, the wire value behind each
  `holds` name, and the calls that must *not* happen when an argument is refused.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"
  @rec_port 52_014
  @media_ip "203.0.113.12"
  @record_dir "/var/lib/kelixip/rec"
  @image_dir "/var/lib/kelixip/img"

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
          "did_range" => "8000-8009",
          "record_dir" => @record_dir,
          "image_dir" => @image_dir
        },
        Keyword.get(opts, :block, %{})
      )

    {:ok, config} = Config.parse(block)
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    returns =
      Map.merge(
        %{
          "StartReceiving" => {:ok, [@rec_port, @media_ip]},
          "StartRecordingBroadcaster" => {:ok, []},
          "StopRecordingBroadcaster" => {:ok, []},
          "SetMosaicSlot" => {:ok, []},
          "SetParticipantBackground" => {:ok, [1]},
          # four slots, all empty — a fresh 2x2
          "GetMosaicPositions" => {:ok, [0, 0, 0, 0]}
        },
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

    {:ok, %{uid: uid}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
    # returned rather than dropped: the create-time RPCs (the logo among them) happen
    # here, and a test that asserts on them cannot use `assert_received` afterwards
    %{uid: uid, rpcs: TestStub.rpc_calls()}
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

  # A real participant, joined the way the call path does, so its row carries a
  # part_id — which is what a pin addresses.
  defp join(uid, user \\ "alice") do
    {:ok, conf} = Mcu.conference(uid)

    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: user, domain: "phone.example.com"},
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

  # ── recording (test 7) ────────────────────────────────────────────────────────

  describe "recording.start" do
    test "records the mix under the configured directory", ctx do
      assert {:ok, reply} = Mcu.handle_control("recording.start", %{"uid" => ctx.uid})

      assert reply.mcu == "mcu1"
      # the default name carries the uid, so a directory of files is readable
      assert reply.file =~ ~r/^#{ctx.uid}-\d{8}-\d{6}\.mp4$/
      assert reply.path == Path.join(@record_dir, reply.file)

      # mosaic 0 + sidebar 0, the only ones this increment drives (§1.2, 6b)
      assert_received {:rpc, "StartRecordingBroadcaster", [42, path, 0, 0]}
      assert path == reply.path
    end

    test "an explicit file name is used as given", ctx do
      assert {:ok, %{file: "record.mp4", path: path}} =
               Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "record.mp4"})

      assert path == "#{@record_dir}/record.mp4"
      assert_received {:rpc, "StartRecordingBroadcaster", [42, ^path, 0, 0]}
    end

    test "a path, a traversal or a dotfile is refused before any RPC", ctx do
      for name <- ["/etc/passwd.mp4", "../../etc/x.mp4", "sub/dir.mp4", ".hidden.mp4"] do
        assert {:error, msg} =
                 Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => name})

        assert msg =~ "file must"
      end

      # nothing reached the media server: a rejected argument costs no RPC
      assert TestStub.rpc_order() == []
      assert {:ok, %{recording: nil}} = Mcu.conference(ctx.uid)
    end

    test "an extension the server cannot write is refused, naming the two it can", ctx do
      assert {:error, msg} =
               Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "record.mkv"})

      assert msg =~ ".mp4 or .flv"
      assert TestStub.rpc_order() == []

      # …and .flv is genuinely accepted
      assert {:ok, _} =
               Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "record.flv"})
    end

    test "a second recording is a conflict, and does not touch the first", ctx do
      assert {:ok, %{file: first}} =
               Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "one.mp4"})

      TestStub.rpc_order()

      assert {:error, :already_recording} =
               Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "two.mp4"})

      # the server enforces one recorder per conference, so we must not ask twice
      assert TestStub.rpc_order() == []
      assert {:ok, %{recording: %{file: ^first}}} = Mcu.conference(ctx.uid)
    end

    test "with no record_dir configured there is nowhere to write, and it says so" do
      %{uid: uid} = restart_without_dirs()

      assert {:error, msg} = Mcu.handle_control("recording.start", %{"uid" => uid})
      assert msg =~ "record_dir is not set"
      assert TestStub.rpc_order() == []
    end

    test "an unknown conference is a 404, not a file", _ctx do
      assert {:error, :not_found} = Mcu.handle_control("recording.start", %{"uid" => "c-ghost"})
    end
  end

  describe "recording.show / stop" do
    test "show reports whether it is running, and where", ctx do
      assert {:ok, %{recording: false, file: nil, mcu: "mcu1"}} =
               Mcu.handle_control("recording.show", %{"uid" => ctx.uid})

      {:ok, _} = Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "r.mp4"})
      TestStub.rpc_order()

      assert {:ok, view} = Mcu.handle_control("recording.show", %{"uid" => ctx.uid})
      assert view.recording == true
      assert view.file == "r.mp4"
      assert view.path == "#{@record_dir}/r.mp4"
      assert view.mcu == "mcu1"
      assert view.duration_s >= 0
      # a read: it answers from our own row, since the server has no RPC to ask
      assert TestStub.rpc_order() == []
    end

    test "stop closes the file and reports the duration", ctx do
      {:ok, _} = Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "r.mp4"})
      TestStub.rpc_order()

      assert {:ok, %{file: "r.mp4", duration_s: duration}} =
               Mcu.handle_control("recording.stop", %{"uid" => ctx.uid})

      assert duration >= 0
      assert_received {:rpc, "StopRecordingBroadcaster", [42]}
      assert {:ok, %{recording: nil}} = Mcu.conference(ctx.uid)
    end

    test "stopping what was never started is a 404, not a stray RPC", ctx do
      assert {:error, :not_recording} = Mcu.handle_control("recording.stop", %{"uid" => ctx.uid})
      assert TestStub.rpc_order() == []
    end
  end

  # ── slots (test 6) ────────────────────────────────────────────────────────────

  describe "slot.update" do
    test "each holds name reaches SetMosaicSlot as its wire value", ctx do
      for {holds, wire} <- [{"vad", -2}, {"locked", -1}, {"free", 0}] do
        # a state holds no participant, and `part_id` says so with nil — not `false`
        assert {:ok, %{slot: 1, holds: ^holds, part_id: nil}} =
                 Mcu.handle_control("slot.update", %{
                   "uid" => ctx.uid,
                   "slot" => 1,
                   "holds" => holds
                 })

        assert_received {:rpc, "SetMosaicSlot", [42, 0, 1, ^wire]}
      end
    end

    test "a participant is pinned by id, and remembered as a pin", ctx do
      part = join(ctx.uid)
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      assert {:ok, %{slot: 0, holds: "part", part_id: ^part_id}} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 0,
                 "holds" => part_id
               })

      assert_received {:rpc, "SetMosaicSlot", [42, 0, 0, ^part_id]}
      assert {:ok, %{slots: %{0 => ^part_id}}} = Mcu.conference(ctx.uid)
    end

    test "…or by name, when the name matches exactly one leg", ctx do
      part = join(ctx.uid, "alice")
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      assert {:ok, %{holds: "part", part_id: ^part_id}} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 2,
                 "holds" => "alice"
               })
    end

    test "a name matching two legs is refused, naming both", ctx do
      first = join(ctx.uid, "alice")
      second = join(ctx.uid, "alice")
      {:ok, %{part_id: id1}} = Mcu.participant(first)
      {:ok, %{part_id: id2}} = Mcu.participant(second)

      assert {:error, msg} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 0,
                 "holds" => "alice"
               })

      assert msg =~ ~s("alice" matches participants)
      assert msg =~ "#{min(id1, id2)}"
      assert msg =~ "use the part_id"
      # a guess is never made, so nothing was pinned
      assert TestStub.rpc_order() == []
    end

    test "a participant that is not in this conference is a 404", ctx do
      assert {:error, :not_found} =
               Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 0, "holds" => 999})

      assert {:error, :not_found} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 0,
                 "holds" => "nobody"
               })
    end

    test "`reset` clears the pin instead of recording one", ctx do
      part = join(ctx.uid)
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 1, "holds" => part_id})

      assert {:ok, %{slots: slots}} = Mcu.conference(ctx.uid)
      assert Map.has_key?(slots, 1)

      assert {:ok, %{holds: "reset"}} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 1,
                 "holds" => "reset"
               })

      assert_received {:rpc, "SetMosaicSlot", [42, 0, 1, -3]}
      assert {:ok, %{slots: slots}} = Mcu.conference(ctx.uid)
      refute Map.has_key?(slots, 1)
    end

    test "pinning turns the automatic layout off", ctx do
      assert {:ok, %{layout: %{auto: true}}} = Mcu.conference(ctx.uid)

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 0, "holds" => "vad"})

      # …or the next arrival would move what the operator pinned (§8.3.7's rule)
      assert {:ok, %{layout: %{auto: false}}} = Mcu.conference(ctx.uid)
    end

    test "the slot bound comes from the server's table, not from the mosaic's name", ctx do
      # 2x2 holds four: 0..3
      assert {:error, msg} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 4,
                 "holds" => "vad"
               })

      assert msg =~ "slot must be 0..3 on a 2x2 mosaic"
      assert TestStub.rpc_order() == []

      # `1+4` reports **16** slots server-side, so slot 15 is legal on it — a bound
      # computed from the name would have refused this pin
      {:ok, _} = Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "layout" => "1+4"})
      TestStub.rpc_order()

      assert {:ok, %{slot: 15}} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => 15,
                 "holds" => "vad"
               })
    end

    test "the slot number arrives as a path param too (a string)", ctx do
      assert {:ok, %{slot: 3}} =
               Mcu.handle_control("slot.update", %{
                 "uid" => ctx.uid,
                 "slot" => "3",
                 "holds" => "locked"
               })
    end

    test "a missing or nonsensical holds is a refusal that prints the vocabulary", ctx do
      assert {:error, msg} = Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 0})
      assert msg =~ "holds is required"
      assert msg =~ "vad, locked, free, reset"

      assert {:error, msg} =
               Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 0, "holds" => 0})

      assert msg =~ "is not a participant id"
      assert TestStub.rpc_order() == []
    end
  end

  describe "slot.list" do
    test "the pins are ours, the occupancy is the mixer's", _ctx do
      # the mixer reports participant 7 in slot 0 and nobody elsewhere
      ctx = restart_with(%{}, %{"GetMosaicPositions" => {:ok, [7, 0, 0, 0]}})
      part = join(ctx.uid)
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 0, "holds" => "vad"})

      TestStub.rpc_order()

      assert {:ok, view} = Mcu.handle_control("slot.list", %{"uid" => ctx.uid})

      # the header an operator reads the reshuffle against
      assert view.layout.comp == 1
      assert view.vad == 1
      assert [slot0, slot1, _, _] = view.slots

      # slot 0 was told to follow the active speaker, and the mixer put our leg there:
      # `holds` and `part_id` differing is exactly what a VAD reshuffle looks like
      assert slot0 == %{
               slot: 0,
               holds: "vad",
               pinned: nil,
               part_id: part_id,
               name: "alice@phone_example_com"
             }

      assert slot1 == %{slot: 1, holds: "free", pinned: nil, part_id: nil, name: nil}

      assert_received {:rpc, "GetMosaicPositions", [42, 0]}
    end

    test "a pinned participant shows in `pinned`, even when the mixer shows nobody", ctx do
      part = join(ctx.uid)
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 3, "holds" => part_id})

      assert {:ok, %{slots: slots}} = Mcu.handle_control("slot.list", %{"uid" => ctx.uid})
      row = Enum.find(slots, &(&1.slot == 3))

      # `GetMosaicPositions` reports slot 3 empty (the leg is audio-only), and the row
      # still says who was pinned there — otherwise the pin would be invisible
      assert row.holds == "part"
      assert row.pinned == part_id
      assert row.part_id == nil
    end
  end

  # ── the empty-slot logo (test 5) ──────────────────────────────────────────────

  describe "the logo" do
    test "the configured one is loaded into every conference", _ctx do
      %{uid: uid, rpcs: rpcs} = restart_with(%{"logo_file" => "ives.png"})

      assert {:ok, %{logo: "ives.png"}} = Mcu.conference(uid)
      # participant id 0: the *mixer's* logo, not a participant's still
      assert {"SetParticipantBackground", [42, 0, "#{@image_dir}/ives.png"]} in rpcs
    end

    test "a conference may name its own, and it wins over the configured one", _ctx do
      restart_with(%{"logo_file" => "ives.png"})

      assert {:ok, %{uid: uid}} =
               Mcu.handle_control("conference.create", %{
                 "domain" => @domain,
                 "logo" => "other.png"
               })

      assert {:ok, %{logo: "other.png"}} = Mcu.conference(uid)
      assert_received {:rpc, "SetParticipantBackground", [42, 0, "#{@image_dir}/other.png"]}
    end

    # The server answers OK whatever the picture did (L14), so what this covers is the
    # RPC *failing* — an unreachable server, or a build without the method.
    test "a logo the server refuses does not fail the conference", _ctx do
      %{uid: uid} =
        restart_with(%{"logo_file" => "missing.png"}, %{
          "SetParticipantBackground" => {:error, {:mcu_error, "no such file"}}
        })

      # the conference exists and serves calls; the logo is reported as absent, which
      # is what is actually on the mixer
      assert {:ok, %{logo: nil}} = Mcu.conference(uid)
    end

    test "an explicit update is answered by the server, not warned about", ctx do
      assert {:ok, %{changed: [:logo]}} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "logo" => "new.png"})

      assert_received {:rpc, "SetParticipantBackground", [42, 0, "#{@image_dir}/new.png"]}
      assert {:ok, %{logo: "new.png"}} = Mcu.conference(ctx.uid)
    end

    test "a path is refused, and an unset is refused (L11)", ctx do
      assert {:error, msg} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "logo" => "/etc/x.png"})

      assert msg =~ "logo must be a bare file name"

      assert {:error, msg} =
               Mcu.handle_control("conference.update", %{"uid" => ctx.uid, "logo" => nil})

      assert msg =~ "cannot be unset"
      assert TestStub.rpc_order() == []
    end

    test "with no image_dir there is nowhere to read one from" do
      %{uid: uid} = restart_without_dirs()

      assert {:error, msg} =
               Mcu.handle_control("conference.update", %{"uid" => uid, "logo" => "x.png"})

      assert msg =~ "image_dir is not set"
    end
  end

  # ── recovery (§9.2 + §8.3.8 decision 5) ───────────────────────────────────────

  describe "an MCU that restarts" do
    test "replays the pins with the composition, and does not resume the recording",
         ctx do
      part = join(ctx.uid)
      {:ok, %{part_id: part_id}} = Mcu.participant(part)

      {:ok, _} =
        Mcu.handle_control("slot.update", %{"uid" => ctx.uid, "slot" => 2, "holds" => part_id})

      {:ok, _} = Mcu.handle_control("recording.start", %{"uid" => ctx.uid, "file" => "r.mp4"})
      TestStub.rpc_order()

      # the server goes away (its event stream dying is the witness) and comes back
      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      wait_until(fn -> match?({:ok, %{stale: true}}, Mcu.conference(ctx.uid)) end)
      assert {:ok, %{recording: nil}} = Mcu.conference(ctx.uid)
      TestStub.rpc_order()

      send(Mcu, {:mcu_client, "mcu1", client_pid(), :up, %{queue_id: 7}})
      wait_until(fn -> match?({:ok, %{stale: false}}, Mcu.conference(ctx.uid)) end)
      rpcs = TestStub.rpc_calls()

      # the pin is policy, so it is put back with the conference…
      assert {"SetMosaicSlot", [42, 0, 2, part_id]} in rpcs
      assert {:ok, %{slots: %{2 => ^part_id}}} = Mcu.conference(ctx.uid)

      # …the recording is a file, and a second truncated one is not what an operator
      # asked for (§8.3.8, decision 5)
      refute Enum.any?(rpcs, &match?({"StartRecordingBroadcaster", _}, &1))

      assert {:ok, %{recording: false}} =
               Mcu.handle_control("recording.show", %{"uid" => ctx.uid})
    end
  end

  # ── helpers ───────────────────────────────────────────────────────────────────

  defp restart_with(block, returns \\ %{}) do
    stop_supervised!(:client_mcu1)
    stop_supervised!(Mcu)
    start_mcu(block: block, returns: returns)
  end

  defp restart_without_dirs() do
    stop_supervised!(:client_mcu1)
    stop_supervised!(Mcu)
    # `start_mcu/1` always sets the two directories, so build the block by hand
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009"})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{}),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_until(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
    {:ok, %{uid: uid}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
    %{uid: uid, rpcs: TestStub.rpc_calls()}
  end

  defp client_pid() do
    {:ok, entry} = Mcu.mediaserver("mcu1")
    entry.client
  end
end
