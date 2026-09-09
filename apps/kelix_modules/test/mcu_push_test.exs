defmodule Kelix.Mod.McuPushTest do
  @moduledoc """
  The live push a UI subscribes to (contract `docs/design/mcu-live-push.md`).

  What is worth pinning down here is not that a message arrives — it is the four
  properties kelescope builds on and which nothing else in the suite would catch:

    * the pushed rows are the rows `conference.list` / `participant.list` return,
      so the initial read and the push cannot drift apart;
    * a **destroyed** conference pushes a remove, never a row — its event is emitted
      before the `:ets.delete`, so a fan-out that re-read the table would resurrect
      it;
    * a conference **nobody watches** pushes nothing, and an unwatched roster is
      never swept — the gating is the whole cost argument of the statistics topic;
    * a subscriber that dies is dropped without unsubscribing.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config, Push, Stats}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"

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
      Config.parse(Map.merge(%{"did_range" => "8000-8002"}, Keyword.get(opts, :block, %{})))

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), Keyword.get(opts, :returns, %{})),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    start_supervised!({Stats, config: config})

    until!(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
    _setup_rpcs = TestStub.rpc_order()
    :ok
  end

  defp join(conf, user \\ "alice") do
    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: user, domain: "phone.example.com"}
    }

    {:ok, ^conf, part} = Mcu.admit(@domain, req)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(client, self(), mcu_participant: part, media: :audio)

    {:ok, _answer} = Adapter.set_remote_offer(conn, @offer)
    :ok = Mcu.attach(part)
    part
  end

  # ── the conference list ──────────────────────────────────────────────────────

  describe "subscribe_conferences/1" do
    test "answers with the current list, then pushes create, edit and destroy" do
      assert {:ok, %{owner: owner, conferences: []}} = Mcu.subscribe_conferences(self())
      assert owner == Process.whereis(Mcu)

      {:ok, conf} = Mcu.create_conference(@domain, name: "Salle 1")

      assert_receive {:kelix_conferences, {:upsert, row}}
      assert row.uid == conf.uid
      assert row.name == "Salle 1"
      # the row `conference.list` returns, from the same function
      assert {:ok, [^row]} = Mcu.handle_control("conference.list", %{})

      {:ok, _changed} = Mcu.update_conference(conf.uid, name: "Salle 2")
      assert_receive {:kelix_conferences, {:upsert, %{name: "Salle 2"}}}

      :ok = Mcu.destroy_conference(conf.uid)
      assert_receive {:kelix_conferences, {:remove, uid}}
      assert uid == conf.uid
      # never a row for a conference that no longer exists
      refute_received {:kelix_conferences, {:upsert, _}}
    end

    test "a participant coming and going changes the list row's count" do
      {:ok, conf} = Mcu.create_conference(@domain)
      {:ok, _} = Mcu.subscribe_conferences(self())

      part = join(conf)
      assert_receive {:kelix_conferences, {:upsert, %{participants: 1}}}

      :ok = Mcu.leave(part, :bye)
      assert_receive {:kelix_conferences, {:upsert, %{participants: 0}}}
    end

    test "losing a media server pushes its conferences as stale" do
      {:ok, conf} = Mcu.create_conference(@domain)
      {:ok, _} = Mcu.subscribe_conferences(self())

      send(Mcu, {:mcu_event_stream_down, "mcu1"})

      assert_receive {:kelix_conferences, {:upsert, %{uid: uid, stale: true}}}, 2000
      assert uid == conf.uid
    end

    test "an unsubscribed pid stops receiving; a dead one is dropped on its own" do
      {:ok, conf} = Mcu.create_conference(@domain)
      {:ok, _} = Mcu.subscribe_conferences(self())
      :ok = Mcu.unsubscribe_conferences(self())

      {:ok, _} = Mcu.update_conference(conf.uid, name: "Silence")
      refute_received {:kelix_conferences, _}

      watcher = spawn(fn -> Process.sleep(:infinity) end)
      {:ok, _} = Mcu.subscribe_conferences(watcher)
      assert Push.subscribers(:list) == [watcher]

      Process.exit(watcher, :kill)
      assert until(fn -> Push.subscribers(:list) == [] end)
    end
  end

  # ── one conference ───────────────────────────────────────────────────────────

  describe "subscribe_conference/2" do
    test "answers with the roster, then pushes it whole on every change" do
      {:ok, conf} = Mcu.create_conference(@domain)

      assert {:ok, %{conference: row, participants: []}} =
               Mcu.subscribe_conference(self(), conf.uid)

      assert row.uid == conf.uid

      part = join(conf)

      # ringing, then connected: one snapshot each, and the rows are
      # `participant.list`'s
      assert_receive {:kelix_conference, _uid, {:snapshot, %{participants: [ringing]}}}
      assert ringing.state == :ringing
      assert ringing.name == "alice@phone_example_com"

      %{participants: pushed} =
        await_snapshot(conf.uid, &match?([%{state: :connected}], &1.participants))

      {:ok, listed} = Mcu.handle_control("participant.list", %{"uid" => conf.uid})
      assert pushed == listed

      :ok = Mcu.leave(part, :bye)
      await_snapshot(conf.uid, &(&1.participants == []))
    end

    test "a destroyed conference ends the topic, and an unknown one is refused" do
      {:ok, conf} = Mcu.create_conference(@domain)
      {:ok, _} = Mcu.subscribe_conference(self(), conf.uid)

      :ok = Mcu.destroy_conference(conf.uid)
      assert_receive {:kelix_conference, uid, :destroyed}
      assert uid == conf.uid

      assert Mcu.subscribe_conference(self(), "c-nope") == {:error, :not_found}
    end

    test "a conference nobody watches pushes nothing" do
      {:ok, watched} = Mcu.create_conference(@domain, did: "8001")
      {:ok, other} = Mcu.create_conference(@domain, did: "8002")
      {:ok, _} = Mcu.subscribe_conference(self(), watched.uid)

      _part = join(other)
      Process.sleep(100)

      refute_received {:kelix_conference, _, _}
      # and no list topic either: nobody subscribed to it
      refute_received {:kelix_conferences, _}
    end
  end

  # ── statistics ───────────────────────────────────────────────────────────────

  describe "subscribe_conference_stats/2" do
    test "samples the expanded conference at once, then on its own period" do
      counter = start_counting()

      # a fast period, so the tick itself is observable
      :ok = restart_with(block: %{"stats_interval_ms" => 60}, returns: counting_stats(counter))

      {:ok, conf} = Mcu.create_conference(@domain)
      _part = join(conf)
      _rpcs = TestStub.rpc_order()

      assert {:ok, %{owner: owner, interval_ms: 60}} =
               Mcu.subscribe_conference_stats(self(), conf.uid)

      assert owner == Process.whereis(Mcu)

      # the first sample is immediate: an expanded panel showing nothing for a whole
      # period is what an operator reads as broken
      assert_receive {:kelix_conference_stats, uid, first}, 1000
      assert uid == conf.uid
      assert first.mcu == "mcu1"
      assert [%{part_id: 7, name: "alice@phone_example_com"} = leg] = first.participants
      # the counters as the server gave them, no rate yet — one sample cannot say
      assert leg.stats.audio.num_recv_packets == 100
      assert leg.since_ms == nil
      assert leg.stats.audio.recv_kbps == nil

      # the next tick derives the rate from the two samples
      assert_receive {:kelix_conference_stats, ^uid, second}, 2000
      assert [%{since_ms: since} = leg] = second.participants
      assert since > 0
      assert leg.stats.audio.recv_kbps > 0
      assert leg.stats.audio.lost_recv_delta == 0

      # collapsing the panel stops the sweep dead
      :ok = Mcu.unsubscribe_conference_stats(self(), conf.uid)
      _drain = drain_stats()
      _rpcs = TestStub.rpc_order()
      Process.sleep(200)
      refute_received {:rpc, "GetParticipantStatistics", _params}
      refute_received {:kelix_conference_stats, _uid, _sample}
    end

    test "no subscriber, no RPC" do
      :ok = restart_with(block: %{"stats_interval_ms" => 60})

      {:ok, conf} = Mcu.create_conference(@domain)
      _part = join(conf)
      _rpcs = TestStub.rpc_order()

      Process.sleep(250)
      refute_received {:rpc, "GetParticipantStatistics", _params}
    end

    test "a leg the media server will not answer for is reported, not hidden" do
      :ok =
        restart_with(
          block: %{"stats_interval_ms" => 60},
          returns: %{"GetParticipantStatistics" => {:error, :timeout}}
        )

      {:ok, conf} = Mcu.create_conference(@domain)
      _part = join(conf)

      {:ok, _} = Mcu.subscribe_conference_stats(self(), conf.uid)

      assert_receive {:kelix_conference_stats, _uid, sample}, 1000
      assert [%{stats: %{}, stats_error: :rpc_error}] = sample.participants
    end

    test "the topic is refused when the deployment disabled it" do
      :ok = restart_with(block: %{"stats_interval_ms" => 0})

      {:ok, conf} = Mcu.create_conference(@domain)

      assert Mcu.subscribe_conference_stats(self(), conf.uid) == {:error, :disabled}
      assert Mcu.subscribe_conference_stats(self(), "c-nope") == {:error, :disabled}
    end
  end

  # ── through the control layer ────────────────────────────────────────────────

  describe "Kelix.Control" do
    test "reaches the module by its configured name, and answers without it" do
      # not loaded: nothing to watch, and no owner to monitor — the answer a node
      # running no conferencing module must give (§16.12)
      assert Kelix.Control.subscribe_conferences(self()) ==
               {:ok, %{owner: nil, conferences: []}}

      assert Kelix.Control.subscribe_conference(self(), "c-nope") == {:error, :not_found}
      assert Kelix.Control.subscribe_conference_stats(self(), "c-nope") == {:error, :not_found}
      assert Kelix.Control.unsubscribe_conferences(self()) == :ok

      Kelix.ModuleRegistry.register("mcu", Mcu, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("mcu") end)

      {:ok, conf} = Mcu.create_conference(@domain, name: "Via Control")

      assert {:ok, %{owner: owner, conferences: [row]}} =
               Kelix.Control.subscribe_conferences(self())

      assert owner == Process.whereis(Mcu)
      assert row.name == "Via Control"

      assert {:ok, %{conference: %{uid: uid}, participants: []}} =
               Kelix.Control.subscribe_conference(self(), conf.uid)

      assert uid == conf.uid

      {:ok, _} = Mcu.update_conference(conf.uid, name: "Toujours via Control")
      assert_receive {:kelix_conferences, {:upsert, %{name: "Toujours via Control"}}}
      assert_receive {:kelix_conference, ^uid, {:snapshot, _}}

      assert Kelix.Control.unsubscribe_conference(self(), conf.uid) == :ok
      assert Kelix.Control.unsubscribe_conferences(self()) == :ok
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────────

  # The registry is started per test by `setup`; a test needing another config stops
  # it and starts its own, rather than parameterising every test with a block.
  defp restart_with(opts) do
    :ok = stop_supervised!(Stats)
    :ok = stop_supervised!(:client_mcu1)
    :ok = stop_supervised!(Mcu)
    _drain = TestStub.rpc_order()
    start_mcu(opts)
  end

  # The roster is pushed whole on every change, so a test waits for the snapshot it
  # is about rather than for the next one: `ringing` and `connected` are two
  # snapshots of the same leg, and which one arrives first is not the point.
  defp await_snapshot(uid, ok?) do
    receive do
      {:kelix_conference, ^uid, {:snapshot, snapshot}} ->
        if ok?.(snapshot), do: snapshot, else: await_snapshot(uid, ok?)
    after
      2000 -> flunk("no snapshot of #{uid} matched")
    end
  end

  defp drain_stats() do
    receive do
      {:kelix_conference_stats, _uid, _sample} -> drain_stats()
    after
      10 -> :ok
    end
  end

  defp start_counting() do
    {:ok, agent} = Agent.start_link(fn -> 0 end)
    agent
  end

  # Counters that grow between two sweeps, which is what a rate needs.
  defp counting_stats(agent) do
    %{
      "GetParticipantStatistics" => fn _params ->
        n = Agent.get_and_update(agent, &{&1, &1 + 1})
        {:ok, [["audio", 1, 1, 0, 100 + n * 50, 90 + n * 50, 16_000 + n * 8000, 14_400]]}
      end
    }
  end
end
