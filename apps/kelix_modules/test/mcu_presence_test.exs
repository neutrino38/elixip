defmodule Kelix.Mod.McuPresenceTest do
  @moduledoc """
  Conference rooms as presentities (`docs/design/mcu-presence-plan.md`, MP3): the
  row → document mapping, a report only when the state changed, and the resync
  after either half restarts.

  The watcher here is the test process, registered on the room's resource the way
  a notifier instance is: what the presence collection pushes to it is what a
  SUBSCRIBE dialog would be NOTIFYed.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.{Mcu, McuPresence, Presence}
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

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
    start_supervised!(Presence)
    :ok
  end

  defp start_mcu() do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8002"})
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

    until!(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
  end

  defp start_link_module(opts \\ []) do
    start_supervised!({McuPresence, Keyword.merge([retry_ms: 20], opts)})
  end

  # The test process watching one room, as a notifier instance would.
  defp watch(did) do
    sub =
      %SIP.Subscription{
        callid: "call-#{did}",
        event: "presence",
        presentity_uri: "sip:#{did}@#{@domain}",
        watcher_username: "alice",
        watcher_domain: @domain
      }
      |> SIP.Subscription.put_status(:active)
      |> SIP.Subscription.grant(3600)

    {:ok, doc} = Presence.watch(@domain, sub)
    doc
  end

  defp join(conf, user) do
    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: user, domain: "phone.example.com"}
    }

    {:ok, _conf, part} = Mcu.admit(@domain, req)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(client, self(), mcu_participant: part, media: :audio)

    {:ok, _answer} = Adapter.set_remote_offer(conn, @offer)
    :ok = Mcu.attach(part)
    part
  end

  defp status(%SIP.Presence.Doc{} = doc), do: {SIP.Presence.Doc.status(doc), doc.activity}

  defp await_state(did) do
    resource = {did, @domain, "presence"}
    assert_receive {:presence, :state, ^resource, doc}, 2_000
    doc && status(doc)
  end

  describe "room_doc/1" do
    @row %{domain: @domain, did: "8001", stale: false, participants: 0, max_participants: 3}

    test "a live room that is not full is open" do
      doc = McuPresence.room_doc(@row)
      assert doc.entity == "sip:8001@example.com"
      assert status(doc) == {:open, nil}
    end

    # RFC 3863 keeps a full room reachable; what it is doing is RPID's to say.
    test "a full room is open and busy" do
      assert status(McuPresence.room_doc(%{@row | participants: 3})) == {:open, :busy}
    end

    test "a room whose media server went away is closed" do
      assert status(McuPresence.room_doc(%{@row | stale: true})) == {:closed, nil}

      assert status(McuPresence.room_doc(%{@row | stale: true, participants: 3})) ==
               {:closed, nil}
    end
  end

  describe "the rooms reported" do
    test "the rooms already there are reported at start" do
      {:ok, conf} = Mcu.create_conference(@domain, did: "8001")
      refute Presence.exists?(@domain, "8001")

      start_link_module()

      assert until(fn -> Presence.exists?(@domain, "8001") end)
      assert watch(conf.did) |> status() == {:open, nil}

      assert {:ok, [%{presentity_uri: "sip:8001@example.com", status: "open", uid: uid}]} =
               McuPresence.handle_control("list", %{})

      assert uid == conf.uid
    end

    test "a room goes open, busy when full, open again, closed, then away" do
      start_link_module()
      assert watch("8001") == nil

      {:ok, conf} = Mcu.create_conference(@domain, did: "8001", max_participants: 2)
      assert await_state("8001") == {:open, nil}

      # a participant joining a half-empty room changes no presence
      _alice = join(conf, "alice")
      refute_receive {:presence, :state, _resource, _doc}, 200

      bob = join(conf, "bob")
      assert await_state("8001") == {:open, :busy}

      :ok = Mcu.leave(bob, :bye)
      assert await_state("8001") == {:open, nil}

      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert await_state("8001") == {:closed, nil}

      :ok = Mcu.destroy_conference(conf.uid, force: true)
      assert await_state("8001") == nil
      refute Presence.exists?(@domain, "8001")
    end

    test "a room outside the configured domains is not reported" do
      start_link_module(domains: MapSet.new(["other.example"]))
      {:ok, _conf} = Mcu.create_conference(@domain, did: "8001")

      Process.sleep(100)
      refute Presence.exists?(@domain, "8001")
      assert {:ok, []} = McuPresence.handle_control("list", %{})
    end
  end

  describe "either half restarting" do
    # Presence dropped every state with the process that held them.
    test "a presence restart is a full re-report" do
      {:ok, _conf} = Mcu.create_conference(@domain, did: "8001")
      start_link_module()
      assert until(fn -> Presence.exists?(@domain, "8001") end)

      stop_supervised!(Presence)
      start_supervised!(Presence)

      assert until(fn -> Presence.exists?(@domain, "8001") end)
    end

    # The rooms the new MCU no longer holds are withdrawn, the others resynced.
    test "an MCU restart is a re-subscribe and a resync" do
      {:ok, conf} = Mcu.create_conference(@domain, did: "8001")
      start_link_module()
      assert until(fn -> Presence.exists?(@domain, "8001") end)
      assert watch(conf.did) |> status() == {:open, nil}

      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      start_mcu()

      # nothing persisted: the room is gone with the old process
      assert await_state("8001") == nil

      # and the new MCU is followed
      {:ok, _conf} = Mcu.create_conference(@domain, did: "8001")
      assert await_state("8001") == {:open, nil}
    end

    test "the MCU coming up after the module is caught up with" do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      start_link_module()

      start_mcu()
      {:ok, _conf} = Mcu.create_conference(@domain, did: "8001")
      assert until(fn -> Presence.exists?(@domain, "8001") end)
    end
  end

  describe "the configuration" do
    # This test node's config.toml declares no module at all.
    test "refuses a block whose halves are not configured" do
      assert {:error, msg} = McuPresence.validate_config(%{"domains" => ["example.com"]})
      assert msg =~ "needs the mcu and presence module(s) loaded"
    end

    test "refuses an unknown key and a malformed domain list" do
      assert {:error, msg} = McuPresence.validate_config(%{"domain" => "example.com"})
      assert msg =~ "unknown key(s): domain"

      assert {:error, msg} = McuPresence.validate_config(%{"domains" => "example.com"})
      assert msg =~ "list"
    end

    # A node missing one half fails at start, not on the first SUBSCRIBE.
    test "names the half that is not configured" do
      assert McuPresence.missing_companions(["mcu", "presence", "auth_db"]) == []
      assert McuPresence.missing_companions(["mcu"]) == ["presence"]
      assert McuPresence.missing_companions([]) == ["mcu", "presence"]
    end

    test "the declared command set is routable" do
      assert :ok = Kelix.Control.Route.check_conflicts(McuPresence.describe_control())
    end
  end
end
