Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.NetworkProfileTest do
  @moduledoc """
  Step 5 of `docs/design/multi-interface.md`: which of the media server's
  addresses a leg's media is placed on.

  The profile is never configured on this side — it is the intersection of what
  the peer's offer allows, what the local address this peer reached prefers, and
  what the server says it carries (§6.7 bis / §6.7 ter).
  """
  use ExUnit.Case, async: true

  alias MediaServer.Mendooze
  alias MediaServer.Mendooze.Sdp

  @v6_local {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
  @v4_local {192, 0, 2, 7}

  defp profile(name, available, announced) do
    %{
      "name" => name,
      "available" => available,
      "announced" => announced,
      "bind" => "",
      "default" => name == "publicv4"
    }
  end

  defp v4_only do
    [
      profile("publicv4", true, "203.0.113.9"),
      profile("publicv6", false, ""),
      profile("internalv4", false, ""),
      profile("internalv6", false, "")
    ]
  end

  # A dual-stack server: both public profiles, neither internal one.
  defp both_families do
    [
      profile("publicv4", true, "203.0.113.9"),
      profile("publicv6", true, "2001:db8::12"),
      profile("internalv4", false, ""),
      profile("internalv6", false, "")
    ]
  end

  # A server carrying all four, so no choice is ever forced by availability.
  defp four_profiles do
    [
      profile("publicv4", true, "203.0.113.9"),
      profile("publicv6", true, "2001:db8::12"),
      profile("internalv4", true, "10.0.0.4"),
      profile("internalv6", true, "fd00::4")
    ]
  end

  defp handler(profiles) do
    fn
      "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
      "GetNetworkProfiles", _ -> if profiles, do: {:ok, profiles}, else: {:error, "unknown method"}
      "MediaSessionCreate", _ -> {:ok, [3]}
      "EndpointCreate", _ -> {:ok, [4]}
      "EndpointStartReceiving", _ -> {:ok, [22_000]}
      "GetMediaCandidates", _ -> {:ok, ["rtp://192.168.5.5:22000"]}
      _, _ -> {:ok, []}
    end
  end

  defp start_conn(profiles, conn_opts) do
    fake = Jsr309FakeServer.start(self(), handler(profiles))
    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)

    assert_receive {:stream_conn, stream, _}, 1_000
    Jsr309FakeServer.await_streaming(server, stream)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), conn_opts)
    assert_receive {:jsr309_call, "MediaSessionCreate", _}, 1_000
    conn
  end

  defp offer(ip) do
    Sdp.build(%{
      ip: ip,
      medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: false}]
    })
  end

  # The parameters of the StartReceiving that actually went out.
  defp await_start_receiving do
    assert_receive {:jsr309_call, "EndpointStartReceiving", params}, 1_000
    params
  end

  describe "the profile a leg asks for" do
    test "a v6 peer reached on our v6 address is placed on publicv6" do
      conn = start_conn(both_families(), media: :audio, local_ip: @v6_local)
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("2001:db8:aa::5"))

      # 6th and last, with the offer struct present so the position is reachable
      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv6"] = await_start_receiving()
    end

    test "a v4 peer is placed on publicv4 even when we were reached on v6" do
      # The offer is the permission and the local address only reorders inside it:
      # announcing v6 to a peer that offered none would be media sent nowhere.
      conn = start_conn(both_families(), media: :audio, local_ip: @v6_local)
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("198.51.100.4"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv4"] = await_start_receiving()
    end

    test "StartSending repeats the profile StartReceiving fixed, 7th" do
      conn = start_conn(both_families(), media: :audio, local_ip: @v6_local)
      {:ok, _offer} = Mendooze.get_local_offer(conn)
      :ok = Mendooze.set_remote_answer(conn, offer("2001:db8:aa::5"))

      assert_receive {:jsr309_call, "EndpointStartSending", params}, 1_000
      assert [3, 4, 0, _ip, _port, _send_map, "publicv6"] = params
    end

    test "a leg we offer on takes the side of the address the peer reached" do
      # No peer SDP yet, so `local_ip:` is the only thing that speaks.
      conn = start_conn(both_families(), media: :audio, local_ip: @v4_local)
      {:ok, _offer} = Mendooze.get_local_offer(conn)

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv4"] = await_start_receiving()
    end
  end

  describe "no profile is asked for" do
    test "a server that does not carry the notion gets the call it always got" do
      conn = start_conn(nil, media: :audio, local_ip: @v6_local)
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("2001:db8:aa::5"))

      # Four parameters, byte-for-byte the call a controller that never heard of
      # profiles makes — no empty offer struct bolted on to reach a 6th.
      assert [3, 4, 0, rtp_map] = await_start_receiving()
      assert is_map(rtp_map)
    end

    test "a leg with no local address and no peer address asks for nothing" do
      conn = start_conn(both_families(), media: :audio)
      {:ok, _offer} = Mendooze.get_local_offer(conn)

      assert [3, 4, 0, _rtp_map] = await_start_receiving()
    end
  end

  describe "an unavailable profile fails the leg" do
    test "a v6 peer on a v4-only server is refused, never placed on v4" do
      # The fallback would answer 200 with an address the peer has no route to,
      # and nothing would say so until the silence.
      conn = start_conn(v4_only(), media: :audio, local_ip: @v6_local)

      assert {:error, {:profile_unavailable, "publicv6"}} =
               Mendooze.set_remote_offer(conn, offer("2001:db8:aa::5"))

      refute_receive {:jsr309_call, "EndpointStartReceiving", _}, 200
    end
  end
  describe "a leg we place takes the profile of the target it is placed to" do
    test "address_profile: wins, because an outbound leg has no local address" do
      # `local_ip:` says which of ours a peer reached; a leg we place has none.
      # What decides is the callee's interface, which the framework states.
      conn =
        start_conn(both_families(), media: :audio, address_profile: "publicv6")

      {:ok, _offer} = Mendooze.get_local_offer(conn)

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv6"] = await_start_receiving()
    end

    test "a stated profile beats a derivable one" do
      # Both are present, which happens to no real leg, but the precedence has to
      # be stated rather than depend on which clause runs first.
      conn =
        start_conn(both_families(),
          media: :audio,
          local_ip: {192, 0, 2, 7},
          address_profile: "publicv6"
        )

      {:ok, _offer} = Mendooze.get_local_offer(conn)

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv6"] = await_start_receiving()
    end
  end

  describe "one interface, two faces: a 1:1 NAT serving both sides" do
    setup do
      previous = Application.fetch_env(:elixip2, :internal_networks)

      on_exit(fn ->
        case previous do
          {:ok, v} -> Application.put_env(:elixip2, :internal_networks, v)
          :error -> Application.delete_env(:elixip2, :internal_networks)
        end
      end)

      # The node binds 10.0.0.5, NAT'd 1:1 to a public address, and 10/8 is its
      # internal network. Both UAs reach the SAME socket: the NAT rewrote the
      # destination, so `local_ip` is 10.0.0.5 for both and discriminates nothing.
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])
      :ok
    end

    @bound {10, 0, 0, 5}

    test "the UA on the internet is placed on publicv4" do
      conn =
        start_conn(four_profiles(),
          media: :audio,
          local_ip: @bound,
          peer_ip: {198, 51, 100, 7}
        )

      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("198.51.100.7"))

      # The media server then announces its public alias in the `c=` line.
      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv4"] = await_start_receiving()
    end

    test "the UA in the private network is placed on internalv4" do
      conn =
        start_conn(four_profiles(),
          media: :audio,
          local_ip: @bound,
          peer_ip: {10, 0, 0, 42}
        )

      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("10.0.0.42"))

      # Same socket, same local_ip, other side — and the private address is kept.
      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "internalv4"] = await_start_receiving()
    end

    test "without the peer's address the local one decides, as before" do
      # A transport that reported no peer, or a leg we placed: the fallback is what
      # the side was derived from before a peer address was carried at all.
      conn = start_conn(four_profiles(), media: :audio, local_ip: @bound)
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("198.51.100.7"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "internalv4"] = await_start_receiving()
    end

    test "the family still comes from OUR address, the side from the peer's" do
      # A v6 peer on a v6 listener of the internal network: neither half decides
      # the other.
      Application.put_env(:elixip2, :internal_networks, [{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}])

      conn =
        start_conn(four_profiles(),
          media: :audio,
          local_ip: {0xFD00, 0, 0, 0, 0, 0, 0, 5},
          peer_ip: {0xFD00, 0, 0, 0, 0, 0, 0, 42}
        )

      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("fd00::42"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "internalv6"] = await_start_receiving()
    end
  end

  describe "the side comes from the local address this peer reached" do
    setup do
      previous = Application.fetch_env(:elixip2, :internal_networks)

      on_exit(fn ->
        case previous do
          {:ok, v} -> Application.put_env(:elixip2, :internal_networks, v)
          :error -> Application.delete_env(:elixip2, :internal_networks)
        end
      end)

      :ok
    end

    test "a peer that reached our internal address is placed on internalv4" do
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])

      conn = start_conn(four_profiles(), media: :audio, local_ip: {10, 20, 30, 40})
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("10.20.30.99"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "internalv4"] = await_start_receiving()
    end

    test "the same peer is public once no listener declares that network" do
      Application.delete_env(:elixip2, :internal_networks)

      conn = start_conn(four_profiles(), media: :audio, local_ip: {10, 20, 30, 40})
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("10.20.30.99"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "publicv4"] = await_start_receiving()
    end

    test "the side is ours, the family is the peer's" do
      # An internal listener reached by a v6 peer: the side comes from our address,
      # the family from the offer. Neither half decides the other.
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])

      conn = start_conn(four_profiles(), media: :audio, local_ip: {10, 20, 30, 40})
      {:ok, _answer} = Mendooze.set_remote_offer(conn, offer("2001:db8:aa::5"))

      assert [3, 4, 0, _rtp_map, %{"fmtp" => _}, "internalv6"] = await_start_receiving()
    end
  end
end
