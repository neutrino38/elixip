defmodule SIP.Test.NetSide do
  @moduledoc """
  Step 5 of `docs/design/multi-interface.md`, phase 2: which side of this node's
  network a resolved address sits on.

  Not `async`: `:internal_networks` is node-wide.
  """
  use ExUnit.Case, async: false

  alias SIP.NetUtils, as: N

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

  describe "in_prefix?/2" do
    test "an address inside its prefix, and one just outside" do
      assert N.in_prefix?({10, 1, 2, 3}, {{10, 0, 0, 0}, 8})
      refute N.in_prefix?({11, 1, 2, 3}, {{10, 0, 0, 0}, 8})

      assert N.in_prefix?({172, 21, 105, 71}, {{172, 21, 0, 0}, 16})
      refute N.in_prefix?({172, 22, 0, 1}, {{172, 21, 0, 0}, 16})

      # A length that is not a byte boundary, which a /8 or /16 would not catch.
      assert N.in_prefix?({10, 0, 0, 5}, {{10, 0, 0, 0}, 24})
      refute N.in_prefix?({10, 0, 1, 5}, {{10, 0, 0, 0}, 24})
      assert N.in_prefix?({10, 0, 0, 200}, {{10, 0, 0, 128}, 25})
      refute N.in_prefix?({10, 0, 0, 100}, {{10, 0, 0, 128}, 25})
    end

    test "IPv6, on group boundaries and inside a group" do
      db8 = {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}

      assert N.in_prefix?({0x2001, 0xDB8, 0, 0, 0, 0, 0, 5}, {db8, 32})
      refute N.in_prefix?({0x2001, 0xDB9, 0, 0, 0, 0, 0, 5}, {db8, 32})

      # fc00::/7 — seven bits, so the boundary is inside the first group.
      ula = {0xFC00, 0, 0, 0, 0, 0, 0, 0}
      assert N.in_prefix?({0xFD00, 0, 0, 0, 0, 0, 0, 1}, {ula, 7})
      refute N.in_prefix?({0xFE80, 0, 0, 0, 0, 0, 0, 1}, {ula, 7})
    end

    test "a prefix of the other family never matches" do
      # Mapped ::ffff: forms are refused everywhere in this stack, so an IPv4
      # address is not inside an IPv6 prefix and the reverse is not either.
      refute N.in_prefix?({10, 1, 2, 3}, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32})
      refute N.in_prefix?({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, {{10, 0, 0, 0}, 8})
    end

    test "degenerate lengths" do
      assert N.in_prefix?({8, 8, 8, 8}, {{0, 0, 0, 0}, 0})
      assert N.in_prefix?({10, 1, 2, 3}, {{10, 1, 2, 3}, 32})
      refute N.in_prefix?({10, 1, 2, 4}, {{10, 1, 2, 3}, 32})
      # Longer than the family holds: refused rather than crashing.
      refute N.in_prefix?({10, 1, 2, 3}, {{10, 0, 0, 0}, 33})
    end
  end

  describe "attached_prefix/1" do
    test "the subnet of an address this host carries, from its netmask" do
      # Whatever this host is, its loopback is a /8 in IPv4.
      assert {{127, 0, 0, 0}, 8} = N.attached_prefix({127, 0, 0, 1})
    end

    test "an address no interface carries has no attached prefix" do
      refute N.attached_prefix({192, 0, 2, 123})
    end

    test "every address the host advertises has one" do
      for ip <- N.get_local_ips([:ipv4, :ipv6]) do
        assert {network, length} = N.attached_prefix(ip), "no prefix for #{inspect(ip)}"
        assert tuple_size(network) == tuple_size(ip)
        assert length >= 0
        # And the address is in the prefix its own interface states.
        assert N.in_prefix?(ip, {network, length})
      end
    end
  end

  describe "net_side/1" do
    test "a node told nothing has one side, and it is the public one" do
      Application.delete_env(:elixip2, :internal_networks)
      assert N.net_side({10, 1, 2, 3}) == :public

      Application.put_env(:elixip2, :internal_networks, [])
      assert N.net_side({10, 1, 2, 3}) == :public
    end

    test "an address inside a declared network is internal" do
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])

      assert N.net_side({10, 1, 2, 3}) == :internal
      assert N.net_side({8, 8, 8, 8}) == :public
    end

    test "several networks, and both families" do
      Application.put_env(:elixip2, :internal_networks, [
        {{10, 0, 0, 0}, 8},
        {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}
      ])

      assert N.net_side({10, 9, 9, 9}) == :internal
      assert N.net_side({0xFD00, 0, 0, 0, 0, 0, 0, 1}) == :internal
      assert N.net_side({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}) == :public
    end

    test "the RFCs do not decide it — the node's topology does" do
      # address_scope/1 answers a different question: a site can route RFC 1918
      # space it does not consider internal, and an internal network can be
      # globally addressed IPv6.
      Application.put_env(:elixip2, :internal_networks, [
        {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}
      ])

      assert N.address_scope({192, 168, 1, 1}) == :private
      assert N.net_side({192, 168, 1, 1}) == :public

      assert N.address_scope({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}) == :global
      assert N.net_side({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}) == :internal
    end

    test "anything that is not an address is public" do
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])
      assert N.net_side("proxy.example.com") == :public
      assert N.net_side(nil) == :public
    end
  end

  describe "the field on %SIP.Uri{}" do
    test "unclassified by default, and never serialized" do
      {:ok, uri} = SIP.Uri.parse("sip:bob@example.com")
      assert uri.net_side == nil

      # It belongs to the resolved-routing cluster, not to the URI's text.
      marked = %SIP.Uri{uri | destip: {10, 0, 0, 1}, destport: 5060, net_side: :internal}
      assert SIP.Uri.serialize(marked) == SIP.Uri.serialize(uri)
    end
  end
end
