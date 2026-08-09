defmodule SIP.Test.ResolverSrv do
  @moduledoc """
  SRV ordering (RFC 2782), tested where all the logic is: `order_srv/1` is pure,
  so none of this needs a DNS server — which is what made the ordering
  untestable before, and untested.

  Records come in as `:inet_res` hands them over: `{priority, weight, port,
  target}`.
  """
  use ExUnit.Case, async: true

  alias SIP.Resolver

  defp names(ordered), do: Enum.map(ordered, fn {_port, target} -> target end)

  describe "order_srv/1 — priorities" do
    test "lowest priority first, whatever order they arrive in" do
      records = [
        {20, 10, 5060, ~c"backup.example.com"},
        {10, 10, 5060, ~c"primary.example.com"},
        {30, 10, 5060, ~c"last.example.com"}
      ]

      assert names(Resolver.order_srv(records)) ==
               ["primary.example.com", "backup.example.com", "last.example.com"]
    end

    test "the port travels with its target" do
      records = [{10, 0, 5061, ~c"tls.example.com"}, {20, 0, 5060, ~c"udp.example.com"}]

      assert Resolver.order_srv(records) == [
               {5061, "tls.example.com"},
               {5060, "udp.example.com"}
             ]
    end

    test "an empty record set orders to nothing" do
      assert Resolver.order_srv([]) == []
    end
  end

  # The bug that made SRV failover impossible: the group was drawn ONCE and the
  # rest of it thrown away, so a failover had nowhere to go but the next
  # priority — skipping every other host the operator published at this one.
  describe "order_srv/1 — within one priority" do
    test "every member of a group is ordered, not one elected" do
      records = [
        {10, 60, 5060, ~c"a.example.com"},
        {10, 30, 5060, ~c"b.example.com"},
        {10, 10, 5060, ~c"c.example.com"}
      ]

      ordered = names(Resolver.order_srv(records))

      assert length(ordered) == 3
      assert Enum.sort(ordered) == ["a.example.com", "b.example.com", "c.example.com"]
    end

    test "a group is exhausted before the next priority is reached" do
      records = [
        {10, 10, 5060, ~c"a.example.com"},
        {10, 10, 5060, ~c"b.example.com"},
        {20, 10, 5060, ~c"z.example.com"}
      ]

      assert ["z.example.com"] == Enum.drop(names(Resolver.order_srv(records)), 2)
    end

    # Weight 0 is legal and means "no preference" — an operator that does not
    # load-balance publishes nothing else. It used to reach :rand.uniform(0),
    # which raises, so such a record set took the resolver down.
    test "a group of all-zero weights is ordered rather than fatal" do
      records = [
        {10, 0, 5060, ~c"a.example.com"},
        {10, 0, 5060, ~c"b.example.com"},
        {10, 0, 5060, ~c"c.example.com"}
      ]

      ordered = names(Resolver.order_srv(records))
      assert Enum.sort(ordered) == ["a.example.com", "b.example.com", "c.example.com"]
    end

    test "a single record needs no drawing at all" do
      assert Resolver.order_srv([{0, 5, 5060, ~c"only.example.com"}]) ==
               [{5060, "only.example.com"}]
    end

    # Not a distribution proof — a statistical smoke test with room to spare, so
    # it says "the weight is being used" without becoming a flaky test.
    test "weight decides who tends to come first" do
      records = [
        {10, 100, 5060, ~c"heavy.example.com"},
        {10, 1, 5060, ~c"light.example.com"}
      ]

      heavy_first =
        Enum.count(1..1_000, fn _ ->
          hd(names(Resolver.order_srv(records))) == "heavy.example.com"
        end)

      assert heavy_first > 800
      # …and the light one is not shut out, which is the point of the RFC's
      # running-sum draw rather than a plain sort.
      assert heavy_first < 1_000
    end
  end
end
