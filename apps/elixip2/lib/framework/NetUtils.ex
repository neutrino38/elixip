defmodule SIP.NetUtils do
  @moduledoc "Various net utils to"

  require Jason
  import Bitwise

  @doc "Create a network address, given an IP and an network length"
  def cidr_network({i1, i2, i3, i4}, bits) when is_integer(bits) and bits <= 32 do
    zeroBits = 8 - rem(bits, 8)
    last = (0xff >>> zeroBits) <<< zeroBits

    case div(bits, 8) do
        0 ->
            {band(i1,last), 0, 0, 0};
        1 ->
            {i1, band(i2, last), 0, 0};
        2 ->
            {i1, i2, band(i3, last), 0};
        3 ->
            {i1, i2, i3, band(i3, last)};
        4 ->
            {i1, i2, i3, i4}
    end
  end

  # IPV6 version
  def cidr_network({i1, i2, i3, i4, i5, i6, i7, i8}, bits) when is_integer(bits) and bits <= 128 do
    zeroBits = 16 - rem(bits, 16)
    last = (0xffff >>> zeroBits) <<< zeroBits

    case div(bits, 16) do
        0 ->
            {band(i1,last), 0, 0, 0, 0, 0, 0 ,0};
        1 ->
            {i1, band(i2, last), 0, 0, 0, 0, 0 ,0};
        2 ->
            {i1, i2, band(i3, last), 0, 0, 0, 0 ,0};
        3 ->
            {i1, i2, i3, band(i4, last),  0, 0, 0 ,0};
        4 ->
            {i1, i2, i3, i4, band(i5, last), 0, 0, 0}
        5 ->
            {i1, i2, i3, i4, i5, band(i6, last), 0, 0}
        6 ->
            {i1, i2, i3, i4, i5, i6, band(i7, last), 0}
        7 ->
            {i1, i2, i3, i4, i5, i6, i7, band(i8, last)}
        8 ->
            {i1, i2, i3, i4, i5, i6, i7, band(i8, last)}

    end
  end


  def cidr_netmask({_i1, _i2, _i3, _i4}, bits) when is_integer(bits) and bits <= 32 do
    zero_bits = 8 - rem(bits, 8)
    last = Bitwise.bsl(0xff, zero_bits) |>  Bitwise.band(0xFF)

    case div(bits, 8) do
      0 ->
        {last, 0, 0, 0}
      1 ->
        {0xff, last, 0, 0}
      2 ->
        {0xff, 0xff, last, 0}
      3 ->
        {0xff, 0xff, 0xff, last}
      4 ->
        {0xff, 0xff, 0xff, 0xff}
    end
  end

  def cidr_netmask({_i1, _i2, _i3, _i4,_i5, _i6, _i7, _i8}, bits) when is_integer(bits) and bits <= 128 do
    zero_bits = 16 - rem(bits, 16)
    last = Bitwise.bsl(0xffff, zero_bits) |>  Bitwise.band(0xFFFF)

    case div(bits, 16) do
      0 ->
        {last, 0, 0, 0, 0, 0, 0, 0}
      1 ->
        {0xffff, last, 0, 0, 0, 0, 0, 0}
      2 ->
        {0xffff, 0xffff, last, 0, 0, 0, 0, 0}
      3 ->
        {0xffff, 0xffff, 0xffff, last, 0, 0, 0, 0}
      4 ->
        {0xffff, 0xffff, 0xffff, 0xffff, last, 0, 0, 0}
      5 ->
        {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, last, 0, 0}
      6 ->
        {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, last, 0}
      7 ->
        {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, last}
      8 ->
        {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}
    end
  end

  # Get the IP routes from the OS (here windows)
  @spec get_ip_routes(:win32) :: {:error, Jason.DecodeError.t()} | {:ok, any()}
  def get_ip_routes( :win32 ) do
    route_cmd = ~c"powershell -Command \"Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric | ConvertTo-Json\""
    routes_str = List.to_string(:os.cmd(route_cmd))
    { :ok, routes } = Jason.decode(routes_str)
    routes = Enum.map(routes, fn r ->
      [ prefaddr, masklen ] = String.split(r["DestinationPrefix"], "/")
      { :ok, prefaddr } = :inet.parse_address(String.to_charlist(prefaddr))
      { :ok, nexthop }  = :inet.parse_address(String.to_charlist(r["NextHop"]))

      { prefaddr, String.to_integer(masklen), nexthop, r["RouteMetric"] }
    end)

    { :ok, Enum.uniq(routes) }
  end

#  Format of interface info list :
#  [
#    flags: [:up, :running],
#    addr: {10754, 33856, 17729, 52593, 43051, 16384, 51495, 58403},
#    netmask: {65535, 65535, 65535, 65535, 0, 0, 0, 0},
#    addr: {10754, 33856, 17729, 52593, 23715, 41032, 27665, 44847},
#    netmask: {65535, 65535, 65535, 65535, 0, 0, 0, 0},
#    addr: {65152, 0, 0, 0, 19775, 10967, 53520, 7709},
#    netmask: {65535, 65535, 65535, 65535, 0, 0, 0, 0},
#    addr: {192, 168, 255, 219},
#    netmask: {255, 255, 255, 0},
#    hwaddr: [240, 158, 74, 220, 237, 58]
#  ]

  @doc """
  The family of an IP address tuple: `:ipv4`, `:ipv6`, or `nil` for anything
  else — a `:all` wildcard, a hostname, `nil` itself.

  A caller that has an address does not configure its family: it reads it here.
  """
  @spec address_family(term()) :: :ipv4 | :ipv6 | nil
  def address_family({_, _, _, _}), do: :ipv4
  def address_family({_, _, _, _, _, _, _, _}), do: :ipv6
  def address_family(_), do: nil

  @doc """
  The scope of an IP address: `:loopback`, `:link_local`, `:private` or
  `:global`.

  This is the single place a scope is recognised. `:private` reads RFC 1918 for
  IPv4 and RFC 4193 unique local addresses (`fc00::/7`) for IPv6: reachable
  inside one site, not from outside it.

  The distinction is not cosmetic. A link-local address does not come back: it
  needs a zone identifier no peer can use, so writing one in a Contact, a Via
  or an SDP `c=` line advertises an address nothing can reach. On a development
  machine `fe80::` is often the only IPv6 address an interface carries, which is
  exactly when a naive selection picks it.
  """
  @spec address_scope(tuple()) :: :loopback | :link_local | :private | :global | nil
  def address_scope({127, _, _, _}), do: :loopback
  def address_scope({169, 254, _, _}), do: :link_local
  def address_scope({10, _, _, _}), do: :private
  def address_scope({172, b2, _, _}) when b2 >= 16 and b2 <= 31, do: :private
  def address_scope({192, 168, _, _}), do: :private
  def address_scope({_, _, _, _}), do: :global

  def address_scope({0, 0, 0, 0, 0, 0, 0, 1}), do: :loopback
  # fe80::/10 — the top ten bits are 1111 1110 10
  def address_scope({g1, _, _, _, _, _, _, _}) when band(g1, 0xFFC0) == 0xFE80,
    do: :link_local

  # fc00::/7, of which RFC 4193 defines fd00::/8
  def address_scope({g1, _, _, _, _, _, _, _}) when band(g1, 0xFE00) == 0xFC00,
    do: :private

  def address_scope({_, _, _, _, _, _, _, _}), do: :global
  def address_scope(_), do: nil

  # IPv6 before IPv4, and a routable address before a restricted one, so that
  # `hd/1` on the result is a defensible choice rather than the order in which
  # the OS happens to enumerate its interfaces.
  @family_rank %{ipv6: 0, ipv4: 1}
  @scope_rank %{global: 0, private: 1, link_local: 2, loopback: 3}

  @doc """
  Local IP addresses of the requested families, most advertisable first.

  `filters` names the families to return — `:ipv4`, `:ipv6`, or both — and
  admits the scopes that are excluded by default: `:loopback` and
  `:link_local`. Global and private addresses are always returned. Asking for
  no family returns an empty list.

  The result is ordered, never enumeration-dependent, so `hd/1` on it is a
  decision: IPv6 before IPv4, and within a family a routable address before a
  restricted one. A caller that has already decided its family asks for that one
  only; `preferred_family/0` is the caller that has not.
  """
  @spec get_local_ips([:ipv4 | :ipv6 | :loopback | :link_local] | atom()) :: [tuple()]
  def get_local_ips(filters) do
    filters = if is_list(filters), do: filters, else: [filters]
    families = Enum.filter([:ipv6, :ipv4], &(&1 in filters))
    scopes = [:global, :private] ++ Enum.filter([:link_local, :loopback], &(&1 in filters))

    {:ok, iflist} = :inet.getifaddrs()

    iflist
    |> Enum.filter(fn {_ifname, ifinfolist} ->
      case List.keyfind(ifinfolist, :flags, 0) do
        {:flags, flaglist} -> :up in flaglist and :running in flaglist
        nil -> false
      end
    end)
    |> Enum.flat_map(fn {_ifname, ifinfolist} -> for {:addr, addr} <- ifinfolist, do: addr end)
    |> Enum.filter(&(address_family(&1) in families and address_scope(&1) in scopes))
    |> Enum.sort_by(&{@family_rank[address_family(&1)], @scope_rank[address_scope(&1)]})
  end

  @doc """
  The address family this node binds and dials — `:ipv6` or `:ipv4`.

  The node's **primary** UDP socket answers it: `:udp_local_addr` is the address
  of the first `udp` listener, so its family is the node's. Without one it is
  `:udp_family`, which the listener supervisor sets from a wildcard entry and
  which defaults to `:ipv4`.

  This orders the two queries of a name resolution — which record is asked for
  first — and nothing else. It does not decide what a datagram may leave by: a
  node binds one UDP socket per family (step 4 of
  docs/design/multi-interface.md), and `SIP.Transport.Selector` picks between
  them on the family of the **resolved destination**, not on this. So a name
  that only has an AAAA record is reached from a node whose primary socket is
  IPv4; the order cost one extra query, not the call.

  A destination that is still a host name when a transport instance has to be
  named has no address to read, and falls back here.
  """
  @spec preferred_family() :: :ipv4 | :ipv6
  def preferred_family() do
    address_family(Application.get_env(:elixip2, :udp_local_addr)) ||
      Application.get_env(:elixip2, :udp_family, :ipv4)
  end

  def get_local_ipv4() do
    hd(SIP.NetUtils.get_local_ips( [ :ipv4 ])) |> :inet.ntoa( ) |> List.to_string()
  end

  @doc "Convert an IP address into a string. Wrapper for the erlang inet module ntoa() function"
  @spec ip2string(
          {byte(), byte(), byte(), byte()}
          | {char(), char(), char(), char(), char(), char(), char(), char()}
        ) :: binary() | {:error, :einval}
  def ip2string(ipaddr) when is_tuple(ipaddr) do
    ret = :inet.ntoa(ipaddr)
    if is_list(ret) do
      to_string(ret)
    else
      # Error case (:einval)
      ret
    end
  end

  @doc """
  Render an address as the RFC 3261 §25.1 `host` production: an IPv6 literal
  comes out as an `IPv6reference`, inside square brackets; anything else — an
  IPv4 address, a hostname, an already bracketed literal — comes out unchanged.

  The single rendering point for every address that becomes message text: a URI
  host (`SIP.Uri`) and a Via `sent-by` (`SIP.Msg.Ops`). Both used to carry their
  own copy of the tuple-to-string conversion, five in all, and a port appended
  to a bare `2001:db8::1` is a `host:port` no peer can split.
  """
  @spec sip_host(tuple() | binary()) :: binary()
  def sip_host(ipaddr) when is_tuple(ipaddr) and tuple_size(ipaddr) == 8 do
    "[" <> ip2string(ipaddr) <> "]"
  end

  def sip_host(ipaddr) when is_tuple(ipaddr), do: ip2string(ipaddr)

  def sip_host("[" <> _rest = host), do: host

  # Only an IPv6 literal can hold a colon: neither a hostname nor an IPv4 address
  # does, so the colon is what tells this apart without parsing every host name
  # that goes out.
  def sip_host(host) when is_binary(host) do
    if String.contains?(host, ":") and match?({:ok, _addr}, parse_address(host)) do
      "[" <> host <> "]"
    else
      host
    end
  end

  @spec parse_address(binary()) ::
          {:error, :einval}
          | {:ok,
             {byte(), byte(), byte(), byte()}
             | {char(), char(), char(), char(), char(), char(), char(), char()}}
  @doc "parse an IP address expressed as a string."
  def parse_address(ipaddr_str) when is_binary(ipaddr_str) do
    :inet.parse_address(String.to_charlist(ipaddr_str))
  end

  @max_port 65_535
  @free_port_attempts 100

  @doc """
  Pick a random free local port for the given protocol.

  Draws random ports in `min_port..65535` and verifies each candidate by
  binding (then closing) a socket, returning the first available one.
  Note the check is inherently racy: the port could be taken by another
  process between the check and the actual bind.
  """
  @spec pick_free_port(:udp | :tcp, pos_integer()) :: {:ok, :inet.port_number()} | {:error, :nofreeport}
  def pick_free_port(proto, min_port \\ 5000)
      when proto in [:udp, :tcp] and min_port > 0 and min_port <= @max_port do
    pick_free_port(proto, min_port, @free_port_attempts)
  end

  defp pick_free_port(_proto, _min_port, 0), do: {:error, :nofreeport}

  defp pick_free_port(proto, min_port, attempts) do
    port = min_port + :rand.uniform(@max_port - min_port + 1) - 1

    if port_free?(proto, port) do
      {:ok, port}
    else
      pick_free_port(proto, min_port, attempts - 1)
    end
  end

  defp port_free?(:udp, port) do
    case :gen_udp.open(port, []) do
      {:ok, sock} -> :gen_udp.close(sock) == :ok
      {:error, _} -> false
    end
  end

  defp port_free?(:tcp, port) do
    case :gen_tcp.listen(port, reuseaddr: true) do
      {:ok, sock} -> :gen_tcp.close(sock) == :ok
      {:error, _} -> false
    end
  end
end
