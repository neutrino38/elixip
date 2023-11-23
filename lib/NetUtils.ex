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
#
#  Extract all IP addresses recursively and return them as a list
#  Apply a filter

  defp get_if_addrs_from_ifinfos(ifinfolist, iplist, filters) when is_list(ifinfolist) do
    # If a single filter is passed as arg, refomat it as a list
    filters = if is_list(filters) do
      filters
    else
      [ filters ]
    end

    # Find the first address in the list
    new_iplist = case List.keyfind(ifinfolist, :addr, 0) do
      { :addr, { 127, 0, 0, 1 } } ->
        if :ipv4 in filters and :loopback in filters do
          [ { 127, 0, 0, 1 } | iplist ]
        else
          iplist
        end

      { :addr, { a, b, c, d } } ->
        if :ipv4 in filters do
          [ { a, b, c, d } | iplist ]
        else
          iplist
        end

      { :addr, {0, 0, 0, 0, 0, 0, 0, 1} }  ->
        if :ipv6 in filters and :loopback in filters do
          [ {0, 0, 0, 0, 0, 0, 0, 1} | iplist ]
        else
          iplist
        end

      { :addr, { a, b, c, d, e, f, g, h } } ->
        if :ipv6 in filters and :loopback in filters do
          [ { a, b, c, d, e, f, g, h } | iplist ]
        else
          iplist
        end

      nil -> nil

      _ -> iplist

    end

    if is_nil(new_iplist) do
      # No more addresses in the list
      iplist
    else
      # Process the rest recursively
      get_if_addrs_from_ifinfos(
        List.keydelete( ifinfolist, :addr, 0),
        new_iplist, filters)
    end
  end

  @doc "Get local IP addresses excluding loopback"
  def get_local_ips(filters) do
    { :ok, iflist } = :inet.getifaddrs()

    #Filter the interface list to include only up and running interfaces
    iflist = Enum.filter( iflist, fn { _ifname, ifinfolist } ->
      case List.keyfind(ifinfolist, :flags, 0) do
        { :flags, flaglist } ->
          :up in flaglist and :running in flaglist and :broadcast not in flaglist

        nil ->
          false
      end
    end)

    Enum.reduce(iflist, [], fn { _ifname, ifinfolist }, acc ->
      Enum.concat(acc, get_if_addrs_from_ifinfos(ifinfolist, [], filters))
    end)
  end

  def get_local_ipv4() do
    hd(SIP.NetUtils.get_local_ips( [ :ipv4 ])) |> :inet.ntoa( ) |> List.to_string()
  end
end
