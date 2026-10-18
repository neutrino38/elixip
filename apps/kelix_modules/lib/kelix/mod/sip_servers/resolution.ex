defmodule Kelix.Mod.SipServers.Resolution do
  @moduledoc """
  Where a server's URIs lead: the transport, address and port of each, and how long
  that answer holds (its DNS TTL).

  What `matches_server/2` recognises a request by (source IP and transport, never
  the port) and what a trunk with an `ext_domain` is sent to. A name is resolved
  through SRV when the server asks for it (`use_dns_srv`), else A and AAAA; a
  literal address never expires. A name the DNS does not know but the host does
  (`/etc/hosts`) is resolved by the system with a default lifetime, since the
  file states none.
  """

  alias Kelix.Mod.SipServers.Server

  @typedoc "One place a URI leads to."
  @type address :: {transport :: String.t(), :inet.ip_address(), :inet.port_number()}

  @hosts_file_ttl 300

  @doc """
  `{:ok, %{uri => [address]}, ttl}` — `ttl` in seconds, `:infinity` when every URI
  is a literal address — or `{:error, :nxdomain}` when no URI resolves at all. A URI
  that does not resolve maps to `[]` while another one does.
  """
  @spec resolve(Server.t()) ::
          {:ok, %{String.t() => [address]}, pos_integer() | :infinity} | {:error, term}
  def resolve(%Server{} = server) do
    results =
      for uri <- Server.uris(server), into: %{} do
        {uri, resolve_uri(uri, server.use_dns_srv)}
      end

    if Enum.all?(results, fn {_uri, {addrs, _ttl}} -> addrs == [] end) do
      {:error, :nxdomain}
    else
      ttl = results |> Enum.map(fn {_uri, {_addrs, ttl}} -> ttl end) |> Enum.min()
      {:ok, Map.new(results, fn {uri, {addrs, _ttl}} -> {uri, addrs} end), ttl}
    end
  end

  defp resolve_uri(uri, use_srv) do
    {:ok, parsed} = SIP.Uri.parse(uri)
    transport = SIP.Uri.get_transport(parsed) || "UDP"
    port = SIP.Uri.target_port(parsed)
    host = String.to_charlist(parsed.domain)

    case :inet.parse_address(host) do
      {:ok, ip} ->
        {[{transport, ip, port}], :infinity}

      {:error, _} ->
        srv = if use_srv, do: srv(transport, host), else: []

        case srv do
          [] ->
            {ips, ttl} = addresses(host)
            {for(ip <- ips, do: {transport, ip, port}), ttl}

          records ->
            Enum.reduce(records, {[], :infinity}, fn {target, srv_port, srv_ttl}, {acc, ttl} ->
              {ips, a_ttl} = addresses(target)

              {acc ++ for(ip <- ips, do: {transport, ip, srv_port}),
               Enum.min([ttl, srv_ttl, a_ttl])}
            end)
        end
    end
  end

  # SRV records in RFC 2782 order, each with its TTL.
  defp srv(transport, host) do
    name = ~c"_sip._" ++ String.to_charlist(String.downcase(transport)) ++ ~c"." ++ host

    case :inet_res.resolve(name, :in, :srv) do
      {:ok, msg} ->
        records =
          for rr <- :inet_dns.msg(msg, :anlist), :inet_dns.rr(rr, :type) == :srv do
            {prio, weight, port, target} = :inet_dns.rr(rr, :data)
            {prio, weight, port, target, :inet_dns.rr(rr, :ttl)}
          end

        ordered =
          SIP.Resolver.order_srv(for {p, w, port, t, _ttl} <- records, do: {p, w, port, t})

        for {port, target} <- ordered do
          ttl =
            Enum.find_value(records, fn
              {_p, _w, ^port, ^target, ttl} -> ttl
              _ -> nil
            end)

          {target, port, ttl}
        end

      {:error, _} ->
        []
    end
  end

  # Every A and AAAA address, with the smallest TTL among them.
  defp addresses(host) do
    answers =
      for type <- [:a, :aaaa],
          {:ok, msg} <- [:inet_res.resolve(host, :in, type)],
          rr <- :inet_dns.msg(msg, :anlist),
          :inet_dns.rr(rr, :type) == type,
          do: {:inet_dns.rr(rr, :data), :inet_dns.rr(rr, :ttl)}

    case answers do
      [] ->
        hosts_file(host)

      _ ->
        {Enum.map(answers, &elem(&1, 0)) |> Enum.uniq(),
         answers |> Enum.map(&elem(&1, 1)) |> Enum.min()}
    end
  end

  defp hosts_file(host) do
    ips =
      for family <- [:inet, :inet6],
          {:ok, list} <- [:inet.getaddrs(host, family)],
          ip <- list,
          do: ip

    {Enum.uniq(ips), @hosts_file_ttl}
  end
end
