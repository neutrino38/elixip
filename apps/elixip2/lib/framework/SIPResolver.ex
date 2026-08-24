defmodule SIP.Resolver do
  @moduledoc "DNS resolver for the SIP stack"
  alias SIP.NetUtils

  require SIP.Uri
  require Logger

  # ── SRV (RFC 2782) ───────────────────────────────────────────────────────────
  #
  # Ordering is kept PURE and public (`order_srv/1`): it is where all the logic
  # is, and testing it must not need a DNS server. The lookup around it does the
  # I/O and nothing else.

  @doc """
  Every destination an SRV record set names, in the order RFC 2782 wants them
  tried: priorities ascending, and within one priority the weighted draw applied
  **until the group is empty** rather than once — the weight orders a group for
  load balancing, it does not elect a single member. A caller that fails over
  therefore has the rest of the group to try before moving to the next priority.

  Takes the records as `:inet_res` returns them, `{priority, weight, port,
  target}`, and gives back `{port, target}` in the order to try.

  Pure: this is the seam that makes SRV testable without a resolver.
  """
  @spec order_srv([{integer(), integer(), integer(), charlist()}]) ::
          [{integer(), String.t()}]
  def order_srv(records) when is_list(records) do
    records
    |> group_by_priority()
    |> Enum.flat_map(fn {_priority, group} -> order_group(group) end)
    |> Enum.map(fn {_prio, _weight, port, target} -> {port, to_string(target)} end)
  end

  # Priorities ascending — the RFC's first ordering key.
  defp group_by_priority(srv_records) do
    srv_records
    |> Enum.group_by(fn {priority, _weight, _port, _target} -> priority end)
    |> Enum.sort_by(fn {priority, _group} -> priority end)
  end

  # RFC 2782 within one priority: weight-0 records are placed FIRST in the
  # running-sum order, which is what leaves them the small chance the algorithm
  # gives them instead of none at all.
  defp order_group(records) do
    {zero, positive} = Enum.split_with(records, fn {_p, w, _po, _t} -> w == 0 end)
    draw_by_weight(zero ++ positive, [])
  end

  defp draw_by_weight([], picked), do: Enum.reverse(picked)

  defp draw_by_weight(records, picked) do
    total = Enum.reduce(records, 0, fn {_p, weight, _po, _t}, sum -> sum + weight end)

    # "a uniform random number between 0 and the sum" — INCLUSIVE of 0, which is
    # how a weight-0 record can be drawn at all. `:rand.uniform/1` gives 1..n and
    # raises outright on 0, so an all-zero group (legal, and what an operator
    # that does not load-balance publishes) used to take the resolver down here.
    random = :rand.uniform(total + 1) - 1

    {record, rest} = take_at_running_sum(records, random)
    draw_by_weight(rest, [record | picked])
  end

  # The first record whose running sum reaches `random`, removed from the list.
  defp take_at_running_sum(records, random), do: take_at_running_sum(records, random, 0, [])

  defp take_at_running_sum([{_p, weight, _po, _t} = record | rest], random, sum, seen) do
    sum = sum + weight

    if sum >= random do
      {record, Enum.reverse(seen) ++ rest}
    else
      take_at_running_sum(rest, random, sum, [record | seen])
    end
  end

  # Unreachable while `random` cannot exceed the total, but a list is a list:
  # answer with what is left rather than raise.
  defp take_at_running_sum([], _random, _sum, seen) do
    case Enum.reverse(seen) do
      [record | rest] -> {record, rest}
      [] -> {nil, []}
    end
  end

  @doc """
  The destinations `_sip._<transport>.<domain>` names, ordered as `order_srv/1`
  says, as URIs still carrying a NAME — resolving all of them up front would be
  DNS traffic for hosts that may never be dialled. `:nosuchname` when the domain
  publishes no SRV record.
  """
  @spec srv_targets(%SIP.Uri{}) :: {:ok, [%SIP.Uri{}]} | :nosuchname
  def srv_targets(uri = %SIP.Uri{}) do
    case srv_lookup(uri) do
      [] ->
        :nosuchname

      records when is_list(records) ->
        targets =
          for {port, target} <- order_srv(records),
              do: %SIP.Uri{uri | domain: target, port: port}

        {:ok, targets}
    end
  end

  defp srv_lookup(uri = %SIP.Uri{}) do
    transport_str = SIP.Uri.get_transport(uri) |> String.downcase()
    name = "_sip._" <> transport_str <> "." <> uri.domain

    case :inet_res.lookup(String.to_charlist(name), :in, :srv, nameserver_options()) do
      [] ->
        Logger.debug(module: __MODULE__, message: "SRV resolution for #{name} returns no records")
        []

      results when is_list(results) ->
        results
    end
  end

  @doc """
  The `idx`-th SRV destination of `uri`, resolved to `{ip, port}`.

  `idx` counts **destinations**, not priority groups: the flattened RFC 2782
  order of `order_srv/1`, so walking it is a failover list. Past the end it
  answers `:nosuchname` — "nothing more to try" — which is what a caller looping
  over it needs.

  (It used to be a priority-group index, and only ever answered for group 0: the
  head read `prio_idx = 0`, a pattern matching nothing else, so every other index
  raised. Past the end it raised too, on `Enum.at` returning nil.)
  """
  @spec resolve_srv_multiple(%SIP.Uri{}, non_neg_integer()) ::
          {tuple(), integer()} | {:error, any()} | :nosuchname | :nxdomain
  def resolve_srv_multiple(uri = %SIP.Uri{}, idx \\ 0) when is_integer(idx) and idx >= 0 do
    with {:ok, targets} <- srv_targets(uri),
         target when not is_nil(target) <- Enum.at(targets, idx) do
      resolve(target, false)
    else
      _ -> :nosuchname
    end
  end

  def resolve(uri = %SIP.Uri{}, _usesrv) when uri.destip != nil and uri.destport != 0 do
    {uri.destip, uri.destport}
  end

  def resolve(uri = %SIP.Uri{}, true) do
    case resolve_srv_multiple(uri, 0) do
      # SRV resolution successful but host returned in SRV record could not be resolved
      {:error, err} -> {:error, err}
      # SRV resolution successful and subsequent A resolution too
      {ip, port} -> {ip, port}
      # No SRV record. Try direct A / AAAA resolution
      :nosuchname -> resolve(uri, false)
    end
  end

  # The family this node can source from is asked for FIRST, and the other one
  # only when that record does not exist. Asking for A unconditionally sent an
  # IPv6-only node towards an IPv4 address it has no route to, on every
  # dual-stack name. `:nxdomain` — the bare atom, as callers match it — means
  # neither family answered.
  def resolve(uri = %SIP.Uri{}, false) do
    [first, second] = family_order(NetUtils.preferred_family())

    case getaddr(uri, first) do
      :nxdomain -> getaddr(uri, second)
      result -> result
    end
  end

  defp family_order(:ipv6), do: [:inet6, :inet]
  defp family_order(_family), do: [:inet, :inet6]

  defp getaddr(uri = %SIP.Uri{}, family) do
    case :inet.getaddr(String.to_charlist(uri.domain), family) do
      {:ok, ip} -> {ip, uri.port}
      {:error, :nxdomain} -> :nxdomain
      {:error, err} -> {:error, err}
    end
  end

  # The system resolver by default: `:inet_res` reads /etc/resolv.conf, so an
  # IPv6-only node reaches its DNS server over IPv6 without being told to. The
  # `:nameserver` key overrides it — `get_dns_default_dns_server/0` sets it — and
  # it takes an IPv6 server too. It used to be forced to 8.8.8.8, which a node
  # with no IPv4 route cannot reach at all.
  defp nameserver_options() do
    case Application.fetch_env(:elixip2, :nameserver) do
      {:ok, ip} when is_tuple(ip) and (tuple_size(ip) == 4 or tuple_size(ip) == 8) ->
        [alt_nameservers: [{ip, 53}]]

      _ ->
        []
    end
  end

  def resolve_and_add_dest(uri = %SIP.Uri{}) do
    {desturi, usesrv} =
      try do
        {Application.fetch_env!(:elixip2, :proxyuri),
         Application.fetch_env!(:elixip2, :proxyusesrv)}
      rescue
        ArgumentError ->
          # No SIP proxy configured. Using R-URI domain
          Logger.debug(module: __MODULE__, message: "no SIP proxy configured")
          {uri, false}
      end

    transport = SIP.Uri.get_transport(desturi)

    if transport in ["WS", "WSS"] do
      # We NEED to pass the name when using WSS or WS protocol
      Logger.debug(
        module: __MODULE__,
        message: " #{desturi} uses Websocket transport. Resolution will be done by socket layer"
      )

      %SIP.Uri{uri | destip: desturi.domain, destport: desturi.port, destproto: transport}
    else
      # For UDP, TCP, TLS use regular DNS resolution
      Logger.debug(module: __MODULE__, message: "resolving #{desturi} with trysrv=#{usesrv}")

      case resolve(desturi, usesrv) do
        {:error, err} ->
          Logger.debug(module: __MODULE__, message: "resolution error #{err}")
          :error

        :nxdomain ->
          Logger.debug(module: __MODULE__, message: "resolution failed")
          :nxdomain

        {ip, port} ->
          %SIP.Uri{uri | destip: ip, destport: port, destproto: transport}
      end
    end
  end

  @doc """
  Read the first nameserver the host is configured with into `:nameserver`, and
  give back the address as a string (`nil` when there is none to read).

  An unreadable or unparseable one leaves `:nameserver` unset, so `:inet_res`
  falls back on the system resolver instead of the node failing to boot. It used
  to be a bare match: a resolv.conf with no `nameserver` line, or one carrying a
  zone identifier (`fe80::1%eth0`, which `SIP.NetUtils.parse_address/1` refuses),
  crashed the boot of a node whose DNS was otherwise fine.
  """
  @spec get_dns_default_dns_server() :: binary() | nil
  def get_dns_default_dns_server() do
    dns_str =
      case System.get_env("OS") do
        "Windows_NT" -> windows_dns_server()
        _ -> linux_dns_server()
      end

    case dns_str && NetUtils.parse_address(dns_str) do
      {:ok, dns_addr} ->
        Logger.debug(module: __MODULE__, message: "DNS server that will be used: #{dns_str}")
        Application.put_env(:elixip2, :nameserver, dns_addr)

      _ ->
        Logger.notice(
          module: __MODULE__,
          message: "no usable nameserver found (#{inspect(dns_str)}); using the system resolver"
        )
    end

    dns_str
  end

  defp windows_dns_server() do
    getipcmd =
      ~c"powershell -Command \"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Get-DnsClientServerAddress -InterfaceAlias $_.Name } | Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique
\""

    :os.cmd(getipcmd) |> List.to_string() |> String.split("\r\n") |> hd()
  end

  defp linux_dns_server() do
    with {:ok, content} <- File.read("/etc/resolv.conf"),
         line when is_binary(line) <-
           content |> String.split("\n") |> Enum.find(&String.starts_with?(&1, "nameserver")) do
      line |> String.trim() |> String.split(" ") |> List.last()
    else
      _ -> nil
    end
  end
end
