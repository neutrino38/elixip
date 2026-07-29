defmodule SIP.Resolver do
  @moduledoc "DNS resolver for the SIP stack"
alias SIP.NetUtils

  require SIP.Uri
  require Logger

  # Grouper par priorité
  defp group_by_priority(srv_records) do
    srv_records
    |> Enum.group_by(fn {priority, _weight, _port, _target} -> priority end)
    |> Enum.sort_by(fn {priority, _group} -> priority end) # Priorité croissante
  end

   # Sélection aléatoire pondérée parmi les enregistrements d'une même priorité
   defp weighted_random_selection(records) do
    total_weight = Enum.reduce(records, 0, fn {_priority, weight, _port, _target}, acc -> acc + weight end)

    random_number = :rand.uniform(total_weight)

    Enum.reduce_while(records, 0, fn {_priority, weight, _port, _target} = record, acc ->
      cumulative_weight = acc + weight

      if random_number <= cumulative_weight do
        {:halt, [record]}
      else
        {:cont, cumulative_weight}
      end
    end)
  end

  @doc "Perform an SIP srv resolution"
  def resolve_srv_multiple(uri = %SIP.Uri{}, prio_idx = 0) do
    transport_str = SIP.Uri.get_transport(uri) |> String.downcase()
    name = "_sip._" <> transport_str <> "." <> uri.domain

    # We need to specify a DNS server otherwise it does not work
    nameserver = case Application.fetch_env(:elixip2, :nameserver) do
      { :ok, { x, y, z, t }} -> { x, y, z, t }
      :error -> {8,8,8,8}
    end

    case :inet_res.lookup(String.to_charlist(name), :in, :srv,  [alt_nameservers: [ { nameserver, 53} ]]) do
      [] ->
        Logger.debug(module: __MODULE__, message: "SRV resolution for #{name} returns no records")
        :nosuchname

      results when is_list(results) ->
        sorted_groups = group_by_priority(results)

        # Get the selected group of answers according to the specified prio index
        { _prio, selected_group } = Enum.at(sorted_groups, prio_idx)
        if is_list(selected_group) do
          [ { _weigh, _prio, port, target } ] =  weighted_random_selection(selected_group)
          resolve(%SIP.Uri{ uri | domain: to_string(target), port: port }, false)
        else
          nb_groups = length(sorted_groups)
          Logger.debug(module: __MODULE__, message: "SRV resolution for #{name} returned #{nb_groups} priorities")
          Logger.debug(module: __MODULE__, message: "but specified priority index (#{prio_idx}) is bigger than nb of priorities")
          :nosuchname
        end
    end
  end



  def resolve(uri = %SIP.Uri{}, _usesrv) when uri.destip != nil and uri.destport != 0 do
    { uri.destip, uri.destport }
  end

  def resolve(uri = %SIP.Uri{}, true) do
    case resolve_srv_multiple(uri, 0) do
      # SRV resolution successful but host returned in SRV record could not be resolved
      {:error, err } -> {:error, err }

      # SRV resolution successful and subsequent A resolution too
      { ip, port } -> { ip, port }

      # No SRV record. Try direct A / AAAA resolution
      :nosuchname -> resolve( uri, false )
    end
  end

  def resolve(uri = %SIP.Uri{}, false) do
    # Try with IPV4
    case :inet.getaddr(String.to_charlist(uri.domain), :inet) do
      { :ok, ip } -> { ip, uri.port }
      { :error, :nxdomain } -> resolve_v6(uri) # Try with IPV6
      { :error, err } -> {:error, err }
    end
  end

  defp resolve_v6(uri = %SIP.Uri{}) do
    case :inet.getaddr(String.to_charlist(uri.domain), :inet6) do
      { :ok, ip } -> { ip, uri.port }
      { :error, :nxdomain } -> :nxdomain
      { :error, err } -> {:error, err }
    end
  end

  def resolve_and_add_dest(uri = %SIP.Uri{}) do
    { desturi, usesrv } = try do
      { Application.fetch_env!(:elixip2, :proxyuri), Application.fetch_env!(:elixip2, :proxyusesrv ) }
    rescue
      ArgumentError ->
        # No SIP proxy configured. Using R-URI domain
        Logger.debug(module: __MODULE__, message: "no SIP proxy configured");
        { uri, false }
    end
    transport = SIP.Uri.get_transport(desturi)
    if transport in [ "WS", "WSS"] do
      # We NEED to pass the name when using WSS or WS protocol
      Logger.debug(module: __MODULE__, message: " #{desturi} uses Websocket transport. Resolution will be done by socket layer");
      %SIP.Uri{ uri | destip: desturi.domain, destport: desturi.port, destproto: transport }
    else
      # For UDP, TCP, TLS use regular DNS resolution
      Logger.debug(module: __MODULE__, message: "resolving #{desturi} with trysrv=#{usesrv}");
      case resolve(desturi, usesrv) do
        { :error, err } ->
          Logger.debug(module: __MODULE__, message: "resolution error #{err}")
          :error

        :nxdomain ->
          Logger.debug(module: __MODULE__, message: "resolution failed")
          :nxdomain
        { ip, port } -> %SIP.Uri{ uri | destip: ip, destport: port, destproto: transport }
      end
    end
  end

  def get_dns_default_dns_server() do
    dns_str = case System.get_env("OS") do
      "Windows_NT" ->
        getipcmd = ~c"powershell -Command \"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Get-DnsClientServerAddress -InterfaceAlias $_.Name } | Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique
\""
        :os.cmd(getipcmd) |> List.to_string() |> String.split("\r\n") |> hd()

      # Assume linux
      _ ->
        case File.read("/etc/resolv.conf") do
          { :ok, content } ->
            String.split(content, "\n") |>
            Enum.find(&String.starts_with?(&1, "nameserver")) |>
            String.trim() |> String.split(" ") |>
            List.last()

          { :error, _code } -> nil
        end
    end

    Logger.debug(module: __MODULE__, message: "DNS server that will be used: #{dns_str}");
    { :ok, dns_addr } = NetUtils.parse_address(dns_str)
    Application.put_env(:elixip2, :nameserver, dns_addr)
    dns_str
  end
end
