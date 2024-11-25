defmodule SIP.Resolver do
  @moduledoc "DNS resolver for the SIP stack"

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

    Enum.reduce_while(records, 0, fn {_priority, weight, port, target} = record, acc ->
      cumulative_weight = acc + weight

      if random_number <= cumulative_weight do
        {:halt, [record]}
      else
        {:cont, cumulative_weight}
      end
    end)
  end

  def resolve_srv_multiple(uri = %SIP.Uri{}, prio_idx = 0) do
    transport_str = SIP.Uri.get_transport(uri) |> String.downcase()
    name = "_sip._" <> transport_str <> "." <> uri.domain

    # We need to specify a DNS server otherwise it does not work
    nameserver = Application.fetch_env(:elixip2, :nameserver)
    nameserver = if is_tuple(nameserver), do: nameserver, else: {8,8,8,8}
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


  def resolve(uri = %SIP.Uri{}, true) do
    resolve_srv_multiple(uri, 0)
  end

  def resolve(uri = %SIP.Uri{}, false) do
    # Try with IPV4
    case :inet.getaddr(String.to_charlist(uri.domain), :inet) do
      { :ok, ip } -> { ip, uri.port }
      { :error, :nxdomain } -> resolve_v6(uri) # Try with IPV6
      { :error, err } -> {:error, err }
    end
  end

  def resolve_v6(uri = %SIP.Uri{}) do
    case :inet.getaddr(String.to_charlist(uri.domain), :inet6) do
      { :ok, ip } -> { ip, uri.port }
      { :error, :nxdomain } -> :nxdomain
      { :error, err } -> {:error, err }
    end
  end

end
