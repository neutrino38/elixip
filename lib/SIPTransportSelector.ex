defmodule SIP.Transport.Selector do
	@moduledoc "Selection of transport given a SIP URI"

  require SIP.Uri
  require SIP.Test.Transport.UDPMockup
  require Registry

  @transport_map %{
    "UDP" => SIP.Transport.UDP,
    "TCP" => SIP.Transport.TCP,
    "TLS" => SIP.Transport.TLS,
    "WS" => SIP.Transport.WS,
    "WSS" => SIP.Transport.WSS,
    "SCTP" => nil
  }

  def start() do
    { :ok, _ } = Registry.start_link(keys: :unique, name: SIP.Transport.Registry)
  end

  defp find_or_launch_transport(t_mod, transport_name, destip, port)  do
    reliable = apply(t_mod, :is_reliable, [])
    instance_name = if reliable do
      transport_name <> "_" <> destip <> ":" <> Integer.to_string(port)
    else
      transport_name
    end

    case Registry.lookup(SIP.Transport.Registry, instance_name) do
      [] ->
        # No such instance. Start a new transport
        name = { :via, Registry, {SIP.Transport.Registry, instance_name}}
        GenServer.start(t_mod, { destip, port } , name: name)

      [{ t_pid, _ }] -> { :ok, t_pid }
    end
  end

  # Resolve and select one of the IP
  defp resolve_dest_domain(uri_domain, _trysrv) do
    # To implement
    { :ok, uri_domain }
  end

  @spec select_transport(binary()) :: { atom(), module(), pid() } | atom()
  @doc "Select a transport module an option given a request URI"
  def select_transport(ruri) when is_binary(ruri) do
    case SIP.Uri.parse(ruri) do
      { :ok, parsed_uri } -> select_transport(parsed_uri)
      { errcode, %{} } -> errcode
    end
  end

  @spec select_transport(map()) :: { atom(), module(), pid() } | atom()
  def select_transport(ruri) when is_map(ruri) do

    #Check if this is a unit test. If this is the case use a mockup for transport
    usemockup = case SIP.Uri.get_uri_param(ruri, "unittest") do
      { :nosuchparam, nil } -> false
      { :ok, "1" } -> true
      _ -> false
    end

    # Obtain the transport part from the Request URI
    transport_str = case SIP.Uri.get_uri_param(ruri, "transport") do
      { :nosuchparam, nil } -> "UDP"
      { :ok, value } -> String.upcase(value)
    end

    t_mod = Map.get(@transport_map, transport_str)

    if t_mod != nil do
      # We have a transport module
      # Test if we use the mockup transport (for unit testing)
      if usemockup do
         # Obtain the transport pid
        { :ok, t_pid } = find_or_launch_transport(SIP.Test.Transport.UDPMockup, "UDPMockup", ruri.domain, ruri.port)
        { :ok, t_mod, t_pid }
      else
        # Get the destination IP address
        { :ok, dest_ip } = resolve_dest_domain(ruri.domain, false)
        # Obtain the transport pid
        { :ok, t_pid } = find_or_launch_transport(t_mod, transport_str, dest_ip, ruri.port)
        { :ok, t_mod, t_pid }

      end
    else
      :invalidtransport
    end
  end
end
