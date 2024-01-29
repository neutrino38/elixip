defmodule SIP.Transport.Selector do
	@moduledoc "Selection of transport given a SIP URI"

  require SIP.Uri
  require Registry
  require Logger

  @transport_map %{
    "UDP" => SIP.Transport.UDP,
    "TCP" => SIP.Transport.TCP,
    "TLS" => SIP.Transport.TLS,
    "WS" => SIP.Transport.WS,
    "WSS" => SIP.Transport.WSS,
    "SCTP" => nil
  }

  def start() do
    case Registry.start_link(keys: :unique, name: Registry.SIPTransport) do
      { :ok, pid } ->
        Logger.info("SIP transport layer started with PID #{inspect(pid)}")
        :ok

      { code, _pid } ->
        Logger.error ("SIP transport layer failed to start with error #{code}")
        code
    end
  end

  defp find_or_launch_transport(t_mod, transport_name, destip, port)  do
    reliable = apply(t_mod, :is_reliable, [])
    instance_name = if reliable do
      transport_name <> "_" <> destip <> ":" <> Integer.to_string(port)
    else
      transport_name
    end

    # Lookup a process matching the existing instance name
    case Registry.lookup(Registry.SIPTransport, instance_name) do
      [] ->
        # No such instance. Start a new transport
        name = { :via, Registry, {Registry.SIPTransport, instance_name}}
        { :ok, t_pid} = GenServer.start(t_mod, { destip, port } , name: name)
        Logger.debug("Started transport instance #{t_mod} PID #{inspect(t_pid)} -> #{destip}:#{port}")
        { :ok, t_pid}

        # Found one. Start return the pid
      [{ t_pid, _ }] -> { :ok, t_pid }
    end
  end

  # Resolve and select one of the IP
  defp resolve_dest_domain(uri_domain, _trysrv) do
    # To implement
    { :ok, uri_domain }
  end

  @spec select_transport(binary(), boolean()) :: { :ok, module(), pid(), list(), integer() } | atom()
  @doc "Select a transport module an option given a request URI"
  def select_transport(ruri, trysrv) when is_binary(ruri) do
    case SIP.Uri.parse(ruri) do
      { :ok, parsed_uri } -> select_transport(parsed_uri, trysrv)
      { errcode, %{} } -> errcode
    end
  end

  @spec select_transport(map(), boolean()) :: { :ok, module(), pid(), list(), integer() } | atom()
  def select_transport(ruri, trysrv) when is_map(ruri) do

    #Check if this is a unit test. If this is the case use a mockup for transport
    usemockup = case SIP.Uri.get_uri_param(ruri, "unittest") do
      { :nosuchparam, nil } -> false
      { :ok, "1" } -> true
      _ -> false
    end

    # Obtain the transport part from the Request URI
    transport_str = case SIP.Uri.get_uri_param(ruri, "transport") do
      { :no_such_param, nil } -> "UDP"
      { :ok, value } -> String.upcase(value)
    end

    t_mod = Map.get(@transport_map, transport_str)

    if t_mod != nil do
      # We have a transport module
      # Test if we use the mockup transport (for unit testing)
      if usemockup do
         # Obtain the transport pid
        { :ok, t_pid } = find_or_launch_transport(SIP.Test.Transport.UDPMockup, "UDPMockup", ruri.domain, ruri.port)
        { :ok , destaddr } = SIP.NetUtils.parse_address("1.2.3.4")
        { :ok, SIP.Test.Transport.UDPMockup, t_pid, destaddr, 5080 }
      else
        # Get the destination IP address
        { :ok, dest_ip } = resolve_dest_domain(ruri.domain, trysrv)
        # Obtain the transport pid
        { :ok, t_pid } = find_or_launch_transport(t_mod, transport_str, dest_ip, ruri.port)
        { :ok, t_mod, t_pid, dest_ip, ruri.port }

      end
    else
      :invalidtransport
    end
  end
end
