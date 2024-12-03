defmodule SIP.Transport.Selector do
	@moduledoc "Selection of transport given a SIP URI"
alias SIP.NetUtils

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

    destip = if is_tuple(destip), do: NetUtils.ip2string(destip), else: destip

    # Lookup a process matching the existing instance name
    Logger.debug([ module: __MODULE__,  message: "Looking for transport instance #{instance_name} for dest #{destip}:#{port}"])
    case Registry.lookup(Registry.SIPTransport, instance_name) do
      [] ->
        # No such instance. Start a new transport
        name = { :via, Registry, {Registry.SIPTransport, instance_name}}
        { :ok, t_pid} = GenServer.start(t_mod, { destip, port } , name: name)
        Logger.debug("Started transport #{inspect(t_mod)} process with PID #{inspect(t_pid)}")
        { :ok, t_pid}

        # Found one. Start return the pid
      [{ t_pid, _ }] ->
        if Process.alive?(t_pid) do
          { :ok, t_pid }
        else
          Logger.warning("Found transport process with PID #{inspect(t_pid)} but it is dead.")
          name = { :via, Registry, {Registry.SIPTransport, instance_name}}
          { :ok, t_pid} = GenServer.start(t_mod, { destip, port } , name: name)
          Logger.debug("Started transport #{inspect(t_mod)} process with PID #{inspect(t_pid)}")
          { :ok, t_pid }
        end
    end
  end

  @spec select_transport(binary(), boolean()) :: { :ok, module(), pid(), list(), integer() } | atom()
  @doc "Select a transport module an option given a request URI"
  def select_transport(ruri, trysrv) when is_binary(ruri) do
    case SIP.Uri.parse(ruri) do
      { :ok, parsed_uri } -> select_transport(parsed_uri, trysrv)
      { errcode, %{} } -> errcode
    end
  end

  @spec select_transport(%SIP.Uri{}, boolean()) :: { :ok, module(), pid(), list(), integer() } | atom()
  def select_transport(ruri = %SIP.Uri{}, trysrv) do

    #Check if this is a unit test. If this is the case use a mockup for transport
    usemockup = case SIP.Uri.get_uri_param(ruri, "unittest") do
      { :nosuchparam, nil } -> false
      { :ok, "1" } -> true
      _ -> false
    end

    # Obtain the transport part from the Request URI
    transport_str = SIP.Uri.get_transport(ruri)

    t_mod = Map.get(@transport_map, transport_str)

    if t_mod != nil do
      try do
        # We have a transport module
        # Test if we use the mockup transport (for unit testing)
        if usemockup do
          # Obtain the transport pid
          { :ok, t_pid } = find_or_launch_transport(SIP.Test.Transport.UDPMockup, "UDPMockup", ruri.domain, ruri.port)
          { :ok , destaddr } = SIP.NetUtils.parse_address("1.2.3.4")
          { :ok, SIP.Test.Transport.UDPMockup, t_pid, destaddr, 5080 }
        else
          # Get the destination IP address
          { dest_ip, dest_port } = SIP.Resolver.resolve(ruri, trysrv)
          # Obtain the transport pid
          { :ok, t_pid } = find_or_launch_transport(t_mod, transport_str, dest_ip, dest_port)
          { :ok, t_mod, t_pid, dest_ip, dest_port }
        end
      rescue
        e ->
          Logger.error(module: __MODULE__, message: "Got an exception during #{transport_str} transport selection")
          Logger.error(Exception.format(:error, e, __STACKTRACE__))
          :invalidtransport
      end
    else
      Logger.error(module: __MODULE__, message: "Transport #{transport_str} is not supported.")
      :invalidtransport
    end
  end
end
