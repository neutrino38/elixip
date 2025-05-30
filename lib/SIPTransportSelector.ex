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
    # Make sure we know which DNS server to use
    SIP.Resolver.get_dns_default_dns_server()
    case Registry.start_link(keys: :unique, name: Registry.SIPTransport) do
      { :ok, pid } ->
        Logger.info("SIP transport layer started with PID #{inspect(pid)}")
        :ok

      { code, _pid } ->
        Logger.error ("SIP transport layer failed to start with error #{code}")
        code
    end
  end

  defp find_or_launch_transport(uri = %SIP.Uri{}) do
    reliable = apply(uri.tp_module, :is_reliable, [])
    destip = NetUtils.ip2string(uri.destip)
    instance_name = if reliable do
      uri.destproto <> "_" <> destip <> ":" <> Integer.to_string(uri.destport)
    else
      uri.destproto
    end

    # Lookup a process matching the existing instance name
    Logger.debug([ module: __MODULE__,
      message: "Looking for transport instance #{instance_name} for dest #{destip}:#{uri.destport}"])
    case Registry.lookup(Registry.SIPTransport, instance_name) do
      [] ->
        # No such instance. Start a new transport
        name = { :via, Registry, {Registry.SIPTransport, instance_name}}
        case GenServer.start(uri.tp_module, { uri.destip, uri.destport } , name: name) do
          { :ok, t_pid } ->
            Logger.debug("Started transport #{inspect(uri.tp_module)} process with PID #{inspect(t_pid)}")
            { :ok, %SIP.Uri{ uri | tp_pid: t_pid } }

          { :error, :networkdown } ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}: No network connection" ])
            { :error, :failedtostart }

          { :error, :cnxerror } ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}: failed to connect to UAS" ])
            { :error, :failedtostart }

          { :error, { errtype, stacktrace }} ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}. Reported error #{errtype}" ])
            Logger.error(Exception.format(:error, { errtype, stacktrace }, stacktrace))
            { :error, :failedtostart }

        end



        # Found one. Start return the pid
      [{ t_pid, _ }] ->
        if Process.alive?(t_pid) do
          { :ok, %SIP.Uri{ uri | tp_pid: t_pid } }
        else
          Logger.warning("Found transport process with PID #{inspect(t_pid)} but it is dead.")
          name = { :via, Registry, {Registry.SIPTransport, instance_name}}
          { :ok, t_pid} = GenServer.start(uri.tp_module, { uri.destip, uri.destport } , name: name)
          Logger.debug("Started transport #{inspect(uri.tp_module)} process with PID #{inspect(t_pid)}")
          { :ok, %SIP.Uri{ uri | tp_pid: t_pid } }
        end
    end
  end

  @spec select_transport(binary() | %SIP.Uri{}) :: %SIP.Uri{} | atom()
  @doc "Select a transport module an option given a request URI"
  def select_transport(ruri) when is_binary(ruri) do
    case SIP.Uri.parse(ruri) do
      { :ok, parsed_uri } -> select_transport(parsed_uri)
      { _errcode, %{} } -> :invaliduri
    end
  end

  def select_transport(ruri = %SIP.Uri{}) do
    #Check if this is a unit test. If this is the case use a mockup for transport
    usemockup = case SIP.Uri.get_uri_param(ruri, "unittest") do
      #{ :nosuchparam, _ } -> false
      { :ok, "1" } -> true
      _ -> false
    end

    newuri_or_err = if usemockup do
      { :ok , destaddr } = SIP.NetUtils.parse_address("1.2.3.4")

       # Here we use the mockup transport (for unit testing)
       %SIP.Uri{ ruri | destip: destaddr, destport: 5080, destproto: "UDPMockup",
                tp_module: SIP.Test.Transport.UDPMockup }
    else
      case SIP.Resolver.resolve_and_add_dest(ruri) do
        # Error
        err when err in [ :nxdomain, :error ] ->
          :invalidsipdestination

        # Resolution successful
        newruri ->
          t_mod = Map.get(@transport_map, newruri.destproto)
          if t_mod != nil do
            # Add transport module
            %SIP.Uri{ newruri | tp_module: t_mod }
          else
            Logger.error(module: __MODULE__, message: "Transport #{ruri.destproto} is not supported.")
            :invalidtransport
          end

      end
    end

    if is_map(newuri_or_err) do
      try do
        # Now obtain the transport pid and launch it if needed
        case find_or_launch_transport(newuri_or_err) do
          { :ok, newuri } -> newuri

          { :error, err } ->
            Logger.debug(module: __MODULE__, message: "failed to find and start #{ruri.tp_module} transport : #{err}")
            :invalidtransport
        end

      rescue
        e ->
          Logger.error(module: __MODULE__, message: "Got an exception during #{ruri.destproto} transport selection")
          Logger.error(Exception.format(:error, e, __STACKTRACE__))
          :invalidtransport
      end
    else
      newuri_or_err
    end
  end
end
