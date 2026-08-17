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

      { :error, { :already_started, _pid } } ->
        # Layer already running (e.g. started by a previous test module): treat as success
        :ok

      { code, _pid } ->
        Logger.error ("SIP transport layer failed to start with error #{code}")
        code
    end
  end

  # How many processes of a transport module exist, and which one a URI gets.
  #
  # The default is the historical rule: one instance per connection for a reliable
  # transport (TCP/TLS/WSS — the name carries the peer), one per protocol for an
  # unreliable one (a node has a single UDP socket, which is also what the kelixip
  # listener config enforces).
  #
  # A module may override it by exporting `select_instance/1`: given the resolved
  # URI it returns the instance name it wants, or nil to keep the default. That is
  # how the test mockup gives a suite two *distinct* peers — a B2BUA has two legs,
  # and with one shared instance the two directions answer each other's requests.
  defp instance_name(uri, destip) do
    case module_instance_name(uri) do
      name when is_binary(name) -> name
      _ -> default_instance_name(uri, destip)
    end
  end

  defp module_instance_name(uri) do
    # ensure_loaded? first: function_exported?/3 answers false for a module that
    # has simply not been loaded yet, and in a release-less run that is exactly
    # the state of the FIRST call — the very one that would then be misnamed,
    # silently, while every later one got it right.
    if Code.ensure_loaded?(uri.tp_module) and
         function_exported?(uri.tp_module, :select_instance, 1) do
      apply(uri.tp_module, :select_instance, [ uri ])
    end
  end

  defp default_instance_name(uri, destip) do
    if apply(uri.tp_module, :is_reliable, []) do
      uri.destproto <> "_" <> destip <> ":" <> Integer.to_string(uri.destport)
    else
      uri.destproto
    end
  end

  defp find_or_launch_transport(uri = %SIP.Uri{}) do
    destip = if is_tuple(uri.destip) do NetUtils.ip2string(uri.destip) else uri.destip end
    instance_name = instance_name(uri, destip)

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

          # Race between concurrent scenario instances: another one registered
          # the same transport instance first. Reuse the already-started pid.
          { :error, { :already_started, t_pid } } ->
            Logger.debug("Transport #{inspect(uri.tp_module)} already started with PID #{inspect(t_pid)}, reusing it")
            { :ok, %SIP.Uri{ uri | tp_pid: t_pid } }

          { :error, :networkdown } ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}: No network connection" ])
            { :error, :failedtostart }

          { :error, :cnxerror } ->
            dest = "sip:#{SIP.NetUtils.ip2string(uri.destip)}:#{uri.destport};transport=#{String.downcase(uri.destproto)}"
            Logger.error([ module: __MODULE__, message: "Unable to connect to SIP server #{dest}" ])
            { :error, :failedtostart }

          # A crash during init returns { reason, stacktrace }. Only format the
          # stacktrace when it actually is one — other { atom, term } shapes
          # (e.g. already_started carrying a pid) would otherwise blow up the
          # formatter with a Protocol.UndefinedError.
          { :error, { errtype, stacktrace }} when is_list(stacktrace) ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}. Reported error #{inspect(errtype)}" ])
            Logger.error(Exception.format(:error, { errtype, stacktrace }, stacktrace))
            { :error, :failedtostart }

          { :error, reason } ->
            Logger.error([ module: __MODULE__, message: "Failed to start transport #{uri.destproto}. Reported error #{inspect(reason)}" ])
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
    # Level 1 — send over an existing flow, short-circuiting everything below.
    case send_over_flow(ruri) do
      %SIP.Uri{} = flow_uri -> flow_uri
      nil -> select_by_destination(ruri)
    end
  end

  # An already-established flow (design §6.4, decision §16.6): the URI carries the
  # pid of a **live** transport process — an inbound connected transport (a NATed
  # browser's WSS/TCP/TLS spawned by a Listener) or a UDP socket already in use.
  # Use it as-is: no DNS resolution, and no `Registry.SIPTransport` lookup either.
  # That lookup is the trap: inbound connections are NOT registered there, so it
  # would try to open a *new outbound* connection to the peer — impossible toward a
  # NATed client, and pointless for a socket we already hold.
  #
  # `Kelix.Mod.Registrar.lookup/1` stamps `tp_pid` (+ `tp_module`) from the stored
  # binding, so routing an inbound request to a registered contact takes this path.
  #
  # Requirements: the pid must be alive (a dead flow falls through — its binding is
  # purged anyway) and the transport module must be *known*, from `tp_module` or
  # from `destproto`. It is never guessed: with neither, we fall through rather
  # than send over a transport whose semantics we cannot name.
  #
  # The `unittest` marker keeps winning over everything (as it does over DNS
  # today), so unit-test URIs behave exactly as before.
  defp send_over_flow(%SIP.Uri{tp_pid: pid} = uri) when is_pid(pid) do
    with false <- unittest?(uri),
         true <- Process.alive?(pid),
         t_mod when not is_nil(t_mod) <- flow_module(uri) do
      Logger.debug(module: __MODULE__,
        message: "Sending over the existing #{inspect(t_mod)} flow #{inspect(pid)}")

      %SIP.Uri{ uri | tp_module: t_mod, destproto: uri.destproto || proto_str(t_mod) }
    else
      _ -> nil
    end
  end

  defp send_over_flow(_uri), do: nil

  defp flow_module(%SIP.Uri{tp_module: t_mod}) when not is_nil(t_mod), do: t_mod
  defp flow_module(%SIP.Uri{destproto: proto}) when is_binary(proto),
    do: Map.get(@transport_map, proto)
  defp flow_module(_uri), do: nil

  # "UDP" / "WSS" / … as the transports themselves spell it
  defp proto_str(t_mod), do: apply(t_mod, :transport_str, []) |> String.upcase()

  # A URI aimed at the in-process test mockup. Any non-empty `unittest` value
  # counts: `unittest=1` is the shared instance every existing suite uses, and any
  # other value names a peer of its own (see the mockup's `select_instance/1`).
  defp unittest?(uri) do
    case SIP.Uri.get_uri_param(uri, "unittest") do
      { :ok, value } when is_binary(value) and value != "" -> true
      _ -> false
    end
  end

  # Levels 2 and 3: resolve a destination (or take the one already resolved), then
  # find or launch the matching transport instance.
  defp select_by_destination(ruri = %SIP.Uri{}) do
    newuri_or_err = cond do
      # Unit test: use the mockup transport. The module comes from the app env
      # so no test code is referenced (nor shipped) from the library — the test
      # suite sets it in test_helper.exs (SIP.Test.Transport.Mockup).
      unittest?(ruri) ->
        t_mod = Application.get_env(:elixip2, :unittest_transport) ||
                  raise "R-URI carries unittest=1 but :elixip2, :unittest_transport is not configured"

        { :ok , destaddr } = SIP.NetUtils.parse_address("1.2.3.4")

        %SIP.Uri{ ruri | destip: destaddr, destport: 5080, destproto: "UDPMockup",
                 tp_module: t_mod }

      # Level 2 — the destination is already resolved (IP + port known: a stored
      # binding's `received`, a configured next hop). Skip DNS and use it as-is.
      # No `destproto` ⇒ UDP (decision §16.6).
      true ->
        case resolved_dest(ruri) do
          %SIP.Uri{} = resolved -> resolved

          # Level 3 — the historical path: resolve the R-URI (DNS/NAPTR/SRV).
          nil -> resolve_dest(ruri)
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

  defp resolved_dest(%SIP.Uri{destip: destip, destport: destport} = uri)
       when not is_nil(destip) and is_integer(destport) and destport > 0 do
    proto = uri.destproto || "UDP"

    case uri.tp_module || Map.get(@transport_map, proto) do
      nil -> nil
      t_mod -> %SIP.Uri{ uri | destproto: proto, tp_module: t_mod }
    end
  end

  defp resolved_dest(_uri), do: nil

  defp resolve_dest(ruri) do
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
end
