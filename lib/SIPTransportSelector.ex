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

  def find_or_launch_transport(t_mod, transport_name, port \\ nil)  do
    instance_name = if is_integer(port) do
      transport_name <> "_" <> Integer.to_string(port) <> "_" <> Integer.to_string(port)
    else
      transport_name
    end

    case Registry.lookup(SIP.Transport.Registry, instance_name) do
      { nil, _ } ->
        name = { :via, Registry, {SIP.Transport.Registry, instance_name}}
        GenServer.start_link(t_mod, { port } , name: name)

      { t_pid, _ } -> { :ok, t_pid }
    end

  end

  @spec select_transport(binary(), boolean()) :: { atom(), module(), pid() } | atom()
  @doc "Select a transport module an option given a request URI"
  def select_transport(ruri, usemockup \\ false) when is_binary(ruri) and is_boolean(usemockup) do
    case SIP.Uri.parse(ruri) do
      { :ok, parsed_uri } -> select_transport(parsed_uri, usemockup)
      { errcode, %{} } -> errcode
    end
  end

  @spec select_transport(map(), boolean()) :: { atom(), module(), pid() } | atom()
  def select_transport(ruri, usemockup) when is_map(ruri) and is_boolean(usemockup) do

    # Obtain the transport part from the Request URI
    transport_str = case SIP.Uri.get_uri_param(ruri, "transport") do
      { :nosuchparam, nil } -> "UDP"
      { :ok, value } -> String.upcase(value)
    end

    t_mod = Map.get(@transport_map, transport_str)

    if t_mod != nil do
      # We have a transport module
      # Test if we use the mockup transport (for unit testing)
      t_mod = if usemockup do
        SIP.Test.Transport.UDPMockup
      end

      # Obtain the transport pid
      t_pid = apply(t_mod, :select_instance, [ ruri ])

      { :ok, t_mod, t_pid }
    else
      :invalidtransport
    end
  end
end
