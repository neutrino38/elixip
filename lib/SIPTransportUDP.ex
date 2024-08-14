defmodule SIP.Transport.UDP do
  use GenServer
  require Logger
  require Socket

  @transport_str "udp"
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: false


  @impl true
  def init({ dest_ip, dest_port}) do
    ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )

    initial_state = %{ t_isreliable: false, localip: hd(ips), localport: 5060 }
    { :ok, initial_state }
  end
end
