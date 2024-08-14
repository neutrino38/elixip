defmodule SIP.Transport do

  # Send a message through a transport
  def send_msg(tid, msg, destip, destport) when is_bitstring(msg) and is_tuple(destip) and is_integer(destport) do
    GenServer.call(tid, { :sendmsg, msg, destip, destport})
  end

  def get_local_ip_port(tid) do
    GenServer.call(tid, :getlocalipandport);
  end
end
