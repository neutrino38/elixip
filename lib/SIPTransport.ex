defmodule SIP.Transport do

  # Send a message through a transport
  def send_msg(tid, msg, destip, destport) when is_bitstring(msg) and is_tuple(destip) and is_integer(destport) do
    GenServer.call(tid, { :sendmsg, msg, destip, destport})
  end

  # Get the IP and port associated with the transport instance
  def get_local_ip_port(tid) do
    GenServer.call(tid, :getlocalipandport);
  end

  # Add contact header to a SIP message given the transport
  def add_contact_header(tid, msg) when is_pid(tid) and is_map(msg) do
   { :ok, localip, localport } = get_local_ip_port(tid)

   contacturi = %SIP.Uri{
     domain: localip,
     port: localport
   }

   Map.put(msg, :contact, contacturi)
  end
end
