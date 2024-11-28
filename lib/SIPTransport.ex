defmodule SIP.Transport do

  # Send a message through a transport
  def send_msg(tid, msg, destip, destport) when is_bitstring(msg) and is_tuple(destip) and is_integer(destport) do
    GenServer.call(tid, { :sendmsg, msg, destip, destport})
  end

  # Get the IP and port associated with the transport instance
  def get_local_ip_port(tid) do
    GenServer.call(tid, :getlocalipandport);
  end

  # Create a contact URI
  @spec build_contact_uri(module(), pid()) :: %SIP.Uri{ domain: binary(), port: integer(), scheme: binary() }
  def build_contact_uri(tmod, tid) do
    { :ok, localip, localport } = get_local_ip_port(tid)
    transport_str = apply(tmod, :transport_str, [])
    scheme = if transport_str == "tls" || transport_str == "TLS", do: "sips:", else: "sip:"
    %SIP.Uri{
     domain: localip,
     port: localport,
     scheme: scheme
    }
  end

  # Add /fix contact header to a SIP message given the transport
  def add_contact_header(tmod, tid, msg) when is_pid(tid) and is_map(msg) do
    new_contact = build_contact_uri(tmod, tid)
    old_contact = Map.get(msg, :contact)

    new_contact = if not is_nil(old_contact) do
      # Transfert contact parameters if specified by the caller
      %SIP.Uri{ new_contact | params: old_contact.params, userpart: old_contact.userpart }
    else
      new_contact
    end

    Map.put(msg, :contact, new_contact)
  end
end
