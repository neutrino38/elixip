defmodule SIP.Transport do

  require Logger

  defmodule Depack do
    @moduledoc """
    SIP depacketizer when SIP protocol is carred over a connectionfull
    stream transport that does not enforce message boundaries (TCP, TLS)
    """
    require SIPMsg

    defstruct [
      buffer: "",
      body: "",
      state: :wait_for_msg,
      clen: 0
    ]

    # If no header was found stop the recurtion and return 0
    defp parse_and_get_clen([]) do
      0
    end

    # Parse the first line and if this is Content-Legnth return the value
    defp parse_and_get_clen(lines) do
      [ first_line | rest ] = lines
      [ header, val ] = String.split(first_line, ": ", parts: 2)
      if header == "Content-Length" do
        String.to_integer(val)
      else
        parse_and_get_clen(rest)
      end
    end

    defp parse_first_line(line) do
      case String.split(line, " ", parts: 3) do

				# This is a SIP response
				[ "SIP/2.0", _response_code, _reason ] -> :ok

				# This is a SIP request
				[ _req, _sip_uri, "SIP/2.0" ] -> :ok

        [ "\r\n" ] -> :ping

				_ -> :error
      end
    end


    def on_data_received(buf = %Depack{}, data, cb_fun) when is_binary(data) and is_function(cb_fun) and buf.state == :wait_for_msg do
      IO.puts("waiting for mesg")
      buf = %Depack{ buf | buffer: buf.buffer <> data } # Accumulate
      if String.contains?(buf.buffer,"\r\n") do
        [ first_line, rest ] = String.split(buf.buffer, "\r\n", parts: 2)
        case parse_first_line(first_line) do
          :ok ->
            buf = %Depack{ buf | state: :reading_headers }
            IO.puts(" -> reading_headers ")
            on_data_received(buf, "", cb_fun)

          :ping ->
            # This is a SIP TCP ping
            cb_fun.(:ping, "")
            buf = %Depack{ buf | buffer: rest }
            IO.puts("ping")
            on_data_received(buf, "", cb_fun)

          :error ->
            # Invalid SIP - discard eveything
            IO.puts("invalid SIP msg: first_line = #{first_line}")
            %Depack{ buf | buffer: "", clen: 0 }
        end
      else
        buf
      end
    end

    def on_data_received(buf = %Depack{}, data, cb_fun) when is_binary(data) and is_function(cb_fun) and buf.state == :reading_headers do
      buf = %Depack{ buf | buffer: buf.buffer <> data } # Accumulate
      IO.puts("reading_headers !")
      if String.contains?(buf.buffer,"\r\n\r\n") do
        [ headers, rest ] = String.split(buf.buffer, "\r\n\r\n", parts: 2)

        # Remove first line
        [ _first_line | header_lines ] = String.split(headers, "\r\n")

        clen = parse_and_get_clen(header_lines)
        if clen == 0 do
          # This SIP message has no body. Pass it to the transaction layer
          IO.puts("Message complete !")
          cb_fun.(:msg, headers)

          # Reset the buffer
          buf = %Depack{ buf | state: :wait_for_msg, buffer: "", clen: 0 }
          # Handle the rest
          on_data_received(buf, rest, cb_fun)
        else
          buf = %Depack{ buf | state: :reading_body, buffer: headers, clen: clen, body: "" }
          # Process the body
          IO.puts(" -> reading_body")
          on_data_received(buf, rest, cb_fun)
        end
      else
        buf
      end
    end



  end
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
