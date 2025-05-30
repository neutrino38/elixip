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
    # Use recursion to parse all the lines
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
      # IO.puts("waiting for mesg")
      buf = %Depack{ buf | buffer: buf.buffer <> data } # Accumulate
      if String.contains?(buf.buffer,"\r\n") do
        [ first_line, rest ] = String.split(buf.buffer, "\r\n", parts: 2)
        case parse_first_line(first_line) do
          :ok ->
            buf = %Depack{ buf | state: :reading_headers }
            # IO.puts(" -> reading_headers ")
            on_data_received(buf, "", cb_fun)

          :ping ->
            # This is a SIP TCP ping
            cb_fun.(:ping, "")
            buf = %Depack{ buf | buffer: rest }
            IO.puts("ping")
            on_data_received(buf, "", cb_fun)

          :error ->
            # Invalid SIP - discard eveything
            # IO.puts("invalid SIP msg: first_line = #{first_line}")
            %Depack{ buf | buffer: "", clen: 0 }
        end
      else
        buf
      end
    end

    def on_data_received(buf = %Depack{}, data, cb_fun) when is_binary(data) and is_function(cb_fun) and buf.state == :reading_headers do
      buf = %Depack{ buf | buffer: buf.buffer <> data } # Accumulate
      # IO.puts("reading_headers !")
      if String.contains?(buf.buffer,"\r\n\r\n") do
        [ headers, rest ] = String.split(buf.buffer, "\r\n\r\n", parts: 2)

        # Remove first line
        [ _first_line | header_lines ] = String.split(headers, "\r\n")

        clen = parse_and_get_clen(header_lines)
        if clen == 0 do
          # This SIP message has no body. Pass it to the transaction layer
          # IO.puts("Message complete !")
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

  # ------------------------------------- Transport implementation helpers  ---------------------------
  defmodule ImplHelpers do
    @moduledoc """
    Common internal functions used to implement transports
    """

    require Logger
    require SIP.NetUtils

    def connect(state, transport, timeout \\ 10000) do
      ssl_options = [
        cert: [path: "certs/certificate.pem"],
        key: [ path: "certs/private_key.pem" ],
        verify: false, # Désactive la vérification du certificat pour simplifier l'exemple
        versions: [:"tlsv1.2"], # Spécifie la version de TLS à utiliser
        ciphers: [~c"AES256-GCM-SHA384"],
        timeout: timeout,
        mode: :active
      ]

      sock = case transport do
        :tcp -> Socket.TCP.connect!(state.destip, state.destport, [ timeout: timeout, mode: :active ])
        :tls -> Socket.SSL.connect!(state.destip, state.destport, ssl_options)
        :wss -> Socket.Web.connect!(state.destip, state.destport, ssl_options)
        :ws  -> Socket.Web.connect!(state.destip, state.destport, [ timeout: timeout, mode: :active ])
        _ -> raise "Unsupported transport #{transport}"
      end
      # Optain local IP and port
      {local_ip, local_port} = Socket.local!(sock)

      #Bind the socket to the GenServer process
      Socket.process!(sock, self())

      # Return the local IP and port inside the state map.
      Map.put(state, :localip, local_ip) |> Map.put(:localport, local_port) |> Map.put(:socket, sock)
    end

    def process_incoming_message(state, message, tp_name, tp_mod, socket, destip, destport) do
      case SIP.Transac.process_sip_message(message) do
        :ok -> { :noreply, state }

        { :no_matching_transaction, parsed_msg } ->
          if is_atom(parsed_msg.method) do
            # We need to start a new transaction
            { local_ip, local_port } = Socket.local!(socket)
            SIP.Transac.start_uas_transaction(parsed_msg,
                { local_ip, local_port, tp_name, tp_mod, self(), state.upperlayer } , { destip, destport })
          else
            Logger.error("Received a SIP #{parsed_msg.response} response from #{state.destip}:#{state.destport} not linked to any transaction. Dropping it")
            { :noreply, state }
          end

        _ ->
          Logger.error("Received an invalid SIP message from #{SIP.NetUtils.ip2string(state.destip)}:#{state.destport}")
          { :noreply, state }
      end
    end


  end


  # ------------------------------------- Transport Public API ----------------------------------------
  @spec send_msg( pid(), binary(), binary() | tuple(), integer() ) :: any()
  @doc "Send a SIP message through a transport instance designated by its process ID"
  def send_msg(tid, msg, destip, destport) when is_bitstring(msg) and is_tuple(destip) and is_integer(destport) do
    GenServer.call(tid, { :sendmsg, msg, destip, destport})
  end

  @doc "Get the IP and port associated with the transport instance"
  def get_local_ip_port(tid) do
    GenServer.call(tid, :getlocalipandport);
  end

  @doc "Create a local contact URI associated with a given transport instance"
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
