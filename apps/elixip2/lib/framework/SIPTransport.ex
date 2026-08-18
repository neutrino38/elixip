defmodule SIP.Transport do

  require Logger

  defmodule Depack do
    @moduledoc """
    SIP depacketizer when SIP protocol is carred over a connectionfull
    stream transport that does not enforce message boundaries (TCP, TLS)
    """
    require SIPMsg
    require Logger

    @maxmsgsize 8000

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

				_ ->
          # The line reaching us has already lost its CRLF, so a keep-alive shows up
          # here as an EMPTY first line — which is why the `[ "\r\n" ]` clause that
          # used to sit here never matched, and every CRLF ping took the :error path
          # and flushed the buffer, dropping whatever valid message was pipelined
          # behind it. Ask the message layer instead.
          if SIPMsg.keepalive?(line), do: :ping, else: :error
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
            # A keep-alive CRLF: consume just it and keep reading what follows.
            cb_fun.(:ping, "")
            buf = %Depack{ buf | buffer: rest }
            Logger.debug([module: __MODULE__, message: "keep-alive CRLF received, dropping"])
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
      if Kernel.byte_size(buf.buffer) > @maxmsgsize do
        raise "SIP message exceeeds maximum size"
      end
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
          on_data_received(buf, rest, cb_fun)
        end
      else
        buf
      end
    end

    def on_data_received(buf = %Depack{}, data, cb_fun) when is_binary(data) and is_function(cb_fun) and buf.state == :reading_body do
      accumulated = buf.body <> data
      if byte_size(accumulated) >= buf.clen do
        {body, rest} = String.split_at(accumulated, buf.clen)
        cb_fun.(:msg, buf.buffer <> "\r\n\r\n" <> body)
        buf = %Depack{ buf | state: :wait_for_msg, buffer: "", body: "", clen: 0 }
        on_data_received(buf, rest, cb_fun)
      else
        %Depack{ buf | body: accumulated }
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

    # Commonly accepted modern cipher suites (Mozilla "intermediate" profile).
    # All provide PFS through ephemeral ECDHE key exchange; RSA-only ciphers are
    # rejected by modern servers. ECDSA and RSA variants are both listed so the
    # suite negotiates regardless of the server certificate type.
    @tls_ciphers [
      ~c"ECDHE-ECDSA-AES256-GCM-SHA384",
      ~c"ECDHE-RSA-AES256-GCM-SHA384",
      ~c"ECDHE-ECDSA-CHACHA20-POLY1305",
      ~c"ECDHE-RSA-CHACHA20-POLY1305",
      ~c"ECDHE-ECDSA-AES128-GCM-SHA256",
      ~c"ECDHE-RSA-AES128-GCM-SHA256"
    ]

    def connect(state, transport, timeout \\ 10000) do
      ssl_options =
        [
          verify: false, # Désactive la vérification du certificat pour simplifier l'exemple
          versions: [:"tlsv1.2"], # Spécifie la version de TLS à utiliser
          # Cipher suites are configurable via :elixip2/:tls_ciphers; @tls_ciphers is the default.
          ciphers: Application.get_env(:elixip2, :tls_ciphers, @tls_ciphers),
          timeout: timeout,
          mode: :active
        ] ++ client_cert_options()

      sock = case transport do
        :tcp ->
          # socket2 expects a string hostname/IP, not an Erlang tuple
          destip_str = SIP.NetUtils.ip2string(state.destip)
          s = Socket.TCP.connect!(destip_str, state.destport, [ timeout: timeout, mode: :active ])
          Socket.process!(s, self())
          s

        :tls ->
          s = Socket.SSL.connect!(state.destip, state.destport, ssl_options)
          Socket.process!(s, self())
          s

        :wss ->
          # With the socket2 fork, mode: :active makes Socket.Web spawn a reader
          # that delivers incoming frames as {:web, socket, data} to this process
          # (see handle_info/2). ssl_options already carries mode: :active.
          wss_options = Keyword.merge(ssl_options, protocol: ["sip"], secure: true)
          Socket.Web.connect!(state.destip, state.destport, wss_options)

        :ws  -> Socket.Web.connect!(state.destip, state.destport, [ timeout: timeout, mode: :active, protocol: ["sip"] ])

        _ -> raise "Unsupported transport #{transport}"
      end

      # Obtain local IP and port. Socket.local! has no implementation for
      # %Socket.Web{} (WS/WSS), so reach into the underlying socket directly.
      {local_ip, local_port} = local_address(sock)

      # Return the local IP and port inside the state map.
      Map.put(state, :localip, local_ip) |> Map.put(:localport, local_port) |> Map.put(:socket, sock)
    end

    # Certificate a TLS/WSS *client* presents. It needs none unless the peer asks for
    # mutual authentication, so the cert/key go in only when both are configured and
    # readable — the same `:tls_certfile` / `:tls_keyfile` keys the listeners use
    # (elixipp exposes them as --tls-cert / --tls-key).
    #
    # They used to be hardcoded to "certs/certificate.pem" / "certs/private_key.pem"
    # and always passed to :ssl, so every outbound TLS or WSS connection failed with
    # `{:options, {:keyfile, ~c"certs/private_key.pem", {:error, :enoent}}}` unless
    # those two files happened to sit in the current directory. Dialling a TLS proxy
    # from anywhere but a checkout could not work, and the error named a path nobody
    # had asked for.
    defp client_cert_options do
      cert = Application.get_env(:elixip2, :tls_certfile)
      key = Application.get_env(:elixip2, :tls_keyfile)

      if is_binary(cert) and is_binary(key) and File.regular?(cert) and File.regular?(key) do
        [cert: [path: cert], key: [path: key]]
      else
        []
      end
    end

    # Local address of a WS/WSS socket: Socket.Web wraps the transport socket,
    # which is an :ssl socket when secure (WSS) and a :gen_tcp port otherwise (WS).
    defp local_address(%Socket.Web{socket: ssl}) when is_tuple(ssl) and elem(ssl, 0) == :sslsocket do
      {:ok, addr} = :ssl.sockname(ssl)
      addr
    end

    defp local_address(%Socket.Web{socket: tcp}) do
      port = if is_tuple(tcp), do: elem(tcp, 1), else: tcp
      {:ok, addr} = :inet.sockname(port)
      addr
    end

    defp local_address(sock), do: Socket.local!(sock)

    @doc """
    Remote (peer) address `{ip, port}` of a connection-oriented socket, or `nil`
    when it cannot be determined (e.g. the socket just closed).

    Connection-oriented transports (WSS/TLS/TCP) dial the proxy by name — for
    WS/WSS the SIP resolver deliberately keeps the hostname and lets the socket
    layer resolve it (SNI / cert validation), so the transport's stored `destip`
    is a hostname string, not an IP. On the receive path the true source of an
    incoming message is therefore the socket's peer, not that hostname; this
    yields it as a real IP tuple, consistent with the sender address UDP passes.
    """
    def remote_address(%Socket.Web{socket: ssl}) when is_tuple(ssl) and elem(ssl, 0) == :sslsocket,
      do: unwrap_peer(:ssl.peername(ssl))

    def remote_address(%Socket.Web{socket: tcp}) do
      port = if is_tuple(tcp), do: elem(tcp, 1), else: tcp
      unwrap_peer(:inet.peername(port))
    end

    def remote_address(s) when is_tuple(s) and elem(s, 0) == :sslsocket,
      do: unwrap_peer(:ssl.peername(s))

    def remote_address(s) when is_port(s), do: unwrap_peer(:inet.peername(s))
    def remote_address(_), do: nil

    defp unwrap_peer({:ok, {ip, port}}), do: {ip, port}
    defp unwrap_peer(_), do: nil

    @doc """
    Tell every dialog that this connected transport is gone, so the ones riding it
    can act (design docs/design/b2bua_module.md §14.4, R4).

    Called from a transport's `terminate/2`, not from its close handlers, and that
    placement is the decision: an orderly close announced itself while a CRASH
    announced nothing at all, so a dialog whose transport died of an exception
    waited for timer B to notice — the difference between an immediate failover
    and 32 s of silence. `terminate/2` covers both. (It does not run on a brutal
    kill; R3's exit-safe transport calls absorb that residue.)

    Only for CONNECTED transports. A connectionless one has no flow to lose: its
    socket is a process-wide singleton the Selector relaunches, so a UDP transport
    going away means "recover" (R3), and announcing it here would kill every
    dialog on the node instead.

    Never raises: this runs while a process is already dying, sometimes during a
    node shutdown where the dialog registry is gone before us.
    """
    def notify_transport_down(tp_module, %{destip: destip, destport: destport}) do
      SIP.Dialog.broadcast({ :transport_down, tp_module, destip, destport })
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end

    def notify_transport_down(_tp_module, _state), do: :ok

    @doc """
    Process an incoming message inside a transport. Message must be complete.
    Parse it, try to find an associated transaction and if not, create an UAS
    transaction
    """
    def process_incoming_message(state, message, tp_name, tp_mod, socket, destip, destport) do
      # A keep-alive is not a message and not an error: dropping it here, before the
      # parser, is what keeps three error lines per ping out of the server log.
      if SIPMsg.keepalive?(message) do
        Logger.debug([module: __MODULE__, message: "#{tp_name}: keep-alive from " <>
          "#{peer_str(destip, destport)} (#{byte_size(message)} bytes), dropping"])
        { :noreply, state }
      else
        # Another protocol on our port is not a broken SIP message either: an RFC 5626
        # §4.4.2 STUN keep-alive, an ICE probe, a scanner. We send no Binding Response,
        # so the sender will eventually give up on this flow — hence a log line that
        # names STUN, which is a lead, instead of blaming the SIP parser.
        case SIP.Stun.decode(message) do
          {:ok, stun} ->
            Logger.debug([module: __MODULE__, message: "#{tp_name}: STUN #{SIP.Stun.describe(stun)}" <>
              " from #{peer_str(destip, destport)}, dropping (not a STUN server)"])
            { :noreply, state }

          :error ->
            process_sip_message(state, message, tp_name, tp_mod, socket, destip, destport)
        end
      end
    end

    # `destip` is an IP tuple on every transport but WSS, where the fallback value is
    # the dialed hostname — and `ip2string/1` only takes tuples, so formatting it
    # eagerly would raise on the very path that has no peer address to show.
    defp peer_str(ip, port) when is_tuple(ip), do: "#{SIP.NetUtils.ip2string(ip)}:#{port}"
    defp peer_str(ip, port) when is_binary(ip), do: "#{ip}:#{port}"
    defp peer_str(ip, port), do: "#{inspect(ip)}:#{port}"

    defp process_sip_message(state, message, tp_name, tp_mod, socket, destip, destport) do
      # Log incoming SIP messages for debug purposes
      log_incoming_message(message, tp_name, destip, destport)

      # One peer's odd datagram must not take down the transport that serves everyone
      # else on this socket.
      try do
        do_process_incoming_message(state, message, tp_name, tp_mod, socket, destip, destport)
      rescue
        e ->
          Logger.error([module: __MODULE__, message: "#{tp_name}: dropping an unparsable " <>
            "message from #{inspect(destip)}:#{destport} (#{Exception.message(e)})"])
          Logger.debug([module: __MODULE__, message: "offending message: #{inspect(message)}"])
          { :noreply, state }
      end
    end

    # Display incoming SIP message for debug purposes.
    # We check that the message is a valid string to avoid Logger crash

    defp log_incoming_message(message, tp_name, destip, destport) do
      dump = if String.valid?(message), do: message, else: inspect(message)

      Logger.debug(
        "#{tp_name}: Message received from #{peer_str(destip, destport)} <----\r\n" <>
          dump <> "\r\n-----------------"
      )
    end

    defp do_process_incoming_message(state, message, tp_name, tp_mod, socket, destip, destport) do
      case SIP.Transac.process_sip_message(message) do
        :ok -> { :noreply, state }

        { :no_matching_transaction, parsed_msg } ->
          # A request has a method atom (e.g. :REGISTER); a response carries
          # `method: false` (and `false` is itself an atom, so guard against it
          # explicitly — otherwise a response with no matching transaction would
          # wrongly take the request path and crash on the missing :ruri).
          if parsed_msg.method != false and is_atom(parsed_msg.method) do
            ruri_with_tp_info = %SIP.Uri{ parsed_msg.ruri | destip: destip, destport: destport,
                                          tp_module: tp_mod, tp_pid: self() }
            msg = Map.put(parsed_msg, :ruri, ruri_with_tp_info )

            if parsed_msg.method == :ACK do
              # An ACK matching no transaction is the ACK of a 2xx (new branch,
              # RFC 3261 §13.2.2.4): it creates NO server transaction (§17.2.3).
              # Route it straight to the dialog, which forwards it to the app.
              SIP.Dialog.process_incoming_request(msg, nil, false)
              { :noreply, state }
            else
              # We need to start a new transaction. Use the transport's own local
              # IP/port (resolved at setup) rather than the socket's bound address,
              # which is the 0.0.0.0 wildcard for UDP. Socket.local/1 also returns
              # {:ok, {ip, port}}, so it cannot be destructured into {ip, port}.
              { local_ip, local_port } = case socket do
                { ip, port } -> { ip, port }
                s when is_port(s) ->
                  # Raw :gen_tcp port (inbound TCP connections): Socket.local/1 only
                  # handles Socket structs, so use :inet.sockname directly.
                  case :inet.sockname(s) do
                    { :ok, {{0,0,0,0}, _} } -> { state.localip, state.localport }
                    { :ok, {ip, port} }     -> { ip, port }
                    _                       -> { state.localip, state.localport }
                  end
                s when is_tuple(s) and elem(s, 0) == :sslsocket ->
                  # Raw :ssl socket (inbound TLS connections via TLSListener).
                  case :ssl.sockname(s) do
                    {:ok, {{0,0,0,0}, _}} -> {state.localip, state.localport}
                    {:ok, {ip, port}}     -> {ip, port}
                    _                     -> {state.localip, state.localport}
                  end
                _ -> case Socket.local(socket) do
                        { :ok, {{0,0,0,0}, _port} } -> { state.localip, state.localport }
                        { :ok, {ip, port}} -> { ip, port }
                     end
              end
              {:ok, _tpid} = SIP.Transac.start_uas_transaction(msg, { local_ip, local_port, tp_name, state.upperlayer })
              { :noreply, state }
            end
          else
            Logger.warning("Received a SIP #{parsed_msg.response} response from #{SIP.NetUtils.ip2string(destip)}:#{destport} not linked to any transaction. Dropping it")
            { :noreply, state }
          end

        _ ->
          Logger.error("Received an invalid SIP message from #{SIP.NetUtils.ip2string(destip)}:#{destport}")
          { :noreply, state }
      end
    end


  end


  # ------------------------------------- Transport Public API ----------------------------------------

  @doc """
  Call a transport instance, turning its death into a transport error.

  A transport is a plain process reached by `GenServer.call`, and its pid is
  CACHED — in a transaction's state, in a dialog's `msg.ruri` — so it long
  outlives any check that it is alive. Calling a dead one raises an exit **in the
  caller's callback**, and the callers here are a transaction (whose death used to
  take its dialog with it, §14.2 (a)) and a dialog handling a scenario's
  `GenServer.call` (whose exit propagated to the scenario and skipped its whole
  teardown, §14.2 (b)).

  So it is turned into `:transporterror` — a return value every caller of a
  transport already handles, because a send can always fail. Design §14.4, R3.
  """
  @spec safe_call(pid(), any()) :: any() | :transporterror
  def safe_call(tid, request) do
    GenServer.call(tid, request)
  catch
    :exit, reason ->
      Logger.debug(module: __MODULE__,
        message: "transport #{inspect(tid)} is gone (#{inspect(reason)}): #{inspect(request)}")
      :transporterror
  end

  @spec send_msg( pid(), binary(), binary() | tuple(), integer() ) :: any()
  @doc "Send a SIP message through a transport instance designated by its process ID"
  def send_msg(tid, msg, destip, destport) when is_bitstring(msg) and is_integer(destport) do
    safe_call(tid, { :sendmsg, msg, destip, destport})
  end

  @doc """
  The IP and port a transport instance is bound to, or `:transporterror` when it
  is gone. Callers must handle both — see `safe_call/2`.
  """
  def get_local_ip_port(tid) do
    safe_call(tid, :getlocalipandport)
  end

  @doc "Create a local contact URI associated with a given transport instance"
  @spec build_contact_uri(module(), pid()) :: %SIP.Uri{ domain: binary(), port: integer(), scheme: binary() } | nil
  def build_contact_uri(tmod, tid) do
    case get_local_ip_port(tid) do
      { :ok, localip, localport } ->
        transport_str = apply(tmod, :transport_str, [])
        %SIP.Uri{
         domain: localip,
         port: localport,
         scheme: "sip:",
         proto: String.upcase(transport_str)
        }
        # The transport, ALWAYS, and in lower case. A Contact is the address a
        # peer sends its in-dialog requests to, and address means the three of
        # address, port and transport: leaving the last one out says "sip:", which
        # every UA reads as UDP (RFC 3263 §4.1) — so a dialog established over TCP
        # got its BYE aimed at a UDP port nobody listens on.
        #
        # Lower case is not cosmetic either. The value is case-insensitive on
        # paper (RFC 3261 §19.1.4) and case-sensitive in the field: we emitted
        # `transport=TCP`, and the capture of 2026-08-14 shows the caller ACKing
        # over UDP a dialog whose every other message was TCP — it had not
        # recognised the value and fallen back to the default. Everyone else
        # writes it lower case; so do we now.
        |> SIP.Uri.set_uri_param("transport", String.downcase(transport_str))

      # The transport died before it could say where it is bound. There is no
      # honest Contact to build, and raising here would take the transaction —
      # and with it its dialog — down over a header (design §14.4, R3).
      _err -> nil
    end
  end

  # Add /fix contact header to a SIP message given the transport
  def add_contact_header(tmod, tid, msg) when is_pid(tid) and is_map(msg) do
    add_contact_header(build_contact_uri(tmod, tid), msg)
  end

  # No local address to advertise: leave the message as it stands rather than
  # stamp a Contact we cannot fill in. The send that follows will fail on its own,
  # through the error path, which is where a dead transport belongs.
  defp add_contact_header(nil, msg), do: msg

  defp add_contact_header(new_contact, msg) do
    old_contact = Map.get(msg, :contact)

    new_contact = if not is_nil(old_contact) do
      # Transfert contact parameters if specified by the caller
      # Override transport params
      #
      # BOTH parameter sets: the caller's binding parameters are header parameters
      # (`expires`, `q`, a `+sip.instance`) and live in `hparams`. Carrying only
      # `params` would drop the `expires` that SIP.Session.Registrar puts on the
      # Contact of a REGISTER — the registration then asks for nothing.
      %SIP.Uri{ new_contact | params: old_contact.params, hparams: old_contact.hparams,
                userpart: old_contact.userpart, displayname: old_contact.displayname }
      # …and the transport of the transport actually used, over whatever the
      # caller had put there. Same value and same case as build_contact_uri/2
      # above: one rule for the Contact we stamp, not two.
      |> SIP.Uri.set_uri_param("transport", String.downcase(new_contact.proto))
    else
      new_contact
    end

    Map.put(msg, :contact, new_contact)
  end
end
