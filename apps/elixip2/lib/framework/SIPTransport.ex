defmodule SIP.Transport do

  require Logger

  defmodule Depack do
    @moduledoc """
    SIP depacketizer when SIP protocol is carred over a connectionfull
    stream transport that does not enforce message boundaries (TCP, TLS)
    """
    require SIPMsg
    require Logger

    defstruct [
      buffer: "",
      body: "",
      state: :wait_for_msg,
      clen: 0
    ]

    # Content-Length as the depacketizer must read it: a non-negative integer, or
    # nothing it can frame on. This is FRAMING, not interpretation — there is no
    # message yet to ask the message layer about — and it has to agree with SIPMsg
    # octet for octet, which the round-trip test in sip_depack_test.exs pins.
    #
    # It used to destructure the split of every header line and `String.to_integer`
    # the value, so a line with no ": " and a non-numeric value each raised out of
    # the transport's own callback and killed the connection with no answer. And a
    # NEGATIVE value went through, where `String.split_at/2` counts from the END —
    # `split_at("abcdefgh", -5)` is `{"abc", "defgh"}` — so the body was framed
    # truncated and its tail re-read as the next message.
    defp parse_and_get_clen([]) do
      { :ok, 0 }
    end

    defp parse_and_get_clen([ line | rest ]) do
      case String.split(line, ": ", parts: 2) do
        [ "Content-Length", val ] ->
          case Integer.parse(String.trim(val)) do
            { clen, "" } when clen >= 0 -> { :ok, clen }
            _ -> :invalid
          end

        _ -> parse_and_get_clen(rest)
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


    @doc """
    Feed received octets to the depacketizer and frame whatever messages they
    complete, through `cb_fun`:

      * `cb_fun.(:msg, message)`      — one complete SIP message;
      * `cb_fun.(:ping, "")`          — a CRLF keep-alive (RFC 5626 §4.4.1);
      * `cb_fun.(:too_large, hdrs)`   — refused, answer **513** then CLOSE;
      * `cb_fun.(:bad_frame, hdrs)`   — unframeable, answer **400** then CLOSE.

    On both refusals `hdrs` is the complete header block when there is one — a SIP
    message without a body, so it parses, and a response can be built from it — or
    `""` when the peer had not even finished its headers. The returned struct is
    then in state `:refused` and frames nothing more: the connection is on its way
    down, and the bytes still arriving on it are not a message.

    Closing is not a severity judgement, it is the only in-sync option left. The
    depacketizer refuses precisely by NOT reading the octets Content-Length
    announced, so there is no point further down the stream where it could pick up
    again. A message that framed correctly and is merely too big for the parser is
    the other case entirely: the transport answers 513 and KEEPS the connection,
    because the stream is still in step and every other dialog riding it is fine.
    """
    def on_data_received(buf = %Depack{ state: :refused }, _data, _cb_fun), do: buf

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
        # Not one CRLF yet, so not even a first line — and nothing to answer with.
        # A peer that never sends one would otherwise be accumulated for as long as
        # it keeps writing: this is the state where a plain flood lands.
        refuse_if_past_bound(buf, "", cb_fun)
      end
    end

    def on_data_received(buf = %Depack{}, data, cb_fun) when is_binary(data) and is_function(cb_fun) and buf.state == :reading_headers do
      buf = %Depack{ buf | buffer: buf.buffer <> data } # Accumulate
      # IO.puts("reading_headers !")
      if String.contains?(buf.buffer,"\r\n\r\n") do
        [ headers, rest ] = String.split(buf.buffer, "\r\n\r\n", parts: 2)

        # Remove first line
        [ _first_line | header_lines ] = String.split(headers, "\r\n")

        case parse_and_get_clen(header_lines) do
          { :ok, 0 } ->
            # This SIP message has no body. Pass it to the transaction layer
            # IO.puts("Message complete !")
            cb_fun.(:msg, headers)

            # Reset the buffer
            buf = %Depack{ buf | state: :wait_for_msg, buffer: "", clen: 0 }
            # Handle the rest
            on_data_received(buf, rest, cb_fun)

          { :ok, clen } ->
            # The bound is applied to the length the peer DECLARES, the moment the
            # header block ends and before one body octet is buffered. That is what
            # turns an announced gigabyte into 450 bytes of work — and it is also
            # what bounds :reading_body, which then needs no check of its own:
            # `body` is only kept while it is SHORTER than `clen`, and `clen` cannot
            # exceed the bound past this point. Checking the accumulated body
            # against the bound instead would refuse wrongly, since a single read
            # legitimately carries the next pipelined messages too.
            if clen > SIPMsg.max_message_size() do
              refuse(buf, :too_large, headers, cb_fun, "Content-Length: #{clen} announced")
            else
              buf = %Depack{ buf | state: :reading_body, buffer: headers, clen: clen, body: "" }
              on_data_received(buf, rest, cb_fun)
            end

          :invalid ->
            # No usable Content-Length: the end of this message is unknowable, so
            # every octet after it would be read at the wrong offset. 400, not 513
            # — the message is malformed, not oversized.
            refuse(buf, :bad_frame, headers, cb_fun, "no usable Content-Length")
        end
      else
        # A header block that has not ended yet is the only thing this state can
        # bound, Content-Length being unknown before the blank line. It used to be
        # checked on the whole accumulated buffer, so a 13 kB message arriving in
        # one read tripped it on its BODY.
        refuse_if_past_bound(buf, "", cb_fun)
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

    # Accumulation is bounded in the two states that cannot know where the message
    # ends yet. Neither has a complete header block, so neither can be answered:
    # the peer gets the close and nothing else.
    defp refuse_if_past_bound(buf, headers, cb_fun) do
      if Kernel.byte_size(buf.buffer) > SIPMsg.max_message_size() do
        refuse(buf, :too_large, headers, cb_fun,
          "#{Kernel.byte_size(buf.buffer)} bytes buffered with no message boundary")
      else
        buf
      end
    end

    defp refuse(buf, what, headers, cb_fun, detail) do
      Logger.warning([module: __MODULE__, message: "#{what}: #{detail} (bound " <>
        "#{SIPMsg.max_message_size()} bytes) — refusing to frame further, the " <>
        "connection goes down"])

      cb_fun.(what, headers)
      %Depack{ buf | state: :refused, buffer: "", body: "", clen: 0 }
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
          versions: [:"tlsv1.2"], # Spécifie la version de TLS à utiliser
          # Cipher suites are configurable via :elixip2/:tls_ciphers; @tls_ciphers is the default.
          ciphers: Application.get_env(:elixip2, :tls_ciphers, @tls_ciphers),
          timeout: timeout,
          mode: :active
        ] ++ client_cert_options() ++ peer_verification_options(state)

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

    @doc false
    # Whether this leg checks the certificate the peer presents, and against what.
    #
    # **Off unless asked for.** Verifying a peer is an interconnect agreement, not a
    # socket setting: it presumes a named authority both sides accepted, and a node
    # cannot decide on its own that yesterday's working link should stop carrying
    # calls. `:tls_verify` is therefore opt-in, and turning it on is the same
    # deliberate act as putting a client certificate on the wire.
    #
    # It is nonetheless the half that gives the other one its worth. A listener
    # demanding a client certificate while its own outbound leg verifies nothing is
    # theatre: the mutual guarantee is worth exactly what the weaker direction is
    # worth. Whoever turns on `verify: :required` for inbound turns this on too.
    #
    # **The name checked is the SIP domain, never the address.** RFC 5922 §7.2 is
    # explicit: the identity in the certificate is the domain the URI named, and a
    # SIP proxy is reached at an address that DNS chose. Passing the domain as SNI
    # is what makes the check both correct and possible — without it OTP falls back
    # to the address we dialled, which needs an iPAddress SAN almost no SIP
    # certificate carries.
    #
    # Two keys:
    #
    #  * `:tls_verify` — `true` checks the peer's certificate.
    #  * `:tls_cacertfile` — the authority to trust, which is normally the point of
    #    an interconnect. Naming one trusts **only** it; absent, the public bundle
    #    is trusted (socket2's default).
    def peer_verification_options(state) do
      case Application.get_env(:elixip2, :tls_verify, false) do
        true ->
          [verify: true] ++ authorities_option() ++ server_name_option(state)

        _ ->
          [verify: false]
      end
    end

    defp authorities_option() do
      case Application.get_env(:elixip2, :tls_cacertfile) do
        path when is_binary(path) -> [authorities: [path: path]]
        _ -> []
      end
    end

    # No domain — a leg aimed at a bare address — leaves the reference identity to
    # OTP, which then matches against that address. Said out loud: it is the case
    # that needs an iPAddress SAN, and the one an operator will otherwise diagnose
    # as "TLS is broken".
    defp server_name_option(state) do
      case Map.get(state, :destdomain) do
        domain when is_binary(domain) and domain != "" ->
          [server_name: domain]

        _ ->
          Logger.debug([
            module: __MODULE__,
            message:
              "outbound TLS with no domain to verify against: the certificate will " <>
                "have to carry the address in an iPAddress SAN"
          ])

          []
      end
    end

    @doc false
    # What to add to a failed outbound TLS/WSS connection's log line.
    #
    # `Socket.Error` keeps only its message, not the reason, so the cause cannot be
    # matched on — and sniffing prose for "certificate" would be a guess. So this
    # claims only what is true: verification is on, and here are the two keys that
    # decide it. Silent when it is off, where the certificate cannot be the cause.
    def connect_failure_hint() do
      if Application.get_env(:elixip2, :tls_verify, false) do
        " (the peer's certificate is checked because :elixip2, :tls_verify is on: " <>
          "trust its authority with :elixip2, :tls_cacertfile, or turn the check off)"
      else
        ""
      end
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
    can act (design docs/design/DESIGN-SIPSTACK.md#57-resilience, R4).

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

        { :msg_too_large, parsed_msg } ->
          refuse_too_large(state, parsed_msg, tp_name, destip, destport)

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

    # A message past `SIPMsg.max_message_size/0` is REFUSED, not dropped: RFC 3261
    # §21.4.11 defines 513 for exactly this and §8.2.1 requires an answer. Silence
    # is indistinguishable from a network outage at the far end, which then waits
    # out its Timer B — the screen-share re-INVITE of 2026-09-08 died that way, and
    # it took three evenings and five traces to see that nothing had been sent.
    #
    # This is the path for a message that FRAMED correctly and is only too big for
    # the parser, so the connection stays up: the stream is still in step, and the
    # other dialogs riding it are none of this message's business. On a stream
    # transport the depacketizer now refuses first (`refuse_and_close/6`); what
    # still arrives here is UDP and WSS, which have no framing layer.
    defp refuse_too_large(state, parsed_msg, tp_name, destip, destport) do
      case refusal_response(parsed_msg, 513, tp_name, destip, destport) do
        nil -> :ok
        msgstr -> send_outside_this_callback(msgstr, destip, destport, false)
      end

      { :noreply, state }
    end

    @doc """
    Answer what the depacketizer would not frame, then take the connection down.

    Called from a stream transport's own callback on `:too_large` / `:bad_frame`
    (see `SIP.Transport.Depack.on_data_received/3`). `headers` is the complete
    header block, or `""` when the peer had not finished its headers — then there
    is nothing to answer with and only the close happens.

    The close is not severity, it is the only in-sync option: refusing means
    deliberately NOT reading the octets Content-Length announced, so no later
    offset in the stream is a message boundary any more. The transport's
    `terminate/1` tells the dialogs riding the connection (`notify_transport_down/2`),
    so they tear down instead of hanging.
    """
    @spec refuse_and_close(map(), 400 | 513, binary(), binary(), any(), any()) :: :ok
    def refuse_and_close(_state, code, headers, tp_name, destip, destport) do
      msgstr =
        try do
          case SIPMsg.parse(headers, fn _c, _m, _l, _li -> nil end) do
            # The parse code is deliberately NOT required to be :ok. `:missing_body`
            # is the expected answer here — the header block announces octets we
            # chose not to read — and a malformed Content-Length stops the parse on
            # the very header that made us refuse. What matters is whether enough of
            # the request survived to answer it. The request is NOT dispatched
            # either way: it was never received in full.
            { _parse_code, parsed_msg } ->
              if answerable?(parsed_msg) do
                refusal_response(parsed_msg, code, tp_name, destip, destport)
              end

            _ -> nil
          end
        rescue
          e ->
            # Composing the answer must never be what keeps the connection open.
            Logger.warning([module: __MODULE__, message: "#{tp_name}: cannot compose the " <>
              "#{code} for #{peer_str(destip, destport)} (#{Exception.message(e)})"])
            nil
        end

      if is_nil(msgstr) do
        Logger.warning([module: __MODULE__, message: "#{tp_name}: closing the connection to " <>
          "#{peer_str(destip, destport)} unanswered — nothing parseable to answer"])
      end

      send_outside_this_callback(msgstr, destip, destport, true)
    end

    # Enough of the request survived the parse to be answered: a response is built
    # out of these five headers and nothing else (§8.2.6.2, and `@reply_filter`).
    # Checked rather than assumed, because a refusal is composed from a PARTIAL
    # parse on purpose.
    defp answerable?(msg) do
      is_map(msg) and is_atom(Map.get(msg, :method)) and
        Enum.all?([ :via, :to, :from, :callid, :cseq ], &Map.has_key?(msg, &1))
    end

    # Which refusal a message gets, and the log line that says why. A response and
    # an ACK are never answered — there is nothing to answer a response with, and
    # §17.1.1.3 forbids answering an ACK — so both come back `nil`.
    defp refusal_response(parsed_msg, code, tp_name, destip, destport) do
      cond do
        # A response carries `method: false`, and `false` is itself an atom.
        parsed_msg.method == false or not is_atom(parsed_msg.method) ->
          Logger.warning([module: __MODULE__, message: "#{tp_name}: dropping an oversized " <>
            "SIP response from #{peer_str(destip, destport)} — a response is never answered"])
          nil

        parsed_msg.method == :ACK ->
          Logger.warning([module: __MODULE__, message: "#{tp_name}: dropping an oversized " <>
            "ACK from #{peer_str(destip, destport)} — an ACK is never answered"])
          nil

        true ->
          Logger.warning([module: __MODULE__, message: "#{tp_name}: #{parsed_msg.method} from " <>
            "#{peer_str(destip, destport)} #{refusal_reason(code)}, answering #{code}"])

          SIPMsg.serialize(SIP.Msg.Ops.reply_to_request(parsed_msg, code, nil))
      end
    end

    defp refusal_reason(513), do: "past the #{SIPMsg.max_message_size()} byte bound"
    defp refusal_reason(400), do: "unframeable"
    defp refusal_reason(_code), do: "refused"

    # `send_msg/4` is a GenServer.call on this transport, and we are running inside
    # that very transport's callback: calling it here deadlocks the socket for the
    # call timeout, then raises. A one-shot process borrows the transport's own send
    # path instead, so the refusal is framed and logged like every other response it
    # emits, on all four transports.
    #
    # It is also what keeps "answer, THEN close" in that order. Stopping the
    # transport from the callback would close the socket with the response still
    # queued behind us, and the peer would read a reset instead of a reason.
    defp send_outside_this_callback(msgstr, destip, destport, close?) do
      tid = self()
      port = if is_integer(destport), do: destport, else: 0

      spawn(fn ->
        if msgstr, do: SIP.Transport.send_msg(tid, msgstr, destip, port)

        if close? do
          try do
            GenServer.stop(tid, :normal)
          catch
            :exit, _ -> :ok
          end
        end
      end)

      :ok
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
  def build_contact_uri(tmod, tid), do: build_contact_uri(tmod, tid, nil)

  @doc """
  The address to publish towards `peer_ip`, given the address we are bound to.

  One interface can have two faces: a 1:1 NAT gives a host a private address and
  peers outside reach a public one. `advertise` on a `[[listen]]` block names that
  public alias, and this is where it is applied — **not** in the transport, which
  must keep answering the address it is really bound to (the media layer reads it
  to choose an interface, and a comparison against a real socket has to hold).

  Which face a peer sees follows from which side it sits on:

    * `:public` — the alias, when one was declared for this bound address;
    * `:internal` — the bound address itself. A peer inside reaches it directly,
      and handing it the public alias would send its in-dialog requests through
      the NAT and back, when the router hairpins at all.

  A peer whose address is unknown gets the alias, which is what a flat
  substitution would have done: a NATed deployment serves mostly outside peers,
  and the private address would break them.
  """
  @spec publish_ip(:inet.ip_address() | binary(), :inet.ip_address() | nil) ::
          :inet.ip_address() | binary()
  def publish_ip(bound, peer_ip) when is_tuple(bound) do
    case Application.get_env(:elixip2, :advertise_map, %{}) do
      map when map == %{} ->
        bound

      map ->
        case Map.fetch(map, bound) do
          {:ok, alias_ip} -> if internal_peer?(peer_ip), do: bound, else: alias_ip
          :error -> bound
        end
    end
  end

  # WSS answers a dialled hostname rather than a tuple on some paths; there is
  # nothing to substitute for a name.
  def publish_ip(bound, _peer_ip), do: bound

  defp internal_peer?(peer_ip) when is_tuple(peer_ip),
    do: SIP.NetUtils.net_side(peer_ip) == :internal

  defp internal_peer?(_peer_ip), do: false

  @doc """
  The address and port to publish towards `peer_ip` on the transport `tid`.
  """
  @spec local_ip_for_peer(pid(), :inet.ip_address() | nil) ::
          {:ok, :inet.ip_address() | binary(), integer()} | any()
  def local_ip_for_peer(tid, peer_ip) do
    case get_local_ip_port(tid) do
      {:ok, bound, port} -> {:ok, publish_ip(bound, peer_ip), port}
      err -> err
    end
  end

  @doc """
  The Contact to publish towards `peer_ip`.

  Same as `build_contact_uri/2` except for the address: `publish_ip/2` decides
  which of ours this peer can reach. Pass the peer whenever it is known — a
  Contact aimed at an address the peer has no route to is a dialog whose BYE
  never arrives.
  """
  @spec build_contact_uri(module(), pid(), :inet.ip_address() | nil) :: %SIP.Uri{} | nil
  def build_contact_uri(tmod, tid, peer_ip) do
    case get_local_ip_port(tid) do
      { :ok, bound, localport } ->
        localip = publish_ip(bound, peer_ip)
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
    add_contact_header(build_contact_uri(tmod, tid, peer_of(msg)), msg)
  end

  # No local address to advertise: leave the message as it stands rather than
  # stamp a Contact we cannot fill in. The send that follows will fail on its own,
  # through the error path, which is where a dead transport belongs.
  # Who this message is going to, when the message itself says. An outbound
  # REQUEST carries its resolved destination in the R-URI; a RESPONSE goes back to
  # where its request came from, which the transport stamped into that same field
  # when it received it. Both are the same field, which is why one clause covers
  # them. `nil` when nothing says, and the alias is then published.
  defp peer_of(%{ruri: %SIP.Uri{destip: ip}}) when is_tuple(ip), do: ip
  defp peer_of(_msg), do: nil

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
