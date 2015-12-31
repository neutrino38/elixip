defmodule SipServer do
	@sip_default_port	5060
	@sip_default_ws_port	8080
	@sip_default_wss_port	8443
	@sip_default_ua			"EliXIP/0.1"
	
	def init() do
		init(@sip_default_port, @sip_default_ws_port, @sip_default_wss_port)
	end
	
    def init(sip_port, ws_port, wss_port ) do
	   socket = Socket.UDP.open!(sip_port)
	   IO.puts "Socket server open on port #{sip_port}"
	   params = %{ "socket" => socket, "ua" => @sip_default_ua }
	   pid = spawn_link udpLoop( params, nil, nil )
	   Socket.UDP.process(socket, pid )
	   Process.register(pid, :sip_udp_transport)
	end

	defp get
	
	defp addViaHeader( packet, socket, addr, port ) do		
		via = "SIP/2.0/UDP " <> Address.to_string(addr)
		if port == 5060 do
			via = via <> Integer.to_string(port)
		end
		
		if packet.branch == nil do
			raise "No transaction ID for SIP request"
		else
			via = via <> ";branch=" <> packet.branch
		end

		packet.addHeaderValue("Via", via)
	end

	defp setContact( packet, socket, user, addr, port ) do
		contactUri = %SIP.URI{ username: user, domain: Address.to_string(addr), port: port }
		setHeaderValue(packet, "Contact", contactUri)
	end
	
	# Main loop of UDP SIP listener
	defp udpLoop( parameters, routing_rules, blacklist, call_list ) do
		IO.puts "Entering server loop in process #{self()}"

		receive do
		    :stop -> exit 1
			
			{:set_proxy, addr, portNo} -> 
				IO.puts "Proxy adresse #{addr} and port #{portNo}", 
				parameters = Dict.put(parameters, :proxyAddr, addr),
				parameters = Dict.put(parameters, :proxyPort, portNo)

			# Raw data received on from UDP socket
			{:udp, socket, addr, portNo, data} -> 
				IO.puts "SIP packet from " <> Socket.Address.to_string(addr),
				processPacket(parameters, socket, routing_rules, blacklist, call_list, addr, portNo, data)
			
			# packet to be send
			{:sip_out, packet, session_pid} -> sendPacket(parameters, packet, session_pid)

			{:sip_out, packet } -> sendPacket(parameters, packet)
			
			# Register a SIP application in this listener and specify the routing criterias
			{:register_app, app_type, src_net, dst_net, domain_rule, user_rule, app_pid }
				-> routing_rules = [ routing_rules | { app_type, src_net, dst_net, domain_rule, user_rule, app_pid }]
				
			{:unregister_app, app_pid } -> 
				routing_rules = Enum.filter(routing_rules, 
											fn(rule) -> elem(rule,6) == app_pid end )
		end
		
		udpLoop( parameters, routing_rules, blacklist, call_list )
	end

	# Parse the SIP packet (data) and dispatch it to the proper process
	#
	# If the dialog
	
	defp processPacket(parameters, socket, routing_rules, blacklist, call_list, src_addr, src_port, tranport, data) do
	
		psip = SIP.Packet.parse(data)
		
		# Add local address and port, remote addresses and port as well as transport
		case :inet.sockname( socket ) do
			{ :ok, { dst_addr, dst_port } } -> psip = %SIP.Packet{psip | src_ip: src_addr, src_port: src_port, dst: dst_addr, 
			                                                      dst_port: dst_port, transport: transport }
			_ -> raise "Failed to get local address"
		end
		
		sess_pid = Dict.get( call_list, psip.getDialogId() )
		
		cond do
			# Blacklisted ? If yes reject
			check_blacklist(blacklist, src_ip) -> rep = packet.reply(403, "Blacklisted", @sip_default_ua), 
			
			# If packet is in active session, forward it to active session
			sess_pid != nil ->  if Process.send( sess_pid, { :sip_in, psip } ) != :ok do
									Process.send( self(), { :session_remove, sess_pid } )
								end
		
			# If the packet matches a routing rule, send it to the proper application
			matches = RoutingRules.matchRule( routing_rules, packet) -> 
				if Process.send( matches, { :sip_in, psip } ) == :ok do
					nil
				else
					Process.send( self(), {:unregister_app, app_pid })
				end
					
					
			
			# If packet is an ACK and does not match any rule or session, ignore it
			packet.method == :ACK -> nil
			
			# If the packet does not match any routing rule, reply statelessly
			if packet.is_request ->
				rep = packet.reply(403, "Forbidden", @sip_default_ua),
				sendPacket(parameters, rep)
				
			true -> nil # Ignore packet in other cases
		end
	end
	
	defp sendPacket( parameters, packet, session_pid) do
		{ rez, packet, parameters } = sendPacket( parameters, packet)
		Process.send( session_pid, { :sip_out, rez, packet} )
		{ packet, parameters }
	end
	
	defp sendPacket( parameters, packet ) do
		{ rez, packet, dnscache } = SIP.Resolver.resolve( parameters.dnscache, packet )
		
		if rez == :ok do
			#Check if packet has already been serialized. If not add headers
			# Add headers
			if packet.packet_bytes == nil do
				# Get local IP and port
				case :inet.sockname( parameters.socket ) do
				    # Add via header if we can get local socket info
					{ :ok, { addr, port } } -> packet = packet.addViaHeader( addr, port )
					_ -> raise "Failed to get local address"
				end

				# Set Contact
				contact = %SIP.URI{ username: }
				packet = packet.setContact( addr, port )
				
				# Serialize 
				packet = packet.serialize2()
			end
			parameter.socket.send(packet.packet_bytes, packet.dst)
		else
			{ rez, packet, parameter }
		end
	end
end