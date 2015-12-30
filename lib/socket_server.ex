defmodule SipServer do
	@sip_default_port	5060
	@sip_default_ws_port	8080
	@sip_default_wss_port	8443
	
	def init() do
		init(@sip_default_port, @sip_default_ws_port, @sip_default_wss_port)
	end
	
    def init(sip_port, ws_port, wss_port ) do
	   socket = Socket.UDP.open!(sip_port)
	   IO.puts "Socket server open on port #{sip_port}"
	   params = %{ "socket" => socket }
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
		contactUri = SIP.URI{ username: user, domain: Address.to_string(addr), port: port }
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

			# Data received on fhte UDP socket
			{:udp, socket, addr, portNo, data} -> 
				IO.puts "SIP packet from " <> Socket.Address.to_string(addr),
				processPacket(parameters, routing_rules, blacklist, call_list, addr, portNo, data)
			
			{:sip_out, packet, session_pid} -> sendPacket(parameters, packet, session_pid)

			{:sip_out, packet } -> sendPacket(:sip_out, packet, session_pid) -> sendPacket(parameters, packet)
			
			# Register a SIP application in this listener and specify the routing criterias
			{:register_app, app_type, src_net, dst_net, domain_rule, user_rule, app_pid }
				-> routing_rules = [ routing_rules | { app_type, src_net, dst_net, domain_rule, user_rule, app_pid }]
				
			{:unregister_app, app_pid } -> 
				routing_rules = Enum.filter(routing_rules, 
											fn(rule) -> elem(rule,6) == app_pid end )
		end
		
		udpLoop( parameters, routing_rules, blacklist, call_list )
	end

	defp processPacket(parameters, routing_rules, blacklist, addr, portNo, packet) do
		case :inet.sockname( socket ) do
			{ :ok, { dst_addr, dst_port } } ->
			_ -> raise "Failed to get local address"
		end

		psip = SIP.Packet.parse(packet)
		psip = %SIP.Packet{psip | src_ip: addr, src_port: portNo, dst: dst_addr, dst_port: dst_port }
		
		sess_pid = Dict.get( psip.getDialogId() )
		if sess_pid != nil do
			# If packet is in active session, forward it to active session
			Process.send( sess_pid, { :sip_in, psip } )
		else
			# If the packet is a request but SIP dialog is not registered yet,
			# find the PID of the app that can handle it according to the routing rules
			
			if packet.is_request do
				matches = RoutingRules.matchRule( routing_rules, )
			end
		end
			
	end
	
	defp sendPacket( parameters, packet, session_pid) do
		{ rez, packet, parameters } = sendPacket( parameters, packet)
		Process.send( session_pid, { :sip_out, rez, packet} )
		{ packet, parameters }
	end
	
	defp sendPacket( parameters, packet )
		{ rez, packet, dnscache } = SIP.Resolver( parameters.dnscache, packet )
		
		if rez == :ok do
			#Check if packet has already been serialized. If not add headers
			# Add headers
			if packet.packet_bytes == nil do
				# Get local IP and port
				case :inet.sockname( socket ) do
					{ :ok, { addr, port } } ->
					_ -> raise "Failed to get local address"
				end

				# Add header
				packet = addViaHeader( packet, parameter.socket, addr, port ) 
				packet = addContact( packet, parameter.socket , addr, port)
				
				# Serialize 
				packet = packet.serialize2()
			end
			parameter.socket.send(packet.packet_bytes, packet.dst)
		else
			{ rez, packet, parameter }
		end
	end
end