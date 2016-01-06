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
	
	defp getTransactionKey(packet)
		if packet.is_request do
			# UAS transaction: user
			#
			# UAS-call-id-totag-branchid
	end
	
	# Main loop of UDP SIP listener
	defp udpLoop( parameters, routing_rules, blacklist, transaction_list, dialog_list ) do
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
				processPacket(parameters, socket, routing_rules, blacklist, transaction_list, , dialog_list, addr, portNo, data)
			
			# packet to be send
			{:sip_out, packet, session_pid} -> sendPacket(parameters, packet, session_pid)

			{:sip_out, packet } -> sendPacket(parameters, packet)
			
			# Register a SIP application in this listener and specify the routing criterias
			{:register_app, app_type, src_net, dst_net, domain_rule, user_rule, app_pid } ->
				routing_rules = [ routing_rules | { app_type, src_net, dst_net, domain_rule, user_rule, app_pid }]
				
			{:unregister_app, app_pid } -> 
				routing_rules = Enum.filter(routing_rules, 
											fn(rule) -> elem(rule,6) == app_pid end )
			
			# Remove transaction for SIP transmission layer
			{ :transaction_remove, key, trans_id } -> 
				transaction_list = Dict.delete(transaction_list, key)
				
			# Add transaction
			{ :transaction_add,  key, trans_pid } -> 
				transaction_list = Dict.put(transaction_list, key, trans_pid)
				
			{ :dialog_add, key, dialog_id } ->
				dialog_list = Dict.put(dialog_list, key, dialog_pid)
				
			{ :dialog_remove, key } ->
				dialog_list = Dict.put(dialog_list, key, dialog_pid)
		end
		
		udpLoop( parameters, routing_rules, blacklist, transaction_list )
	end

	# Parse the SIP packet (data) and dispatch it to the proper process
	#
	# If the dialog
	
	defp processPacket(parameters, socket, routing_rules, blacklist, transaction_list, dialog_list, src_addr, src_port, tranport, data) do
	
		psip = SIP.Packet.parse(data)
		
		# Add local address and port, remote addresses and port as well as transport
		case :inet.sockname( socket ) do
			{ :ok, { dst_addr, dst_port } } -> psip = %SIP.Packet{psip | src_ip: src_addr, src_port: src_port, dst: dst_addr, 
			                                                      dst_port: dst_port, transport: transport }
			_ -> raise "Failed to get local address"
		end
		
		trans_id = nil
		rule = nil
		dialog_id = Dict.get(dialog_list, p.getDialogId())
		
		if p.is_request do
			t_key = SIP.Transaction.compute_transaction_key(p, "uas")
		else
			t_key = SIP.Transaction.compute_transaction_key(p, "uac")
		end
		
		# Ckeck if packet is attached to an existing transaction
		trans_id = Dict.get( transaction_list, t_key )
		if trans_id != nil and ! Process.alive?(trans_id) do
			if p.is_request do
				Process.send( self(), { :uas_transaction_remove, t_key } )
			else
				Process.send( self(), { :uac_transaction_remove, t_key } )
			end
			trans_id = nil
		end
		
		# Check if pacjet can be dispatched by an application rule
		if trans_id == nil and dialog_id == nil do
			rule = RoutingRules.matchRule( routing_rules, packet)
			if rule != nil and ! Process.alive?(rule) do
				rule = nil
			end
		end
			
			
		cond do
			# Blacklisted ? If yes reject
			check_blacklist(blacklist, src_ip) ->
				rep = packet.reply(403, "Blacklisted", @sip_default_ua),
				Process.send( self(), { :sip_out, p } )
			
			# If packet is in active transaction, send it
			trans_id != nil ->  Process.send( trans_id, { :sip_in, psip } )
			
			# If packet is in an active dialog
			dialog_id != nil ->  Process.send( dialog_id, { :sip_in, psip } )

			# If packet is an ACK and does not match any rule or session, ignore it
			packet.method == :ACK -> nil
	
			# If the packet matches a routing rule, send it to the proper application
			rule != nil -> Process.send( rule, { :sip_in, psip } )
			
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