defmodule SocketServer do

    def init do
	   socket = Socket.UDP.open!(10000)
	   IO.puts "Socket server open on port 10000"
	   params = %{ "socket" => socket }
	   pid = spawn_link udpLoop( params )
	   Socket.UDP.process(socket, pid )
	   Process.register(pid, :sip_udp_transport)
	end

	defp get
	
	defp addViaHeader( packet, socket, destination ) do
	end
	
	defp setContact
	
	defp udpLoop( parameters ) do
		IO.puts "Entering server loop in process #{self()}"

		receive do
		    :stop -> exit 1
			
			{:set_proxy, addr, portNo} -> 
				IO.puts "Proxy adresse #{addr} and port #{portNo}", 
				parameters = Dict.put(parameters, :proxyAddr, addr),
				parameters = Dict.put(parameters, :proxyPort, portNo)

			{:udp, socket, addr, portNo, packet} -> 
				IO.puts "SIP packet from " <> Socket.Address.to_string(addr),
				processPacket(socket, addr, portNo, packet)
			
			{:sip_out, packet, session_pid} -> sendPacket(parameters, packet, session_pid)

			{:sip_out, packet } -> sendPacket(:sip_out, packet, session_pid) -> sendPacket(parameters, packet)
			
		end
		
		udpLoop( parameters )
	end

	defp processPacket(parameters, addr, portNo, packet) do
		psip = SIP.Packet.parse(packet)
	end
	
	defp sendPacket( parameters, packet, session_pid) do
		{ rez, packet, parameters } = sendPacket( parameters, packet)
		Process.send( session_pid, { :sip_out, rez, packet} )
		{ packet, parameters }
	end
	
	defp sendPacket( parameters, packet )
		{ packet, dnscache } = SIP.Resolver( parameters.dnscache, packet )
		case :inet.sockname( parameter.socket ) do
			{ :ok, { addr, port } } ->
			_ -> raise "Failed to get local address"
			
		end
end