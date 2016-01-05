defmodule SIP.Packet do
	@moduledoc """
	SIP parser. The parse() function analyze a binary and create a Packet structure that will be used
	by other SIP modules. The serialize function turn a packet structure into a binary ready to be send
	by a SIP transport
	"""
	
	@doc """
	SIP message structure that is filled when parsing a SIP message
	
	It holds the request URI (ruri), method and response code.
	It holds the message body if any
	It holds a dictionary of headers
	It also holds tranport parameter such as source IP (src_ip)/ port (src_port), transport protocol (transport)
	Finally: branch is a field used by the transaction layer to store the transaction ID for outgoing SIP requests
	and the transport layer is responsible of creating the proper via header
	"""
	defstruct method: nil, ruri: nil, headers: nil, is_request: true, response_code: nil, reason: nil, 
					  body: nil, transport: :sip_udp, dst: nil, dstlist: [], dst_port: 5060, src_ip: nil, src_port: 0,
					  branch: nil, packet_bytes: nil
	
	@doc """
	Parse a SIP message as received by the transport layer.
	"""
	def parse( data, transport ) when is_binary(data) do
		[ fline, rest ] = String.split( data, << 13, 10 >>, parts: 2)
		p1 = parseFirstLine( String.split( fline ) )
		{ body, hlist } = Dict.pop( parseHeaders( rest ), :body )
		
		%SIP.Packet{ p1 | headers: hlist, body: body, transport: transport }
	end

	@doc """
	Serialize a SIP packet into a binary ready to be sent
	"""
	def serialize( packet ) do
		header_order = [ :Via, "Record-Route", :Route, :From, :To ]
		
		if packet.is_request do
			fl = Atom.to_string(packet.method) <> " " <> packet.ruri.serialize() <> " SIP/2.0"
		else
			fl = "SIP/2.0 " <> Integer.to_string(packet.response_code) <> " " <> packet.reason 
		end
		
		data = fl <> << 13,10 >> <> serializeHeaders( packet.headers, header_order )
		if packet.body != nil do
			sizestr = Integer.to_string(byte_size(packet.body))
			data <> "Content-Size: " <> sizestr <> << 13,10 >> <> packet.body
		else
			data
		end
	end
	
	@doc """
	Serialize a SIP packet into a binary and store serialized
	packet data inside packet structure
	"""
	def serialize2( packet ) do
		%SIP.Packet{ packet | packet_bytes: packet.serialize() }
	end
	
	@doc """
	Create a reply statelessly
	"""
	def reply(packet, code, reason, ua) when is_integer(code) do
		# Todo if reason is nil, use default reason
		if code >= 100 && code < 700 do
			p = %SIP.Packet{ packet | is_request: false, response_code: code, reason: reason, packet_bytes: nil }
			p = setHeaderValue(p, "User-Agent", ua)
			
		else
			raise "Invalid reply code"
		end
	end
	
	def getHeaderValue(packet, hKey) do
		if packet.headers != nil do
			vallist = Dict.get(packet.headers, headerKey(hKey) )
			case vallist do
				nil -> nil
				[ val ] -> val
				_ -> vallist
		else
			nil
		end
	end
	
	def popHeaderValue(packet, hKey)
		value = getHeaderValue(packet, hKey)
		cond do
			value == nil 	-> packet
			is_list(value)	-> setHeaderValue(packet, hKey, tl value)
			true ->			-> setHeaderValue(packet, hKey, no)
		end
	end
	
	
	defp getHeaderDict(packet)
		if packet.headers == nil do
			hl = HashDict.new
		else
			hl = packet.headers
		end
	end
	
	@doc """
	Set the value of a packet header or erases an header entirely (if value is nil)
	"""
	def setHeaderValue(packet, hKey, nil) do
		hl = packet.getHeaderDict()
		%SIP.Packet{ packet | headers: Dict.remove(hl, headerKey(hKey)) }
	end
	
	def setHeaderValue(packet, hKey, []) do
		hl = packet.getHeaderDict()
		%SIP.Packet{ packet | headers: Dict.remove(hl, headerKey(hKey)) }
	end

	def setHeaderValue(packet, hKey, value) when is_list(value) do
		hl = packet.getHeaderDict()
		%SIP.Packet{ packet | headers: Dict.put(hl, headerKey(hKey), value ) }
	end
	
	def setHeaderValue(packet, hKey, value) when is_binary(value) or is_integer(value) do 
		hl = packet.getHeaderDict()
		%SIP.Packet{ packet | headers: Dict.put(hl, headerKey(hKey), [ value ]) }
	end
	
	def setHeaderValue(packet, hKey, value) when is_map(value) do 
		hl = packet.getHeaderDict()
		%SIP.Packet{ packet | headers: Dict.put(hl, headerKey(hKey), [ value ]) }
	end
		
	def addHeaderValue(packet, headerKey, value, option) do
		hl = packet.getHeaderDict()		
		
		vallist = Dict.get(packet.headers, headerKey(hKey) )
		
		if not is_list(value) do
			value = [ value ]
		end
		
		if vallist == nil do
			vallist = value
		else
			case option do
				:append -> vallist = [ vallist | value ]
				:prepend -> vallist = [ value | vallist ]
			end
		end
		
		%SIP.Packet{ packet | headers: Dict.put(hl, headerKey(hKey), value ) }
	end
	
	@spec generateTag( t, String.t | Atom.t ) :: t
	def generateTag( packet, header )
		case header do
			:From -> from = packet.getHeaderValue(header),
					if from != nil do
						from.setParam( "tag", genTag() )
						packet = packet.setHeaderValue(header, from)
					end 
					
			:To -> 
				to = packet.getHeaderValue(header),
				if to != nil do
					to.setParam( "tag", genTag() )
					packet = packet.setHeaderValue(header, to)
				end 
			
			"Call-ID" -> 
				cid = packet.getHeaderValue(header),
				if cid == nil do
					packet = packet.setHeaderValue(header, genHash() )
				end
				
			:Via ->
				if packet.branch == nil do
					packet = %SIP.Packet{ packet | branch: genTag() }
				end
		end
		packet
	end
	
	@spec getDialogId( t ) :: {String.t, String.t, String.t}
	def getDialogId(packet) do
		from = packet.getHeaderValue(:From)
		to = packet.getHeaderValue(:To)
		callid = packet.getHeaderValue("Call-ID")
		
		if from == nil or to == nil do
			raise "Missing From or To header. Invalid SIP packet"
		end
		
		{ from.getParam("tag"), callid, from.getParam("to") }
	end
	
	
	
	#---------------- private functions (implementation) ---------------------

	defp parseMethod( method ) do
		case method do
			"INVITE" -> :INVITE
			"UPDATE" -> :UPDATE
			"OPTIONS" -> :OPTIONS
			"MESSAGE" -> :MESSAGE
			"INFO" -> :INFO
			"SUBSCRIBE" -> :SUBSCRIBE
			"NOTIFY" -> :NOTIFY
			"PUBLISH" -> :PUBLISH
			_ -> raise "Unrecognized SIP method"
		end
	end
	
	defp parseFirstLine( [ method, ruri, "SIP/2.0" ] ) do			
		%SIP.Packet{ method: parseMethod(method), ruri: SIP.URI.parse(ruri), is_request: true }
	end

	defp parseFirstLine( [ "SIP/2.0", codestr, reason ] ) do
		code = String.to_integer(codestr)
		if code < 100 or code > 699 do
			raise "Invalid SIP response code"
		else
			%SIP.Packet{ is_request: false, response_code: code, reason: reason }
		end
	end
			
	defp headerKey( headerName ) do
		case headerName do
			"From" 	-> :From
			"f" 	-> :From
			"Via" 	-> :Via
			"To"	-> :To
			"t"		-> :To
			"Route" -> :Route
			"Record-Route" 	-> :RecordRoute
			"CSeq"			-> :CSeq
			"c"			-> :CSeq
			"Contact"		-> :Contact
			"Call-ID"		-> :CallID
			"Allow"			-> :Allow
			_		-> headerName
		end
	end
	
	defp parseHeaders( [] ) do
		HashDict.new
	end
	
	defp parseHeaders( headers ) when is_binary(headers) do
		header_plus_rest = String.split( headers, << 13, 10 >>, parts: 2)
		header = String.split( hd(header_plus_rest), ":", parts: 2)
		parseHeaders( header, tl header_plus_rest )
	end

	defp parseHeaders( [ "" ], [ body ] ) do
		hlist = HashDict.new
		Dict.put(hlist, :body, body)
	end
	
	defp parseHeaders( [ headerName, value ], [rest] ) do
		key = headerKey( headerName )
		hlist = parseHeaders( rest )
		
		if key in [:From, :To, :Contact ] do
			if val2 == nil do
				hlist = Dict.put(hlist, key, [ SIP.URI.parse(value) ])
			else
				raise "Several #{Key} headers. Invalid SIP packet"
			end
		else
			val2 = Dict.get(hlist, headerName, [])
			parsed_val = String.split( value, ",", trim: true )
			Dict.put(hlist, key, [ parsed_val | val2 ] )
		end		
	end

	defp genHash( src ) do
		:crypto.hash(:md5, src) |> Base.encode64 |> String.strip ?=
	end
	
	defp genTag() do
		Integer.to_string(abs(:erlang.unique_integer))
	end

	defp genHash() do
		genHash( genTag() )
	end
	
	defp serializeValue( val ) when is_map(val) do
		if val.__struct__ == "SIP.URI" do
			val.serialize()
		else
			val
		end
	end

	defp serializeValue( val ) when is_list(val) do
	
	end
	
	defp serializeValue( val ) do
		val
	end
	
	defp serializeHeader( { key, val }, valsep ) do
		cond do
		
			# Those are URIs
			key in [ :From, :To, :Contact ] -> 
				Atom.to_string(key) <> ": " <> val.serialize()
				
			# key is an atom
			is_atom(key) -> Atom.to_string(key) <> ": " <> serializeValue(x)
			
			
		if is_atom(key) do
			keystr = Atom.to_string(key) <> ": "
		else
			keystr = key <> ": "
		end
		
		if is_list(val) do
			#Repeat the same header for each value
			#multiheaders = Enum.map( val, fn(x) -> data <> serializeValue(x) end )
			multiheaders = for x <- val, do: keystr <> serializeValue(x)
			Enum.join(multiheaders, valsep)
		else
			keystr <> serializeValue(val)
		end			
	end
	
	defp serializeHeaders( [] ) do
	end
	
	defp serializeHeaders( headers ) when is_list(headers) do
		h2 = Enum.map(headers, fn({k,v}) -> serializeHeader({k,v}, <<13,10>>) end)
		data = Enum.join( h2, << 13,10 >> )
	end

	# When no ordered headers remain, serialize remaining headers
	defp serializeHeaders( headers, [] ) do
		# Do not include Content-Size. Header will be added at the end
		# of serialization		
		serializeHeaders( Dict.to_list(Dict.delete(headers, "Content-Size")) )
	end
	
	# Recursive serialization of ordered headers
	defp serializeHeaders( headers, order ) when is_list(order) do
		k = hd order
		if Dict.has_key?(headers, k) do
			{ v, headers } = Dict.pop(headers, k)
			serializeHeader( { k, v } ) <> << 13,10 >> <> serializeHeaders(headers, tl order)
		else
			serializeHeaders(headers, tl order)
		end
	end 
end