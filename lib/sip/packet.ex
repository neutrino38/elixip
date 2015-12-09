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
	It holds a dictionary of
	"""
	defstruct method: nil, ruri: nil, headers: nil, is_request: true, response_code: nil, reason: nil, 
					  body: nil, transport: :sip_udp, dst: nil, dstlist: [], src_ip: nil, src_port: 0,
					  trans_id: nil
	
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
			fl = Atom.to_string(packet.method) <> " " <> packet.ruri <> " SIP/2.0"
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
	def setHeaderValue(packet, headerKey, value) do
	
		if packet.headers == nil do
			hl = HashDict.new
		else
			hl = packet.headers
		end

		if is_list(value) do
			hl = Dict.put(hl, headerKey(hKey), value )
		else
			hl = Dict.put(hl, headerKey(hKey), [ value ] )
		end
		
		%SIP.Packet{ packet | headers: hl }
	end
	
	def addHeaderValue(packet, headerKey, value) do
		if packet.headers == nil do
			hl = HashDict.new
		else
			hl = packet.headers
		end
		
		vallist = Dict.get(packet.headers, headerKey(hKey) )
		
		if not is_list(value) do
			value = [ value ]
		end
		
		if vallist == nil do
			vallist = value
		else
			vallist = [ vallist | value ]
		end
		
		hl = Dict.put(hl, headerKey(hKey), value )
		
		%SIP.Packet{ packet | headers: hl }
	end
			
	
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
		%SIP.Packet{ method: parseMethod(method), ruri: ruri, is_request: true }
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
		parsed_val = String.split( value, ",", trim: true )
		hlist = parseHeaders( rest )
		if Dict.has_key?(hlist, key) do
			val2 = Dict.get(hlist, headerName)
			Dict.put(hlist, key, [ parsed_val | val2 ] )
		else
			Dict.put(hlist, key, parsed_val )
		end
	end

	
	defp serializeValue( val ) do
		val
	end
	
	defp serializeHeader( { key, val }, valsep ) do
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