defmodule SIP.Packet do
	@moduledoc """
	SIP parser. The parse() function analyze a binary and create a Packet structure that will be used
	by other SIP modules. The serialize function turn a packet structure into a binary ready to be send
	by a SIP transport
	"""
	
	@max_body_len 			10000
	@max_nb_body_parts 		5
	
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
	@spec parse( String.t, pid ) :: t
	def parse( data, transport ) when is_binary(data) do
		[ fline, rest ] = String.split( data, << 13, 10 >>, parts: 2)
		p1 = parseFirstLine( String.split( fline ) )
		{ body, hlist } = Dict.pop( parseHeaders( rest ), :body )
		
		%SIP.Packet{ p1 | headers: hlist, body: body, transport: transport }
	end

	@doc """
	Serialize a SIP packet into a binary ready to be sent
	"""
	@spec parse( t ) :: String.t
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
	@spec serialize2( t ) :: t
	def serialize2( packet ) do
		%SIP.Packet{ packet | packet_bytes: packet.serialize() }
	end
	
	@doc """
	Create a reply statelessly
	"""
	@spec reply( t, int, String.t, String.t ) :: t
	def reply(packet, code, reason, ua) when is_integer(code) do
				
		if reason == nil do
			case code do
				100 -> reason = "Trying"
				180 -> reason = "Ringing"
				181 -> reason = "Call is Being Forwarded"
				182 -> reason = "Queued"
				183 -> reason = "Session in Progress"
				
				200 -> reason = "OK"
				202 -> reason = "Accepted"
				
				300 -> reason = "Multiple choices"
				301 -> reason = "Moved permanently"
				302 -> reason = "Moved temporarily"
				305 -> reason = "Use Proxy"
				
				400 -> reason = "Bad Request"
				401 -> reason = "Unauthorized"
			end
		end
		if code >= 100 && code < 700 do
			p = %SIP.Packet{ packet | is_request: false, response_code: code, reason: reason, packet_bytes: nil, body: nil }
			p = setHeaderValue(p, "User-Agent", ua)
			
		else
			raise "Invalid reply code"
		end
	end

	@doc """
	Create a 401 or 407 reply with challenge info
	"""
	@spec reply( t, int, String.t, String.t, String.t ) :: t
	def challenge(packet, code, realm, algorithm, ua) when is_integer(code)
		if code == 401 or code == 407 do
			p = packet.reply(code, nil, ua)
			# todo create a nonce and set header
		else
			raise "response code must be 401 or 407 to create a challenge"
		end
	end
	
	@doc """
	Create a SIP packet from a set of parameters.
	
	session_id can be:
		- nil, then a from tag and call-ID are generated.
		- tuple { fromtag, callid, totag }
		
	body can be:
		- nil (packet has no attached body)
		- tuple { mime-type, body }
		- a list of such tuples
	"""
	@spec reply( atom, int, String.t, String.t, nil | tuple, String.t, tuple | list | nil) :: t
	create(method, cseq, ruri, from, to, session_id, ua, body ) when is_atom(method) and is_integer(cseq) do
		p = %SIP.Packet{ method: method, ruri: ruri, is_request: true }
		
		cond do
			is_binary(from) -> from = SIP.URI.parse(from)
			from.__struct__ == "SIP.URI" -> from
			true -> raise "Invalid from"
		end
		
		cond do
			is_binary(to) -> to = SIP.URI.parse(to)
			to.__struct__ == "SIP.URI" -> to
			to == nil -> to = ruri
			true -> raise "Invalid to"
		end
			
		case session_id do
			{ fromtag, callid, totag } -> 
				p = p.setHeaderValue( :From, 	from.setParam("tag", fromtag )),
				p = p.setHeaderValue( :To, 		to.setParam("tag", totag )),
				p = p.setHeaderValue( "Call-ID", callid )
								
			
			# No session ID specifed ? Create one !
			nil ->
				p = p.setHeaderValue(:From, from) |> 
					SIP.Packet.setHeaderValue(:To, to) |> 
					SIP.Packet.generateTag(:From) |> 
					SIP.Packet.generateTag("Call-ID")
					
			_ -> raise "Invalid session ID"
		end
		
		# Add CSeq and generage branch tag.
		p = p |> setHeaderValue(:CSeq, "#{cseq} #{method}") |> generateTag(:Via) |> setBody(body)
	end
	
	@doc """
	Get one header value
	"""		
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
	
	
	@doc """
	Get one value from the header. And remove it from the packet header
	nil, if the packet does not contain the header. Returns the modified SIP packet
	"""	
	def popHeaderValue(packet, hKey)
		value = getHeaderValue(packet, hKey)
		cond do
			value == nil 	-> packet
			is_list(value)	-> setHeaderValue(packet, hKey, tl value)
			true ->			-> setHeaderValue(packet, hKey, no)
		end
	end
	
	@doc """
	Get the numerical sequence number of the SIP packet
	"""	
	def getCSeqNum(packet)
		val = getHeaderValue(packet, :CSeq)
		if val != nil do
			[ cseq, method ] =String.split(val, " ")
			String.to_integer(cseq)
		else
			nil
		end
	end
	
	@doc """
	Get all the packet's parsed header dictionary
	"""	
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
	
	defp checkMimeType( mimetype ) when is_binary (mimetype) do
		if mimetype in [ "application/sdp", "text/plain", "text/xml" ] do
			mimetype
		else
			raise "Invalid mimetype #{mimetype}"
		end	
	end
	
	defp checkBodyPart( { mimetype, payload } )
		if byte_size( payload ) <= @max_body_len do
			{ checkMimeType(mimetype), payload }
		else
			raise "#{mimetype} body part is too big"
		end
	end
	
	@doc """
	Set or replace the packet body
	"""
	def setBody(packet, nil) do
		packet
	end
	
	def setBody(packet, { mimetype, payload } ) do
		%SIP.Packet{ packet | body: { checkBodyPart( { mimetype, payload } ) }
	end
	
	def setBody(packet, body) when is_list(body) do
		if size(body) <= @max_nb_body_parts do
			body2 = for bpart <- body, do: checkBodyPart(bpart)
			%SIP.Packet{ packet | body: body2 }
		else
			raise "Number of body parts exceeds the limit"
		end
	end
	
	@doc """
	Utility function to add a from-tag, a to-tag or generate a Call-ID
	Do not overwrite existing tag or call-iD. Returns the modified SIP packet
	"""
	@spec generateTag( t, String.t | Atom.t ) :: t
	def generateTag( packet, header ) when header in [ :From, :To ] do
		headerv = packet.getHeaderValue(header)
		if headerv != nil do
			headerv.setParam( "tag", genTag() )
			packet = packet.setHeaderValue(header, headerv)
		end
		packet
	end
		
	def generateTag( packet, "Call-ID" ) do
		cid = packet.getHeaderValue(header)
		if cid == nil do
			packet = packet.setHeaderValue(header, genHash() )
		end
		packet
	end
	
	def generateTag( packet, "Call-ID" ) do
		if packet.branch == nil do
			packet = %SIP.Packet{ packet | branch: genTag() }
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
	
	
	@doc """
	Obtain a map of SIP 401 or 407 challenge
	"""
	def getChallengeInfo(packet) do
		case packet.response_code do
			401 ->
			
			407 ->
	
			_ -> raise "Only 401 and 407 responses contains authentication challenge info"
		end
	end
	
	@doc """
	Check if this packet answers correctly a challenge and comply
	with rhe credentials
	"""
	def checkCredentials(packet, challenge, credentials) do
	end

	@doc """
	Check if this packet answers correctly a challenge and comply
	with rhe credentials
	"""	
	def getAuthUserAndDomain(packet) do
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