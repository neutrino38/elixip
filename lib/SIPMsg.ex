defmodule SIPMsg do
	@moduledoc "SIP protocol parser and serializer"

	# Concat multi value headers in a single list
	defp concat_multi_header_values(val1, val2) when is_list(val1) and is_list(val2) do
		val1 ++ val2
	end

	defp concat_multi_header_values(val1, val2) when is_list(val1) and is_bitstring(val2) do
		val1 ++ [ val2 ]
 	end

	defp concat_multi_header_values(val1, val2) when is_bitstring(val1) and is_list(val2) do
		[ val1 ] ++ val2
 	end

	defp concat_multi_header_values(val1, val2) when is_bitstring(val1) and is_bitstring(val2) do
		[ val1 , val2 ]
 	end

	# guard that defines which header is single or multivalued

	defguardp is_single_value(k) when k in [ :from, :to, :callid, :cseq, :useragent, :contenttype ]

	# Predefined header that was not yet parsed
	defp acc_header_values(key, nil, new_value, _parse_error_callback) when is_single_value(key) do
			new_value
	end

	# Single value header with an incorrect duplicate value -> ignore
	defp acc_header_values(key, old_value, _new_value, parse_error_callback) when is_single_value(key) do
		parse_error_callback.( :duplicate, "Duplicate SIP header '#{key}'", 0, key )
		old_value
	end

	# Process multivalued headers values
	defp acc_header_values(_key, old_value, new_value, _parse_error_callback) do
		# Add values in a list
		concat_multi_header_values(old_value, new_value)
	end



	# Translate header name to atoms for usual headers
	defp headername_to_atomkey(name) do
		case name do
			"From" -> :from
			"To" -> :to
			"Via" -> :via
			"Call-ID" -> :callid
			"User-Agent" -> :useragent
			"Route" -> :route
			"Record-Route" -> :recordroute
			"Content-Length" -> :contentlength
			"Content-Type" -> :contenttype
			"CSeq" -> :cseq
			"Proxy-Authorization" -> :proxyauthorization
			"Expire" -> :expire
			"Contact" -> :contact
			"Supported" -> :supported
			_ -> name
		end
	end

	# Convert SIP method name to atom or nil if not recognized
	defp method_to_atom(reqname) do
		case reqname do
			"REGISTER" -> :REGISTER
			"INVITE" -> :INVITE
			"UPDATE" -> :UPDATE
			"ACK" -> :ACK
			"INFO" -> :INFO
			"MESSAGE" -> :MESSAGE
			"REFER" -> :REFER
			"OPTIONS" -> :OPTIONS
			"PUBLISH" -> :PUBLISH
			"SUBSCRIBE" -> :SUBSCRIBE
			"NOTIFY" -> :NOTIFY
			"BYE" -> :BYE
			"CANCEL" -> :CANCEL
			_ -> nil
		end
	end


	#Parse header content
	defp parse_header_content( :cseq, value ) do
		case String.split(value, " ") do
			[ seqnum, method ] ->
				rez = [ String.to_integer(seqnum), method_to_atom(method) ]
				if is_atom(Enum.at(rez,1)) do
					{ :ok, rez }
				else
					{ :invalid_cseq_header, "Invalid method #{method} referenced in CSeq header." }
				end

			_ -> { :invalid_cseq_header, "Invalid CSeq header format." }
		end
	end

	defp parse_header_content( :via, value ) do
		{ :ok, String.split(value, ", ") }
	end

	defp parse_header_content( :supported, value ) do
		{ :ok, String.split(value, ", ") }
	end

	defp parse_header_content( :contentlength, value ) do
		{ :ok, String.to_integer(value) }
	end

	defp parse_header_content( :contact, value ) do
		case SIP.Uri.parse(value) do
			{ :ok, value } -> { :ok, value }
			{ errcode, _value } -> { errcode, "Invalid contact URI" }
		end
	end

	defp parse_header_content( :proxyauthorization, value ) do
		authparams = Map.new(
			Enum.map(
				String.split(value, ","),
				fn val ->
					[ k, v] = String.split(val, "=", parts: 2)
					{ String.trim(k), String.trim(v) }
				end)
		)
		{ :ok, authparams }
	end

	defp parse_header_content( "Max-Forwards", value ) do
		{ :ok, String.to_integer(value) }
	end


	defp parse_header_content( _key, value ) do
		{ :ok, value }
	end
	#Parse empty header
	defp parse_header(nil, _line_number, dest_map, _parse_error_callback) do
		{ :end_of_message, dest_map }
	end

	#Parse empty header
	defp parse_header("", _line_number, dest_map, _parse_error_callback) do
		{ :end_of_message, dest_map }
	end

	#Parse one header line
	defp parse_header(line, line_number, dest_map, parse_error_callback) do
		case String.split(line, ": ", parts: 2) do
			[ name, content ] ->
				if String.match?(name,~r/^[A-Z][0-9 a-zA-Z\-]+$/) do
					key = headername_to_atomkey(name)
					# Now parse the header content
					case parse_header_content( key, content ) do
						{ :ok, value } ->
							#Header Content parsed successfully. Add to the map
							updated_map = Map.update(dest_map, key, value, fn existing_value ->
								acc_header_values( key, existing_value, value, parse_error_callback)
							end)
							{ :ok, updated_map }

						{ err, errmsg } ->
							#Failed to parse header
							parse_error_callback.( err, errmsg, line_number, line )
							{ err, dest_map }
					end
				else
					parse_error_callback.( :no_header_separator, "Invalid header name '#{name}'", line_number, line )
					{ :invalid_header_name, dest_map }
				end

			_ ->
				parse_error_callback.( :no_header_separator, "No header separator ':'", line_number, line )
				{ :no_header_separator, dest_map }
		end
	end


	# Parse a single line of header and recurse
	defp parse_header_lines(lines, line_number, parsed_msg, parse_error_callback) do

		# Parse the first header in the list and update the parsed message map
		case parse_header( List.first(lines), line_number, parsed_msg, parse_error_callback) do

			# Header successfully parsed and msg is updated
			{ :ok, upd_msg } ->
				#Now recurse to parse the following headers
				parse_header_lines(List.delete_at(lines, 0), line_number+1, upd_msg, parse_error_callback)

			# End of headers detected
			{ :end_of_message, upd_msg } ->
				{ :ok, lines, upd_msg }

			# Parsing error. Stop it and report int
			{ err, upd_msg } ->
				# Parse error. Stop here. Do not remove the offending line from the list
				{ err, lines, upd_msg }
		end
	end

	# Create an empty SIP request
	defp create_sip_req( req, ruri ) do
		req2 = method_to_atom(req)
		if !is_nil(req2) do
			case SIP.Uri.parse(ruri) do
				{ :ok, parsed_uri } ->
					{ :ok, %{ method: req2, ruri: parsed_uri,
					  from: nil, to: nil, via: [], callid: nil, cseq: nil } }
					_ -> { :invalid_ruri,  Map.new() }
			end
		else
			{ :invalid_request, Map.new() }
		end

	end

	defp create_sip_resp( response_code, reason ) do
		%{ method: false, response: String.to_integer(response_code),
									reason: reason, from: nil, to: nil,
									via: [], callid: nil, cseq: nil }
	end


	# Parse the first line, create the initial message map
	# then recurse to parse the headers
	defp start_header_parsing(lines,parse_error_callback) do
		first_line = List.first(lines)
		line_number = 1
		if is_bitstring(first_line) do
			case String.split(first_line, " ") do

				# This is a SIP response
				[ "SIP/2.0", response_code, reason ] ->
					parse_header_lines(
							List.delete_at(lines, 0),
							line_number+1,
							create_sip_resp(response_code, reason),
							parse_error_callback)

				# This is a SIP request
				[ req, sip_uri, "SIP/2.0" ] ->
					case create_sip_req(req, sip_uri) do
							{ :ok, req_map } ->
								parse_header_lines(
									List.delete_at(lines, 0),
									line_number+1,
									req_map,
									parse_error_callback)

							# Request URI is invalid
							{ :invalid_ruri, req_map } ->
								parse_error_callback.( :invalid_ruri, "Invalid request URI '#{sip_uri}'", line_number, first_line )
								{ :invalid_ruri, lines, req_map }

							# Unrecognized request
							{ :invalid_request, req_map } ->
								parse_error_callback.( :invalid_request, "Unknown SIP request '#{req}'", line_number, first_line )
								{ :invalid_request, lines, req_map }
					end

				_ ->
					parse_error_callback.( :bad_first_line, "Failed to parse SIP msg first line", line_number, first_line )
					{ :bad_first_line, lines, Map.new() }
			end
		else
			parse_error_callback.( :empty_message, "Empty SIP message", line_number, first_line )
			{ :bad_first_line, Map.new() }
		end
	end

	# Parse the transaction ID from topmost via
	def parse_transaction_id({ :ok, msg }) do
		cond do
			Map.has_key?(msg, :via) == false ->
				# No via header
				{ :ok, Map.put(msg, :transid, nil) }

			is_nil(msg.via) or msg.via == [] ->
				# Empty Via header
				{ :ok, Map.put(msg, :transid, nil) }

			Kernel.length(msg.via) >= 1 ->
				# Get topmost via and branch parameter
				[ _transport, topmost_via ] = String.split(Enum.at(msg.via, 0), " ", parts: 2)

				case SIP.Uri.get_uri_param("sip:" <> topmost_via, "branch") do
					{ :ok, branch } -> { :ok, Map.put(msg, :transid, branch) }
					{ :no_such_param, nil } -> { :ok, Map.put(msg, :transid, nil) }
					{ _code, _parsed_via } -> { :invalid_tompost_via, msg }
				end
		end
	end

	# We don't parse anything if the messge is not correct
	def parse_transaction_id({ code, msg }) do
		{ code, msg }
	end

	# Compute dialog ID using from tag, to tag and callid
	# Then add it to parsed message
	defp compute_dialog_id(msg, from, callid, to) do
			{ _code_from, from_tag } = SIP.Uri.get_uri_param(from, "tag")
			{ _code_to, to_tag } = SIP.Uri.get_uri_param(to, "tag")
			case { from_tag, callid, to_tag } do
				{ nil, _cid, _totag } -> { :invalid_dialog_id_no_from_tag, "no from tag" }
				{ _from_tag, nil, _totag } -> { :invalid_dialog_id_no_callid, "no callid" }
				{ f_tag, cid, t_tag } ->
					{ :ok, Map.put(msg, :dialog_id, {f_tag, cid, t_tag}) }
			end
	end

	# Compute dialog ID of a successfully parsed message
	defp compute_dialog_id({ :ok, msg }) when is_map(msg) do
			cond do
				Map.has_key?(msg, :from) and Map.has_key?(msg, :to) and Map.has_key?(msg, :callid) ->
						compute_dialog_id( msg, msg.from, msg.callid, msg.to )
				!Map.has_key?(msg, :from) -> { :missing_from_header, "Missing From header" }
				!Map.has_key?(msg, :to) -> { :missing_to_header, "Missing To header" }
				!Map.has_key?(msg, :callid) -> { :missing_callid_header, "Missing Call-ID header" }
				true -> { :invalid_dialog_id, "Failed to compte dialog ID (unspecified)" }
			end
	end

	# Message was not successully parsed. Pass the error code down
	defp compute_dialog_id({ code, msg }) when is_map(msg) do
		{ code, msg }
	end

	defp do_final_checks(parsed_msg_or_error) do
		{ code, msg } = parsed_msg_or_error
		if code == :ok do
			#Todo
			{ :ok, msg }
		else
			{ code, msg }
		end
	end

	# Parse RFC 2046 mime, multipart sub body and put it in a map
	defp parse_sub_body(subbody) do

		[ headers, data ] = case String.split(String.trim(subbody), "\r\n\r\n", parts: 2) do
			[ h, d ] -> [ h, d ]
			[ _one ] -> raise "mixed/multipart: Invalid body part. Missing empty line between MIME headers and data"
		end
		hlist = String.split(headers, "\r\n")

		#Parse headers of subbody
		{ code, _rest, dstmap } = parse_header_lines(hlist, 1, %{}, fn _code, _errmsg, _lineno, _line -> nil end)

		if code == :ok do
			dstmap = if Map.has_key?(dstmap, :contenttype) do
				dstmap
			else
				Map.put(dstmap, :contenttype, "text/plain; charset=UTF-8")
			end

			#Add data body in the map
			Map.put(dstmap, :data, data)
		else
			raise "Invalid header inside multipart/mixed message"
		end
	end

	# Parse RFC 2046 mime, multipart body and returns a list of sub bodies
	def parse_multi_part_body(ctype, body) do
		case String.split(ctype, "; boundary=") do
			[ "multipart/mixed", boundary] ->
				# We do have a multipart mixed
				# Spilt into the parts according to the boundaries
				bodies = String.split(body, "--" <> boundary )
				if Kernel.length(bodies) < 3 do # prologue, bodies, last boundary
					raise "Invalid MIME multipart SIP message body. Missing bpundaries."
				else
					# Remove everything before the first boundary
				 	bodies = List.delete_at(bodies, 0)

					#Remove last boundary
					bodies = List.delete_at(bodies, -1)

					# Parse all sub bodies and return them as a list of maps
					Enum.map(bodies,
						fn v -> Map.put(parse_sub_body(v), :boundary, boundary) end)
				end
			_ ->
				# Single body
				[ %{ contenttype: ctype, data: body } ]
		end
	end

	# Parse data after the headers and add body in the SIP message map
	defp add_body(parsed_msg, body) do
		clen = parsed_msg.contentlength
		sz = if is_nil(body) do
			0
		else
			# Add 2 because Content-Length includes the \r\n separator
			# between the message body and the headers
			Kernel.byte_size(body) + 2
		end

		cond do
			clen == 0 ->
				# No body attached to this SIP message
				{ :ok, parsed_msg, nil }

			sz == 0 and clen > 0 ->
				# content length > 0 and no body data
				{ :missing_body, parsed_msg, nil }

			!Map.has_key?(parsed_msg, :contenttype) and clen > 0 ->
				# Missing content-type header
				{ :missing_content_type, parsed_msg, body }

			clen > sz ->
				# ANnounced content length exceeds data read
				IO.puts("Content-Length: #{clen} > data size: #{sz}")
				{ :bad_body_size, parsed_msg, nil }

			clen <= sz ->
				# Multipart/mixed as defined by RFC 2046
				mod_msg = Map.put(parsed_msg, :body,
								  	parse_multi_part_body(
											parsed_msg.contenttype,
											Kernel.binary_part(body, 0, clen-2)))

				rest = if clen < sz do Kernel.binary_part(body, clen-2, sz - clen) else "" end
				{ :ok, mod_msg, rest }
		end
	end
	@doc """
	Parse a SIP message stored as a string and return it as map
	Takes a callback that document all parsing errors. In case of
	parsing error, the callback function is called as

	parse_error_callback(err_code, err_message, line_num, offending_line)
	"""
	def parse(message, parse_error_callback) when is_binary(message) do
		# Size check
		if String.length(message) > 10000 do
			raise "SIP message exceeds max length of 10000"
		end

		# Separate headers from the rest.
		{ headers, body } = case String.split(message, "\r\n\r\n", parts: 2) do
			[ hs, bd ] ->
				{ String.split(hs, "\r\n"), bd }

			[ _hs ] ->
				{ String.split(message, "\r\n"), nil }
		end

		#Parse headers
		{ code, _lines, parsed_msg } = start_header_parsing(headers, parse_error_callback)

		if code == :ok do
			{ code, parsed_msg_or_error	}
				= do_final_checks(
					compute_dialog_id(
						parse_transaction_id(
							{ code, parsed_msg } )))

			if code == :ok do
				# Now parse message body and insert it into the map under de body key
				{ code, final_msg, _rest } = add_body(parsed_msg_or_error, body)
				if code == :ok do
					{ code, final_msg }
				else
					{ code, parsed_msg_or_error }
				end
			else
				parse_error_callback.(code, parsed_msg_or_error, 0, "")
				{ code, parsed_msg }
			end
		else
			{ code, parsed_msg }
		end
	end

	# ---------------------- serialize -----------------------------------------
	defp serialize_first_line(req, uri) when is_atom(req) do
		{ :ok, uri_str } = SIP.Uri.serialize(uri)
		Atom.to_string(req) <> " " <> uri_str <> " SIP/2.0\r\n"
	end

	defp serialize_first_line(response, reason) when is_integer(response) do
		"SIP/2.0 " <> Integer.to_string(response) <> " " <> reason <> "\r\n"
	end



	@common_headers_atoms %{ via: "Via", from: "From", to: "To", callid: "Call-ID",
		route: "Route", recordroute: "Record-Route", useragent: "UserAgent",
		contact: "Contact", cseq: "CSeq", contenttype: "Content-Type",
		contentlength: "Content-Length", proxyauthorization: "Proxy-Authorization",
		supported: "Supported" }

	defp header_name_to_string(name) when is_atom(name) do
		@common_headers_atoms[name]
	end

	defp header_name_to_string(name) when is_bitstring(name) do
		name
	end

	# Serialize an empty header
	defp serialize_one_header( _name, nil ) do
		""
	end

	# Serialize a contact header header
	defp serialize_one_header( :contact, contact ) do
		case SIP.Uri.serialize(contact) do
			{ :ok, contact_str} -> header_name_to_string(:contact) <> ": " <> contact_str <> "\r\n"
			# _ -> raise "Invalid contact in SIP message"
		end
	end

	# Serialize single value common headers (which name are represented by an atom)
	defp serialize_one_header( name, val ) when name in [ :from, :to, :callid, :useragent, :contenttype	] and is_bitstring(val) do
		header_name_to_string(name) <> ": " <> val <> "\r\n"
	end

	# Serialize a CSeq header
	defp serialize_one_header( :cseq, [ seqno, method ] ) do
		header_name_to_string(:cseq) <> ": " <> Integer.to_string(seqno) <> " " <> Atom.to_string(method) <> "\r\n"
	end

	# Serialize a Proxy-Authorization header
	defp serialize_one_header( :proxyauthorization, authinfo ) do
		header_name_to_string(:proxyauthorization) <> ": " <>
			String.trim_trailing(Enum.reduce(authinfo, "", fn {k, v}, acc ->
				acc <> k <> "=" <> v <> ", "
			end), ", ") <> "\r\n"
	end

	# Serialize a header that can have multiple string values represented as a list
	defp serialize_one_header( name, value ) when is_list(value) do
		Enum.reduce(value, "", fn v, acc ->
			acc <> header_name_to_string(name) <> ": " <> v <> "\r\n"
		end)
	end

	# Serialize a single value header with a string value
	defp serialize_one_header( name, value ) when is_bitstring(value) do
		header_name_to_string(name) <> ": " <> value <> "\r\n"
	end

	# Serialize a single value header with an integer value
	defp serialize_one_header( name, value ) when is_integer(value) do
		header_name_to_string(name) <> ": " <> Integer.to_string(value) <> "\r\n"
	end

	defp serialize_headers(sipmsg, ordered_header_list, mandatory) do
		Enum.reduce( ordered_header_list, "", fn h, acc ->
			if Map.has_key?(sipmsg, h) do
				acc <> serialize_one_header(h, sipmsg[h])
			else
				if mandatory and h not in [:via] do
					name = header_name_to_string(h)
					raise "Missing mandatory header #{name} in SIP message"
				else
					acc
				end
			end
		end)
	end

	defp serialize_headers(sipmsg) do
		header_order1 = [ :via, :from, :to, :callid, :cseq ]
		header_order2 = [ :useragent, :contenttype, :contentlength ]
		toskip = [ :transid, :body, :dialog_id, :boundary, :method, :response, :reason, :ruri, :response_code ]

		remaining_headers = Enum.reduce(sipmsg, [], fn {k, _v}, acc ->
			if k not in header_order1 and k not in toskip and k not in header_order2 do
				List.insert_at(acc, -1, k)
			else
				acc
			end
		end)
		# First we serialize all headers mentionned in "order1" in order
		# They are mandatory so we fail if they are not in the SIP msg
		serialize_headers(sipmsg, header_order1, true) <>
			serialize_headers(sipmsg, remaining_headers, false) <>
				serialize_headers(sipmsg, header_order2, false)
	end

	defp serialize_body([]) do
		"\r\n"
	end

	defp serialize_body([ body ]) do
		"\r\n" <> body.data
	end

	# Serialize a sub body of a multipart/mixed body
	defp serialize_body(body) when is_map(body) do
		h = "\r\n" <> body.boundary <> "\r\n" <> serialize_headers(body)
		h <> "\r\n" <> body.data
	end

	# Serialize a list of bodies into multipart/mixed body
	defp serialize_body( bodies ) when is_list(bodies) do
		bds = Enum.reduce(bodies, "", fn bd, acc -> acc <> serialize_body(bd) end)
		bds <> "\r\n" <> Enum.at(bodies, 0).boundary <> "--\r\n"
	end



	@doc """
	Serialize a SIP request into a string to be sent on the network
	"""
	def serialize(sipmsg) when is_map(sipmsg) and is_atom(sipmsg.method) do
		msgstr = serialize_first_line(sipmsg.method, sipmsg.ruri)
		headers = serialize_headers(sipmsg)
		body = if Map.has_key?(sipmsg, :body) do
			serialize_body(sipmsg.body)
		else
			""
		end
		msgstr <> headers <> body
	end

	def serialize(sipmsg) when is_map(sipmsg) and is_boolean(sipmsg.method) do
		msgstr = serialize_first_line(sipmsg.code, sipmsg.reason)
		headers = serialize_headers(sipmsg)
		body = if Map.has_key?(sipmsg, :body) do
			serialize_body(sipmsg.body)
		else
			""
		end
		msgstr <> headers <> body
	end
end
