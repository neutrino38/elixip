defmodule SIP.Uri do

	defstruct [
		displayname: nil,
		userpart: nil,
		domain: nil,
		port: nil,
		scheme: "sip:",
		proto: "UDP",
		destip: nil, # IP to be used
		destport: 0, # port to be used
		destproto: nil,
		tp_module: nil, # transport module
		tp_pid: nil, # transport PID
		params: %{}
	]

	defp parse_uri_parameters(param_list) do
		params = Enum.map( param_list, fn pv ->
				case String.split(pv, "=") do
					[ p, v ] -> { p, v }
					[ p ]  -> { p, true }
				end
			end )

		# Convert list of couples [ {p1, v1}, {p2, v2}, ... ]
		# into a map
		Map.new(params)
	end

	# parse domain, user@domain, user@domain:port

	defp parse_core_uri(scheme, core_uri_str) do

		case String.split(core_uri_str, "@") do
			[ user, domainport ] ->
				if String.match?(user,~r/^[a-zA-Z0-9\+][a-zA-Z0-9\-\._]+$/) do
					tmpuri = parse_core_uri( scheme, domainport )
					if is_map(tmpuri) do Map.put(tmpuri, :userpart, user) else tmpuri end
				else
					nil
				end

			[ domainport ] ->
				case String.split(domainport, ":") do
					[ domain, port ] ->
						if String.match?(port,~r/^[0-9]+$/) do
							tmpuri = parse_core_uri( scheme, domain )
							if is_map(tmpuri) do Map.put( tmpuri, :port, String.to_integer(port) ) else tmpuri end
						else
							:invalid_sip_uri_port
						end

					[ domain ] ->
						if String.match?(domain,~r/^[a-zA-Z0-9\-\.]+$/) do
							%SIP.Uri{ domain: domain }
						else
							:invalid_sip_domain
						end
				end
		end
	end

	@doc """
	Parse a single SIP URI and store its parts in a map
	"""
	@spec parse( bitstring() ) :: { atom(), map() }
	def parse(uri_string) do
		proto = if String.contains?(uri_string, "sips:") do
				"sips:"
		else
				"sip:"
		end

		case String.split(uri_string, proto, parts: 2) do
			[ "", part2 ] ->
				# Form sip:user@domain;param=value
				parts = String.split( part2, ";" )

				# parse core URI
				case parse_core_uri( proto, Enum.at(parts, 0) ) do
					err when is_atom(err) ->
						{ err, Map.new() }

					core_uri ->
						# Parse parameters
						params = parse_uri_parameters( Enum.drop( parts, 1 ) )
						core_uri = if core_uri.port != nil do
							core_uri
						else
							# Add default port
							Map.put(core_uri,
								:port,
								if proto == "sips:" do 5061 else 5060 end)
						end
						core_uri = Map.put(core_uri, :scheme, proto) |> Map.put(:params, params)
						{ :ok, core_uri }
				end

			[ "<", part2 ] ->
				# Form <sip:user@domain>;param=value
				[ core_uri_str, params_str ] =  String.split( part2, ">", parts: 2 )
				case SIP.Uri.parse( proto <> core_uri_str ) do
					{ :ok, core_uri } ->
						# Parse params
						param_list = case String.split( String.trim_leading(params_str,";"), ";" ) do
							[ "" ] -> []
							[ "" | tail ] -> tail
							[ p ] -> [ p ]
							plist -> plist
						end
						params = parse_uri_parameters( param_list )

						#Add params to URI and fix proto field
						uri = %SIP.Uri{ core_uri | params: params, proto: get_transport(core_uri) }
						if uri.scheme == "sips" and uri.proto != "TLS" do
							raise "Invalid URI. sips is specified and transport is not TLS"
						else
							{ :ok, uri }
						end


					{ code, core_uri } -> { code, core_uri }
				end

			[ part1, part2 ] ->
				# Form "Display Name" <sip:user@domain>;param=value
				# Form "Display Name"<sip:user@domain>;param=value
				# Form DisplayName <sip:user@domain>;param=value

				display_name = cond do

					# test "Display Name" <....
					String.contains?(part1, "\" <") ->
						[ d_name, _truc ] = String.split( part1, "\" <")
						URI.decode_www_form(String.slice(d_name, 1..-1//1))

					# test "Display Name"<....
					String.contains?(part1, "\"<") ->
						[ d_name, _truc ] = String.split( part1, "\"<")
						# URI.decode_www_form(String.slice(d_name, 1..-1))
						URI.decode_www_form(String.slice(d_name, 1..-1//1))

						# test DisplayName <....
					String.contains?(part1, " <") ->
						[ d_name, _truc ] = String.split( part1, " <")
						URI.decode_www_form(d_name)

					# test DisplayName <....
					String.contains?(part1, "<") ->
						[ d_name, _truc ] = String.split( part1, "<")
						d_name

					# Parse error
						true -> part1
				end

				#Recurse to parse the URI part
				case SIP.Uri.parse( "<" <> proto <> part2 ) do
					{ :ok, core_uri } ->
						 { :ok, Map.put(core_uri, :displayname, display_name) }

					{ code, core_uri } -> { code, core_uri }
				end

			_ -> { :invalid_sip_uri_general, Map.new() }
		end
	end

	@doc "Obtain a parameter from an URI"
	@spec get_uri_param(%SIP.Uri{} | binary(), binary()) :: { :ok, binary() } | { :no_such_param, nil } | { atom(), nil }
	def get_uri_param(sip_uri, param) when is_binary(sip_uri) do
		case SIP.Uri.parse(sip_uri) do
			{ :ok, parsed_uri } -> get_uri_param(parsed_uri, param)
			{ code, _dump } -> { code, nil }
		end
	end

	def get_uri_param(sip_uri = %SIP.Uri{}, param) do
		case Map.get(sip_uri.params, param) do
			nil -> { :no_such_param, nil }
			val -> { :ok, val }
		end
	end

	@doc "Set an URI parameter"
	def set_uri_param(sip_uri = %SIP.Uri{}, param, value) do
		new_params = Map.put(sip_uri.params, param, value)
		Map.put(sip_uri, :params, new_params)
	end

	@doc "Obtain the transport string in capitals from the URI"
	def get_transport(uri = %SIP.Uri{}) do
		case get_uri_param(uri, "transport") do
			{ :no_such_param, nil } ->
				if uri.scheme == "sips:", do: "TLS", else: uri.proto
				{ :ok, value } -> String.upcase(value)
		end
	end

	defp serialize_core_uri( scheme, user, host, port ) when is_tuple(host) do
		serialize_core_uri(scheme, user, SIP.NetUtils.ip2string(host), port)
	end

	defp serialize_core_uri( "sips:", nil, host, 5061 ) do
		"sips:" <> host
	end

	defp serialize_core_uri( "sips:", user, host, 5061 ) do
		"sips:" <> user <> "@" <> host
	end

	defp serialize_core_uri( "sips:", user, host, nil ) do
		"sips:" <> user <> "@" <> host
	end

	defp serialize_core_uri( "sips:", user, host, port ) do
		"sips:" <> user <> "@" <> host <> ":" <> Integer.to_string(port)
	end

	defp serialize_core_uri( "sip:", nil, host, 5060 ) when is_binary(host) do
		"sip:" <> host
	end


	defp serialize_core_uri( "sip:", user, host, 5060 ) when is_binary(host) do
		"sip:" <> user <> "@" <> host
	end

	defp serialize_core_uri( "sip:", nil, host, nil ) when is_binary(host) do
		"sip:" <> host
	end
	defp serialize_core_uri( "sip:", nil, host, port ) when is_binary(host) do
		"sip:" <> host <> ":" <> Integer.to_string(port)
	end

	defp serialize_core_uri( "sip:", user, host, nil ) do
		"sip:" <> user <> "@" <> host
	end


	defp serialize_core_uri( "sip:", user, host, port ) when is_binary(host) do
		"sip:" <> user <> "@" <> host <> ":" <> Integer.to_string(port)
	end

	defp serialize_one_param(key, value) when is_boolean(value) do
		if value do key else "" end
	end

	defp serialize_one_param(key, value) when is_bitstring(value) do
		key <> "=" <> value
	end

	# Turn the param map in a string param1=val1;param2=val2
	defp serialize_params(params) when is_map(params) do
		pstr = Enum.reduce(params, "", fn { key, value}, acc ->
			acc <> serialize_one_param(key, value) <> ";"
		end)
		String.trim_trailing(pstr, ";")
	end

	#Serialize a map into a SIP URI
	def serialize( uri = %SIP.Uri{} ) do
		core_uri_str = serialize_core_uri(
				uri.scheme,
				Map.get(uri, :userpart),
				uri.domain,
				uri.port )

		# add transport in params if needed
		params = if Map.has_key?(uri.params, "transport") or uri.proto == "UDP" do
			uri.params
		else
			Map.put(uri.params, "transport", uri.proto)
		end
		#URI.encode_www_form()

		uri_str = if uri.displayname != nil do
			"\"" <> URI.encode_www_form(uri.displayname) <> "\" <" <> core_uri_str <> ">;" <> serialize_params(params)
		else
			core_uri_str <> ";" <> serialize_params(params)
		end
		{ :ok, String.trim_trailing(uri_str, ";") }
	end

	def has_tp_info(uri = %SIP.Uri{}) do
		is_tuple(uri.destip) and uri.destport > 0 and is_pid(uri.tp_pid) and not is_nil(uri.tp_module)
	end

	defimpl String.Chars do
		def to_string(uri) do
			case SIP.Uri.serialize(uri) do
				{ :ok, uri_str } -> uri_str
			end
		end
	end
end
