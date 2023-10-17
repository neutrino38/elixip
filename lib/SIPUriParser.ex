defmodule SIPUriParser do
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

	defp parse_core_uri(core_uri_str) do

		case String.split(core_uri_str, "@") do
			[ user, domainport ] ->
				if String.match?(user,~r/^[a-zA-Z0-9\+][a-zA-Z0-9\-\._]+$/) do
					tmpuri = parse_core_uri( domainport )
					if is_map(tmpuri) do Map.merge( %{ userpart: user }, tmpuri) else tmpuri end
				else
					nil
				end

			[ domainport ] ->
				case String.split(domainport, ":") do
					[ domain, port ] ->
						if String.match?(port,~r/^[0-9]+$/) do
							tmpuri = parse_core_uri( domain )
							if is_map(tmpuri) do Map.merge( %{ port: String.to_integer(port) }, tmpuri ) else tmpuri end
						else
							:invalid_sip_uri_port
						end

					[ domain ] ->
						if String.match?(domain,~r/^[a-zA-Z0-9\-\.]+$/) do
							%{ domain: domain }
						else
							:invalid_sip_domain
						end
				end
		end
	end

	@doc """
	Parse a single SIP URI and store its parts in a map
	"""
	def parse_sip_uri(uri_string) do
		proto = if String.contains?(uri_string, "sips:") do
				"sips:"
		else
				"sip:"
		end

		case String.split(uri_string, proto) do
			[ "", part2 ] ->
				# Form sip:user@domain;param=value
				parts = String.split( part2, ";" )

				# parse core URI
				case parse_core_uri( Enum.at(parts, 0) ) do
					err when is_atom(err) ->
						{ err, Map.new() }

					core_uri ->
						# Parse parameters
						params = parse_uri_parameters( Enum.drop( parts, 1 ) )
						{ :ok, Map.put(core_uri, :params, params) }
				end

			[ "<", part2 ] ->
				# Form <sip:user@domain>;param=value
				[ core_uri_str, params_str ] =  String.split( part2, ">", parts: 2 )
				case parse_sip_uri( "sip:" <> core_uri_str ) do
					{ :ok, core_uri } ->
						# Parse params
						param_list = case String.split( params_str, ";" ) do
							[ "" ] -> []
							[ "" | tail ] -> tail
							[ p ] -> [ p ]
						end
						params = parse_uri_parameters( param_list )
						{ :ok, Map.put(core_uri, :params, params) }

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
						String.slice(d_name, 1..-1)

					# test "Display Name"<....
					String.contains?(part1, "\"<") ->
						[ d_name, _truc ] = String.split( part1, "\"<")
						String.slice(d_name, 1..-1)

						# test DisplayName <....
					String.contains?(part1, " <") ->
						[ d_name, _truc ] = String.split( part1, " <")
						d_name

					# test DisplayName <....
					String.contains?(part1, "<") ->
						[ d_name, _truc ] = String.split( part1, "<")
						d_name

					# Parse error
						true -> part1
				end

				#Recurse to parse the URI part
				case parse_sip_uri( "<sip:" <> part2 ) do
					{ :ok, core_uri } ->
						 { :ok, Map.put(core_uri, :displayname, display_name) }

					{ code, core_uri } -> { code, core_uri }
				end

			_ -> { :invalid_sip_uri_general, Map.new() }
		end
	end

	def get_uri_param(sip_uri, param) when is_map(sip_uri) do
		cond do
			!Map.has_key?(sip_uri, :params) -> { :uri_without_params, nil }
			Map.has_key?(sip_uri.params, param) -> { :ok, sip_uri.params[param] }
			true -> { :no_such_param, nil }
		end
	end

	def get_uri_param(sip_uri, param) when is_binary(sip_uri) do
		case parse_sip_uri(sip_uri) do
			{ :ok, parsed_uri } -> get_uri_param(parsed_uri, param)
			{ code, _dump } -> { code, nil }
		end
	end
end
