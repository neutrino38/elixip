#---------------- SIP URI PARSER / SERIALIZER ---------------------
defmodule SIP.URI do
	@moduledoc """
	SIP URI parser
	"""
	
	defstruct scheme: :sip, displayname: nil, username: nil, domain: nil, port: 5060, transport: :sip_udp, params: nil
	
	defp parseParameters( paramsstr ) do
		paramList = String.split(paramsstr,";")
		paramMap = HashDict.new
		for p <- paramList do
			case String.split(p,"=") do
				[ pkey, pvalue ] -> Dict.put(paramMap, pkey, pvalue)
				[ pkey ] 		 -> Dict.put(paramMap, pkey, nil)
			end
		end
	end
	
	defp parseHostPort( hostport ) do
		case String.split(hostport, ":") do
			[ host, port ] -> [ host, String.to_integer(port) ]
			[ host ] -> [ host, 5060 ]
		end
	end
	
	defp parseUserHostPort( userhoststr ) do
		case String.split(userhoststr, "@") do
			[ user, hostport ] -> [ user | parseHostPort(hostport) ]
			[ hostport ] 	   -> [ nil  | parseHostPort(hostport) ]
		end
	end
	
	defp parseScheme( schemestr ) do
		case schemestr do
			"sip" -> :sip
			"sips" -> :sips
			"tel" -> :tel
			_ -> raise "Invalid scheme for SIP URI"
		end
	end
	
	defp getTransportFromParams( nil ) do
		:udp
	end
	
	defp getTransportFromParams( paramMap ) do
		case Dict.fetch(paramMap, "transport") do
			"WS" -> :ws
			"ws" -> :ws
			"WSS" -> :wss
			"wss" -> :wss
			"UDP" -> :udp
			"udp" -> :udp
			"TCP" -> :tcp
			"tcp" -> :tcp
			:error -> :udp
			_ -> raise "Unsupported transport for SIP uri"
		end
	end
	
	defp newSipUri( [ displayname, scheme, userhost ] ) do
		[ user, host, port ] = parseUserHostPort(userhost)
		s = parseScheme( scheme )
		%SIP.URI{ scheme: s, displayname: displayname, username: user, domain: host, port: port, transport: :udp, params: HashDict.new }
	end
		
	defp newSipUri( [ displayname, scheme, userhost, params] ) do
		[ user, host, port ] = parseUserHostPort(userhost)
		paramMap = parseParameters(params)
		s = parseScheme( scheme )
		t = getTransportFromParams( paramMap )
		%SIP.URI{ scheme: s, displayname: displayname, username: user, domain: host, port: port, transport: t, params: paramMap }
	end
	
	defp parse2( uristr, regex_lst  ) do
		if List.empty?(regex_lst) do
			raise "Invalid SIP URI"
		else
			{ uriform, has_dn } = hd regex_lst
			{ rez, reg } = Regex.compile(uriform)
			if rez != :ok do
				raise "Internal error in URI parser (invalid regex)"
			end 

			capt = Regex.run( reg, uristr )
					
			if is_list(capt) do
				if has_dn do
					newSipUri( tl capt )
				else
					newSipUri( [ nil | tl capt] )
				end
			else
				parse2( uristr, tl regex_lst )
			end
		end
	end
	
	def parse( uristr ) do	
		rgx_list = [ 
			{ "\"([[:alnum:]+%]+)\"[ ]+<(sip|sips):([[:alnum:]\.:@]+)>;(*)", true },
			{ "\"([[:alnum:]+%]+)\"[ ]+<(sip|sips):([[:alnum:]\.:@]+)>"	 , true },
			{ "(sip|sips):([[:alnum:]\.:@]+);(*)", false },
			{ "(sip|sips):([[:alnum:]\.:@]+)", false }
		]
		
		parse2(uristr, rgx_list)	
	end
	
	def setParam(uri, key, val) do
		if val != nil do
			%SIP.URI{uri | params: Dict.put(uri.params, key, val) }
		else
			uri
		end
	end
	
	def setParam(uri, key) do
		%SIP.URI{uri | params: Dict.put(uri.params, key, true) }
	end
	
	defp serialize2( scheme, user, host, port ) do
		if user != nil do
			data = Atom.to_string(scheme) <> ":" <> user <> "@" <> host
		else
			data = Atom.to_string(scheme) <> ":" <> host
		end
		
		case scheme do
			:sip -> if port != 5060, do: data <> ":" <> Integer.to_string(port), else: data
			:sips -> if port != 5061, do: data <> ":" <> Integer.to_string(port), else: data
			_ -> data <> ":" <> Integer.to_string(port)
		end
	end
	
	def serialize( uri ) do
		if uri.displayname != nil do
			"\"" <> URI.encode_www_form(uri.displayname) <> "\" <" <> 
				serialize2(uri.scheme, uri.user, uri.host, uri.port) <> ">;" <> 
				serializeParams(uri.params)
		else
			serialize2(uri.scheme, uri.user, uri.host, uri.port) <> ";" <> serializeParams(uri.params)
		end
	end
	
	@spec getParam(t,String.t) :: String.t | nil
	def getParam( uri, key  ) do 
		Dict.get(uri.params, key)
	end
end