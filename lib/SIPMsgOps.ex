defmodule SIP.Msg.Ops do
	@moduledoc "Operations on SIP messages"

  require SIP.Auth

  defp build_via_addr( local_ip , 5060, "UDP" ) do
    local_ip = if is_tuple(local_ip), do: SIP.NetUtils.ip2string(local_ip), else: local_ip
    "SIP/2.0/UDP " <> local_ip
  end

  defp build_via_addr( local_ip , 5060, "TCP" ) do
    local_ip = if is_tuple(local_ip), do: SIP.NetUtils.ip2string(local_ip), else: local_ip
    "SIP/2.0/TCP " <> local_ip
  end

  defp build_via_addr( local_ip , 5061, "TLS" ) do
    local_ip = if is_tuple(local_ip), do: SIP.NetUtils.ip2string(local_ip), else: local_ip
    "SIP/2.0/TLS " <> local_ip
  end

  defp build_via_addr( local_ip , local_port, transport ) when is_integer(local_port) do
    if local_port < 1000 or local_port > 65535 do
      # Un port non privilegié UDP ou TCP est compris entre 1000 et 65535
      raise "Invalid port #{local_port} for via header"
    end

    if String.upcase(transport, :ascii) not in ["UDP", "TCP", "TLS", "WS", "WSS"] do
      raise "Invalid transport #{transport} for via header"
    end

    local_ip = if is_tuple(local_ip), do: SIP.NetUtils.ip2string(local_ip), else: local_ip
    "SIP/2.0/" <> String.upcase(transport) <> " " <> local_ip <> ":" <> Integer.to_string(local_port)
  end

  defguard is_req(msg) when is_map(msg) and is_atom(msg.method)

  defguard is_this_req(msg, method) when is_req(msg) and msg.method == method

  defguard is_resp(msg) when msg.method == false

  defguard is_1xx_resp(msg) when is_resp(msg) and msg.response in 100..199

  defguard is_2xx_resp(msg) when is_resp(msg) and msg.response in 200..299

  defguard is_3xx_resp(msg) when is_resp(msg) and msg.response in 300..399

  defguard is_failure_resp(msg) when is_resp(msg) and msg.response in 400..699



  @doc "Add a tomost via"
  def add_via(sipmsg, { local_ip, local_port, transport }, branch_id, additional_params \\ nil) when is_bitstring(branch_id) do
    via = build_via_addr(local_ip, local_port, transport)
    via = cond do
      is_bitstring(additional_params) -> via <> additional_params <> ";branch=" <> branch_id
      additional_params == nil -> via <> ";branch=" <> branch_id
      #To do add, list of tuples and maps
    end

    newvia = case Map.get(sipmsg, :via) do
      nil -> [ via ]
      oldvia when is_list(oldvia) -> [ via | oldvia ]
      _ -> raise "Invalid via header"
    end
    # Add the new via header as the head of the list and change the transaction id
    Map.put(sipmsg, :via, newvia) |> Map.put(:transid, branch_id)
  end

  @doc "Return a SIP reason given a SIP code"
  def sip_reason(sip_code) when sip_code in 100..607 do
    case sip_code do
      100 -> "Trying"
      180 -> "Ringing"
      181 -> "Call is being forwarded"
      182 -> "Call queued"
      183 -> "Session progress"
      199 -> "Early Dialog terminated"
      200 -> "OK"
      202 -> "Accepted"
      204 -> "No Notification"
      300 -> "Multiple choices"
      301 -> "Moved permanently"
      302 -> "Moved temporarily"
      305 -> "Use proxy"
      380 -> "Alternative service"
      400 -> "Bad request"
      401 -> "Unauthorized"
      402 -> "Payment required"
      403 -> "Forbidden"
      404 -> "Not found"
      405 -> "Method not allowed"
      406 -> "Not acceptable"
      407 -> "Proxy authentication required"
      408 -> "Request timeout"
      410 -> "Gone"
      413 -> "Request entity too large"
      414 -> "Request URI too long"
      415 -> "Unsupported media type"
      416 -> "Unsupported URI scheme"
      417 -> "Unknown resource priority"
      418 -> "I'm a teapot"
      420 -> "Bad extension"
      421 -> "Extension required"
      422 -> "Session interval too small"
      423 -> "Interval too brief"
      424 -> "Bad location information"
      428 -> "Use identity header"
      429 -> "Provide referrer identity"
      430 -> "Flow failed"
      433 -> "Anonymity disallowed"
      436 -> "Bad identity-Info"
      437 -> "Unsupported certificate"
      438 -> "Invalid identity header"
      439 -> "First hop Lacks Outbound Support"
      440 -> "Max-Breadth Exceeded"
      469 -> "Bad Info Package"
      470 -> "Consent needed"
      478 -> "Unresolvable destination"
      480 -> "Temporarily unavailable"
      481 -> "Call leg/transaction does not exist"
      482 -> "Loop detected"
      483 -> "Too many hops"
      484 -> "Address incomplete"
      485 -> "Ambiguous"
      486 -> "Busy here"
      487 -> "Request terminated"
      488 -> "Not acceptable here"
      491 -> "Request pending"
      493 -> "Undecipherable"
      494 -> "Security agreement required"
      500 -> "Server internal error"
      501 -> "Not implemented"
      502 -> "Bad gateway"
      503 -> "Service unavailable"
      504 -> "Server timeout"
      505 -> "Version not supported"
      513 -> "Message too large"
      580 -> "Precondition Failure"
      600 -> "Busy everywhere"
      603 -> "Decline"
      604 -> "Does not exist anywhere"
      606 -> "Not Acceptable"
      _ -> "Unknown SIP Code"
    end
  end


  @doc "Génère une valeur aléatoire pour le paramètre branch"
  def generate_branch_value() do
    # Génère une chaîne aléatoire de 20 caractères en ajoutant le numéro aléatoire
    random_branch = :crypto.strong_rand_bytes(10) |> Base.encode16
    branch_value = String.replace(random_branch, ~r/[^a-f0-9]/, "")

    # Assurez-vous que la chaîne commence par "z9hG4bK" comme requis par RFC 3261
    "z9hG4bK" <> branch_value
  end


  @doc "Génère une valeur aléatoire pour le paramètre fromtag ou totag"
  def generate_from_or_to_tag() do
    random_branch = :crypto.strong_rand_bytes(10) |> Base.encode16
    String.replace(random_branch, ~r/[^a-f0-9]/, "")
  end

  @doc "Met a jour ou ajout des champs dans un message SIP"
  def update_sip_msg(sipmsg, fields) when is_list(fields) do
    Enum.reduce(fields, sipmsg, fn {header, value}, acc ->
      update_sip_msg(acc, { header, value})
    end)
  end

  def update_sip_msg(sipmsg, fields) when is_map(fields) do
    Enum.reduce(fields, sipmsg, fn {header, value}, acc ->
      update_sip_msg(acc, { header, value})
    end)
  end

  # Ignore update
  def update_sip_msg(sipmsg, { _header, :ignore }) do
    sipmsg
  end

  # Remove update
  def update_sip_msg(sipmsg, { header, nil }) do
    Map.delete(sipmsg, header)
  end

  # Specific case for contact
  def update_sip_msg(sipmsg, { :contact, value }) when is_bitstring(value) do
    { :ok, contact_uri } = SIP.Uri.parse(value)
    sipmsg |> Map.put(:contact, contact_uri)
  end

  # Specific case for body
  def update_sip_msg(sipmsg, { :body, [] } ) do
    sipmsg |> Map.put(:body, []) |> Map.put(:contentlength, 0)
  end

  def update_sip_msg(sipmsg, { :body, [ %{ contenttype: ctype, data: body_data } ] } ) do
    sipmsg |> Map.put(:body, [%{ contenttype: ctype, data: body_data }]) |> Map.put(:contenttype, ctype) |> Map.put(:contentlength, Kernel.byte_size(body_data))
  end

  def update_sip_msg(sipmsg, { :body, body_data } ) when is_binary(body_data) do
    sipmsg |> Map.put(:body,  body_data) |>  Map.put(:contentlength, Kernel.byte_size(body_data))
  end

  def update_sip_msg(_sipmsg, { :body, body_list }) when is_list(body_list) do
    raise "Multipart bodies are not yet supported"
  end


  def update_sip_msg(sipmsg, { header, value }) do
    sipmsg |> Map.put(header, value)
  end

  @doc "Crée un message CANCEL à partir d'une requête existante"
  def cancel_request(sipmsg) when is_map(sipmsg) and is_atom(sipmsg.method) do
    cancel_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    fieldlist = [
      {:method, :CANCEL},
      {:contentlength, 0},
      {:body, []}]

    sipmsg |> update_sip_msg(fieldlist) |> Map.filter(cancel_filter)
  end

  def cancel_request(sipmsg) do
    raise "passed argument is not a SIP request"
    sipmsg
  end

  def add_transaction_id(msg) do
		cond do
			Map.has_key?(msg, :via) == false ->
				# No via header
				{ :ok, Map.put(msg, :transid, nil) }

			is_nil(msg.via) or msg.via == [] ->
				# Empty Via header
				{ :ok, Map.put(msg, :transid, nil) }

			length(msg.via) >= 1 ->
				# Get topmost via and branch parameter
				[ _transport, topmost_via ] = String.split(Enum.at(msg.via, 0), " ", parts: 2)

				case SIP.Uri.get_uri_param("sip:" <> topmost_via, "branch") do
					{ :ok, branch } ->
            if String.starts_with?(branch, "z9hG4bK") do
              Map.put(msg, :transid, branch)
            else
              raise("Invalid SIP message. branch ID does not start with z9hG4bK")
            end
					{ :no_such_param, nil } -> raise("Invalid SIP message. No branch parameter in the topmost Via")
					{ _code, _parsed_via } -> raise("Invalid SIP message. Failed to parse Via header")
				end
		end
	end
  @reply_filter [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]

  @spec reply_to_request(
          %{:method => atom(), :to => binary(), optional(any()) => any()},
          integer(),
          binary() | nil,
          list(),
          binary() | nil
        ) :: any()
  @doc "Build a SIP reply given a SIP request"
  def reply_to_request(req, resp_code, reason, upd_fields \\ [], totag \\ nil) when is_atom(req.method) and resp_code in 100..699 do
    resp_filter = fn { k, _v } ->
      k in @reply_filter
    end

    reason = if is_nil(reason) do
      sip_reason(resp_code)
    else
      reason
    end

    fieldlist = %{
      method: false,
      reason: reason,
      response: resp_code,
      body: []}

    # Merge upd_fields and fieldlist. The content of upd_fields take priority. Remove fields that are compted
    # automatically
    upd_map = Map.merge(fieldlist, Map.new(upd_fields)) |> Map.delete(:contentlength)

    # If totag is missing add it
    { :ok, to_uri } = SIP.Uri.parse(req.to)
    upd_map = case SIP.Uri.get_uri_param(to_uri, "tag") do

      #If "to" header has no tag and tag is specified
      { :no_such_param, nil } ->
        if totag != nil do
          to_uri_modified = SIP.Uri.set_uri_param(to_uri, "tag", totag)
          Map.put(upd_map, :to, to_uri_modified)
        else
          if resp_code > 100 do
            raise "Missing totag for SIP response #{resp_code} > 100"
          else
            fieldlist
          end
        end

      { :ok, _old_totag } ->
        upd_map
    end

    rsp = req |> Map.filter(resp_filter) |> update_sip_msg(upd_map) |> add_transaction_id()

    # Specific case for 200 OK and 183 Session Progress for invite
    if req.method == :INVITE and resp_code in [183, 200] do
      case Map.fetch(rsp, :body) do
        {:ok, [] } -> raise "183 or 200 OK response cannot have an empty body"
        {:ok, _ } -> nil
        :error -> raise "183 or 200 OK need to be provided with an SDP body"
      end
    end

    if resp_code in 300..303 or resp_code in 200..202 do
      case Map.fetch(rsp, :contact) do
        {:ok, _ } -> nil
        :error -> raise "#{resp_code} response needs to be provided with a contact field"
      end
    end

    rsp
  end

  @spec challenge_request(
          %{:method => atom() | false, :to => binary(), optional(any()) => any()},
          401 | 407,
          <<_::48>>,
          binary()
        ) :: map()
  @doc "Create a 401 or a 407 response and compute the challenge"
  def challenge_request(req, resp_code, authproc, realm, algorithm \\ nil, upd_fields \\ [], totag \\ nil)

  def challenge_request(req, resp_code, "Digest", realm, algorithm, upd_fields, totag) when is_atom(req.method) and resp_code in [401, 407] do
    rsp = reply_to_request(req, resp_code, sip_reason(resp_code), upd_fields, totag)
    authparams = %{ "realm" => realm, "nonce" => SIP.Auth.generate_nonce(), authproc: "Digest" }
    authparams = if algorithm in [ "MD5", "SHA1", "SHA256" ], do: Map.put(authparams, "algorithm", algorithm), else: algorithm

    header = case resp_code do
      401 -> :wwwauthenticate
      407 -> :proxyauthenticate
    end
    Map.put(rsp, header, authparams)
  end

  def challenge_request(req, resp_code, "NTLM", realm, nil, upd_fields, totag) when is_atom(req.method) and resp_code in [401, 407] do
    rsp = reply_to_request(req, resp_code, sip_reason(resp_code), upd_fields, totag)
    authparams = %{ "realm" => realm, authproc: "NTLM" }
    header = case resp_code do
      401 -> :wwwauthenticate
      407 -> :proxyauthenticate
    end
    Map.put(rsp, header, authparams)
    raise "NTLM challenge not yet implemented"
  end

  @doc "Crée un message ACK à partir d'une requête existante"
  def ack_request(sipmsg, remote_contact, routeset \\ :ignore , body \\ []) when is_map(sipmsg) and sipmsg.method in [:INVITE, :UPDATE] do
    ack_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    remote_contact = if remote_contact == nil do
      sipmsg.ruri
    else
      remote_contact
    end

    # update fields
    fieldlist = [
      {:method, :ACK},
      {:ruri, remote_contact},
      {:route, routeset},
      {:body, body}]

    # Update message
    sipmsg |> Map.filter(ack_filter) |> update_sip_msg(fieldlist)
  end

  @doc "Crée une requête autentifiée à partir d'une requête non authentifiée et d'en entête auth"
  def add_authorization_to_req(req, authparams, autheader, username, passwd_or_hash, pwdformat) when is_atom(req.method) do

    header2 = case autheader do
      :wwwauthenticate -> :authorization
      :proxyauthenticate -> :proxyauthorization
      _ ->  raise "Invalid authentication header #{autheader}"
    end

    case SIPMsg.check_required_params(authparams, [ "nonce", "realm"]) do
      :ok ->
        algo = Map.get(authparams, "algorithm", "MD5")
        autorisation_params = SIP.Auth.build_auth_response(algo, username, authparams["nonce"], authparams["realm"],
                                                  passwd_or_hash, pwdformat, req.method, to_string(req.ruri))

        # Increment CSeq to start a new transaction
        new_cseq = if Map.get(req, :cseq) != nil, do: hd(req.cseq) + 1, else: 1

        # Build new request (delete auth header, add autorization header and overwrite CSeq)
        upd_map = %{ header2 => autorisation_params, autheader => nil, cseq: [ new_cseq, req.method ]}
        update_sip_msg(req, upd_map)

      { :ko, mparam } ->
        raise "Invalid autentication params. Missing #{mparam} parameter"
    end
  end

  defp check_nonce({ header, authparams}, nonce) do
    if !is_nil(nonce) and authparams["nonce"] != nonce do
      { :nonce_mismatch, authparams }
    else
      # Skip nonce check
      { header, authparams }
    end
  end

  defp get_auth_params_and_check_nonce(req, nonce) do
    cond do
      Map.has_key?(req, :authorization)
        -> { :authorization, Map.get(req, :authorization) } |> check_nonce(nonce)
      Map.has_key?(req, :proxyauthorization)
        -> { :proxyauthorization, Map.get(req, :proxyauthorization) } |> check_nonce(nonce)
      true -> { :no_auth_header, nil }
    end
  end



  @doc """
  Check authenticated request- check that auth header is valid
  req: request with auth header
  nonce: nonce that was sent in the challenge response
  """
  def check_authrequest(req, password, nonce \\ nil) when is_req(req) do

    case get_auth_params_and_check_nonce(req, nonce) do
      { header, authparams } when header in [ :authorization, :proxyauthorization ] ->
        response = SIP.Auth.compute_auth_response_from_pwd(
          authparams["algorithm"], authparams["username"],
          authparams["nonce"], authparams["realm"], password,
          req.method, req.ruri )

        if response == authparams["response"] do
          :ok
        else
          :invalid_password
        end

      { header, nil } -> header

      { :nonce_mismatch, _authparams } -> :nonce_mismatch
    end
  end

end
