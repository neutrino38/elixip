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

  # ── REGISTER lifetimes (RFC 3261 §10.2.4 and §20.19) ─────────────────────────
  #
  # THE one place that answers "what lifetime does this REGISTER ask for". Callers
  # add their policy on top (bounds, per-domain defaults, which code to reply);
  # none of them re-reads the headers. See CLAUDE.md, Message Layer: this rule had
  # been re-derived five times and no two derivations agreed, each divergence found
  # on real traffic (a rebinding handset read as an un-registration, a registration
  # evaporating after 1 s, a crash on a valueless `;expires`).
  #
  # The rule: a Contact's `expires` URI parameter wins **when present**, otherwise
  # the request's `Expires` header applies, otherwise the default (3600). It is
  # resolved **per contact** — a rebinding REGISTER carries the old binding with
  # `;expires=0` and the new one whose lifetime is in the header, so the request as
  # a whole asks for the longest-lived of its bindings.

  @register_default_expires 3600

  @doc "The lifetime a REGISTER gets when neither a Contact param nor a header says (RFC 3261 §20.19)."
  @spec register_default_expires() :: pos_integer()
  def register_default_expires, do: @register_default_expires

  @doc """
  The `Expires` header as an integer, or `nil` when absent (or unparseable).

  The parser already yields an integer; a binary is accepted too, because a message
  built by hand (templates, tests, a scenario) carries the header as text.
  """
  @spec expires_header(map()) :: non_neg_integer() | nil
  def expires_header(msg) do
    case Map.get(msg, :expires) do
      exp when is_integer(exp) and exp >= 0 -> exp
      exp when is_binary(exp) -> parse_expires(exp, nil)
      _ -> nil
    end
  end

  @doc """
  The `expires` URI parameter of a single Contact, or `nil` when it carries none.

  A wildcard Contact (`:*`, §10.2.2) and an unparsed Contact have no parameter of
  their own, so they read as `nil` — the header speaks for them.
  """
  @spec contact_expires_param(term()) :: non_neg_integer() | nil
  def contact_expires_param(%SIP.Uri{} = contact) do
    case SIP.Uri.get_uri_param(contact, "expires") do
      {:ok, value} -> parse_expires(value, nil)
      _ -> nil
    end
  end

  def contact_expires_param(_other), do: nil

  @doc """
  Lifetime asked for by **one** contact: its `expires` parameter when present, else
  `header_expires` (as read by `expires_header/1`), else `default`.

  Pass `default` to override the RFC default with a configured one (kelixip's
  per-domain `default_expires`).
  """
  @spec contact_expires(term(), non_neg_integer() | nil, non_neg_integer()) ::
          non_neg_integer()
  def contact_expires(contact, header_expires, default \\ @register_default_expires) do
    # 0 is a meaningful lifetime (an un-binding), and only nil is falsy here, so
    # `||` resolves the precedence without swallowing it.
    contact_expires_param(contact) || header_expires || default
  end

  @doc """
  Per-contact lifetimes of a REGISTER, in header order — `[0, 600]` is a rebinding,
  `[0]` an un-registration. Empty when the request carries no Contact at all.
  """
  @spec contact_lifetimes(map(), non_neg_integer()) :: [non_neg_integer()]
  def contact_lifetimes(msg, default \\ @register_default_expires) do
    header = expires_header(msg)

    msg
    |> Map.get(:contact)
    |> List.wrap()
    |> Enum.map(&contact_expires(&1, header, default))
  end

  @doc """
  Lifetime the request asks for as a whole: the longest-lived binding in it, or the
  header/default when it carries no Contact.
  """
  @spec requested_expires(map(), non_neg_integer()) :: non_neg_integer()
  def requested_expires(msg, default \\ @register_default_expires) do
    case contact_lifetimes(msg, default) do
      [] -> expires_header(msg) || default
      lifetimes -> Enum.max(lifetimes)
    end
  end

  @doc """
  True when the request drops every binding it mentions — i.e. its longest-lived
  binding is 0. A request that drops one contact and refreshes another is *not* an
  un-registration.
  """
  @spec unregister?(map(), non_neg_integer()) :: boolean()
  def unregister?(msg, default \\ @register_default_expires) do
    requested_expires(msg, default) == 0
  end

  # Be liberal in what we accept: a valueless `;expires` is parsed as `true`, and
  # handsets have been seen sending junk. Neither may crash the dialog reading it.
  defp parse_expires(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {n, _rest} when n >= 0 -> n
      _ -> fallback
    end
  end

  defp parse_expires(_value, fallback), do: fallback

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

  @doc "Generate a unique MIME multipart boundary token (RFC 2046)."
  def generate_boundary() do
    "elixip-boundary-" <> (:crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower))
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
    sipmsg |> Map.put(:body,  body_data) |>  Map.put(:contentlength, Kernel.byte_size(body_data)) |> Map.put(:contenttype, "application/sdp")
  end

  # Multipart/mixed body (RFC 2046): a list of two or more sub-bodies. Generate a
  # boundary, stamp it on every part, set the top-level Content-Type and compute
  # the Content-Length from the serialized body octets. Each part must be a
  # `%{contenttype: ct, data: bin}` map (extra keys are preserved).
  def update_sip_msg(sipmsg, { :body, parts }) when is_list(parts) do
    if not Enum.all?(parts, &match?(%{contenttype: _, data: _}, &1)) do
      raise "Multipart body parts must be %{contenttype: ..., data: ...} maps, got #{inspect(parts)}"
    end

    boundary = generate_boundary()
    parts = Enum.map(parts, &Map.put(&1, :boundary, boundary))
    body_octets = SIPMsg.multipart_body(parts)

    sipmsg
    |> Map.put(:body, parts)
    |> Map.put(:contenttype, "multipart/mixed; boundary=" <> boundary)
    |> Map.put(:contentlength, Kernel.byte_size(body_octets))
  end


  def update_sip_msg(sipmsg, { header, value }) do
    sipmsg |> Map.put(header, value)
  end

  @doc "Crée un message CANCEL à partir d'une requête existante"
  def cancel_request(sipmsg) when is_map(sipmsg) and is_atom(sipmsg.method) do
    cancel_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :callid, :contentlength, :cseq, :method, :ruri ]
    end
    [ seqno, _method ] = sipmsg.cseq
    fieldlist = [
      {:method, :CANCEL},
      {:contentlength, 0},
      {:cseq, [ seqno, :CANCEL]},
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
  @reply_filter [ :via, :to, :from, :route, :recordroute, :cseq, :callid, :contentlength ]

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

    rsp = req |> Map.filter(resp_filter) |> update_sip_msg(upd_map)

    # A UAS copies the Record-Route set of the request only into dialog
    # establishing 2xx responses (RFC 3261 §12.1.1). Provisional responses
    # must not carry it (reliable 1xx / 100rel is not supported).
    rsp = if resp_code in 100..199, do: Map.delete(rsp, :recordroute), else: rsp

    rsp = if Map.has_key?(req, :transid) do
      Map.put(rsp, :transid, req.transid )
    else
      add_transaction_id(rsp)
    end

    # Specific case for 200 OK and 183 Session Progress for invite
    if req.method == :INVITE and resp_code in [183, 200] do
      case Map.fetch(rsp, :body) do
        {:ok, [] } -> raise "183 or 200 OK response cannot have an empty body"
        {:ok, _ } -> nil
        :error -> raise "183 or 200 OK need to be provided with an SDP body"
      end
    end

    contact = Map.get(rsp, :contact)
    if contact == nil do
      if resp_code in 300..303 and contact == nil do
        raise "#{resp_code} response needs to be provided with a contact field"
      end

      # REGISTER is excluded on purpose: RFC 3261 §10.3 step 8 says the 200 SHOULD
      # enumerate the *current* bindings, and after an un-REGISTER (`Expires: 0`, or
      # the `Contact: *` wildcard) there are none — a Contact-less 200 is then the
      # correct answer, not a programming error.
      if resp_code in 200..202 and req.method in [ :INVITE, :UPDATE ] do
        raise "#{resp_code} response to #{req.method} needs to be provided with a contact field"
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
    # Stateless nonce, keyed by the server secret and bound to this realm: nothing
    # to store, and a nonce minted for another realm cannot be replayed here.
    authparams = %{ "realm" => realm, "nonce" => SIP.Auth.Nonce.generate(realm), authproc: "Digest" }
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
      k in [ :to, :from, :route, "Max-Forward", :callid, :contentlength ]
    end

    remote_contact = if remote_contact == nil do
      sipmsg.ruri
    else
      remote_contact
    end

    [ seqno, _method ] = sipmsg.cseq
    # build ACK according to RFC 3261 section 17.1.1.3
    # - contact is copied from the final response (provided as argument)
    # - routeset is copied too (same)
    # - cseq copy the seq number and change the method to ACK
    # - via contains only the top most via header of the original request
    # - note the to field is copied from the message passed as argument
    #   so the to needs to be modified to contain the to of the final response

    fieldlist = [
      {:method, :ACK},
      {:ruri, remote_contact},
      {:route, routeset},
      {:body, body},
      {:cseq, [ seqno, :ACK ]},
      {:via, hd(sipmsg.via)}]

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

  def is_response_for?(req_type, rsp) when is_req(req_type) and is_resp(rsp) do
    # A parsed CSeq header is stored as a [seqno, method] list (see SIPMsg).
    case Map.get(rsp, :cseq) do
      [ _seqno, method ] -> method == req_type.method
      _ -> false
    end
  end
end
