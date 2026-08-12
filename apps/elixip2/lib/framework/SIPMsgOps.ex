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
  The `expires` parameter of a single Contact, or `nil` when it carries none.

  A wildcard Contact (`:*`, §10.2.2) and an unparsed Contact have no parameter of
  their own, so they read as `nil` — the header speaks for them.

  `get_header_param/2`, because `c-p-expires` is a Contact *header* parameter
  (RFC 3261 §25.1): `<sip:x@y;expires=10>;expires=600` expires in 600 s.
  """
  @spec contact_expires_param(term()) :: non_neg_integer() | nil
  def contact_expires_param(%SIP.Uri{} = contact) do
    case SIP.Uri.get_header_param(contact, "expires") do
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

  # ── Who a request says it is from (RFC 3261 §8.1.1.3, RFC 3325 §9) ───────────
  #
  # THE one place that answers "which identity does this request assert for its
  # sender", for the same reason as the REGISTER lifetimes above (CLAUDE.md,
  # Message Layer): every caller — the monitor's `account` column, a module
  # deciding what to display or to bill — layers its policy on this single
  # reading rather than picking a header of its own.
  #
  # In decreasing order of how much the name can be trusted:
  #
  #   1. the digest `username` of Authorization / Proxy-Authorization — the only
  #      name the server has had a chance to verify;
  #   2. the user part of P-Asserted-Identity (RFC 3325) — asserted by a trusted
  #      upstream on the caller's behalf, not by the caller itself;
  #   3. the user part of From — what the caller claims, which any UA sets freely.

  @doc """
  The identity a request asserts for its sender, as a bare user name: the digest
  username it authenticates with, else the user part of P-Asserted-Identity, else
  the user part of From. `nil` when none of the three yields a name.

  P-Asserted-Identity may carry two values (RFC 3325 §9.1: one `sip:`, one
  `tel:`), on one line or on two — the first one that yields a user wins, and a
  `tel:` URI counts (its number IS the user part, even though it is not a SIP URI
  and does not parse as one).
  """
  @spec asserted_username(map()) :: String.t() | nil
  def asserted_username(msg) when is_map(msg) do
    auth_username(msg) || header_userpart(msg, "p-asserted-identity") ||
      uri_userpart(Map.get(msg, :from))
  end

  @doc """
  The digest username a request authenticates with (Authorization, else
  Proxy-Authorization), `nil` when it carries no credentials.

  This is the *claimed* username: the header is only proof once the digest has
  been checked (`check_authrequest/3`), which is the caller's business.
  """
  @spec auth_username(map()) :: String.t() | nil
  def auth_username(msg) when is_map(msg) do
    case Map.get(msg, :authorization) || Map.get(msg, :proxyauthorization) do
      %{"username" => user} -> presence(user)
      _ -> nil
    end
  end

  # A header SIPMsg has no atom for keeps the spelling the peer used as its map key
  # (`headername_to_atomkey/1`), and header names are case-insensitive (RFC 3261
  # §7.3.1) — so the lookup is too. Repeated occurrences arrive as a list.
  defp header_userpart(msg, lowercase_name) do
    msg
    |> Enum.find_value(fn
      {key, value} when is_binary(key) ->
        if String.downcase(key) == lowercase_name, do: value

      _other ->
        nil
    end)
    |> List.wrap()
    |> Enum.find_value(&value_userpart/1)
  end

  # One header value, which may itself hold several comma-separated URIs.
  defp value_userpart(value) when is_binary(value) do
    case uri_userpart(value) do
      nil -> value |> String.split(",") |> Enum.find_value(&uri_userpart/1)
      user -> user
    end
  end

  defp value_userpart(other), do: uri_userpart(other)

  defp uri_userpart(%SIP.Uri{userpart: user}), do: presence(user)

  defp uri_userpart(value) when is_binary(value) do
    value = String.trim(value)

    case SIP.Uri.parse(value) do
      {:ok, uri} -> uri_userpart(uri)
      _not_a_sip_uri -> tel_number(value)
    end
  end

  defp uri_userpart(_other), do: nil

  # `tel:+33970260233;phone-context=+33` and `<tel:+33970260233>` assert
  # +33970260233. SIP.Uri does not model a tel: URI, and teaching it to would
  # change every parse in the stack — the number is read here instead.
  @tel_uri ~r/^(?:[^<]*<)?tel:([^;>\s]+)/i

  defp tel_number(value) do
    case Regex.run(@tel_uri, value) do
      [_match, number] -> presence(number)
      _no_tel_uri -> nil
    end
  end

  defp presence(value) when is_binary(value) do
    if String.trim(value) == "", do: nil, else: value
  end

  defp presence(_other), do: nil

  @doc """
  The user part of **From**: who the sender *claims* to be, unverified.

  Deliberately not `asserted_username/1`, which answers "the best name available"
  and prefers the digest username. An authenticator needs the opposite: the raw
  claim, so it can compare it with the name the digest actually proved and refuse
  the mismatch. Reading `asserted_username/1` there would compare the digest
  username with itself and always agree — an identity check that can never fail.
  """
  @spec from_username(map()) :: String.t() | nil
  def from_username(msg) when is_map(msg), do: uri_userpart(Map.get(msg, :from))

  @doc """
  The user part of **To**: who the request is addressed to, which for a REGISTER is
  the address-of-record being bound (RFC 3261 §10.2).

  Beware the shape: `SIPMsg` parses `:ruri` and `:contact` into a `%SIP.Uri{}` but
  leaves `:to` as the RAW header string, so this is not `msg.to.userpart`. Reading
  it by hand is what produced "400 Missing To user-part" on every real REGISTER
  once already.
  """
  @spec to_username(map()) :: String.t() | nil
  def to_username(msg) when is_map(msg), do: uri_userpart(Map.get(msg, :to))

  @doc """
  Does this request belong to an **established dialog**?

  The test is the To tag (RFC 3261 §12.1): only a request sent inside a dialog
  carries one, an initial request never does. It is what separates "this
  conversation was authenticated when it was created" from "this is someone new
  knocking" — re-challenging mid-dialog buys nothing and breaks UAs.
  """
  @spec in_dialog?(map()) :: boolean()
  def in_dialog?(msg) when is_map(msg) do
    case to_uri(Map.get(msg, :to)) do
      %SIP.Uri{} = uri -> match?({:ok, tag} when is_binary(tag), SIP.Uri.get_uri_param(uri, "tag"))
      _ -> false
    end
  end

  defp to_uri(%SIP.Uri{} = uri), do: uri

  defp to_uri(value) when is_binary(value) do
    case SIP.Uri.parse(String.trim(value)) do
      {:ok, uri} -> uri
      _ -> nil
    end
  end

  defp to_uri(_other), do: nil

  @doc """
  The address-of-record a request is **for**: the user part of its Request-URI
  (RFC 3261 §10.3), or `nil` when it carries none.

  The counterpart of `asserted_username/1`, which answers who a request comes
  from. Returned verbatim: the AOR is case-insensitive, but folding it is the
  location service's rule, not the message's.
  """
  @spec target_aor(map()) :: String.t() | nil
  def target_aor(msg) when is_map(msg), do: uri_userpart(Map.get(msg, :ruri))

  # ── The SDP body, and what a re-offer asks for (RFC 3264 §8, RFC 3261 §14) ───
  #
  # THE one place that answers "what does this offer change, given the one it
  # replaces", for the same reason as the two sections above (CLAUDE.md, Message
  # Layer). A B2BUA that terminates media has to decide whether a re-INVITE or an
  # UPDATE concerns the far end at all, and that decision is a *reading* of the
  # message. The policy built on it — which kinds cross and which are answered
  # locally — stays the caller's (docs/design/b2bua_media_impl_plan.md §R4.1b).
  #
  # The SDP parser is borrowed from the media layer rather than rewritten:
  # `MediaServer.SdpTools.parse/1` is already the stack's single reading of an
  # SDP body, and a second one here would be the very duplication this section
  # exists to prevent.

  @doc """
  The SDP carried by a message, or `nil` when it carries none.

  Accepts every body shape the stack produces: a bare binary, a single part, or a
  multipart list — in which case the `application/sdp` part wins, and the first
  part is the fallback for a message whose content type is missing or misspelt.
  """
  @spec sdp_body(map()) :: binary() | nil
  def sdp_body(msg) when is_map(msg) do
    case Map.get(msg, :body) do
      sdp when is_binary(sdp) and sdp != "" ->
        sdp

      [%{data: sdp}] ->
        sdp

      list when is_list(list) and list != [] ->
        case Enum.find(list, fn part -> to_string(Map.get(part, :contenttype)) =~ "sdp" end) do
          %{data: sdp} ->
            sdp

          _ ->
            case list do
              [%{data: sdp} | _] -> sdp
              _ -> nil
            end
        end

      _ ->
        nil
    end
  end

  @typedoc """
  What a re-offer changes, relative to the offer it replaces:

    * `:no_sdp` — no body at all (an offerless re-INVITE: a session-timer
      refresh, or a peer asking *us* to offer);
    * `:media_change` — the media set moved: one added, one withdrawn (port 0),
      a type or transport changed, or a direction changed in a way that is not a
      hold;
    * `:hold` / `:resume` — the peer stopped, or resumed, wanting media
      (`a=sendonly`, `a=inactive`, or the RFC 2543 `c=0.0.0.0`);
    * `:address_change` — only where the media goes moved: `c=`, a port, an ICE
      restart, a new DTLS fingerprint;
    * `:no_change` — the offer says exactly what the previous one said;
    * `:unknown` — nothing to compare against, or an SDP neither side can parse.

  The two that a media-terminating B2BUA can absorb are `:address_change` and
  `:no_sdp` (plus `:no_change`, which asks for nothing): our endpoint has not
  moved, so the far end's media path is unchanged. Everything else — including
  `:unknown`, deliberately — concerns the far end and has to cross.
  """
  @type reoffer_kind ::
          :no_sdp | :media_change | :hold | :resume | :address_change | :no_change | :unknown

  @doc """
  Classify a re-offer against the last SDP the same peer gave us.

  `previous_sdp` is that peer's previous description — its offer, or its answer:
  both describe the same thing, which is where its media lives and what it wants
  of it. `nil` (nothing stored yet) yields `:unknown` rather than a guess.

  Precedence, when a re-offer does several things at once, is by what the far end
  needs to know: the media set first, then hold, then addressing. A peer that
  moves *and* goes on hold reads as `:hold` — swallowing that would leave it
  receiving media it asked to stop.
  """
  @spec reoffer_kind(map(), binary() | nil) :: reoffer_kind()
  def reoffer_kind(req, previous_sdp \\ nil) when is_map(req) do
    case {presence(sdp_body(req)), presence(previous_sdp)} do
      {nil, _previous} -> :no_sdp
      {_new, nil} -> :unknown
      {new, previous} -> compare_offers(new, previous)
    end
  end

  defp compare_offers(new_sdp, previous_sdp) do
    with {:ok, new} <- MediaServer.SdpTools.parse(new_sdp),
         {:ok, previous} <- MediaServer.SdpTools.parse(previous_sdp) do
      classify_offer(new, previous)
    else
      # An SDP we cannot read is not an SDP we may absorb.
      _unparseable -> :unknown
    end
  end

  defp classify_offer(new, previous) do
    cond do
      media_set(new) != media_set(previous) -> :media_change
      held?(new) and not held?(previous) -> :hold
      held?(previous) and not held?(new) -> :resume
      directions(new) != directions(previous) -> :media_change
      codecs(new) != codecs(previous) -> :media_change
      addressing(new) != addressing(previous) -> :address_change
      true -> :no_change
    end
  end

  # What each m= section IS, in offer order: RFC 3264 §8 forbids reordering or
  # dropping them, so position is identity and a disabled section (port 0) still
  # counts — its disappearance from the active set is exactly the change to spot.
  defp media_set(descs) do
    for d <- descs,
        do: {Map.get(d, :type), Map.get(d, :transport), Map.get(d, :port, 0) != 0}
  end

  # The sections that carry media right now. Everything below compares these
  # only: a section already at port 0 says nothing about where media goes.
  defp active(descs) do
    Enum.filter(descs, fn d -> Map.get(d, :supported?, false) and Map.get(d, :port, 0) != 0 end)
  end

  defp directions(descs), do: for(d <- active(descs), do: Map.get(d, :direction))

  # Which codecs each active media offers, as a set — a re-offer that merely
  # reorders its preferences has not changed what it can do.
  #
  # A narrowed codec list counts as a media change even though our own endpoint
  # could re-answer it alone: with two legs bridged, the codec both sides settled
  # on is what the direct attach relies on, and a peer that drops it has changed
  # something only the far end can answer.
  defp codecs(descs),
    do: for(d <- active(descs), do: d |> Map.get(:codecs, []) |> MapSet.new())

  # `a=sendonly`/`a=inactive` (RFC 3264 §8.4) or the pre-RFC-3264 `c=0.0.0.0`
  # that older phones still send. One media on hold is enough: a peer that holds
  # its audio has put the call on hold whatever it left its video saying.
  defp held?(descs), do: Enum.any?(active(descs), &held_media?/1)

  defp held_media?(desc) do
    Map.get(desc, :direction) in [:sendonly, :inactive] or Map.get(desc, :ip) == "0.0.0.0"
  end

  # Where the media goes and how it is protected. ICE is compared on its
  # credentials only — a re-offer that merely adds candidates for the same ufrag
  # is not a restart, and the media server learns them by other means.
  defp addressing(descs) do
    for d <- active(descs) do
      {Map.get(d, :ip), Map.get(d, :port), Map.get(d, :ice), Map.get(d, :crypto)}
    end
  end

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
    # "Max-Forwards", with the S the header actually has (§20.22, and what the
    # parser stores): spelt "Max-Forward" the test never matched, so every CANCEL
    # and every ACK we built went out without the header §8.1.1 makes mandatory
    # in a request.
    cancel_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forwards", :callid, :contentlength, :cseq, :method, :ruri ]
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

  # ── B2BUA forwarding (docs/design/b2bua_module.md §1, §4, §5) ─────────────────
  #
  # THE one place that answers "what part of a SIP message crosses a B2BUA leg
  # boundary". The session layer (SIP.Session.B2bua) decides *whether* and *where*
  # a message is relayed; these two functions decide *what survives* the crossing.

  # Fields that never cross a leg boundary: hop-scoped routing (Via, Route,
  # Record-Route, Path), the receiving leg's target (Contact), the credentials
  # presented to *us* (they answered our challenge, for our realm — the outbound
  # leg authenticates itself when challenged), and the receiving side's
  # transaction id. The dialog identity (Call-ID, tags) is cleared separately in
  # prepare_forwarded_request/2 rather than dropped: reusing the inbound
  # Call-ID/from-tag on the outbound leg would collide with the inbound dialog in
  # Registry.SIPDialog.
  @b2bua_dropped_fields [
    :via,
    :route,
    :recordroute,
    "Path",
    :contact,
    :authorization,
    :proxyauthorization,
    :transid
  ]

  # Response headers copied verbatim when a reply is relayed leg-to-leg.
  @b2bua_reply_passthrough ["Reason", "Warning", "Retry-After"]

  @doc """
  Prepare a request received on one B2BUA leg to be re-sent on another leg.

  Strips everything hop- or dialog-scoped (see `@b2bua_dropped_fields`), clears
  the dialog identity — `Call-ID` and the `From`/`To` tags are left for the
  dialog layer to mint afresh — resets the R-URI routing fields (the stamped
  `destip`/`tp_pid` point back at the leg the request came in on), replaces the
  User-Agent and decrements `Max-Forwards`.

  The body and every other header (identity `From`/`To`, `P-Asserted-Identity`,
  `Privacy`, custom `X-*`…) cross unchanged. Callers layer their own policy on
  top; they do not re-read the message.

  Returns `{:ok, req}`, or `{:error, :too_many_hops}` when `Max-Forwards` is
  exhausted (RFC 3261 §16.6 — answer 483).

  Options: `:useragent` overrides the User-Agent stamped on the forwarded
  request (defaults to the `:elixip2 :useragent` application env).
  """
  @spec prepare_forwarded_request(map(), keyword()) ::
          {:ok, map()} | {:error, :too_many_hops}
  def prepare_forwarded_request(req, opts \\ []) when is_req(req) do
    case forwarded_max_forwards(req) do
      {:error, _} = err ->
        err

      {:ok, max_forwards} ->
        useragent =
          Keyword.get(
            opts,
            :useragent,
            Application.get_env(:elixip2, :useragent, "Elixipp/0.1")
          )

        req2 =
          req
          |> Map.drop(@b2bua_dropped_fields)
          |> Map.put("Max-Forwards", max_forwards)
          |> Map.put(:callid, nil)
          |> strip_tag(:from)
          |> strip_tag(:to)
          |> Map.put(:useragent, useragent)
          |> Map.update(:ruri, nil, &reset_uri_routing/1)

        {:ok, req2}
    end
  end

  @doc """
  What a response relayed leg-to-leg carries over: the body (normalized to the
  `[%{contenttype, data}]` part shape so its Content-Type survives
  `update_sip_msg/2`) and the `#{inspect(@b2bua_reply_passthrough)}` headers.
  Returned as an `upd_fields` keyword list for `SIP.Dialog.reply/5`.

  The Contact is deliberately NOT copied: the relayed response must advertise
  *our* contact on the answering leg, which the reply path adds (same rule as
  `reply_invite_with_sdp`).
  """
  @spec forwarded_reply_fields(map()) :: keyword()
  def forwarded_reply_fields(resp) when is_resp(resp) do
    body_fields =
      case normalize_forwarded_body(Map.get(resp, :body), Map.get(resp, :contenttype)) do
        nil -> []
        parts -> [body: parts]
      end

    passthrough = for h <- @b2bua_reply_passthrough, v = Map.get(resp, h), do: {h, v}
    body_fields ++ passthrough
  end

  # Current Max-Forwards, tolerant of the shapes seen in traffic: parsed integer,
  # textual value, absent (RFC 3261 §20.22 default 70), or garbage (treated as
  # the default rather than taking the whole relay down).
  defp forwarded_max_forwards(req) do
    value =
      case Map.get(req, "Max-Forwards", 70) do
        v when is_integer(v) ->
          v

        v when is_binary(v) ->
          case Integer.parse(v) do
            {n, _} -> n
            :error -> 70
          end

        _ ->
          70
      end

    if value <= 0, do: {:error, :too_many_hops}, else: {:ok, value - 1}
  end

  # Remove the `tag` parameter from a From/To header (kept as a %SIP.Uri{} or a
  # binary depending on the path the message took). A missing or unparsable
  # header is left untouched.
  defp strip_tag(req, field) do
    case Map.get(req, field) do
      %SIP.Uri{} = uri ->
        Map.put(req, field, SIP.Uri.delete_param(uri, "tag"))

      bin when is_binary(bin) ->
        case SIP.Uri.parse(bin) do
          {:ok, uri} ->
            Map.put(req, field, SIP.Uri.delete_param(uri, "tag"))

          _ ->
            req
        end

      _ ->
        req
    end
  end

  # Clear the routing side of a URI (destination and transport handles) while
  # keeping its textual identity — the forwarded request must not short-circuit
  # back over the connection it arrived on.
  defp reset_uri_routing(%SIP.Uri{} = uri) do
    %SIP.Uri{uri | destip: nil, destport: 0, destproto: nil, tp_module: nil, tp_pid: nil}
  end

  defp reset_uri_routing(other), do: other

  # nil / empty body -> nothing to carry; a bare binary is wrapped with its
  # Content-Type (defaulting to SDP, the overwhelmingly common case); the parser
  # part shapes pass through as-is.
  defp normalize_forwarded_body(nil, _ct), do: nil
  defp normalize_forwarded_body("", _ct), do: nil
  defp normalize_forwarded_body([], _ct), do: nil

  defp normalize_forwarded_body(bin, ct) when is_binary(bin),
    do: [%{contenttype: ct || "application/sdp", data: bin}]

  defp normalize_forwarded_body(parts, _ct) when is_list(parts), do: parts

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

  # The To tag a response carries when the request itself named none. (When the
  # request DID name one, §8.2.6.2 requires echoing it and this is never reached —
  # including on a 100, which is why an in-dialog request still gets its tag back.)
  #
  # A 100 (Trying) goes out WITHOUT one, and that beats an explicit `totag` handed
  # in by the caller. RFC 3261 §8.2.6.2 merely permits it — "with the exception of
  # the 100 (Trying) response, in which a tag MAY be present" — but §17.2.1 is
  # firmer for the response a server transaction emits: "the insertion of tags in
  # the To header field of the response (when none was present in the request) is
  # downgraded from MAY to SHOULD NOT". kamailio applies that to its TU-generated
  # 100 too — an explicit `sl_reply(100, "Trying")` in kamailio.cfg adds no tag —
  # and we follow, so the rule holds by role rather than by which layer composed
  # the message. The reason behind the exception: a 100 is hop-by-hop (§16.7: "a
  # stateful proxy MUST NOT forward any 100 (Trying) response"), it is emitted
  # before anyone knows which UAS will answer, and §8.2.6.2's "same tag for all
  # responses" excepts it precisely so the real UAS's tag may differ.
  #
  # Above 100 a tag is mandatory, and when we have none to hand we MINT one rather
  # than fail: raising here killed the whole server transaction, so a caller who
  # cancelled a call that had only ever been answered 100 got no 200 to its CANCEL
  # at all, retransmitted, and its INVITE stayed unanswered until it timed out.
  defp response_totag(100, _totag), do: nil
  defp response_totag(_resp_code, totag) when is_binary(totag), do: totag
  defp response_totag(_resp_code, _totag), do: generate_from_or_to_tag()

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

      # The request already names a To tag (an in-dialog request, a re-INVITE):
      # a response echoes it, RFC 3261 §8.2.6.2.
      { :ok, _old_totag } ->
        upd_map

      { :no_such_param, nil } ->
        case response_totag(resp_code, totag) do
          nil -> upd_map
          tag -> Map.put(upd_map, :to, SIP.Uri.set_header_param(to_uri, "tag", tag))
        end
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

  @doc """
  Which response header carries a digest challenge for `resp_code`: a **401**
  answers as a UAS (`WWW-Authenticate`, RFC 3261 §22.2), a **407** as a proxy
  (`Proxy-Authenticate`, §22.3).

  The single reading of that mapping — a caller composing a challenge asks for the
  header instead of re-deriving it from the code (`add_authorization_to_req/6` is
  its inverse, on the request side).
  """
  @spec challenge_header(401 | 407) :: :wwwauthenticate | :proxyauthenticate
  def challenge_header(401), do: :wwwauthenticate
  def challenge_header(407), do: :proxyauthenticate

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

    Map.put(rsp, challenge_header(resp_code), authparams)
  end

  def challenge_request(req, resp_code, "NTLM", realm, nil, upd_fields, totag) when is_atom(req.method) and resp_code in [401, 407] do
    rsp = reply_to_request(req, resp_code, sip_reason(resp_code), upd_fields, totag)
    authparams = %{ "realm" => realm, authproc: "NTLM" }
    Map.put(rsp, challenge_header(resp_code), authparams)
    raise "NTLM challenge not yet implemented"
  end

  @doc "Crée un message ACK à partir d'une requête existante"
  def ack_request(sipmsg, remote_contact, routeset \\ :ignore , body \\ []) when is_map(sipmsg) and sipmsg.method in [:INVITE, :UPDATE] do
    # "Max-Forwards" — see cancel_request/1 above for the missing S.
    ack_filter = fn { k, _v } ->
      k in [ :to, :from, :route, "Max-Forwards", :callid, :contentlength ]
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
        # The digest is computed over the Request-URI *as it goes on the wire*
        # (RFC 2617 A2 = Method ":" digest-uri-value, and RFC 3261 §22.4 has the
        # client's `uri=` mirror the Request-URI), so it must be the same
        # serialization the Request-Line uses — no display name, no header
        # parameters. `to_string/1` here would digest a different string than the
        # one sent as soon as the target came from a stored Contact.
        { :ok, digest_uri } = SIP.Uri.serialize_ruri(req.ruri)
        autorisation_params = SIP.Auth.build_auth_response(algo, username, authparams["nonce"], authparams["realm"],
                                                  passwd_or_hash, pwdformat, req.method, digest_uri)

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
        # Same serialization as the sender used (see add_authorization_to_req/6):
        # the Request-URI form, not the header-field form.
        { :ok, digest_uri } = SIP.Uri.serialize_ruri(req.ruri)
        response = SIP.Auth.compute_auth_response_from_pwd(
          authparams["algorithm"], authparams["username"],
          authparams["nonce"], authparams["realm"], password,
          req.method, digest_uri )

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
