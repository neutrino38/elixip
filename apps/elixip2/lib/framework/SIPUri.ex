defmodule SIP.Uri do
  @typedoc """
  A parsed SIP URI. `destip`/`destport`/`destproto`/`tp_module`/`tp_pid` are the
  transport info attached once the URI has been resolved or received (see
  `has_tp_info/1`); they are nil on a freshly parsed URI.

  `params` holds the URI parameters — those *inside* the angle brackets, the
  `uri-parameters` of RFC 3261 §25.1 — and `hparams` the header field parameters
  that follow the closing bracket (`contact-params`, `to-param`, …). The two are
  NOT interchangeable and keeping them apart is the point: see the module doc.
  """
  @type t :: %__MODULE__{
          displayname: String.t() | nil,
          userpart: String.t() | nil,
          domain: String.t() | nil,
          port: non_neg_integer() | nil,
          scheme: String.t(),
          proto: String.t(),
          destip: tuple() | nil,
          destport: non_neg_integer(),
          destproto: String.t() | nil,
          tp_module: module() | nil,
          tp_pid: pid() | nil,
          params: %{optional(String.t()) => String.t() | true},
          hparams: %{optional(String.t()) => String.t() | true}
        }

  @moduledoc """
  Parsing and serializing of SIP URIs (RFC 3261 §19.1, ABNF §25.1).

  ## URI parameters vs header parameters

  In `"Bob" <sip:bob@host;transport=tcp>;expires=60;+sip.instance="<urn:uuid:…>"`
  there are two distinct parameter sets, and the closing bracket is the frontier:

    * `transport=tcp` is a **URI parameter** — part of the address. It travels
      wherever the address travels, and RFC 3261 §19.1.5 makes carrying it
      mandatory: *"An implementation MUST include any provided transport, maddr,
      ttl, or user parameter in the Request-URI of the formed request. […]
      Unknown URI parameters MUST be placed in the message's Request-URI."*
    * `expires` and `+sip.instance` are **header field parameters** — they
      describe the *binding*, not the address (`contact-param = (name-addr /
      addr-spec) *(SEMI contact-params)`, §25.1). Putting them on a Request-URI
      is what §16.6 item 2 forbids: *"If the URI contains any parameters not
      allowed in a Request-URI, they MUST be removed."*

  The distinction is not academic. A header parameter's value may be a
  `quoted-string` (`gen-value = token / host / quoted-string`) while a URI
  parameter's may not (`pvalue = 1*paramchar`, and `paramchar` admits neither
  `"` nor `<`, `>`, `,`) — so `+sip.instance="<urn:uuid:…>"` is not even
  *expressible* as a URI parameter.

  This module used to merge both sets into `params`, losing the frontier for
  good. Everything downstream then had to guess, and a denylist of "parameters
  that are really header parameters" could never be complete: `q` and `expires`
  were listed, `+sip.instance` / `+org.linphone.specs` / `reg-id` / `methods` /
  `pub-gruu` were not. A forwarded INVITE consequently went out as
  `INVITE "Bob" <sip:bob@host>;+sip.instance="<urn:uuid:…>";transport=tcp
  SIP/2.0` — a Request-Line that no parser accepts (`Request-URI = SIP-URI /
  SIPS-URI / absoluteURI`, never a `name-addr`), and the call hung with no
  answer at all. Hence `params` / `hparams`, and `serialize_ruri/1` as the only
  way a Request-URI reaches the wire.

  Reading is deliberately tolerant, writing is strict: `get_uri_param/2` finds a
  parameter in either set (a UA that misplaces `transport` after the bracket
  still gets TCP), while `set_uri_param/3` files the parameter where it belongs
  and `serialize/1` puts each set back on its own side of the bracket.
  """

  defstruct displayname: nil,
            userpart: nil,
            domain: nil,
            port: nil,
            scheme: "sip:",
            proto: "UDP",
            # IP to be used
            destip: nil,
            # port to be used
            destport: 0,
            destproto: nil,
            # transport module
            tp_module: nil,
            # transport PID
            tp_pid: nil,
            # URI parameters: inside the <>
            params: %{},
            # header field parameters: after the >
            hparams: %{}

  # Never on a Request-URI. `method` because §19.1.5 says so explicitly ("The
  # method parameter MUST NOT be placed in the Request-URI"); it names the method
  # of the request to form, it is not part of the address.
  @non_ruri_params ~w(method)

  # The uri-parameters RFC 3261 §19.1.1 names in the grammar. Their presence in
  # `params` is what forces the angle brackets on a serialized header URI (see
  # serialize/1): each of them is meaningless as a header parameter, while a name
  # outside this list may be either — the positional parser cannot tell — and so
  # keeps the side it was parsed on.
  @uri_nature_params ~w(transport user method maddr ttl lr)

  defp parse_uri_parameters(param_list) do
    params =
      Enum.map(param_list, fn pv ->
        # Split on the first '=' only: quoted values may contain '='
        # (e.g. base64 keys) and must stay intact
        case String.split(pv, "=", parts: 2) do
          [p, v] -> {p, v}
          [p] -> {p, true}
        end
      end)

    # Convert list of couples [ {p1, v1}, {p2, v2}, ... ]
    # into a map
    Map.new(params)
  end

  # Split a parameter string on ";" respecting double-quoted values, so that
  # params like received="sip:1.2.3.4:5060;transport=TLS" are never split in
  # the middle. Empty fragments are dropped.
  defp split_params(param_str) do
    {parts, cur, _in_quote} =
      Enum.reduce(String.graphemes(param_str), {[], "", false}, fn ch, {parts, cur, in_quote} ->
        cond do
          ch == "\"" -> {parts, cur <> "\"", !in_quote}
          ch == ";" and not in_quote -> {[cur | parts], "", false}
          true -> {parts, cur <> ch, in_quote}
        end
      end)

    [cur | parts]
    |> Enum.reverse()
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  # parse domain, user@domain, user@domain:port

  defp parse_core_uri(scheme, core_uri_str) do
    case String.split(core_uri_str, "@") do
      [user, domainport] ->
        # `*`, not `+`, on the tail: a one-character user part is legal (RFC 3261
        # §19.1.1 user = 1*…) and common in test labs and short extensions. Requiring
        # a second character made SIP.Uri.parse/1 fail on `sip:1@example.com`, and a
        # URI that does not parse discards the whole message — a REGISTER from
        # extension "1" was answered by nothing at all.
        if String.match?(user, ~r/^[a-zA-Z0-9\+][a-zA-Z0-9\-\._]*$/) do
          tmpuri = parse_core_uri(scheme, domainport)

          if is_map(tmpuri) do
            Map.put(tmpuri, :userpart, user)
          else
            tmpuri
          end
        else
          nil
        end

      [domainport] ->
        case String.split(domainport, ":") do
          [domain, port] ->
            if String.match?(port, ~r/^[0-9]+$/) do
              tmpuri = parse_core_uri(scheme, domain)

              if is_map(tmpuri) do
                Map.put(tmpuri, :port, String.to_integer(port))
              else
                tmpuri
              end
            else
              :invalid_sip_uri_port
            end

          [domain] ->
            if String.match?(domain, ~r/^[a-zA-Z0-9\-\.]+$/) do
              %SIP.Uri{domain: domain}
            else
              :invalid_sip_domain
            end
        end
    end
  end

  @doc """
  Parse a single SIP URI and store its parts in a map
  """
  @spec parse(bitstring()) :: {atom(), map()}
  def parse(uri_string) do
    proto =
      if String.contains?(uri_string, "sips:") do
        "sips:"
      else
        "sip:"
      end

    case String.split(uri_string, proto, parts: 2) do
      ["", part2] ->
        # Form sip:user@domain;param=value
        parts = split_params(part2)

        # parse core URI
        case parse_core_uri(proto, Enum.at(parts, 0)) do
          err when is_atom(err) ->
            {err, Map.new()}

          core_uri ->
            # Parse parameters
            params = parse_uri_parameters(Enum.drop(parts, 1))

            finalport =
              if core_uri.port != nil do
                core_uri.port
              else
                if proto == "sips:" do
                  5061
                else
                  5060
                end
              end

            finaluri = %SIP.Uri{core_uri | scheme: proto, params: params, port: finalport}

            # Fix protocol. get_transport/1 reads the `transport` parameter first and
            # falls back to sips: -> TLS, so BOTH URI forms agree on `proto`: the
            # bracketed one derived it from the parameter while this one did not, and
            # `sip:x@y;transport=tcp` came out claiming UDP.
            finaluri = %SIP.Uri{finaluri | proto: get_transport(finaluri)}
            {:ok, finaluri}
        end

      ["<", part2] ->
        # Form <sip:user@domain>;param=value
        [core_uri_str, params_str] = String.split(part2, ">", parts: 2)

        case SIP.Uri.parse(proto <> core_uri_str) do
          {:ok, core_uri} ->
            # The closing bracket is the frontier (see the module doc): what the
            # recursive parse above collected is the URI parameters, what follows
            # here is the header field parameters. They are kept apart — merging
            # them is what sent a `name-addr` out as a Request-URI.
            header_params = params_str |> split_params() |> parse_uri_parameters()

            # `get_transport/1` on the assembled URI, not on `core_uri`: it reads
            # both sets, so a UA that writes `<sip:x@y>;transport=tcp` — the
            # parameter misplaced outside the bracket — is still understood as TCP
            # instead of silently defaulting to UDP.
            uri = %SIP.Uri{core_uri | hparams: header_params}
            uri = %SIP.Uri{uri | proto: get_transport(uri)}

            if uri.scheme == "sips" and uri.proto != "TLS" do
              raise "Invalid URI. sips is specified and transport is not TLS"
            else
              {:ok, uri}
            end

          {code, core_uri} ->
            {code, core_uri}
        end

      [part1, part2] ->
        # Form "Display Name" <sip:user@domain>;param=value
        # Form "Display Name"<sip:user@domain>;param=value
        # Form DisplayName <sip:user@domain>;param=value

        display_name =
          cond do
            # test "Display Name" <....
            String.contains?(part1, "\" <") ->
              [d_name, _truc] = String.split(part1, "\" <")
              URI.decode_www_form(String.slice(d_name, 1..-1//1))

            # test "Display Name"<....
            String.contains?(part1, "\"<") ->
              [d_name, _truc] = String.split(part1, "\"<")
              # URI.decode_www_form(String.slice(d_name, 1..-1))
              URI.decode_www_form(String.slice(d_name, 1..-1//1))

            # test DisplayName <....
            String.contains?(part1, " <") ->
              [d_name, _truc] = String.split(part1, " <")
              URI.decode_www_form(d_name)

            # test DisplayName <....
            String.contains?(part1, "<") ->
              [d_name, _truc] = String.split(part1, "<")
              d_name

            # Parse error
            true ->
              part1
          end

        # Recurse to parse the URI part
        case SIP.Uri.parse("<" <> proto <> part2) do
          {:ok, core_uri} ->
            {:ok, Map.put(core_uri, :displayname, display_name)}

          {code, core_uri} ->
            {code, core_uri}
        end

      _ ->
        {:invalid_sip_uri_general, Map.new()}
    end
  end

  @doc """
  Obtain a parameter of an URI, from either set — URI parameters first, header
  field parameters second.

  Tolerant, and URI-first: it answers whichever side of the bracket the sender
  chose, which is the only way `transport` survives a UA that writes it as a
  header parameter. Use it for the parameters that are URI parameters by nature
  (`transport`, `user`, `ttl`, `maddr`, `lr`) — and `get_header_param/2`, which
  has the opposite precedence, for those that are header parameters by nature
  (`expires`, `q`, a feature tag).

  The precedence only decides the malformed case where the *same* name appears on
  both sides. It matters for exactly one parameter seen in traffic: a Contact
  `<sip:x@y;expires=10>;expires=600` expires in 600 s, because RFC 3261 §10.2.4
  reads the Contact header parameter — hence `get_header_param/2` there.
  """
  @spec get_uri_param(%SIP.Uri{} | binary(), binary()) ::
          {:ok, binary()} | {:no_such_param, nil} | {atom(), nil}
  def get_uri_param(sip_uri, param) when is_binary(sip_uri) do
    case SIP.Uri.parse(sip_uri) do
      {:ok, parsed_uri} -> get_uri_param(parsed_uri, param)
      {code, _dump} -> {code, nil}
    end
  end

  def get_uri_param(sip_uri = %SIP.Uri{}, param) do
    case Map.get(sip_uri.params, param, Map.get(sip_uri.hparams, param)) do
      nil -> {:no_such_param, nil}
      val -> {:ok, val}
    end
  end

  @doc """
  Obtain a parameter that is a header field parameter by nature (`expires`, `q`,
  a feature tag): header parameters first, URI parameters as a fallback.

  The mirror of `get_uri_param/2` — same tolerance, opposite precedence. The
  fallback is what makes it work on an unbracketed address too, where the whole
  parameter set is parsed as URI parameters (`To: sip:bob@host;tag=xyz`, and
  RFC 3261 §20 does rule those to be header parameters).
  """
  @spec get_header_param(%SIP.Uri{}, binary()) :: {:ok, binary()} | {:no_such_param, nil}
  def get_header_param(sip_uri = %SIP.Uri{}, param) do
    case Map.get(sip_uri.hparams, param, Map.get(sip_uri.params, param)) do
      nil -> {:no_such_param, nil}
      val -> {:ok, val}
    end
  end

  @doc """
  Return the first URI of a Contact header value.

  Since multiple contacts are supported, a parsed Contact header is either a
  single `%SIP.Uri{}` or a list of them. Use this when a single URI is needed
  (e.g. the remote target of a dialog); returns nil when no contact is present.
  """
  @spec first_contact(%SIP.Uri{} | [%SIP.Uri{}] | nil) :: %SIP.Uri{} | nil
  def first_contact([first | _]), do: first
  def first_contact(sip_uri = %SIP.Uri{}), do: sip_uri
  def first_contact(_), do: nil

  @doc """
  Set a **URI** parameter — inside the angle brackets, part of the address.

  No guessing from the name: an unregistered parameter is a URI parameter here if
  the caller says so, and RFC 3261 §19.1.5 requires it to be carried onto the
  Request-URI ("Unknown URI parameters MUST be placed in the message's
  Request-URI"). Classifying unknown names as header parameters instead is how a
  `sip:…;scenario=answered_call` target quietly lost its parameter on the way to
  the wire. Use `set_header_param/3` for `tag`, `expires`, `q` and the other
  `contact-params`.

  Setting one side clears the same name on the other: a parameter is set *once*,
  and a To whose tag arrived as a URI parameter must not go out carrying two.
  """
  def set_uri_param(sip_uri = %SIP.Uri{}, param, value) do
    %SIP.Uri{
      sip_uri
      | params: Map.put(sip_uri.params, param, value),
        hparams: Map.delete(sip_uri.hparams, param)
    }
  end

  @doc """
  Set a **header field** parameter — after the closing bracket, describing the
  binding or the dialog rather than the address (`tag`, `expires`, `q`, a feature
  tag). Clears the same name among the URI parameters, as `set_uri_param/3` does.
  """
  def set_header_param(sip_uri = %SIP.Uri{}, param, value) do
    %SIP.Uri{
      sip_uri
      | hparams: Map.put(sip_uri.hparams, param, value),
        params: Map.delete(sip_uri.params, param)
    }
  end

  @doc """
  Remove a parameter, from both sets.

  Removing means the parameter must be *gone*, and where the sender happened to
  put it is not the caller's business: a `strip_tag` that only cleared one side
  left the other's tag on a forwarded request, which is a dialog identity the
  B2BUA never meant to reuse.
  """
  @spec delete_param(%SIP.Uri{}, binary()) :: %SIP.Uri{}
  def delete_param(sip_uri = %SIP.Uri{}, param) do
    %SIP.Uri{
      sip_uri
      | params: Map.delete(sip_uri.params, param),
        hparams: Map.delete(sip_uri.hparams, param)
    }
  end

  @doc "Obtain the transport string in capitals from the URI"
  def get_transport(uri = %SIP.Uri{}) do
    case get_uri_param(uri, "transport") do
      {:no_such_param, nil} ->
        if uri.scheme == "sips:", do: "TLS", else: uri.proto

      {:ok, value} ->
        String.upcase(value)
    end
  end

  defp serialize_core_uri(scheme, user, host, port) when is_tuple(host) do
    serialize_core_uri(scheme, user, SIP.NetUtils.ip2string(host), port)
  end

  defp serialize_core_uri("sips:", nil, host, 5061) do
    "sips:" <> host
  end

  defp serialize_core_uri("sips:", nil, host, nil) do
    "sips:" <> host
  end

  defp serialize_core_uri("sips:", user, host, 5061) do
    "sips:" <> user <> "@" <> host
  end

  defp serialize_core_uri("sips:", user, host, nil) do
    "sips:" <> user <> "@" <> host
  end

  defp serialize_core_uri("sips:", user, host, port) do
    "sips:" <> user <> "@" <> host <> ":" <> Integer.to_string(port)
  end

  defp serialize_core_uri("sip:", nil, host, 5060) when is_binary(host) do
    "sip:" <> host
  end

  defp serialize_core_uri("sip:", user, host, 5060) when is_binary(host) do
    "sip:" <> user <> "@" <> host
  end

  defp serialize_core_uri("sip:", nil, host, nil) when is_binary(host) do
    "sip:" <> host
  end

  defp serialize_core_uri("sip:", nil, host, port) when is_binary(host) do
    "sip:" <> host <> ":" <> Integer.to_string(port)
  end

  defp serialize_core_uri("sip:", user, host, nil) do
    "sip:" <> user <> "@" <> host
  end

  defp serialize_core_uri("sip:", user, host, port) when is_binary(host) do
    "sip:" <> user <> "@" <> host <> ":" <> Integer.to_string(port)
  end

  defp serialize_one_param(key, value) when is_boolean(value) do
    if value do
      key
    else
      ""
    end
  end

  defp serialize_one_param(key, value) when is_bitstring(value) do
    key <> "=" <> value
  end

  # Turn the param map in a string param1=val1;param2=val2
  defp serialize_params(params) when is_map(params) do
    pstr =
      Enum.reduce(params, "", fn {key, value}, acc ->
        acc <> serialize_one_param(key, value) <> ";"
      end)

    String.trim_trailing(pstr, ";")
  end

  # Do not add transport=TLS for sips URI
  defp fix_transport_param(uri = %SIP.Uri{}, "sips:", "TLS") do
    uri.params
  end

  # Do not add transport=UDP
  defp fix_transport_param(uri = %SIP.Uri{}, _scheme, "UDP") do
    uri.params
  end

  defp fix_transport_param(uri = %SIP.Uri{}, _scheme, proto) do
    # Both sets are consulted: a `transport` the sender misplaced after the
    # bracket is already reflected in `proto`, and re-adding it inside would emit
    # it twice, once on each side.
    case get_uri_param(uri, "transport") do
      {:ok, _value} ->
        uri.params

      _ ->
        # RFC 3261 §19.1.1 registers the values lower-case (udp/tcp/tls/ws/wss);
        # `proto` is held upper-case internally, so a synthesized parameter would
        # otherwise go out as `transport=TCP`.
        Map.put(uri.params, "transport", String.downcase(proto))
    end
  end

  @doc """
  Serialize an URI as it appears in a **header field** (Contact, To, From,
  Route…): URI parameters inside the angle brackets, header field parameters
  after them.

  Brackets appear when there is a display name, at least one header parameter,
  or at least one parameter of *URI nature* — the RFC 3261 §19.1.1
  `uri-parameters` the grammar itself names (#{inspect(@uri_nature_params)}).
  Not merely cosmetic: §20 rules that in an unbracketed address every
  semicolon-delimited parameter is a *header* parameter — so a URI parameter can
  only exist with the frontier drawn. The capture of 2026-08-14 measured the
  cost of forgetting that: a 200 OK whose Contact went out as
  `sip:b2bua@host:5070;transport=tcp` was read (per the RFC, correctly) as
  carrying a header parameter, the caller's remote target had no transport, and
  its ACK and BYE left over UDP on a TCP dialog.

  Only the §19.1.1 names force the brackets, not every entry in `params`: the
  parser is positional, so a bare `sip:bob@host;tag=xyz` — what a To with a tag
  has always looked like on the wire — lands its `tag` in `params`, and drawing
  brackets around it would move the tag inside them and change its nature.
  A parameter the grammar does not name is genuinely ambiguous in the bare form,
  so it keeps the position it was parsed in.

  A Request-URI is NOT this: use `serialize_ruri/1`.
  """
  def serialize(uri = %SIP.Uri{}) do
    {addr_spec, eff_params} = serialize_addr_spec(uri)
    hparams_str = serialize_params(uri.hparams)

    uri_str =
      if uri.displayname != nil or hparams_str != "" or
           Enum.any?(@uri_nature_params, &Map.has_key?(eff_params, &1)) do
        name_prefix =
          if uri.displayname != nil,
            do: "\"" <> URI.encode_www_form(uri.displayname) <> "\" ",
            else: ""

        join_params(name_prefix <> "<" <> addr_spec <> ">", hparams_str)
      else
        addr_spec
      end

    {:ok, uri_str}
  end

  defp join_params(base, ""), do: base
  defp join_params(base, params_str), do: base <> ";" <> params_str

  # The bare `addr-spec`: scheme, identity, host, port and the URI parameters,
  # nothing else. Returned with the effective parameter map (fix_transport_param/3
  # may have synthesized `transport` from `proto`) so serialize/1 can decide on
  # brackets from what actually goes out.
  defp serialize_addr_spec(uri = %SIP.Uri{}) do
    core_uri_str =
      serialize_core_uri(
        uri.scheme,
        uri.userpart,
        uri.domain,
        uri.port
      )

    # add transport in params if needed and serialize params as string
    eff_params = fix_transport_param(uri, uri.scheme, uri.proto)
    {join_params(core_uri_str, serialize_params(eff_params)), eff_params}
  end

  @doc """
  The same address reduced to what may appear in a Request-URI: no display name,
  no angle brackets, no header field parameters, no `method` parameter.

  `Request-URI = SIP-URI / SIPS-URI / absoluteURI` (RFC 3261 §25.1) — a
  `name-addr` is not one of them, and §16.6 item 2 requires the parameters that a
  Request-URI does not admit to be removed. The URI parameters are kept, all of
  them: §19.1.5 makes that mandatory ("Unknown URI parameters MUST be placed in
  the message's Request-URI"), which is why this is a targeted removal and not an
  allowlist.

  The transport info (`destip`/`tp_pid`/…) rides along untouched: it never
  reaches the wire, and dropping it here would lose the flow a NATed contact is
  reachable over.
  """
  @spec to_request_uri(%SIP.Uri{}) :: %SIP.Uri{}
  def to_request_uri(uri = %SIP.Uri{}) do
    %SIP.Uri{
      uri
      | displayname: nil,
        hparams: %{},
        params: Map.drop(uri.params, @non_ruri_params)
    }
  end

  @doc """
  Serialize an URI for use as a Request-URI (see `to_request_uri/1`).

  Always the bare `addr-spec` — a Request-URI is `SIP-URI / SIPS-URI /
  absoluteURI` (RFC 3261 §25.1), never a `name-addr`, so the brackets that
  `serialize/1` draws around a parametered header URI must not appear here.
  """
  @spec serialize_ruri(%SIP.Uri{}) :: {:ok, binary()}
  def serialize_ruri(uri = %SIP.Uri{}) do
    {addr_spec, _eff_params} = uri |> to_request_uri() |> serialize_addr_spec()
    {:ok, addr_spec}
  end

  def has_tp_info(uri = %SIP.Uri{}) do
    is_tuple(uri.destip) and uri.destport > 0 and is_pid(uri.tp_pid) and not is_nil(uri.tp_module)
  end

  defimpl String.Chars do
    def to_string(uri) do
      case SIP.Uri.serialize(uri) do
        {:ok, uri_str} -> uri_str
      end
    end
  end
end
