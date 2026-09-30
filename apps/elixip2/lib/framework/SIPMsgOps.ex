defmodule SIP.Msg.Ops do
  @moduledoc "Operations on SIP messages"

  require SIP.Auth

  defp build_via_addr(local_ip, 5060, "UDP") do
    local_ip = SIP.NetUtils.sip_host(local_ip)
    "SIP/2.0/UDP " <> local_ip
  end

  defp build_via_addr(local_ip, 5060, "TCP") do
    local_ip = SIP.NetUtils.sip_host(local_ip)
    "SIP/2.0/TCP " <> local_ip
  end

  defp build_via_addr(local_ip, 5061, "TLS") do
    local_ip = SIP.NetUtils.sip_host(local_ip)
    "SIP/2.0/TLS " <> local_ip
  end

  defp build_via_addr(local_ip, local_port, transport) when is_integer(local_port) do
    if local_port < 1000 or local_port > 65535 do
      # Un port non privilegié UDP ou TCP est compris entre 1000 et 65535
      raise "Invalid port #{local_port} for via header"
    end

    if String.upcase(transport, :ascii) not in ["UDP", "TCP", "TLS", "WS", "WSS"] do
      raise "Invalid transport #{transport} for via header"
    end

    local_ip = SIP.NetUtils.sip_host(local_ip)

    "SIP/2.0/" <>
      String.upcase(transport) <> " " <> local_ip <> ":" <> Integer.to_string(local_port)
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

  The parser already yields an integer under the `:expires` key; a message built by
  hand (templates, tests, a scenario) carries the header name as a string key and
  its value as text, and both are read here.
  """
  @spec expires_header(map()) :: non_neg_integer() | nil
  def expires_header(msg) do
    case first_header_value(msg, :expires, "expires") do
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

  # ── Event notification headers (RFC 6665 §8.2, RFC 3903 §11) ────────────────
  #
  # THE one place that answers what a SUBSCRIBE, a NOTIFY or a PUBLISH says about
  # its event package, the bodies it accepts, the lifetime it asks for and the
  # state of its subscription — the same rule as the sections above (CLAUDE.md,
  # *Message Layer*). The subscription layer, the event packages, the presence
  # module and the Router all layer their policy on these readings; none of them
  # re-reads a header.
  #
  # Every reading here takes both message shapes. A parsed message carries the
  # atom key `SIPMsg` assigns (`:event`, `:accept`, `:subscriptionstate`…); a
  # message built by hand — a template, a test, a scenario — carries the header
  # name as a string key, in whatever case its author typed, and header names are
  # case-insensitive (RFC 3261 §7.3.1). A malformed value read off the network
  # reads as "absent", it never raises: the rule `parse_expires/2` already
  # encodes.

  @doc """
  The event package a request names, as `{package, id}`, or `nil` when it carries
  no usable `Event` header.

  The package name is case-insensitive (RFC 6665 §8.2.1) and comes back folded to
  lower case, which is the form `SIP.EventPackage` is keyed on. The `id`
  parameter is **not** case-insensitive and comes back verbatim, `nil` when the
  header carries none.

      iex> SIP.Msg.Ops.event_package(%{"Event" => "PRESENCE;id=Ab12"})
      {"presence", "Ab12"}
  """
  @spec event_package(map()) :: {binary(), binary() | nil} | nil
  def event_package(msg) when is_map(msg) do
    with value when is_binary(value) <- first_header_value(msg, :event, "event"),
         {name, params} when name != "" <- split_params(value) do
      {String.downcase(name), presence(Map.get(params, "id"))}
    else
      _no_event_header -> nil
    end
  end

  @doc """
  The content types a SUBSCRIBE says it accepts, in the order it listed them,
  folded to lower case.

  `[]` means the request carried **no** `Accept` header, which RFC 6665 §4.4.5
  reads as "the default type of the event package" — not as "nothing is
  acceptable". Turning that empty list into the package's own default is the
  notifier's business, not the message's.

  `Accept` is a comma-separated list that may also be spread over several header
  lines, and each entry may carry parameters (`;q=0.8`): the media range alone is
  returned, in the order sent. The client's `q` is dropped on purpose — the
  notifier picks from `content_types/0`, which is already in the *package's*
  preference order.
  """
  @spec accepted_content_types(map()) :: [binary()]
  def accepted_content_types(msg) when is_map(msg) do
    msg
    |> header_list(:accept, "accept")
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(fn entry ->
      entry |> split_params() |> elem(0) |> String.downcase()
    end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  @doc """
  The resource list a SUBSCRIBE carries in its own body (RFC 5367), or `:none`
  when it carries none.

  What makes a SUBSCRIBE a **list subscription** is read here and nowhere else:
  `Content-Disposition: recipient-list` over a body of
  `application/resource-lists+xml`. Both are required — a body with no
  disposition is a body the request did not say what to do with — and the URIs
  come back as the watcher wrote them.

  `{:error, reason}` is a disposition that says "recipient-list" over something
  that is not one: the request asked for a list subscription and did not supply a
  readable list, which is a **400**, not a subscription to nothing.
  """
  @spec recipient_list(map()) :: {:ok, [binary()]} | :none | {:error, term()}
  def recipient_list(msg) when is_map(msg) do
    if content_disposition(msg) == "recipient-list" do
      case {body_content_type(msg), body_string(msg)} do
        {"application/resource-lists+xml", body} when is_binary(body) ->
          SIP.Presence.ResourceLists.parse(body)

        {type, _body} ->
          {:error, {:not_a_resource_list, type}}
      end
    else
      :none
    end
  end

  @doc """
  What a body is for (RFC 3261 §20.11), folded to lower case and stripped of its
  parameters (`;handling=optional`), or `nil`.
  """
  @spec content_disposition(map()) :: binary() | nil
  def content_disposition(msg) when is_map(msg) do
    case first_header_value(msg, :contentdisposition, "content-disposition") do
      value when is_binary(value) ->
        value |> split_params() |> elem(0) |> String.trim() |> String.downcase() |> presence()

      _absent ->
        nil
    end
  end

  @doc """
  The coding applied to the body (RFC 3261 §20.12), folded to lower case, or
  `nil` when the message carries no `Content-Encoding`.

  Only the first coding is read. A stack of them (`deflate, gzip`) is legal on
  paper, never sent, and the composite it would name is not one we can undo.

      iex> SIP.Msg.Ops.body_encoding(%{"Content-Encoding" => "deflate"})
      "deflate"
  """
  @spec body_encoding(map()) :: binary() | nil
  def body_encoding(msg) when is_map(msg) do
    case option_tags(msg, :contentencoding, "content-encoding") do
      [coding | _] -> coding
      [] -> nil
    end
  end

  @doc """
  The codings a peer says it can read (RFC 3261 §20.2), folded to lower case.

  `[]` is an absent header, which RFC 2616 §14.3 reads as "identity only": a body
  we compress anyway is a body this peer cannot read.
  """
  @spec accepted_encodings(map()) :: [binary()]
  def accepted_encodings(msg) when is_map(msg) do
    msg
    |> option_tags(:acceptencoding, "accept-encoding")
    |> Enum.map(&(&1 |> split_params() |> elem(0)))
    |> Enum.reject(&(&1 == ""))
  end

  @doc """
  The option tags a request **requires** the server to support (RFC 3261 §20.32),
  folded to lower case.

  An extension named here is not a hint: a server that does not implement one of
  them answers **420 Bad Extension** listing it in `Unsupported`, and answering
  anything else is answering a request one did not read.

      iex> SIP.Msg.Ops.required_extensions(%{"Require" => "recipient-list-subscribe"})
      ["recipient-list-subscribe"]
  """
  @spec required_extensions(map()) :: [binary()]
  def required_extensions(msg) when is_map(msg), do: option_tags(msg, :require, "require")

  @doc """
  The option tags a request says it **supports** (RFC 3261 §20.37), folded to
  lower case.

  `Supported: eventlist` is what tells a notifier a watcher can read the
  `multipart/related` of RFC 4662; unlike `Require`, its absence refuses nothing.
  """
  @spec supported_extensions(map()) :: [binary()]
  def supported_extensions(msg) when is_map(msg), do: option_tags(msg, :supported, "supported")

  # One reading for both: a comma-separated list that may also be spread over
  # several header lines, exactly like `Accept` above. Option tags are `token`s
  # and the IANA registry holds them in lower case, so they are compared folded —
  # a peer writing `Require: Replaces` means the registered extension.
  defp option_tags(msg, atom_key, lowercase_name) do
    msg
    |> header_list(atom_key, lowercase_name)
    |> Enum.flat_map(&String.split(to_string(&1), ","))
    |> Enum.map(&(&1 |> String.trim() |> String.downcase()))
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  @doc """
  The lifetime a SUBSCRIBE asks for: its `Expires` header, else `package_default`.

  A **second** expiry reading, and deliberately not `requested_expires/2`: a
  SUBSCRIBE carries no Contact `expires` parameter, the default it falls back on
  belongs to the event package (RFC 6665 §4.4.1) and not to RFC 3261 §20.19, and
  the notifier may grant less than what is asked. Same rule, different rules.

  `Expires: 0` is a lifetime, not an absence: it is how a watcher un-subscribes
  (RFC 6665 §4.4.4), so it comes back as `0` and never as the default.
  """
  @spec subscription_expires(map(), non_neg_integer()) :: non_neg_integer()
  def subscription_expires(msg, package_default) when is_map(msg) do
    expires_header(msg) || package_default
  end

  @doc """
  The `Subscription-State` of a NOTIFY (RFC 6665 §8.2.3), as `{state, params}`,
  or `nil` when the message carries no such header.

  The state is `:active`, `:pending` or `:terminated`; an extension value nobody
  here knows comes back as the lower-cased binary rather than as a new atom — a
  value off the network never grows the atom table.

  Parameter names are folded to lower case and their values kept verbatim, so
  `reason` stays a string whether or not it is one of the seven of §8.2.3.
  `expires` and `retry-after` are the two the layer acts on, so they are returned
  as integers, and a malformed one is dropped rather than handed on as junk.

      iex> SIP.Msg.Ops.subscription_state(%{"Subscription-State" => "active;expires=3600"})
      {:active, %{"expires" => 3600}}
  """
  @spec subscription_state(map()) ::
          {:active | :pending | :terminated | binary(), map()} | nil
  def subscription_state(msg) when is_map(msg) do
    with value when is_binary(value) <-
           first_header_value(msg, :subscriptionstate, "subscription-state"),
         {state, params} when state != "" <- split_params(value) do
      {substate_value(state), numeric_params(params, ["expires", "retry-after"])}
    else
      _no_subscription_state -> nil
    end
  end

  @doc """
  The entity-tag a PUBLISH refreshes or removes — its `SIP-If-Match` header (RFC
  3903 §11.3.2) — or `nil` when it carries none, which makes it an initial
  publication.

  The tag is opaque and case-sensitive: it comes back exactly as the publisher
  wrote it, whitespace aside.
  """
  @spec publish_etag(map()) :: binary() | nil
  def publish_etag(msg) when is_map(msg) do
    case first_header_value(msg, :sipifmatch, "sip-if-match") do
      value when is_binary(value) -> presence(String.trim(value))
      _no_tag -> nil
    end
  end

  @doc """
  The entity-tag an event state compositor **granted** — the `SIP-ETag` of a 2xx
  to a PUBLISH (RFC 3903 §11.3.1) — or `nil` when the response carries none.

  The other half of `publish_etag/1`, which reads the tag a publisher
  *presents* (`SIP-If-Match`). Two headers, two directions, one lifecycle: what
  comes back here is what the next refresh sends back there. Opaque and
  case-sensitive, like its counterpart.

  A 2xx answering a removal carries none — there is no state left to name — so
  `nil` is an answer and not an omission.
  """
  @spec entity_tag(map()) :: binary() | nil
  def entity_tag(msg) when is_map(msg) do
    case first_header_value(msg, :sipetag, "sip-etag") do
      value when is_binary(value) -> presence(String.trim(value))
      _no_tag -> nil
    end
  end

  @doc """
  What a PUBLISH is actually asking for (RFC 3903 §4.1 and §6), read from its
  `SIP-If-Match`, its `Expires` and whether it carries a body:

  | Answer | The request |
  |---|---|
  | `{:initial, nil, expires}` | a body and no tag: publish this state |
  | `{:modify, etag, expires}` | a body and a tag: replace the state that tag names |
  | `{:refresh, etag, expires}` | a tag and no body: the same state, for longer |
  | `{:remove, etag, 0}` | `Expires: 0`: drop it |
  | `:invalid` | neither a tag nor a body — nothing to publish and nothing to name (**400**) |

  `package_default` is the lifetime to assume when the request states none: the
  event package's, never a number of this layer's own — the same rule
  `subscription_expires/2` follows, and the reason both exist beside
  `requested_expires/2` rather than inside it.

  `Expires: 0` reads as a removal whatever else the request carries, tag or body:
  a publication with no lifetime is a publication that is not kept, which is what
  the publisher asked for. An initial PUBLISH carrying `Expires: 0` is therefore
  `{:remove, nil, 0}` — it names no state, and the 200 that answers it carries no
  entity-tag.
  """
  @spec publish_operation(map(), non_neg_integer()) ::
          {:initial | :modify | :refresh | :remove, binary() | nil, non_neg_integer()}
          | :invalid
  def publish_operation(req, package_default) when is_map(req) do
    etag = publish_etag(req)
    body = body_string(req)
    expires = expires_header(req) || package_default

    cond do
      is_nil(etag) and is_nil(body) -> :invalid
      expires == 0 -> {:remove, etag, 0}
      is_nil(etag) -> {:initial, nil, expires}
      is_nil(body) -> {:refresh, etag, expires}
      true -> {:modify, etag, expires}
    end
  end

  @doc """
  The body of a message as a binary, whatever shape it arrived in — a bare
  string, the parser's `[%{contenttype, data}]` part list, or a multipart list
  (the first part) — and `nil` when it carries none.

  `sdp_body/1` is the same question asked about a *session description*, and it
  picks the SDP part out of a multipart body; this one makes no such choice,
  because a PUBLISH body or an event state document is whatever its content type
  says it is.
  """
  @spec body_string(map()) :: binary() | nil
  def body_string(msg) when is_map(msg) do
    case Map.get(msg, :body) do
      body when is_binary(body) -> presence(body)
      [%{data: data} | _] when is_binary(data) -> presence(data)
      [data | _] when is_binary(data) -> presence(data)
      _no_body -> nil
    end
  end

  @doc """
  The media type of a message's body, folded to lower case and stripped of its
  parameters (`application/pidf+xml;charset=utf-8` reads
  `"application/pidf+xml"`), or `nil` when it carries none.

  The part's own Content-Type wins over the message's: a body carried as a part
  states its type beside its bytes, and that is the one the body was written
  with.
  """
  @spec body_content_type(map()) :: binary() | nil
  def body_content_type(msg) when is_map(msg) do
    value =
      case Map.get(msg, :body) do
        [%{contenttype: ct} | _] when is_binary(ct) -> ct
        _ -> first_header_value(msg, :contenttype, "content-type")
      end

    case value do
      value when is_binary(value) ->
        value |> split_params() |> elem(0) |> String.downcase() |> presence()

      _no_content_type ->
        nil
    end
  end

  # ── instant messaging (RFC 3428) ─────────────────────────────────────────────
  #
  # What the chat function asks of a MESSAGE: what its body is, how long its
  # content is worth keeping, and which device a contact is. Read here, once, so
  # the relay, the Silo and the scripts match on an answer rather than compare
  # strings of their own (docs/design/chat-basic-plan.md, C1).

  @doc """
  What a page-mode MESSAGE carries: `:im` (a message for a person),
  `:is_composing` (a typing indicator, RFC 3994) or `:imdn` (a disposition
  notification, RFC 5438).

  A `message/cpim` body (RFC 3862) is an envelope, and the kind is that of the
  content it wraps: its MIME header block names the type. An envelope naming no
  type, or no body at all, reads `:im` — the answer that stores and relays, which
  is the safe side for a message nobody could classify.

  The distinction exists for one decision: a typing indicator is worth nothing a
  second later and is never stored.
  """
  @spec message_kind(map()) :: :im | :is_composing | :imdn
  def message_kind(msg) when is_map(msg) do
    type =
      case body_content_type(msg) do
        "message/cpim" -> cpim_content_type(body_string(msg))
        type -> type
      end

    case type do
      "application/im-iscomposing+xml" -> :is_composing
      "message/imdn+xml" -> :imdn
      _other -> :im
    end
  end

  @doc """
  What a MESSAGE is, in one line a log or a report may carry: its kind
  (`message_kind/1`), its sender's AOR, its media type and its size —
  `"im from alice@example.com (text/plain, 17 octets)"`. **Never its content**
  (chat-basic-plan, C1b): this is what a tool says it received.
  """
  @spec page_summary(map()) :: String.t()
  def page_summary(msg) when is_map(msg) do
    octets = byte_size(body_string(msg) || "")
    sender = address_of_record(msg, :from) || "an unknown sender"

    "#{message_kind(msg)} from #{sender} (#{body_content_type(msg) || "no type"}, #{octets} octets)"
  end

  # The final answers to a page that are a verdict on the content or the sender,
  # not on the moment: a device that said one of these will say it again.
  # 403 blocked sender, 413 too large, 415 unsupported type, 488 not acceptable,
  # 603 decline, 606 not acceptable anywhere.
  @page_refusals [403, 413, 415, 488, 603, 606]

  @doc """
  What one device's answer to a page-mode MESSAGE means for the message:

    * `:delivered` — a 2xx other than 202: the device has it;
    * `:accepted` — a 202: the device took it without saying it reached anyone
      (a client quarantining an unknown sender answers so);
    * `:refused` — a verdict on the content or the sender (403, 413, 415, 488,
      603, 606): trying again later changes nothing;
    * `:unreachable` — anything else, a request that never got a final answer
      (`:failed`) included: *not now*, which is what storage is for.

  One reading for the relay that fans a MESSAGE out (`SBB.Page`) and for the
  delivery from storage that later retries it.
  """
  @spec page_verdict(100..699 | :failed) :: :delivered | :accepted | :refused | :unreachable
  def page_verdict(202), do: :accepted
  def page_verdict(code) when code in 200..299, do: :delivered
  def page_verdict(code) when code in @page_refusals, do: :refused
  def page_verdict(_code_or_failed), do: :unreachable

  # The Content-Type of the content inside a CPIM envelope: the envelope's own
  # headers come first, then the MIME headers of the content, then the content.
  # Only the header blocks are searched — a Content-Type line in the text of the
  # message itself is the user's, not the envelope's.
  defp cpim_content_type(body) when is_binary(body) do
    body
    |> String.split(~r/\r?\n\r?\n/, parts: 3)
    |> Enum.take(2)
    |> Enum.flat_map(&String.split(&1, ~r/\r?\n/))
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          if String.downcase(String.trim(name)) == "content-type" do
            value |> String.trim() |> split_params() |> elem(0) |> String.downcase() |> presence()
          end

        _ ->
          nil
      end
    end)
  end

  defp cpim_content_type(_no_body), do: nil

  @doc """
  Does this message carry **user content** — text a person wrote to another?

  A MESSAGE of kind `:im` with a body, in or out of a dialog. A typing indicator
  and a disposition notification carry a state, not text; a response carries
  nothing of the kind. This is the one reading of "what must never be recorded"
  (GDPR): the journal and the debug logs go through `SIPMsg.redacted/1`, which
  asks it (docs/design/chat-basic-plan.md, C1b).
  """
  @spec user_content?(map()) :: boolean()
  def user_content?(%{method: :MESSAGE} = msg),
    do: message_kind(msg) == :im and body_string(msg) != nil

  def user_content?(_msg), do: false

  @doc """
  The lifetime a MESSAGE's sender gives its **content**, in seconds, or `nil`
  when it says nothing.

  On a non-INVITE request the `Expires` header is the validity of the content
  (RFC 3261 §20.19), not a registration lifetime: there is no Contact parameter
  to prefer and no default to fall back on, so this is **not**
  `requested_expires/2`. `nil` matters — the Silo's retention takes the script's
  value, then the domain's, only when the sender said nothing.
  """
  @spec content_expires(map()) :: non_neg_integer() | nil
  def content_expires(msg) when is_map(msg), do: expires_header(msg)

  @doc """
  The instance ID of a Contact (`+sip.instance`, RFC 5626 §4.1), as a bare URN —
  `"urn:uuid:a11ce000-…"` — or `nil` when it carries none.

  A Contact **header** parameter, read with `SIP.Uri.get_header_param/2`. The
  value arrives quoted and in angle brackets, which are stripped; a `urn:uuid:`
  is folded to lower case, since two spellings of one UUID are one device.
  """
  @spec instance_id(term()) :: binary() | nil
  def instance_id(%SIP.Uri{} = contact) do
    with {:ok, value} when is_binary(value) <- SIP.Uri.get_header_param(contact, "+sip.instance"),
         urn when urn != "" <-
           String.trim(value, "\"")
           |> String.trim_leading("<")
           |> String.trim_trailing(">")
           |> String.trim() do
      if String.match?(urn, ~r/^urn:uuid:/i), do: String.downcase(urn), else: urn
    else
      _ -> nil
    end
  end

  def instance_id(_other), do: nil

  @doc """
  The identity a delivery to `contact` is recorded against: its instance ID when
  it sends one, else its contact URI as a Request-URI.

  The fallback drops the header parameters (`expires`, `q`…), which change from
  one REGISTER to the next, and keeps the address — so a device re-registering
  from a new address without an instance ID is a new device, the duplicate risk
  the design accepts (DESIGN-CHAT.md, *Multi-device*).
  """
  @spec device_key(term()) :: binary() | nil
  def device_key(%SIP.Uri{} = contact) do
    case instance_id(contact) do
      nil ->
        {:ok, ruri} = SIP.Uri.serialize_ruri(contact)
        ruri

      urn ->
        urn
    end
  end

  def device_key(_other), do: nil

  @doc """
  The flow a request arrived on, as the transport layer stamped it on its
  Request-URI: `received` is `{proto, ip, port}` of the source (`nil` when
  unstamped), `tp_pid` and `tp_module` the transport instance — the connection,
  for TCP, TLS and WSS — that carried it.

  What a registrar stores beside a binding, and what a delivery to the device
  that sent the request goes back over (`reach_contact/2`). `source_flow/1`
  names the same flow as a comparable key; this is what a send needs.
  """
  @spec arrival_flow(map()) :: %{
          received: {term(), term(), term()} | nil,
          tp_pid: pid() | nil,
          tp_module: module() | nil
        }
  def arrival_flow(req) when is_map(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{destip: ip, destport: port, destproto: proto, tp_pid: pid, tp_module: mod} ->
        received = if is_nil(ip), do: nil, else: {proto, ip, port}
        %{received: received, tp_pid: pid, tp_module: mod}

      _ ->
        %{received: nil, tp_pid: nil, tp_module: nil}
    end
  end

  @doc """
  The Request-URI that reaches `contact` — a Contact header value — over `flow`
  (`arrival_flow/1`'s shape): the contact as a Request-URI, stamped with the
  destination and the transport instance `SIP.Transport.Selector` short-circuits
  on, so a NATed device is reached over the connection it registered on, with
  no DNS.

  `SIP.Uri.to_request_uri/1` first: the display name and the binding parameters
  (`q`, `expires`, the RFC 3840 feature tags) may not appear on a Request-URI
  (RFC 3261 §16.6 item 2), while every URI parameter is kept (§19.1.5). One
  header parameter is carried back on, `+sip.instance`, so whoever sends to the
  result can still name the device (`device_key/1`); it cannot reach the wire,
  since a Request-URI is serialized by `SIP.Uri.serialize_ruri/1`, which drops
  every header parameter.
  """
  @spec reach_contact(SIP.Uri.t(), map()) :: SIP.Uri.t()
  def reach_contact(%SIP.Uri{} = contact, flow) when is_map(flow) do
    ruri = contact |> SIP.Uri.to_request_uri() |> keep_instance(contact)
    ruri = %SIP.Uri{ruri | tp_pid: Map.get(flow, :tp_pid), tp_module: Map.get(flow, :tp_module)}

    case Map.get(flow, :received) do
      {proto, ip, port} -> %SIP.Uri{ruri | destip: ip, destport: port, destproto: proto}
      _ -> ruri
    end
  end

  defp keep_instance(ruri, contact) do
    case SIP.Uri.get_header_param(contact, "+sip.instance") do
      {:ok, value} when is_binary(value) -> SIP.Uri.set_header_param(ruri, "+sip.instance", value)
      _none -> ruri
    end
  end

  @doc """
  Where the devices a REGISTER binds can be reached **now**: one Request-URI per
  Contact it binds (a lifetime above 0, `contact_expires/3`), each over the flow
  the REGISTER arrived on (`reach_contact/2`). Empty for an un-registration and
  for the `Contact: *` wildcard.

  What a delivery triggered by that REGISTER — the Silo's flush — sends to: the
  device that just registered, not the AOR's other bindings, which are served by
  their own REGISTERs.
  """
  @spec register_targets(map()) :: [SIP.Uri.t()]
  def register_targets(req) when is_map(req) do
    header = expires_header(req)
    flow = arrival_flow(req)

    for %SIP.Uri{} = contact <- List.wrap(Map.get(req, :contact)),
        contact_expires(contact, header) > 0,
        do: reach_contact(contact, flow)
  end

  @doc """
  The value of a `Subscription-State` header (RFC 6665 §8.2.3), built.

  The writer beside the reader above, so the one place that knows how this header
  is spelt is the one place that knows how to read it. `params` are appended in
  the order given, values written verbatim:

      iex> SIP.Msg.Ops.subscription_state_value(:active, expires: 600)
      "active;expires=600"
      iex> SIP.Msg.Ops.subscription_state_value(:terminated, reason: :timeout)
      "terminated;reason=timeout"
  """
  @spec subscription_state_value(atom() | binary(), keyword()) :: binary()
  def subscription_state_value(state, params \\ []) when is_list(params) do
    Enum.reduce(params, to_string(state), fn
      {_name, nil}, acc -> acc
      {name, value}, acc -> acc <> ";" <> to_string(name) <> "=" <> to_string(value)
    end)
  end

  @doc """
  The value of an `Event` header (RFC 6665 §8.2.1) built from a package name and
  an optional `id`.
  """
  @spec event_value(binary(), binary() | nil) :: binary()
  def event_value(package, nil), do: package
  def event_value(package, id), do: package <> ";id=" <> to_string(id)

  @doc """
  The value of an `Allow-Events` header (RFC 6665 §8.2.2) built from a list of
  package names.

  It is composed from what the **domain** enables, never from what the node has
  compiled in (docs/design/presence-basic-plan.md, decision 3), so the caller
  passes the names and this only writes them out.
  """
  @spec allow_events([binary()]) :: binary()
  def allow_events(names) when is_list(names) do
    names
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.join(", ")
  end

  defp substate_value(value) do
    case String.downcase(value) do
      "active" -> :active
      "pending" -> :pending
      "terminated" -> :terminated
      extension -> extension
    end
  end

  # `name;p1=v1;p2` -> {"name", %{"p1" => "v1", "p2" => ""}}. A valueless
  # parameter is kept as an empty value, which every reading above treats as
  # "said nothing" — the shape `;expires` with no value arrives as.
  defp split_params(value) when is_binary(value) do
    [head | rest] = String.split(value, ";")

    params =
      Enum.reduce(rest, %{}, fn part, acc ->
        case String.split(part, "=", parts: 2) do
          [name, param_value] ->
            put_param(acc, name, strip_quotes(param_value))

          [name] ->
            put_param(acc, name, "")
        end
      end)

    {String.trim(head), params}
  end

  defp put_param(params, name, value) do
    case String.downcase(String.trim(name)) do
      "" -> params
      name -> Map.put(params, name, value)
    end
  end

  defp strip_quotes(value) do
    case String.trim(value) do
      "\"" <> _ = quoted -> String.trim(quoted, "\"")
      plain -> plain
    end
  end

  # The listed parameters as integers; one that does not parse is dropped, so a
  # caller reading params["expires"] gets a number or nothing, never junk.
  defp numeric_params(params, names) do
    Enum.reduce(names, params, fn name, acc ->
      case Map.fetch(acc, name) do
        :error -> acc
        {:ok, value} -> put_numeric_param(acc, name, parse_expires(value, nil))
      end
    end)
  end

  defp put_numeric_param(params, name, nil), do: Map.delete(params, name)
  defp put_numeric_param(params, name, number), do: Map.put(params, name, number)

  # A header by both of its keys: the atom SIPMsg gives a parsed message, and the
  # name a hand-built one carries as a string key, case-insensitively. A header
  # repeated on several lines arrives as a list — the first value wins for the
  # single-valued ones, and `header_list/3` keeps them all for the others.
  defp first_header_value(msg, atom_key, lowercase_name) do
    case header_list(msg, atom_key, lowercase_name) do
      [value | _] -> value
      [] -> nil
    end
  end

  defp header_list(msg, atom_key, lowercase_name) do
    case Map.get(msg, atom_key) do
      nil -> header_values(msg, lowercase_name)
      value -> List.wrap(value)
    end
  end

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

  @doc """
  The identity a trusted upstream asserted for the sender, as the whole
  `%SIP.Uri{}` of `P-Asserted-Identity` (RFC 3325 §9.1). `nil` when the request
  carries none that parses as a SIP URI.

  The counterpart of `asserted_username/1` for a B2BUA that *re-asserts* what it
  was handed: a scenario which has established that the request comes from inside
  its trust domain feeds this to `SIP.Context.assert_identity/2`, and
  `prepare_forwarded_request/2` writes it out on the outbound leg. The inbound
  header itself never crosses a leg boundary — see `strip_asserted_identity/1`,
  and never bypass it: relaying a foreign assertion verbatim is what RFC 3325 §5
  forbids.

  The display name is kept, unlike the one `SIP.Context.assert_identity/2` builds
  from a digest verdict. Here it is not the caller's claim but part of what the
  trusted upstream asserts, and dropping it would blank the callee's display.

  A `tel:` URI yields `nil`: `SIP.Uri` does not model one, and there is no
  honest way to assert it as a SIP URI. When the header carries both forms, the
  `sip:` one is taken whichever comes first.
  """
  @spec asserted_identity(map()) :: %SIP.Uri{} | nil
  def asserted_identity(msg) when is_map(msg) do
    msg
    |> header_values("p-asserted-identity")
    |> Enum.find_value(&value_uri/1)
  end

  # A header SIPMsg has no atom for keeps the spelling the peer used as its map key
  # (`headername_to_atomkey/1`), and header names are case-insensitive (RFC 3261
  # §7.3.1) — so the lookup is too. Repeated occurrences arrive as a list.
  defp header_values(msg, lowercase_name) do
    msg
    |> Enum.find_value(fn
      {key, value} when is_binary(key) ->
        if String.downcase(key) == lowercase_name, do: value

      _other ->
        nil
    end)
    |> List.wrap()
  end

  defp header_userpart(msg, lowercase_name) do
    msg
    |> header_values(lowercase_name)
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

  # Same value, read as a whole URI. The comma is only a separator once the
  # value has failed to parse entire: a display name is allowed to hold one
  # (`"Dupont, Jean" <sip:j@example.com>`).
  defp value_uri(value) when is_binary(value) do
    case to_uri(value) do
      %SIP.Uri{} = uri -> uri
      nil -> value |> String.split(",") |> Enum.find_value(&to_uri/1)
    end
  end

  defp value_uri(%SIP.Uri{} = uri), do: uri
  defp value_uri(_other), do: nil

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
  # The comma stops the number too: it separates the two values of RFC 3325 §9.1
  # when they share a line, and `tel:+33970260233, sip:a@b` asserted a number with
  # a comma glued to it.
  @tel_uri ~r/^(?:[^<]*<)?tel:([^;>,\s]+)/i

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
      %SIP.Uri{} = uri ->
        match?({:ok, tag} when is_binary(tag), SIP.Uri.get_uri_param(uri, "tag"))

      _ ->
        false
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

  @doc """
  The user and the host of an address header, as `{user, domain}` — `{nil, nil}`
  when the header is absent or unparsable.

  `target_aor/1` answers "which resource", `asserted_username/1` "who claims to
  send this"; this one answers "who do these two headers NAME", which is a
  different question and the one a subscription row asks twice: `active_watchers`
  keeps `from_user`/`from_domain` and `to_user`/`to_domain` side by side, plus
  `watcher_username`/`watcher_domain` — the watcher being the `From` of the
  SUBSCRIBE.

  Tolerant like every other reading here: `SIPMsg` leaves `:from` and `:to` as
  the raw header value (only `:ruri` and `:contact` are parsed), a hand-built
  message carries a `%SIP.Uri{}`, and neither must make the caller parse.
  """
  @spec header_aor(map(), :from | :to) :: {String.t() | nil, String.t() | nil}
  def header_aor(msg, header) when is_map(msg) and header in [:from, :to] do
    case to_uri(Map.get(msg, header)) do
      %SIP.Uri{userpart: user, domain: domain} -> {presence(user), host_string(domain)}
      _ -> {nil, nil}
    end
  end

  @doc """
  The address-of-record an address header names, as one comparable string,
  `"user@host"` — `nil` when the header is absent, unparsable, or names no user.

  What a page-mode conversation is keyed on: the `From` and the `To` of every
  MESSAGE of one conversation name the same two AORs, while their tags, their
  display names and the Call-ID change with each message. The host is folded to
  lower case (RFC 3261 §19.1.4 compares it case-insensitively); the user part is
  kept verbatim, as `target_aor/1` keeps it.
  """
  @spec address_of_record(map(), :from | :to) :: String.t() | nil
  def address_of_record(msg, header) when is_map(msg) and header in [:from, :to] do
    case header_aor(msg, header) do
      {user, host} when is_binary(user) and is_binary(host) ->
        user <> "@" <> String.downcase(host)

      _ ->
        nil
    end
  end

  @doc """
  The flow a request arrived on, as `{transport, ip, port}` — `"UDP"`, `"TCP"`,
  `"TLS"` or `"WSS"`, the peer's address and port — or `nil` for a request that
  did not come off the network (hand-built, or not yet stamped).

  The transport layer stamps it on the Request-URI of every inbound request that
  starts a transaction (`destip`, `destport`, `tp_module`): where an answer must
  go back is where the request came from. A page-mode conversation is keyed on it
  (chat-basic-plan, C3c): the same `From` writing to the same `To` over the same
  flow is the same sender, which a `From` alone does not prove.
  """
  @spec source_flow(map()) :: {String.t(), :inet.ip_address(), :inet.port_number()} | nil
  def source_flow(msg) when is_map(msg) do
    case Map.get(msg, :ruri) do
      %SIP.Uri{tp_module: mod, destip: ip, destport: port}
      when is_atom(mod) and not is_nil(mod) and is_tuple(ip) and is_integer(port) ->
        {String.upcase(mod.transport_str()), ip, port}

      _ ->
        nil
    end
  end

  @doc """
  The connection a request arrived on — the pid of its connected transport
  instance (TCP, TLS, WSS) — or `nil` for a connectionless one (UDP), which has
  no connection to lose, and for a request that did not come off the network.
  """
  @spec source_connection(map()) :: pid() | nil
  def source_connection(msg) when is_map(msg) do
    case Map.get(msg, :ruri) do
      %SIP.Uri{tp_module: mod, tp_pid: pid}
      when is_atom(mod) and not is_nil(mod) and is_pid(pid) ->
        if mod.is_reliable(), do: pid, else: nil

      _ ->
        nil
    end
  end

  # A host may have been parsed as an IP tuple; a row column holds text.
  defp host_string(domain) when is_binary(domain), do: presence(domain)

  defp host_string(domain) when is_tuple(domain) do
    case :inet.ntoa(domain) do
      {:error, _} -> nil
      addr -> to_string(addr)
    end
  end

  defp host_string(_other), do: nil

  # ── The SDP body, and what a re-offer asks for (RFC 3264 §8, RFC 3261 §14) ───
  #
  # THE one place that answers "what does this offer change, given the one it
  # replaces", for the same reason as the two sections above (CLAUDE.md, Message
  # Layer). A B2BUA that terminates media has to decide whether a re-INVITE or an
  # UPDATE concerns the far end at all, and that decision is a *reading* of the
  # message. The policy built on it — which kinds cross and which are answered
  # locally — stays the caller's (docs/design/DESIGN-FRAMEWORK.md#57-media-modes §R4.1b).
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
  True for the one request whose 2xx carries **no SDP at all**: an UPDATE that made
  no offer.

  RFC 3311 §5.1 — "if the UPDATE did not contain an offer, the 2xx response MUST NOT
  contain an answer" — and it may carry no offer of ours either, since an UPDATE has
  no ACK for the answer to come back in. An offerless *re-INVITE* is the opposite
  case (RFC 3261 §14.2: its 2xx MUST contain an offer), which is why the method is
  part of the reading and not an afterthought.

  This is what an RFC 4028 session-timer refresh looks like on the wire, so every
  layer that answers a request meets it: a UAS scenario, and a B2BUA on each of its
  two legs.
  """
  @spec offerless_update?(map()) :: boolean()
  def offerless_update?(req) when is_map(req),
    do: Map.get(req, :method) == :UPDATE and is_nil(sdp_body(req))

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

  @doc """
  The media a description carries: `[:audio, :video, :text]`, in that order,
  whichever of them the SDP holds an `m=` section for with a port other than 0.

  Read on an **answer**, this is what the two ends settled on: a section the
  answerer declined is a `m=… 0 …` line (RFC 3264 §6), and a section neither side
  named is not there at all. Any other media type — `application`, and the sections
  this stack cannot answer — is absent from the result: the question asked here is
  which of the three streams a human calls a call, which is also why `supported?`
  plays no part. A relayed section we would not terminate ourselves still carries
  the callee's media.

  `[]` for a description that carries none of the three, and for one that cannot be
  parsed: a caller reads "nothing negotiated" out of both.
  """
  @spec media_kinds(binary() | nil) :: [:audio | :video | :text]
  def media_kinds(sdp) do
    case presence(sdp) && MediaServer.SdpTools.parse(sdp) do
      {:ok, descs} ->
        present = for d <- descs, Map.get(d, :port, 0) != 0, do: Map.get(d, :type)
        Enum.filter([:audio, :video, :text], &(&1 in present))

      _no_readable_sdp ->
        []
    end
  end

  @doc """
  True for a request carrying the RFC 5168 picture-fast-update primitive: the one
  body a video UA sends to ask the far end's encoder for a fresh intra-frame,
  because its decoder lost sync.

  Both halves are read, and either alone is wrong. The content type is what
  identifies the body (`application/media_control+xml`); the primitive is what
  says which request it carries, so a `media_control` message asking for
  something else is not a request for a frame. A multipart body is searched part
  by part, since the content type may sit on the part rather than on the message.

  Any video leg meets this question — a conference leg, a B2BUA relaying INFO —
  so the reading lives here and the policy built on it (ask the media server for
  the frame, or answer 200 and do nothing else) stays with the caller.
  """
  @spec picture_fast_update?(map()) :: boolean()
  def picture_fast_update?(msg) when is_map(msg) do
    case Map.get(msg, :body) do
      body when is_binary(body) ->
        media_control?(Map.get(msg, :contenttype)) and fpu_primitive?(body)

      parts when is_list(parts) ->
        Enum.any?(parts, fn part ->
          (media_control?(Map.get(part, :contenttype)) or
             media_control?(Map.get(msg, :contenttype))) and fpu_primitive?(Map.get(part, :data))
        end)

      _no_body ->
        false
    end
  end

  defp media_control?(contenttype), do: String.contains?(to_string(contenttype), "media_control")

  defp fpu_primitive?(body),
    do: is_binary(body) and String.contains?(body, "picture_fast_update")

  @doc """
  The RFC 5168 picture-fast-update body, and the content type it goes out as:
  `{body, "application/media_control+xml"}`.

  Kept whole rather than assembled, because this exact wording is what
  interoperates. It sits next to `picture_fast_update?/1`, which reads it back,
  so one place owns the primitive in both directions.
  """
  @spec picture_fast_update() :: {binary(), binary()}
  def picture_fast_update do
    body = """
    <?xml version="1.0" encoding="utf-8" ?>\
    <media_control><vc_primitive><to_encoder><picture_fast_update/>\
    </to_encoder></vc_primitive></media_control>
    """

    {body, "application/media_control+xml"}
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

  # `a=sendonly`/`a=inactive` (RFC 3264 §8.4) or the pre-RFC-3264 blackhole that
  # older phones still send. One media on hold is enough: a peer that holds its
  # audio has put the call on hold whatever it left its video saying.
  defp held?(descs), do: Enum.any?(active(descs), &held_media?/1)

  defp held_media?(desc) do
    Map.get(desc, :direction) in [:sendonly, :inactive] or MediaServer.SdpTools.blackholed?(desc)
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
  def add_via(sipmsg, {local_ip, local_port, transport}, branch_id, additional_params \\ nil)
      when is_bitstring(branch_id) do
    via = build_via_addr(local_ip, local_port, transport)

    via =
      cond do
        is_bitstring(additional_params) ->
          via <> additional_params <> ";branch=" <> branch_id

        additional_params == nil ->
          via <> ";branch=" <> branch_id
          # To do add, list of tuples and maps
      end

    newvia =
      case Map.get(sipmsg, :via) do
        nil -> [via]
        oldvia when is_list(oldvia) -> [via | oldvia]
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
    random_branch = :crypto.strong_rand_bytes(10) |> Base.encode16()
    branch_value = String.replace(random_branch, ~r/[^a-f0-9]/, "")

    # Assurez-vous que la chaîne commence par "z9hG4bK" comme requis par RFC 3261
    "z9hG4bK" <> branch_value
  end

  @doc "Génère une valeur aléatoire pour le paramètre fromtag ou totag"
  def generate_from_or_to_tag() do
    random_branch = :crypto.strong_rand_bytes(10) |> Base.encode16()
    String.replace(random_branch, ~r/[^a-f0-9]/, "")
  end

  @doc "Generate a unique MIME multipart boundary token (RFC 2046)."
  def generate_boundary() do
    "elixip-boundary-" <> (:crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower))
  end

  @doc """
  Stamp one boundary on `parts` and compose the `Content-Type` that goes with
  them: `{parts, content_type}`.

  `opts[:subtype]` is `"mixed"` by default. A list NOTIFY (RFC 4662 §4.2) needs
  `"related"` with the two parameters that make its root part findable:

      {parts, ctype} =
        SIP.Msg.Ops.compose_multipart(parts,
          subtype: "related",
          type: "application/rlmi+xml",
          start: "<rlmi@example.com>")

  `type` names the media type of the root part and `start` its `Content-ID`
  (RFC 2387 §3.1-3.2). Without `start` the root is the *first* part, which is why
  it is a parameter rather than an ordering rule: a watcher reading the parts in
  any other order finds the manifest by its identifier.

  The caller hands the answer to `update_sip_msg/2` as `{:body, parts}` after
  setting `:contenttype` — the parts carry the boundary, so neither is redrawn.
  """
  @spec compose_multipart([map()], keyword()) :: {[map()], binary()}
  def compose_multipart(parts, opts \\ []) when is_list(parts) do
    boundary = generate_boundary()
    subtype = Keyword.get(opts, :subtype, "mixed")

    parameters =
      [{"type", Keyword.get(opts, :type)}, {"start", Keyword.get(opts, :start)}]
      |> Enum.reject(fn {_name, value} -> is_nil(value) end)
      |> Enum.map_join("", fn {name, value} -> "; #{name}=\"#{value}\"" end)

    {Enum.map(parts, &Map.put(&1, :boundary, boundary)),
     "multipart/" <> subtype <> parameters <> "; boundary=" <> boundary}
  end

  defp mixed(boundary), do: "multipart/mixed; boundary=" <> boundary

  @doc "Met a jour ou ajout des champs dans un message SIP"
  def update_sip_msg(sipmsg, fields) when is_list(fields) do
    Enum.reduce(fields, sipmsg, fn {header, value}, acc ->
      update_sip_msg(acc, {header, value})
    end)
  end

  def update_sip_msg(sipmsg, fields) when is_map(fields) do
    Enum.reduce(fields, sipmsg, fn {header, value}, acc ->
      update_sip_msg(acc, {header, value})
    end)
  end

  # Ignore update
  def update_sip_msg(sipmsg, {_header, :ignore}) do
    sipmsg
  end

  # Remove update
  def update_sip_msg(sipmsg, {header, nil}) do
    Map.delete(sipmsg, header)
  end

  # Specific case for contact
  def update_sip_msg(sipmsg, {:contact, value}) when is_bitstring(value) do
    {:ok, contact_uri} = SIP.Uri.parse(value)
    sipmsg |> Map.put(:contact, contact_uri)
  end

  # Specific case for body
  def update_sip_msg(sipmsg, {:body, []}) do
    sipmsg |> Map.put(:body, []) |> Map.put(:contentlength, 0)
  end

  # One part and no boundary: a single-part body in the parser's own shape, whose
  # own type is the message's. A part that DOES carry a boundary falls through to
  # the multipart clause below even when it is alone — dropping the boundary there
  # left a message announcing a multipart Content-Type over a bare payload, which
  # is what a list NOTIFY naming one buddy with no published state looks like.
  def update_sip_msg(sipmsg, {:body, [%{contenttype: ctype, data: body_data} = part]})
      when not is_map_key(part, :boundary) do
    sipmsg
    |> Map.put(:body, [%{contenttype: ctype, data: body_data}])
    |> Map.put(:contenttype, ctype)
    |> Map.put(:contentlength, Kernel.byte_size(body_data))
  end

  def update_sip_msg(sipmsg, {:body, body_data}) when is_binary(body_data) do
    sipmsg
    |> Map.put(:body, body_data)
    |> Map.put(:contentlength, Kernel.byte_size(body_data))
    |> Map.put(:contenttype, "application/sdp")
  end

  # Multipart/mixed body (RFC 2046): a list of two or more sub-bodies. Generate a
  # boundary, stamp it on every part, set the top-level Content-Type and compute
  # the Content-Length from the serialized body octets. Each part must be a
  # `%{contenttype: ct, data: bin}` map (extra keys are preserved).
  #
  # Parts that ALREADY carry a boundary keep it, and keep the Content-Type the
  # caller set: that is a body `compose_multipart/2` built, whose type names both
  # the subtype and the boundary, and re-drawing either here would leave the
  # message announcing a boundary its body does not use.
  def update_sip_msg(sipmsg, {:body, parts}) when is_list(parts) do
    if not Enum.all?(parts, &match?(%{contenttype: _, data: _}, &1)) do
      raise "Multipart body parts must be %{contenttype: ..., data: ...} maps, got #{inspect(parts)}"
    end

    {parts, content_type} =
      case parts do
        [%{boundary: boundary} | _] -> {parts, Map.get(sipmsg, :contenttype, mixed(boundary))}
        _ -> compose_multipart(parts, [])
      end

    sipmsg
    |> Map.put(:body, parts)
    |> Map.put(:contenttype, content_type)
    |> Map.put(:contentlength, Kernel.byte_size(SIPMsg.multipart_body(parts)))
  end

  def update_sip_msg(sipmsg, {header, value}) do
    sipmsg |> Map.put(header, value)
  end

  @doc "Crée un message CANCEL à partir d'une requête existante"
  def cancel_request(sipmsg) when is_map(sipmsg) and is_atom(sipmsg.method) do
    # "Max-Forwards", with the S the header actually has (§20.22, and what the
    # parser stores): spelt "Max-Forward" the test never matched, so every CANCEL
    # and every ACK we built went out without the header §8.1.1 makes mandatory
    # in a request.
    cancel_filter = fn {k, _v} ->
      k in [
        :via,
        :to,
        :from,
        :route,
        "Max-Forwards",
        :callid,
        :contentlength,
        :cseq,
        :method,
        :ruri
      ]
    end

    [seqno, _method] = sipmsg.cseq

    fieldlist = [
      {:method, :CANCEL},
      {:contentlength, 0},
      {:cseq, [seqno, :CANCEL]},
      {:body, []}
    ]

    sipmsg |> update_sip_msg(fieldlist) |> Map.filter(cancel_filter)
  end

  def cancel_request(sipmsg) do
    raise "passed argument is not a SIP request"
    sipmsg
  end

  # ── B2BUA forwarding (docs/design/DESIGN-FRAMEWORK.md#51-layer-split) ─────────────────
  #
  # THE one place that answers "what part of a SIP message crosses a B2BUA leg
  # boundary". The session layer (SIP.Session.B2bua) decides *whether* and *where*
  # a message is relayed; these two functions decide *what survives* the crossing.

  # Fields that never cross a leg boundary: hop-scoped routing (Via, Route,
  # Record-Route, Path), the receiving leg's target (Contact — though its
  # *identity* half is carried over, see contact_identity/1), the credentials
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

  # Matched case-insensitively: a header with no atom of its own keeps the
  # spelling the peer used (see strip_asserted_identity/1).
  @pai_header_lc "p-asserted-identity"

  @doc """
  Prepare a request received on one B2BUA leg to be re-sent on another leg.

  Strips everything hop- or dialog-scoped (see `@b2bua_dropped_fields`), keeps
  the *identity* of the inbound Contact — its userpart and display name, on a
  placeholder host the transport layer stamps with the outbound leg's own
  address, port and transport (see `contact_identity/1`) — clears the dialog
  identity — `Call-ID` and the `From`/`To` tags are left for the dialog layer to
  mint afresh — resets the R-URI routing fields (the stamped `destip`/`tp_pid`
  point back at the leg the request came in on), replaces the User-Agent and
  decrements `Max-Forwards`.

  The body and every other header (identity `From`/`To`, custom `X-*`…) cross
  unchanged. Callers layer their own policy on top; they do not re-read the
  message.

  **`P-Asserted-Identity` is the exception, and it is a security rule.** An
  inbound one is a *claim* by a peer we do not trust; relaying it would launder
  it into an assertion signed by this node (RFC 3325 §5). So it is always
  dropped, and the only one that can leave is the one this function writes from
  `:asserted_identity` — the identity an authentication verdict proved
  (`SIP.Context.assert_identity/2`). Dropping and re-adding live in the same
  place on purpose: neither can be done without the other, so no call site can
  forward a foreign assertion by forgetting an option.

  A request asking for `Privacy: id` (RFC 3325 §7) gets no assertion at all: a
  B2BUA forwarding to an arbitrary registered contact leaves the trust domain,
  and asserting the identity of a caller who asked to be anonymous is a privacy
  breach with a specification saying so.

  Returns `{:ok, req}`, or `{:error, :too_many_hops}` when `Max-Forwards` is
  exhausted (RFC 3261 §16.6 — answer 483).

  Options:

    * `:useragent` — overrides the User-Agent stamped on the forwarded request
      (defaults to the `:elixip2 :useragent` application env);
    * `:asserted_identity` — the `%SIP.Uri{}` to assert, normally
      `sip_ctx.asserted_identity`. `nil` (the default) asserts nothing.
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
          |> strip_asserted_identity()
          |> put_asserted_identity(Keyword.get(opts, :asserted_identity))
          |> put_contact_identity(Map.get(req, :contact))
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
  Remove every `P-Asserted-Identity` from a message (RFC 3325 §5).

  Case-insensitive, because a header this layer has no atom for keeps whatever
  spelling the peer used as its map key: `Map.delete/2` on one spelling would
  leave `p-asserted-identity` sitting there.
  """
  @spec strip_asserted_identity(map()) :: map()
  def strip_asserted_identity(msg) when is_map(msg) do
    msg
    |> Enum.filter(fn
      {key, _value} when is_binary(key) -> String.downcase(key) == @pai_header_lc
      _other -> false
    end)
    |> Enum.reduce(msg, fn {key, _}, acc -> Map.delete(acc, key) end)
  end

  @doc """
  True when a message asks for its identity to be withheld outside the trust
  domain — `Privacy: id`, RFC 3325 §7.

  The header carries a `;`-separated list of privacy values (RFC 3323 §4.2), so
  `Privacy: id;user` counts as much as a bare `id`.
  """
  @spec privacy_id?(map()) :: boolean()
  def privacy_id?(msg) when is_map(msg) do
    msg
    |> Enum.find_value(fn
      {key, value} when is_binary(key) ->
        if String.downcase(key) == "privacy", do: value

      _other ->
        nil
    end)
    |> List.wrap()
    |> Enum.any?(fn
      value when is_binary(value) ->
        value
        |> String.split(";")
        |> Enum.any?(&(String.trim(&1) |> String.downcase() == "id"))

      _other ->
        false
    end)
  end

  # Assert an identity on a request being forwarded. Nothing to assert, or a
  # caller asking for privacy, means no header at all.
  defp put_asserted_identity(req, nil), do: req

  defp put_asserted_identity(req, %SIP.Uri{} = uri) do
    if privacy_id?(req) do
      req
    else
      Map.put(req, "P-Asserted-Identity", asserted_identity_value(uri))
    end
  end

  # RFC 3325 §9.1 takes a name-addr or a bare addr-spec; the bracketed form is
  # what the examples use and what a display name would force anyway, so it is
  # the one written. `serialize/1` already brackets whatever needs it.
  defp asserted_identity_value(%SIP.Uri{} = uri) do
    {:ok, value} = SIP.Uri.serialize(uri)
    if String.contains?(value, "<"), do: value, else: "<" <> value <> ">"
  end

  @doc """
  What a response relayed leg-to-leg carries over: the body (normalized to the
  `[%{contenttype, data}]` part shape so its Content-Type survives
  `update_sip_msg/2`), the `#{inspect(@b2bua_reply_passthrough)}` headers, and
  the *identity* of the answerer's Contact (see `contact_identity/1`).

  The Contact's address is deliberately NOT copied: the relayed response must
  advertise *our* address on the answering leg, which the transport layer stamps
  (`SIP.Transport.add_contact_header/3`) — it keeps the userpart carried here and
  rewrites host, port and transport.
  """
  @spec forwarded_reply_fields(map()) :: keyword()
  def forwarded_reply_fields(resp) when is_resp(resp) do
    body_fields =
      case normalize_forwarded_body(Map.get(resp, :body), Map.get(resp, :contenttype)) do
        nil -> []
        parts -> [body: parts]
      end

    contact_fields =
      case contact_identity(Map.get(resp, :contact)) do
        nil -> []
        uri -> [contact: uri]
      end

    passthrough = for h <- @b2bua_reply_passthrough, v = Map.get(resp, h), do: {h, v}
    body_fields ++ contact_fields ++ passthrough
  end

  # The identity half of a Contact crossing a leg boundary: the userpart and
  # display name say WHO answers there; the host, port and transport say WHERE,
  # are this leg's own business, and are stamped by the transport layer
  # (SIP.Transport.add_contact_header/3) with the address of the transport that
  # actually carries the message. Both parameter sets are cleared: the peer's
  # binding parameters (+sip.instance, expires, q, feature tags…) describe ITS
  # binding on ITS side, and forwarding them as ours re-creates the two-token
  # Request-Line bug documented in SIP.Uri. The placeholder host marks the URI
  # as "to be stamped", same convention as the session layers' local_contact.
  defp contact_identity(%SIP.Uri{} = contact) do
    %SIP.Uri{
      userpart: contact.userpart,
      displayname: contact.displayname,
      domain: "0.0.0.0"
    }
  end

  # Several contacts only legally show up on messages that are not relayed
  # leg-to-leg (REGISTER, 3xx): keep the first one's identity if it ever happens.
  defp contact_identity([first | _]), do: contact_identity(first)
  defp contact_identity(_), do: nil

  defp put_contact_identity(req, orig_contact) do
    case contact_identity(orig_contact) do
      nil -> req
      uri -> Map.put(req, :contact, uri)
    end
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
        {:ok, Map.put(msg, :transid, nil)}

      is_nil(msg.via) or msg.via == [] ->
        # Empty Via header
        {:ok, Map.put(msg, :transid, nil)}

      length(msg.via) >= 1 ->
        # Get topmost via and branch parameter
        [_transport, topmost_via] = String.split(Enum.at(msg.via, 0), " ", parts: 2)

        case SIP.Uri.get_uri_param("sip:" <> topmost_via, "branch") do
          {:ok, branch} ->
            if String.starts_with?(branch, "z9hG4bK") do
              Map.put(msg, :transid, branch)
            else
              raise("Invalid SIP message. branch ID does not start with z9hG4bK")
            end

          {:no_such_param, nil} ->
            raise("Invalid SIP message. No branch parameter in the topmost Via")

          {_code, _parsed_via} ->
            raise("Invalid SIP message. Failed to parse Via header")
        end
    end
  end

  # Route is NOT here: RFC 3261 Table 3 gives it no place in any response —
  # Record-Route is what a UAS echoes (into dialog-establishing 2xx, below), the
  # request's Route is spent once the request has been routed. Copying it gave
  # every 200 OK we sent a Route header naming the caller's own outbound proxy.
  @reply_filter [:via, :to, :from, :recordroute, :cseq, :callid, :contentlength]

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
  def reply_to_request(req, resp_code, reason, upd_fields \\ [], totag \\ nil)
      when is_atom(req.method) and resp_code in 100..699 do
    resp_filter = fn {k, _v} ->
      k in @reply_filter
    end

    reason =
      if is_nil(reason) do
        sip_reason(resp_code)
      else
        reason
      end

    fieldlist = %{
      method: false,
      reason: reason,
      response: resp_code,
      body: []
    }

    # Merge upd_fields and fieldlist. The content of upd_fields take priority. Remove fields that are compted
    # automatically
    upd_map = Map.merge(fieldlist, Map.new(upd_fields)) |> Map.delete(:contentlength)

    # If totag is missing add it
    {:ok, to_uri} = SIP.Uri.parse(req.to)

    upd_map =
      case SIP.Uri.get_uri_param(to_uri, "tag") do
        # The request already names a To tag (an in-dialog request, a re-INVITE):
        # a response echoes it, RFC 3261 §8.2.6.2.
        {:ok, _old_totag} ->
          upd_map

        {:no_such_param, nil} ->
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

    rsp =
      if Map.has_key?(req, :transid) do
        Map.put(rsp, :transid, req.transid)
      else
        add_transaction_id(rsp)
      end

    # A 200 OK to an INVITE always carries a session description: the answer to
    # the offer it received, or an offer of its own when the INVITE had none
    # (RFC 3261 §13.3.1). Nothing of the sort binds a 183 — it is a provisional,
    # and one with no body at all is both legal and common. Refusing to BUILD it
    # raised inside the server transaction, which took the dialog and the whole
    # call with it, over a response the far end had every right to send
    # (production, 2026-09-16: a gateway's 183 relayed by the B2BUA).
    if req.method == :INVITE and resp_code == 200 do
      case Map.fetch(rsp, :body) do
        {:ok, []} -> raise "200 OK response cannot have an empty body"
        {:ok, _} -> nil
        :error -> raise "200 OK needs to be provided with an SDP body"
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
      if resp_code in 200..202 and req.method in [:INVITE, :UPDATE] do
        raise "#{resp_code} response to #{req.method} needs to be provided with a contact field"
      end
    end

    rsp
  end

  @doc """
  The response the stack makes up for a request that will never be answered.

  RFC 3261 §8.1.3.1 names the two cases and the code each takes: a transaction
  that times out is reported to the application as a **408**, a fatal transport
  error as a **503**. Both are local notifications and neither goes on the wire,
  so this response carries only what a reader of one needs — the status, and the
  dialog / CSeq coordinates that say WHICH request it answers
  (`SIP.Session.dispatch_reply/3` routes on the CSeq method, and the B2BUA
  correlates on the transaction pid delivered alongside).

  Deliberately not `reply_to_request/5`: that one composes a response a UAS sends
  out, minting a To tag and demanding a Contact that this response has no use for.
  """
  @spec local_response(map(), 100..699, binary()) :: map()
  def local_response(req, code, reason) when is_map(req) and code in 100..699 do
    %{
      method: false,
      response: code,
      reason: reason,
      callid: Map.get(req, :callid),
      cseq: Map.get(req, :cseq),
      from: Map.get(req, :from),
      to: Map.get(req, :to),
      contentlength: 0,
      body: []
    }
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
  def challenge_request(
        req,
        resp_code,
        authproc,
        realm,
        algorithm \\ nil,
        upd_fields \\ [],
        totag \\ nil
      )

  def challenge_request(req, resp_code, "Digest", realm, algorithm, upd_fields, totag)
      when is_atom(req.method) and resp_code in [401, 407] do
    rsp = reply_to_request(req, resp_code, sip_reason(resp_code), upd_fields, totag)
    # Stateless nonce, keyed by the server secret and bound to this realm: nothing
    # to store, and a nonce minted for another realm cannot be replayed here.
    authparams = %{
      "realm" => realm,
      "nonce" => SIP.Auth.Nonce.generate(realm),
      authproc: "Digest"
    }

    authparams =
      if algorithm in ["MD5", "SHA1", "SHA256"],
        do: Map.put(authparams, "algorithm", algorithm),
        else: algorithm

    Map.put(rsp, challenge_header(resp_code), authparams)
  end

  def challenge_request(req, resp_code, "NTLM", realm, nil, upd_fields, totag)
      when is_atom(req.method) and resp_code in [401, 407] do
    rsp = reply_to_request(req, resp_code, sip_reason(resp_code), upd_fields, totag)
    authparams = %{"realm" => realm, authproc: "NTLM"}
    Map.put(rsp, challenge_header(resp_code), authparams)
    raise "NTLM challenge not yet implemented"
  end

  @doc """
  Crée un message ACK à partir d'une requête existante.

  `ack_2xx` says WHICH of the two ACKs of RFC 3261 this is, because they differ
  by one thing: the branch. The ACK of a non-2xx final belongs to the INVITE
  transaction and reuses its branch (§17.1.1.3); the ACK of a 2xx is a new
  transaction the TU constructs, so it gets a branch of its own (§13.2.2.4,
  §17.1.1.3 "The ACK for a 2xx response to an INVITE request is a separate
  transaction"). We reused the INVITE's branch on both: a strict UAS matching
  that ACK by branch (§17.2.3) files it under the INVITE server transaction
  instead of handing it to the dialog — capture13 of 2026-08-14, frames 113/123.
  """
  def ack_request(sipmsg, remote_contact, routeset \\ :ignore, body \\ [], ack_2xx \\ false)
      when is_map(sipmsg) and sipmsg.method in [:INVITE, :UPDATE] do
    # "Max-Forwards" — see cancel_request/1 above for the missing S.
    ack_filter = fn {k, _v} ->
      k in [:to, :from, :route, "Max-Forwards", :callid, :contentlength]
    end

    remote_contact =
      if remote_contact == nil do
        sipmsg.ruri
      else
        remote_contact
      end

    [seqno, _method] = sipmsg.cseq
    # build ACK according to RFC 3261 section 17.1.1.3
    # - contact is copied from the final response (provided as argument)
    # - routeset is copied too (same)
    # - cseq copy the seq number and change the method to ACK
    # - via contains only the top most via header of the original request,
    #   with a fresh branch when this ACK acknowledges a 2xx (see @doc)
    # - note the to field is copied from the message passed as argument
    #   so the to needs to be modified to contain the to of the final response

    topvia = hd(sipmsg.via)
    topvia = if ack_2xx, do: refresh_via_branch(topvia), else: topvia

    fieldlist = [
      {:method, :ACK},
      {:ruri, remote_contact},
      {:route, routeset},
      {:body, body},
      {:cseq, [seqno, :ACK]},
      {:via, topvia}
    ]

    # Update message
    sipmsg |> Map.filter(ack_filter) |> update_sip_msg(fieldlist)
  end

  # Same Via — same sent-by, same parameters — under a new branch: what makes
  # the 2xx ACK the separate transaction §17.1.1.3 says it is.
  defp refresh_via_branch(via) when is_binary(via) do
    String.replace(via, ~r/branch=[^;]+/, "branch=" <> generate_branch_value())
  end

  @doc "Crée une requête autentifiée à partir d'une requête non authentifiée et d'en entête auth"
  def add_authorization_to_req(req, authparams, autheader, username, passwd_or_hash, pwdformat)
      when is_atom(req.method) do
    header2 =
      case autheader do
        :wwwauthenticate -> :authorization
        :proxyauthenticate -> :proxyauthorization
        _ -> raise "Invalid authentication header #{autheader}"
      end

    case SIPMsg.check_required_params(authparams, ["nonce", "realm"]) do
      :ok ->
        algo = Map.get(authparams, "algorithm", "MD5")
        # The digest is computed over the Request-URI *as it goes on the wire*
        # (RFC 2617 A2 = Method ":" digest-uri-value, and RFC 3261 §22.4 has the
        # client's `uri=` mirror the Request-URI), so it must be the same
        # serialization the Request-Line uses — no display name, no header
        # parameters. `to_string/1` here would digest a different string than the
        # one sent as soon as the target came from a stored Contact.
        {:ok, digest_uri} = SIP.Uri.serialize_ruri(req.ruri)

        autorisation_params =
          SIP.Auth.build_auth_response(
            algo,
            username,
            authparams["nonce"],
            authparams["realm"],
            passwd_or_hash,
            pwdformat,
            req.method,
            digest_uri
          )

        # Increment CSeq to start a new transaction
        new_cseq = if Map.get(req, :cseq) != nil, do: hd(req.cseq) + 1, else: 1

        # Build new request (delete auth header, add autorization header and overwrite CSeq)
        upd_map = %{
          header2 => autorisation_params,
          autheader => nil,
          cseq: [new_cseq, req.method]
        }

        update_sip_msg(req, upd_map)

      {:ko, mparam} ->
        raise "Invalid autentication params. Missing #{mparam} parameter"
    end
  end

  defp check_nonce({header, authparams}, nonce) do
    if !is_nil(nonce) and authparams["nonce"] != nonce do
      {:nonce_mismatch, authparams}
    else
      # Skip nonce check
      {header, authparams}
    end
  end

  defp get_auth_params_and_check_nonce(req, nonce) do
    cond do
      Map.has_key?(req, :authorization) ->
        {:authorization, Map.get(req, :authorization)} |> check_nonce(nonce)

      Map.has_key?(req, :proxyauthorization) ->
        {:proxyauthorization, Map.get(req, :proxyauthorization)} |> check_nonce(nonce)

      true ->
        {:no_auth_header, nil}
    end
  end

  @doc """
  Check authenticated request- check that auth header is valid
  req: request with auth header
  nonce: nonce that was sent in the challenge response
  """
  def check_authrequest(req, password, nonce \\ nil) when is_req(req) do
    case get_auth_params_and_check_nonce(req, nonce) do
      {header, authparams} when header in [:authorization, :proxyauthorization] ->
        # Same serialization as the sender used (see add_authorization_to_req/6):
        # the Request-URI form, not the header-field form.
        {:ok, digest_uri} = SIP.Uri.serialize_ruri(req.ruri)

        response =
          SIP.Auth.compute_auth_response_from_pwd(
            authparams["algorithm"],
            authparams["username"],
            authparams["nonce"],
            authparams["realm"],
            password,
            req.method,
            digest_uri
          )

        if response == authparams["response"] do
          :ok
        else
          :invalid_password
        end

      {header, nil} ->
        header

      {:nonce_mismatch, _authparams} ->
        :nonce_mismatch
    end
  end

  def is_response_for?(req_type, rsp) when is_req(req_type) and is_resp(rsp) do
    # A parsed CSeq header is stored as a [seqno, method] list (see SIPMsg).
    case Map.get(rsp, :cseq) do
      [_seqno, method] -> method == req_type.method
      _ -> false
    end
  end
end
