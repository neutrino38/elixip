defmodule SIP.MsgTemplate do
  require EEx
  require SIP.NetUtils

  defp add_default_bindings(bindings) do
    bindings
  end

  @doc "Generate a SIP message string from a template"
  def apply_template(msg_template, bindings \\ []) do
    bindings = add_default_bindings(bindings)

    # Split headers an bodies. Compute content length
    [headers, body, clen] =
      case String.split(msg_template, "\n\n", parts: 2) do
        [headers, body] ->
          body = EEx.eval_string(body, bindings)
          body = Regex.replace(~r/\n(?<!\r\n)/, body, "\r\n")
          [headers, body, Kernel.byte_size(body) + 2]

        [headers] ->
          [headers, nil, 0]
      end

    # Apply header template
    headers = EEx.eval_string(headers, bindings ++ [content_length: clen])
    headers = Regex.replace(~r/\n(?<!\r\n)/, headers, "\r\n")

    if is_nil(body) do
      headers
    else
      headers <> "\r\n\r\n" <> body
    end
  end

  @doc "Generate a SIP message structure from a template"
  def apply_and_build(msgemplate, fn_parse_cb, bindings \\ []) do
    apply(msgemplate, bindings) |> SIPMsg.parse(fn_parse_cb)
  end

  # The headers a page-mode MESSAGE keeps when it is rebuilt, lower case. Each is
  # written by the sender's UA and read by the recipient's: the subject line, the
  # conversation a client files the message under (RFC 4975 / OMA CPM), and the
  # identity a trusted proxy asserted.
  @page_headers ["subject", "conversation-id", "contribution-id", "p-asserted-identity"]

  @doc """
  A new out-of-dialog MESSAGE (RFC 3428) carrying the content of `source`.

  `source` is a MESSAGE that arrived — relayed to a device, or delivered hours
  later from storage — or a map holding only `:from`, `:to`, `:contenttype` and
  `:body`, which is how `send_page/4` composes a new one. The request is
  **rebuilt, never replayed**: the identities, the Content-Type, the body and the
  headers of `@page_headers` are carried over; the Via, Route, Call-ID, CSeq,
  tags and everything else of the source are not, since they describe a
  transaction that is over. The dialog layer draws a new Call-ID, From tag and
  CSeq when the request goes out.

  The `From` stays the sender's: a client files and screens a message by its
  `From` URI, and a relay that signs as itself makes every message look as if it
  came from the node.

  Options:

    * `:ruri` — where the request goes (a URI string or `%SIP.Uri{}`), when not
      to the `To` itself: a relay addresses one registered contact of the AOR in
      the `To`;
    * `:date` — the time the message **arrived**, written as a `Date` header
      (RFC 3261 §20.17). A message delivered from storage says when it was sent,
      not when it was delivered.
  """
  @spec page_request(map(), keyword()) :: map()
  def page_request(source, opts \\ []) when is_map(source) and is_list(opts) do
    to = source |> Map.fetch!(:to) |> uri!() |> SIP.Uri.delete_param("tag")
    from = source |> Map.fetch!(:from) |> uri!() |> SIP.Uri.delete_param("tag")
    ruri = opts |> Keyword.get(:ruri, to) |> uri!() |> SIP.Uri.to_request_uri()

    %{
      "Max-Forwards" => "70",
      method: :MESSAGE,
      ruri: ruri,
      from: from,
      to: to,
      callid: nil,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      contentlength: 0
    }
    |> Map.merge(page_headers(source))
    |> put_date(Keyword.get(opts, :date))
    |> put_page_body(page_body(source), Map.get(source, :contenttype))
  end

  # A multipart body is carried whole (its Content-Type and boundary are
  # recomputed from the parts); anything else as the string it is.
  defp page_body(source) do
    case Map.get(source, :body) do
      [_first, _second | _] = parts -> parts
      _single -> SIP.Msg.Ops.body_string(source)
    end
  end

  defp uri!(%SIP.Uri{} = uri), do: uri

  defp uri!(str) when is_binary(str) do
    case SIP.Uri.parse(str) do
      {:ok, uri} ->
        uri

      {err, _} ->
        raise ArgumentError, "page_request: invalid URI #{inspect(str)}: #{inspect(err)}"
    end
  end

  # Header names are case-insensitive (RFC 3261 §7.3.1) and SIPMsg keeps the
  # spelling the peer used, so the allowlist is matched folded and the header
  # goes out as it came in.
  defp page_headers(source) do
    for {name, value} <- source,
        is_binary(name) and String.downcase(name) in @page_headers,
        into: %{},
        do: {name, value}
  end

  defp put_date(req, nil), do: req

  defp put_date(req, %DateTime{} = at) do
    date =
      at
      |> DateTime.shift_zone!("Etc/UTC")
      |> Calendar.strftime("%a, %d %b %Y %H:%M:%S GMT")

    Map.put(req, "Date", date)
  end

  defp put_date(req, date) when is_binary(date), do: Map.put(req, "Date", date)

  # A page with no body is legal (RFC 3428 §7 does not require one) and goes out
  # with no Content-Type. `update_sip_msg/2` computes the Content-Length and
  # defaults the type to SDP, which the source's own type then replaces.
  defp put_page_body(req, nil, _content_type), do: req
  defp put_page_body(req, "", _content_type), do: req

  defp put_page_body(req, parts, _content_type) when is_list(parts),
    do: SIP.Msg.Ops.update_sip_msg(req, {:body, parts})

  defp put_page_body(req, body, content_type) do
    req
    |> SIP.Msg.Ops.update_sip_msg({:body, body})
    |> Map.put(:contenttype, content_type || "text/plain")
  end
end
