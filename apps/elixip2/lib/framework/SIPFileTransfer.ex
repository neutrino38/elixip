# File transfer over HTTP, the way Linphone sends a photo or a voice message
# in chat (docs/design/DESIGN-CHAT-MEDIA.md §2, §5): the RCS `fthttp` XML a
# MESSAGE carries, and the upload and download it points at.

defmodule SIP.FileTransfer do
  @moduledoc """
  An attachment in chat: the file goes to an HTTP store, and the MESSAGE
  carries an XML naming it (`application/vnd.gsma.rcs-ft-http+xml`, GSMA RCC.07
  §3.5.4.8, DESIGN-CHAT-MEDIA §2.2).

  Three things, in the one place that reads them:

    * `parse/1` — the XML of a MESSAGE, read as Linphone reads it: the
      `file-info` of type `file` alone, the name percent-decoded, the
      `playing-length` of a voice message in **milliseconds**;
    * `serialize/1` — the XML a client sends, as Linphone rebuilds it after
      the upload: CRLF line ends, the server's `url`, `until` and size, the
      local name and type;
    * `upload/4` and `download/2` — the HTTP side, with a digest answered from
      the SIP credentials.

  ## The upload, against the server that exists

  RCS describes an empty `POST` answered 204, then the `POST` of the file.
  With digest on, the reference server (`flexisip-http-file-transfer-server`,
  DESIGN-CHAT-MEDIA §2.8) authenticates the empty request and then answers it
  **400** — it finds no file. So the empty `POST` is sent to learn the
  challenge, and the credentials go on the `POST` that carries the file: a
  204 there means no challenge, a 401 a challenge to answer. That is RCS's
  sequence on a server without digest, and the only one that works on the
  reference server with it.
  """

  alias SIP.FileTransfer.Info

  @content_type "application/vnd.gsma.rcs-ft-http+xml"
  @fthttp "urn:gsma:params:xml:ns:rcs:rcs:fthttp"
  @rram "urn:gsma:params:xml:ns:rcs:rcs:rram"

  # An fthttp document is a few hundred octets; past this it is not one.
  @max_xml 16 * 1024

  defmodule Info do
    @moduledoc "One file, as the `fthttp` XML describes it."
    @type t :: %__MODULE__{
            url: String.t(),
            until: String.t() | nil,
            name: String.t() | nil,
            size: non_neg_integer() | nil,
            content_type: String.t() | nil,
            playing_length: non_neg_integer() | nil
          }
    defstruct [:url, :until, :name, :size, :content_type, :playing_length]
  end

  @doc "The media type of the XML a MESSAGE carries."
  @spec content_type() :: String.t()
  def content_type, do: @content_type

  @doc """
  Is this file a voice message? Linphone's test is strict, parameter included
  (DESIGN-CHAT-MEDIA §2.3): `audio/wav;voice-recording=yes`, whatever the
  container really is.
  """
  @spec voice_message?(Info.t()) :: boolean()
  def voice_message?(%Info{content_type: type}) when is_binary(type),
    do: String.replace(String.downcase(type), " ", "") == "audio/wav;voice-recording=yes"

  def voice_message?(_info), do: false

  # ── The XML ──────────────────────────────────────────────────────────────────

  @doc """
  Read an `fthttp` document. Only `file-info type="file"` is read — a
  thumbnail is ignored, as Linphone ignores it — and it must carry a `data`
  with a `url`. Refused without raising: a body over 16 kB, a doctype, XML
  that is not well-formed, a document with no file.
  """
  @spec parse(binary()) :: {:ok, Info.t()} | {:error, term()}
  def parse(xml) when is_binary(xml) do
    with :ok <- check_size(xml),
         :ok <- check_no_doctype(xml),
         {:ok, root} <- scan(xml),
         {:ok, file_info} <- file_info(root) do
      read_file_info(file_info)
    end
  end

  def parse(other), do: {:error, {:not_a_body, other}}

  @doc """
  The XML a client sends in its MESSAGE, in Linphone's shape (DESIGN-CHAT-MEDIA
  §2.2): CRLF line ends, the `am` namespace declared, `playing-length` only
  for a voice message, the name percent-escaped but for alphanumerics and
  `-_.[]` as Linphone escapes it.
  """
  @spec serialize(Info.t()) :: String.t()
  def serialize(%Info{url: url} = info) when is_binary(url) do
    until = if info.until, do: ~s( until="#{escape(info.until)}"), else: ""

    [
      ~s(<?xml version="1.0" encoding="UTF-8"?>),
      ~s(<file xmlns="#{@fthttp}" xmlns:am="#{@rram}">),
      ~s(<file-info type="file">),
      info.size && "<file-size>#{info.size}</file-size>",
      info.name && "<file-name>#{escape(escape_name(info.name))}</file-name>",
      info.content_type && "<content-type>#{escape(info.content_type)}</content-type>",
      info.playing_length && "<am:playing-length>#{info.playing_length}</am:playing-length>",
      ~s(<data url="#{escape(url)}"#{until}/>),
      "</file-info>",
      "</file>"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\r\n")
    |> Kernel.<>("\r\n")
  end

  defp check_size(xml) when byte_size(xml) > @max_xml,
    do: {:error, {:body_too_large, byte_size(xml)}}

  defp check_size(_xml), do: :ok

  defp check_no_doctype(xml) do
    prolog = xml |> String.split(~r/<[A-Za-z_]/, parts: 2) |> hd()
    if prolog =~ ~r/<!DOCTYPE/i, do: {:error, :doctype_not_allowed}, else: :ok
  end

  # erlsom signals a malformed document by throwing or exiting, never by
  # answering: a MESSAGE carrying junk must not kill the scenario reading it.
  defp scan(xml) do
    case :erlsom.simple_form(xml, output_encoding: :utf8) do
      {:ok, root, _tail} -> {:ok, root}
      {:error, reason} -> {:error, {:malformed_xml, reason}}
    end
  catch
    _kind, reason -> {:error, {:malformed_xml, reason}}
  end

  defp file_info(root) do
    with {_ns, "file", _attrs, children} <- element(root),
         %{} = info <-
           Enum.find_value(children, fn child ->
             case element(child) do
               {_ns, "file-info", attrs, grandchildren} ->
                 if attribute(attrs, "type") == "file", do: %{children: grandchildren}

               _ ->
                 nil
             end
           end) do
      {:ok, info.children}
    else
      _ -> {:error, :no_file_info}
    end
  end

  defp read_file_info(children) do
    info =
      Enum.reduce(children, %Info{}, fn child, acc ->
        case element(child) do
          {_ns, "file-size", _a, c} ->
            %{acc | size: integer(text_of(c))}

          {_ns, "file-name", _a, c} ->
            %{acc | name: decode_name(text_of(c))}

          {_ns, "content-type", _a, c} ->
            %{acc | content_type: text_of(c)}

          {@rram, "playing-length", _a, c} ->
            %{acc | playing_length: integer(text_of(c))}

          {_ns, "data", attrs, _c} ->
            %{acc | url: attribute(attrs, "url"), until: attribute(attrs, "until")}

          _ ->
            acc
        end
      end)

    if is_binary(info.url) and info.url != "", do: {:ok, info}, else: {:error, :no_url}
  end

  # Linphone escapes everything but alphanumerics and -_.[] in the name it
  # writes (DESIGN-CHAT-MEDIA §2.1); a name not escaped reads as itself.
  defp escape_name(name), do: URI.encode(name, &(URI.char_unreserved?(&1) or &1 in ~c"[]"))

  defp decode_name(nil), do: nil

  defp decode_name(name) do
    URI.decode(name)
  rescue
    ArgumentError -> name
  end

  defp integer(nil), do: nil

  defp integer(text) do
    case Integer.parse(text) do
      {n, ""} when n >= 0 -> n
      _ -> nil
    end
  end

  defp escape(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  # `simple_form/2` answers `{Name, Attributes, Content}`, names as charlists,
  # `'{namespace}local'` in a namespace (SIP.Presence.Pidf reads it the same way).
  defp element({name, attrs, children}) when is_list(name) do
    case name |> to_string() |> String.split("}", parts: 2) do
      ["{" <> ns, local] -> {ns, local, attrs, children}
      [local] -> {"", local, attrs, children}
    end
  end

  defp element(_text), do: nil

  defp attribute(attrs, name) do
    Enum.find_value(attrs, fn
      {attr_name, value} -> if to_string(attr_name) == name, do: to_string(value)
      _other -> nil
    end)
  end

  defp text_of(children) do
    case children |> Enum.filter(&is_binary/1) |> Enum.join() |> String.trim() do
      "" -> nil
      text -> text
    end
  end

  # ── HTTP ─────────────────────────────────────────────────────────────────────

  @typedoc """
  Who uploads: `from`, the bare SIP URI sent as the HTTP `From` (the reference
  server reads the user and the realm out of it, and a display name or angle
  brackets break it — DESIGN-CHAT-MEDIA §2.8); `username`, and `passwd` or an
  MD5 `ha1` computed with the SIP domain as realm.
  """
  @type credentials :: %{
          required(:from) => String.t(),
          required(:username) => String.t(),
          optional(:passwd) => String.t(),
          optional(:ha1) => String.t(),
          optional(:ha1_algorithm) => String.t()
        }

  @typedoc "The file: its name, its type (parameters kept) and its octets."
  @type file :: %{name: String.t(), content_type: String.t(), data: binary()}

  @doc """
  Upload `file` to the store at `url` (`file_transfer_server_url`) and answer
  what the store's XML says, with the local name and type put back — the
  store drops a type's parameters (DESIGN-CHAT-MEDIA §2.2).

  `{:error, {:http, status}}` for a final answer other than 200: 400 is "too
  large" on the reference server, 401 "credentials rejected". `opts` go to
  `Req` (`:receive_timeout`, a test `:plug`…).
  """
  @spec upload(String.t(), file(), credentials(), keyword()) ::
          {:ok, Info.t()} | {:error, term()}
  def upload(url, %{name: name, content_type: type, data: data}, creds, opts \\ []) do
    headers = [{"from", creds.from}]

    with {:ok, challenge} <- probe(url, headers, opts),
         {:ok, xml} <- post_file(url, headers, {name, type, data}, creds, challenge, opts),
         {:ok, info} <- parse(xml) do
      {:ok, %{info | name: name, content_type: type}}
    end
  end

  # The empty POST: 204 is a store without digest, 401 its challenge.
  defp probe(url, headers, opts) do
    case Req.post(url, [headers: headers, body: "", retry: false] ++ opts) do
      {:ok, %Req.Response{status: 204}} -> {:ok, nil}
      {:ok, %Req.Response{status: 401} = rsp} -> challenge(rsp)
      {:ok, %Req.Response{status: status}} -> {:error, {:http, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  # The file POST, answering the challenge the probe got; a 401 to it is
  # answered once more, with the challenge it carries — the nonce of the probe
  # may have aged out of its window.
  defp post_file(url, headers, file, creds, challenge, opts, tries \\ 2) do
    auth = if challenge, do: [{"authorization", authorization(url, challenge, creds)}], else: []

    case Req.post(
           url,
           [headers: headers ++ auth, form_multipart: [File: part(file)], retry: false] ++ opts
         ) do
      {:ok, %Req.Response{status: 200, body: xml}} when is_binary(xml) ->
        {:ok, xml}

      {:ok, %Req.Response{status: 401} = rsp} when tries > 1 ->
        with {:ok, fresh} <- challenge(rsp),
             do: post_file(url, headers, file, creds, fresh, opts, tries - 1)

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp part({name, type, data}),
    do: {data, filename: name, content_type: type}

  @doc """
  Download the file a MESSAGE names. The store serves it statically on the
  reference server (the URL is the capability); a 401 is reported, not
  answered.
  """
  @spec download(String.t() | Info.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def download(%Info{url: url}, opts), do: download(url, opts)

  def download(url, opts) when is_binary(url) do
    case Req.get(url, [decode_body: false, retry: false] ++ opts) do
      {:ok, %Req.Response{status: 200, body: data}} -> {:ok, data}
      {:ok, %Req.Response{status: status}} -> {:error, {:http, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── The digest ───────────────────────────────────────────────────────────────

  # The challenges of a 401, one per WWW-Authenticate field; the one answered is
  # the strongest the credentials allow — an HA1 is MD5's.
  defp challenge(%Req.Response{} = rsp) do
    challenges =
      rsp
      |> Req.Response.get_header("www-authenticate")
      |> Enum.flat_map(fn value ->
        case SIPMsg.parse_challenge(value) do
          {:ok, %{authproc: "Digest"} = c} -> [c]
          _ -> []
        end
      end)

    case challenges do
      [] -> {:error, :no_digest_challenge}
      list -> {:ok, list}
    end
  end

  @doc false
  # The Authorization answering one of `challenges` for a POST to `url`.
  @spec authorization(String.t(), [map()], credentials()) :: String.t()
  def authorization(url, challenges, creds) do
    {algorithm, c} = pick(challenges, creds)
    uri = URI.parse(url)
    path = (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: "")

    ha1 =
      Map.get(creds, :ha1) ||
        SIP.Auth.compute_ha1(algorithm, creds.username, c["realm"], creds.passwd)

    cnonce = 8 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
    qop = %{"nc" => "00000001", "cnonce" => cnonce, "qop" => "auth"}

    response =
      SIP.Auth.compute_auth_response_from_ha1(algorithm, c["nonce"], ha1, "POST", path, qop)

    [
      ~s(Digest username="#{creds.username}"),
      ~s(realm="#{c["realm"]}"),
      ~s(nonce="#{c["nonce"]}"),
      ~s(uri="#{path}"),
      "algorithm=#{c["algorithm"] || "MD5"}",
      ~s(response="#{response}"),
      "qop=auth",
      "nc=00000001",
      ~s(cnonce="#{cnonce}")
    ]
    |> Kernel.++(if c["opaque"], do: [~s(opaque="#{c["opaque"]}")], else: [])
    |> Enum.join(", ")
  end

  # An HA1 answers only the algorithm it was hashed with (`:ha1_algorithm`,
  # MD5 unless said); a password answers any, SHA-256 first.
  defp pick(challenges, creds) do
    by_algorithm =
      Map.new(challenges, fn c -> {normalize(c["algorithm"] || "MD5"), c} end)

    if Map.has_key?(creds, :ha1) do
      wanted = normalize(Map.get(creds, :ha1_algorithm) || "MD5")
      {atom(wanted), by_algorithm[wanted] || hd(challenges)}
    else
      wanted = if Map.has_key?(by_algorithm, "SHA-256"), do: "SHA-256", else: "MD5"
      {atom(wanted), by_algorithm[wanted] || hd(challenges)}
    end
  end

  defp normalize(algorithm) do
    case String.upcase(to_string(algorithm)) do
      a when a in ["SHA-256", "SHA256"] -> "SHA-256"
      _ -> "MD5"
    end
  end

  defp atom("SHA-256"), do: :sha256
  defp atom(_md5), do: :md5
end
