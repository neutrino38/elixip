# Chat attachments as scenario verbs: upload a file to the HTTP store, page the
# XML naming it, read and download what a received MESSAGE names.
# Part of the SIP.Session namespace; see SIPFileTransfer.ex for the protocol and
# docs/design/chat-media-plan.md, S1.

defmodule SIP.Session.FileTransfer do
  @moduledoc """
  What a scenario calls to send or receive a photo or a voice message in chat.

      state upload do
        upload_file(appdata_get(:ft_url), "photo.jpg", :upload)

        on_events do
          {:upload, {:ok, info}} ->
            send_file_page("sip:bob@example.com", info)
            goto(wait_answer)

          {:upload, {:error, reason}} ->
            scenario_failure("upload: \#{inspect(reason)}")
        end
      end

  The HTTP side runs outside the scenario and comes back as **one** tagged
  event, like `http_GET/3`: `{tag, {:ok, result}}`, `{tag, {:error, reason}}`,
  `{tag, {:error, :timeout}}` past the timeout. The credentials are the
  context's — the store authenticates with the SIP account's (DESIGN-CHAT-MEDIA
  §2.8) — and the HTTP `From` is the account's bare URI.
  """

  @doc false
  defmacro __using__(_opts) do
    quote do
      import SIP.Session.FileTransfer,
        only: [
          upload_file: 3,
          upload_file: 4,
          download_file: 2,
          download_file: 3,
          send_file_page: 2,
          send_file_page: 3,
          file_info: 1
        ]
    end
  end

  @default_timeout 60_000

  @doc """
  Upload `file` to the store at `url`; the outcome is `{tag, {:ok, %SIP.FileTransfer.Info{}}}`.

  `file` is a path, or `%{name:, content_type:, data:}`. Options:
  `:content_type` for a path (else read from its extension), `:timeout` in ms
  (60 s), `:req` options passed to `Req`.
  """
  defmacro upload_file(url, file, tag, opts \\ []) do
    quote do
      SIP.Session.FileTransfer.do_upload(
        var!(sip_ctx),
        unquote(url),
        unquote(file),
        unquote(tag),
        unquote(opts)
      )
    end
  end

  @doc """
  Download what `info_or_url` names; the outcome is `{tag, {:ok, binary}}`.
  Options: `:timeout` in ms (60 s), `:req`.
  """
  defmacro download_file(info_or_url, tag, opts \\ []) do
    quote do
      SIP.Session.FileTransfer.do_download(unquote(info_or_url), unquote(tag), unquote(opts))
    end
  end

  @doc """
  Page `to` with the XML naming `info`, as Linphone sends it: bare, out of
  dialog, `application/vnd.gsma.rcs-ft-http+xml`. The answer comes back as
  `send_page/4`'s does; `opts` are its options.
  """
  defmacro send_file_page(to, info, opts \\ []) do
    quote do
      var!(sip_ctx) =
        SIP.Session.Page.do_send_page(
          var!(sip_ctx),
          unquote(to),
          SIP.FileTransfer.serialize(unquote(info)),
          SIP.FileTransfer.content_type(),
          unquote(opts)
        )
    end
  end

  @doc false
  def do_upload(sip_ctx, url, file, tag, opts) do
    SIP.Scenario.Monitor.note_command(:http, "upload_file")
    creds = credentials(sip_ctx)
    req_opts = Keyword.get(opts, :req, [])

    FSL.Valet.ask(
      tag,
      fn ->
        with {:ok, file} <- load(file, opts),
             do: SIP.FileTransfer.upload(url, file, creds, req_opts)
      end,
      [],
      Keyword.get(opts, :timeout, @default_timeout)
    )

    sip_ctx
  end

  @doc false
  def do_download(info_or_url, tag, opts) do
    SIP.Scenario.Monitor.note_command(:http, "download_file")

    FSL.Valet.ask(
      tag,
      &SIP.FileTransfer.download/2,
      [info_or_url, Keyword.get(opts, :req, [])],
      Keyword.get(opts, :timeout, @default_timeout)
    )

    :ok
  end

  @doc """
  The file a received MESSAGE names, or `{:error, :not_a_file_message}`: its
  body bare, inside a CPIM envelope, or the `fthttp` part of a multipart — a
  photo with its caption.
  """
  @spec file_info(map()) :: {:ok, SIP.FileTransfer.Info.t()} | {:error, term()}
  def file_info(req) when is_map(req) do
    case SIP.Msg.Ops.file_transfer_xml(req) do
      nil -> {:error, :not_a_file_message}
      xml -> SIP.FileTransfer.parse(xml)
    end
  end

  # The account's: the HTTP From is its bare URI, never the display-named From
  # of a SIP request (the reference server cannot read one).
  defp credentials(sip_ctx) do
    base = %{
      from: "sip:#{sip_ctx.username}@#{sip_ctx.domain}",
      username: sip_ctx.authusername || sip_ctx.username
    }

    # The context keeps the HA1 alone, computed with the SIP domain as realm —
    # which is the realm the store challenges with.
    if is_binary(sip_ctx.ha1) and sip_ctx.ha1 != "",
      do: Map.merge(base, %{ha1: sip_ctx.ha1, ha1_algorithm: sip_ctx.algorithm || "MD5"}),
      else: base
  end

  defp load(%{name: _, content_type: _, data: _} = file, _opts), do: {:ok, file}

  defp load(path, opts) when is_binary(path) do
    case File.read(path) do
      {:ok, data} ->
        {:ok,
         %{
           name: Path.basename(path),
           content_type: Keyword.get(opts, :content_type) || type_of(path),
           data: data
         }}

      {:error, reason} ->
        {:error, {:file, path, reason}}
    end
  end

  # What a client would put on the part when nothing says better.
  @types %{
    ".jpg" => "image/jpeg",
    ".jpeg" => "image/jpeg",
    ".png" => "image/png",
    ".gif" => "image/gif",
    ".webp" => "image/webp",
    ".mka" => "audio/wav;voice-recording=yes",
    ".wav" => "audio/wav",
    ".pdf" => "application/pdf",
    ".txt" => "text/plain"
  }

  defp type_of(path),
    do: Map.get(@types, path |> Path.extname() |> String.downcase(), "application/octet-stream")
end
