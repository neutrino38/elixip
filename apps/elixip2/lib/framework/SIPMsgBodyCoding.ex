# What `Content-Encoding` (RFC 3261 §20.12) does to a body: undone, and applied.
# Read from the parser (SIPMsg.add_body/2); the header itself is read in exactly
# one place, SIP.Msg.Ops.body_encoding/1.

defmodule SIP.Msg.BodyCoding do
  @moduledoc """
  Decode the `Content-Encoding` a peer applied to a message body, and apply
  `deflate` where a body would not fit otherwise: a list NOTIFY (`encode/2`, on
  the watcher's word) and a MESSAGE on a datagram transport (`fit_datagram/1`).

  ## Why a SIP body is compressed at all

  A Linphone client opening its buddy list sends its whole resource list in one
  SUBSCRIBE, deflated, and asks for the answer deflated too (`Accept-Encoding`).
  A list NOTIFY carrying one PIDF per buddy is several kilobytes — past the UDP
  MTU, which IPv6 will not fragment in transit — so the compression is what makes
  the exchange fit, not an optimisation.

  ## "deflate" names two formats

  RFC 2616 defines `deflate` as the zlib format (RFC 1950), and half the
  implementations in the field emit raw DEFLATE (RFC 1951) instead. Both are
  tried, zlib first, because the sender does not say which it meant and guessing
  wrong reads as a corrupt body.

  `identity` and an absent header are the same thing: the body as sent.

  ## `gzip`

  RFC 1952, the same DEFLATE stream in a gzip wrapper; `x-gzip` is its old
  spelling (RFC 2616 §3.5). No SIP stack in the field sends it that we know of,
  but a peer that does used to get a 415 for a body we could have read.

  ## Inflation is bounded

  A few hundred octets of DEFLATE can inflate to gigabytes. Every coding is
  inflated as a stream and abandoned past the node's largest accepted message
  (`SIPMsg.max_message_size/0`): a compressed body may not smuggle in what the
  transport would have refused in clear. Going past it answers what a corrupt
  body answers, a 415.
  """

  # Past this, a body does not fit in one datagram beside its headers. RFC 3261
  # §18.1.1 puts the MESSAGE bound at 1300, and the headers of a list NOTIFY are
  # not small: over IPv6 they carry the watcher's address twice (Request-URI and
  # Via), ours in Contact, and a multipart Content-Type naming its root and its
  # boundary — 679 octets on a Linphone subscription captured on 2026-09-26. The
  # bound used to be 1200, as if headers took a hundred: a 1079-octet body went out
  # clear in a 1806-octet datagram, which the path fragmented and the watcher's
  # side dropped. 800 octets are kept for the headers.
  @compress_above 500

  require Logger

  # zlib window bits: the wrapper is chosen by the sign and the offset.
  @zlib 15
  @raw_deflate -15
  @gzip 31

  @doc """
  Undo `coding` on `body`.

  `{:error, :unsupported}` is a coding this node does not implement — the answer
  is **415**, listing `supported/0` in `Accept-Encoding`, so the peer can send the
  same request uncompressed. `{:error, :corrupt}` is a body that will not inflate,
  and it gets the same refusal: the peer's next move is the same either way, and a
  body we cannot read is one we cannot dispatch.
  """
  @spec decode(binary(), binary() | nil) ::
          {:ok, binary()} | {:error, :unsupported | :corrupt | :too_large}
  def decode(body, coding) when is_binary(body) do
    case coding do
      nil -> {:ok, body}
      "identity" -> {:ok, body}
      "deflate" -> inflate_deflate(body)
      "gzip" -> inflate(body, @gzip)
      "x-gzip" -> inflate(body, @gzip)
      _other -> {:error, :unsupported}
    end
  end

  @doc "The codings this node can read, as `Accept-Encoding` states them."
  @spec supported() :: binary()
  def supported, do: "deflate, gzip, identity"

  @doc """
  Compress `body` when the peer can read `coding` **and** the body is big enough
  to be worth it: `{:ok, octets}`, or `:as_is`.

  The bound is #{@compress_above} octets: the RFC 3261 §18.1.1 figure of 1300 for
  "this will not fit in a datagram", minus 800 for the headers of a list NOTIFY
  sent over IPv6. Below it nothing is
  compressed, and that is deliberate: a small NOTIFY stays readable in a capture,
  where half the work of diagnosing presence is done. Above it a list NOTIFY does
  not fit in one IPv6 datagram at all, and nothing in the path will fragment it.
  """
  @spec encode(binary(), binary() | nil) :: {:ok, binary()} | :as_is
  def encode(body, coding) when is_binary(body) do
    cond do
      coding != "deflate" -> :as_is
      byte_size(body) <= @compress_above -> :as_is
      true -> {:ok, :zlib.compress(body)}
    end
  end

  # RFC 3261 §18.1.1: past this, a request does not belong on a datagram.
  @datagram_bound 1300

  # The mark of `send_in_clear/1`; skipped by the serializer.
  @clear :send_in_clear

  @doc """
  A request about to leave on a datagram transport, its body deflated when the
  request would not fit in one: `Content-Encoding: deflate` (RFC 3261 §20.12).

  Only a MESSAGE. §18.1.1 answers an oversized request by moving it to TCP,
  which a UDP-registered contact does not allow — it listens on the address it
  registered, and nowhere else — and a MESSAGE grows past 1300 octets in
  ordinary use: a file-transfer XML in a CPIM envelope with a caption beside it
  (docs/design/chat-media-plan.md, S1). `deflate` because Linphone reads it and
  this node already writes it for the presence NOTIFYs. An INVITE's SDP or a
  NOTIFY is not touched here: the NOTIFY is compressed by the dialog, on the
  watcher's word.

  Left as it is: a request that fits, one whose body already carries a coding,
  one marked `send_in_clear/1`, and one whose body deflates to no less. A
  request still past the bound once compressed leaves anyway — the path may
  fragment it, which is what happened to all of them before — and says so.
  """
  @spec fit_datagram(map()) :: map()
  def fit_datagram(%{method: :MESSAGE} = req) do
    cond do
      Map.get(req, @clear) -> req
      SIP.Msg.Ops.body_encoding(req) != nil -> req
      byte_size(SIPMsg.serialize(req)) <= @datagram_bound -> req
      true -> deflate_body(req)
    end
  end

  def fit_datagram(msg), do: msg

  @doc """
  Mark `req` to leave with its body in clear, whatever its size: the request
  sent again after a **415** whose `Accept-Encoding` does not list `deflate`
  (RFC 3261 §21.4.13). A mark on the map, never a header on the wire.
  """
  @spec send_in_clear(map()) :: map()
  def send_in_clear(req) when is_map(req), do: Map.put(req, @clear, true)

  @doc """
  Is `rsp` a refusal of the body's coding — a 415 naming the codings it reads,
  `deflate` not among them? What a page compressed by `fit_datagram/1` is sent
  again in clear on. A 415 without `Accept-Encoding` refuses the media type,
  which no coding changes.
  """
  @spec coding_refused?(map()) :: boolean()
  def coding_refused?(%{response: 415} = rsp) do
    case SIP.Msg.Ops.accepted_encodings(rsp) do
      [] -> false
      codings -> "deflate" not in codings
    end
  end

  def coding_refused?(_rsp), do: false

  # The whole body — a multipart with its delimiters — is compressed as one: the
  # Content-Type still names the subtype and the boundary. Stamped after the
  # body, since `update_sip_msg/2` names a bare binary `application/sdp`.
  defp deflate_body(req) do
    clear = SIPMsg.body_octets(Map.get(req, :body))
    compressed = :zlib.compress(clear)

    if byte_size(compressed) < byte_size(clear) do
      req =
        req
        |> SIP.Msg.Ops.update_sip_msg({:body, compressed})
        |> Map.put(:contenttype, Map.get(req, :contenttype))
        |> Map.put("Content-Encoding", "deflate")

      size = byte_size(SIPMsg.serialize(req))

      if size > @datagram_bound do
        Logger.warning(
          module: __MODULE__,
          message: "MESSAGE of #{size} octets once deflated: sent past the datagram bound"
        )
      end

      req
    else
      req
    end
  end

  # zlib first, then raw DEFLATE: the sender does not say which it meant. A body
  # too large in one format is too large in the other, and is not retried.
  defp inflate_deflate(body) do
    case inflate(body, @zlib) do
      {:error, :corrupt} -> inflate(body, @raw_deflate)
      result -> result
    end
  end

  # One stream, inflated a chunk at a time (`safeInflate/2` hands back at most
  # what fits in its buffer), and abandoned as soon as it outgrows the bound.
  defp inflate(body, window) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, window)
      drain(z, :zlib.safeInflate(z, body), [], 0, SIPMsg.max_message_size())
    rescue
      _ -> {:error, :corrupt}
    catch
      # :zlib signals a truncated or corrupt stream by exiting, not by raising.
      _, _ -> {:error, :corrupt}
    after
      :zlib.close(z)
    end
  end

  defp finish(z, clear) do
    :ok = :zlib.inflateEnd(z)
    {:ok, IO.iodata_to_binary(clear)}
  end

  defp drain(z, {status, out}, acc, size, limit) do
    size = size + IO.iodata_length(out)

    cond do
      size > limit -> {:error, :too_large}
      # `:finished` only says the INPUT ran out: a truncated stream ends the same
      # way, and only `inflateEnd/1` tells them apart (it raises on the latter).
      status == :finished -> finish(z, [acc | out])
      true -> drain(z, :zlib.safeInflate(z, []), [acc | out], size, limit)
    end
  end
end
