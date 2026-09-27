# What `Content-Encoding` (RFC 3261 §20.12) does to a body, undone.
# Read from the parser (SIPMsg.add_body/2); the header itself is read in exactly
# one place, SIP.Msg.Ops.body_encoding/1.

defmodule SIP.Msg.BodyCoding do
  @moduledoc """
  Decode the `Content-Encoding` a peer applied to a message body.

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

  @doc """
  Undo `coding` on `body`.

  `{:error, :unsupported}` is a coding this node does not implement — the answer
  is **415**, listing `supported/0` in `Accept-Encoding`, so the peer can send the
  same request uncompressed. `{:error, :corrupt}` is a body that will not inflate,
  and it gets the same refusal: the peer's next move is the same either way, and a
  body we cannot read is one we cannot dispatch.
  """
  @spec decode(binary(), binary() | nil) :: {:ok, binary()} | {:error, :unsupported | :corrupt}
  def decode(body, coding) when is_binary(body) do
    case coding do
      nil -> {:ok, body}
      "identity" -> {:ok, body}
      "deflate" -> inflate(body)
      _other -> {:error, :unsupported}
    end
  end

  @doc "The codings this node can read, as `Accept-Encoding` states them."
  @spec supported() :: binary()
  def supported, do: "deflate, identity"

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

  defp inflate(body) do
    case try_inflate(&:zlib.uncompress/1, body) do
      {:ok, clear} -> {:ok, clear}
      :error -> try_inflate(&:zlib.unzip/1, body) |> corrupt_if_failed()
    end
  end

  defp try_inflate(fun, body) do
    {:ok, fun.(body)}
  rescue
    _ -> :error
  catch
    # :zlib signals a truncated stream by exiting, not by raising.
    _, _ -> :error
  end

  defp corrupt_if_failed(:error), do: {:error, :corrupt}
  defp corrupt_if_failed({:ok, clear}), do: {:ok, clear}
end
