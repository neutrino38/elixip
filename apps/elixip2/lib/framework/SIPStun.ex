defmodule SIP.Stun do
  @moduledoc """
  STUN (RFC 5389) as it is seen from a SIP port: telling a STUN message apart from
  a SIP one, and decoding its header.

  **A SIP UDP port does receive these.** RFC 5626 §4.4.2 makes STUN the keep-alive
  of an outbound flow over UDP — the client sends a Binding Request to the very
  address:port its SIP flow uses, and §4.4.2 requires an edge proxy that offers
  outbound over UDP to be a STUN server on that port. ICE clients that pick the
  signalling port as a candidate, and plain network scanners, land there too.

  STUN and SIP are unambiguous to demultiplex (the rule RFC 7983 uses for the same
  problem on an RTP port): a STUN message starts with two zero bits and carries the
  fixed magic cookie 0x2112A442 in its 5th to 8th byte, and no SIP start-line —
  which is ASCII, and begins with a method name or "SIP/2.0" — can produce either.

  This module lives apart from `SIPMsg` because STUN is a different protocol, not a
  variety of SIP message: its attribute encoding, its transaction ids and its
  retransmission rules have nothing to do with the SIP parser's.

  ## Recognising is not answering — yet

  Today a transport drops a STUN message with a debug log. That is a *diagnosis*,
  not a fix: the client is waiting for a Binding Response carrying its
  XOR-MAPPED-ADDRESS, and without one it declares the flow dead and re-registers.
  We intend to answer eventually, so `decode/1` already returns what a responder
  needs — a response echoes the request's **transaction id** and keeps its method,
  changing only the class (RFC 5389 §6) — and `attributes/1` hands back the
  still-encoded attribute block for whoever first needs to look inside it.

  What is missing for that day, and deliberately absent until then: attribute
  parsing/encoding (§15), XOR-MAPPED-ADDRESS (§15.2), MESSAGE-INTEGRITY and the
  long-term credentials that make a public STUN server safe to run (§15.4, §10.2),
  and the transport-side decision of which listeners answer at all.
  """

  @magic_cookie 0x2112A442
  @header_size 20

  @typedoc """
  A decoded STUN header. `method` is the 12-bit method (`0x001` = Binding) and
  `class` is the transaction role, split out of the type field as §6 defines them.
  """
  @type t :: %__MODULE__{
          class: :request | :indication | :success_response | :error_response,
          method: non_neg_integer(),
          txid: binary(),
          attributes: binary()
        }

  defstruct [:class, :method, :txid, :attributes]

  @doc """
  True when this payload is a STUN message rather than a SIP one.

  Checks the three things that make the demultiplexing safe: the two leading zero
  bits, the magic cookie, and a declared attribute length that is both a multiple
  of 4 (§15: every attribute is padded to a word) and actually present.

      iex> SIP.Stun.message?(<<0x0001::16, 0::16, 0x2112A442::32, 0::96>>)
      true

      iex> SIP.Stun.message?("REGISTER sip:example.com SIP/2.0\\r\\n")
      false
  """
  @spec message?(binary()) :: boolean()
  def message?(payload), do: match?({:ok, _}, decode(payload))

  @doc """
  Decode the header of a STUN message, leaving the attributes encoded.

  Returns `:error` for anything that is not one — same test as `message?/1`, which
  is written in terms of this function so the two can never disagree.

      iex> {:ok, req} = SIP.Stun.decode(<<0x0001::16, 0::16, 0x2112A442::32, 7::96>>)
      iex> {req.class, req.method, byte_size(req.txid)}
      {:request, 1, 12}
  """
  @spec decode(binary()) :: {:ok, t()} | :error
  def decode(
        <<0::2, m_hi::5, class_hi::1, m_mid::3, class_lo::1, m_lo::4, len::16, @magic_cookie::32,
          txid::binary-size(12), rest::binary>>
      )
      when rem(len, 4) == 0 and byte_size(rest) >= len do
    # §6 interleaves the 12 method bits with the 2 class bits inside the 16-bit type
    # field — `0 0 M M M M M C M M M C M M M M` — so neither is one contiguous slice
    # and a Binding Success Response is 0x0101, not 0x0100.
    {:ok,
     %__MODULE__{
       class: class(class_hi * 2 + class_lo),
       method: m_hi * 128 + m_mid * 16 + m_lo,
       txid: txid,
       attributes: binary_part(rest, 0, len)
     }}
  end

  def decode(_payload), do: :error

  @doc """
  A short human label for a decoded message, for logs.

      iex> {:ok, req} = SIP.Stun.decode(<<0x0001::16, 0::16, 0x2112A442::32, 0::96>>)
      iex> SIP.Stun.describe(req)
      "Binding Request"
  """
  @spec describe(t()) :: String.t()
  def describe(%__MODULE__{method: method, class: class}) do
    method_name =
      case method do
        0x001 -> "Binding"
        other -> "method 0x#{Integer.to_string(other, 16)}"
      end

    class_name =
      case class do
        :request -> "Request"
        :indication -> "Indication"
        :success_response -> "Success Response"
        :error_response -> "Error Response"
      end

    method_name <> " " <> class_name
  end

  @doc "Size of the fixed STUN header, before any attribute."
  @spec header_size() :: pos_integer()
  def header_size, do: @header_size

  defp class(0b00), do: :request
  defp class(0b01), do: :indication
  defp class(0b10), do: :success_response
  defp class(0b11), do: :error_response
end
