defmodule SIP.Test.EventPackages.Dummy do
  @moduledoc """
  An event package whose document is a line of text.

  What the `SIP.EventPackage` behaviour is *for*: it lets the subscription layer
  be exercised end to end — negotiation, 423, 406, 489, the refresh, the final
  NOTIFY — with no PIDF, no XML parser and no `presence` package in sight. When
  `SIP.EventPackage.Presence` is substituted for it and the same suite passes,
  that is the proof the behaviour is a behaviour and not a hole shaped like one
  implementation.

  Its bounds are short on purpose: a test that has to wait 3600 s for an expiry
  proves nothing.
  """

  @behaviour SIP.EventPackage

  @content_type "text/plain"

  @impl true
  def name, do: "dummy"

  @impl true
  def default_expires, do: 60

  @impl true
  def min_expires, do: 10

  @impl true
  def max_expires, do: 3600

  @impl true
  def content_types, do: [@content_type]

  @impl true
  def parse(@content_type, body) when is_binary(body), do: {:ok, body}
  def parse(content_type, _body), do: {:error, {:unsupported_content_type, content_type}}

  @impl true
  def serialize(@content_type, state) when is_binary(state), do: {:ok, state}
  def serialize(@content_type, state), do: {:ok, to_string(state)}
  def serialize(content_type, _state), do: {:error, {:unsupported_content_type, content_type}}
end
